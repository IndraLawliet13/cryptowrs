import os
import requests
import uuid, time, base64, json
from bs4 import BeautifulSoup
import asyncio
import urllib.parse
import re
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.cookies import create_cookie


# --- KONFIGURASI & KONSTANTA ---
WALLET_EMAIL = os.getenv("CRYPTOWRS_WALLET_EMAIL", "").strip()
BASE_URL = "https://earncryptowrs.in/"
LOGIN_VALIDATION_URL = f"{BASE_URL}/app/auth/validation"
ICAPTCHA_URL = f"{BASE_URL}/icaptcha/req"
MAIN_HOST = urllib.parse.urlparse(BASE_URL).hostname
CURRENCY = os.getenv("CRYPTOWRS_CURRENCY", "BCH").strip().upper()  # Pilihan: BTC, LTC, DOGE, DASH, BCH, ETH

# XPATH tombol faucet (untuk deteksi halaman sudah siap)
XPATH_FAUCET_BTN = "/html/body/div[3]/div[3]/div[2]/div/div[2]/div[1]/form/div[1]/button"

# Menonaktifkan peringatan InsecureRequestWarning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# --- HEADERS ---
BASE_HEADERS = {
    'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    'Accept-Language': "en-US,en;q=0.9,id;q=0.8",
}

CAPTCHA_HEADERS = {
  **BASE_HEADERS,
  'x-requested-with': "XMLHttpRequest",
  'origin': "https://earncryptowrs.in",
  'sec-fetch-site': "same-origin",
  'sec-fetch-mode': "cors",
  'sec-fetch-dest': "empty",
  'referer': "https://earncryptowrs.in/",
}

# -------------------------------------------------------------------
#  DETEKSI CLOUDFLARE & UTILITAS COOKIES/POP-UNDER
# -------------------------------------------------------------------
CF_TITLE_PATTERNS = (
    "Just a moment...",
    "Attention Required!",
    "Checking your browser before accessing",
)
CF_HTML_PATTERNS = (
    r"cf-\w*challenge",
    r"data-cf-beacon",
    r"Ray ID:\s*[\w-]+",
    r"DDoS protection by Cloudflare",
)

def install_retries(session: requests.Session):
    retry = Retry(
        total=5,
        connect=5,
        read=5,
        backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET","POST"]),  # termasuk POST
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=50)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

def safe_request(session, method: str, url: str, max_soft_retry: int = 2, **kwargs):
    """Lapisan retry ekstra utk error seperti RemoteDisconnected/ProtocolError."""
    for attempt in range(max_soft_retry + 1):
        try:
            return session.request(method, url, **kwargs)
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ChunkedEncodingError) as e:
            if attempt >= max_soft_retry:
                raise
            time.sleep(0.8 * (attempt + 1))
            # opsi: paksa tutup koneksi keep-alive di next call
            kwargs.setdefault("headers", {})
            kwargs["headers"]["Connection"] = "close"


def looks_like_cloudflare_html(html: str, title: str = "") -> bool:
    t = (title or "").strip()
    if any(p.lower() in t.lower() for p in CF_TITLE_PATTERNS):
        return True
    for pat in CF_HTML_PATTERNS:
        if re.search(pat, html or "", flags=re.I):
            return True
    return False


def looks_like_cloudflare_response(resp: requests.Response) -> bool:
    if resp is None:
        return False
    server = (resp.headers.get("Server", "") or "").lower()
    cf_ray = resp.headers.get("cf-ray")
    text = resp.text or ""
    if resp.status_code in (403, 503) and ("cloudflare" in server or cf_ray):
        return True
    if any(s in text for s in CF_TITLE_PATTERNS):
        return True
    if re.search(CF_HTML_PATTERNS[0], text, flags=re.I):
        return True
    return False


def _normalize_base(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else url


def _session_cookies_to_driver(sb, session: requests.Session, base_url: str) -> None:
    sb.open(_normalize_base(base_url))
    for c in session.cookies:
        cookie = {
            "name": c.name,
            "value": c.value,
            "path": c.path or "/",
            "secure": bool(c.secure),
        }
        if c.domain:
            cookie["domain"] = c.domain.lstrip(".")
        if c.expires:
            try:
                cookie["expiry"] = int(c.expires)
            except Exception:
                pass
        try:
            sb.driver.add_cookie(cookie)
        except Exception:
            continue


def _driver_cookies_to_session(sb, session: requests.Session) -> None:
    try:
        cookies = sb.get_cookies()  # List[dict]
    except Exception:
        cookies = []
    jar = session.cookies
    for c in cookies:
        ck = create_cookie(
            name=c.get("name", ""),
            value=c.get("value", ""),
            domain=(c.get("domain") or "").lstrip("."),
            path=c.get("path") or "/",
            secure=bool(c.get("secure", False)),
            expires=c.get("expiry"),
        )
        jar.set_cookie(ck)

# -------------------------------
#  BRIDGE DENGAN POP-UNDER AWARE
# -------------------------------

def _current_host(sb) -> str:
    try:
        url = sb.get_current_url()
    except Exception:
        return ""
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""


def _wait_new_window(sb, start_count: int, timeout: float = 10.0) -> bool:
    import time as _t
    end = time.time() + timeout
    while time.time() < end:
        if len(sb.driver.window_handles) > start_count:
            return True
        _t.sleep(0.2)
    return False

def _any_element_visible(sb, selectors: list[str]) -> bool:
    for sel in selectors:
        try:
            if sb.is_element_visible(sel):
                return True
        except Exception:
            pass
    return False

def _select_target_window(sb) -> None:
    """Pastikan kita di window/host target; tutup tab liar jika perlu."""
    # Cari window dgn host yg cocok
    for h in sb.driver.window_handles:
        sb.switch_to_window(h)
        host = _current_host(sb)
        if host and host.endswith(MAIN_HOST):
            return
    # Jika tidak ketemu tapi >1 tab, tutup yg sekarang, pindah ke newest
    if len(sb.driver.window_handles) > 1:
        try:
            sb.close_current_window()
        except Exception:
            pass
        try:
            sb.switch_to_newest_window()
        except Exception:
            pass

def wait_cf_then_button(sb, session: requests.Session, faucet_url: str, wait_xpath: str,
                        total_timeout: float = 180.0, poll: float = 3.0) -> None:
    """
    Tunggu sampai:
      - tombol faucet muncul (by XPATH/selector alternatif), ATAU
      - faucet via requests sudah 200 & non-CF.
    Sambil itu, per 6-9 detik lakukan klik netral & re-pilih window untuk atasi pop-under.
    """
    import time as _t
    start = _t.time()
    next_nudge = start + 7.0

    # Kandidat selector alternatif kalau XPATH berubah / beda layout
    alt_selectors = [
        wait_xpath,
        "form[action*='/app/faucet/verify'] button[type='submit']",
        "button:contains('Claim')",
        "button.btn.btn-primary",           # fallback umum
    ]

    while True:
        # 1) kalau tombol terlihat → selesai
        if _any_element_visible(sb, alt_selectors):
            return

        # 2) sinkron cookies → session dan cek via requests
        _driver_cookies_to_session(sb, session)
        try:
            r = session.get(faucet_url, verify=False, allow_redirects=True, timeout=20)
            if r.status_code == 200 and not looks_like_cloudflare_response(r):
                # halaman sudah ready di sisi requests → cukup
                return
        except Exception:
            pass

        # 3) kalau masih di tab/host salah → pilih ulang / tutup tab liar
        _select_target_window(sb)

        # 4) nudge: klik netral untuk memicu tab/lanjutkan interstitial
        now = _t.time()
        if now >= next_nudge:
            try:
                sb.execute_script("document.body.dispatchEvent(new MouseEvent('click', {bubbles:true}))")
            except Exception:
                try:
                    sb.js_click("html")
                except Exception:
                    pass
            next_nudge = now + random.uniform(6.0, 9.0)

        # 5) timeout?
        if now - start > total_timeout:
            html = ""
            ttl = ""
            try:
                html = sb.get_page_source()
                ttl = sb.get_title()
            except Exception:
                pass
            if looks_like_cloudflare_html(html, ttl):
                raise RuntimeError("Timeout: Cloudflare challenge belum rampung.")
            raise RuntimeError("Timeout: Tombol faucet tidak ditemukan.")

        _t.sleep(poll)


def bridge_via_driver(session: requests.Session, url: str, wait_xpath: str, *, headless: bool = False, timeout: float = 120.0, click_to_spawn_tab: bool = True) -> None:
    """
    1) Samakan UA+cookies dari requests → browser
    2) Buka URL faucet
    3) Jika situs memerlukan *user gesture* untuk membuka tab baru (pop-under),
       lakukan satu klik JS netral (bukan pada tombol aksi) agar tab 2 muncul.
    4) Pilih jendela yang host-nya = MAIN_HOST; tutup jendela yang bukan domain itu.
    5) Tunggu sampai elemen `wait_xpath` muncul (indikasi halaman siap / sudah login).
    6) Sinkron cookies dari browser → requests.

    Catatan: Tidak mengotomatiskan penyelesaian challenge apa pun.
    """
    from seleniumbase import SB
    import time as _t

    with SB(uc=True, test=True, locale="en", headless=headless) as sb:
        # Samakan UA
        ua = session.headers.get("User-Agent")
        if ua:
            try:
                sb.driver.execute_cdp_cmd("Network.enable", {})
                sb.driver.execute_cdp_cmd("Network.setUserAgentOverride", {"userAgent": ua})
            except Exception:
                pass

        # Seed cookies agar status login kebawa
        _session_cookies_to_driver(sb, session, url)

        # Buka URL faucet
        sb.open(url)
        sb.wait_for_ready_state_complete()
        _t.sleep(0.5)

        # Beberapa situs perlu klik awal untuk memicu tab baru.
        if click_to_spawn_tab:
            start_count = len(sb.driver.window_handles)
            try:
                # klik netral lewat JS (minim resiko overlay)
                sb.execute_script("document.body.dispatchEvent(new MouseEvent('click', {bubbles:true}))")
            except Exception:
                try:
                    sb.js_click("html")
                except Exception:
                    pass
            if _wait_new_window(sb, start_count, timeout=5.0):
                sb.switch_to_newest_window()

        # Seleksi jendela yang host-nya sesuai; tutup yang bukan domain kita
        # (iklan / tab liar biasanya beda domain)
        max_passes = 4
        for _ in range(max_passes):
            host = _current_host(sb)
            if host and host.endswith(MAIN_HOST):
                break
            # Kalau bukan domain target, coba cari window lain yang domainnya cocok
            found = False
            for h in sb.driver.window_handles:
                sb.switch_to_window(h)
                if _current_host(sb).endswith(MAIN_HOST):
                    found = True
                    break
            if found:
                break
            else:
                # Tutup tab yang bukan domain target (hanya jika >1 tab untuk keamanan)
                if len(sb.driver.window_handles) > 1:
                    try:
                        sb.close_current_window()
                    except Exception:
                        pass
                    try:
                        sb.switch_to_newest_window()
                    except Exception:
                        pass
                else:
                    break

        # Tunggu sampai tombol faucet tersedia (indikasi sudah di halaman benar & login)
        # sb.wait_for_element(wait_xpath, timeout=timeout)
        wait_cf_then_button(sb, session, url, wait_xpath, total_timeout=timeout)

        # Sinkron cookies kembali ke session
        _driver_cookies_to_session(sb, session)
        try:
            new_ua = sb.get_user_agent()
            if new_ua:
                session.headers.update({"User-Agent": new_ua})
        except Exception:
            pass

# ----------------------
#  FUNGSI INTI (LOGIN) — TIDAK DIUBAH
# ----------------------

def get_initial_tokens(session: requests.Session, url: str = '') -> tuple:
    print("1. Mengunjungi halaman untuk mengambil token...")
    try:
        response = safe_request(session, "GET", url, verify=False)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        csrf_token = soup.find('input', {'name': 'ci_csrf_token'})['value']
        iconcaptcha_token = soup.find('input', {'name': '_iconcaptcha-token'})['value']

        print(f"   > CSRF Token: {csrf_token[:20]}...")
        print(f"   > IconCaptcha Token: {iconcaptcha_token[:20]}...")
        return csrf_token, iconcaptcha_token
    except (requests.exceptions.RequestException, KeyError, TypeError) as e:
        raise ValueError(f"Gagal mendapatkan token awal: {e}")


def solve_static_captcha(session: requests.Session, iconcaptcha_token: str) -> str:
    print("2. Mencoba menyelesaikan captcha...")
    ic_wid = str(uuid.uuid4())
    init_ts = int(time.time() * 1000)

    session.headers.update(CAPTCHA_HEADERS)
    session.headers.update({'x-iconcaptcha-token': iconcaptcha_token})

    while True:
        ts = int(time.time() * 1000)
        payload_load_str = f'{"{"}"widgetId":"{ic_wid}","action":"LOAD","theme":"light","token":"{iconcaptcha_token}","timestamp":{ts},"initTimestamp":{init_ts}{"}"}'
        payload = {'payload': base64.b64encode(payload_load_str.encode()).decode()}

        response_load = safe_request(session, "POST", ICAPTCHA_URL, data=payload, verify=False)
        js_response_load = json.loads(base64.b64decode(response_load.text).decode())
        ic_cid = js_response_load.get('identifier')

        if not ic_cid:
            raise ValueError("Gagal mendapatkan challengeId (ic_cid) dari captcha.")

        time.sleep(random.uniform(2.0, 4.0))  # Simulasi waktu pengguna membaca & mengklik
        ts = int(time.time() * 1000)

        static_x, static_y = 297, 23
        payload_select_str = f'{"{"}"widgetId":"{ic_wid}","challengeId":"{ic_cid}","action":"SELECTION","x":{static_x},"y":{static_y},"width":320,"token":"{iconcaptcha_token}","timestamp":{ts},"initTimestamp":{init_ts}{"}"}'
        payload = {'payload': base64.b64encode(payload_select_str.encode()).decode()}

        response_select = safe_request(session, "POST", ICAPTCHA_URL, data=payload, verify=False)
        js_response_select = base64.b64decode(response_select.text).decode()

        if '"completed":true' in js_response_select:
            print("   > Captcha berhasil diselesaikan.")
            return ic_cid, ic_wid
        else:
            print("   > Gagal, mencoba captcha baru...")
            init_ts = int(time.time() * 1000)
            time.sleep(random.uniform(1.0, 2.0))


def perform_login(session: requests.Session, csrf_token: str, iconcaptcha_token: str, ic_cid: str, ic_wid: str = None):
    print("3. Mengirim permintaan login...")

    login_payload = {
        'ci_csrf_token': csrf_token,
        'wallet': WALLET_EMAIL,
        'uid': '',
        'private_ip': '',
        'captcha': 'icaptcha',
        '_iconcaptcha-token': iconcaptcha_token,
        'ic-rq': "1",
        'ic-wid': ic_wid,
        'ic-cid': ic_cid,
        'ic-hp': ''
    }

    login_response = safe_request(session, "POST", LOGIN_VALIDATION_URL, data=login_payload, verify=False, allow_redirects=False)

    if login_response.status_code == 303 and '/app/dashboard' in login_response.headers.get('Location', ''):
        print("   > Login Berhasil! Anda diarahkan ke dashboard.")
    else:
        print(f"   > Login Gagal. Status Code: {login_response.status_code}")

def claim_faucet(session: requests.Session, csrf_token: str, iconcaptcha_token: str, ic_cid: str, ic_wid: str = None):
    print("5. Mengklaim faucet...")

    claim_payload = {
        'ci_csrf_token': csrf_token,
        'currency': CURRENCY,
        'captcha': 'icaptcha',
        '_iconcaptcha-token': iconcaptcha_token,
        'ic-rq': "1",
        'ic-wid': ic_wid,
        'ic-cid': ic_cid,
        'ic-hp': ''
    }

    claim_url = f"{BASE_URL}/app/faucet/verify?currency={CURRENCY}"
    claim_response = safe_request(session, "POST", claim_url, data=claim_payload, verify=False, allow_redirects=True, timeout=30)
    if claim_response.status_code == 200:
        print("   > Klaim faucet berhasil.")
        time.sleep(10)  # Tunggu sejenak sebelum klaim berikutnya
    else:
        print(f"   > Klaim faucet gagal. Status Code: {claim_response.status_code}")

# -----------------
#   ALUR UTAMA
# -----------------
async def main():
    with requests.Session() as s:
        s.headers.update(BASE_HEADERS)
        install_retries(s)
        try:
            # 1) Token awal
            csrf_token, iconcaptcha_token = get_initial_tokens(s, BASE_URL)

            # 2) Selesaikan captcha (sesuai skrip asli)
            challenge_id, widget_id = solve_static_captcha(s, iconcaptcha_token)
            s.headers.clear(); s.headers.update(BASE_HEADERS)

            # 3) Login (sesuai skrip asli)
            perform_login(s, csrf_token, iconcaptcha_token, challenge_id, widget_id)

            # 4) Akses faucet via requests, deteksi Cloudflare
            print("4. Mengakses halaman faucet...")
            faucet_url = f"{BASE_URL}/app/faucet?currency={CURRENCY}"
            while True:
                faucet_response = safe_request(s, "GET", faucet_url, verify=False, allow_redirects=True, timeout=30)
                cf_hit = looks_like_cloudflare_response(faucet_response)
                print("   > Status:", faucet_response.status_code, "| Tersinyal CF?", cf_hit)

                if cf_hit:
                    while True:
                        print("   > Cloudflare terdeteksi. Membuka via browser untuk menyelesaikan interstisial…")
                        try:
                            # Jalankan bridge di thread terpisah agar tidak bentrok dengan event loop asyncio
                            await asyncio.to_thread(
                                bridge_via_driver,
                                session=s,
                                url=faucet_url,
                                wait_xpath=XPATH_FAUCET_BTN,
                                headless=True,
                                timeout=180.0,
                                click_to_spawn_tab=True,
                            )
                            break
                        except Exception as e:
                            print("   > Gagal menyelesaikan interstisial di browser:", e)
                            raise
                        finally:
                            time.sleep(2)


                    # Coba lagi via requests setelah sesi disegarkan dari browser
                    faucet_response = safe_request(s, "GET", faucet_url, verify=False, allow_redirects=True, timeout=30)
                    print("   > Coba ulang faucet via requests → Status:", faucet_response.status_code,
                        "| Tersinyal CF?", looks_like_cloudflare_response(faucet_response))

                if faucet_response.status_code == 200:
                    print("   > Berhasil mengakses halaman faucet.")
                    # Ambil token baru untuk sesi berikutnya
                    csrf_token, iconcaptcha_token = get_initial_tokens(s, faucet_url)
                    challenge_id, widget_id = solve_static_captcha(s, iconcaptcha_token)
                    s.headers.clear(); s.headers.update(BASE_HEADERS)
                    claim_faucet(s, csrf_token, iconcaptcha_token, challenge_id, widget_id)
                else:
                    print(f"   > Gagal mengakses halaman faucet. Status Code: {faucet_response.status_code}")

        except Exception as e:
            print(f"Terjadi kesalahan: {e}")
            exit(1)

if __name__ == "__main__":
    if not WALLET_EMAIL:
        raise SystemExit("Set CRYPTOWRS_WALLET_EMAIL dulu di environment lokal.")
    asyncio.run(main())
