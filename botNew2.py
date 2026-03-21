#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import time
import uuid
import json
import base64
import random
import asyncio
import urllib.parse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from requests.cookies import create_cookie
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# =========================
#   KONFIGURASI & KONSTANTA
# =========================
WALLET_EMAIL = os.getenv("CRYPTOWRS_WALLET_EMAIL", "").strip()

BASE_URL = "https://earncryptowrs.in/"
LOGIN_VALIDATION_URL = f"{BASE_URL}/app/auth/validation"
ICAPTCHA_URL = f"{BASE_URL}/icaptcha/req"
MAIN_HOST = urllib.parse.urlparse(BASE_URL).hostname

# Atur daftar koin yang mau diklaim dalam 1 sesi
CURRENCIES = [x.strip().upper() for x in os.getenv("CRYPTOWRS_CURRENCIES", "BCH,LTC,DOGE").split(",") if x.strip()]

# XPATH tombol faucet (untuk deteksi halaman sudah siap)
XPATH_FAUCET_BTN = "/html/body/div[3]/div[3]/div[2]/div/div[2]/div[1]/form/div[1]/button"

# Matikan warning SSL bawel
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# =========================
#          HEADERS
# =========================
BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
}

CAPTCHA_HEADERS = {
    **BASE_HEADERS,
    "x-requested-with": "XMLHttpRequest",
    "origin": "https://earncryptowrs.in",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "referer": "https://earncryptowrs.in/",
}

# =========================
#   CLOUDFLARE DETECTION
# =========================
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

# =========================
#      REQUESTS RETRIES
# =========================
def install_retries(session: requests.Session):
    retry = Retry(
        total=5, connect=5, read=5,
        backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET","POST"]),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=50)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

def safe_request(session, method: str, url: str, max_soft_retry: int = 2, **kwargs):
    """Retry ringan untuk ConnectionError/ChunkedEncodingError."""
    for attempt in range(max_soft_retry + 1):
        try:
            return session.request(method, url, **kwargs)
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ChunkedEncodingError):
            if attempt >= max_soft_retry:
                raise
            time.sleep(0.8 * (attempt + 1))
            hdrs = kwargs.setdefault("headers", {})
            hdrs["Connection"] = "close"

# =========================
#  UTILITAS COOKIES/DRIVER
# =========================
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
        cookies = sb.get_cookies()
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

# =========================
#   HTML PARSER / TOKENS
# =========================
def extract_faucet_message(html: str) -> str:
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return ""
    for sel in [".alert-success", ".alert-warning", ".alert-danger", ".alert", "#message", "#msg"]:
        el = soup.select_one(sel)
        if el and el.get_text(strip=True):
            return el.get_text(strip=True)[:300]
    text = soup.get_text(" ", strip=True)
    m = re.search(r"(success|claimed|wait|minute|second|cooldown|already|error|invalid|Shortlink)", text, re.I)
    if m:
        start = max(0, m.start()-60); end = min(len(text), m.end()+160)
        return text[start:end]
    return ""

def get_tokens_from_page(html: str):
    soup = BeautifulSoup(html, "html.parser")
    csrf_el = soup.find("input", {"name": "ci_csrf_token"})
    icon_el = soup.find("input", {"name": "_iconcaptcha-token"})
    csrf = csrf_el.get("value") if csrf_el and csrf_el.has_attr("value") else None
    icon = icon_el.get("value") if icon_el and icon_el.has_attr("value") else None
    return csrf, icon

# =========================
#     BRIDGE (ROBUST)
# =========================
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
    end = time.time() + timeout
    while time.time() < end:
        if len(sb.driver.window_handles) > start_count:
            return True
        time.sleep(0.2)
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
    # pilih window domain target
    for h in sb.driver.window_handles:
        sb.switch_to_window(h)
        host = _current_host(sb)
        if host and host.endswith(MAIN_HOST):
            return
    # kalau belum ketemu tapi >1 tab, close current & pindah newest
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
      - tombol faucet muncul (beberapa selector kandidat), ATAU
      - faucet via requests sudah 200 & non-CF.
    Sambil itu, re-sync cookies dan nudge click netral berkala untuk pop-under.
    """
    start = time.time()
    next_nudge = start + 7.0
    alt_selectors = [
        wait_xpath,
        "form[action*='/app/faucet/verify'] button[type='submit']",
        "button:contains('Claim')",
        "button.btn.btn-primary",
    ]
    while True:
        if _any_element_visible(sb, alt_selectors):
            return

        _driver_cookies_to_session(sb, session)
        try:
            r = safe_request(session, "GET", faucet_url, verify=False, allow_redirects=True, timeout=20)
            if r.status_code == 200 and not looks_like_cloudflare_response(r):
                return
        except Exception:
            pass

        _select_target_window(sb)

        now = time.time()
        if now >= next_nudge:
            try:
                sb.execute_script("document.body.dispatchEvent(new MouseEvent('click', {bubbles:true}))")
            except Exception:
                try:
                    sb.js_click("html")
                except Exception:
                    pass
            next_nudge = now + random.uniform(6.0, 9.0)

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

        time.sleep(poll)

def bridge_via_driver(session: requests.Session, url: str, wait_xpath: str,
                      *, headless: bool = True, timeout: float = 120.0,
                      click_to_spawn_tab: bool = True) -> None:
    """
    Sinkron S<->D; buka faucet; handle pop-under; tunggu siap; sync balik.
    """
    from seleniumbase import SB

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
        time.sleep(0.5)

        # Pop-under trigger awal
        if click_to_spawn_tab:
            start_count = len(sb.driver.window_handles)
            try:
                sb.execute_script("document.body.dispatchEvent(new MouseEvent('click', {bubbles:true}))")
            except Exception:
                try:
                    sb.js_click("html")
                except Exception:
                    pass
            if _wait_new_window(sb, start_count, timeout=6.0):
                sb.switch_to_newest_window()

        # Tunggu CF clean atau tombol siap
        wait_cf_then_button(sb, session, url, wait_xpath, total_timeout=timeout)

        # Sync cookies balik
        _driver_cookies_to_session(sb, session)
        try:
            new_ua = sb.get_user_agent()
            if new_ua:
                session.headers.update({"User-Agent": new_ua})
        except Exception:
            pass

# =========================
#      LOGIN / CAPTCHA
# =========================
def get_initial_tokens(session: requests.Session, url: str = "") -> tuple:
    print("1. Mengunjungi halaman untuk mengambil token...")
    try:
        response = safe_request(session, "GET", url, verify=False, allow_redirects=True, timeout=30)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        csrf_token = soup.find("input", {"name": "ci_csrf_token"})["value"]
        iconcaptcha_token = soup.find("input", {"name": "_iconcaptcha-token"})["value"]
        print(f"   > CSRF Token: {csrf_token[:20]}...")
        print(f"   > IconCaptcha Token: {iconcaptcha_token[:20]}...")
        return csrf_token, iconcaptcha_token
    except (requests.exceptions.RequestException, KeyError, TypeError) as e:
        raise ValueError(f"Gagal mendapatkan token awal: {e}")

def solve_static_captcha(session: requests.Session, iconcaptcha_token: str) -> tuple[str, str]:
    print("2. Mencoba menyelesaikan captcha...")
    ic_wid = str(uuid.uuid4())
    init_ts = int(time.time() * 1000)

    session.headers.update(CAPTCHA_HEADERS)
    session.headers.update({"x-iconcaptcha-token": iconcaptcha_token})

    # batasi retry biar nggak kejebak
    for _ in range(12):
        ts = int(time.time() * 1000)
        payload_load_str = (
            f'{{"widgetId":"{ic_wid}","action":"LOAD","theme":"light","token":"{iconcaptcha_token}",'
            f'"timestamp":{ts},"initTimestamp":{init_ts}}}'
        )
        payload = {"payload": base64.b64encode(payload_load_str.encode()).decode()}
        response_load = safe_request(session, "POST", ICAPTCHA_URL, data=payload, verify=False, timeout=30)
        js_response_load = json.loads(base64.b64decode(response_load.text).decode())
        ic_cid = js_response_load.get("identifier")
        if not ic_cid:
            raise ValueError("Gagal mendapatkan challengeId (ic_cid) dari captcha.")

        time.sleep(random.uniform(2.0, 4.0))
        ts = int(time.time() * 1000)

        static_x, static_y = 297, 23
        payload_select_str = (
            f'{{"widgetId":"{ic_wid}","challengeId":"{ic_cid}","action":"SELECTION","x":{static_x},"y":{static_y},'
            f'"width":320,"token":"{iconcaptcha_token}","timestamp":{ts},"initTimestamp":{init_ts}}}'
        )
        payload = {"payload": base64.b64encode(payload_select_str.encode()).decode()}
        response_select = safe_request(session, "POST", ICAPTCHA_URL, data=payload, verify=False, timeout=30)
        js_response_select = base64.b64decode(response_select.text).decode()

        if '"completed":true' in js_response_select:
            print("   > Captcha berhasil diselesaikan.")
            return ic_cid, ic_wid

        print("   > Gagal, mencoba captcha baru...")
        init_ts = int(time.time() * 1000)
        time.sleep(random.uniform(1.0, 2.0))

    raise RuntimeError("iCaptcha gagal diselesaikan setelah banyak percobaan.")

def perform_login(session: requests.Session, csrf_token: str, iconcaptcha_token: str,
                  ic_cid: str, ic_wid: str | None = None):
    print("3. Mengirim permintaan login...")
    login_payload = {
        "ci_csrf_token": csrf_token,
        "wallet": WALLET_EMAIL,
        "uid": "",
        "private_ip": "",
        "captcha": "icaptcha",
        "_iconcaptcha-token": iconcaptcha_token,
        "ic-rq": "1",
        "ic-wid": ic_wid,
        "ic-cid": ic_cid,
        "ic-hp": "",
    }
    login_response = safe_request(session, "POST", LOGIN_VALIDATION_URL,
                                  data=login_payload, verify=False, allow_redirects=False, timeout=30)
    if login_response.status_code == 303 and "/app/dashboard" in login_response.headers.get("Location", ""):
        print("   > Login Berhasil! Anda diarahkan ke dashboard.")
    else:
        print(f"   > Login Gagal. Status Code: {login_response.status_code}")

# =========================
#          CLAIM
# =========================
def claim_faucet(session: requests.Session, faucet_url: str,
                 currency: str, csrf_token: str, iconcaptcha_token: str,
                 ic_cid: str, ic_wid: str | None = None,
                 *, retry_after_bridge: bool = False) -> requests.Response:
    print("5. Mengklaim faucet...")

    claim_payload = {
        "ci_csrf_token": csrf_token,
        "currency": currency,
        "captcha": "icaptcha",
        "_iconcaptcha-token": iconcaptcha_token,
        "ic-rq": "1",
        "ic-wid": ic_wid,
        "ic-cid": ic_cid,
        "ic-hp": "",
    }

    claim_url = f"{BASE_URL}/app/faucet/verify?currency={currency}"
    browserish_headers = {
        "Origin": f"{urllib.parse.urlsplit(BASE_URL).scheme}://{urllib.parse.urlsplit(BASE_URL).netloc}",
        "Referer": faucet_url,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "Upgrade-Insecure-Requests": "1",
    }

    r = safe_request(session, "POST", claim_url,
                     data=claim_payload, headers=browserish_headers,
                     verify=False, allow_redirects=False, timeout=30)

    if r.status_code in (302, 303) and r.headers.get("Location"):
        redirect_url = urljoin(BASE_URL, r.headers["Location"])
        final = safe_request(session, "GET", redirect_url, verify=False, allow_redirects=True, timeout=30)
        return final

    # Kalau disini 403/503, caller yang akan melakukan bridge & retry
    return r

# =========================
#     PER-COIN WORKFLOW
# =========================
async def claim_one_currency(session: requests.Session, currency: str):
    faucet_url = f"{BASE_URL}/app/faucet?currency={currency}"
    print(f"\n=== Claim {currency} ===")

    # 1) GET faucet
    resp = safe_request(session, "GET", faucet_url, verify=False, allow_redirects=True, timeout=30)
    if looks_like_cloudflare_response(resp):
        print("   > CF pada GET faucet. Bridge…")
        await asyncio.to_thread(
            bridge_via_driver,
            session=session,
            url=faucet_url,
            wait_xpath=XPATH_FAUCET_BTN,
            headless=True,     # VPS-friendly
            timeout=180.0,
            click_to_spawn_tab=True,
        )
        resp = safe_request(session, "GET", faucet_url, verify=False, allow_redirects=True, timeout=30)

    if resp.status_code != 200:
        print(f"   > Faucet {currency} gagal dibuka. Status {resp.status_code}")
        return

    print(f"   > Faucet {currency} terbuka.")
    # 2) Gate / cooldown?
    csrf2, icon2 = get_tokens_from_page(resp.text)
    if not (csrf2 and icon2):
        msg = extract_faucet_message(resp.text)
        print("   > Token tidak tersedia (gate/cooldown).", f"Pesan: {msg}" if msg else "")
        return

    # 3) Solve captcha & claim
    try:
        cid2, wid2 = solve_static_captcha(session, icon2)
        session.headers.clear(); session.headers.update(BASE_HEADERS)
    except Exception as e:
        print("   > Gagal solve captcha:", e)
        return

    final = claim_faucet(session, faucet_url, currency, csrf2, icon2, cid2, wid2)
    if final.status_code in (403, 503) or looks_like_cloudflare_response(final):
        print("   > Claim masih ketahan CF. Bridge & retry…")
        await asyncio.to_thread(
            bridge_via_driver,
            session=session,
            url=faucet_url,
            wait_xpath=XPATH_FAUCET_BTN,
            headless=True,
            timeout=120.0,
            click_to_spawn_tab=True,
        )
        # Re-fetch token dari faucet setelah bridge
        resp2 = safe_request(session, "GET", faucet_url, verify=False, allow_redirects=True, timeout=30)
        csrf3, icon3 = get_tokens_from_page(resp2.text)
        if not (csrf3 and icon3):
            msg = extract_faucet_message(resp2.text)
            print("   > Setelah bridge, token tetap tidak ada.", f"Pesan: {msg}" if msg else "")
            return
        cid3, wid3 = solve_static_captcha(session, icon3)
        session.headers.clear(); session.headers.update(BASE_HEADERS)
        final = claim_faucet(session, faucet_url, currency, csrf3, icon3, cid3, wid3, retry_after_bridge=False)

    if final.status_code == 200:
        msg = extract_faucet_message(final.text)
        print("   > Hasil:", msg or "200 OK (tanpa pesan terstruktur)")
        # jeda manusiawi sebelum pindah coin berikutnya
        time.sleep(10 + random.uniform(0.5, 2.0))
    else:
        print(f"   > Claim {currency} selesai dengan status: {final.status_code}")

async def claim_many(session: requests.Session, currencies: list[str]):
    for cur in currencies:
        await claim_one_currency(session, cur)

# =========================
#           MAIN
# =========================
async def main():
    with requests.Session() as s:
        s.headers.update(BASE_HEADERS)
        install_retries(s)

        try:
            # 1) Token awal & iCaptcha login
            csrf_token, iconcaptcha_token = get_initial_tokens(s, BASE_URL)
            challenge_id, widget_id = solve_static_captcha(s, iconcaptcha_token)
            s.headers.clear(); s.headers.update(BASE_HEADERS)

            perform_login(s, csrf_token, iconcaptcha_token, challenge_id, widget_id)

            # 2) Optional: bridge awal pada coin pertama (fresh clearance)
            first_url = f"{BASE_URL}/app/faucet?currency={CURRENCIES[0]}"
            print("4. Mengakses halaman faucet...")
            faucet_response = safe_request(s, "GET", first_url, verify=False, allow_redirects=True, timeout=30)
            print("   > Status:", faucet_response.status_code, "| Tersinyal CF?", looks_like_cloudflare_response(faucet_response))
            if looks_like_cloudflare_response(faucet_response):
                print("   > Cloudflare terdeteksi. Membuka via browser untuk menyelesaikan interstisial…")
                try:
                    await asyncio.to_thread(
                        bridge_via_driver,
                        session=s,
                        url=first_url,
                        wait_xpath=XPATH_FAUCET_BTN,
                        headless=True,
                        timeout=180.0,
                        click_to_spawn_tab=True,
                    )
                finally:
                    time.sleep(2)

                faucet_response = safe_request(s, "GET", first_url, verify=False, allow_redirects=True, timeout=30)
                print("   > Coba ulang faucet via requests → Status:", faucet_response.status_code,
                      "| Tersinyal CF?", looks_like_cloudflare_response(faucet_response))

            # 3) Multi-coin claim dalam satu sesi
            await claim_many(s, CURRENCIES)

        except Exception as e:
            print(f"Terjadi kesalahan: {e}")
            raise

if __name__ == "__main__":
    if not WALLET_EMAIL:
        raise SystemExit("Set CRYPTOWRS_WALLET_EMAIL dulu di environment lokal.")
    asyncio.run(main())
