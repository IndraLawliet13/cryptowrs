# cryptowrs

![Python](https://img.shields.io/badge/Python-Automation-3776AB?logo=python&logoColor=white)
![Target](https://img.shields.io/badge/Target-earncryptowrs.in-111827)
![Modes](https://img.shields.io/badge/Modes-Single%20%7C%20Multi%20Coin-0F766E)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

Python automation scripts for the `earncryptowrs.in` faucet flow, preserved as a safe public showcase version from a private working setup.

This public candidate intentionally keeps the reusable script variants while removing live wallet identifiers, downloaded browser-helper state, screenshots, and debug logs.

## Highlights

- three Python variants for similar faucet flows
- Cloudflare-aware browser bridging in the richer variants
- retry-aware requests session handling
- env-based wallet and coin configuration
- public packaging without local debug/runtime state

## Included variants

- `bot.py` - main single-coin variant with Cloudflare-aware browser bridge
- `botNew.py` - alternate single-coin variant
- `botNew2.py` - multi-coin variant for one session flow
- `requirements.txt`
- `.env.example`
- `LICENSE`

## Local configuration

Required:
- `CRYPTOWRS_WALLET_EMAIL`

Optional:
- `CRYPTOWRS_CURRENCY` for `bot.py` / `botNew.py`
- `CRYPTOWRS_CURRENCIES` for `botNew2.py`
- `CRYPTOWRS_HEADLESS` for the browser-assisted variant in `bot.py`

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
set -a
source .env
set +a
python3 bot.py
```

Other variants:

```bash
python3 botNew.py
python3 botNew2.py
```

## Project behavior

The variants all revolve around the same general flow:

1. open the faucet page and collect CSRF / IconCaptcha tokens
2. log in with a FaucetPay wallet identity
3. detect Cloudflare/public/login states
4. use a browser-assisted bridge when requests-only access is blocked
5. solve static captcha flows
6. submit faucet claims and wait for cooldowns

## Documentation

- `docs/VARIANTS.md`

## Security notes

- Never commit real wallet emails tied to your live faucet identity.
- Treat screenshots, debug HTML, and session-derived logs as sensitive local artifacts.
- Keep browser-helper runtime folders outside version control.

## Disclaimer

Shared for educational and automation-architecture reference. Use it responsibly and according to the target platform's rules and your own risk tolerance.
