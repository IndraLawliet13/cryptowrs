# QUICKSTART

## What you need

- Python 3.10+
- a FaucetPay-linked wallet email exported as `CRYPTOWRS_WALLET_EMAIL`
- optional currency selection for single-coin or multi-coin variants

## Basic setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
set -a
source .env
set +a
```

## Run the main variant

```bash
python3 bot.py
```

## Alternate variants

```bash
python3 botNew.py
python3 botNew2.py
```

## Local safety notes

- keep real wallet identifiers local only
- do not commit screenshots, cookies, or browser-helper state
- browser-assisted variants may need extra local setup when Cloudflare blocks pure requests flows
