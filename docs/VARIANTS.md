# VARIANTS

## `bot.py`

The most feature-rich public entry point.

Key traits:
- single-coin flow
- explicit Cloudflare detection helpers
- browser bridge for requests-to-browser cookie syncing
- optional headless control through env vars

Use this when you want the strongest resilience path.

## `botNew.py`

A lighter alternate single-coin implementation.

Use this when you want a simpler script path without the extra multi-coin expansion.

## `botNew2.py`

Multi-coin mode in one session.

Instead of a single `CRYPTOWRS_CURRENCY`, this variant reads `CRYPTOWRS_CURRENCIES` and iterates across several symbols such as `BCH`, `LTC`, and `DOGE` in one run.

## Shared public pattern

All three variants now share the same safe-public assumptions:

- wallet identity comes from environment variables
- debug/runtime artifacts stay local
- browser-helper state is not committed

That makes the repo reusable as a code reference without leaking the original live faucet identity.
