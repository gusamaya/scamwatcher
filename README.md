# ScamWatcher MVP

A lightweight MVP that reviews an email submission, assigns a simple scam risk score, and generates a reply draft.

## What it does
- accepts an email submission in a web form or JSON API
- checks for common scam indicators using a rule-based engine
- returns a risk rating, findings, recommended actions, and a reply email draft
- includes a generic inbound webhook endpoint you can connect to an email forwarding provider later

## Intended use
This is a **validation MVP**, not a production-grade detection engine. It is designed to help you test:
- whether people will forward suspicious emails
- which scam types appear most often
- whether the response format feels useful
- how much manual review is still required

## Quick start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
FLASK_DEBUG=1 python app.py
```

Then open `http://127.0.0.1:5000` and sign in. In production run `gunicorn app:app`.

## Settings (environment variables)
| Variable | Required | What it does |
|---|---|---|
| `ADMIN_PASSWORD` | **Yes** | Password for the dashboard. Login is disabled until it is set. |
| `ADMIN_USERNAME` | No | Dashboard username (default `admin`). |
| `SECRET_KEY` | **Yes** | Long random string used to sign login sessions. Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`. |
| `EMAIL_ADDRESS` / `EMAIL_PASSWORD` | Yes | Mailbox the inbox worker reads and replies from (use a Gmail app password). |
| `AUTO_SEND_ENABLED` | No | `false` by default, so every reply waits for "Approve & send". Set `true` only once you trust the scoring. |
| `MAX_SEND_ATTEMPTS` | No | How many times a failed reply is retried automatically (default `3`). |
| `SESSION_COOKIE_SECURE` | No | `true` by default (login cookie only sent over HTTPS). Set `false` only for local testing over plain HTTP if sign-in will not stick. |
| `DB_PATH` | No | SQLite database location (default `/var/data/scamwatcher.db`). |

## Suggested next steps
1. connect `check@scamwatcher.com.au` to an email forwarding service
2. store submissions in a database or spreadsheet
3. add a manual review queue before any user-facing auto-send
4. add domain reputation, attachment analysis, and lookalike-domain checks
5. tag submissions so you can build the pattern recognition feature later

## Important
Do not auto-send responses without a manual review step in the early MVP. False positives and false negatives matter in this category.
