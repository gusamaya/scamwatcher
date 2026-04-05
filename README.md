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
uvicorn app:app --reload
```

Then open:
- `http://127.0.0.1:8000`

## API example
```bash
curl -X POST http://127.0.0.1:8000/api/review \
  -H 'Content-Type: application/json' \
  -d '{
    "from_header": "\"Telstra Billing\" <notice@gmail.com>",
    "subject": "Final notice: your account will be suspended",
    "body": "Dear customer, click here to verify your account immediately.",
    "target_audience": "general"
  }'
```

## Suggested next steps
1. connect `check@scamwatcher.com.au` to an email forwarding service
2. store submissions in a database or spreadsheet
3. add a manual review queue before any user-facing auto-send
4. add domain reputation, attachment analysis, and lookalike-domain checks
5. tag submissions so you can build the pattern recognition feature later

## Important
Do not auto-send responses without a manual review step in the early MVP. False positives and false negatives matter in this category.
