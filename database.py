import json
import os
import sqlite3
from datetime import datetime

DB_NAME = os.getenv("DB_PATH", "/var/data/scamwatcher.db")


def get_connection():
    db_dir = os.path.dirname(DB_NAME)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    # Wait up to 30 seconds for another thread to finish writing instead of
    # failing straight away with "database is locked".
    conn = sqlite3.connect(DB_NAME, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def enable_wal():
    """Write-ahead logging: readers (the dashboard) never block the writer
    (the inbox checker) and the other way round. Persistent once set."""
    conn = sqlite3.connect(DB_NAME, timeout=30)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
    finally:
        conn.close()


def column_exists(conn, table_name, column_name):
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(row["name"] == column_name for row in rows)


def ensure_columns():
    conn = get_connection()

    required_columns = {
        "response_status": "TEXT DEFAULT 'draft'",
        "sent_at": "TEXT",
        "sent_to_email": "TEXT",
        "is_internal": "INTEGER DEFAULT 0",
        "exclude_from_calibration": "INTEGER DEFAULT 0",
        "submitter_name": "TEXT",
        "submitter_email": "TEXT",
        "submitter_from_header": "TEXT",
        "has_attachments": "INTEGER DEFAULT 0",
        "attachment_names": "TEXT",
        "attachment_signals": "TEXT",
        "response_error": "TEXT",
        "last_send_attempt_at": "TEXT",
        "send_attempts": "INTEGER DEFAULT 0",
        "submission_type": "TEXT",
        "forward_method": "TEXT",
        "review_checks": "TEXT",
        "scam_type": "TEXT",
        "scam_category": "TEXT",
        "country": "TEXT",
        "channel": "TEXT",
        "screenshot_files": "TEXT",
        "created_at": "TEXT",
        "screenshot_text": "TEXT",
        "auto_review": "TEXT",
        "auto_review_error": "TEXT",
        "verdict_note": "TEXT",
        "brand": "TEXT",
        "message_kind": "TEXT",
    }

    for column_name, column_type in required_columns.items():
        if not column_exists(conn, "submissions", column_name):
            conn.execute(
                f"ALTER TABLE submissions ADD COLUMN {column_name} {column_type}"
            )

    conn.commit()
    conn.close()


def init_db():
    get_connection().close()  # makes sure the folder exists
    enable_wal()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT UNIQUE,
            received_at TEXT,
            from_header TEXT,
            subject TEXT,
            body TEXT,
            risk_score INTEGER,
            risk_rating TEXT,
            summary TEXT,
            human_summary TEXT,
            findings TEXT,
            findings_count INTEGER,
            recommended_action TEXT,
            proposed_response TEXT,
            should_reply INTEGER,
            confidence_label TEXT,
            confidence_reason TEXT
        )
    """)

    conn.commit()
    conn.close()

    ensure_columns()


def _normalise_findings_for_storage(findings):
    if not findings:
        return [], "[]"

    if isinstance(findings, list):
        cleaned = []
        for item in findings:
            if item is None:
                continue
            text = str(item).strip()
            if text:
                cleaned.append(text)
        return cleaned, json.dumps(cleaned)

    if isinstance(findings, str):
        try:
            parsed = json.loads(findings)
            if isinstance(parsed, list):
                cleaned = []
                for item in parsed:
                    if item is None:
                        continue
                    text = str(item).strip()
                    if text:
                        cleaned.append(text)
                return cleaned, json.dumps(cleaned)
        except Exception:
            pass

        text = findings.strip()
        cleaned = [text] if text else []
        return cleaned, json.dumps(cleaned)

    cleaned = [str(findings).strip()] if str(findings).strip() else []
    return cleaned, json.dumps(cleaned)


def _normalise_list_json(value):
    if not value:
        return "[]"

    if isinstance(value, list):
        cleaned = []
        for item in value:
            if item is None:
                continue
            text = str(item).strip()
            if text:
                cleaned.append(text)
        return json.dumps(cleaned)

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                cleaned = []
                for item in parsed:
                    if item is None:
                        continue
                    text = str(item).strip()
                    if text:
                        cleaned.append(text)
                return json.dumps(cleaned)
        except Exception:
            pass

        cleaned = [item.strip() for item in value.split(",") if item.strip()]
        return json.dumps(cleaned)

    return "[]"


def _normalise_dict_json(value):
    if not value:
        return "{}"

    if isinstance(value, dict):
        return json.dumps(value)

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return json.dumps(parsed)
        except Exception:
            pass

    return "{}"


def insert_submission(
    message_id,
    received_at,
    from_header,
    subject,
    body,
    risk_score,
    risk_rating,
    summary,
    human_summary,
    findings,
    recommended_action,
    proposed_response,
    should_reply,
    confidence_label=None,
    confidence_reason=None,
    submitter_name=None,
    submitter_email=None,
    submitter_from_header=None,
    has_attachments=0,
    attachment_names=None,
    attachment_signals=None,
    submission_type=None,
    forward_method=None,
    review_checks=None,
    scam_type=None,
    scam_category=None,
    country=None,
    channel=None,
    screenshot_files=None,
    needs_manual_review=False,
    verdict_note=None,
    brand=None,
    message_kind=None,
    **kwargs,
):
    if (not from_header) and kwargs.get("sender"):
        from_header = kwargs.get("sender")

    cleaned_findings, findings_json = _normalise_findings_for_storage(findings)
    findings_count = len(cleaned_findings)

    attachment_names_json = _normalise_list_json(attachment_names)
    attachment_signals_json = _normalise_dict_json(attachment_signals)
    has_attachments_int = 1 if has_attachments else 0

    # Emails sent straight to our address (not forwarded by a person) are held:
    # the "sender" is usually the scammer, so we must never reply automatically.
    # Screenshots can't be read by the rule-based checks, so anything that
    # depends on an image waits for a person to write the reply.
    if submission_type == "direct":
        response_status = "held"
    elif needs_manual_review:
        response_status = "manual"
    else:
        response_status = "draft"

    screenshot_files_json = _normalise_list_json(screenshot_files)
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    if isinstance(review_checks, (list, dict)):
        review_checks_json = json.dumps(review_checks)
    elif isinstance(review_checks, str) and review_checks.strip():
        review_checks_json = review_checks
    else:
        review_checks_json = "[]"

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO submissions (
            message_id,
            received_at,
            from_header,
            subject,
            body,
            risk_score,
            risk_rating,
            summary,
            human_summary,
            findings,
            findings_count,
            recommended_action,
            proposed_response,
            should_reply,
            confidence_label,
            confidence_reason,
            response_status,
            sent_at,
            sent_to_email,
            is_internal,
            exclude_from_calibration,
            submitter_name,
            submitter_email,
            submitter_from_header,
            has_attachments,
            attachment_names,
            attachment_signals,
            response_error,
            last_send_attempt_at,
            send_attempts,
            submission_type,
            forward_method,
            review_checks,
            scam_type,
            scam_category,
            country,
            channel,
            screenshot_files,
            created_at,
            verdict_note,
            brand,
            message_kind
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        message_id,
        received_at,
        from_header,
        subject,
        body,
        risk_score,
        risk_rating,
        summary,
        human_summary,
        findings_json,
        findings_count,
        recommended_action,
        proposed_response,
        1 if should_reply else 0,
        confidence_label,
        confidence_reason,
        response_status,
        None,
        None,
        0,
        0,
        submitter_name,
        submitter_email,
        submitter_from_header,
        has_attachments_int,
        attachment_names_json,
        attachment_signals_json,
        None,
        None,
        0,
        submission_type,
        forward_method,
        review_checks_json,
        scam_type or None,
        scam_category or None,
        country or None,
        channel or None,
        screenshot_files_json,
        created_at,
        verdict_note or None,
        brand or None,
        message_kind or None,
    ))

    conn.commit()
    conn.close()


def get_submission_by_message_id(message_id):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM submissions WHERE message_id = ?",
        (message_id,)
    ).fetchone()
    conn.close()
    return row


def submission_exists(message_id):
    return get_submission_by_message_id(message_id) is not None


def submission_exists_by_message_id(message_id):
    return get_submission_by_message_id(message_id) is not None


def get_all_submissions():
    conn = get_connection()
    rows = conn.execute("""
        SELECT *
        FROM submissions
        ORDER BY datetime(received_at) DESC
    """).fetchall()
    conn.close()
    return rows
