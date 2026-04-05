import sqlite3
import json

DB_NAME = "scamwatcher.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(conn, table_name, column_name):
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(row["name"] == column_name for row in rows)


def ensure_columns():
    conn = get_connection()

    required_columns = {
        "response_status": "TEXT DEFAULT 'draft'",
        "sent_at": "TEXT",
        "submitter_name": "TEXT",
        "submitter_email": "TEXT",
        "submitter_from_header": "TEXT",
        "has_attachments": "INTEGER DEFAULT 0",
        "attachment_names": "TEXT",
        "attachment_signals": "TEXT",
    }

    for column_name, column_type in required_columns.items():
        if not column_exists(conn, "submissions", column_name):
            conn.execute(
                f"ALTER TABLE submissions ADD COLUMN {column_name} {column_type}"
            )

    conn.commit()
    conn.close()


def init_db():
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
    **kwargs,
):
    # Support older/flexible callers that may pass sender instead of from_header
    if (not from_header) and kwargs.get("sender"):
        from_header = kwargs.get("sender")

    cleaned_findings, findings_json = _normalise_findings_for_storage(findings)
    findings_count = len(cleaned_findings)

    attachment_names_json = _normalise_list_json(attachment_names)
    attachment_signals_json = _normalise_dict_json(attachment_signals)
    has_attachments_int = 1 if has_attachments else 0

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
            submitter_name,
            submitter_email,
            submitter_from_header,
            has_attachments,
            attachment_names,
            attachment_signals
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        "draft",
        None,
        submitter_name,
        submitter_email,
        submitter_from_header,
        has_attachments_int,
        attachment_names_json,
        attachment_signals_json,
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