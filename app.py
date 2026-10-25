import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
import sys
import threading
import time
from datetime import datetime
from email.message import EmailMessage

from flask import Flask, render_template, request, redirect, url_for, abort, flash, session
from dotenv import load_dotenv

load_dotenv()

# Write log lines immediately. Without this, output from background threads can
# sit in a buffer and never appear in the hosting provider's logs.
try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except Exception:
    pass

DB_NAME = os.getenv("DB_PATH", "/var/data/scamwatcher.db")
AUDIT_BCC_EMAIL = "scamwatcher.audit@gmail.com"

# Off by default: replies wait in the dashboard until an admin clicks
# "Approve & send". Set AUTO_SEND_ENABLED=true only once you trust the scoring.
AUTO_SEND_ENABLED = os.getenv("AUTO_SEND_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
AUTO_SEND_INTERVAL_SECONDS = int(os.getenv("AUTO_SEND_INTERVAL_SECONDS", "15"))
MAX_SEND_ATTEMPTS = int(os.getenv("MAX_SEND_ATTEMPTS", "3"))
# A submission left in "sending" this long (e.g. the server restarted mid-send)
# is treated as failed so it can be retried or reviewed.
STUCK_SENDING_MINUTES = int(os.getenv("STUCK_SENDING_MINUTES", "10"))

INBOX_WORKER_ENABLED = os.getenv("INBOX_WORKER_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}

# Dashboard login. Set ADMIN_PASSWORD (and optionally ADMIN_USERNAME) in your
# environment. If ADMIN_PASSWORD is missing the dashboard refuses all logins.
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

app = Flask(__name__)

_secret_key = os.getenv("SECRET_KEY", "").strip()
if not _secret_key:
    # A random key keeps sessions secure, but everyone is logged out whenever the
    # server restarts. Set SECRET_KEY in your environment to avoid that.
    _secret_key = secrets.token_hex(32)
    print("[Security] SECRET_KEY is not set; using a temporary random key.")
app.secret_key = _secret_key

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "true").strip().lower() in {"1", "true", "yes", "on"},
)

_auto_send_thread_started = False
_inbox_worker_thread_started = False

# In-memory admin review flags for MVP only.
# Values: "unreviewed", "correct", "review_required"
_review_flags = {}
_review_lock = threading.Lock()


def get_connection():
    db_dir = os.path.dirname(DB_NAME)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(DB_NAME, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def get_review_status(submission_id):
    with _review_lock:
        return _review_flags.get(int(submission_id), "unreviewed")


def set_review_status(submission_id, status):
    submission_id = int(submission_id)
    normalized = (status or "").strip().lower()

    if normalized not in {"unreviewed", "correct", "review_required"}:
        normalized = "unreviewed"

    with _review_lock:
        if normalized == "unreviewed":
            _review_flags.pop(submission_id, None)
        else:
            _review_flags[submission_id] = normalized


def review_status_label(status):
    status = (status or "unreviewed").strip().lower()
    if status == "correct":
        return "Appears Correct"
    if status == "review_required":
        return "Review Required"
    return "Unreviewed"


def parse_findings(value):
    if not value:
        return []

    if isinstance(value, list):
        return value

    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else [value]
    except Exception:
        return [value]


def clean_finding_text(text):
    if text is None:
        return ""

    cleaned = str(text).strip()
    cleaned = cleaned.strip("[]").strip()
    cleaned = cleaned.strip("'").strip('"')
    return cleaned


def split_combined_finding_text(text):
    text = clean_finding_text(text)
    if not text:
        return []

    if "', '" in text or '", "' in text:
        parts = re.split(r"""['"]\s*,\s*['"]""", text)
        cleaned_parts = []
        for part in parts:
            item = clean_finding_text(part)
            if item:
                cleaned_parts.append(item)
        if cleaned_parts:
            return cleaned_parts

    sentence_splits = re.split(r"\.\s+(?=[A-Z])", text)
    if len(sentence_splits) > 1:
        cleaned_parts = []
        for part in sentence_splits:
            item = part.strip()
            if not item:
                continue
            if not item.endswith("."):
                item += "."
            cleaned_parts.append(item)
        if cleaned_parts:
            return cleaned_parts

    return [text]


def normalize_findings(value):
    raw_findings = parse_findings(value)
    cleaned_findings = []

    for item in raw_findings:
        parts = split_combined_finding_text(item)
        for part in parts:
            if part:
                cleaned_findings.append(part)

    seen = set()
    deduped = []
    for item in cleaned_findings:
        key = item.strip().lower()
        if key and key not in seen:
            seen.add(key)
            deduped.append(item)

    return deduped


def parse_json_list(value):
    if not value:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return parsed
            if parsed:
                return [parsed]
        except Exception:
            pass

        cleaned = [item.strip() for item in value.split(",") if item.strip()]
        return cleaned

    return []


def parse_json_dict(value):
    if not value:
        return {}

    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    return {}


def normalize_attachment_names(value):
    names = parse_json_list(value)
    cleaned = []

    for name in names:
        if name:
            cleaned.append(str(name).strip())

    seen = set()
    deduped = []
    for name in cleaned:
        key = name.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(name)

    return deduped


def normalize_attachment_signals(value):
    signals = parse_json_dict(value)

    if not isinstance(signals, dict):
        return {}

    findings = signals.get("attachment_findings", [])
    if isinstance(findings, str):
        findings = [findings]
    elif not isinstance(findings, list):
        findings = []

    cleaned_findings = []
    seen = set()
    for item in findings:
        if not item:
            continue
        text = str(item).strip()
        key = text.lower()
        if key not in seen:
            seen.add(key)
            cleaned_findings.append(text)

    signals["attachment_findings"] = cleaned_findings
    return signals


def extract_email(from_header):
    if not from_header:
        return ""
    match = re.search(r"<([^>]+)>", from_header)
    if match:
        return match.group(1).strip()
    match = re.search(r"([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})", from_header, re.I)
    return match.group(1).strip() if match else ""


def column_exists(conn, table_name, column_name):
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(row["name"] == column_name for row in rows)


def ensure_schema():
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
    }

    for column_name, column_type in required_columns.items():
        if not column_exists(conn, "submissions", column_name):
            conn.execute(f"ALTER TABLE submissions ADD COLUMN {column_name} {column_type}")

    conn.commit()
    conn.close()


def prepare_submission_record(data):
    if not data:
        return None

    data["findings"] = normalize_findings(data.get("findings"))
    data["is_internal"] = int(data.get("is_internal") or 0)
    data["exclude_from_calibration"] = int(data.get("exclude_from_calibration") or 0)
    data["has_attachments"] = int(data.get("has_attachments") or 0)
    data["attachment_names"] = normalize_attachment_names(data.get("attachment_names"))
    data["attachment_signals"] = normalize_attachment_signals(data.get("attachment_signals"))

    try:
        checks = json.loads(data.get("review_checks") or "[]")
        data["review_checks"] = checks if isinstance(checks, list) else []
    except Exception:
        data["review_checks"] = []

    if data["attachment_names"]:
        data["has_attachments"] = 1

    return data


def get_submission(submission_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM submissions WHERE id = ?", (submission_id,)).fetchone()
    conn.close()

    if not row:
        return None

    submission = prepare_submission_record(dict(row))
    submission["review_status"] = get_review_status(submission_id)
    submission["review_status_label"] = review_status_label(submission["review_status"])
    return submission


def get_mail_config():
    username = (
        os.getenv("EMAIL_ADDRESS")
        or os.getenv("EMAIL_ACCOUNT")
        or os.getenv("SMTP_USERNAME")
    )

    password = (
        os.getenv("EMAIL_PASSWORD")
        or os.getenv("APP_PASSWORD")
        or os.getenv("SMTP_PASSWORD")
    )

    return username, password


def html_escape(text):
    if text is None:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def make_reference_code(submission_id):
    try:
        return f"SW-{int(submission_id):05d}"
    except Exception:
        return f"SW-{submission_id}"


def sanitize_preview(text, max_length=700):
    if not text:
        return "No message excerpt available."

    preview = str(text)
    preview = re.sub(r"https?://\S+", "[link removed]", preview, flags=re.I)
    preview = re.sub(r"www\.\S+", "[link removed]", preview, flags=re.I)
    preview = re.sub(r"\s+", " ", preview).strip()

    if not preview:
        return "No message excerpt available."

    if len(preview) > max_length:
        preview = preview[: max_length - 3].rstrip() + "..."

    return preview


def build_attachment_insight_lines(submission):
    attachment_names = submission.get("attachment_names") or []
    attachment_signals = submission.get("attachment_signals") or {}
    has_attachments = bool(submission.get("has_attachments")) or bool(attachment_names)

    if not has_attachments:
        return []

    lines = []

    if attachment_names:
        lines.append(f"Attachment(s) detected: {', '.join(attachment_names[:3])}.")
    else:
        lines.append("One or more attachments were detected in this email.")

    if attachment_signals.get("pdf_present"):
        lines.append("The attachment is the primary risk area in this email.")

    if attachment_signals.get("updated_payment_details_present"):
        lines.append("The attachment appears to request updated or changed banking details.")
    elif attachment_signals.get("payment_instructions_present"):
        lines.append("The attachment appears to request payment or transfer of funds.")
    elif attachment_signals.get("sensitive_info_request_present"):
        lines.append("The attachment appears to request personal or identity information.")
    elif attachment_signals.get("invoice_like_document"):
        lines.append("The attachment appears to be an invoice or payment request.")
    elif attachment_signals.get("receipt_like_document"):
        lines.append("The attachment appears to be a receipt or remittance notice.")

    if attachment_signals.get("bank_details_present") and not attachment_signals.get("payment_instructions_present"):
        lines.append("The attachment includes bank or account details.")

    if attachment_signals.get("attachment_identity_mismatch"):
        lines.append("The business identity in the attachment does not clearly match the sender.")

    if attachment_signals.get("urgency_in_attachment"):
        lines.append("The attachment uses urgency or pressure language.")

    if attachment_signals.get("attachment_only_action_pattern"):
        lines.append("The main request appears to be inside the attachment rather than the email body.")

    if len(lines) <= 2:
        lines.append("The attachment did not show strong standalone warning signs based on the available review.")

    seen = set()
    deduped = []
    for line in lines:
        key = line.lower().strip()
        if key not in seen:
            seen.add(key)
            deduped.append(line)

    return deduped


def build_html_email(submission):
    risk = submission.get("risk_rating") or "Needs Attention"
    action = submission.get("recommended_action") or ""
    findings = normalize_findings(submission.get("findings") or [])
    reference_code = make_reference_code(submission.get("id"))
    attachment_lines = build_attachment_insight_lines(submission)

    risk_lower = risk.lower()
    if "high" in risk_lower:
        risk_color = "#b91c1c"
    elif "attention" in risk_lower:
        risk_color = "#b45309"
    else:
        risk_color = "#1d4ed8"

    findings_items = ""
    for finding in findings[:5]:
        findings_items += f"<li>{html_escape(finding)}</li>"

    if not findings_items:
        findings_items = "<li>No findings available.</li>"

    attachment_items = ""
    for line in attachment_lines[:5]:
        attachment_items += f"<li>{html_escape(line)}</li>"

    attachment_box = ""
    if attachment_items:
        attachment_box = f"""
            <div style="background:#f9fafb; border:1px solid #e5e7eb; border-radius:10px; padding:14px 16px; margin:0 0 22px 0;">
                <div style="font-size:14px; font-weight:700; color:#111827; margin-bottom:8px;">
                    Attachment Insight:
                </div>
                <ul style="margin:0 0 0 20px; padding:0; color:#111827; line-height:1.6;">
                    {attachment_items}
                </ul>
            </div>
        """

    if "low" in risk.lower():
        guidance_strong = "No immediate action is required. If this message is not relevant, it can be safely ignored."
        guidance = "If you are considering engaging, ensure any response or action is appropriate for your situation."
    elif "high" in risk.lower():
        if attachment_lines:
            guidance_strong = "Do not open the attachment, click any links, or act on this email unless it has been independently verified."
        else:
            guidance_strong = "Do not click any links, reply, or act on this email unless it has been independently verified."
        guidance = "Verify any request using contact details sourced independently from the email, and do not rely on any attachment without verification."
    else:
        guidance_strong = "We recommend not taking action until this request has been independently verified."
        guidance = "Verify any request using contact details sourced independently from the email, and do not rely on any attachment without verification."

    original_from = html_escape(submission.get("from_header") or "Unknown sender")
    original_subject = html_escape(submission.get("subject") or "(No subject)")
    original_received = html_escape(submission.get("received_at") or "Unknown")
    original_excerpt = html_escape(sanitize_preview(submission.get("body") or ""))
    attachment_names = submission.get("attachment_names") or []

    divider = "-" * 112

    status_styles = {
        "fail": ("Warning", "#fef2f2", "#991b1b", "#fecaca"),
        "caution": ("Caution", "#fffbeb", "#92400e", "#fde68a"),
        "pass": ("OK", "#f0fdf4", "#166534", "#bbf7d0"),
        "info": ("Info", "#eff6ff", "#1d4ed8", "#bfdbfe"),
    }
    check_rows = ""
    for check in submission.get("review_checks") or []:
        label, bg, fg, border = status_styles.get(check.get("status"), status_styles["info"])
        check_rows += f"""
                <tr>
                    <td valign="top" style="padding:8px 10px 8px 0; font-weight:700; color:#111827; white-space:nowrap;">{html_escape(check.get("title"))}</td>
                    <td valign="top" style="padding:8px 10px;"><span style="display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:700; background:{bg}; color:{fg}; border:1px solid {border};">{label}</span></td>
                    <td valign="top" style="padding:8px 0; color:#111827;">{html_escape(check.get("headline"))}</td>
                </tr>"""
    checks_box = ""
    if check_rows:
        checks_box = f"""
            <div style="font-size:14px; font-weight:700; color:#111827; margin-bottom:6px;">How we checked it:</div>
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="border-collapse:collapse; margin:0 0 22px 0; font-size:14px; line-height:1.5;">
                {check_rows}
            </table>
        """

    tip_box = ""
    for check in submission.get("review_checks") or []:
        if check.get("key") == "known_scams" and check.get("status") in ("fail", "caution") and check.get("details"):
            tip_box = f"""
            <div style="background:#eff6ff; border:1px solid #bfdbfe; border-radius:10px; padding:12px 14px; margin:0 0 22px 0; color:#1e3a8a; font-size:14px; line-height:1.6;">
                <strong>Tip:</strong> {html_escape(check["details"][-1])}
            </div>
            """

    scam_type_box = ""
    if submission.get("scam_type"):
        scam_type_box = f"""
            <div style="font-size:14px; font-weight:700; color:#111827; margin-bottom:4px;">Likely scam type:</div>
            <div style="font-size:14px; color:#991b1b; font-weight:700; margin-bottom:14px;">{html_escape(submission.get("scam_type"))}</div>
        """

    original_attachment_block = ""
    if attachment_names:
        original_attachment_block = f"""
                <div style="margin-top:10px;"><strong>Attachments:</strong> {html_escape(', '.join(attachment_names[:5]))}</div>
        """

    return f"""
    <html>
    <body style="margin:0; padding:20px; background:#ffffff; font-family:Arial, sans-serif; font-size:14px; color:#111827; line-height:1.6;">
        <div style="max-width:640px; margin:0 auto;">

            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="border-collapse:collapse; margin-bottom:24px;">
                <tr>
                    <td valign="top" style="font-size:20px; font-weight:700; color:#0f2d5c;">
                        ScamWatcher
                    </td>
                    <td valign="top" align="right" style="font-size:11px; font-weight:500; color:#6b7280; line-height:1.2; white-space:nowrap;">
                        Helping people stay safe in a digital world
                    </td>
                </tr>
            </table>

            <div style="font-size:14px; color:#111827; margin-bottom:10px;">Hi there,</div>

            <div style="font-size:14px; color:#111827; margin-bottom:18px;">
                You requested this review via ScamWatcher — outcome details are below.
            </div>

            <div style="font-size:13px; color:#6b7280; margin-bottom:18px;">
                Reference: <strong>{html_escape(reference_code)}</strong>
            </div>

            <div style="font-size:14px; font-weight:700; color:#111827; margin-bottom:4px;">
                Assessment result:
            </div>
            <div style="font-size:14px; font-weight:700; color:{risk_color}; margin-bottom:14px;">
                {html_escape(risk)}.
            </div>

            {scam_type_box}

            <div style="font-size:14px; font-weight:700; color:#111827; margin-bottom:4px;">
                Recommended Action:
            </div>
            <div style="font-size:14px; font-weight:700; color:#0f4c8a; margin-bottom:28px;">
                {html_escape(action)}
            </div>

            {checks_box}

            <div style="font-size:14px; font-weight:700; color:#111827; margin-bottom:8px;">
                What ScamWatcher observed:
            </div>
            <ul style="margin:0 0 22px 20px; padding:0; color:#111827;">
                {findings_items}
            </ul>

            {attachment_box}

            {tip_box}

            <div style="font-size:14px; line-height:1.7; font-weight:700; font-style:italic; color:#111827; margin-bottom:12px;">
                {html_escape(guidance_strong)}
            </div>

            <div style="font-size:14px; line-height:1.7; color:#111827; margin-bottom:34px;">
                {html_escape(guidance)}
            </div>

            <div style="font-size:14px; color:#111827; margin-bottom:10px;">Regards,</div>
            <div style="font-size:14px; font-weight:700; color:#111827;">Serena</div>
            <div style="font-size:14px; color:#111827; margin-top:6px;">ScamWatcher Advisor</div>
            <div style="font-size:12px; color:#111827; margin-top:8px;">
                Independent advisory service.
            </div>

            <div style="margin-top:28px; margin-bottom:18px; font-size:12px; line-height:1.4; color:#6b7280; white-space:pre-wrap; word-break:break-word; overflow-wrap:anywhere;">{divider}</div>

            <div style="margin-top:0; font-size:14px; font-weight:700; color:#111827; margin-bottom:8px;">
                Original Email (for reference)
            </div>
            <div style="font-size:13px; line-height:1.6; color:#374151;">
                <div><strong>Reference:</strong> {html_escape(reference_code)}</div>
                <div><strong>From:</strong> {original_from}</div>
                <div><strong>Subject:</strong> {original_subject}</div>
                <div><strong>Received:</strong> {original_received}</div>
                {original_attachment_block}
                <div style="margin-top:10px;"><strong>Original Message Excerpt:</strong> {original_excerpt}</div>
                <div style="margin-top:8px; font-size:12px; color:#6b7280;">
                    Links have been removed from this reply for safety.
                </div>
            </div>

        </div>
    </body>
    </html>
    """


def send_email(to, subject, body, html_body=None, bcc=None):
    username, password = get_mail_config()

    if not username or not password:
        raise RuntimeError("Email credentials not configured.")

    msg = EmailMessage()
    msg["From"] = username
    msg["To"] = to
    msg["Subject"] = subject

    recipients = [to]

    if bcc:
        if isinstance(bcc, (list, tuple, set)):
            bcc_list = [email.strip() for email in bcc if email and str(email).strip()]
        else:
            bcc_list = [email.strip() for email in str(bcc).split(",") if email.strip()]
        recipients.extend(bcc_list)

    msg.set_content(body or "ScamWatcher review attached.")

    if html_body:
        msg.add_alternative(html_body, subtype="html")

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(username, password)
        server.send_message(msg, to_addrs=recipients)


def is_excluded_submission(submission):
    if not submission:
        return False
    return bool(
        int(submission.get("is_internal") or 0)
        or int(submission.get("exclude_from_calibration") or 0)
    )


def resolve_submission_recipient(submission):
    return (
        submission.get("submitter_email")
        or extract_email(submission.get("submitter_from_header", ""))
        or extract_email(submission.get("from_header", ""))
    )


def can_auto_send_submission(submission):
    if not submission:
        return False, "Submission not found."

    if is_excluded_submission(submission):
        return False, "Submission is marked internal/excluded."

    if not submission.get("proposed_response"):
        return False, "No proposed response available."

    if not resolve_submission_recipient(submission):
        return False, "No recipient email address found."

    status = (submission.get("response_status") or "draft").strip().lower()
    if status == "sent":
        return False, "Already sent."

    return True, ""


def mark_sent(submission_id, sent_to_email):
    conn = get_connection()
    conn.execute(
        """
        UPDATE submissions
        SET response_status = ?,
            sent_at = ?,
            sent_to_email = ?,
            response_error = NULL
        WHERE id = ?
        """,
        ("sent", now(), sent_to_email, submission_id),
    )
    conn.commit()
    conn.close()


def mark_failed(submission_id, error_message):
    conn = get_connection()
    conn.execute(
        """
        UPDATE submissions
        SET response_status = ?,
            response_error = ?
        WHERE id = ?
        """,
        ("failed", str(error_message)[:1000], submission_id),
    )
    conn.commit()
    conn.close()


def try_claim_submission_for_sending(submission_id):
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT id, response_status
            FROM submissions
            WHERE id = ?
            """,
            (submission_id,),
        ).fetchone()

        if not row:
            conn.rollback()
            return False

        status = (row["response_status"] or "draft").strip().lower()
        if status in {"sent", "sending"}:
            conn.rollback()
            return False

        updated = conn.execute(
            """
            UPDATE submissions
            SET response_status = ?,
                last_send_attempt_at = ?,
                send_attempts = COALESCE(send_attempts, 0) + 1
            WHERE id = ?
              AND COALESCE(response_status, 'draft') NOT IN ('sent', 'sending')
            """,
            ("sending", now(), submission_id),
        )

        if updated.rowcount != 1:
            conn.rollback()
            return False

        conn.commit()
        return True
    except Exception:
        conn.rollback()
        return False
    finally:
        conn.close()


def send_submission_response(submission_id, manual=False):
    submission = get_submission(submission_id)
    allowed, reason = can_auto_send_submission(submission)

    if not allowed:
        return False, reason

    if not try_claim_submission_for_sending(submission_id):
        return False, "Submission already being processed or already sent."

    submission = get_submission(submission_id)
    to_email = resolve_submission_recipient(submission)

    try:
        html_body = build_html_email(submission)
        reference_code = make_reference_code(submission.get("id"))
        original_subject = submission.get("subject") or "Submitted Email"

        send_email(
            to=to_email,
            subject=f"ScamWatcher Review – {reference_code} – {original_subject}",
            body=submission.get("proposed_response") or "ScamWatcher review attached.",
            html_body=html_body,
            bcc=AUDIT_BCC_EMAIL,
        )

        mark_sent(submission_id, to_email)
        return True, f"Reply sent to {to_email}."

    except Exception as exc:
        mark_failed(submission_id, exc)
        return False, f"Failed to send response: {str(exc)}"


def get_pending_auto_send_ids(limit=25):
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT id
        FROM submissions
        WHERE COALESCE(is_internal, 0) = 0
          AND COALESCE(exclude_from_calibration, 0) = 0
          AND COALESCE(response_status, 'draft') IN ('draft', 'failed')
          AND COALESCE(proposed_response, '') <> ''
          AND COALESCE(send_attempts, 0) < ?
          -- Only ever auto-reply to people who forwarded an email to us. Direct
          -- emails (and older records saved before this was tracked) need a
          -- person to click "Approve and Send".
          AND submission_type = 'forwarded'
        ORDER BY datetime(received_at) ASC, id ASC
        LIMIT ?
        """,
        (MAX_SEND_ATTEMPTS, limit),
    ).fetchall()
    conn.close()
    return [row["id"] for row in rows]


def release_stuck_sending():
    conn = get_connection()
    conn.execute(
        """
        UPDATE submissions
        SET response_status = 'failed',
            response_error = 'Send was interrupted (server restart or crash). Check before resending.'
        WHERE response_status = 'sending'
          AND datetime(last_send_attempt_at) < datetime('now', ?)
        """,
        (f"-{STUCK_SENDING_MINUTES} minutes",),
    )
    conn.commit()
    conn.close()


def auto_send_pending_submissions():
    if not AUTO_SEND_ENABLED:
        return

    release_stuck_sending()

    pending_ids = get_pending_auto_send_ids(limit=25)
    for submission_id in pending_ids:
        send_submission_response(submission_id, manual=False)


def auto_send_worker_loop():
    while True:
        try:
            auto_send_pending_submissions()
        except Exception as exc:
            print(f"[AutoSend] Error: {exc}")
        time.sleep(max(5, AUTO_SEND_INTERVAL_SECONDS))


def start_auto_send_thread():
    global _auto_send_thread_started

    if _auto_send_thread_started or not AUTO_SEND_ENABLED:
        return

    thread = threading.Thread(target=auto_send_worker_loop, daemon=True)
    thread.start()
    _auto_send_thread_started = True
    print(f"[AutoSend] Started. Interval: {AUTO_SEND_INTERVAL_SECONDS}s")


def start_inbox_worker_thread():
    global _inbox_worker_thread_started

    if _inbox_worker_thread_started:
        return

    if not INBOX_WORKER_ENABLED:
        print("[InboxWorker] Not started: INBOX_WORKER_ENABLED is set to false, so this service will not check the inbox.", flush=True)
        _inbox_worker_thread_started = True  # only log once
        return

    try:
        import inbox_worker
    except Exception as exc:
        print(f"[InboxWorker] Import failed: {exc}")
        return

    def _run_worker():
        try:
            print("[InboxWorker] Starting embedded inbox worker thread...")
            inbox_worker.main()
        except Exception as exc:
            print(f"[InboxWorker] Worker stopped due to error: {exc}")

    thread = threading.Thread(target=_run_worker, daemon=True)
    thread.start()
    _inbox_worker_thread_started = True
    print("[InboxWorker] Embedded worker thread started.")


def start_background_threads():
    start_auto_send_thread()
    start_inbox_worker_thread()


def get_filter_counts():
    """Number of submissions in each dashboard view, for the sidebar."""
    conn = get_connection()
    row = conn.execute(
        """
        SELECT
            COUNT(*) AS all_count,
            SUM(CASE WHEN LOWER(COALESCE(response_status, 'draft')) IN ('draft', 'sending') THEN 1 ELSE 0 END) AS pending,
            SUM(CASE WHEN LOWER(COALESCE(response_status, '')) = 'sent' THEN 1 ELSE 0 END) AS sent,
            SUM(CASE WHEN submission_type = 'direct' OR LOWER(COALESCE(response_status, '')) = 'held' THEN 1 ELSE 0 END) AS direct,
            SUM(CASE WHEN LOWER(COALESCE(response_status, '')) = 'failed' THEN 1 ELSE 0 END) AS failed,
            SUM(CASE WHEN LOWER(risk_rating) = 'high risk' THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN LOWER(risk_rating) = 'needs attention' THEN 1 ELSE 0 END) AS attention,
            SUM(CASE WHEN LOWER(risk_rating) = 'low risk' THEN 1 ELSE 0 END) AS low
        FROM submissions
        WHERE COALESCE(is_internal, 0) = 0
          AND COALESCE(exclude_from_calibration, 0) = 0
        """
    ).fetchone()
    conn.close()
    return {
        "all": row["all_count"] or 0,
        "pending": row["pending"] or 0,
        "sent": row["sent"] or 0,
        "direct": row["direct"] or 0,
        "failed": row["failed"] or 0,
        "high": row["high"] or 0,
        "attention": row["attention"] or 0,
        "low": row["low"] or 0,
    }


def get_submissions(filter_value):
    conn = get_connection()

    query = """
        SELECT *
        FROM submissions
        WHERE COALESCE(is_internal, 0) = 0
          AND COALESCE(exclude_from_calibration, 0) = 0
    """

    if filter_value == "high":
        query += " AND LOWER(risk_rating)='high risk'"
    elif filter_value == "attention":
        query += " AND LOWER(risk_rating)='needs attention'"
    elif filter_value == "low":
        query += " AND LOWER(risk_rating)='low risk'"
    elif filter_value == "sent":
        query += " AND LOWER(COALESCE(response_status, 'draft'))='sent'"
    elif filter_value == "failed":
        query += " AND LOWER(COALESCE(response_status, 'draft'))='failed'"
    elif filter_value == "pending":
        query += " AND LOWER(COALESCE(response_status, 'draft')) IN ('draft', 'sending')"
    elif filter_value == "direct":
        query += " AND (submission_type = 'direct' OR LOWER(COALESCE(response_status, '')) = 'held')"

    query += " ORDER BY datetime(received_at) DESC, id DESC"

    rows = conn.execute(query).fetchall()
    conn.close()

    results = []
    for row in rows:
        item = prepare_submission_record(dict(row))
        item["review_status"] = get_review_status(item.get("id"))
        item["review_status_label"] = review_status_label(item["review_status"])
        results.append(item)

    return results


ensure_schema()

# Start the inbox checker and auto-sender as soon as the app loads, so emails
# are processed even if nobody has opened the dashboard since the last deploy.
# (Under the Flask debug reloader, only the child process starts them.)
if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not os.environ.get("FLASK_DEBUG"):
    start_background_threads()


# ------------------------------------------------------------------
# Login and CSRF protection
# ------------------------------------------------------------------

PUBLIC_ENDPOINTS = {"login", "static"}


def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = get_csrf_token
app.jinja_env.globals["auto_send_enabled"] = AUTO_SEND_ENABLED


@app.template_filter("clean_sender")
def clean_sender(value):
    """'"Linkt" <a@b.com>' -> 'Linkt <a@b.com>' for display."""
    return re.sub(r'\s+', ' ', str(value or "").replace('"', "")).strip()


def _credentials_valid(username, password):
    if not ADMIN_PASSWORD:
        return False
    user_ok = hmac.compare_digest((username or "").encode(), ADMIN_USERNAME.encode())
    pass_ok = hmac.compare_digest((password or "").encode(), ADMIN_PASSWORD.encode())
    return user_ok and pass_ok


@app.before_request
def require_login_and_csrf():
    # Start the inbox/send workers on the first request of any kind, including
    # logged-out visits and health checks, before any redirect can skip it.
    warm_background_threads()

    if request.method == "POST":
        sent_token = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent_token, expected):
            abort(400, "Your session expired or the form was invalid. Please go back and try again.")

    if request.endpoint in PUBLIC_ENDPOINTS:
        return None

    if not session.get("logged_in"):
        return redirect(url_for("login", next=request.path))

    return None


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


_failed_logins = {}
_failed_logins_lock = threading.Lock()
MAX_LOGIN_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 15 * 60


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    client = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()

    if not ADMIN_PASSWORD:
        error = "Login is disabled because ADMIN_PASSWORD is not set on the server."

    elif request.method == "POST":
        with _failed_logins_lock:
            count, first = _failed_logins.get(client, (0, time.time()))
            if time.time() - first > LOGIN_LOCKOUT_SECONDS:
                count, first = 0, time.time()

        if count >= MAX_LOGIN_FAILURES:
            error = "Too many failed attempts. Please wait 15 minutes and try again."
        elif _credentials_valid(request.form.get("username"), request.form.get("password")):
            with _failed_logins_lock:
                _failed_logins.pop(client, None)
            session.clear()
            session["logged_in"] = True
            get_csrf_token()
            next_path = request.args.get("next") or ""
            if not next_path.startswith("/") or next_path.startswith("//"):
                next_path = url_for("dashboard")
            return redirect(next_path)
        else:
            with _failed_logins_lock:
                _failed_logins[client] = (count + 1, first)
            error = "Incorrect username or password."

    return render_template("login.html", error=error, admin_password_set=bool(ADMIN_PASSWORD))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def warm_background_threads():
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        start_background_threads()


@app.route("/")
def dashboard():
    filter_value = (request.args.get("filter") or "all").lower()
    submissions = get_submissions(filter_value)
    return render_template(
        "index.html",
        submissions=submissions,
        active_filter=filter_value,
        counts=get_filter_counts(),
    )


@app.route("/submission/<int:submission_id>", methods=["GET", "POST"])
def submission_detail(submission_id):
    submission = get_submission(submission_id)
    if not submission:
        abort(404)

    if request.method == "POST":
        action = (request.form.get("action") or "").strip().lower()

        if action == "approve_send":
            is_held = (submission.get("response_status") or "").lower() == "held"
            if is_held and request.form.get("confirm_direct") != "yes":
                flash("This email was sent directly to ScamWatcher. Confirm before replying.", "error")
                return redirect(url_for("submission_detail", submission_id=submission_id))
            success, message = send_submission_response(submission_id, manual=True)
            flash(message, "success" if success else "error")
            return redirect(url_for("submission_detail", submission_id=submission_id))

        if action == "mark_correct":
            set_review_status(submission_id, "correct")
            flash("Saved: verdict is correct.", "success")
            return redirect(url_for("submission_detail", submission_id=submission_id))

        if action == "mark_review_required":
            set_review_status(submission_id, "review_required")
            flash("Saved: verdict needs review.", "success")
            return redirect(url_for("submission_detail", submission_id=submission_id))

        if action == "clear_review":
            set_review_status(submission_id, "unreviewed")
            flash("Assessment cleared.", "success")
            return redirect(url_for("submission_detail", submission_id=submission_id))

        return redirect(url_for("submission_detail", submission_id=submission_id))

    try:
        reply_html = build_html_email(submission)
    except Exception as exc:
        reply_html = f"<p style='font-family:sans-serif'>Preview unavailable: {html_escape(exc)}</p>"

    return render_template(
        "detail.html",
        submission=submission,
        reply_html=reply_html,
        counts=get_filter_counts(),
        active_filter="",
    )


if __name__ == "__main__":
    start_background_threads()
    port = int(os.environ.get("PORT", "5000"))
    # Debug mode exposes an interactive console that can run code, so it is only
    # enabled when explicitly requested for local development.
    debug = os.environ.get("FLASK_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    host = "127.0.0.1" if debug else "0.0.0.0"
    app.run(host=host, port=port, debug=debug)
