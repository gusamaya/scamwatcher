import inspect
import json
import time
from datetime import datetime


POLL_INTERVAL_SECONDS = 30


def _import_module(module_name: str):
    module = __import__(module_name)
    return module


def _get_first_callable(module, names):
    for name in names:
        fn = getattr(module, name, None)
        if callable(fn):
            return fn
    return None


def _safe_str(value):
    if value is None:
        return ""
    return str(value)


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _normalise_list(value):
    if not value:
        return []

    if isinstance(value, list):
        return [item for item in value if item is not None]

    if isinstance(value, tuple):
        return [item for item in value if item is not None]

    return [value]


def _normalise_email_record(record):
    if not isinstance(record, dict):
        return {
            "message_id": "",
            "uid": "",
            "sender": "",
            "subject": "",
            "body": _safe_str(record),
            "reply_to": "",
            "received_at": _now(),
            "from_header": "",
            "has_attachments": False,
            "attachment_names": [],
            "attachments": [],
            "attachment_text": "",
            "raw": record,
        }

    message_id = (
        record.get("message_id")
        or record.get("id")
        or record.get("gmail_message_id")
        or ""
    )

    uid = (
        record.get("uid")
        or record.get("imap_uid")
        or record.get("email_uid")
        or ""
    )

    sender = (
        record.get("sender")
        or record.get("from")
        or record.get("from_email")
        or record.get("original_sender")
        or ""
    )

    subject = record.get("subject") or ""
    body = (
        record.get("body")
        or record.get("plain_text")
        or record.get("text")
        or record.get("content")
        or ""
    )

    reply_to = record.get("reply_to") or ""
    received_at = (
        record.get("received_at")
        or record.get("date")
        or record.get("sent_at")
        or _now()
    )
    from_header = (
        record.get("from_header")
        or record.get("from")
        or sender
        or ""
    )

    has_attachments = bool(record.get("has_attachments", False))

    attachment_names = record.get("attachment_names") or []
    if not isinstance(attachment_names, list):
        attachment_names = [attachment_names]
    attachment_names = [
        _safe_str(name).strip()
        for name in attachment_names
        if _safe_str(name).strip()
    ]

    attachments = record.get("attachments") or []
    if not isinstance(attachments, list):
        attachments = []

    attachment_text = _safe_str(record.get("attachment_text") or "").strip()

    if attachment_names:
        has_attachments = True

    return {
        "message_id": _safe_str(message_id).strip(),
        "uid": _safe_str(uid).strip(),
        "sender": _safe_str(sender).strip(),
        "subject": _safe_str(subject).strip(),
        "body": _safe_str(body),
        "reply_to": _safe_str(reply_to).strip(),
        "received_at": _safe_str(received_at).strip(),
        "from_header": _safe_str(from_header).strip(),
        "has_attachments": has_attachments,
        "attachment_names": attachment_names,
        "attachments": attachments,
        "attachment_text": attachment_text,
        "raw": record,
    }


def _call_with_supported_args(func, kwargs):
    sig = inspect.signature(func)
    accepted = {}

    has_var_kwargs = any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
    )

    if has_var_kwargs:
        return func(**kwargs)

    for name in sig.parameters.keys():
        if name in kwargs:
            accepted[name] = kwargs[name]

    return func(**accepted)


def _analyse_email(analyze_email, email_record):
    message = {
        "message_id": email_record["message_id"],
        "uid": email_record["uid"],
        "sender": email_record["sender"],
        "from": email_record["sender"],
        "from_header": email_record["from_header"],
        "subject": email_record["subject"],
        "body": email_record["body"],
        "reply_to": email_record["reply_to"],
        "has_attachments": email_record["has_attachments"],
        "attachment_names": email_record["attachment_names"],
        "attachments": email_record["attachments"],
        "attachment_text": email_record["attachment_text"],
        "raw_email": email_record["raw"],
    }

    try:
        result = analyze_email(message)
        if isinstance(result, dict):
            return result
    except TypeError:
        pass

    try:
        result = analyze_email(
            sender=email_record["sender"],
            from_header=email_record["from_header"],
            subject=email_record["subject"],
            body=email_record["body"],
            reply_to=email_record["reply_to"],
            has_attachments=email_record["has_attachments"],
            attachment_names=email_record["attachment_names"],
            attachments=email_record["attachments"],
            attachment_text=email_record["attachment_text"],
        )
        if isinstance(result, dict):
            return result
    except TypeError:
        pass

    try:
        result = analyze_email(
            email_record["sender"],
            email_record["subject"],
            email_record["body"],
        )
        if isinstance(result, dict):
            return result
    except TypeError as exc:
        raise RuntimeError(
            "Could not call analyze_email with any supported argument pattern."
        ) from exc

    raise RuntimeError("analyze_email did not return a dictionary.")


def _normalise_analysis_result(result):
    risk_score = result.get("risk_score", 0)
    risk_rating = result.get("risk_rating") or result.get("rating") or "Needs Attention"
    findings = result.get("findings") or result.get("analysis") or ""
    recommended_action = result.get("recommended_action") or result.get("action") or ""
    should_reply = result.get("should_reply")
    proposed_response = (
        result.get("proposed_response")
        or result.get("response")
        or result.get("stored_response")
        or ""
    )

    summary = result.get("summary") or findings
    human_summary = result.get("human_summary") or summary
    confidence_label = result.get("confidence_label") or ""
    confidence_reason = result.get("confidence_reason") or ""
    attachment_signals = result.get("attachment_signals") or {}

    try:
        risk_score = int(risk_score)
    except Exception:
        risk_score = 0

    if isinstance(findings, list):
        findings_value = json.dumps(findings)
    else:
        findings_value = _safe_str(findings)

    if not isinstance(attachment_signals, dict):
        attachment_signals = {}

    return {
        "risk_score": risk_score,
        "risk_rating": _safe_str(risk_rating),
        "findings": findings_value,
        "recommended_action": _safe_str(recommended_action),
        "should_reply": should_reply,
        "proposed_response": _safe_str(proposed_response),
        "summary": _safe_str(summary),
        "human_summary": _safe_str(human_summary),
        "confidence_label": _safe_str(confidence_label),
        "confidence_reason": _safe_str(confidence_reason),
        "attachment_signals": attachment_signals,
    }


def _insert_submission_flexible(insert_submission, email_record, clean):
    insert_kwargs = {
        "message_id": email_record["message_id"],
        "received_at": email_record["received_at"],
        "sender": email_record["sender"],
        "from_header": email_record["from_header"],
        "subject": email_record["subject"],
        "body": email_record["body"],

        "submitter_name": email_record["raw"].get("submitter_name"),
        "submitter_email": email_record["raw"].get("submitter_email"),
        "submitter_from_header": email_record["raw"].get("submitter_from_header"),

        "risk_score": clean["risk_score"],
        "risk_rating": clean["risk_rating"],
        "summary": clean["summary"],
        "human_summary": clean["human_summary"],
        "findings": clean["findings"],
        "recommended_action": clean["recommended_action"],
        "should_reply": clean["should_reply"],
        "proposed_response": clean["proposed_response"],
        "confidence_label": clean["confidence_label"],
        "confidence_reason": clean["confidence_reason"],
        "reply_to": email_record["reply_to"],

        "has_attachments": int(bool(email_record["has_attachments"])),
        "attachment_names": json.dumps(email_record["attachment_names"]),
        "attachment_signals": json.dumps(clean.get("attachment_signals", {})),
    }

    try:
        return _call_with_supported_args(insert_submission, insert_kwargs)
    except TypeError:
        pass

    try:
        return insert_submission(
            email_record["message_id"],
            email_record["received_at"],
            email_record["sender"],
            email_record["from_header"],
            email_record["subject"],
            email_record["body"],
            clean["risk_score"],
            clean["risk_rating"],
            clean["summary"],
            clean["human_summary"],
            clean["findings"],
            clean["recommended_action"],
            clean["should_reply"],
            clean["proposed_response"],
            clean["confidence_label"],
            clean["confidence_reason"],
            email_record["reply_to"],
            int(bool(email_record["has_attachments"])),
            json.dumps(email_record["attachment_names"]),
            json.dumps(clean.get("attachment_signals", {})),
        )
    except TypeError:
        return insert_submission(
            email_record["message_id"],
            email_record["received_at"],
            email_record["sender"],
            email_record["from_header"],
            email_record["subject"],
            email_record["body"],
            clean["risk_score"],
            clean["risk_rating"],
            clean["summary"],
            clean["human_summary"],
            clean["findings"],
            clean["recommended_action"],
            clean["should_reply"],
            clean["proposed_response"],
            clean["confidence_label"],
            clean["confidence_reason"],
        )


def _mark_as_read(mark_email_as_read, email_record):
    last_error = None

    if email_record["uid"]:
        try:
            return mark_email_as_read(email_record["uid"])
        except Exception as exc:
            last_error = exc

    try:
        return mark_email_as_read(email_record["raw"])
    except Exception as exc:
        last_error = exc

    if email_record["message_id"]:
        try:
            return mark_email_as_read(email_record["message_id"])
        except Exception as exc:
            last_error = exc

    if last_error:
        raise last_error


def main():
    print(f"[{_now()}] ScamWatcher inbox worker starting...")

    email_reader = _import_module("email_reader")
    analyzer = _import_module("analyzer")
    database = _import_module("database")

    fetch_unread_emails = _get_first_callable(
        email_reader,
        [
            "fetch_unread_emails",
            "get_unread_emails",
            "read_unread_emails",
            "fetch_emails",
        ],
    )

    mark_email_as_read = _get_first_callable(
        email_reader,
        [
            "mark_email_as_read",
            "mark_as_read",
            "mark_read",
        ],
    )

    analyze_email = _get_first_callable(analyzer, ["analyze_email"])

    init_db = _get_first_callable(
        database,
        [
            "init_db",
            "initialize_db",
            "setup_database",
        ],
    )

    submission_exists = _get_first_callable(
        database,
        [
            "submission_exists",
            "message_exists",
            "record_exists",
            "email_exists",
        ],
    )

    insert_submission = _get_first_callable(
        database,
        [
            "insert_submission",
            "save_submission",
            "create_submission",
            "insert_email_result",
        ],
    )

    if not fetch_unread_emails:
        raise RuntimeError("Could not find a fetch unread emails function in email_reader.py")

    if not mark_email_as_read:
        raise RuntimeError("Could not find a mark-as-read function in email_reader.py")

    if not analyze_email:
        raise RuntimeError("Could not find analyze_email in analyzer.py")

    if not submission_exists:
        raise RuntimeError("Could not find a submission_exists-style function in database.py")

    if not insert_submission:
        raise RuntimeError("Could not find an insert_submission-style function in database.py")

    if init_db:
        init_db()
        print(f"[{_now()}] Database initialised.")

    while True:
        try:
            unread = fetch_unread_emails() or []

            if unread:
                print(f"[{_now()}] Found {len(unread)} unread email(s).")

            for item in unread:
                try:
                    email_record = _normalise_email_record(item)
                    message_id = email_record["message_id"]

                    is_internal = bool(item.get("is_internal", False))
                    exclude_from_calibration = bool(item.get("exclude_from_calibration", False))

                    if is_internal or exclude_from_calibration:
                        print(f"[{_now()}] Skipping internal/excluded email: {message_id or '(no message_id)'}")

                        try:
                            _mark_as_read(mark_email_as_read, email_record)
                        except Exception as exc:
                            print(f"[{_now()}] Failed to mark internal/excluded email as read: {exc}")

                        continue

                    if not message_id:
                        print(f"[{_now()}] Skipping email with no message_id.")
                        continue

                    if submission_exists(message_id):
                        print(f"[{_now()}] Duplicate skipped: {message_id}")
                        try:
                            _mark_as_read(mark_email_as_read, email_record)
                        except Exception as exc:
                            print(f"[{_now()}] Failed to mark duplicate as read: {exc}")
                        continue

                    analysis = _analyse_email(analyze_email, email_record)
                    clean = _normalise_analysis_result(analysis)

                    _insert_submission_flexible(insert_submission, email_record, clean)

                    try:
                        _mark_as_read(mark_email_as_read, email_record)
                    except Exception as exc:
                        print(f"[{_now()}] Failed to mark as read: {exc}")

                    print(
                        f"[{_now()}] Processed: {message_id} | "
                        f"sender={email_record['sender']} | "
                        f"from_header={email_record['from_header']} | "
                        f"attachments={email_record['has_attachments']} | "
                        f"attachment_names={email_record['attachment_names']} | "
                        f"{clean['risk_rating']} ({clean['risk_score']})"
                    )

                except Exception as email_error:
                    print(f"[{_now()}] Error processing one email: {email_error}")

        except Exception as loop_error:
            print(f"[{_now()}] Worker loop error: {loop_error}")

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()