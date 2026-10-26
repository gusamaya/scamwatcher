import base64
import inspect
import json
import sys
import time
from datetime import datetime


POLL_INTERVAL_SECONDS = 30

# Emails are fetched without being marked read, so one that fails is retried on
# the next poll. After this many failures it is marked read so a single broken
# email cannot block or spam the logs forever.
MAX_PROCESSING_ATTEMPTS = 3
_failed_attempts = {}

# Emails this process has dealt with without saving them (Google's own
# notices, ones with no Message-ID, ones given up on), so the inbox checker
# doesn't download them again on every check.
_handled = set()

# Images smaller than this are treated as logos or icons, not screenshots.
MIN_SCREENSHOT_BYTES = 30 * 1024


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


def _log(message):
    print(f"[InboxWorker] {message}", flush=True)


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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
            "raw": {},
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


def _is_temporary_db_error(exc):
    text = str(exc).lower()
    return "database is locked" in text or "database is busy" in text or "database table is locked" in text


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
        "html_links": email_record["raw"].get("html_links") or [],
        "auth_results": email_record["raw"].get("auth_results") or {},
        "submission_type": email_record["raw"].get("submission_type") or "",
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
    review_checks = result.get("review_checks") or []

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
        "review_checks": review_checks,
        "scam_type": _safe_str(result.get("scam_type") or ""),
        "scam_category": _safe_str(result.get("scam_category") or ""),
        "verdict_note": _safe_str(result.get("verdict_note") or ""),
        "brand": _safe_str(result.get("brand") or ""),
        "message_kind": _safe_str(result.get("message_kind") or ""),
    }


def _save_screenshots(email_record):
    """Store image attachments (screenshots, photos of a phone screen) so a
    reviewer can see them in the dashboard. Returns the stored file names."""
    try:
        import uploads
    except Exception as exc:
        _log(f"Screenshot storage unavailable: {exc}")
        return []

    stored = []
    for attachment in email_record.get("attachments") or []:
        content_type = (attachment.get("content_type") or "").lower()
        name = (attachment.get("filename") or "").lower()
        looks_like_image = content_type.startswith("image/") or name.endswith(
            (".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic")
        )
        if not looks_like_image or not attachment.get("content_base64"):
            continue
        try:
            data = base64.b64decode(attachment["content_base64"])
        except Exception:
            continue
        # Logos, icons and signature images in ordinary HTML emails are small;
        # a phone screenshot or photo is far larger. Skip the small ones so
        # every newsletter-style email doesn't land in manual review.
        if len(data) < MIN_SCREENSHOT_BYTES:
            continue
        saved = uploads.save_image(data)
        if saved:
            stored.append(saved)
        if len(stored) >= 5:
            break
    return stored


def _insert_submission_flexible(insert_submission, email_record, clean, screenshot_files=None):
    screenshot_files = screenshot_files or []
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
        "submission_type": email_record["raw"].get("submission_type"),
        "forward_method": email_record["raw"].get("forward_method"),
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
        "review_checks": json.dumps(clean.get("review_checks", [])),
        "scam_type": clean.get("scam_type", ""),
        "scam_category": clean.get("scam_category", ""),
        "verdict_note": clean.get("verdict_note", ""),
        "brand": clean.get("brand", ""),
        "message_kind": clean.get("message_kind", ""),
        "screenshot_files": screenshot_files,
        # The text checks can't see what is in a screenshot, so a person
        # writes the reply for any email that includes one.
        "needs_manual_review": bool(screenshot_files),
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
            clean["proposed_response"],
            clean["should_reply"],
            clean["confidence_label"],
            clean["confidence_reason"],
            email_record["raw"].get("submitter_name"),
            email_record["raw"].get("submitter_email"),
            email_record["raw"].get("submitter_from_header"),
            int(bool(email_record["has_attachments"])),
            json.dumps(email_record["attachment_names"]),
            json.dumps(clean.get("attachment_signals", {})),
        )
    except TypeError:
        return insert_submission(
            email_record["message_id"],
            email_record["received_at"],
            email_record["from_header"],
            email_record["subject"],
            email_record["body"],
            clean["risk_score"],
            clean["risk_rating"],
            clean["summary"],
            clean["human_summary"],
            clean["findings"],
            clean["recommended_action"],
            clean["proposed_response"],
            clean["should_reply"],
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
            "submission_exists_by_message_id",
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

    _log(f"Checking the inbox every {POLL_INTERVAL_SECONDS} seconds.")
    last_heartbeat = 0

    while True:
        try:
            fetch_new = getattr(email_reader, "fetch_new_emails", None)
            if fetch_new:
                # Everything recent that isn't in the dashboard yet, read or not.
                unread = fetch_new(lambda mid: mid in _handled or bool(mid and submission_exists(mid))) or []
            else:
                unread = fetch_unread_emails() or []

            if unread:
                _log(f"Found {len(unread)} new email(s).")
            elif time.time() - last_heartbeat > 600:
                _log("Inbox checked: no new emails.")
                last_heartbeat = time.time()

            for item in unread:
                try:
                    email_record = _normalise_email_record(item)
                    message_id = email_record["message_id"]

                    is_internal = bool(item.get("is_internal", False))
                    exclude_from_calibration = bool(item.get("exclude_from_calibration", False))

                    if is_internal or exclude_from_calibration:
                        print(f"[{_now()}] Skipping internal/excluded email: {message_id or '(no message_id)'}")
                        _handled.add(message_id or f"uid:{email_record['uid']}")

                        try:
                            _mark_as_read(mark_email_as_read, email_record)
                        except Exception as exc:
                            print(f"[{_now()}] Failed to mark internal/excluded email as read: {exc}")

                        continue

                    if not message_id:
                        print(f"[{_now()}] Skipping email with no message_id.")
                        _handled.add(f"uid:{email_record['uid']}")
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

                    screenshot_files = _save_screenshots(email_record)
                    _insert_submission_flexible(insert_submission, email_record, clean, screenshot_files)

                    if screenshot_files:
                        try:
                            import auto_review
                            saved = database.get_submission_by_message_id(message_id)
                            if saved:
                                auto_review.review_in_background(saved["id"])
                        except Exception as exc:
                            _log(f"Automatic review not started: {exc}")

                    try:
                        _mark_as_read(mark_email_as_read, email_record)
                    except Exception as exc:
                        print(f"[{_now()}] Failed to mark as read: {exc}")

                    print(
                        f"[InboxWorker] Processed: {message_id} | "
                        f"sender={email_record['sender']} | "
                        f"from_header={email_record['from_header']} | "
                        f"type={item.get('submission_type')} | "
                        f"attachments={email_record['has_attachments']} | "
                        f"attachment_names={email_record['attachment_names']} | "
                        f"screenshots={len(screenshot_files)} | "
                        f"{clean['risk_rating']} ({clean['risk_score']})"
                    )

                except Exception as email_error:
                    if _is_temporary_db_error(email_error):
                        # Not the email's fault: leave it unread and try again
                        # on the next check, however many times it takes.
                        _log(f"Database busy, will retry this email on the next check: {email_error}")
                        continue

                    key = ""
                    try:
                        key = email_record["message_id"] or email_record["uid"]
                    except Exception:
                        pass

                    attempts = _failed_attempts.get(key, 0) + 1
                    _failed_attempts[key] = attempts
                    print(
                        f"[InboxWorker] Error processing one email "
                        f"(attempt {attempts}/{MAX_PROCESSING_ATTEMPTS}): {email_error}"
                    )

                    if key and attempts >= MAX_PROCESSING_ATTEMPTS:
                        print(f"[{_now()}] Giving up on {key}; marking as read. Review it manually in the inbox.")
                        _handled.add(key)
                        try:
                            _mark_as_read(mark_email_as_read, email_record)
                        except Exception as exc:
                            print(f"[{_now()}] Failed to mark failed email as read: {exc}")
                        _failed_attempts.pop(key, None)

        except Exception as loop_error:
            _log(f"Could not check the inbox: {type(loop_error).__name__}: {loop_error}")

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
