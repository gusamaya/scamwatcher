import base64
import imaplib
import email
import email.message
from html.parser import HTMLParser
import os
import re
from email.header import decode_header
from email.utils import parseaddr
from typing import Dict, List, Tuple

from dotenv import load_dotenv

try:
    from PyPDF2 import PdfReader
    import io
except Exception:
    PdfReader = None
    io = None


load_dotenv()

IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD") or os.getenv("EMAIL_APP_PASSWORD")
IMAP_FOLDER = os.getenv("IMAP_FOLDER", "INBOX")


def connect_imap():
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        raise ValueError("EMAIL_ADDRESS and EMAIL_PASSWORD must be set.")

    # Timeout so a stalled connection cannot freeze the inbox checker forever.
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT, timeout=30)
    mail.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    return mail


# Only Google's own system senders count as "internal". Ordinary gmail.com /
# googlemail.com addresses are real people submitting emails and must never be
# skipped.
INTERNAL_SERVICE_DOMAINS = {
    "google.com",
    "accounts.google.com",
    "workspace.google.com",
    "notifications.google.com",
}

INTERNAL_SERVICE_LOCAL_PARTS = (
    "no-reply",
    "noreply",
    "workspace-noreply",
    "accounts-noreply",
    "mail-noreply",
    "calendar-notification",
)


def is_internal_service_email(sender_email: str, subject: str, body: str, is_forwarded: bool) -> bool:
    """True only for notifications sent by Google itself to this mailbox.

    Matches on the exact sender domain (not a substring, so "google.com.evil.ru"
    or "notgoogle.com" do not match) and on a no-reply style local part.
    """
    if is_forwarded:
        return False

    sender_email = (sender_email or "").strip().lower()
    if "@" not in sender_email:
        return False

    local_part, domain = sender_email.rsplit("@", 1)

    if domain not in INTERNAL_SERVICE_DOMAINS:
        return False

    return local_part.startswith(INTERNAL_SERVICE_LOCAL_PARTS)


# Phrases a person typically writes when they paste a suspicious email into a
# new message (instead of forwarding it) and ask us to check it.
USER_REQUEST_PHRASES = (
    "is this a scam",
    "is this legit",
    "is this legitimate",
    "is this real",
    "is this genuine",
    "is this safe",
    "is this spam",
    "can you check",
    "could you check",
    "please check",
    "pls check",
    "please review",
    "can you review",
    "could you review",
    "can you have a look",
    "please have a look",
    "what do you think of this",
    "i received this",
    "i got this",
    "received this email",
    "got this email",
    "got this message",
    "received this message",
)

FORWARD_SUBJECT_PREFIX = re.compile(r"^\s*(fwd?|fw)\s*:", re.IGNORECASE)


def looks_like_user_request(subject: str, body: str) -> bool:
    text = f"{subject or ''} {body or ''}".lower()
    text = re.sub(r"\s+", " ", text)
    return any(phrase in text for phrase in USER_REQUEST_PHRASES)


def find_attached_email(message):
    """Return the first email attached as a file (Outlook "Forward as
    attachment", or a dragged-in .eml), or None."""
    for part in message.walk():
        if part.get_content_type() == "message/rfc822":
            payload = part.get_payload()
            if isinstance(payload, list) and payload:
                return payload[0]
            if isinstance(payload, email.message.Message):
                return payload

        filename = (part.get_filename() or "").lower()
        if filename.endswith(".eml"):
            try:
                data = part.get_payload(decode=True)
                if data:
                    return email.message_from_bytes(data)
            except Exception:
                continue
    return None


class _LinkCollector(HTMLParser):
    """Collects <a href> links with their visible text."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href") or ""
            self._href = href.strip()
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            text = re.sub(r"\s+", " ", "".join(self._text)).strip()
            if self._href.lower().startswith(("http://", "https://", "www.")):
                self.links.append({"text": text[:200], "url": self._href[:2000]})
            self._href = None
            self._text = []


def extract_html_links(message) -> List[Dict]:
    """Return every web link in the email's HTML, with the text shown to the
    reader. Plain-text conversion drops these, so a "Click here" button would
    otherwise never be checked."""
    links = []
    seen = set()

    for part in message.walk():
        if part.get_content_type() != "text/html":
            continue
        if "attachment" in str(part.get("Content-Disposition", "")).lower():
            continue
        try:
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            html = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            collector = _LinkCollector()
            collector.feed(html)
            for link in collector.links:
                key = (link["url"], link["text"])
                if key not in seen:
                    seen.add(key)
                    links.append(link)
        except Exception:
            continue

    return links[:100]


def extract_auth_results(message) -> Dict[str, str]:
    """Read SPF / DKIM / DMARC results added by the receiving mail server.

    Only meaningful for the email as it originally arrived: either sent
    directly to us, or attached as a file (which keeps the original headers).
    An inline forward loses them.
    """
    results = {}
    headers = message.get_all("Authentication-Results") or []
    headers += message.get_all("ARC-Authentication-Results") or []

    for header in headers:
        text = str(header).lower()
        for method in ("spf", "dkim", "dmarc"):
            if method in results:
                continue
            match = re.search(rf"\b{method}=(\w+)", text)
            if match:
                results[method] = match.group(1)

    if "spf" not in results:
        received_spf = str(message.get("Received-SPF", "")).lower().strip()
        if received_spf:
            results["spf"] = received_spf.split()[0]

    return results


def decode_mime_header(value: str) -> str:
    if not value:
        return ""

    parts = decode_header(value)
    decoded_string = ""

    for part, encoding in parts:
        if isinstance(part, bytes):
            decoded_string += part.decode(encoding or "utf-8", errors="replace")
        else:
            decoded_string += part

    return decoded_string.strip()


def html_to_text(html: str) -> str:
    if not html:
        return ""

    text = re.sub(r"(?i)<br\s*/?>", "\n", html)
    text = re.sub(r"(?i)</p>|</div>|</li>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)

    text = (
        text.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
    )

    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]{2,}", " ", text)

    return text.strip()


def extract_email_body(message) -> str:
    if message.is_multipart():
        plain_parts = []
        html_parts = []

        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", "")).lower()

            if "attachment" in content_disposition:
                continue

            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue

                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace").strip()

                if content_type == "text/plain":
                    plain_parts.append(text)
                elif content_type == "text/html":
                    html_parts.append(html_to_text(text))

            except Exception:
                continue

        if plain_parts:
            return "\n".join(plain_parts).strip()

        if html_parts:
            return "\n".join(html_parts).strip()

        return ""

    try:
        payload = message.get_payload(decode=True)
        if payload is None:
            return ""

        charset = message.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace").strip()

        if message.get_content_type() == "text/html":
            return html_to_text(text)

        return text

    except Exception:
        return ""


def extract_forwarded_email_details(body: str) -> Tuple[bool, Dict[str, str]]:
    if not body:
        return False, {"from_header": "", "subject": "", "body": ""}

    text = body.strip()

    forwarded_markers = [
        "---------- Forwarded message ---------",
        "Begin forwarded message:",
        "Forwarded message",
    ]

    header_start = -1

    for marker in forwarded_markers:
        idx = text.find(marker)
        if idx != -1:
            header_start = idx
            break

    if header_start == -1:
        match = re.search(r"(?im)^from:\s+.+$", text)
        if match:
            header_start = match.start()

    if header_start == -1:
        return False, {"from_header": "", "subject": "", "body": ""}

    forwarded_section = text[header_start:].strip()
    lines = forwarded_section.splitlines()

    original_from = ""
    original_subject = ""
    body_start_index = None

    for i, line in enumerate(lines):
        stripped = line.strip()

        if not stripped:
            continue

        if re.match(r"(?i)^from:\s*", stripped):
            original_from = re.sub(r"(?i)^from:\s*", "", stripped).strip()
            continue

        if re.match(r"(?i)^subject:\s*", stripped):
            original_subject = re.sub(r"(?i)^subject:\s*", "", stripped).strip()
            continue

        if re.match(r"(?i)^to:\s*", stripped):
            continue

        if re.match(r"(?i)^sent:\s*", stripped):
            continue

        if re.match(r"(?i)^date:\s*", stripped):
            continue

        if re.match(r"(?i)^cc:\s*", stripped):
            continue

        if stripped in forwarded_markers:
            continue

        if original_from:
            body_start_index = i
            break

    original_body = ""

    if body_start_index is not None:
        original_body = "\n".join(lines[body_start_index:]).strip()

    if not original_body:
        split_match = re.split(
            r"(?im)^subject:\s+.*$",
            forwarded_section,
            maxsplit=1,
        )
        if len(split_match) > 1:
            tail = split_match[1].strip()
            tail_lines = tail.splitlines()
            cleaned_tail = []
            passed_headers = False

            for line in tail_lines:
                if not passed_headers:
                    if not line.strip():
                        passed_headers = True
                    continue
                cleaned_tail.append(line)

            original_body = "\n".join(cleaned_tail).strip()

    if not original_from and not original_subject and not original_body:
        return False, {"from_header": "", "subject": "", "body": ""}

    return True, {
        "from_header": original_from,
        "subject": original_subject,
        "body": original_body,
    }


def extract_pdf_text_from_bytes(pdf_bytes: bytes, max_chars: int = 12000) -> str:
    if not pdf_bytes or not PdfReader or not io:
        return ""

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        parts = []

        for page in reader.pages[:10]:
            try:
                page_text = page.extract_text() or ""
                if page_text.strip():
                    parts.append(page_text.strip())
            except Exception:
                continue

        combined = "\n\n".join(parts).strip()
        if combined and len(combined) > max_chars:
            combined = combined[:max_chars]

        return combined
    except Exception:
        return ""


def extract_attachments(message) -> Tuple[bool, List[str], List[Dict], str]:
    """
    Returns:
    has_attachments, attachment_names, attachments, attachment_text
    """
    has_attachments = False
    attachment_names = []
    attachments = []
    extracted_text_parts = []

    for part in message.walk():
        content_disposition = str(part.get("Content-Disposition", "")).lower()
        filename = part.get_filename()

        is_attachment = "attachment" in content_disposition or bool(filename)
        if not is_attachment:
            continue

        has_attachments = True

        decoded_name = decode_mime_header(filename) if filename else ""
        if decoded_name:
            attachment_names.append(decoded_name)

        content_type = (part.get_content_type() or "").lower()

        try:
            payload_bytes = part.get_payload(decode=True)
        except Exception:
            payload_bytes = None

        attachment_record = {
            "filename": decoded_name,
            "content_type": content_type,
            "content_base64": "",
        }

        if payload_bytes:
            try:
                attachment_record["content_base64"] = base64.b64encode(payload_bytes).decode("utf-8")
            except Exception:
                attachment_record["content_base64"] = ""

        attachments.append(attachment_record)

        is_pdf = (
            content_type == "application/pdf"
            or (decoded_name and decoded_name.lower().endswith(".pdf"))
        )

        if is_pdf and payload_bytes:
            pdf_text = extract_pdf_text_from_bytes(payload_bytes)
            if pdf_text.strip():
                extracted_text_parts.append(pdf_text.strip())

    deduped_names = []
    seen_names = set()
    for name in attachment_names:
        key = (name or "").strip().lower()
        if key and key not in seen_names:
            seen_names.add(key)
            deduped_names.append(name)

    attachment_text = "\n\n".join(extracted_text_parts).strip()
    if attachment_text and len(attachment_text) > 12000:
        attachment_text = attachment_text[:12000]

    return has_attachments, deduped_names, attachments, attachment_text


def get_unread_emails() -> List[Dict]:
    mail = connect_imap()

    try:
        status, _ = mail.select(IMAP_FOLDER)
        if status != "OK":
            raise RuntimeError(f"Could not open IMAP folder: {IMAP_FOLDER}")

        status, data = mail.uid("search", None, "UNSEEN")
        if status != "OK":
            raise RuntimeError("Failed to search unread emails.")

        uid_list = data[0].split()
        emails = []

        for uid in uid_list:
            uid_str = uid.decode()

            status, msg_data = mail.uid("fetch", uid, "(BODY.PEEK[])")
            if status != "OK" or not msg_data or msg_data[0] is None:
                continue

            raw_email = msg_data[0][1]
            message = email.message_from_bytes(raw_email)

            message_id = (message.get("Message-ID") or "").strip()

            raw_from = decode_mime_header(message.get("From", ""))
            sender_name, sender_email = parseaddr(raw_from)

            sender_name = sender_name.strip()
            sender_email = sender_email.strip()

            submitter_name = sender_name
            submitter_email = sender_email
            submitter_from_header = raw_from

            if sender_name and sender_email:
                sender = f"{sender_name} <{sender_email}>"
            else:
                sender = sender_email or raw_from

            reply_to_header = decode_mime_header(message.get("Reply-To", ""))
            subject = decode_mime_header(message.get("Subject", ""))

            has_attachments, attachment_names, attachments, attachment_text = extract_attachments(message)
            body = extract_email_body(message)

            parsed_from_header = raw_from
            parsed_sender = sender
            parsed_subject = subject
            parsed_body = body
            forwarded_by = raw_from

            is_forwarded, forwarded_data = extract_forwarded_email_details(body)
            forward_method = "inline" if is_forwarded else ""

            html_links = extract_html_links(message)
            auth_results = extract_auth_results(message)

            attached_email = find_attached_email(message)
            if attached_email is not None:
                # The real suspicious email is the attachment; review that instead.
                inner_from = decode_mime_header(attached_email.get("From", ""))
                inner_subject = decode_mime_header(attached_email.get("Subject", ""))
                inner_body = extract_email_body(attached_email)
                (
                    has_attachments,
                    attachment_names,
                    attachments,
                    attachment_text,
                ) = extract_attachments(attached_email)
                html_links = extract_html_links(attached_email)
                auth_results = extract_auth_results(attached_email)
                reply_to_header = decode_mime_header(attached_email.get("Reply-To", ""))
                is_forwarded = True
                forward_method = "attachment"
                forwarded_data = {
                    "from_header": inner_from,
                    "subject": inner_subject,
                    "body": inner_body,
                }

            if is_forwarded:
                original_from = forwarded_data.get("from_header", "").strip()
                original_subject = forwarded_data.get("subject", "").strip()
                original_body = forwarded_data.get("body", "").strip()

                if original_from:
                    parsed_from_header = original_from
                    orig_name, orig_email = parseaddr(original_from)
                    orig_name = (orig_name or "").strip()
                    orig_email = (orig_email or "").strip()

                    if orig_name and orig_email:
                        parsed_sender = f"{orig_name} <{orig_email}>"
                    else:
                        parsed_sender = orig_email or original_from

                if original_subject:
                    parsed_subject = original_subject

                if original_body:
                    parsed_body = original_body

            # Who sent this to us?
            #   "forwarded" - a person forwarded or pasted in an email to check.
            #                 They are the submitter and should get a reply.
            #   "direct"    - the email itself was sent straight to our address
            #                 (spam, phishing, newsletters). The sender is NOT a
            #                 user, so we must not reply to them.
            if is_forwarded:
                submission_type = "forwarded"
            elif FORWARD_SUBJECT_PREFIX.match(subject or ""):
                submission_type = "forwarded"
                forward_method = "subject"
            elif looks_like_user_request(subject, body):
                submission_type = "forwarded"
                forward_method = "pasted"
            else:
                submission_type = "direct"

            if submission_type == "forwarded" and forward_method != "attachment":
                # Auth headers and Reply-To belong to the user's own email, not
                # the scam. Only a direct email or an attached .eml keeps the
                # original sender's headers.
                auth_results = {}
                reply_to_header = ""

            internal_email = is_internal_service_email(
                sender_email=sender_email,
                subject=parsed_subject,
                body=parsed_body,
                is_forwarded=is_forwarded,
            )

            emails.append(
                {
                    "imap_uid": uid_str,
                    "message_id": message_id,

                    "submitter_name": submitter_name,
                    "submitter_email": submitter_email,
                    "submitter_from_header": submitter_from_header,

                    "sender": parsed_sender,
                    "from_header": parsed_from_header,
                    "reply_to": reply_to_header,
                    "subject": parsed_subject,
                    "body": parsed_body,
                    "has_attachments": has_attachments,
                    "attachment_names": attachment_names,
                    "attachments": attachments,
                    "attachment_text": attachment_text,
                    "forwarded_by": forwarded_by,
                    "is_forwarded": is_forwarded,
                    "submission_type": submission_type,
                    "forward_method": forward_method,
                    "html_links": html_links,
                    "auth_results": auth_results,
                    "original_forward_wrapper_subject": subject,
                    "is_internal": internal_email,
                    "exclude_from_calibration": internal_email,
                }
            )

        return emails

    finally:
        try:
            mail.close()
        except Exception:
            pass
        mail.logout()


def mark_email_as_read(imap_uid: str) -> bool:
    if not imap_uid:
        return False

    mail = connect_imap()

    try:
        status, _ = mail.select(IMAP_FOLDER)
        if status != "OK":
            return False

        status, _ = mail.uid("store", imap_uid, "+FLAGS", "(\\Seen)")
        return status == "OK"

    except Exception as e:
        print(f"Failed to mark email UID {imap_uid} as read: {e}")
        return False

    finally:
        try:
            mail.close()
        except Exception:
            pass
        mail.logout()


fetch_unread_emails = get_unread_emails