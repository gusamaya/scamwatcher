import base64
import io
import json
import re
from urllib.parse import urlparse

from scoring_model import assess_email_risk

try:
    from PyPDF2 import PdfReader
except Exception:
    PdfReader = None


def extract_urls(text):
    if not text:
        return []
    raw_urls = re.findall(r"(https?://[^\s<>()\"']+|www\.[^\s<>()\"']+)", text, flags=re.IGNORECASE)

    cleaned = []
    for url in raw_urls:
        candidate = url.strip().rstrip(".,);:!?]>\"'")
        if candidate.lower().startswith("www."):
            candidate = "http://" + candidate
        cleaned.append(candidate)

    return list(set(cleaned))


def get_domain_from_url(url):
    try:
        parsed = urlparse(url)
        domain = (parsed.netloc or parsed.path).lower().strip()
        domain = domain.split("@")[-1].split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return ""


def domains_align(sender_domain, target_domain):
    if not sender_domain or not target_domain:
        return False

    sender_domain = sender_domain.lower().strip()
    target_domain = target_domain.lower().strip()

    if sender_domain.startswith("www."):
        sender_domain = sender_domain[4:]
    if target_domain.startswith("www."):
        target_domain = target_domain[4:]

    if sender_domain == target_domain:
        return True

    if target_domain.endswith("." + sender_domain):
        return True

    trusted_alias_map = {
        "google.com": ["c.gle", "g.co", "googlemail.com", "googleapis.com", "withgoogle.com", "youtu.be", "youtube.com"],
        "facebook.com": ["fb.com", "fb.me", "meta.com", "messenger.com"],
        "instagram.com": ["instagr.am", "meta.com"],
        "amazon.com": ["amzn.to", "amazon.com.au"],
        "youtube.com": ["youtu.be"],
        "youtu.be": ["youtube.com"],
    }

    sender_aliases = trusted_alias_map.get(sender_domain, [])
    if target_domain in sender_aliases:
        return True

    for canonical_domain, aliases in trusted_alias_map.items():
        if sender_domain in aliases and target_domain == canonical_domain:
            return True
        if sender_domain in aliases and target_domain in aliases:
            return True

    return False


def extract_email_domains(text):
    emails = re.findall(r"[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", text or "")
    return list(set([e.lower() for e in emails]))


def parse_from_header(from_header):
    if not from_header:
        return "", "", ""

    email_match = re.search(r"<\s*([^>]+@[^>]+)\s*>", from_header)
    email_address = email_match.group(1).strip().lower() if email_match else ""

    display_name = from_header
    if "<" in from_header:
        display_name = from_header.split("<")[0].strip().strip('"')

    sender_domain = ""
    if email_address and "@" in email_address:
        sender_domain = email_address.split("@", 1)[1].lower().strip()

    return display_name, email_address, sender_domain


def clean_forwarded_content(body):
    if not body:
        return ""

    cleaned = body

    forwarding_patterns = [
        r"[- ]*forwarded message[- ]*",
        r"^from:\s.*$",
        r"^sent:\s.*$",
        r"^date:\s.*$",
        r"^to:\s.*$",
        r"^cc:\s.*$",
        r"^bcc:\s.*$",
        r"^subject:\s.*$",
    ]

    for pattern in forwarding_patterns:
        cleaned = re.sub(pattern, "", cleaned, flags=re.IGNORECASE | re.MULTILINE)

    cleaned = re.sub(r"\n\s*\n\s*\n+", "\n\n", cleaned)
    return cleaned.strip()


def normalize_finding_text(finding):
    if not finding:
        return finding

    lower = finding.lower().strip()

    free_email_patterns = [
        "the sender uses a free email service",
        "the sender uses a free email address",
    ]

    if any(pattern in lower for pattern in free_email_patterns):
        return (
            "The sender uses a free email address, which is common in unsolicited or "
            "promotional emails but less typical for formal business communication."
        )

    payment_verification_patterns = [
        "the email includes a request relating to payment or transfer of funds.",
        "the email includes a request relating to payment or transfer of funds",
    ]

    if any(pattern == lower for pattern in payment_verification_patterns):
        return "The email requests verification of payment details, which is a common phishing technique."

    return finding


def build_response(submission):
    findings = submission.get("findings", [])

    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except Exception:
            findings = []

    bullet_lines = []
    for f in findings[:5]:
        if f:
            clean_f = f.strip().replace("[", "").replace("]", "").replace("'", "")
            bullet_lines.append(f"• {clean_f}")

    findings_block = "\n".join(bullet_lines)

    response = f"""Hi,

Thanks for submitting this email to ScamWatcher.

Assessment result: {submission.get("risk_rating")}.

Recommended Action
{submission.get("recommended_action")}

What ScamWatcher observed:
{findings_block}

No immediate action is required. If this message is not relevant, it can be safely ignored.

If you are considering engaging, ensure any response or action is appropriate for your situation.

Regards,

Serena
ScamWatcher Advisor

ScamWatcher is an independent advisory service.
"""

    return response


def safe_lower(value):
    return (value or "").lower().strip()


def safe_filename_list(submission):
    names = submission.get("attachment_names", []) or []
    cleaned = []

    if isinstance(names, list):
        for name in names:
            if name:
                cleaned.append(str(name).strip())

    attachments = submission.get("attachments", []) or []
    if isinstance(attachments, list):
        for att in attachments:
            if isinstance(att, dict):
                filename = att.get("filename") or att.get("name")
                if filename:
                    cleaned.append(str(filename).strip())

    deduped = []
    seen = set()
    for name in cleaned:
        key = name.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(name)

    return deduped


def get_submission_attachments(submission):
    attachments = submission.get("attachments", [])
    if isinstance(attachments, list):
        return attachments
    return []


def get_attachment_text_from_submission(submission):
    """
    Supports future-safe optional pre-extracted attachment text if your pipeline adds it.
    """
    candidates = [
        submission.get("attachment_text"),
        submission.get("attachments_text"),
        submission.get("pdf_text"),
        submission.get("extracted_attachment_text"),
    ]

    combined = []
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            combined.append(candidate.strip())
        elif isinstance(candidate, list):
            for item in candidate:
                if isinstance(item, str) and item.strip():
                    combined.append(item.strip())

    if combined:
        return "\n\n".join(combined)
    return ""


def decode_attachment_bytes(att):
    """
    Best-effort decoder for common attachment shapes.
    Supports:
    - raw bytes in content/data/body
    - base64 string in content_base64/data_base64/body_base64/content/data/body
    """
    if not isinstance(att, dict):
        return None

    byte_candidates = [
        att.get("content"),
        att.get("data"),
        att.get("body"),
        att.get("bytes"),
    ]

    for candidate in byte_candidates:
        if isinstance(candidate, (bytes, bytearray)):
            return bytes(candidate)

    base64_candidates = [
        att.get("content_base64"),
        att.get("data_base64"),
        att.get("body_base64"),
        att.get("base64"),
        att.get("content"),
        att.get("data"),
        att.get("body"),
    ]

    for candidate in base64_candidates:
        if isinstance(candidate, str) and candidate.strip():
            try:
                return base64.b64decode(candidate, validate=False)
            except Exception:
                continue

    return None


def extract_pdf_text_from_bytes(pdf_bytes, max_chars=12000):
    if not pdf_bytes or not PdfReader:
        return ""

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        text_parts = []

        for page in reader.pages[:10]:
            try:
                page_text = page.extract_text() or ""
                if page_text.strip():
                    text_parts.append(page_text.strip())
            except Exception:
                continue

        combined = "\n\n".join(text_parts).strip()
        if combined and len(combined) > max_chars:
            combined = combined[:max_chars]
        return combined
    except Exception:
        return ""


def extract_pdf_text_from_attachments(submission, attachment_names):
    """
    Returns:
    {
        "pdf_present": bool,
        "pdf_text_available": bool,
        "pdf_extraction_failed": bool,
        "pdf_text": str,
        "pdf_source_count": int
    }
    """
    pre_extracted_text = get_attachment_text_from_submission(submission)
    attachments = get_submission_attachments(submission)

    pdf_present = any(name.lower().endswith(".pdf") for name in attachment_names)

    if pre_extracted_text.strip():
        return {
            "pdf_present": pdf_present or True,
            "pdf_text_available": True,
            "pdf_extraction_failed": False,
            "pdf_text": pre_extracted_text[:12000],
            "pdf_source_count": 1,
        }

    if not pdf_present:
        return {
            "pdf_present": False,
            "pdf_text_available": False,
            "pdf_extraction_failed": False,
            "pdf_text": "",
            "pdf_source_count": 0,
        }

    if not attachments:
        return {
            "pdf_present": True,
            "pdf_text_available": False,
            "pdf_extraction_failed": False,
            "pdf_text": "",
            "pdf_source_count": 0,
        }

    extracted_parts = []
    pdf_source_count = 0

    for att in attachments:
        if not isinstance(att, dict):
            continue

        filename = safe_lower(att.get("filename") or att.get("name"))
        content_type = safe_lower(att.get("content_type") or att.get("mime_type"))

        is_pdf = filename.endswith(".pdf") or content_type == "application/pdf"
        if not is_pdf:
            continue

        pdf_source_count += 1
        pdf_bytes = decode_attachment_bytes(att)
        if not pdf_bytes:
            continue

        pdf_text = extract_pdf_text_from_bytes(pdf_bytes)
        if pdf_text.strip():
            extracted_parts.append(pdf_text.strip())

    combined = "\n\n".join(extracted_parts).strip()
    if combined and len(combined) > 12000:
        combined = combined[:12000]

    return {
        "pdf_present": True,
        "pdf_text_available": bool(combined),
        "pdf_extraction_failed": pdf_source_count > 0 and not bool(combined),
        "pdf_text": combined,
        "pdf_source_count": pdf_source_count,
    }


def extract_attachment_identity_name(pdf_text):
    """
    Lightweight issuer-name guess from top PDF text only.
    Keep simple and conservative for MVP.
    """
    if not pdf_text:
        return ""

    lines = [line.strip() for line in pdf_text.splitlines()[:40] if line.strip()]
    if not lines:
        return ""

    skip_patterns = [
        "invoice",
        "tax invoice",
        "receipt",
        "statement",
        "quote",
        "purchase order",
        "amount due",
        "balance due",
        "payment due",
        "bill to",
        "ship to",
        "remittance",
        "page ",
        "date",
        "abn",
        "gst",
    ]

    company_suffixes = [
        "pty ltd", "ltd", "limited", "group", "services", "solutions",
        "holdings", "company", "corp", "corporation", "inc", "llc"
    ]

    for line in lines:
        lower = line.lower()

        if len(line) < 3 or len(line) > 80:
            continue

        if any(pattern in lower for pattern in skip_patterns):
            continue

        # Stronger confidence if it looks like a company heading
        if any(suffix in lower for suffix in company_suffixes):
            return line

        # Title case or uppercase heading near top
        alpha_words = re.findall(r"[A-Za-z][A-Za-z&'.-]{2,}", line)
        if 1 <= len(alpha_words) <= 6:
            upperish = (line == line.upper())
            titleish = (line == line.title())
            if upperish or titleish:
                return line

    return ""


def compare_attachment_identity_to_sender(attachment_identity_name, sender_domain, display_name):
    if not attachment_identity_name or not sender_domain:
        return False, "none"

    identity_lower = attachment_identity_name.lower()
    display_lower = safe_lower(display_name)
    domain_root = sender_domain.split(".")[0].lower()

    generic_tokens = {
        "and", "the", "pty", "ltd", "limited", "services", "service",
        "solutions", "solution", "group", "company", "corp", "corporation",
        "australia", "australian", "official", "invoice", "tax"
    }

    identity_tokens = [t for t in re.findall(r"[a-zA-Z]{3,}", identity_lower) if t not in generic_tokens]

    if not identity_tokens:
        return False, "none"

    if any(token in sender_domain for token in identity_tokens):
        return False, "none"

    if display_lower and any(token in display_lower for token in identity_tokens):
        return False, "none"

    strong = len(identity_tokens) >= 2 and all(token not in sender_domain for token in identity_tokens[:2])
    if strong:
        return True, "strong"

    return True, "weak"


def analyze_pdf_signals(pdf_text, sender_email, sender_domain, display_name, body_text):
    pdf_lower = (pdf_text or "").lower()
    body_lower = (body_text or "").lower()

    invoice_keywords = [
        "invoice", "tax invoice", "receipt", "remittance", "statement",
        "quote", "purchase order", "payment due", "amount due", "balance due"
    ]

    payment_instruction_keywords = [
        "bsb", "account number", "bank transfer", "direct deposit",
        "remit payment", "eft", "wire transfer", "pay now", "bank details"
    ]

    updated_payment_keywords = [
        "new bank details",
        "updated bank details",
        "future payments should be made to",
        "please note our new account",
        "change of banking details",
        "updated banking details",
        "new banking details",
        "please use the following bank details",
    ]

    sensitive_request_keywords = [
        "password", "pin", "login", "log in", "verify identity", "passport",
        "driver licence", "drivers licence", "card details", "date of birth",
        "security code", "otp", "one time password", "verification code",
        "medicare", "tax file number", "tfn"
    ]

    urgency_keywords = [
        "immediate", "urgently", "overdue", "final notice", "today",
        "action required", "payment required immediately", "past due"
    ]

    attachment_body_leadins = [
        "please see attached",
        "attached for your review",
        "see attached invoice",
        "please find attached",
        "attached invoice",
        "attached statement",
        "attached receipt",
        "attached remittance",
    ]

    invoice_like_document = any(k in pdf_lower for k in invoice_keywords)
    receipt_like_document = ("receipt" in pdf_lower or "remittance" in pdf_lower) and not invoice_like_document
    payment_instructions_present = any(k in pdf_lower for k in payment_instruction_keywords)
    bank_details_present = any(k in pdf_lower for k in ["bsb", "account number", "bank details", "direct deposit"])
    updated_payment_details_present = any(k in pdf_lower for k in updated_payment_keywords)
    sensitive_info_request_present = any(k in pdf_lower for k in sensitive_request_keywords)
    urgency_in_attachment = any(k in pdf_lower for k in urgency_keywords)

    body_vague = any(p in body_lower for p in attachment_body_leadins)
    action_or_financial_pdf = any([
        invoice_like_document,
        receipt_like_document,
        payment_instructions_present,
        bank_details_present,
        updated_payment_details_present,
        sensitive_info_request_present,
        urgency_in_attachment,
    ])
    attachment_only_action_pattern = body_vague and action_or_financial_pdf

    attachment_identity_name = extract_attachment_identity_name(pdf_text)
    attachment_identity_mismatch, attachment_identity_mismatch_confidence = compare_attachment_identity_to_sender(
        attachment_identity_name=attachment_identity_name,
        sender_domain=sender_domain,
        display_name=display_name,
    )

    attachment_findings = []

    if invoice_like_document:
        attachment_findings.append("A PDF attachment appears to contain invoice or payment-related content.")

    if receipt_like_document:
        attachment_findings.append("A PDF attachment appears to contain receipt or remittance-style content.")

    if payment_instructions_present:
        attachment_findings.append("The attachment includes payment instructions that should be independently verified.")

    if bank_details_present:
        attachment_findings.append("The attachment includes bank or account details.")

    if updated_payment_details_present:
        attachment_findings.append("The attachment references updated or changed banking details.")

    if sensitive_info_request_present:
        attachment_findings.append("The attachment appears to request sensitive personal or account information.")

    if urgency_in_attachment:
        attachment_findings.append("The attachment uses urgency or pressure language.")

    if attachment_only_action_pattern:
        attachment_findings.append("The email body is minimal while the attachment contains the main request or action.")

    if attachment_identity_mismatch:
        attachment_findings.append("The business identity referenced in the attachment did not clearly align with the sender details.")

    return {
        "attachment_present": True,
        "pdf_present": True,
        "pdf_text_available": bool(pdf_text.strip()),
        "invoice_like_document": invoice_like_document,
        "receipt_like_document": receipt_like_document,
        "payment_instructions_present": payment_instructions_present,
        "bank_details_present": bank_details_present,
        "updated_payment_details_present": updated_payment_details_present,
        "sensitive_info_request_present": sensitive_info_request_present,
        "urgency_in_attachment": urgency_in_attachment,
        "attachment_only_action_pattern": attachment_only_action_pattern,
        "attachment_identity_name": attachment_identity_name,
        "attachment_identity_mismatch": attachment_identity_mismatch,
        "attachment_identity_mismatch_confidence": attachment_identity_mismatch_confidence,
        "attachment_findings": attachment_findings,
    }


def analyze_email(submission):
    from_header = submission.get("from_header", "")
    subject = submission.get("subject", "")
    raw_body = submission.get("body", "")
    body = clean_forwarded_content(raw_body)

    base = assess_email_risk(from_header, subject, body)

    risk_score = base["score"]
    findings = list(base["findings"])
    signals = base["signals"]

    combined_lower = f"{subject} {body}".lower()
    display_name, parsed_sender_email, parsed_sender_domain = parse_from_header(from_header)

    has_attachments = bool(submission.get("has_attachments", False))
    attachment_names = safe_filename_list(submission)

    if attachment_names:
        has_attachments = True

    action_keywords = [
        "verify", "verification", "confirm", "confirmation",
        "login", "log in", "update", "claim", "view",
        "track", "respond", "reply", "complete", "submit"
    ]

    trusted_keywords = [
        "bank", "insurance", "government", "ato", "uber",
        "facebook", "nrma", "customs", "border protection",
        "delivery", "hotdoc", "help center", "opensea",
        "gmail", "google docs", "google drive", "google workspace",
        "workspace", "google"
    ]

    google_trusted_context_phrases = [
        "gmail",
        "google drive",
        "google docs",
        "google workspace",
        "google account",
        "google security",
        "google verification",
        "google support",
    ]

    reward_keywords = [
        "winner", "reward", "grant", "prize", "remittance",
        "funding", "payout", "congratulations", "claim"
    ]

    unexpected_reward_phrases = [
        "you have been awarded",
        "you've been awarded",
        "you are entitled to",
        "you have been selected",
        "you qualify for",
        "welcome pack",
        "exclusive offer for you",
    ]

    soft_urgency_phrases = [
        "timely action",
        "without interruption",
        "may limit",
        "may suspend",
        "avoid disruption",
        "maintain access",
        "immediate attention",
    ]

    sensitive_request_keywords = [
        "personal information", "personal details", "identity",
        "address", "phone number", "mobile phone number",
        "account details", "payment details", "delivery",
        "parcel", "package"
    ]

    info_request_phrases = [
        "provide your information",
        "provide your details",
        "provide information",
        "provide your personal information",
        "provide your personal details",
        "confirm your details",
        "confirm your information",
        "verify your information",
        "verify your details",
        "send your details",
        "send your information",
        "full personal information",
        "personal information",
        "submit your information",
        "submit your details",
        "complete your details",
        "complete your information",
    ]

    authority_keywords = [
        "customs",
        "border protection",
        "government",
        "department",
        "ato",
        "tax",
        "bank",
    ]

    large_value_keywords = [
        "visa",
        "million",
        "millions",
        "8.5m",
        "$8.5m",
        "8.5 million",
        "beneficiary",
        "inheritance",
        "compensation fund",
    ]

    advance_fee_phrases = [
        "confidential matter",
        "strictly confidential",
        "profitable business venture",
        "business venture",
        "venture worth millions",
        "worth millions",
        "million dollars",
        "millions of dollars",
        "lucrative opportunity",
        "financial opportunity",
        "introduce it to you",
        "introduce this to you",
        "looking forward to your response",
        "quick response",
    ]

    promotional_marketing_phrases = [
        "recommendations",
        "save time",
        "learn more",
        "discover",
        "new features",
        "feature update",
        "product update",
        "workspace",
        "google workspace",
        "newsletter",
        "manage preferences",
        "unsubscribe",
        "view in browser",
        "help your team",
        "boost productivity",
        "tips and tricks",
        "get more from",
        "see what's new",
        "explore",
        "resources",
        "webinar",
        "guide",
        "blog",
        "insights",
    ]

    sender_domain = signals.get("sender_domain", "") or parsed_sender_domain
    display_lower = (display_name or "").lower()

    display_mismatch = False
    meaningful_display_tokens = []

    generic_tokens = {
        "and", "the", "pty", "ltd", "limited", "services", "service",
        "support", "team", "group", "australia", "australian", "official"
    }

    if display_lower and sender_domain:
        token_candidates = re.findall(r"[a-zA-Z]{3,}", display_lower)
        meaningful_display_tokens = [t for t in token_candidates if t not in generic_tokens]

        is_likely_business_name = any(k in display_lower for k in [
            "support", "team", "service", "services", "bank", "admin", "billing"
        ])

        if meaningful_display_tokens and is_likely_business_name:
            matched_token = any(token in sender_domain for token in meaningful_display_tokens)
            if not matched_token:
                display_mismatch = True

    if display_mismatch:
        findings.append("Sender display name does not align with the sender email address/domain.")
        risk_score += 20

    info_request_detected = any(p in combined_lower for p in info_request_phrases)

    if not info_request_detected:
        if (
            ("personal" in combined_lower and "information" in combined_lower)
            or ("personal" in combined_lower and "details" in combined_lower)
            or ("provide" in combined_lower and ("information" in combined_lower or "details" in combined_lower))
            or ("submit" in combined_lower and ("information" in combined_lower or "details" in combined_lower))
        ):
            info_request_detected = True

    if info_request_detected:
        findings.append("The email requests personal or sensitive information.")
        risk_score += 25

    authority_detected = any(k in combined_lower for k in authority_keywords) or any(
        k in display_lower for k in authority_keywords
    )

    if authority_detected:
        findings.append("The message appears to represent an authority or organisation.")
        risk_score += 15

    if authority_detected and info_request_detected:
        findings.append("The email combines an authority-style message with a request for information.")
        risk_score += 25
        risk_score = max(risk_score, 75)

    if display_mismatch and authority_detected:
        findings.append("Authority-style sender name does not align with the actual sender email/domain.")
        risk_score = max(risk_score, 80)

    if display_mismatch and info_request_detected:
        findings.append("Sender mismatch combined with a request for information increases risk.")
        risk_score = max(risk_score, 80)

    large_value_detected = any(k in combined_lower for k in large_value_keywords)

    if large_value_detected:
        findings.append("The message contains a large-value offer or visa-related claim, which is a common scam pattern.")
        risk_score += 20

    if large_value_detected and info_request_detected:
        findings.append("Large-value or visa-related claims combined with a request for personal information increase risk.")
        risk_score = max(risk_score, 85)

    advance_fee_detected = any(p in combined_lower for p in advance_fee_phrases)

    if advance_fee_detected:
        findings.append("The message uses vague confidential or high-value opportunity language, which is a common scam pattern.")
        risk_score += 20

    if advance_fee_detected and authority_detected:
        findings.append("Authority-style sender context combined with a vague financial approach increases risk.")
        risk_score = max(risk_score, 90)

    if advance_fee_detected and ("reply" in combined_lower or "respond" in combined_lower):
        findings.append("The message pushes for a direct reply to continue an unexplained opportunity.")
        risk_score = max(risk_score, 85)

    body_domains = extract_email_domains(body)

    body_mismatch = False
    gmail_body_contact = False

    for d in body_domains:
        is_free_body_domain = any(x in d for x in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"])

        if is_free_body_domain:
            gmail_body_contact = True

        if sender_domain and not domains_align(sender_domain, d):
            if signals.get("trusted_brand_notification") and not is_free_body_domain:
                continue
            body_mismatch = True

    if body_mismatch:
        findings.append("Email contains contact details that do not align with the sender domain.")
        risk_score += 15

    if body_mismatch and gmail_body_contact:
        findings.append("The message directs contact to a free email address that does not match the sender.")
        risk_score += 20
        risk_score = max(risk_score, 85)

    if body_mismatch and gmail_body_contact and info_request_detected:
        findings.append("Free email contact combined with a request for personal information increases risk.")
        risk_score = max(risk_score, 90)

    links = extract_urls(body)
    link_domains = [get_domain_from_url(url) for url in links if get_domain_from_url(url)]

    mismatch_detected = False

    if link_domains:
        findings.append(f"Email contains {len(link_domains)} link(s).")

        for domain in set(link_domains):
            findings.append(f'Link points to "{domain}".')

            if sender_domain and not domains_align(sender_domain, domain):
                mismatch_detected = True

        if mismatch_detected:
            findings.append("At least one link does not align with the sender domain.")
            risk_score += 20

        if mismatch_detected and (
            signals.get("payment_request")
            or signals.get("credential_request")
            or signals.get("account_reference")
        ):
            findings.append("Link mismatch combined with action-based message increases risk.")
            risk_score += 15

        if mismatch_detected:
            risk_score = max(risk_score, 55)

            if signals.get("domain_mismatch"):
                findings.append("Sender identity and link destination do not align.")
                risk_score = max(risk_score, 75)

    if mismatch_detected and any(k in combined_lower for k in action_keywords):
        findings.append("Message requests action using a link that does not match the sender.")
        risk_score = max(risk_score, 80)

    account_like = any(k in combined_lower for k in [
        "account", "notification", "security", "verify", "login", "update"
    ])

    if (
        link_domains
        and account_like
        and not (
            signals.get("trusted_brand_alignment")
            or signals.get("trusted_brand_notification")
        )
    ):
        findings.append("Account-related message includes a link, which is a common phishing pattern.")
        risk_score = max(risk_score, 80)

    soft_urgency_detected = any(p in combined_lower for p in soft_urgency_phrases)

    if soft_urgency_detected:
        findings.append("The message uses urgency or pressure language to prompt quick action.")
        risk_score += 10

    if (
        soft_urgency_detected
        and (signals.get("payment_request") or account_like)
        and not signals.get("trusted_brand_notification")
    ):
        findings.append("Urgency combined with account or payment request increases risk.")
        risk_score = max(risk_score, 85)

    attachment_detected = has_attachments
    attachment_risky_context = False

    if attachment_detected:
        if attachment_names:
            findings.append(f"Email includes attachment(s): {', '.join(attachment_names[:3])}.")
        else:
            findings.append("Email includes one or more attachment(s).")
        risk_score += 3
    else:
        attachment_indicators = [
            "attachment", "attached", ".pdf", ".zip", ".doc", ".docx", ".xls", ".xlsx", ".html"
        ]
        if any(indicator in combined_lower for indicator in attachment_indicators):
            attachment_detected = True
            findings.append("Email contains attachment-style content.")
            risk_score += 3

    # ------------------------------------------------------------
    # MVP PDF attachment analysis
    # ------------------------------------------------------------
    attachment_signals = {
        "attachment_present": attachment_detected,
        "pdf_present": False,
        "pdf_text_available": False,
        "pdf_extraction_failed": False,
        "invoice_like_document": False,
        "receipt_like_document": False,
        "payment_instructions_present": False,
        "bank_details_present": False,
        "updated_payment_details_present": False,
        "sensitive_info_request_present": False,
        "urgency_in_attachment": False,
        "attachment_only_action_pattern": False,
        "attachment_identity_name": "",
        "attachment_identity_mismatch": False,
        "attachment_identity_mismatch_confidence": "none",
        "attachment_findings": [],
    }

    if attachment_detected:
        pdf_extract = extract_pdf_text_from_attachments(submission, attachment_names)
        attachment_signals["pdf_present"] = pdf_extract["pdf_present"]
        attachment_signals["pdf_text_available"] = pdf_extract["pdf_text_available"]
        attachment_signals["pdf_extraction_failed"] = pdf_extract["pdf_extraction_failed"]

        if pdf_extract["pdf_present"]:
            findings.append("A PDF attachment was detected and reviewed for invoice, payment, and identity-related signals.")
            risk_score += 2

        if pdf_extract["pdf_extraction_failed"] and any(k in combined_lower for k in action_keywords):
            findings.append("A PDF attachment could not be fully reviewed, and the email also requests action.")
            risk_score += 3

        if pdf_extract["pdf_text_available"]:
            pdf_signals = analyze_pdf_signals(
                pdf_text=pdf_extract["pdf_text"],
                sender_email=parsed_sender_email,
                sender_domain=sender_domain,
                display_name=display_name,
                body_text=body,
            )
            attachment_signals.update(pdf_signals)

            for finding in pdf_signals.get("attachment_findings", []):
                findings.append(finding)

            if pdf_signals.get("invoice_like_document"):
                risk_score += 8

            if pdf_signals.get("receipt_like_document"):
                risk_score += 3

            if pdf_signals.get("payment_instructions_present"):
                risk_score += 15

            if pdf_signals.get("bank_details_present"):
                risk_score += 8

            if pdf_signals.get("updated_payment_details_present"):
                risk_score += 25

            if pdf_signals.get("sensitive_info_request_present"):
                risk_score += 20

            if pdf_signals.get("urgency_in_attachment"):
                risk_score += 8

            if pdf_signals.get("attachment_only_action_pattern"):
                risk_score += 8

            if pdf_signals.get("attachment_identity_mismatch"):
                if pdf_signals.get("attachment_identity_mismatch_confidence") == "strong":
                    risk_score += 15
                else:
                    risk_score += 8

    reward_detected = any(k in combined_lower for k in reward_keywords)

    if reward_detected:
        findings.append("Message contains reward, prize, or financial incentive language.")

        if (
            info_request_detected
            or signals.get("payment_request")
            or signals.get("credential_request")
            or mismatch_detected
            or body_mismatch
            or any(k in combined_lower for k in action_keywords)
        ):
            risk_score += 20
            risk_score = max(risk_score, 80)
        else:
            risk_score += 5

        if link_domains:
            findings.append("Reward-style message includes links, which increases risk.")

        if signals.get("domain_mismatch") or body_mismatch:
            risk_score = max(risk_score, 80)

        weak_sender = False

        if not sender_domain:
            weak_sender = True
        elif any(x in sender_domain for x in ["gmail", "yahoo", "outlook", "hotmail"]):
            weak_sender = True
        elif signals.get("domain_mismatch"):
            weak_sender = True
        elif sender_domain.count(".") >= 2 and len(sender_domain.split(".")) > 2:
            weak_sender = True

        if weak_sender and link_domains:
            findings.append("Reward-style message from an unverified sender includes links.")
            risk_score = max(risk_score, 80)

        suspicious_tld_keywords = [
            ".pics", ".xyz", ".top", ".click", ".loan", ".online"
        ]

        unknown_domain = False

        if sender_domain:
            if any(sender_domain.endswith(tld) for tld in suspicious_tld_keywords):
                unknown_domain = True
            elif len(sender_domain.split(".")) > 2:
                unknown_domain = True

        if unknown_domain and any(k in combined_lower for k in action_keywords):
            findings.append("Reward-style message uses an unfamiliar or low-trust domain with action requested.")
            risk_score = max(risk_score, 80)

    unexpected_reward_detected = any(p in combined_lower for p in unexpected_reward_phrases)

    if unexpected_reward_detected:
        findings.append("The message offers an unexpected reward or benefit.")
        risk_score += 15
        risk_score = max(risk_score, 85)

    trusted_brand_detected = any(k in combined_lower for k in trusted_keywords)

    if any(p in combined_lower for p in google_trusted_context_phrases):
        trusted_brand_detected = True

    if trusted_brand_detected:
        if signals.get("domain_mismatch") or mismatch_detected or display_mismatch:
            findings.append("Message references a known organisation but sender details do not align.")
            risk_score += 20
            risk_score = max(risk_score, 75)

    impersonation_detected = False

    if trusted_brand_detected and (
        display_mismatch
        or mismatch_detected
        or body_mismatch
        or signals.get("domain_mismatch")
    ):
        impersonation_detected = True
        findings.append("The email appears to impersonate a known organisation.")
        risk_score += 15
        risk_score = max(risk_score, 85)

    if body_mismatch and trusted_brand_detected:
        findings.append("The message references a known organisation, but body contact details do not align.")
        risk_score = max(risk_score, 80)

    if body_mismatch and any(k in combined_lower for k in action_keywords):
        findings.append("Body contact mismatch combined with requested action increases risk.")
        risk_score = max(risk_score, 80)

    if body_mismatch and any(k in combined_lower for k in sensitive_request_keywords):
        findings.append("Body contact mismatch combined with sensitive or delivery-related requests increases risk.")
        risk_score = max(risk_score, 80)

    suspicious_tld_detected = False
    suspicious_tld_keywords = [".pics", ".xyz", ".top", ".click", ".loan", ".online"]

    if sender_domain and any(sender_domain.endswith(tld) for tld in suspicious_tld_keywords):
        suspicious_tld_detected = True

    strong_attachment_risk = any([
        attachment_signals.get("updated_payment_details_present"),
        attachment_signals.get("sensitive_info_request_present"),
        attachment_signals.get("payment_instructions_present") and attachment_signals.get("urgency_in_attachment"),
        attachment_signals.get("invoice_like_document") and attachment_signals.get("attachment_identity_mismatch"),
        attachment_signals.get("attachment_only_action_pattern") and (
            attachment_signals.get("payment_instructions_present")
            or attachment_signals.get("bank_details_present")
            or attachment_signals.get("sensitive_info_request_present")
        ),
    ])

    attachment_risky_context = any([
        reward_detected,
        unexpected_reward_detected,
        soft_urgency_detected,
        mismatch_detected,
        body_mismatch,
        display_mismatch,
        trusted_brand_detected,
        suspicious_tld_detected,
        large_value_detected,
        advance_fee_detected,
        info_request_detected,
        strong_attachment_risk,
    ])

    if attachment_detected and attachment_risky_context:
        findings.append("Attachment is especially risky because it appears in a suspicious email context.")
        risk_score = max(risk_score, 85)

    if attachment_detected and (reward_detected or unexpected_reward_detected or soft_urgency_detected):
        findings.append("Attachment combined with reward or urgency language increases risk.")
        risk_score = max(risk_score, 85)

    mismatch_count = 0
    if signals.get("domain_mismatch"):
        mismatch_count += 1
    if mismatch_detected:
        mismatch_count += 1
    if body_mismatch:
        mismatch_count += 1
    if display_mismatch:
        mismatch_count += 1
    if attachment_signals.get("attachment_identity_mismatch"):
        mismatch_count += 1

    if mismatch_count >= 2:
        risk_score = max(risk_score, 60)

    if mismatch_count >= 3:
        findings.append("Multiple identity mismatches detected across sender, content, links, or attachment content.")
        risk_score = max(risk_score, 80)

    if signals.get("payment_request"):
        risk_score = max(risk_score, 70)

    if signals.get("credential_request") and not signals.get("trusted_brand_alignment"):
        risk_score = max(risk_score, 75)

    if signals.get("payment_request") and signals.get("urgency"):
        risk_score = max(risk_score, 85)

    if signals.get("promotion") and signals.get("urgency"):
        risk_score = max(risk_score, 75)

    direct_money_phrases = [
        "send me money",
        "send money",
        "please send money",
        "money please",
        "transfer me",
        "transfer money",
        "pay me",
        "pay now",
        "i need money",
    ]

    direct_sensitive_phrases = [
        "send me your pin",
        "send your pin",
        "give me your password",
        "tell me your code",
    ]

    direct_money_detected = any(p in combined_lower for p in direct_money_phrases) or (
        "money" in combined_lower and ("send" in combined_lower or "transfer" in combined_lower or "pay" in combined_lower)
    )

    direct_sensitive_detected = any(p in combined_lower for p in direct_sensitive_phrases)

    if direct_money_detected:
        risk_score = max(risk_score, 85)

    if direct_sensitive_detected:
        risk_score = max(risk_score, 95)

    promotional_phrases = [
        "promote",
        "promotion",
        "marketing",
        "music",
        "album",
        "streams",
        "our services",
        "our service",
        "we help",
        "we provide",
        "we offer",
        "reaching out",
        "reach out",
        "introduce our",
        "introducing our",
        "business proposal",
        "partnership opportunity",
        "collaboration opportunity",
        "brand visibility",
        "digital marketing",
        "seo",
        "seo service",
        "lead generation",
        "advertising",
        "social media",
        "social media management",
        "website development",
        "ranking optimization",
        "ranking",
        "optimization",
        "search ranking",
        "search engine",
        "top page of google",
        "top page",
        "website",
        "minimal cost",
    ]

    unsubscribe_phrases = [
        "unsubscribe",
        "opt out",
        "remove me",
        "stop receiving",
        "mailing list",
    ]

    promotional_outreach_detected = any(p in combined_lower for p in promotional_phrases) or any(
        p in combined_lower for p in unsubscribe_phrases
    )

    dangerous_evidence = any([
        signals.get("payment_request"),
        signals.get("credential_request"),
        info_request_detected,
        unexpected_reward_detected,
        large_value_detected,
        advance_fee_detected,
        soft_urgency_detected,
        attachment_detected and attachment_risky_context,
        strong_attachment_risk,
        (mismatch_detected and any(k in combined_lower for k in action_keywords)),
        (body_mismatch and gmail_body_contact and info_request_detected),
        (trusted_brand_detected and (display_mismatch or mismatch_detected or body_mismatch)),
    ])

    if promotional_outreach_detected and not dangerous_evidence:
        findings.append("The message appears to be promotional or marketing outreach.")
        risk_score = min(risk_score, 35)

    trusted_promotional_detected = any(p in combined_lower for p in promotional_marketing_phrases)

    trusted_promotional_safe = (
        signals.get("trusted_brand_notification")
        and trusted_brand_detected
        and trusted_promotional_detected
        and not signals.get("payment_request")
        and not signals.get("sensitive_info_request")
        and not info_request_detected
        and not signals.get("suspicious_link")
        and not signals.get("domain_mismatch")
        and not mismatch_detected
        and not body_mismatch
        and not display_mismatch
        and not impersonation_detected
        and not unexpected_reward_detected
        and not large_value_detected
        and not advance_fee_detected
        and not strong_attachment_risk
        and not attachment_signals.get("payment_instructions_present")
        and not attachment_signals.get("updated_payment_details_present")
        and not attachment_signals.get("sensitive_info_request_present")
        and not attachment_signals.get("attachment_identity_mismatch")
    )

    if trusted_promotional_safe:
        findings.append("This appears to be a trusted-brand promotional or product-update email rather than a scam-style message.")
        risk_score = min(risk_score, 20)

    business_outreach_phrases = [
        "our company",
        "our business",
        "our agency",
        "our team",
        "our service",
        "our services",
        "we help businesses",
        "we help brands",
        "we can help",
        "we offer",
        "we provide",
        "book a call",
        "schedule a call",
        "quick call",
        "free consultation",
        "case study",
        "portfolio",
        "pricing",
        "packages",
        "learn more",
        "contact us",
        "visit our website",
    ]

    high_risk_financial_phrases = [
        "bank account",
        "bsb",
        "account number",
        "credit card",
        "debit card",
        "gift card",
        "wire transfer",
        "crypto",
        "wallet",
        "seed phrase",
        "payment details",
        "invoice attached",
        "pay this invoice",
    ]

    high_risk_identity_phrases = [
        "passport",
        "driver licence",
        "drivers licence",
        "license number",
        "medicare",
        "tax file number",
        "tfn",
        "one time password",
        "otp",
        "verification code",
        "security code",
        "pin",
        "password",
    ]

    marketing_signal_count = 0
    for phrase in promotional_phrases + unsubscribe_phrases + business_outreach_phrases:
        if phrase in combined_lower:
            marketing_signal_count += 1

    strict_dangerous_evidence = any([
        signals.get("payment_request"),
        signals.get("credential_request"),
        info_request_detected,
        signals.get("sensitive_info_request"),
        unexpected_reward_detected,
        large_value_detected,
        advance_fee_detected,
        authority_detected,
        impersonation_detected,
        soft_urgency_detected,
        direct_money_detected,
        direct_sensitive_detected,
        strong_attachment_risk,
        attachment_signals.get("payment_instructions_present"),
        attachment_signals.get("updated_payment_details_present"),
        attachment_signals.get("sensitive_info_request_present"),
        attachment_signals.get("attachment_identity_mismatch"),
        any(p in combined_lower for p in high_risk_financial_phrases),
        any(p in combined_lower for p in high_risk_identity_phrases),
        (body_mismatch and gmail_body_contact),
        (trusted_brand_detected and (display_mismatch or mismatch_detected or body_mismatch or signals.get("domain_mismatch"))),
    ])

    marketing_false_positive_override = (
        promotional_outreach_detected
        and marketing_signal_count >= 2
        and not strict_dangerous_evidence
    )

    if marketing_false_positive_override:
        findings.append("Final review: this appears more consistent with general marketing outreach than scam-style behaviour.")
        risk_score = min(risk_score, 20)

    # ------------------------------------------------------------
    # Reduce false 100s for realistic account/payment phishing
    # Keep them high risk, but not at absolute max unless
    # additional severe signals are present.
    # IMPORTANT: this cap must sit at the very end so later
    # escalation rules cannot push the score back to 100.
    # ------------------------------------------------------------
    realistic_phishing_high = (
        signals.get("has_links")
        and signals.get("urgency")
        and (
            signals.get("domain_mismatch")
            or mismatch_detected
            or display_mismatch
        )
        and (
            signals.get("credential_request")
            or signals.get("payment_request")
        )
        and not authority_detected
        and not unexpected_reward_detected
        and not large_value_detected
        and not advance_fee_detected
        and not direct_sensitive_detected
        and not direct_money_detected
        and not attachment_detected
    )

    if realistic_phishing_high:
        risk_score = min(risk_score, 95)

    # ------------------------------------------------------------
    # Attachment outcome guardrails
    # Prevent false reassurance on payment/sensitive attachment cases
    # ------------------------------------------------------------
    if strong_attachment_risk:
        risk_score = max(risk_score, 75)

    if attachment_signals.get("updated_payment_details_present"):
        risk_score = max(risk_score, 85)

    if attachment_signals.get("sensitive_info_request_present"):
        risk_score = max(risk_score, 85)

    if attachment_signals.get("payment_instructions_present") and attachment_signals.get("urgency_in_attachment"):
        risk_score = max(risk_score, 85)

    if attachment_signals.get("invoice_like_document") and attachment_signals.get("attachment_identity_mismatch"):
        risk_score = max(risk_score, 80)

    risk_score = max(0, min(100, risk_score))

    if risk_score >= 75:
        risk_rating = "High Risk"
        recommended_action = "Do not reply, click links, open attachments, or act on this email. Verify independently."
        should_reply = 0
    elif risk_score >= 40:
        risk_rating = "Needs Attention"
        recommended_action = "Do not act until independently verified. Review any attachment carefully before opening or relying on it."
        should_reply = 1
    else:
        risk_rating = "Low Risk"
        recommended_action = "No strong scam indicators found. This email appears low risk, but still verify before opening attachments or taking action."
        should_reply = 1

    # Final safeguard: strong attachment scenarios cannot be Low Risk
    if risk_rating == "Low Risk" and strong_attachment_risk:
        risk_rating = "Needs Attention"
        recommended_action = "Do not act until independently verified. The attachment contains payment, identity, or document-level warning signs."
        should_reply = 1

    unique_findings = list(dict.fromkeys(findings))
    unique_findings = [normalize_finding_text(f) for f in unique_findings]
    unique_findings = list(dict.fromkeys(unique_findings))

    if marketing_false_positive_override:
        confidence_label = "Moderate"
        confidence_reason = "The message contains clear marketing-style signals and no strong scam-style request or verification pattern."
    elif (
        risk_score >= 85
        or (signals.get("domain_mismatch") and mismatch_detected)
        or (signals.get("credential_request") and signals.get("suspicious_link"))
        or (signals.get("payment_request") and signals.get("urgency") and mismatch_detected)
        or (body_mismatch and trusted_brand_detected)
        or (display_mismatch and authority_detected)
        or (authority_detected and info_request_detected)
        or (authority_detected and advance_fee_detected)
        or impersonation_detected
        or unexpected_reward_detected
        or soft_urgency_detected
        or large_value_detected
        or advance_fee_detected
        or (attachment_detected and attachment_risky_context)
        or strong_attachment_risk
        or (body_mismatch and gmail_body_contact and info_request_detected)
    ):
        confidence_label = "High"
        confidence_reason = "Multiple strong warning signals were identified across sender, content, links, or attachment content."
    elif risk_score >= 50:
        confidence_label = "Moderate"
        confidence_reason = "Several warning signals were identified, but some context may still require manual verification."
    else:
        confidence_label = "Lower"
        confidence_reason = "Some caution signals were identified, but the evidence is limited or mixed."

    return {
        "risk_score": risk_score,
        "risk_rating": risk_rating,
        "summary": f"{risk_rating} email based on sender, content, link, and attachment analysis.",
        "human_summary": recommended_action,
        "findings": unique_findings,
        "findings_count": len(unique_findings),
        "recommended_action": recommended_action,
        "should_reply": should_reply,
        "confidence_label": confidence_label,
        "confidence_reason": confidence_reason,
        "has_attachments": attachment_detected,
        "attachment_names": attachment_names,
        "attachment_signals": attachment_signals,
        "proposed_response": build_response({
            "from_header": from_header,
            "risk_rating": risk_rating,
            "recommended_action": recommended_action,
            "findings": unique_findings
        }),
    }