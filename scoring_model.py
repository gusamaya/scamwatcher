import re
from urllib.parse import urlparse


FREE_EMAIL_PROVIDERS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.com.au",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "icloud.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "bigpond.com",
    "bigpond.net.au",
}


KNOWN_BRANDS = {
    "google": ["google.com", "accounts.google.com", "workspace.google.com"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.com.au"],
    "paypal": ["paypal.com"],
    "debank": ["debank.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com", "meta.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "xero": ["xero.com"],
    "mygov": ["my.gov.au"],
    "ato": ["ato.gov.au"],
    "auspost": ["auspost.com.au"],
    "telstra": ["telstra.com.au"],
}


URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\basap\b",
    r"\bright now\b",
    r"\bwithin \d+ (hours?|days?)\b",
    r"\baction required\b",
    r"\bfinal notice\b",
    r"\brespond now\b",
    r"\btime sensitive\b",
    r"\bverify now\b",
    r"\bact now\b",
    r"\bimportant notice\b",
]

PAYMENT_PATTERNS = [
    r"\bpayment\b",
    r"\bpay\b",
    r"\btransfer\b",
    r"\bbank transfer\b",
    r"\bwire\b",
    r"\bremittance\b",
    r"\binvoice\b",
    r"\bdeposit\b",
    r"\bbsb\b",
    r"\baccount number\b",
    r"\bpayid\b",
    r"\bgift card\b",
    r"\bsettlement\b",
    r"\boverdue\b",
    r"\bsend me money\b",
]

CREDENTIAL_PATTERNS = [
    r"\bpassword\b",
    r"\blogin\b",
    r"\bsign in\b",
    r"\bverification code\b",
    r"\bpin code\b",
    r"\b2fa\b",
    r"\bmfa\b",
    r"\bone-time code\b",
    r"\botp\b",
    r"\bconfirm your account\b",
    r"\bverify your identity\b",
    r"\bsecurity alert\b",
]

PROMOTION_PATTERNS = [
    r"promo code",
    r"prize",
    r"reward",
    r"bonus",
    r"\bwon\b",
    r"winner",
    r"winner id",
    r"claim now",
    r"congratulations",
    r"free",
    r"giveaway",
    r"new notification",
]

SENSITIVE_INFO_PATTERNS = [
    r"\bdriver'?s licence\b",
    r"\bpassport\b",
    r"\bmedicare\b",
    r"\bdate of birth\b",
    r"\bdob\b",
    r"\bpersonal information\b",
    r"\bidentity\b",
    r"\baccount information\b",
]

GENERIC_GREETING_PATTERNS = [
    r"\bdear customer\b",
    r"\bdear user\b",
    r"\bhello customer\b",
    r"\bvalued customer\b",
]

SUSPICIOUS_TLDS = {
    ".ru", ".cn", ".top", ".xyz", ".click", ".shop", ".info", ".biz"
}


def _safe_lower(value):
    return (value or "").strip().lower()


def _extract_email_address(from_header):
    if not from_header:
        return ""
    match = re.search(r"<([^>]+)>", from_header)
    if match:
        return match.group(1).strip().lower()
    email_match = re.search(r"([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})", from_header, re.I)
    return email_match.group(1).strip().lower() if email_match else ""


def _extract_display_name(from_header):
    if not from_header:
        return ""
    if "<" in from_header:
        return from_header.split("<", 1)[0].strip().strip('"').strip()
    return ""


def _extract_domain_from_email(email_address):
    if "@" not in (email_address or ""):
        return ""
    return email_address.split("@", 1)[1].strip().lower()


def _extract_urls(text):
    if not text:
        return []
    raw_urls = re.findall(r'https?://[^\s<>"\']+', text, flags=re.I)
    return [url.rstrip(").,;]>") for url in raw_urls]


def _get_domain_from_url(url):
    try:
        parsed = urlparse(url)
        domain = (parsed.netloc or "").lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return ""


def _matches_any_pattern(text, patterns):
    lowered = _safe_lower(text)
    for pattern in patterns:
        if re.search(pattern, lowered, flags=re.I):
            return True
    return False


def _find_brand_mentions(text):
    lowered = _safe_lower(text)
    matches = []
    for brand in KNOWN_BRANDS.keys():
        if re.search(rf"\b{re.escape(brand)}\b", lowered):
            matches.append(brand)
    return matches


def _domain_matches_brand(domain, brand):
    if not domain or brand not in KNOWN_BRANDS:
        return False
    allowed_domains = KNOWN_BRANDS[brand]
    return any(domain == allowed or domain.endswith("." + allowed) for allowed in allowed_domains)


def _looks_like_suspicious_sender_format(email_address):
    if not email_address:
        return True

    local_part = email_address.split("@", 1)[0]
    if len(local_part) > 35:
        return True

    if re.search(r"\d{5,}", local_part):
        return True

    if re.search(r"[._-]{3,}", local_part):
        return True

    return False


def _looks_like_deceptive_domain(domain):
    if not domain:
        return False

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        return True

    deceptive_keywords = [
        "secure-login",
        "verify-now",
        "account-update",
        "wallet-verify",
        "auth-check",
    ]
    return any(keyword in domain for keyword in deceptive_keywords)


def _build_signals(from_header, subject, body):
    combined_text = f"{subject or ''}\n{body or ''}".strip()

    sender_email = _extract_email_address(from_header)
    sender_domain = _extract_domain_from_email(sender_email)
    display_name = _extract_display_name(from_header)

    urls = _extract_urls(body or "")
    url_domains = []
    for url in urls:
        domain = _get_domain_from_url(url)
        if domain:
            url_domains.append(domain)

    brand_mentions = _find_brand_mentions(combined_text)

    sender_brand_aligned = False
    any_link_brand_aligned = False
    has_brand_domain_mismatch = False

    if brand_mentions:
        for brand in brand_mentions:
            if sender_domain and _domain_matches_brand(sender_domain, brand):
                sender_brand_aligned = True
            if any(_domain_matches_brand(link_domain, brand) for link_domain in url_domains):
                any_link_brand_aligned = True

        for brand in brand_mentions:
            brand_sender_mismatch = sender_domain and not _domain_matches_brand(sender_domain, brand)
            brand_link_mismatch = bool(url_domains) and any(
                not _domain_matches_brand(link_domain, brand) for link_domain in url_domains
            )

            if brand_sender_mismatch or brand_link_mismatch:
                if not (sender_brand_aligned or any_link_brand_aligned):
                    has_brand_domain_mismatch = True
                    break

    suspicious_link_domains = []
    for domain in url_domains:
        if _looks_like_deceptive_domain(domain):
            suspicious_link_domains.append(domain)

    mass_recipient_count = (body or "").count("@")

    account_reference = bool(
        re.search(r"\b(account|wallet|notification|security|message)\b", _safe_lower(combined_text))
    )

    payment_request = _matches_any_pattern(combined_text, PAYMENT_PATTERNS)
    credential_request = _matches_any_pattern(combined_text, CREDENTIAL_PATTERNS)
    promotion = _matches_any_pattern(combined_text, PROMOTION_PATTERNS)

    trusted_brand_notification = bool(brand_mentions) and (
        (sender_brand_aligned or any_link_brand_aligned)
        and not has_brand_domain_mismatch
        and len(suspicious_link_domains) == 0
    )

    signals = {
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "display_name": display_name,
        "urls": urls,
        "url_domains": url_domains,
        "brand_mentions": brand_mentions,
        "has_links": len(urls) > 0,
        "unverified_sender": not bool(sender_email),
        "free_email_provider": sender_domain in FREE_EMAIL_PROVIDERS if sender_domain else False,
        "suspicious_sender_format": _looks_like_suspicious_sender_format(sender_email),
        "sender_brand_aligned": sender_brand_aligned,
        "any_link_brand_aligned": any_link_brand_aligned,
        "trusted_brand_alignment": bool(brand_mentions) and (sender_brand_aligned or any_link_brand_aligned),
        "trusted_brand_notification": trusted_brand_notification,
        "domain_mismatch": has_brand_domain_mismatch,
        "urgency": _matches_any_pattern(combined_text, URGENCY_PATTERNS),
        "payment_request": payment_request,
        "credential_request": credential_request,
        "promotion": promotion,
        "sensitive_info_request": _matches_any_pattern(combined_text, SENSITIVE_INFO_PATTERNS),
        "generic_greeting": _matches_any_pattern(combined_text, GENERIC_GREETING_PATTERNS),
        "mass_recipients": mass_recipient_count >= 3,
        "deceptive_link_domain": len(suspicious_link_domains) > 0,
        "suspicious_link": (
            len(suspicious_link_domains) > 0
            or (has_brand_domain_mismatch and not (sender_brand_aligned or any_link_brand_aligned))
        ),
        "account_reference": account_reference,
        "gift_card_language": bool(re.search(r"\bgift card\b", _safe_lower(combined_text))),
    }

    return signals


def _base_score_from_signals(signals):
    score = 0
    findings = []

    if signals["unverified_sender"]:
        score += 10
        findings.append("The sender identity could not be reliably parsed from the email header.")

    if signals["free_email_provider"]:
        score += 8
        findings.append("The sender uses a free email service, which may be unusual for some business or official requests.")

    if signals["suspicious_sender_format"] and not signals["unverified_sender"]:
        score += 6
        findings.append("The sender address format appears unusual and may warrant extra caution.")

    if signals["domain_mismatch"]:
        score += 22
        findings.append("The sender or linked domain does not clearly align with the organisation named in the email.")

    if signals["deceptive_link_domain"]:
        score += 16
        findings.append("The message includes a link domain that appears unusual or potentially misleading.")

    if signals["urgency"]:
        score += 12
        findings.append("The message uses urgency or time pressure language.")

    if signals["payment_request"]:
        score += 24
        findings.append("The email includes a request relating to payment or transfer of funds.")

    if signals["credential_request"]:
        score += 22
        findings.append("The email requests login, security, or authentication-related information.")

    if signals["promotion"]:
        score += 14
        findings.append("The message includes promotional, prize, or reward-style language.")

    if signals["sensitive_info_request"]:
        score += 16
        findings.append("The email requests or references sensitive personal, identity, or account information.")

    if signals["generic_greeting"]:
        score += 5
        findings.append("The greeting is generic rather than clearly personalised.")

    if signals["mass_recipients"]:
        score += 6
        findings.append("The message appears to have been sent to multiple recipients.")

    return score, findings


def _apply_combination_rules(signals, score, findings):
    if signals["urgency"] and signals["promotion"]:
        score += 12
        findings.append("Urgency combined with promotional language increases caution.")

    if signals["urgency"] and signals["payment_request"]:
        score += 14
        findings.append("Urgency combined with a payment-related request increases risk.")

    if signals["payment_request"] and signals["credential_request"]:
        score += 16
        findings.append("The email combines financial and account-access related signals.")

    if signals["suspicious_link"] and signals["account_reference"]:
        score += 12
        findings.append("A link is included alongside account or notification-related language.")

    if signals["suspicious_link"] and signals["brand_mentions"]:
        score += 10
        findings.append("A branded message includes a link that does not clearly align with that brand.")

    if signals["mass_recipients"] and signals["promotion"]:
        score += 8
        findings.append("Bulk-recipient promotional messaging increases caution.")

    if signals["unverified_sender"] and signals["promotion"]:
        score += 8
        findings.append("Promotional language from an unclear sender increases caution.")

    if signals["free_email_provider"] and signals["payment_request"]:
        score += 10
        findings.append("A payment-related request from a free email domain warrants extra caution.")

    if signals["gift_card_language"] and signals["urgency"]:
        score += 12
        findings.append("Urgent gift card-related language is a common scam pattern.")

    if signals["trusted_brand_alignment"] and not signals["domain_mismatch"]:
        score -= 18
        findings.append("The sender or linked domain appears to align with the named organisation.")

    if (
        signals["trusted_brand_notification"]
        and signals["credential_request"]
        and not signals["payment_request"]
        and not signals["suspicious_link"]
        and not signals["domain_mismatch"]
    ):
        score -= 18
        findings.append("This appears to be an account or security notification from an aligned branded domain.")

    # Promotional override
    if signals["promotion"] and not (
        signals["payment_request"]
        or signals["credential_request"]
        or signals["domain_mismatch"]
        or signals["suspicious_link"]
    ):
        score = min(score, 25)
        findings.append("The message appears to be general promotional or marketing communication.")

    # Trusted branded account/security notification cap
    if (
        signals["trusted_brand_notification"]
        and signals["credential_request"]
        and not signals["payment_request"]
        and not signals["sensitive_info_request"]
        and not signals["domain_mismatch"]
        and not signals["suspicious_link"]
    ):
        score = min(score, 55)
        findings.append("Aligned branded security-style notifications should still be reviewed, but are not high risk on wording alone.")

    return max(score, 0), findings


def _apply_risk_floors(signals, score):
    # Skip floors for clean promotional emails
    if signals["promotion"] and not (
        signals["payment_request"]
        or signals["credential_request"]
        or signals["domain_mismatch"]
        or signals["suspicious_link"]
    ):
        return min(score, 30)

    # Soften credential floor for aligned branded notifications
    if not (
        signals["trusted_brand_notification"]
        and signals["credential_request"]
        and not signals["payment_request"]
        and not signals["domain_mismatch"]
        and not signals["suspicious_link"]
    ):
        if signals["credential_request"]:
            score = max(score, 40)

    if signals["payment_request"]:
        score = max(score, 35)

    if signals["promotion"] and signals["urgency"]:
        score = max(score, 45)

    if signals["suspicious_link"] and not signals["trusted_brand_notification"]:
        score = max(score, 42)

    if signals["domain_mismatch"]:
        score = max(score, 50)

    return min(score, 100)


def _risk_rating_from_score(score):
    if score >= 70:
        return "High Risk"
    if score >= 30:
        return "Needs Attention"
    return "Low Risk"


def score_attachment_signals(attachment_signals):
    """
    Optional helper for future use.
    Safe to call with an empty dict.
    Returns a small isolated score package so attachment logic can stay modular.
    """
    attachment_signals = attachment_signals or {}

    score = 0
    reasons = []
    floor_flags = {
        "prevent_low_risk": False,
    }

    if attachment_signals.get("attachment_present"):
        score += 3
        reasons.append("The email includes one or more attachments.")

    if attachment_signals.get("pdf_present"):
        score += 2
        reasons.append("A PDF attachment was included.")

    if attachment_signals.get("pdf_extraction_failed"):
        score += 3
        reasons.append("A PDF attachment could not be fully reviewed.")

    if attachment_signals.get("invoice_like_document"):
        score += 8
        reasons.append("The attachment appears to contain invoice or payment-related content.")

    if attachment_signals.get("receipt_like_document"):
        score += 3
        reasons.append("The attachment appears to contain receipt or remittance-style content.")

    if attachment_signals.get("payment_instructions_present"):
        score += 15
        reasons.append("The attachment includes payment instructions.")

    if attachment_signals.get("bank_details_present"):
        score += 8
        reasons.append("The attachment includes bank or account details.")

    if attachment_signals.get("updated_payment_details_present"):
        score += 25
        reasons.append("The attachment references updated or changed banking details.")
        floor_flags["prevent_low_risk"] = True

    if attachment_signals.get("sensitive_info_request_present"):
        score += 20
        reasons.append("The attachment appears to request sensitive personal or account information.")
        floor_flags["prevent_low_risk"] = True

    if attachment_signals.get("urgency_in_attachment"):
        score += 8
        reasons.append("The attachment uses urgency or pressure language.")

    if attachment_signals.get("attachment_only_action_pattern"):
        score += 8
        reasons.append("The attachment contains the main request or action.")

    if attachment_signals.get("attachment_identity_mismatch"):
        if attachment_signals.get("attachment_identity_mismatch_confidence") == "strong":
            score += 15
            reasons.append("The business identity in the attachment does not clearly align with the sender.")
        else:
            score += 8
            reasons.append("The business identity in the attachment may not align with the sender.")

    if (
        attachment_signals.get("payment_instructions_present")
        and attachment_signals.get("urgency_in_attachment")
    ):
        floor_flags["prevent_low_risk"] = True

    if (
        attachment_signals.get("invoice_like_document")
        and attachment_signals.get("attachment_identity_mismatch")
    ):
        floor_flags["prevent_low_risk"] = True

    seen = set()
    unique_reasons = []
    for reason in reasons:
        if reason not in seen:
            unique_reasons.append(reason)
            seen.add(reason)

    return {
        "score": min(max(score, 0), 100),
        "reasons": unique_reasons,
        "floor_flags": floor_flags,
    }


def assess_email_risk(from_header, subject, body):
    signals = _build_signals(from_header, subject, body)

    score, findings = _base_score_from_signals(signals)
    score, findings = _apply_combination_rules(signals, score, findings)
    score = _apply_risk_floors(signals, score)

    seen = set()
    unique_findings = []
    for finding in findings:
        if finding not in seen:
            unique_findings.append(finding)
            seen.add(finding)

    return {
        "score": score,
        "risk_rating": _risk_rating_from_score(score),
        "findings": unique_findings,
        "signals": signals,
    }
