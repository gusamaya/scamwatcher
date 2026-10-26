"""The plain-language advice shown at the very top of every reply.

One headline that says what we think, then two to four numbered steps the
person can follow straight away. Everything else in the reply (the checks,
what we noticed, the original message) sits underneath as the explanation.

When we know which organisation the message names (Telstra, a bank, the
ATO...), the steps tell people who deal with that organisation to contact it
directly through its official app or website, and everyone else to delete it.
"""

import html

try:
    import review_checks
    from review_checks import BRANDS
except Exception:  # pragma: no cover
    review_checks = None
    BRANDS = {}


def infer_brand(submission):
    """Work out the organisation from the sender, for submissions saved before
    the brand was stored (or where the review didn't record one)."""
    if review_checks is None:
        return ""
    try:
        display, _address, domain = review_checks.parse_sender(submission.get("from_header") or "")
        return (
            review_checks.brand_claimed_by_display_name(display)
            or review_checks.brand_imitated_by_domain(domain)
            # A personal Gmail or Outlook address isn't Google or Microsoft.
            or ("" if domain in review_checks.FREE_EMAIL_PROVIDERS else review_checks.official_brand_of(domain))
            or ""
        )
    except Exception:
        return ""

# Organisations you "deal with" rather than are a "customer" of.
GOVERNMENT_BRANDS = {
    "ATO", "myGov", "Services Australia", "ASIC", "AFP", "Service NSW",
    "Queensland Government", "VicRoads",
}

# Advice the rule engine writes for every email of a given rating. When the
# recommended action is one of these, the steps below replace it. Anything
# else was written for this message (by a reviewer or the screenshot review)
# and is shown as the first step.
GENERIC_ACTION_PREFIXES = (
    "Do not reply, click links, open attachments",
    "Do not act until independently verified",
    "No strong scam indicators found",
    "This looks like a real ",
)


# Names that read naturally with "the" in front: "the ATO", "the AFP".
THE_BRANDS = {"ATO", "AFP", "ASIC"}


def _name(brand):
    return f"the {brand}" if brand in THE_BRANDS else brand


MARKETING_WORDS = (
    "unsubscribe", "opt out", "opt-out", "mailing list", "newsletter", "stop receiving",
    "manage your preferences", "email preferences", "you received this email because",
    "% off", "sale", "shop now", "book now", "special offer", "deal", "promo", "discount",
)
RISKY_REQUESTS = {"payment", "credentials", "sensitive", "bank_change", "untraceable_payment",
                  "remote_access", "personal_info", "prize", "callback"}


def is_marketing(submission):
    """Advertising rather than a scam. Recorded by the analyser for new
    emails; for ones assessed before that, worked out from the email itself
    (Low Risk, advertising wording, and no request for money, details,
    sign-in or a call)."""
    kind = (submission.get("message_kind") or "")
    if kind:
        return kind == "marketing"
    if "low" not in (submission.get("risk_rating") or "").lower():
        return False
    if submission.get("verdict_note") or submission.get("submission_type") == "web_form":
        return False
    findings = submission.get("findings") or []
    if isinstance(findings, str):
        findings = [findings]
    if any("general marketing outreach" in str(f).lower() for f in findings):
        return True
    text = f"{submission.get('subject') or ''}\n{submission.get('body') or ''}"
    lowered = text.lower()
    if not any(w in lowered for w in MARKETING_WORDS):
        return False
    if review_checks is None:
        return False
    try:
        signals = set(review_checks.check_content(submission.get("subject") or "", submission.get("body") or "").get("signals") or [])
    except Exception:
        return False
    return not (signals & RISKY_REQUESTS)


def _sender_name(submission):
    if review_checks is None:
        return ""
    try:
        display, address, _domain = review_checks.parse_sender(submission.get("from_header") or "")
        return (display or "").strip().strip('"')
    except Exception:
        return ""


def _official_site(brand):
    domains = (BRANDS.get(brand) or {}).get("domains") or []
    return domains[0] if domains else ""


def _relationship(brand):
    if brand in GOVERNMENT_BRANDS:
        return f"If you deal with {_name(brand)}"
    return f"If you're a {brand} customer"


def _contact_step(brand, action="check your account"):
    site = _official_site(brand)
    where = f"open the {brand} app or type {site} into your browser" if site else \
        f"open the {brand} app or type their website address into your browser yourself"
    return f"{_relationship(brand)}, {where} to {action}. Or call the number on your bill or their website."


def build(submission, money_contact="your bank"):
    """Return {"tone", "headline", "steps"} for a submission dict."""
    rating = (submission.get("risk_rating") or "").lower()
    brand = (submission.get("brand") or "").strip() or infer_brand(submission)
    if brand and brand not in BRANDS:
        # Brand named by the screenshot review: still useful, without a site.
        pass
    marketing = is_marketing(submission)
    genuine = bool(submission.get("verdict_note")) and not marketing
    action = (submission.get("recommended_action") or "").strip()
    specific = action and not action.startswith(GENERIC_ACTION_PREFIXES)

    steps = []
    if specific:
        steps.append(action)

    if marketing and "high" not in rating and "attention" not in rating:
        tone = "low"
        name = brand or _sender_name(submission) or "a company"
        headline = f"This looks like marketing from {_name(name) if name in BRANDS else name}, not a scam."
        steps += [
            "There are no signs of a scam. It's an advertising email, so you don't need to do anything.",
            "If you don't want these emails, unsubscribe in your account settings on their official website or app.",
            "As always, don't enter passwords or card details through a link in an email. Go to the website yourself.",
        ]
    elif genuine and brand:
        tone = "genuine"
        headline = f"This looks like a real {brand} message, but don't use its links."
        steps += [
            _contact_step(brand, "check your account and pay"),
            "Don't click the links or call the phone number in it, just to be safe.",
            f"If you're not a {brand} customer, it isn't meant for you. Delete it."
            if brand not in GOVERNMENT_BRANDS else
            f"If you don't deal with {_name(brand)}, it isn't meant for you. Delete it.",
        ]
    elif "high" in rating:
        tone = "high"
        headline = f"This looks like a scam pretending to be {_name(brand)}." if brand else "This looks like a scam."
        steps.append("Don't click the links, reply, call any number in it, or pay anything.")
        if brand:
            steps.append(_contact_step(brand, "check your account"))
        steps.append("Then delete the message.")
        steps.append(
            f"Already clicked, paid or shared details? Contact {money_contact} straight away"
            + (f" and tell {_name(brand)}" if brand else "") + ", and change your passwords."
        )
    elif "attention" in rating or "medium" in rating:
        tone = "attention"
        headline = (f"Be careful: this message about {_name(brand)} has warning signs." if brand
                    else "Be careful: this message has warning signs.")
        steps.append("Don't click the links, reply, or pay until you've checked it.")
        if brand:
            steps.append(_contact_step(brand, "check whether it's real"))
        else:
            steps.append("Check it with the person or organisation directly, using contact details you already have.")
        steps.append(f"Already clicked, paid or shared details? Contact {money_contact} straight away.")
    else:
        tone = "low"
        headline = "We didn't find signs of a scam."
        if brand:
            steps.append(f"If you need to act on it, use the {brand} app or type their website address yourself, rather than the links.")
        else:
            steps.append("If you need to act on it, go to the organisation's official app or website rather than the links.")

    # Keep it short: at most four steps, no repeats.
    seen, unique = set(), []
    for step in steps:
        key = step.lower().strip()
        if key and key not in seen:
            seen.add(key)
            unique.append(step)
    return {"tone": tone, "headline": headline, "steps": unique[:4]}


TONE_STYLES = {
    # background, border, headline colour
    "high": ("#FEF2F2", "#B91C1C", "#991B1B"),
    "attention": ("#FFFBEB", "#B45309", "#92400E"),
    "genuine": ("#F0FDF4", "#15803D", "#166534"),
    "low": ("#F0FDF4", "#15803D", "#166534"),
}


def html_box(submission, money_contact="your bank"):
    advice = build(submission, money_contact)
    bg, border, colour = TONE_STYLES.get(advice["tone"], TONE_STYLES["attention"])
    items = "".join(
        f'<li style="margin:0 0 8px 0;">{html.escape(step)}</li>' for step in advice["steps"]
    )
    return f"""
            <div style="background:{bg}; border:1px solid {border}; border-left:5px solid {border}; border-radius:10px; padding:16px 18px; margin:0 0 24px 0;">
                <div style="font-size:18px; line-height:1.35; font-weight:700; color:{colour}; margin-bottom:10px;">{html.escape(advice["headline"])}</div>
                <div style="font-size:14px; font-weight:700; color:#111827; margin-bottom:6px;">What to do now:</div>
                <ol style="margin:0 0 0 20px; padding:0; font-size:15px; line-height:1.55; color:#111827;">
                    {items}
                </ol>
            </div>
    """


def text_block(submission, money_contact="your bank"):
    advice = build(submission, money_contact)
    lines = [advice["headline"].upper(), "", "What to do now:"]
    lines += [f"{i}. {step}" for i, step in enumerate(advice["steps"], 1)]
    return lines
