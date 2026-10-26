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
    from review_checks import BRANDS
except Exception:  # pragma: no cover
    BRANDS = {}

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
    brand = (submission.get("brand") or "").strip()
    if brand and brand not in BRANDS:
        # Brand named by the screenshot review: still useful, without a site.
        pass
    genuine = bool(submission.get("verdict_note"))
    action = (submission.get("recommended_action") or "").strip()
    specific = action and not action.startswith(GENERIC_ACTION_PREFIXES)

    steps = []
    if specific:
        steps.append(action)

    if genuine and brand:
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
