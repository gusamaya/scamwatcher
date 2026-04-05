# trust_lists.py

"""
ScamWatcher / CAI trust and block reference lists.

Purpose:
- Keep trusted and blocked domain logic OUT of analyzer.py
- Provide a clean source of truth for sender/link domain reputation context
- Support scoring adjustments without hardcoding lots of brand logic everywhere

Principles:
- Trusted domains lower suspicion, but do not automatically make an email safe
- Blocked domains raise suspicion significantly
- Brand alignment is stronger when both sender and links align to the same trusted brand
"""


TRUSTED_BRANDS = {
    "google": {
        "sender_domains": {
            "google.com",
        },
        "link_domains": {
            "google.com",
            "accounts.google.com",
            "support.google.com",
            "notifications.google.com",
            "mail.google.com",
        },
    },
    "microsoft": {
        "sender_domains": {
            "microsoft.com",
            "office.com",
            "microsoftonline.com",
        },
        "link_domains": {
            "microsoft.com",
            "office.com",
            "microsoftonline.com",
            "account.microsoft.com",
            "login.microsoftonline.com",
            "support.microsoft.com",
        },
    },
    "apple": {
        "sender_domains": {
            "apple.com",
            "email.apple.com",
        },
        "link_domains": {
            "apple.com",
            "id.apple.com",
            "support.apple.com",
            "email.apple.com",
        },
    },
    "xero": {
        "sender_domains": {
            "xero.com",
        },
        "link_domains": {
            "xero.com",
            "login.xero.com",
            "go.xero.com",
        },
    },
    "technologyone": {
        "sender_domains": {
            "technologyonecorp.com",
        },
        "link_domains": {
            "technologyonecorp.com",
        },
    },
    "amazon": {
        "sender_domains": {
            "amazon.com",
            "amazon.com.au",
        },
        "link_domains": {
            "amazon.com",
            "amazon.com.au",
            "amazon.com/ap/signin",
        },
    },
    "paypal": {
        "sender_domains": {
            "paypal.com",
        },
        "link_domains": {
            "paypal.com",
            "www.paypal.com",
        },
    },
}


BLOCKED_DOMAINS = {
    # Seed examples only — expand over time from real submissions
    "goog1e-login.net",
    "google-login-alert.net",
    "micr0soft-secure.net",
    "paypa1-alerts.net",
    "account-verify-paypal.net",
}


def normalise_domain(domain):
    """
    Lowercase and strip surrounding whitespace / dots.
    """
    if not domain:
        return ""

    return str(domain).strip().lower().strip(".")


def domain_matches(candidate, reference):
    """
    True when:
    - candidate exactly matches reference, or
    - candidate is a subdomain of reference

    Examples:
    - accounts.google.com matches google.com
    - google.com matches google.com
    - evilgoogle.com does NOT match google.com
    """
    candidate = normalise_domain(candidate)
    reference = normalise_domain(reference)

    if not candidate or not reference:
        return False

    return candidate == reference or candidate.endswith("." + reference)


def is_blocked_domain(domain):
    """
    Check whether a domain matches anything in the blocked domain set.
    """
    domain = normalise_domain(domain)

    if not domain:
        return False

    for blocked in BLOCKED_DOMAINS:
        if domain_matches(domain, blocked):
            return True

    return False


def get_brand_for_sender_domain(sender_domain):
    """
    Return the trusted brand key if the sender domain matches one of the
    known trusted sender domains.
    """
    sender_domain = normalise_domain(sender_domain)

    if not sender_domain:
        return None

    for brand, rules in TRUSTED_BRANDS.items():
        for trusted_sender in rules.get("sender_domains", set()):
            if domain_matches(sender_domain, trusted_sender):
                return brand

    return None


def is_trusted_sender_domain(sender_domain):
    """
    True if sender domain matches any trusted sender domain.
    """
    return get_brand_for_sender_domain(sender_domain) is not None


def is_trusted_link_domain(link_domain):
    """
    True if link domain matches any trusted link domain for any brand.
    """
    link_domain = normalise_domain(link_domain)

    if not link_domain:
        return False

    for rules in TRUSTED_BRANDS.values():
        for trusted_link in rules.get("link_domains", set()):
            if domain_matches(link_domain, trusted_link):
                return True

    return False


def brand_link_alignment(sender_domain, link_domains):
    """
    Returns a tuple:
    (
        trusted_brand_alignment: bool,
        sender_brand: str | None,
        aligned_links: list[str],
        misaligned_links: list[str],
    )

    Logic:
    - Find the sender's trusted brand, if any
    - Check whether each link aligns to that same brand
    - Alignment only means something when sender domain belongs to a trusted brand
    """
    sender_brand = get_brand_for_sender_domain(sender_domain)

    if not sender_brand:
        return False, None, [], list(link_domains or [])

    brand_rules = TRUSTED_BRANDS.get(sender_brand, {})
    trusted_links = brand_rules.get("link_domains", set())

    aligned_links = []
    misaligned_links = []

    for link_domain in link_domains or []:
        matched = False
        for trusted_link in trusted_links:
            if domain_matches(link_domain, trusted_link):
                matched = True
                break

        if matched:
            aligned_links.append(link_domain)
        else:
            misaligned_links.append(link_domain)

    trusted_brand_alignment = len(aligned_links) > 0 and len(misaligned_links) == 0

    return trusted_brand_alignment, sender_brand, aligned_links, misaligned_links