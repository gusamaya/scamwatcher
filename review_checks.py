"""
ScamWatcher structured review.

Runs four independent checks on an email and returns a verdict for each:

    1. Sender & domain   - is the sender who they claim to be?
    2. Content           - what is the email asking the reader to do?
    3. Links             - where do the links actually go?
    4. Known scams       - does it match a scam campaign we know about?

Each check returns:
    {
        "key":      "sender" | "content" | "links" | "known_scams",
        "title":    human-readable name,
        "status":   "fail" | "caution" | "pass" | "info",
        "headline": one plain-English sentence,
        "details":  list of plain-English observations,
    }

Everything here works offline (no web lookups), so it is fast and predictable.
To keep it current, add brands to BRANDS and campaigns to SCAM_PATTERNS.
"""

import ipaddress
import re
from urllib.parse import urlparse, parse_qs, unquote

try:
    from trust_lists import BLOCKED_DOMAINS
except Exception:  # pragma: no cover
    BLOCKED_DOMAINS = set()


# ----------------------------------------------------------------------
# Brand registry
# ----------------------------------------------------------------------
# names:   how the brand appears in a display name or email text
# domains: official domains (subdomains of these are also official)
# ----------------------------------------------------------------------

BRANDS = {
    # Delivery
    "Australia Post": {"names": ["australia post", "auspost", "aus post"], "domains": ["auspost.com.au"]},
    "StarTrack": {"names": ["startrack"], "domains": ["startrack.com.au", "auspost.com.au"]},
    "DHL": {"names": ["dhl"], "domains": ["dhl.com", "dhl.com.au", "dhl.de"]},
    "FedEx": {"names": ["fedex"], "domains": ["fedex.com"]},
    "Aramex": {"names": ["aramex", "fastway"], "domains": ["aramex.com.au", "aramex.com"]},
    # Tolls and transport
    "Linkt": {"names": ["linkt", "transurban"], "domains": ["linkt.com.au", "transurban.com"]},
    "Service NSW": {"names": ["service nsw"], "domains": ["service.nsw.gov.au", "nsw.gov.au"]},
    "Queensland Government": {"names": ["queensland government", "qld government", "tmr", "transport and main roads"], "domains": ["qld.gov.au"]},
    "VicRoads": {"names": ["vicroads"], "domains": ["vicroads.vic.gov.au", "vic.gov.au"]},
    # Government
    "ATO": {"names": ["australian taxation office", "ato", "tax office"], "domains": ["ato.gov.au"]},
    "myGov": {"names": ["mygov", "my gov"], "domains": ["my.gov.au", "servicesaustralia.gov.au"]},
    "Services Australia": {"names": ["services australia", "centrelink", "medicare"], "domains": ["servicesaustralia.gov.au", "my.gov.au", "humanservices.gov.au"]},
    "ASIC": {"names": ["asic"], "domains": ["asic.gov.au"]},
    "AFP": {"names": ["australian federal police", "afp"], "domains": ["afp.gov.au"]},
    # Banks and payments
    "CommBank": {"names": ["commonwealth bank", "commbank", "netbank", "cba"], "domains": ["commbank.com.au", "cba.com.au"]},
    "Westpac": {"names": ["westpac"], "domains": ["westpac.com.au"]},
    "ANZ": {"names": ["anz"], "domains": ["anz.com.au", "anz.com"]},
    "NAB": {"names": ["nab", "national australia bank"], "domains": ["nab.com.au"]},
    "St.George": {"names": ["st george", "st.george", "stgeorge"], "domains": ["stgeorge.com.au"]},
    "Bendigo Bank": {"names": ["bendigo bank"], "domains": ["bendigobank.com.au"]},
    "Suncorp": {"names": ["suncorp"], "domains": ["suncorp.com.au", "suncorpbank.com.au"]},
    "PayPal": {"names": ["paypal"], "domains": ["paypal.com", "paypal.com.au", "paypalobjects.com", "paypal-communication.com"]},
    "Afterpay": {"names": ["afterpay"], "domains": ["afterpay.com", "afterpay.com.au"]},
    # Telco and energy
    "Telstra": {"names": ["telstra"], "domains": ["telstra.com.au", "telstra.com"]},
    "Optus": {"names": ["optus"], "domains": ["optus.com.au"]},
    "Vodafone": {"names": ["vodafone"], "domains": ["vodafone.com.au", "vodafone.com"]},
    "AGL": {"names": ["agl"], "domains": ["agl.com.au"]},
    "Origin Energy": {"names": ["origin energy"], "domains": ["originenergy.com.au"]},
    # Tech and subscriptions
    "Microsoft": {"names": ["microsoft", "office 365", "microsoft 365", "outlook", "onedrive", "sharepoint"], "domains": ["microsoft.com", "office.com", "microsoftonline.com", "outlook.com", "live.com", "office365.com", "sharepoint.com", "onedrive.com"]},
    "Google": {"names": ["google", "gmail"], "domains": ["google.com", "google.com.au", "gmail.com", "googlemail.com", "youtube.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "withgoogle.com", "googlegroups.com"]},
    "Apple": {"names": ["apple", "icloud", "itunes", "app store"], "domains": ["apple.com", "icloud.com", "apple.com.au", "mzstatic.com"]},
    "Amazon": {"names": ["amazon", "amazon prime"], "domains": ["amazon.com", "amazon.com.au", "amazon.co.uk", "amazonaws.com", "amazonses.com", "media-amazon.com"]},
    "Netflix": {"names": ["netflix"], "domains": ["netflix.com"]},
    "eBay": {"names": ["ebay"], "domains": ["ebay.com", "ebay.com.au"]},
    "DocuSign": {"names": ["docusign"], "domains": ["docusign.com", "docusign.net"]},
    "Dropbox": {"names": ["dropbox"], "domains": ["dropbox.com", "dropboxusercontent.com", "dropboxmail.com"]},
    "Xero": {"names": ["xero"], "domains": ["xero.com"]},
    "MYOB": {"names": ["myob"], "domains": ["myob.com", "myob.com.au"]},
    "Facebook": {"names": ["facebook", "meta"], "domains": ["facebook.com", "meta.com", "facebookmail.com"]},
    "Instagram": {"names": ["instagram"], "domains": ["instagram.com", "facebookmail.com"]},
    "LinkedIn": {"names": ["linkedin"], "domains": ["linkedin.com"]},
    "Norton": {"names": ["norton", "norton lifelock"], "domains": ["norton.com", "nortonlifelock.com", "gen.com"]},
    "McAfee": {"names": ["mcafee"], "domains": ["mcafee.com"]},
    "Coinbase": {"names": ["coinbase"], "domains": ["coinbase.com"]},
    "Binance": {"names": ["binance"], "domains": ["binance.com"]},
}

# Short names that are also ordinary words are only matched in a display name
# or a domain, never in body text.
AMBIGUOUS_NAMES = {"apple", "meta", "outlook", "origin", "ato", "nab", "anz", "agl", "afp", "tmr", "cba", "asic"}

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.com.au", "hotmail.com",
    "hotmail.com.au", "outlook.com", "outlook.com.au", "live.com", "live.com.au",
    "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com",
    "bigpond.com", "bigpond.net.au", "optusnet.com.au", "mail.com", "gmx.com",
    "yandex.com", "zoho.com",
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "loan", "online", "pics", "icu", "buzz", "cfd", "sbs",
    "rest", "bond", "quest", "cyou", "monster", "lat", "mom", "beauty", "hair",
    "zip", "mov", "work", "support", "live", "shop", "vip", "win", "tk", "ml",
    "ga", "cf", "gq", "cn", "ru",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly",
    "shorturl.at", "rb.gy", "t.ly", "buff.ly", "goo.gl", "tiny.cc", "s.id",
    "lnkd.in", "bl.ink", "short.io", "tinu.be", "qrco.de", "urlz.fr",
}

# Free website / form hosts that anyone can sign up to. Common in phishing,
# but also used legitimately, so they are a caution on their own.
FREE_HOSTING = {
    "sites.google.com", "forms.gle", "docs.google.com", "firebaseapp.com", "web.app",
    "weebly.com", "wixsite.com", "glitch.me", "netlify.app", "vercel.app",
    "pages.dev", "workers.dev", "ngrok.io", "ngrok-free.app", "blogspot.com",
    "000webhostapp.com", "square.site", "godaddysites.com", "notion.site",
    "github.io", "herokuapp.com", "onrender.com", "replit.app", "framer.app",
    "webflow.io", "jotform.com", "typeform.com", "ipfs.io", "dweb.link",
    "r2.dev", "storage.googleapis.com", "blob.core.windows.net", "s3.amazonaws.com",
}

# Email marketing and link-tracking services. Genuine newsletters route links
# through these, so a mismatch between link text and destination is expected.
TRACKING_DOMAINS = {
    "sendgrid.net", "list-manage.com", "mailchi.mp", "mcusercontent.com",
    "hubspotlinks.com", "hubspotemail.net", "hs-sites.com", "klclick.com",
    "klclick1.com", "klclick2.com", "klclick3.com", "klaviyomail.com",
    "exct.net", "rs6.net", "cmail19.com", "cmail20.com", "createsend.com",
    "createsend1.com", "mandrillapp.com", "mailgun.org", "sparkpostmail.com",
    "awstrack.me", "mlsend.com", "sendibt2.com", "sendibt3.com", "e.customeriomail.com",
    "customeriomail.com", "mailjet.com", "mjt.lu", "campaign-archive.com",
    "ccsend.com", "constantcontact.com", "salesforce.com", "pardot.com",
    "marketo.com", "mktoweb.com", "braze.com", "iterable.com", "omnisend.com",
    "sailthru.com", "emltrk.com", "linktrack.info", "lnk.to",
}

# Link-protection services that wrap the real link; the real address is in a
# query parameter. These are added by the user's own mail system when they
# forward, so they must be unwrapped before checking.
WRAPPER_PARAMS = {
    "safelinks.protection.outlook.com": "url",
    "statics.teams.cdn.office.net": "url",
    "www.google.com": "q",
    "google.com": "q",
    "urldefense.proofpoint.com": "u",
    "l.facebook.com": "u",
    "lm.facebook.com": "u",
    "out.reddit.com": "url",
}

DANGEROUS_FILE_EXTENSIONS = (".exe", ".scr", ".apk", ".msi", ".bat", ".vbs", ".js", ".jar", ".cmd", ".ps1", ".lnk")
RISKY_FILE_EXTENSIONS = (".zip", ".rar", ".7z", ".iso", ".img", ".html", ".htm", ".docm", ".xlsm", ".one")

# Common two-part public suffixes, so "paypal.com.au" registers as paypal, not com.
MULTI_PART_SUFFIXES = {
    "com.au", "net.au", "org.au", "gov.au", "edu.au", "asn.au", "id.au",
    "co.uk", "org.uk", "gov.uk", "co.nz", "org.nz", "govt.nz", "co.jp",
    "com.br", "com.cn", "co.in", "co.za", "com.sg", "com.my", "com.hk",
    "nsw.gov.au", "vic.gov.au", "qld.gov.au", "wa.gov.au", "sa.gov.au",
    "tas.gov.au", "act.gov.au", "nt.gov.au",
}

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _lower(value):
    return (value or "").lower() if isinstance(value, str) else str(value or "").lower()


# Letters scammers swap in so a brand name looks right to people but not to
# filters: accented Latin ("Teļștra"), and Cyrillic or Greek letters that look
# like Latin ones ("Тelstra" with a Cyrillic Т).
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ӏ": "l", "һ": "h", "ԛ": "q", "ԝ": "w", "в": "b", "к": "k", "м": "m", "н": "h", "т": "t",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "χ": "x", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Χ": "X", "Υ": "Y", "Ζ": "Z",
    "ı": "i", "ł": "l", "Ł": "L", "ø": "o", "Ø": "O", "đ": "d", "Đ": "D", "ħ": "h", "ŧ": "t", "ƚ": "l",
    "ⅼ": "l", "ǀ": "l", "ｌ": "l", "０": "0",
})


def fold_lookalikes(text):
    """Plain-letter version of text: accents removed and look-alike letters
    from other alphabets replaced, so "Teļștra" reads as "Telstra"."""
    import unicodedata
    text = str(text or "").translate(_CONFUSABLES)
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def disguised_brand(display_name):
    """The brand a sender name spells with look-alike letters, or "".
    Genuine organisations never write their own name this way."""
    raw = display_name or ""
    folded = fold_lookalikes(raw)
    if folded == raw:
        return ""
    brand = _brand_in_name(folded)
    if not brand:
        return ""
    # Only a disguise if the brand's plain spelling isn't in the raw name.
    names = (BRANDS.get(brand) or {}).get("names") or []
    raw_lower = raw.lower()
    return "" if any(n in raw_lower for n in names) else brand


def parse_sender(from_header):
    """Return (display_name, email_address, domain). Handles "Name <a@b>" and bare addresses."""
    from_header = (from_header or "").strip()
    # Outlook forwards: "a@x.com <a@x.com> on behalf of Brand Name <a@x.com>".
    # The name after "on behalf of" is what the recipient saw.
    behalf = re.search(r"\bon behalf of\b\s*(.+)$", from_header, flags=re.I)
    if behalf:
        from_header = behalf.group(1).strip()
    email_match = re.search(r"<\s*([^<>\s]+@[^<>\s]+)\s*>", from_header)
    if email_match:
        address = email_match.group(1)
        display = from_header[: email_match.start()].strip().strip('"').strip("'").strip()
    else:
        bare = re.search(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", from_header)
        address = bare.group(0) if bare else ""
        display = from_header.replace(address, "").strip().strip('"').strip("'").strip("<>").strip() if address else from_header
    address = address.strip().lower()
    domain = address.rsplit("@", 1)[1] if "@" in address else ""
    return display, address, domain


def host_of(url):
    try:
        if url.lower().startswith("www."):
            url = "http://" + url
        netloc = urlparse(url).netloc.lower()
    except Exception:
        return ""
    netloc = netloc.rsplit("@", 1)[-1].split(":")[0].strip(".")
    return netloc


def unwrap_url(url):
    """Return the real destination of a link-protection or redirect wrapper."""
    for _ in range(3):
        try:
            parsed = urlparse(url if "://" in url else "http://" + url)
        except Exception:
            return url
        host = parsed.netloc.lower().split(":")[0]
        param = None
        for wrapper, name in WRAPPER_PARAMS.items():
            if host == wrapper or host.endswith("." + wrapper):
                if wrapper.endswith("google.com") and parsed.path != "/url":
                    continue
                param = name
                break
        if host.endswith("urldefense.com"):
            match = re.search(r"/v3/__(.+?)__;", url)
            if match:
                url = match.group(1)
                continue
        if not param:
            return url
        values = parse_qs(parsed.query).get(param)
        if not values:
            return url
        inner = unquote(values[0])
        if host.startswith("urldefense.proofpoint.com"):
            inner = inner.replace("-", "%").replace("_", "/")
            inner = unquote(inner)
        if not inner.lower().startswith(("http://", "https://")):
            return url
        url = inner
    return url


def registrable_domain(host):
    """example.com.au -> example.com.au, mail.example.com -> example.com."""
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-3:]) in MULTI_PART_SUFFIXES and len(parts) >= 4:
        return ".".join(parts[-4:])
    if ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def domain_label(host):
    """The name part of the registrable domain: paypal.com.au -> paypal."""
    return registrable_domain(host).split(".")[0]


def tld_of(host):
    return (host or "").rsplit(".", 1)[-1] if "." in (host or "") else ""


def is_official(host, brand):
    host = (host or "").lower()
    return any(host == d or host.endswith("." + d) for d in BRANDS[brand]["domains"])


def official_brand_of(host):
    """The brand a host officially belongs to (telstra.com.au -> Telstra), or ""."""
    for brand in BRANDS:
        if is_official(host, brand):
            return brand
    return ""


def same_organisation(host_a, host_b):
    """True when two hosts belong to the same organisation, e.g. telstra.com
    and telstra.com.au, or two official domains of one brand."""
    if registrable_domain(host_a) == registrable_domain(host_b):
        return True
    brand_a = official_brand_of(host_a)
    return bool(brand_a) and is_official(host_b, brand_a)


def _domain_tokens(host):
    return set(t for t in re.split(r"[.\-_]", (host or "").lower()) if t)


def _levenshtein(a, b):
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_imitated_by_domain(host):
    """Return the brand a non-official domain is imitating, or "".

    Catches the brand used as part of the domain (auspost-redelivery.top,
    paypal.com.secure-login.xyz) and near-misspellings (paypa1.com, telsrta.com).
    """
    host = (host or "").lower()
    if not host:
        return ""
    tokens = _domain_tokens(host)
    label = domain_label(host)
    label_clean = label.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")

    for brand, info in BRANDS.items():
        if is_official(host, brand):
            continue
        for official in info["domains"]:
            off_label = domain_label(official)
            if len(off_label) < 4:
                # Very short names (anz, nab, agl) only count as an exact token.
                if off_label in tokens and off_label not in {"com", "net", "org", "gov"}:
                    return brand
                continue
            if off_label in tokens:
                return brand
            # Brand glued to other words (paypalsecure, myauspost). Only for
            # longer names, so "apple" does not match "pineapple".
            if len(off_label) >= 6 and any(
                (t.startswith(off_label) or t.endswith(off_label)) for t in tokens if len(t) > len(off_label)
            ):
                return brand
            if label_clean == off_label and label != off_label:
                return brand
            if len(off_label) >= 6 and _levenshtein(label_clean, off_label) == 1:
                return brand
    return ""


FILLER_WORDS = {
    "support", "team", "billing", "security", "account", "accounts", "service",
    "services", "notification", "notifications", "noreply", "no", "reply",
    "customer", "care", "help", "alert", "alerts", "official", "australia",
    "au", "online", "delivery", "deliveries", "admin", "info", "update",
    "updates", "the", "centre", "center", "dept", "department", "of", "and",
    "payments", "payment", "collections", "verification", "fraud", "desk",
    "express", "parcel", "tracking", "mail", "bank", "banking", "group",
    "refund", "refunds", "rebate", "rebates", "notice", "notices", "office",
    "enquiries", "compliance", "debt", "recovery", "claims", "fines", "tolls",
    "member", "members", "rewards", "id", "pay", "secure", "assistance",
    "card", "cards", "statement", "statements", "transaction", "transactions",
    "purchase", "purchases", "order", "orders", "message", "messages", "infos",
    "news", "digital", "mobile", "app", "system", "automated", "auto", "desk",
}


def brand_claimed_by_display_name(display_name):
    """Return the brand a display name presents itself as, or "".

    "Telstra Billing" or "ATO Refunds" claim a brand; "Big Apple Pizza" does not,
    because the remaining words are not generic filler.
    """
    text = re.sub(r"[^a-z0-9. ]", " ", _lower(fold_lookalikes(display_name)))
    text = " " + re.sub(r"\s+", " ", text).strip() + " "
    if not text.strip():
        return ""
    for brand, info in BRANDS.items():
        for name in info["names"]:
            if f" {name} " in text:
                remainder = text.replace(f" {name} ", " ").split()
                if all(word in FILLER_WORDS or word.isdigit() for word in remainder):
                    return brand
    return ""


def brand_named_in_display(display_name):
    """A brand named anywhere in the display name, e.g. "NAB Card Notifications"
    or "Telstra Billing Team AU". Short names that are also ordinary words
    (nab, anz, ato...) only count when written in capitals, as organisations
    write them; "apple", "meta", "outlook" and "origin" only count through
    brand_claimed_by_display_name, so "Big Apple Pizza" isn't Apple."""
    raw = fold_lookalikes(display_name or "")
    lowered = " " + re.sub(r"[^a-z0-9. ]", " ", raw.lower()) + " "
    for brand, info in BRANDS.items():
        for name in info["names"]:
            if name in {"apple", "meta", "outlook", "origin"}:
                continue
            if name in AMBIGUOUS_NAMES:
                if re.search(rf"(?<![A-Za-z0-9]){re.escape(name.upper())}(?![A-Za-z0-9])", raw):
                    return brand
                continue
            if f" {name} " in lowered:
                return brand
    return ""


def _brand_in_name(name):
    return brand_claimed_by_display_name(name) or brand_named_in_display(name)


def brands_mentioned(text):
    lowered = " " + re.sub(r"\s+", " ", _lower(fold_lookalikes(text))) + " "
    found = []
    for brand, info in BRANDS.items():
        for name in info["names"]:
            if name in AMBIGUOUS_NAMES:
                continue
            if re.search(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])", lowered):
                found.append(brand)
                break
    return found


def _any(patterns, text):
    return any(re.search(p, text) for p in patterns)


def _matches(patterns, text):
    out = []
    for p in patterns:
        m = re.search(p, text)
        if m:
            out.append(m.group(0))
    return out


def _status(levels):
    if "fail" in levels:
        return "fail"
    if "caution" in levels:
        return "caution"
    return "pass"


def _dedupe(items):
    seen = set()
    out = []
    for item in items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


# ----------------------------------------------------------------------
# 1. Sender & domain
# ----------------------------------------------------------------------

def check_sender(from_header, reply_to="", auth_results=None, submission_type="", body_text=""):
    display, address, domain = parse_sender(from_header)
    auth_results = auth_results or {}
    details = []
    levels = []
    claimed_brand = ""

    if not address:
        return {
            "key": "sender", "title": "Sender & domain", "status": "caution",
            "headline": "The sender's email address could not be identified.",
            "details": ["No sender address was found, so the sender could not be verified."],
            "claimed_brand": "", "sender_domain": "",
        }

    details.append(f"Sent from {address}" + (f' (shown as "{display}")' if display and display.lower() != address else "") + ".")

    # Blocked list
    if registrable_domain(domain) in BLOCKED_DOMAINS or domain in BLOCKED_DOMAINS:
        details.append(f"{domain} is on ScamWatcher's list of known scam domains.")
        levels.append("fail")

    # Display name hides a different address: "support@paypal.com" <x@evil.top>
    shown_address = re.search(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", display or "")
    if shown_address and shown_address.group(0).lower() != address:
        details.append(f"The display name shows a different address ({shown_address.group(0)}) from the real sender ({address}).")
        levels.append("fail")

    # A brand name spelled with look-alike letters ("Teļștra") is a disguise.
    disguised = disguised_brand(display)
    if disguised:
        details.append(f'The sender name "{display}" spells {disguised} with look-alike letters, a trick to get past filters. Genuine organisations never do this.')
        levels.append("fail")

    # Brand claimed by display name or imitated by the domain
    claimed_brand = brand_claimed_by_display_name(display) or brand_named_in_display(display)
    imitated_brand = brand_imitated_by_domain(domain)

    if claimed_brand:
        if is_official(domain, claimed_brand):
            details.append(f"{domain} is an official {claimed_brand} domain.")
        elif domain in FREE_EMAIL_PROVIDERS:
            details.append(f"Presents itself as {claimed_brand} but uses a free personal email account ({domain}). Organisations do not do this.")
            levels.append("fail")
        else:
            details.append(f"Presents itself as {claimed_brand}, but {domain} is not an official {claimed_brand} domain.")
            levels.append("fail")

    if imitated_brand and imitated_brand != claimed_brand:
        details.append(f"The domain {domain} looks designed to resemble {imitated_brand}, but is not an official {imitated_brand} domain.")
        levels.append("fail")
        claimed_brand = claimed_brand or imitated_brand
    elif imitated_brand and not claimed_brand:
        claimed_brand = imitated_brand

    # Business-sounding name on a free email account (common in invoice scams,
    # but also used by genuine small businesses, so only a caution).
    business_words = ("support", "billing", "accounts", "payments", "invoice", "admin", "team", "service", "helpdesk", "department", "pty", "ltd")
    if not claimed_brand and domain in FREE_EMAIL_PROVIDERS and any(w in _lower(display) for w in business_words):
        details.append(f'Uses a free email account ({domain}) with a business-style name ("{display}").')
        levels.append("caution")

    # Suspicious TLD / sender format
    if tld_of(domain) in SUSPICIOUS_TLDS:
        details.append(f'The domain ends in ".{tld_of(domain)}", an ending heavily used by scam sites.')
        levels.append("caution")

    local = address.split("@", 1)[0]
    if len(local) > 30 or re.search(r"\d{5,}", local) or re.search(r"[._\-]{3,}", local):
        details.append("The sender address looks randomly generated.")
        levels.append("caution")

    # Reply-To pointing somewhere else
    if reply_to:
        _, reply_address, reply_domain = parse_sender(reply_to)
        if reply_domain and registrable_domain(reply_domain) != registrable_domain(domain):
            if reply_domain in FREE_EMAIL_PROVIDERS or claimed_brand:
                details.append(f"Replies would go to a different address ({reply_address}), not the sender.")
                levels.append("fail")
            else:
                details.append(f"Replies would go to a different domain ({reply_domain}).")
                levels.append("caution")

    # Contact addresses in the body that point to free email accounts
    body_free = sorted(set(
        m.lower() for m in re.findall(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", body_text or "")
        if m.lower() in FREE_EMAIL_PROVIDERS
    ))
    if body_free and domain not in FREE_EMAIL_PROVIDERS and claimed_brand:
        details.append(f"Asks you to contact a free email account ({', '.join(body_free)}) instead of the organisation.")
        levels.append("fail")

    # SPF / DKIM / DMARC (only available for direct emails or attached .eml files)
    if auth_results:
        dmarc = auth_results.get("dmarc", "")
        spf = auth_results.get("spf", "")
        dkim = auth_results.get("dkim", "")
        if dmarc == "fail":
            details.append(f"Failed DMARC authentication: the email was not genuinely sent by {domain}.")
            levels.append("fail")
        elif spf in ("fail", "softfail") and dkim not in ("pass",):
            details.append(f"Failed sender authentication (SPF {spf}, DKIM {dkim or 'missing'}).")
            levels.append("caution")
        elif dmarc == "pass" or (spf == "pass" and dkim == "pass"):
            details.append(f"Passed sender authentication, so it really came from {domain}" + (" (but that domain is not the organisation it claims to be)." if "fail" in levels else "."))
    elif submission_type == "forwarded":
        details.append("Sender authentication could not be checked because the email was forwarded. Forwarding it as an attachment keeps this information.")

    status = _status(levels)
    if status == "fail":
        headline = "The sender is not who they claim to be." if claimed_brand else "The sender shows strong warning signs."
    elif status == "caution":
        headline = "The sender has some warning signs and should be verified."
    elif claimed_brand and is_official(domain, claimed_brand):
        headline = f"The sender's domain matches {claimed_brand}."
    else:
        headline = "No problems found with the sender's address."

    return {
        "key": "sender", "title": "Sender & domain", "status": status,
        "headline": headline, "details": _dedupe(details),
        "claimed_brand": claimed_brand, "sender_domain": domain,
    }


# ----------------------------------------------------------------------
# 2. Content
# ----------------------------------------------------------------------

CONTENT_SIGNALS = [
    # (key, level when alone, plain-English description, patterns)
    ("urgency", "caution", "Creates urgency or a deadline", [
        r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\bwithin \d+ ?(hours?|hrs?)\b", r"\bwithin (1|2|3|one|two|three) ?days?\b",
        r"\b(24|48|72) ?hours?\b", r"\bfinal (notice|reminder|warning)\b", r"\baction required\b",
        r"\bexpires? (today|soon|in)\b", r"\blast chance\b", r"\bact now\b", r"\btime[- ]sensitive\b",
        r"\btoday only\b", r"\bdeadline\b",
    ]),
    ("threat", "caution", "Threatens a penalty, suspension or legal action", [
        r"\b(will be|has been|have been) (suspended|locked|closed|terminated|deactivated|restricted|disabled|cancelled)\b",
        r"\b(suspend|deactivat|terminat)\w*\b.{0,40}\baccount\b", r"\blegal action\b", r"\bcourt\b",
        r"\barrest\b", r"\bwarrant\b", r"\bdebt collect", r"\bpolice\b", r"\blate fees?\b",
        r"\bpenalt(y|ies)\b", r"\blose access\b",
    ]),
    ("payment", "caution", "Asks for a payment", [
        r"\bpay (now|today|immediately|the|your|this|an?)\b", r"\bpayment (is )?(due|required|overdue|outstanding)\b",
        r"\boutstanding (balance|amount|payment|fee)\b", r"\bsettle\b", r"\b(small|delivery|customs|processing|release|admin(istration)?) fee\b",
        r"\btransfer (the|funds|money|payment)\b", r"\bbsb\b", r"\bpayid\b", r"\bdirect deposit\b",
    ]),
    ("credentials", "caution", "Asks you to sign in or confirm account details", [
        r"\b(log ?in|sign ?in)\b.{0,40}\b(verify|confirm|restore|update|secure|validate|unlock)\b",
        r"\b(verify|confirm|validate|update|restore|unlock)\b.{0,30}\b(your )?(account|identity|details|information|password|login)\b",
        r"\b(password|passcode|one[- ]time (code|password)|otp|verification code|security code|pin)\b",
    ]),
    ("sensitive", "fail", "Asks for sensitive personal or financial details", [
        r"\b(tax file number|tfn)\b", r"\b(credit|debit) card (number|details)\b", r"\bcard (number|details)\b",
        r"\bcvv\b|\bcvc\b", r"\bpassport (number|details|copy)\b", r"\bdriver'?s? licen[cs]e (number|details|copy)\b",
        r"\bmedicare (number|card)\b", r"\b(date of birth|dob)\b", r"\bseed phrase\b|\brecovery phrase\b|\bprivate key\b",
        r"\b(online )?banking (password|login|details)\b", r"\bsend (us )?(a )?(photo|copy|scan) of your\b",
    ]),
    ("bank_change", "fail", "Says bank or payment details have changed", [
        r"\b(new|updated|changed?|change of|amended) (bank|banking|account|payment|remittance) (details|information|account|instructions)\b",
        r"\bbank (details|account) (has|have) (been )?changed\b", r"\b(remit|pay|payment) to (our|the) new (bank )?account\b",
        r"\bplease (update|amend) (our|your records with our|the) (bank|payment) details\b",
    ]),
    ("untraceable_payment", "fail", "Asks for payment by gift card, crypto or wire transfer", [
        r"\bgift ?cards?\b", r"\b(itunes|google play|steam|apple|amazon|ebay|jb hi-?fi|coles|woolworths) (gift )?card\b",
        r"\bbitcoin\b|\bbtc\b|\busdt\b|\bethereum\b|\bcrypto(currency)?\b", r"\bwestern union\b|\bmoneygram\b|\bwire transfer\b",
    ]),
    ("prize", "caution", "Promises money, a prize or something too good to be true", [
        r"\byou(\'ve| have)? (won|been selected|been chosen)\b", r"\bcongratulations\b", r"\b(lottery|jackpot|sweepstake)\b",
        r"\binheritance\b|\bbeneficiary\b|\bnext of kin\b", r"\bunclaimed (funds?|money|parcel)\b",
        r"\b(guaranteed|risk[- ]free) (returns?|profit|income)\b", r"\bdouble your (money|investment)\b",
        r"\b(refund|rebate|reward|compensation) (of|is|has been|for you)\b", r"\bfree (iphone|gift|money)\b",
        r"\$\s?\d{1,3}(,\d{3}){2,}", r"\b\d+(\.\d+)? million\b",
    ]),
    ("secrecy", "fail", "Asks you to keep it secret or not tell anyone", [
        r"\b(keep this|keep it) (confidential|secret|between us|private)\b", r"\bdo not (tell|discuss|share this with)\b",
        r"\bdon'?t tell\b", r"\bstrictly confidential\b",
    ]),
    ("callback", "caution", "Asks you to call a phone number", [
        r"\b(call|phone|ring|contact)( us)?( now| immediately| on| at)?\s*:?\s*(\+?61|0|1[38]00)[\d \-]{7,}",
        r"\b(call|phone|ring) (our|the) (support|helpline|help desk|billing|fraud) (team|line|department)\b",
        r"\b(call|phone|ring|contact|support|helpline)\b[^0-9\n]{0,20}(\+?61 ?4|04)\d{2}[ \d]{6,9}",
    ]),
    ("mobile_contact", "caution", "Gives a mobile phone number as the organisation's contact (banks and large companies don't)", [
        r"\b(support|helpline|customer service|fraud team|security team|contact us|call us)\b[^0-9\n]{0,20}(\+?61 ?4|04)\d{2}[ \d]{6,9}",
    ]),
    ("remote_access", "fail", "Asks you to install remote-access software", [
        r"\banydesk\b", r"\bteamviewer\b", r"\bultraviewer\b", r"\bquick ?assist\b", r"\bremote (access|desktop|support) (app|software|tool)\b",
    ]),
    ("personal_info", "caution", "Asks you to send personal details", [
        r"\b(reply|respond|send|provide|confirm|update)\b.{0,50}\b(full name|home address|residential address|phone number|mobile number|date of birth|personal (details|information))\b",
    ]),
    ("open_attachment", "caution", "Pushes you to open an attachment or enable content", [
        r"\b(open|see|view|download) (the )?attach(ed|ment)\b", r"\benable (editing|content|macros)\b",
    ]),
    ("generic_greeting", "info", "Uses a generic greeting instead of your name", [
        r"\bdear (customer|client|user|member|sir|madam|account holder|valued customer|beneficiary|friend)\b",
        r"^\s*(hello|hi|dear),?\s*$",
    ]),
]

HIGH_RISK_REQUESTS = {"payment", "credentials", "sensitive", "bank_change", "untraceable_payment", "remote_access", "callback", "personal_info"}
PRESSURE = {"urgency", "threat", "secrecy"}


def check_content(subject, body, attachment_text=""):
    text = _lower(f"{subject}\n{body}\n{attachment_text}")
    text_ml = re.sub(r"[ \t]+", " ", text)
    found = {}
    for key, level, description, patterns in CONTENT_SIGNALS:
        flags = re.MULTILINE if key == "generic_greeting" else 0
        hits = [m.group(0) for p in patterns for m in [re.search(p, text_ml, flags)] if m]
        if hits:
            found[key] = (level, description, hits[0])

    details = []
    levels = []
    for key, (level, description, example) in found.items():
        example = re.sub(r"\s+", " ", example).strip()
        details.append(f'{description} ("{example[:60]}").')
        if level in ("fail", "caution"):
            levels.append(level)

    requests = HIGH_RISK_REQUESTS & set(found)
    pressure = PRESSURE & set(found)

    # The classic scam combination: a risky request plus pressure.
    if requests and pressure:
        levels.append("fail")
        details.insert(0, "Combines a request for money, details or action with pressure tactics, the most common scam pattern.")

    # Attachment-only text deserves a mention
    if attachment_text and _any([p for k, _, _, ps in CONTENT_SIGNALS if k in HIGH_RISK_REQUESTS for p in ps], _lower(attachment_text)):
        details.append("The attachment itself contains a request for payment or details.")

    status = _status(levels)
    if status == "fail":
        headline = "The email asks for something risky using common scam tactics."
    elif status == "caution":
        headline = "The email contains some wording often used in scams."
    else:
        headline = "No scam-style requests or pressure tactics found in the wording."

    return {
        "key": "content", "title": "Content", "status": status,
        "headline": headline, "details": _dedupe(details),
        "signals": sorted(found),
    }


# ----------------------------------------------------------------------
# 3. Links
# ----------------------------------------------------------------------

URL_RE = re.compile(r"(https?://[^\s<>()\"'\]]+|www\.[^\s<>()\"'\]]+)", re.IGNORECASE)


def collect_links(body, html_links=None):
    links = []
    seen = set()
    for item in html_links or []:
        url = unwrap_url((item.get("url") or "").strip())
        if url and url not in seen:
            seen.add(url)
            links.append({"url": url, "text": (item.get("text") or "").strip()})
    for url in URL_RE.findall(body or ""):
        url = unwrap_url(url.rstrip(".,);:!?]>\"'"))
        if url not in seen:
            seen.add(url)
            links.append({"url": url, "text": ""})
    return links


def check_links(body, html_links=None, sender_domain="", claimed_brand="", content_signals=None):
    links = collect_links(body, html_links)
    content_signals = set(content_signals or [])
    details = []
    levels = []
    domains = []

    if not links:
        return {
            "key": "links", "title": "Links", "status": "pass",
            "headline": "The email contains no links.", "details": ["No web links were found in the email."],
            "domains": [],
        }

    for link in links:
        url = link["url"]
        host = host_of(url)
        if not host:
            continue
        domains.append(host)
        reg = registrable_domain(host)
        problems = []
        lowered_url = url.lower()

        try:
            ipaddress.ip_address(host)
            problems.append(("fail", f"{url[:80]} goes to a raw IP address instead of a website name."))
        except ValueError:
            pass

        if "xn--" in host:
            problems.append(("fail", f"{host} uses disguised (lookalike) characters."))

        netloc = urlparse(url if "://" in url else "http://" + url).netloc
        if "@" in netloc:
            problems.append(("fail", f"{url[:80]} hides its real destination ({host}) behind an @ sign."))

        if reg in BLOCKED_DOMAINS or host in BLOCKED_DOMAINS:
            problems.append(("fail", f"{host} is on ScamWatcher's list of known scam domains."))

        imitated = brand_imitated_by_domain(host)
        if imitated:
            problems.append(("fail", f"{host} imitates {imitated} but is not an official {imitated} website."))
        elif claimed_brand and not is_official(host, claimed_brand) and host not in URL_SHORTENERS:
            if any(reg == registrable_domain(d) for d in BRANDS[claimed_brand]["domains"]):
                pass
            elif content_signals & {"payment", "credentials", "sensitive", "bank_change"}:
                # Asking you to pay or sign in on someone else's website is the scam.
                problems.append(("fail", f"The email claims to be from {claimed_brand} and asks you to pay or sign in, but this link goes to {host}, not {claimed_brand}."))
            else:
                problems.append(("caution", f"The email claims to be from {claimed_brand}, but this link goes to {host}."))

        # Visible link text shows one website but the link goes to another.
        is_tracker = reg in TRACKING_DOMAINS or any(host.endswith("." + t) for t in TRACKING_DOMAINS)
        shown = re.search(r"(?:https?://)?((?:[a-z0-9\-]+\.)+[a-z]{2,})", _lower(link.get("text")))
        if shown and not is_tracker:
            shown_host = re.sub(r"^www\.", "", shown.group(1))
            shown_tld = tld_of(shown_host)
            looks_like_domain = shown_tld in {"com", "au", "net", "org", "gov", "io", "co", "uk", "nz", "info", "biz", "app"} or shown_tld in SUSPICIOUS_TLDS
            if looks_like_domain and registrable_domain(shown_host) != reg and not same_organisation(shown_host, host):
                problems.append(("fail", f'The link text shows "{shown.group(0)}" but actually goes to {host}.'))

        if host in URL_SHORTENERS or reg in URL_SHORTENERS:
            problems.append(("caution", f"{host} is a link shortener that hides the real destination."))

        if host in FREE_HOSTING or reg in FREE_HOSTING or any(host.endswith("." + h) for h in FREE_HOSTING):
            level = "fail" if (claimed_brand or "credentials" in content_signals) else "caution"
            problems.append((level, f"{host} is a free website or form service that anyone can set up."))

        if tld_of(host) in SUSPICIOUS_TLDS and not imitated:
            problems.append(("caution", f'{host} ends in ".{tld_of(host)}", an ending heavily used by scam sites.'))

        path = urlparse(url if "://" in url else "http://" + url).path.lower()
        if path.endswith(DANGEROUS_FILE_EXTENSIONS):
            problems.append(("fail", f"{url[:80]} downloads a program file ({path.rsplit('.', 1)[-1]})."))
        elif path.endswith(RISKY_FILE_EXTENSIONS):
            problems.append(("caution", f"{url[:80]} downloads a {path.rsplit('.', 1)[-1]} file, often used to hide malware."))

        if lowered_url.startswith("http://") and "credentials" in content_signals:
            problems.append(("caution", f"{host} is not a secure (https) page, yet the email asks you to sign in."))

        for level, text in problems:
            levels.append(level)
            details.append(text)

    unique_domains = sorted(set(domains))
    summary = f"Found {len(links)} link{'s' if len(links) != 1 else ''} to {len(unique_domains)} website{'s' if len(unique_domains) != 1 else ''}: {', '.join(unique_domains[:6])}{'…' if len(unique_domains) > 6 else ''}."
    details.insert(0, summary)

    if claimed_brand and unique_domains and all(is_official(d, claimed_brand) for d in unique_domains):
        details.append(f"All links go to official {claimed_brand} websites.")

    status = _status(levels)
    if status == "fail":
        headline = "One or more links lead to a deceptive or dangerous website."
    elif status == "caution":
        headline = "Some links have warning signs. Avoid clicking them."
    else:
        headline = "No problems found with the links."

    return {
        "key": "links", "title": "Links", "status": status,
        "headline": headline, "details": _dedupe(details),
        "domains": unique_domains,
    }


# ----------------------------------------------------------------------
# 4. Known scam patterns
# ----------------------------------------------------------------------
# Each pattern needs at least one match in EVERY group in "all_of".
# "official_brands": if the sender and links are official for one of these
# brands, the match is treated as possibly genuine (caution, not fail).
# ----------------------------------------------------------------------

SCAM_PATTERNS = [
    {
        "name": "Toll road unpaid fee scam",
        "category": "Fines & tolls",
        "all_of": [
            [r"\btoll(s|ing)?\b", r"\blinkt\b", r"\be-?toll\b", r"\btoll ?road\b", r"\btoll notice\b"],
            [r"\bunpaid\b", r"\boutstanding\b", r"\boverdue\b", r"\bowing\b", r"\bpay\b", r"\bsettle\b", r"\bfine\b", r"\bpenalt", r"\blate fee"],
        ],
        "official_brands": ["Linkt", "Queensland Government", "Service NSW", "VicRoads"],
        "advice": "Check any toll balance by signing in to your toll account through the official website or app, not a link in a message.",
    },
    {
        "name": "Parcel delivery scam",
        "category": "Delivery",
        "all_of": [
            [r"\bparcel\b", r"\bpackage\b", r"\bdelivery\b", r"\bshipment\b", r"\bconsignment\b", r"\bcourier\b"],
            [r"\bre-?deliver", r"\breschedul", r"\bunable to (be )?deliver", r"\bcould not be delivered\b", r"\bfailed (delivery|to deliver)\b",
             r"\bdelivery attempt\b", r"\b(update|confirm|incomplete|incorrect) (your )?(delivery )?address\b", r"\bcustoms (fee|duty|charge)\b",
             r"\b(delivery|shipping|redelivery) fee\b", r"\bon hold\b", r"\bheld at\b", r"\baddress (is )?(incomplete|invalid)\b"],
        ],
        "official_brands": ["Australia Post", "StarTrack", "DHL", "FedEx", "Aramex", "Amazon"],
        "advice": "Track parcels using the tracking number on the official courier website or app. Couriers do not charge surprise redelivery fees by email or text.",
    },
    {
        "name": "Traffic fine scam",
        "category": "Fines & tolls",
        "all_of": [
            [r"\binfringement\b", r"\btraffic (fine|offence|violation)\b", r"\bspeeding\b", r"\bpenalty notice\b", r"\bfine notice\b", r"\bdemerit\b", r"\bcamera\b.{0,20}\b(detect|record)", r"\bparking (fine|ticket|infringement)\b"],
            [r"\bpay\b", r"\boverdue\b", r"\boutstanding\b", r"\bdue\b", r"\bsuspen", r"\blicen[cs]e\b", r"\bview\b"],
        ],
        "official_brands": ["Service NSW", "Queensland Government", "VicRoads"],
        "advice": "Check fines through your state's official fines or transport website by typing the address yourself.",
    },
    {
        "name": "ATO or myGov impersonation",
        "category": "Government",
        "all_of": [
            [r"\bato\b", r"\btax(ation)? office\b", r"\bmygov\b", r"\bmy gov\b", r"\btax refund\b", r"\btax return\b"],
            [r"\brefund\b", r"\bowed\b", r"\bentitled\b", r"\bclaim\b", r"\bverify\b", r"\bdebt\b", r"\boverdue\b", r"\boutstanding\b", r"\bsuspend", r"\bupdate\b", r"\bsign ?in\b", r"\blog ?in\b"],
        ],
        "official_brands": ["ATO", "myGov", "Services Australia"],
        "advice": "Sign in to myGov or the ATO by typing my.gov.au into your browser. The ATO and myGov have said they no longer send links asking you to sign in.",
    },
    {
        "name": "Government payment or rebate scam",
        "category": "Government",
        "all_of": [
            [r"\bcentrelink\b", r"\bmedicare\b", r"\bservices australia\b", r"\benergy (bill )?(relief|rebate)\b", r"\bcost of living (payment|relief|rebate)\b",
             r"\bgovernment (rebate|grant|payment|relief)\b", r"\bstimulus\b"],
            [r"\bclaim\b", r"\beligible\b", r"\bentitled\b", r"\bverify\b", r"\bupdate\b", r"\bapply\b", r"\bbank details\b", r"\bconfirm\b"],
        ],
        "official_brands": ["Services Australia", "myGov"],
        "advice": "Government payments are managed through myGov. Go there directly instead of using links in messages.",
    },
    {
        "name": "Bank account alert phishing",
        "category": "Banking",
        "all_of": [
            [r"\bbank\b", r"\bcommbank\b", r"\bnetbank\b", r"\bwestpac\b", r"\banz\b", r"\bnab\b", r"\bst\.? ?george\b", r"\bsuncorp\b", r"\bbendigo\b", r"\bpaypal\b", r"\bcard\b"],
            [r"\b(account|card) (has been |is |will be )?(suspended|locked|restricted|frozen|blocked|limited|on hold)\b", r"\bunusual (activity|sign[- ]?in|login|transaction)",
             r"\bsuspicious (activity|transaction|login|sign[- ]?in)", r"\bverify your (identity|account|details)\b", r"\bsecurity (alert|check|update)\b",
             r"\bunauthori[sz]ed (transaction|access|payment)\b", r"\bnew payee\b", r"\bconfirm (this|the) (transaction|payment)\b",
             r"\bsecurity checks?\b", r"\b(payment|transaction|purchase) (is |has been |was )?(currently )?(on hold|paused|pending review|declined|blocked|flagged)\b",
             r"\bpaused (a |the |your )?(recent )?(transaction|payment|purchase)\b", r"\bsecure your (account|card)\b"],
        ],
        "official_brands": ["CommBank", "Westpac", "ANZ", "NAB", "St.George", "Suncorp", "Bendigo Bank", "PayPal"],
        "advice": "Call your bank on the number on the back of your card, or open your banking app directly. Banks will not ask you to confirm details through an email link.",
    },
    {
        "name": "Payment redirection (fake invoice or changed bank details)",
        "category": "Business email compromise",
        "all_of": [
            [r"\b(new|updated|changed?|change of|amended) (bank|banking|account|payment|remittance) (details|information|account|instructions)\b",
             r"\bbank (details|account) (has|have) (been )?changed\b", r"\b(remit|pay|payment) to (our|the) new (bank )?account\b",
             r"\b(please )?(update|amend) (our|the) (bank|payment) details\b"],
        ],
        "official_brands": [],
        "advice": "Before paying, phone the business on a number you already have (not one in the email) to confirm the bank details. This scam is one of the costliest for Australian businesses.",
    },
    {
        "name": "Subscription payment failed scam",
        "category": "Subscriptions",
        "all_of": [
            [r"\bnetflix\b", r"\bstan\b", r"\bspotify\b", r"\bdisney\+?\b", r"\bamazon prime\b", r"\bprime video\b", r"\bicloud\b", r"\bapple\b", r"\bsubscription\b", r"\bmembership\b", r"\bplan\b"],
            [r"\bpayment (has )?(failed|declined|unsuccessful|was not processed)\b", r"\bupdate (your )?(payment|billing|card)( details| method| information)?\b", r"\bcard (has )?expired\b",
             r"\bunable to (process|charge|authori[sz]e)\b", r"\bbilling (problem|issue|error)\b", r"\b(account|membership|subscription) (will be |has been )?(suspended|on hold|cancelled|paused)\b"],
        ],
        "official_brands": ["Netflix", "Apple", "Amazon", "Google", "Microsoft"],
        "advice": "Open the app or type the company's website address yourself to check your billing.",
    },
    {
        "name": "Email account or password expiry phishing",
        "category": "Account phishing",
        "all_of": [
            [r"\bmailbox\b", r"\bemail account\b", r"\bpassword\b", r"\bstorage\b", r"\bquota\b", r"\boutlook\b", r"\boffice ?365\b", r"\bmicrosoft 365\b", r"\bwebmail\b", r"\bicloud\b"],
            [r"\bexpir(e|es|ed|ing|y)\b", r"\b(is |almost |nearly )?full\b", r"\bexceeded\b", r"\bdeactivat", r"\bvalidate\b", r"\bre-?activat", r"\bkeep (your )?(current |same )?password\b", r"\bupgrade (your )?(storage|mailbox)\b", r"\bpending (messages|emails)\b"],
        ],
        "official_brands": ["Microsoft", "Google", "Apple"],
        "advice": "Check your account by going to your email provider's website directly. Do not enter your password through a link in an email.",
    },
    {
        "name": "Fake shared document",
        "category": "Account phishing",
        "all_of": [
            [r"\bshared (a |an )?(document|file|folder|invoice|pdf)\b", r"\bdocusign\b", r"\bsent you (a |an )?(document|file)\b", r"\b(review|sign) (the |this )?document\b",
             r"\bsecure (document|file|message)\b", r"\bonedrive\b", r"\bsharepoint\b", r"\bdropbox\b", r"\bdocument (is )?(waiting|ready|pending)\b"],
            [r"\bview\b", r"\bopen\b", r"\breview\b", r"\baccess\b", r"\bsign\b", r"\bdownload\b"],
        ],
        "official_brands": ["Microsoft", "Google", "DocuSign", "Dropbox"],
        "advice": "If you were not expecting a document, check with the person who supposedly sent it using a contact you already have.",
    },
    {
        "name": "Prize, lottery or inheritance scam",
        "category": "Advance fee",
        "all_of": [
            [r"\blottery\b", r"\byou(\'ve| have)? won\b", r"\bwinner\b", r"\bprize\b", r"\binheritance\b", r"\bbeneficiary\b", r"\bnext of kin\b", r"\bunclaimed (funds?|money)\b",
             r"\bcompensation fund\b", r"\b\d+(\.\d+)? million\b", r"\$\s?\d{1,3}(,\d{3}){2,}", r"\bconsignment box\b"],
            [r"\bclaim\b", r"\brelease\b", r"\btransfer\b", r"\bfee\b", r"\bcontact\b", r"\bsend\b", r"\bdetails\b", r"\bbank\b", r"\breply\b"],
        ],
        "official_brands": [],
        "advice": "You cannot win a lottery you did not enter, and genuine prizes never require a fee to release them.",
    },
    {
        "name": "Investment or crypto scam",
        "category": "Investment",
        "all_of": [
            [r"\bcrypto(currency)?\b", r"\bbitcoin\b", r"\busdt\b", r"\bethereum\b", r"\btrading (platform|bot|account)\b", r"\binvestment opportunit", r"\bguaranteed (returns?|profit)\b",
             r"\bdouble your\b", r"\bpassive income\b", r"\bforex\b"],
            [r"\binvest", r"\bprofit", r"\breturns?\b", r"\bdeposit\b", r"\bearn\b", r"\bwallet\b", r"\bplatform\b"],
        ],
        "official_brands": ["Coinbase", "Binance"],
        "advice": "Check any investment firm is licensed on ASIC's Moneysmart website. Promises of guaranteed or fast returns are a red flag.",
    },
    {
        "name": "Job or task scam",
        "category": "Employment",
        "all_of": [
            [r"\bjob offer\b", r"\bpart[- ]time\b", r"\bwork (from|at) home\b", r"\bremote (job|position|role|work)\b", r"\brecruit", r"\bhiring\b", r"\bposition (is )?available\b", r"\btasks?\b.{0,20}\b(app|online|daily)\b", r"\b(rate|review|like) (products|videos|hotels)\b"],
            [r"\$\s?\d+ ?(per|/|a) ?(hour|day|week|task)\b", r"\bearn\b", r"\bsalary\b", r"\bcommission\b", r"\bwhatsapp\b", r"\btelegram\b", r"\bno experience\b", r"\bflexible hours\b"],
        ],
        "official_brands": ["LinkedIn"],
        "advice": "Real employers do not contact you out of the blue on WhatsApp or Telegram, or ask you to pay to start work.",
    },
    {
        "name": "Sextortion or blackmail scam",
        "category": "Extortion",
        "all_of": [
            [r"\brecorded you\b", r"\bwebcam\b", r"\bvideo of you\b", r"\byour (device|computer|phone) (was|has been) (hacked|infected|compromised)\b", r"\bi have access to your\b",
             r"\badult (site|website|content)\b", r"\bpornograph", r"\bintimate (video|images|photos)\b", r"\bi know your password\b"],
            [r"\bbitcoin\b", r"\bbtc\b", r"\bwallet\b", r"\bpay\b", r"\bsend\b", r"\b\d+ hours\b", r"\bcontacts\b", r"\bfriends\b", r"\bfamily\b", r"\bcolleagues\b"],
        ],
        "official_brands": [],
        "advice": "These emails are almost always bluffs sent in bulk. Do not pay or reply. If they mention a real password, change it. Report it to the eSafety Commissioner.",
    },
    {
        "name": "Tech support or fake renewal scam",
        "category": "Tech support",
        "all_of": [
            [r"\bvirus\b", r"\binfected\b", r"\bmalware\b", r"\bhacked\b", r"\bsecurity alert\b", r"\bfirewall\b", r"\bnorton\b", r"\bmcafee\b", r"\bgeek squad\b",
             r"\b(microsoft|apple|windows) support\b", r"\bauto[- ]?renew", r"\b(subscription|membership) (has been )?renewed\b", r"\border (confirmation|#)\b"],
            [r"\bcall\b", r"\bphone\b", r"\bhelpline\b", r"\btoll[- ]free\b", r"\b1[38]00\b", r"\bcharged\b", r"\brefund\b", r"\bcancel\b", r"\banydesk\b", r"\bteamviewer\b"],
        ],
        "official_brands": ["Microsoft", "Apple", "Norton", "McAfee"],
        "advice": "Never call a number from an unexpected invoice or alert, and never let a caller access your computer. Check orders by signing in to the company's website directly.",
    },
    {
        "name": "Gift card request scam",
        "category": "Impersonation",
        "all_of": [
            [r"\bgift ?cards?\b", r"\b(itunes|google play|steam|apple|jb hi-?fi|coles|woolworths|ebay) card\b"],
            [r"\bbuy\b", r"\bpurchase\b", r"\bsend\b", r"\bscratch\b", r"\bcodes?\b", r"\burgent", r"\bfavou?r\b", r"\bdiscreet\b", r"\bquick(ly)?\b"],
        ],
        "official_brands": [],
        "advice": "No genuine boss, business or government agency asks for payment in gift cards. Confirm any request by phone using a number you already have.",
    },
    {
        "name": "Remote access request",
        "category": "Tech support",
        "all_of": [
            [r"\banydesk\b", r"\bteamviewer\b", r"\bultraviewer\b", r"\bquick ?assist\b", r"\bremote (access|desktop|support)\b"],
            [r"\binstall\b", r"\bdownload\b", r"\baccess\b", r"\bconnect\b", r"\bcode\b", r"\bsession\b"],
        ],
        "official_brands": [],
        "advice": "Never install remote-access software because someone asked you to by email or phone.",
    },
]

# ----------------------------------------------------------------------
# Pacific campaigns: the six scam types described on scamwatcherpacific.com.
# The advice lines mirror the website's guidance.
# ----------------------------------------------------------------------
SCAM_PATTERNS += [
    {
        "name": "Fake overseas job offer",
        "category": "Work",
        "all_of": [
            [r"\bseasonal (work|job|worker)", r"\bfarm (work|job)", r"\bfruit pick", r"\bpalm scheme\b", r"\brse\b", r"\brecognised seasonal employer",
             r"\bwork (in|visa for) (australia|new zealand|nz|canada)\b", r"\bjob offer\b", r"\bjobs? (in|available in) (australia|new zealand|nz)\b", r"\bpacific australia labour mobility\b"],
            [r"\b(visa|placement|processing|registration|application|medical|training) (fee|payment|cost|charge)", r"\bpay\b.{0,30}\b(fee|deposit)\b",
             r"\bsend\b.{0,30}\b(money|payment|fee)\b", r"\bdeposit\b", r"\bsecure your (place|spot|position)\b"],
        ],
        "official_brands": [],
        "advice": "Real recruitment schemes don't charge you to apply. Check any job offer with your government's labour mobility office before paying anything.",
    },
    {
        "name": "Family money request from a new number or hacked account",
        "category": "Family",
        "all_of": [
            [r"\bnew (number|phone)\b", r"\bchanged? (my )?number\b", r"\blost my phone\b", r"\bphone (broke|is broken)\b", r"\bhi (mum|mom|dad|aunty|uncle|cuz)\b",
             r"\bit'?s me\b", r"\bthis is my new\b"],
            [r"\bsend\b.{0,20}\b(money|cash|\$|funds)\b", r"\btransfer\b", r"\burgent(ly)?\b", r"\bpay (a|this) bill\b", r"\bneed (some )?money\b", r"\bpay you back\b"],
        ],
        "official_brands": [],
        "advice": "Call them on their usual number first. Don't send money until you have spoken to them.",
    },
    {
        "name": "Remittance or money transfer on hold",
        "category": "Money transfer",
        "all_of": [
            [r"\bremittance\b", r"\bmoney transfer\b", r"\btransfer\b", r"\bwestern union\b", r"\bmoneygram\b", r"\bwire\b", r"\bfunds\b"],
            [r"\bon hold\b", r"\bpending\b.{0,30}\b(release|clearance)\b", r"\b(release|clearance|unlock(ing)?|activation) fee\b", r"\bpay\b.{0,30}\bto release\b",
             r"\bconfirm your (details|identity|account)\b", r"\bfunds? (have been|are) (held|frozen|suspended)\b"],
        ],
        "official_brands": [],
        "advice": "Check directly with the transfer company using their official contact details, not the ones in the message.",
    },
    {
        "name": "Prize or mobile money scam",
        "category": "Mobile",
        "all_of": [
            [r"\byou('ve| have) won\b", r"\bwinner\b", r"\bprize\b", r"\bpromotion\b", r"\blucky draw\b", r"\bmobile money\b", r"\be-?wallet\b", r"\bairtime\b", r"\btop[- ]?up\b"],
            [r"\bsend\b.{0,30}\b(credit|airtime|code|pin|fee)\b", r"\b(share|send|tell us|forward)\b.{0,30}\b(code|otp|pin)\b", r"\bverification code\b",
             r"\b(processing|collection|delivery|claim) fee\b", r"\bto claim\b"],
        ],
        "official_brands": [],
        "advice": "Never share a code sent to your phone. Phone companies and banks don't ask you to pay to collect a prize.",
    },
    {
        "name": "Investment or \"double your money\" scheme",
        "category": "Investment",
        "all_of": [
            [r"\bdouble your money\b", r"\binvest(ment|ing)?\b", r"\bcrypto\b", r"\bbitcoin\b", r"\bforex\b", r"\btrading\b", r"\bsavings group\b", r"\bscheme\b"],
            [r"\bguaranteed\b", r"\b\d{2,4} ?% (return|profit|interest)", r"\b(daily|weekly) (profit|returns?)\b", r"\bdouble\b", r"\brecruit\b", r"\binvite (friends|others|members)\b",
             r"\bno risk\b", r"\brisk[- ]free\b"],
        ],
        "official_brands": [],
        "advice": "If you must recruit others to earn, walk away. Big, fast, guaranteed returns are a warning sign.",
    },
    {
        "name": "Online romance scam",
        "category": "Relationships",
        "all_of": [
            [r"\bmy (love|darling|dear|sweetheart|honey)\b", r"\bi love you\b", r"\bsoul ?mate\b", r"\bmet (you )?online\b", r"\bcan'?t (video )?call\b", r"\bdeployed\b", r"\boil rig\b"],
            [r"\bsend\b.{0,30}\b(money|funds|\$)\b", r"\bcustoms (fee|charge)\b", r"\b(plane|flight|travel) ticket\b", r"\bhospital (bill|fee)\b", r"\bemergency\b", r"\bgift card\b"],
        ],
        "official_brands": [],
        "advice": "Don't send money to someone you haven't met in person. Send us the messages to check first.",
    },
    # --- Social media account takeovers (Facebook, Instagram, WhatsApp) ---
    {
        "name": "Fake Meta policy violation or page takeover",
        "category": "Social media",
        "all_of": [
            [r"\bmeta\b", r"\bfacebook\b", r"\binstagram\b", r"\bbusiness (support|suite|manager|centre|center)\b",
             r"\bfan ?page\b", r"\bcommunity standards\b"],
            [r"\bviolat", r"\bcopyright\b", r"\binfring", r"\bintellectual property\b", r"\bcommunity standards\b",
             r"\b(page|account) (has been |will be |is )?(restricted|suspended|disabled|deactivated|deleted|removed|locked|unpublished)\b",
             r"\b(permanent(ly)?|scheduled for) (delet|deactivat|disabl|remov)", r"\bappeal\b", r"\breported\b.{0,40}\b(page|account|post)\b",
             r"\bpolicy (breach|violation|warning)\b", r"\bfinal (warning|notice)\b"],
        ],
        "official_brands": ["Facebook", "Instagram"],
        "advice": "Meta does not send warnings about your page by Messenger, chat or a PDF. Check your page in the Facebook app under Account Status or Support Inbox, and never enter your password through a link or file.",
    },
    {
        "name": "Fake Meta verification or blue tick offer",
        "category": "Social media",
        "all_of": [
            [r"\bmeta\b", r"\bfacebook\b", r"\binstagram\b"],
            [r"\bblue (tick|badge|check)\b", r"\bverified badge\b", r"\bmeta verified\b", r"\bget (your page |your account )?verified\b",
             r"\bverification (request|badge|form|process)\b", r"\beligible for verification\b"],
        ],
        "official_brands": ["Facebook", "Instagram"],
        "advice": "Meta Verified is only applied for inside the Facebook or Instagram app itself. Ignore messages offering a blue tick and don't enter your login details.",
    },
    {
        "name": "Verification code theft (WhatsApp, Facebook or SMS code)",
        "category": "Social media",
        "all_of": [
            [r"\b(\d-digit |6 digit |six digit |verification |security |login |whatsapp )code\b", r"\bcode (i|we) (just )?sent\b", r"\bsent (you )?a code\b"],
            [r"\b(send|forward|share|give|tell) (me|us)?\s?(the|that|this|your)? ?code\b", r"\bsent (to you|to your phone) by (mistake|accident)\b",
             r"\bby mistake\b", r"\bwrong number\b", r"\bplease send\b"],
        ],
        "official_brands": [],
        "advice": "Never share a code sent to your phone, even with a friend or family member. Anyone asking for it is trying to take over your account. If you already shared it, turn on two-step verification and contact the app's support from inside the app.",
    },
]


def check_known_scams(subject, body, attachment_text="", sender_check=None, links_check=None, sender_domain="", link_domains=None):
    text = re.sub(r"\s+", " ", _lower(f"{subject}\n{body}\n{attachment_text}"))
    sender_check = sender_check or {}
    links_check = links_check or {}
    link_domains = link_domains or []

    matches = []
    for pattern in SCAM_PATTERNS:
        group_hits = []
        for group in pattern["all_of"]:
            hits = _matches(group, text)
            if not hits:
                group_hits = None
                break
            group_hits.append(hits)
        if group_hits:
            strength = sum(len(h) for h in group_hits)
            matches.append((strength, pattern, group_hits))

    if not matches:
        return {
            "key": "known_scams", "title": "Known scam patterns", "status": "pass",
            "headline": "Does not match any known scam campaign in our library.",
            "details": [f"Compared against {len(SCAM_PATTERNS)} common scam types seen in the Pacific and Australia."],
            "scam_type": "", "scam_category": "", "advice": "",
        }

    matches.sort(key=lambda m: m[0], reverse=True)
    strength, best, group_hits = matches[0]

    # Is it plausibly the genuine organisation? Only if the sender (and any
    # links) are official for one of the brands this scam usually imitates.
    official_hit = ""
    for brand in best["official_brands"]:
        if sender_domain and is_official(sender_domain, brand) and all(
            is_official(d, brand) for d in link_domains
        ):
            official_hit = brand
            break

    evidence = sorted(set(h for hits in group_hits for h in hits))[:4]
    details = [f'Matches the "{best["name"]}" pattern (key phrases: {", ".join(evidence)}).']

    others = [m[1]["name"] for m in matches[1:3]]
    if others:
        details.append("Also shares features with: " + ", ".join(others) + ".")

    # Links that go somewhere other than the organisations this kind of message
    # normally comes from (e.g. a "parcel" email linking to a random site).
    unofficial_links = [
        d for d in link_domains
        if best["official_brands"] and not any(is_official(d, b) for b in best["official_brands"])
        and registrable_domain(d) not in TRACKING_DOMAINS
    ]
    always_scam = best["category"] in (
        "Business email compromise", "Advance fee", "Extortion", "Investment", "Employment", "Impersonation",
        # Pacific campaigns: asking for a fee or code in these contexts is never genuine.
        "Work", "Money transfer", "Mobile", "Relationships",
        # A page warning or code request sent by chat is never Meta itself;
        # a real notice from Meta's own address still lands on "caution" above.
        "Social media",
    )

    if official_hit:
        status = "caution"
        headline = f"The wording resembles a common scam, but it comes from an official {official_hit} address. It may be genuine; verify through the official app or website."
        details.append(f"The sender and links are official {official_hit} addresses.")
    elif always_scam or sender_check.get("status") == "fail" or links_check.get("status") == "fail":
        status = "fail"
        headline = f"This matches a known scam: {best['name'].lower()}."
    elif unofficial_links:
        status = "fail"
        headline = f"This matches a known scam: {best['name'].lower()}."
        details.append(f"Links go to {', '.join(unofficial_links[:3])}, not an official website for this kind of message.")
    else:
        status = "caution"
        headline = f"The wording resembles a {best['name'].lower()}, though the sender and links look normal."

    details.append(best["advice"])

    return {
        "key": "known_scams", "title": "Known scam patterns", "status": status,
        "headline": headline, "details": _dedupe(details),
        "scam_type": best["name"] if status == "fail" else "",
        "possible_scam_type": best["name"],
        "scam_category": best["category"] if status == "fail" else "",
        "advice": best["advice"],
    }


# ----------------------------------------------------------------------
# Combined review
# ----------------------------------------------------------------------

def run_review(from_header, subject, body, reply_to="", html_links=None, auth_results=None,
               attachment_text="", submission_type=""):
    sender = check_sender(from_header, reply_to=reply_to, auth_results=auth_results,
                          submission_type=submission_type, body_text=body)
    content = check_content(subject, body, attachment_text)
    links = check_links(body, html_links, sender_domain=sender.get("sender_domain", ""),
                        claimed_brand=sender.get("claimed_brand", ""), content_signals=content.get("signals"))
    known = check_known_scams(subject, body, attachment_text, sender_check=sender, links_check=links,
                              sender_domain=sender.get("sender_domain", ""), link_domains=links.get("domains"))

    checks = [sender, content, links, known]
    statuses = {c["key"]: c["status"] for c in checks}
    fails = [k for k, s in statuses.items() if s == "fail"]
    cautions = [k for k, s in statuses.items() if s == "caution"]

    # A "looks like a known scam, but from the official sender with official
    # links" result is reassurance, not a warning, for scoring purposes.
    effective_cautions = [
        k for k in cautions
        if not (k == "known_scams" and statuses["sender"] == "pass" and statuses["links"] == "pass")
    ]

    # Minimum score implied by the checks. analyzer.py applies this after its
    # own scoring, so marketing-style discounts can never undo a clear failure.
    floor = 0
    if statuses["known_scams"] == "fail":
        floor = max(floor, 80)
    if statuses["sender"] == "fail" or statuses["links"] == "fail":
        floor = max(floor, 75)
    if len(fails) >= 2:
        floor = max(floor, 90)
    if statuses["content"] == "fail" and floor < 75:
        floor = max(floor, 60)
    if len(cautions) >= 2 and floor < 40:
        floor = 40

    scam_type = known.get("scam_type", "")
    scam_category = known.get("scam_category", "")
    if not scam_type and fails:
        if "credentials" in content.get("signals", []) or statuses["links"] == "fail":
            scam_type, scam_category = "Phishing (fake sign-in or details request)", "Account phishing"
        elif sender.get("claimed_brand") and statuses["sender"] == "fail":
            scam_type, scam_category = f"{sender['claimed_brand']} impersonation", "Impersonation"
        else:
            scam_type, scam_category = "Suspicious email (no specific campaign)", "Other"

    # Does it appear to be genuinely from the organisation it names? The sender
    # address is an official domain of that brand, the sender check passed, and
    # every link goes to that brand (or a known email-tracking service).
    brand = sender.get("claimed_brand", "")
    sender_domain = sender.get("sender_domain", "")
    link_domains = links.get("domains") or []
    links_official = all(
        is_official(d, brand)
        or registrable_domain(d) in TRACKING_DOMAINS
        or any(d.endswith("." + t) for t in TRACKING_DOMAINS)
        for d in link_domains
    ) if brand else False
    appears_genuine = bool(
        brand
        and sender_domain
        and is_official(sender_domain, brand)
        and statuses["sender"] == "pass"
        and statuses["links"] != "fail"
        and links_official
    )
    authenticated = bool(auth_results) and (
        (auth_results or {}).get("dmarc") == "pass"
        or ((auth_results or {}).get("spf") == "pass" and (auth_results or {}).get("dkim") == "pass")
    )
    if appears_genuine:
        # Keep the warning signs visible, but don't call a real organisation's
        # email "phishing". The analyzer turns this into "Needs Attention".
        floor = 0
        scam_type, scam_category = "", ""

    # Tidy, storable version (drop internal-only fields)
    public_checks = [
        {k: c[k] for k in ("key", "title", "status", "headline", "details")}
        for c in checks
    ]

    return {
        "checks": public_checks,
        "score_floor": floor,
        "scam_type": scam_type,
        "scam_category": scam_category,
        "advice": known.get("advice", ""),
        "claimed_brand": sender.get("claimed_brand", ""),
        "fail_count": len(fails),
        "caution_count": len(cautions),
        "effective_caution_count": len(effective_cautions),
        "appears_genuine": appears_genuine,
        "genuine_brand": brand if appears_genuine else "",
        "sender_authenticated": authenticated,
        "content_signals": content.get("signals", []),
    }
