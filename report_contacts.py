"""Where to report a scam, by country.

One list used by both the website ("Where to report, by country") and the
reply emails ("To report it in Samoa: ..."). Every contact here was checked
against an official or reputable source; the source is kept next to each
country so it can be re-checked. Do not add a contact you haven't verified.

After changing this file, rebuild the website section:
    python report_contacts.py --html   (prints the block to paste into site/index.html)

Last checked: October 2026.
"""

import html
import re
import sys

CHECKED = "October 2026"

# Each item: (label, text, link or "")
#   link "tel:..." becomes a tap-to-call link, "https://..." a web link,
#   "mailto:..." an email link.
CONTACTS = [
    {
        "code": "fj", "name": "Fiji",
        "aliases": ["fiji", "fiji islands", "viti"],
        "items": [
            ("Emergency", "Police 917", "tel:917"),
            ("Check a caller claiming to be police", "National Police Command Centre 9905 296", "tel:+6799905296"),
            ("Report a scam", "Consumer Council of Fiji, free call 155", "tel:155"),
            ("Report by email", "complaints@consumersfiji.org", "mailto:complaints@consumersfiji.org"),
        ],
        "reply": "call the Consumer Council of Fiji on 155 (free) or email complaints@consumersfiji.org, and tell the Fiji Police (917 in an emergency)",
        "sources": [
            "https://consumersfiji.org/?p=2480",
            "https://fijisun.com.fj/news/crime/dont-fall-for-fake-messages-police-warn",
            "https://www.fijitimes.com.fj/high-prank-calls-to-emergency-line-concerns-fijian-police/",
        ],
    },
    {
        "code": "ws", "name": "Samoa",
        "aliases": ["samoa", "western samoa", "apia"],
        "items": [
            ("Emergency and police", "911", "tel:911"),
            ("Report a scam", "Samoa Police Service. Go to your nearest police station or call 911", ""),
            ("Money or bank scams", "Central Bank of Samoa passes scam reports to the police", "https://cbs.gov.ws/"),
        ],
        "reply": "report it to the Samoa Police Service at your nearest station or on 911, and tell your bank",
        "sources": [
            "https://www.osac.gov/Content/Report/60cb31f6-3624-4b79-b430-1ccf0552309f",
            "https://cbs.gov.ws/news/central-bank-of-samoa-warns-public-of-rising-scams",
        ],
    },
    {
        "code": "to", "name": "Tonga",
        "aliases": ["tonga", "tongatapu", "nuku'alofa", "nukualofa"],
        "items": [
            ("Emergency", "Police 922", "tel:922"),
            ("Report a scam", "Tonga Police, free call 0800 922 or 23 713", "tel:0800922"),
            ("Hacked accounts and online attacks", "CERT Tonga, cert@cert.gov.to", "mailto:cert@cert.gov.to"),
        ],
        "reply": "report it to Tonga Police on 922, 0800 922 (free) or 23 713",
        "sources": [
            "https://kanivatonga.co.nz/2022/08/tonga-police-urge-residents-to-be-aware-of-potential-scams",
            "https://www.smartraveller.gov.au/destinations/pacific/tonga",
            "https://pacnog.org/pacnog32/presentations/TongaCERT-update.pdf",
        ],
    },
    {
        "code": "pg", "name": "Papua New Guinea",
        "aliases": ["papua new guinea", "png", "port moresby", "lae"],
        "items": [
            ("Emergency", "Police 112", "tel:112"),
            ("Report a scam", "Your nearest Royal PNG Constabulary police station", ""),
            ("Lost money", "Contact your bank or mobile money provider straight away", ""),
        ],
        "reply": "report it at your nearest Royal PNG Constabulary police station (112 in an emergency), and tell your bank or mobile money provider",
        "sources": [
            "https://rpngc.gov.pg/advice-services/cybercrime-awareness/vi-what-to-do-if-youre-a-victim-of-cybercrime/",
            "https://www.smartraveller.gov.au/destinations/papua-new-guinea",
        ],
    },
    {
        "code": "vu", "name": "Vanuatu",
        "aliases": ["vanuatu", "port vila", "santo", "espiritu santo"],
        "items": [
            ("Emergency", "Police 111 (Digicel) or 1111 (TVL)", "tel:111"),
            ("Police", "Port Vila 22 222 · Santo 36 222", "tel:+67822222"),
            ("Report a scam online", "CERT Vanuatu report form", "https://cert.gov.vu/index.php/report-incident"),
        ],
        "reply": "report it to CERT Vanuatu at cert.gov.vu (Report incident) and to the police (Port Vila 22 222, Santo 36 222)",
        "sources": [
            "https://cert.gov.vu/index.php/report-incident",
            "https://police.gov.vu/what-we-do/criminal-investigation/fraud",
            "https://police.gov.vu/contact-us/3-police-emergency",
        ],
    },
    {
        "code": "sb", "name": "Solomon Islands",
        "aliases": ["solomon islands", "solomons", "solomon", "honiara"],
        "items": [
            ("Emergency", "Police 999 (free)", "tel:999"),
            ("Report a scam", "Royal Solomon Islands Police Force 23666", "tel:+67723666"),
            ("Lost money", "Contact your bank or mobile money provider straight away", ""),
        ],
        "reply": "report it to the Royal Solomon Islands Police Force on 23666 or 999 (free)",
        "sources": [
            "https://sundayisles.islesmedia.net/police-reminds-public-to-report-criminal-activities/",
        ],
    },
    {
        "code": "au", "name": "Australia",
        "aliases": ["australia", "aus", "au"],
        "items": [
            ("Report a scam", "Scamwatch", "https://www.scamwatch.gov.au/report-a-scam"),
            ("Report to police online", "ReportCyber", "https://www.cyber.gov.au/report-and-recover/report"),
            ("Free recovery help", "IDCARE 1800 595 160", "tel:1800595160"),
        ],
        "reply": "report it to Scamwatch (scamwatch.gov.au) and to police through ReportCyber (cyber.gov.au), and call IDCARE on 1800 595 160 for free help",
        "sources": [
            "https://www.scamwatch.gov.au/node/235",
        ],
    },
    {
        "code": "nz", "name": "New Zealand",
        "aliases": ["new zealand", "nz", "aotearoa"],
        "items": [
            ("Report a scam", "National Cyber Security Centre", "https://www.ncsc.govt.nz/report/"),
            ("Lost money", "NZ Police, call 105", "tel:105"),
            ("Free recovery help", "IDCARE 0800 121 068", "tel:0800121068"),
        ],
        "reply": "report it to the National Cyber Security Centre (ncsc.govt.nz/report) and, if you lost money, to NZ Police on 105",
        "sources": [
            "https://www.govt.nz/browse/law-crime-and-justice/scams/",
            "https://www.dia.govt.nz/Spam-How-to-Report-Scams",
        ],
    },
]

_BY_ALIAS = {}
for _c in CONTACTS:
    for _a in _c["aliases"] + [_c["name"].lower()]:
        _BY_ALIAS[_a] = _c


def for_country(country):
    """The contacts for a country typed into the form, or None."""
    text = re.sub(r"[^a-z' ]+", " ", (country or "").lower()).strip()
    text = re.sub(r"\s+", " ", text)
    if not text:
        return None
    if text in _BY_ALIAS:
        return _BY_ALIAS[text]
    # "I live in Samoa", "Fiji (Suva)"
    for alias in sorted(_BY_ALIAS, key=len, reverse=True):
        if len(alias) > 3 and re.search(rf"\b{re.escape(alias)}\b", text):
            return _BY_ALIAS[alias]
    return None


def reply_line(country):
    """One sentence for the reply email, or ""."""
    entry = for_country(country)
    if not entry:
        return ""
    name = "the Solomon Islands" if entry["code"] == "sb" else entry["name"]
    return f"In {name}, {entry['reply']}."


# ----------------------------------------------------------------------
# Website block
# ----------------------------------------------------------------------

def _item_html(label, text, link):
    t = html.escape(text)
    if link.startswith(("tel:", "mailto:")):
        value = f'<a href="{html.escape(link)}">{t}</a>'
    elif link:
        value = f'<a href="{html.escape(link)}" rel="noopener" target="_blank">{t}</a>'
    else:
        value = t
    return f'<div><dt>{html.escape(label)}</dt><dd>{value}</dd></div>'


def website_html(indent="          "):
    options = "".join(f'<option value="{c["code"]}">{html.escape(c["name"])}</option>' for c in CONTACTS)
    panels = []
    for c in CONTACTS:
        items = "".join(_item_html(*i) for i in c["items"])
        panels.append(
            f'<section class="report-country" id="report-{c["code"]}" data-country="{c["code"]}" aria-label="{html.escape(c["name"])}">'
            f'<h4>{html.escape(c["name"])}</h4><dl>{items}</dl></section>'
        )
    lines = [
        '<div class="report-pick js-only">',
        '  <label for="report-country">Choose your country</label>',
        f'  <select id="report-country"><option value="">Select…</option>{options}</select>',
        '</div>',
        '<div class="report-list" aria-live="polite">',
        *["  " + p for p in panels],
        '</div>',
    ]
    return "\n".join(indent + l for l in lines)


if __name__ == "__main__":
    if "--html" in sys.argv:
        print(website_html())
    else:
        for c in CONTACTS:
            print(c["name"], "->", reply_line(c["name"]))
