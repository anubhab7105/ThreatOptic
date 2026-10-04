"""Full header parsing: X-Mailer, Message-ID, auth headers, display-name spoof checks."""
import re
from typing import Any

EMAIL_RE = re.compile(r"([\w.\-+]+@[\w.\-]+\.\w+)")
DISPLAY_RE = re.compile(r'^\s*"?([^"<]+)"?\s*<([^>]+)>\s*$')

# Display names trading on these identities while sending from elsewhere.
SPOOFED_IDENTITY_HINTS = (
    "ceo", "cfo", "cto", "president", "chairman", "board of directors",
    "human resources", "hr department", "payroll", "it helpdesk", "helpdesk",
    "security team", "support team", "billing department", "finance department",
    "paypal", "apple", "microsoft", "google", "amazon", "bank",
)

# RFC 5322 2.2: header field names are case-insensitive. Senders pick the
# casing, so every lookup has to be too -- `fROM:`, `rECEIVED:` and
# `FrOm:` previously reached the parsers as-is, blanking from_addr and
# suppressing every From/Received-derived detection.
#
# Canonical spellings for the names this codebase looks up. Anything not
# listed keeps the sender's casing.
CANONICAL_HEADER_NAMES = {
    "from": "From",
    "to": "To",
    "cc": "Cc",
    "bcc": "Bcc",
    "reply-to": "Reply-To",
    "return-path": "Return-Path",
    "received": "Received",
    "received-spf": "Received-SPF",
    "subject": "Subject",
    "date": "Date",
    "message-id": "Message-ID",
    "in-reply-to": "In-Reply-To",
    "references": "References",
    "x-mailer": "X-Mailer",
    "user-agent": "User-Agent",
    "dkim-signature": "DKIM-Signature",
    "authentication-results": "Authentication-Results",
    "arc-authentication-results": "ARC-Authentication-Results",
    "x-authentication-results": "X-Authentication-Results",
    "content-type": "Content-Type",
    "content-transfer-encoding": "Content-Transfer-Encoding",
    "x-originating-ip": "X-Originating-IP",
    "x-sender-ip": "X-Sender-IP",
    "x-client-ip": "X-Client-IP",
    "x-real-ip": "X-Real-IP",
    "x-forwarded-for": "X-Forwarded-For",
    "x-original-client-ip": "X-Original-Client-IP",
    "cf-connecting-ip": "CF-Connecting-IP",
    "true-client-ip": "True-Client-IP",
}


def canonical_header_name(name: str) -> str:
    """Canonical spelling for a header name, case-insensitively."""
    cleaned = str(name).strip()
    return CANONICAL_HEADER_NAMES.get(cleaned.lower(), cleaned)


def header_value(raw_headers: Any, name: str, default: str = "") -> str:
    """Case-insensitive header lookup.

    Exact hit first (the common path once parser.parse_eml has canonicalised
    the keys), then a case-insensitive scan so rows persisted before that
    normalisation -- or dicts handed in by a caller -- still resolve.
    """
    if not isinstance(raw_headers, dict):
        return default
    if name in raw_headers:
        val = raw_headers[name]
        if isinstance(val, list):
            return "\n".join(str(v) for v in val)
        return str(val or "")
    low = name.lower()
    for k, v in raw_headers.items():
        if str(k).strip().lower() == low:
            if isinstance(v, list):
                return "\n".join(str(x) for x in v)
            return str(v or "")
    return default


def _identity_spoof(disp_name: str, from_addr: str) -> bool:
    """Display name trades on an identity the sender domain doesn't own."""
    name = (disp_name or "").lower()
    if not name or not from_addr:
        return False
    if "@" in name and name.strip() != from_addr.lower():
        return True  # display name is itself a different address
    domain = from_addr.lower().split("@")[-1] if "@" in from_addr else ""
    for hint in SPOOFED_IDENTITY_HINTS:
        if hint in name and hint.replace(" ", "") not in domain.replace(".", ""):
            return True
    return False


def parse_headers(raw_headers: dict[str, Any]) -> dict[str, Any]:
    frm = header_value(raw_headers, "From")
    reply_to = header_value(raw_headers, "Reply-To")
    return_path = header_value(raw_headers, "Return-Path")
    x_mailer = header_value(raw_headers, "X-Mailer") or header_value(raw_headers, "User-Agent")
    message_id = header_value(raw_headers, "Message-ID")
    auth_results = header_value(raw_headers, "Authentication-Results")

    def extract(addr: str) -> tuple[str, str]:
        m = DISPLAY_RE.match(addr.strip())
        if m:
            return m.group(1).strip().strip('"'), m.group(2).strip()
        e = EMAIL_RE.search(addr)
        return "", e.group(1) if e else addr.strip()

    disp_name, from_addr = extract(frm)
    _, reply_addr = extract(reply_to) if reply_to else ("", "")
    _, rp_addr = extract(return_path) if return_path else ("", "")

    flags: list[str] = []
    # multiple From headers/addresses: classic spoofing setup
    from_addrs = EMAIL_RE.findall(frm)
    if len(from_addrs) > 1 or "\n" in frm:
        flags.append("multiple-from")
    # display-name spoof: name trades on an unowned identity
    if _identity_spoof(disp_name, from_addr):
        flags.append("display-name-spoof")
    # reply-to mismatch (PSL-aware same-organization comparison so
    # support@mail.company.com vs ceo@company.com is NOT flagged, while
    # attacker@evil.co.uk vs ceo@bank.co.uk IS).
    if reply_addr and from_addr and reply_addr.lower() != from_addr.lower():
        try:
            from .psl import same_organization
            d1 = reply_addr.split("@")[1].lower()
            d2 = from_addr.split("@")[1].lower()
            if not same_organization(d1, d2):
                flags.append("reply-to-mismatch")
        except IndexError:
            flags.append("reply-to-mismatch")
    # lookalike: punycode, homoglyph folds, and typosquats (shared module)
    for val in [from_addr, reply_addr, rp_addr]:
        if "xn--" in val.lower():
            flags.append("punycode-domain")
            break
    try:
        from ..threat_intel.lookalikes import lookalike_of
        for val in [from_addr, reply_addr, rp_addr]:
            dom = val.split("@")[-1].lower() if "@" in val else ""
            lk = lookalike_of(dom) if dom else None
            if lk:
                flags.append(f"lookalike-domain:{lk['impersonates']}:{','.join(lk['via'])}")
                break
    except Exception:
        pass

    return {
        "from_display": disp_name,
        "from_addr": from_addr,
        "reply_to": reply_addr,
        "return_path": rp_addr,
        "x_mailer": x_mailer,
        "message_id": message_id,
        "auth_results_header": auth_results[:2000],
        "flags": flags,
    }
