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
    frm = str(raw_headers.get("From", ""))
    reply_to = str(raw_headers.get("Reply-To", ""))
    return_path = str(raw_headers.get("Return-Path", ""))
    x_mailer = str(raw_headers.get("X-Mailer", raw_headers.get("User-Agent", "")))
    message_id = str(raw_headers.get("Message-ID", raw_headers.get("Message-Id", "")))
    auth_results = str(raw_headers.get("Authentication-Results", ""))

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
