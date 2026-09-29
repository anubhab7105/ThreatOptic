"""PII masking (GDPR/CCPA). Exactly what is masked:

- payment card numbers: 13–19 digits (spaces/dashes allowed) that pass the
  Luhn checksum — bare digit runs that fail Luhn are left alone.
- US SSNs: NNN-NN-NNNN.
- phone numbers: E.164 (`+` followed by 7–15 digits, separators allowed) and
  NANP 10-digit numbers only when written with separators/parentheses.
- email local-parts (`***@domain`); domains are kept for forensics.

Names, street addresses and IPs are NOT masked by this module.

Masking is unconditional — there is no unmask bypass anywhere in the
request path (Step 3).
"""
import re

CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ \-.]*?){13,19}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
E164_RE = re.compile(r"\+\d(?:[\d.\s\-()]*\d)?")
NANP_RE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}\b")
EMAIL_RE = re.compile(r"([\w.\-+]+)@([\w.\-]+\.\w+)")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total > 0 and total % 10 == 0


def _mask_card(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    if 13 <= len(digits) <= 19 and _luhn_ok(digits):
        return "[CARD-REDACTED]"
    return m.group(0)


def _mask_e164(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    if 7 <= len(digits) <= 15:
        return "[PHONE-REDACTED]"
    return m.group(0)


def mask_text(text: str) -> str:
    if not text:
        return ""
    t = CARD_CANDIDATE_RE.sub(_mask_card, text)
    t = SSN_RE.sub("[SSN-REDACTED]", t)
    t = E164_RE.sub(_mask_e164, t)
    t = NANP_RE.sub("[PHONE-REDACTED]", t)
    # mask local part of emails, keep domain for forensics
    t = EMAIL_RE.sub(r"***@\2", t)
    return t
