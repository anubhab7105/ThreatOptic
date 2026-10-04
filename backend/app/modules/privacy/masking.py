"""PII masking (GDPR/CCPA). Exactly what is masked:

- payment card numbers: 13–19 digits (spaces/dashes allowed) that pass the
  Luhn checksum — bare digit runs that fail Luhn are left alone.
- US SSNs: NNN-NN-NNNN.
- phone numbers: E.164 (`+` followed by 7+ digits, separators allowed) and
  NANP 10-digit numbers only when written with separators/parentheses.
- email local-parts (`***@domain`); domains are kept for forensics.

Names, street addresses and IPs are NOT masked by this module.

Masking is unconditional — there is no unmask bypass anywhere in the
request path (Step 3).
"""
import re

CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ \-.]*){13,19}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# Only the visual separators E.164 permits (space, '.', '-', '(', ')'). This
# class must NOT contain \s: a newline-spanning match swallowed the following
# line, so 'call +1\n2025550123' lost its line break and an over-long run
# spanning lines was returned unmasked (see _mask_e164).
E164_RE = re.compile(r"\+\d(?:[\d .\-()]*\d)?")
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
    """Redact any `+`-prefixed run of >= 7 digits, with no upper bound.

    The 7-15 upper bound from the E.164 grammar could not be enforced safely:
    a run over 15 digits was returned verbatim, so a space-separated pair
    like '+12025550123 15551234567' left BOTH phone numbers in the masked
    body. Enforcing the ceiling is what caused the leak, so this fails
    closed instead — the match is `+` followed by digits and permitted
    separators, which is phone-shaped by construction.

    Genuine 13-19 digit card runs are unaffected: CARD_CANDIDATE_RE runs
    first with its Luhn gate, so anything that reaches here has already been
    rejected as a card.
    """
    digits = re.sub(r"\D", "", m.group(0))
    if len(digits) >= 7:
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
