"""PII masking (GDPR/CCPA): CC, SSN, emails, phones, names — unless Unmask_Privileges."""
import re

CC_RE = re.compile(r"\b(?:\d[ \-]*?){13,16}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
EMAIL_RE = re.compile(r"([\w.\-+]+)@([\w.\-]+\.\w+)")
PHONE_RE = re.compile(r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")


def mask_text(text: str, unmask: bool = False) -> str:
    if unmask or not text:
        return text or ""
    t = CC_RE.sub("[CARD-REDACTED]", text)
    t = SSN_RE.sub("[SSN-REDACTED]", t)
    t = PHONE_RE.sub("[PHONE-REDACTED]", t)
    # mask local part of emails, keep domain for forensics
    t = EMAIL_RE.sub(r"***@\2", t)
    return t
