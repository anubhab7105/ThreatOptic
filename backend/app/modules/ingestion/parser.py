"""Robust MIME parser: headers, body (text/html), attachments metadata, .eml hash.

Step 4 (C9) hardening:
- hard caps: max .eml bytes, max attachment count/size (ValueError over).
- HTML is sanitized with bleach: <script>/<style> elements removed
  entirely, then all remaining tags stripped. The stored/returned
  body_html is the SANITIZED version — never raw markup — so downstream
  rendering cannot execute stored scripts.
- malformed MIME raises ValueError (API maps to 400), never a raw traceback.
"""
import email
import email.policy
import hashlib
import re
from email.message import Message
from typing import Any

MAX_EML_BYTES = 10 * 1024 * 1024
MAX_ATTACHMENTS = 20
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024

_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL)


def sanitize_html(html_text: str) -> str:
    """Remove script/style elements, then strip all tags. Returns text."""
    no_scripts = _SCRIPT_STYLE_RE.sub(" ", html_text or "")
    try:
        import bleach
        return bleach.clean(no_scripts, tags=[], attributes={}, strip=True)
    except Exception:
        return re.sub(r"<[^>]+>", " ", no_scripts)


def parse_eml(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("email payload must be bytes")
    if len(raw) > MAX_EML_BYTES:
        raise ValueError(f"email exceeds {MAX_EML_BYTES} byte limit")
    sha = hashlib.sha256(raw).hexdigest()
    try:
        msg: Message = email.message_from_bytes(bytes(raw), policy=email.policy.default)
    except Exception as e:
        raise ValueError(f"malformed message: {e}")

    raw_headers: dict[str, str] = {}
    for k, v in msg.raw_items():
        # keep first occurrence + join duplicates for Received chains
        if k in raw_headers:
            raw_headers[k] = raw_headers[k] + "\n" + str(v)
        else:
            raw_headers[k] = str(v)

    subject = str(msg.get("Subject", ""))
    sender = str(msg.get("From", ""))
    recipient = str(msg.get("To", ""))
    message_id = str(msg.get("Message-ID", ""))

    from email.utils import parsedate_to_datetime
    from datetime import datetime, timezone
    email_dt = None
    date_hdr = str(msg.get("Date", "") or "").strip()
    if date_hdr:
        try:
            email_dt = parsedate_to_datetime(date_hdr)
            if email_dt.tzinfo is None:
                email_dt = email_dt.replace(tzinfo=timezone.utc)
            else:
                email_dt = email_dt.astimezone(timezone.utc)
        except Exception:
            email_dt = None

    if email_dt is None:
        recv_hdr = str(msg.get("Received", "") or "")
        if ";" in recv_hdr:
            try:
                date_part = recv_hdr.split(";")[-1].strip()
                email_dt = parsedate_to_datetime(date_part)
                if email_dt.tzinfo is None:
                    email_dt = email_dt.replace(tzinfo=timezone.utc)
                else:
                    email_dt = email_dt.astimezone(timezone.utc)
            except Exception:
                email_dt = None

    if email_dt is None:
        email_dt = datetime.now(timezone.utc)

    body_text = ""
    body_html = ""
    attachments: list[dict] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get_content_disposition()
            if disp == "attachment":
                payload = part.get_payload(decode=True) or b""
                if len(payload) > MAX_ATTACHMENT_BYTES:
                    raise ValueError(f"attachment exceeds {MAX_ATTACHMENT_BYTES} byte limit")
                attachments.append({
                    "filename": part.get_filename() or "unnamed",
                    "content_type": ctype,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    # first bytes only: enough for magic-byte checks without
                    # retaining the (possibly malicious) full payload.
                    "magic": payload[:8].hex(),
                })
                if len(attachments) > MAX_ATTACHMENTS:
                    raise ValueError(f"email exceeds {MAX_ATTACHMENTS} attachments")
            elif ctype == "text/plain" and not body_text:
                try:
                    body_text = part.get_content()
                except Exception:
                    body_text = ""
            elif ctype == "text/html" and not body_html:
                try:
                    body_html = sanitize_html(part.get_content())
                except Exception:
                    body_html = ""
    else:
        try:
            body_text = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True)
            body_text = payload.decode("utf-8", errors="ignore") if payload else str(msg.get_payload())

    if not body_text and body_html:
        # crude html strip fallback (full defang in url_analyzer)
        import re
        body_text = re.sub(r"<[^>]+>", " ", body_html)

    return {
        "message_id": message_id,
        "sender_address": sender,
        "recipient_address": recipient,
        "subject": subject,
        "raw_headers": raw_headers,
        "body_text": body_text or "",
        "body_html": body_html or "",
        "attachments_metadata": attachments,
        "raw_eml_hash": sha,
        "timestamp": email_dt,
    }
