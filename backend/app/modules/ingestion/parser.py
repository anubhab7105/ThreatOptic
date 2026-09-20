"""Robust MIME parser: headers, body (text/html), attachments metadata, .eml hash."""
import email
import email.policy
import hashlib
from email.message import Message
from typing import Any


def parse_eml(raw: bytes) -> dict[str, Any]:
    sha = hashlib.sha256(raw).hexdigest()
    msg: Message = email.message_from_bytes(raw, policy=email.policy.default)

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

    body_text = ""
    body_html = ""
    attachments: list[dict] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = part.get_content_disposition()
            if disp == "attachment":
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": part.get_filename() or "unnamed",
                    "content_type": ctype,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    # first bytes only: enough for magic-byte checks without
                    # retaining the (possibly malicious) full payload.
                    "magic": payload[:8].hex(),
                })
            elif ctype == "text/plain" and not body_text:
                try:
                    body_text = part.get_content()
                except Exception:
                    body_text = ""
            elif ctype == "text/html" and not body_html:
                try:
                    body_html = part.get_content()
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
    }
