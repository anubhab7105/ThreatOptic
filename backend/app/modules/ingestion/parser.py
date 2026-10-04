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

from ..forensics.header_parser import canonical_header_name

MAX_EML_BYTES = 10 * 1024 * 1024
MAX_ATTACHMENTS = 20
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024

_SCRIPT_STYLE_OPEN_RE = re.compile(r"<(script|style)\b", re.IGNORECASE)


def strip_script_style(html_text: str) -> str:
    """Remove <script>/<style> elements together with their content.

    Hand-rolled instead of `<(script|style)\\b.*?</\\1\\s*>` with re.DOTALL.
    That pattern is quadratic: when no closing tag follows an opening tag,
    the lazy `.*?` plus the `\\1` backreference re-tries every end offset, and
    find/replace restarts at each `<`. Measured at ~24s for 256KB of repeated
    `<script>` (~10 hours projected at the 10MB MAX_EML_BYTES ceiling), from a
    single unauthenticated upload.

    Walking the string with str.find visits each element once, so this is
    linear. An unterminated <script>/<style> now drops to end-of-string
    instead of being left in place; that is strictly safer, since the
    remainder could otherwise survive as visible text.
    """
    text = html_text or ""
    lowered = text.lower()
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        lt = text.find("<", i)
        if lt < 0:
            out.append(text[i:])
            break
        out.append(text[i:lt])
        m = _SCRIPT_STYLE_OPEN_RE.match(text, lt)
        if not m:
            out.append("<")
            i = lt + 1
            continue
        tag = m.group(1).lower()
        close = lowered.find(f"</{tag}", m.end())
        if close < 0:
            break  # unterminated: drop the remainder
        gt = text.find(">", close)
        if gt < 0:
            break
        out.append(" ")
        i = gt + 1
    return "".join(out)


def sanitize_html(html_text: str) -> str:
    """Remove script/style elements, then strip all tags. Returns text."""
    no_scripts = strip_script_style(html_text)
    try:
        import bleach
        cleaned = bleach.clean(no_scripts, tags=[], attributes={}, strip=True)
    except Exception:
        cleaned = re.sub(r"<[^>]+>", " ", no_scripts)
    return re.sub(r"[ \t]+", " ", cleaned).strip()


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
    # Header names are case-insensitive (RFC 5322 2.2) but msg.raw_items()
    # preserves whatever the sender typed, so `fROM:` and `From:` used to
    # become two entries: parsers that look a header up by exact name saw
    # nothing, and the duplicate-detection below missed the extra From.
    seen_names: dict[str, str] = {}
    for k, v in msg.raw_items():
        name = str(k).strip()
        low = name.lower()
        key = seen_names.get(low)
        if key is None:
            key = seen_names[low] = canonical_header_name(name)
        # keep first occurrence + join duplicates for Received chains
        if key in raw_headers:
            raw_headers[key] = raw_headers[key] + "\n" + str(v)
        else:
            raw_headers[key] = str(v)

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
            content = msg.get_content()
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="ignore")
            body_text = sanitize_html(content) if msg.get_content_type() == "text/html" else content
            if msg.get_content_type() == "text/html":
                body_html = body_text
        except Exception:
            payload = msg.get_payload(decode=True)
            body_text = payload.decode("utf-8", errors="ignore") if payload else str(msg.get_payload())

    if not body_text and body_html:
        # body_html is already bleach-sanitized text at this point.
        body_text = re.sub(r"\s+", " ", body_html).strip()

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
