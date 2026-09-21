"""Inline SMTP relay (aiosmtpd) -> enqueue raw bytes for pipeline.

Step 5 (C8) hardening:
- Binds localhost by default; 0.0.0.0 only with explicit SMTP_HOST.
- Optional SMTP AUTH (LOGIN/PLAIN) via SMTP_USERNAME/PASSWORD; required
  when SMTP_REQUIRE_AUTH=1. TLS via SMTP_TLS_CERT/KEY (STARTTLS enforced
  for AUTH when a cert is configured).
- DATA size cap (SMTP_DATA_LIMIT_BYTES, default 10MB) enforced by the
  server itself (552 on overflow).
- Envelope RCPT TO is preserved into the queued payload (was discarded).
- Per-IP intake bucket (30/min) from Step 2 is unchanged.
"""
import hmac
import logging
import time
from aiosmtpd.controller import Controller
from .queue import enqueue_email

log = logging.getLogger("smtp")

SMTP_INTAKE_PER_MINUTE = 30
_intake_hits: dict[str, list[float]] = {}


def _intake_allowed(peer_ip: str) -> bool:
    now = time.time()
    hits = [t for t in _intake_hits.get(peer_ip, []) if now - t < 60.0]
    _intake_hits[peer_ip] = hits
    if len(hits) >= SMTP_INTAKE_PER_MINUTE:
        return False
    hits.append(now)
    return True


class IngestHandler:
    async def handle_DATA(self, server, session, envelope):
        from ..auth.rate_limit import audit
        peer_ip = getattr(session, "peer", "") or "unknown"
        if not _intake_allowed(peer_ip):
            audit("smtp.intake.throttled", peer=peer_ip, sender=envelope.mail_from)
            return "421 rate limited, try again later"
        await enqueue_email({"raw": envelope.content, "source": "smtp",
                             "envelope_from": envelope.mail_from,
                             "rcpt_tos": list(getattr(envelope, "rcpt_tos", []) or [])})
        audit("smtp.intake", peer=peer_ip, sender=envelope.mail_from)
        return "250 queued for forensic analysis"


def _auth_callback(username: bytes, password: bytes, mechanism: str = "") -> bool:
    from ...config import get_settings
    settings = get_settings()
    expected_user = (settings.smtp_username or "").encode()
    expected_pass = (settings.smtp_password or "").encode()
    if not expected_user or not expected_pass:
        return False
    return hmac.compare_digest(username or b"", expected_user) and \
        hmac.compare_digest(password or b"", expected_pass)


def _tls_context():
    from ...config import get_settings
    import ssl
    settings = get_settings()
    cert, key = settings.smtp_tls_cert, settings.smtp_tls_key
    if not cert or not key:
        return None
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert, key)
    return ctx


def start_smtp(host: str = "127.0.0.1", port: int = 1025) -> Controller:
    """Start the relay. Localhost bind unless SMTP_HOST says otherwise.

    Controller forwards extra kwargs straight to the SMTP server, so auth,
    TLS and size limits land on the protocol handler itself.
    """
    from ...config import get_settings
    settings = get_settings()
    server_kwargs: dict = {
        "data_size_limit": max(1024, int(settings.smtp_data_limit_bytes or 10 * 1024 * 1024)),
    }
    if str(settings.smtp_require_auth).lower() not in ("", "0", "false", "no"):
        server_kwargs.update(auth_required=True, auth_require_tls=bool(_tls_context()),
                             auth_callback=_auth_callback)
        log.info("SMTP AUTH required")
    tls = _tls_context()
    if tls is not None:
        server_kwargs.update(tls_context=tls, require_starttls=True)
        log.info("SMTP STARTTLS enforced")
    controller = Controller(IngestHandler(), hostname=host, port=port, **server_kwargs)
    controller.start()
    return controller
