
import hmac
import logging
import time
from collections import OrderedDict
from aiosmtpd.controller import Controller
from .queue import enqueue_email

log = logging.getLogger("smtp")

SMTP_INTAKE_PER_MINUTE = 30

INTAKE_MAX_IPS = 4096
_intake_hits: OrderedDict[str, list[float]] = OrderedDict()


def _intake_allowed(peer_ip: str) -> bool:
    now = time.time()
    hits = _intake_hits.pop(peer_ip, None) or []
    hits = [t for t in hits if now - t < 60.0]
    if len(hits) > SMTP_INTAKE_PER_MINUTE * 2:
        hits = hits[-(SMTP_INTAKE_PER_MINUTE * 2):]
    allowed = len(hits) < SMTP_INTAKE_PER_MINUTE
    if allowed:
        hits.append(now)
    _intake_hits[peer_ip] = hits
    while len(_intake_hits) > INTAKE_MAX_IPS:
        _intake_hits.popitem(last=False)
    if len(_intake_hits) % 128 == 0:
        cutoff = now - 60.0
        for key in [k for k, v in _intake_hits.items() if not v or v[-1] < cutoff]:
            _intake_hits.pop(key, None)
    return allowed


class IngestHandler:
    async def handle_DATA(self, server, session, envelope):
        import queue as _queue_mod
        from ..auth.rate_limit import audit
        peer_ip = getattr(session, "peer", "") or "unknown"
        if not _intake_allowed(peer_ip):
            audit("smtp.intake.throttled", peer=peer_ip, sender=envelope.mail_from)
            return "421 rate limited, try again later"
        try:
            await enqueue_email({"raw": envelope.content, "source": "smtp",
                                 "envelope_from": envelope.mail_from,
                                 "rcpt_tos": list(getattr(envelope, "rcpt_tos", []) or [])})
        except _queue_mod.Full:
            audit("smtp.intake.queue-full", peer=peer_ip)
            return "452 mailbox full, try again later"
        audit("smtp.intake", peer=peer_ip, sender=envelope.mail_from)
        return "250 queued for forensic analysis"


def _auth_callback(mechanism: str, login: bytes, password: bytes) -> bool:
    from ...config import get_settings
    settings = get_settings()
    expected_user = (settings.smtp_username or "").encode()
    expected_pass = (settings.smtp_password or "").encode()
    if not expected_user or not expected_pass:
        return False
    return hmac.compare_digest(login or b"", expected_user) and \
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


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _is_loopback(host: str) -> bool:

    h = (host or "").strip().lower()
    return h in _LOOPBACK_HOSTS or h.startswith("127.")


def _auth_required() -> bool:
    from ...config import get_settings
    return str(get_settings().smtp_require_auth).lower() not in ("", "0", "false", "no")


def start_smtp(host: str = "127.0.0.1", port: int = 1025) -> Controller:

    from ...config import get_settings
    settings = get_settings()
    loopback = _is_loopback(host)
    need_auth = _auth_required()
    tls = _tls_context()
    if not loopback and not need_auth:
        raise RuntimeError(
            f"Refusing SMTP bind to non-loopback {host!r} without authentication "
            "(open relay). Set SMTP_REQUIRE_AUTH=1 with SMTP_USERNAME/PASSWORD, "
            "or bind a loopback address."
        )
    if not loopback and need_auth and tls is None:
        raise RuntimeError(
            f"Refusing SMTP AUTH over plaintext on non-loopback {host!r}. "
            "Configure SMTP_TLS_CERT/SMTP_TLS_KEY."
        )
    server_kwargs: dict = {
        "data_size_limit": max(1024, int(settings.smtp_data_limit_bytes or 10 * 1024 * 1024)),
    }
    if need_auth:
        server_kwargs.update(auth_required=True, auth_require_tls=bool(tls),
                             auth_callback=_auth_callback)
        log.info("SMTP AUTH required")
    if tls is not None:
        server_kwargs.update(tls_context=tls, require_starttls=True)
        log.info("SMTP STARTTLS enforced")
    controller = Controller(IngestHandler(), hostname=host, port=port, **server_kwargs)
    controller.start()
    return controller
