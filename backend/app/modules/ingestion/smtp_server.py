"""Inline SMTP relay (aiosmtpd) -> enqueue raw bytes for pipeline."""
import logging
import time
from aiosmtpd.controller import Controller
from .queue import enqueue_email

log = logging.getLogger("smtp")

# Per-sender-IP intake bucket: 30 msgs/minute (Step 2). In-process like the
# HTTP limiter; shared Redis in front for multi-replica deployments.
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
        await enqueue_email({"raw": envelope.content, "source": "smtp", "envelope_from": envelope.mail_from})
        audit("smtp.intake", peer=peer_ip, sender=envelope.mail_from)
        return "250 queued for forensic analysis"


def start_smtp(host: str = "0.0.0.0", port: int = 1025) -> Controller:
    controller = Controller(IngestHandler(), hostname=host, port=port)
    controller.start()
    return controller
