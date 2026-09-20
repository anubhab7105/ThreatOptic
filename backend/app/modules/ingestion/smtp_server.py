"""Inline SMTP relay (aiosmtpd) -> enqueue raw bytes for pipeline."""
from aiosmtpd.controller import Controller
from .queue import enqueue_email


class IngestHandler:
    async def handle_DATA(self, server, session, envelope):
        await enqueue_email({"raw": envelope.content, "source": "smtp", "envelope_from": envelope.mail_from})
        return "250 queued for forensic analysis"


def start_smtp(host: str = "0.0.0.0", port: int = 1025) -> Controller:
    controller = Controller(IngestHandler(), hostname=host, port=port)
    controller.start()
    return controller
