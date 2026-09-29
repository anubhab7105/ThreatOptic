"""SMTP ingestion end-to-end (F3): raw message via aiosmtplib -> EmailRecord row."""
import asyncio
import uuid
from email.message import EmailMessage

SMTP_TEST_PORT = 10025


def test_smtp_ingest_creates_record(monkeypatch):
    import aiosmtplib
    from app import models
    from app.database import SessionLocal, init_db
    from app.main import _smtp_consumer
    from app.modules.ingestion.smtp_server import start_smtp
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "smtp_require_auth", "0")

    init_db()
    from app.modules.ingestion import smtp_server
    smtp_server._intake_hits.clear()
    marker = f"<smtp-{uuid.uuid4().hex[:8]}@test.local>"
    controller = start_smtp("127.0.0.1", SMTP_TEST_PORT)

    async def run():
        task = asyncio.create_task(_smtp_consumer())
        try:
            msg = EmailMessage()
            msg["From"] = "alice@test.local"
            msg["To"] = "bob@test.local"
            msg["Subject"] = "SMTP probe"
            msg["Message-ID"] = marker
            msg.set_content("hello via smtp")
            await aiosmtplib.send(msg, hostname="127.0.0.1", port=SMTP_TEST_PORT)

            row = None
            for _ in range(100):
                db = SessionLocal()
                try:
                    row = db.query(models.EmailRecord).filter(
                        models.EmailRecord.message_id == marker).first()
                    if row:
                        email_id, subject = row.id, row.subject
                        break
                finally:
                    db.close()
                await asyncio.sleep(0.1)
            assert row is not None, "SMTP message never reached the pipeline"
            assert subject == "SMTP probe"

            # cleanup forensic rows for the probe
            db = SessionLocal()
            try:
                db.query(models.AnalysisResult).filter(
                    models.AnalysisResult.email_id == email_id).delete()
                db.query(models.TraceabilityData).filter(
                    models.TraceabilityData.email_id == email_id).delete()
                db.query(models.EmailRecord).filter(
                    models.EmailRecord.id == email_id).delete()
                db.commit()
            finally:
                db.close()
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    try:
        asyncio.run(run())
    finally:
        controller.stop()


def test_smtp_refuses_open_relay_and_plaintext_auth(monkeypatch):
    """P0: non-loopback binds fail fast instead of running insecure."""
    from app.config import get_settings
    from app.modules.ingestion import smtp_server
    from app.modules.ingestion.smtp_server import _is_loopback, start_smtp

    assert _is_loopback("127.0.0.1") and _is_loopback("::1") and _is_loopback("localhost")
    assert _is_loopback("127.0.0.9") and not _is_loopback("0.0.0.0")
    assert not _is_loopback("mail.example.com")  # unknown => non-loopback (fail closed)

    # open relay: non-loopback without auth
    monkeypatch.setattr(get_settings(), "smtp_require_auth", "0")
    try:
        start_smtp("0.0.0.0", 10029)
        raise SystemExit("should have refused open relay")
    except RuntimeError as e:
        assert "open relay" in str(e)
    # plaintext auth: non-loopback + auth but no TLS cert
    monkeypatch.setattr(get_settings(), "smtp_require_auth", "1")
    monkeypatch.setattr(get_settings(), "smtp_tls_cert", "")
    monkeypatch.setattr(get_settings(), "smtp_tls_key", "")
    try:
        start_smtp("0.0.0.0", 10029)
        raise SystemExit("should have refused plaintext auth")
    except RuntimeError as e:
        assert "plaintext" in str(e)


def test_smtp_intake_table_bounded():
    """P0: per-IP intake table cannot grow without bound."""
    from app.modules.ingestion import smtp_server
    from app.modules.ingestion.smtp_server import INTAKE_MAX_IPS, _intake_allowed
    smtp_server._intake_hits.clear()
    for i in range(INTAKE_MAX_IPS + 500):
        assert _intake_allowed(f"10.9.{i // 256}.{i % 256}") is True
    assert len(smtp_server._intake_hits) <= INTAKE_MAX_IPS
    # earliest IPs were evicted LRU-style
    assert "10.9.0.0" not in smtp_server._intake_hits
    # per-IP rate limit still enforced (fresh IP outside the fill range)
    assert all(_intake_allowed("10.9.200.200") for _ in range(30))
    assert _intake_allowed("10.9.200.200") is False
    smtp_server._intake_hits.clear()
