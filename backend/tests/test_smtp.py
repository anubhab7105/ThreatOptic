"""SMTP ingestion end-to-end (F3): raw message via aiosmtplib -> EmailRecord row."""
import asyncio
import uuid
from email.message import EmailMessage

SMTP_TEST_PORT = 10025


def test_smtp_ingest_creates_record():
    import aiosmtplib
    from app import models
    from app.database import SessionLocal, init_db
    from app.main import _smtp_consumer
    from app.modules.ingestion.smtp_server import start_smtp

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
