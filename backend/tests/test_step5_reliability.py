
import uuid

from fastapi.testclient import TestClient
from helpers import login


def _auth(c: TestClient, role: str = "Analyst") -> dict:
    return login(role=role)[0]


def test_cors_star_with_credentials_refuses_boot(monkeypatch):
    from app.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "cors_origins", "*")
    import asyncio
    from app.main import lifespan, app
    with __import__("pytest").raises(RuntimeError, match="CORS_ORIGINS"):
        asyncio.run(lifespan(app).__aenter__())


def test_bearer_scheme_is_bearer():

    from fastapi.testclient import TestClient
    from app.config import get_settings
    from app.main import app

    assert get_settings().api_prefix == "/api/v1"
    with TestClient(app) as c:
        assert c.get("/api/v1/emails", headers={"Authorization": "Basic dXNlcjpwdw=="}).status_code == 401
        assert c.get("/api/v1/emails", params={"token": "anything"}).status_code == 401


def test_smtp_auth_size_and_rcpt(monkeypatch):
    import asyncio
    from email.message import EmailMessage
    import aiosmtplib
    from app.config import get_settings
    from app import models
    from app.database import SessionLocal, init_db
    from app.main import _smtp_consumer
    from app.modules.ingestion.smtp_server import start_smtp

    settings = get_settings()
    monkeypatch.setattr(settings, "smtp_require_auth", "1")
    monkeypatch.setattr(settings, "smtp_username", "relay")
    monkeypatch.setattr(settings, "smtp_password", "s3cret-relay")
    monkeypatch.setattr(settings, "smtp_data_limit_bytes", 50 * 1024)
    init_db()
    from app.modules.ingestion import smtp_server
    smtp_server._intake_hits.clear()
    marker = f"<smtp5-{uuid.uuid4().hex[:8]}@test.local>"
    controller = start_smtp("127.0.0.1", 10026)

    async def run():
        task = asyncio.create_task(_smtp_consumer())
        try:
            msg = EmailMessage()
            msg["From"] = "alice@test.local"
            msg["To"] = "primary@test.local"
            msg["Subject"] = "auth probe"
            msg["Message-ID"] = marker
            msg.set_content("hello")

            try:
                await aiosmtplib.send(msg, hostname="127.0.0.1", port=10026,
                                      sender="alice@test.local", recipients=["bcc@test.local"])
                raise SystemExit("unauthenticated send should have failed")
            except Exception as e:
                assert "535" in str(e) or "auth" in str(e).lower()

            await aiosmtplib.send(msg, hostname="127.0.0.1", port=10026,
                                  username="relay", password="s3cret-relay",
                                  sender="alice@test.local", recipients=["bcc@test.local"])
            row = None
            for _ in range(100):
                db = SessionLocal()
                try:
                    row = db.query(models.EmailRecord).filter(
                        models.EmailRecord.message_id == marker).first()
                    if row:
                        eid = row.id
                        break
                finally:
                    db.close()
                await asyncio.sleep(0.1)
            assert row is not None
            db = SessionLocal()
            try:
                ar = db.query(models.AnalysisResult).filter_by(email_id=eid).first()
                assert ar.trace_summary.get("envelope_rcpt_tos") == ["bcc@test.local"]
                db.query(models.AnalysisResult).filter_by(email_id=eid).delete()
                db.query(models.TraceabilityData).filter_by(email_id=eid).delete()
                db.query(models.EmailRecord).filter_by(id=eid).delete()
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


def test_smtp_oversize_rejected(monkeypatch):
    import asyncio
    from email.message import EmailMessage
    import aiosmtplib
    from app.config import get_settings
    from app.modules.ingestion.smtp_server import start_smtp

    settings = get_settings()
    monkeypatch.setattr(settings, "smtp_require_auth", "0")
    monkeypatch.setattr(settings, "smtp_data_limit_bytes", 200)
    controller = start_smtp("127.0.0.1", 10027)
    try:
        async def run():
            msg = EmailMessage()
            msg["From"] = "a@t.local"
            msg["To"] = "b@t.local"
            msg["Subject"] = "big"
            msg.set_content("x" * 5000)
            try:
                await aiosmtplib.send(msg, hostname="127.0.0.1", port=10027)
                raise SystemExit("oversize send should have failed")
            except Exception as e:
                assert "552" in str(e) or "too large" in str(e).lower() or "message" in str(e).lower()
        asyncio.run(run())
    finally:
        controller.stop()


def test_queue_bounded_and_bytes_safe(monkeypatch):
    import asyncio
    import queue as std_queue
    from app.modules.ingestion import queue as qmod
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "smtp_queue_max", 2)
    while not qmod._mem_queue.empty():
        qmod._mem_queue.get()
    asyncio.run(qmod.enqueue_email({"a": 1}))
    asyncio.run(qmod.enqueue_email({"a": 2}))
    try:
        asyncio.run(qmod.enqueue_email({"a": 3}))
        raise SystemExit("queue should have been full")
    except std_queue.Full:
        pass
    while not qmod._mem_queue.empty():
        qmod._mem_queue.get()

    blob = qmod._json_safe({"raw": b"\x00\x01"})
    assert isinstance(blob, bytes)
    import json
    assert json.loads(blob)["raw"]["__bytes_b64__"] == "AAE="


def test_kafka_producer_singleton(monkeypatch):
    from app.modules.ingestion import queue as qmod
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "kafka_bootstrap", "kafka:9092")
    made = []

    class FakeProducer:
        def __init__(self, *args, **kwargs):
            made.append((args, kwargs))

        async def start(self):
            pass

    import sys
    import types
    fake_mod = types.ModuleType("aiokafka")
    fake_mod.AIOKafkaProducer = FakeProducer
    monkeypatch.setitem(sys.modules, "aiokafka", fake_mod)
    qmod._producer = None
    try:
        assert qmod._get_producer() is qmod._get_producer()
        assert len(made) == 1
        assert made[0][1] == {"bootstrap_servers": "kafka:9092"}
    finally:
        qmod._producer = None


def test_alembic_upgrade_fresh_db(tmp_path):
    import sqlite3
    import os
    from alembic.config import Config
    from alembic import command

    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ini_path = os.path.join(backend_dir, "alembic.ini")
    script_loc = os.path.join(backend_dir, "alembic")

    db = tmp_path / "fresh.db"
    cfg = Config(ini_path)
    cfg.set_main_option("script_location", script_loc)
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db}")



    os.environ["TEST_DATABASE_URL"] = f"sqlite:///{db}"
    from app.config import get_settings
    get_settings.cache_clear()
    try:
        command.upgrade(cfg, "head")
    finally:
        os.environ.pop("TEST_DATABASE_URL", None)
        get_settings.cache_clear()
    tables = {r[0] for r in sqlite3.connect(db).execute("select name from sqlite_master where type='table'")}


    assert {"users", "organizations", "email_records", "mailbox_connections",
            "gmail_accounts", "oauth_states"} <= tables
    assert "alembic_version" in tables


def test_tz_aware_model_defaults():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app import models
    from app.database import Base
    from datetime import timezone
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    db = sessionmaker(bind=eng)()
    try:
        u = models.User(id="tzprobe", email="tzprobe@test.local")
        db.add(u)
        db.flush()
        assert u.created_at.tzinfo is not None
        e = models.EmailRecord()
        db.add(e)
        db.flush()
        assert e.timestamp.tzinfo == timezone.utc
    finally:
        db.close()


def test_pagination_report_metrics_dedup():
    from app.main import app

    with TestClient(app) as c:
        h = _auth(c)
        assert c.get("/api/v1/emails?limit=5&offset=0", headers=h).status_code == 200
        assert c.get("/api/v1/cases?limit=5&offset=0", headers=h).status_code == 200
        assert c.get("/api/v1/emails?limit=0", headers=h).status_code == 422

        assert c.get("/api/v1/reports/..%2F..%2Fetc.pdf", headers=h).status_code in (400, 404)

        assert c.get("/api/v1/reports/00000000-0000-0000-0000-000000000000.pdf", headers=h).status_code == 404

        raw = f"From: dup-{uuid.uuid4().hex[:6]}@t.test\nSubject: dup\n\nsame body"
        e1 = c.post("/api/v1/emails/ingest", headers=h, json={"raw": raw}).json()["email_id"]
        e2 = c.post("/api/v1/emails/ingest", headers=h, json={"raw": raw}).json()["email_id"]
        assert e1 == e2


def test_metrics_corrupt_file(tmp_path):
    from fastapi import HTTPException
    import app.routers.api as api_mod

    bad = tmp_path / "metrics.json"
    bad.write_text("{not valid json")
    try:
        api_mod._load_model_metrics(metrics_path=str(bad), model_path=str(tmp_path / "nope.joblib"))
        raise SystemExit("corrupt metrics should raise")
    except HTTPException as e:
        assert e.status_code == 500 and e.detail == "model metrics unavailable"
    try:
        api_mod._load_model_metrics(metrics_path=str(tmp_path / "missing.json"))
        raise SystemExit("missing metrics should raise")
    except HTTPException as e:
        assert e.status_code == 404


def test_queue_byte_budget_and_accounting(monkeypatch):

    import asyncio
    import queue as std_queue
    from app.modules.ingestion import queue as qmod
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "smtp_queue_max", 1000)
    monkeypatch.setattr(get_settings(), "smtp_queue_max_bytes", 3000)
    monkeypatch.setattr(get_settings(), "kafka_bootstrap", "")
    while not qmod._mem_queue.empty():
        qmod._mem_queue.get()
    qmod._mem_bytes = 0
    qmod._inflight = 0
    try:
        asyncio.run(qmod.enqueue_email({"raw": b"x" * 500}))
        assert qmod.queue_bytes() > 0

        try:
            asyncio.run(qmod.enqueue_email({"raw": b"y" * 2000}))
            raise SystemExit("byte budget should have rejected")
        except std_queue.Full:
            pass

        assert qmod.queue_inflight() == 0
        payload = asyncio.run(qmod.dequeue_email())
        assert payload["raw"] == b"x" * 500
        assert qmod.queue_inflight() == 1
        assert qmod.queue_bytes() == 0
        qmod.ack_email()
        assert qmod.queue_inflight() == 0
        asyncio.run(qmod.enqueue_email({"raw": b"z" * 1000}))
        assert qmod.queue_depth() == 1
    finally:
        while not qmod._mem_queue.empty():
            qmod._mem_queue.get()
        qmod._mem_bytes = 0
        qmod._inflight = 0


def test_kafka_mirror_never_blackholes_and_starts_once(monkeypatch):

    import asyncio
    import sys
    import types
    from app.modules.ingestion import queue as qmod
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "kafka_bootstrap", "kafka:9092")
    monkeypatch.setattr(get_settings(), "smtp_queue_max_bytes", 10 * 1024 * 1024)
    starts, sends = [], []

    class FakeProducer:
        async def start(self):
            starts.append(1)

        async def send_and_wait(self, topic, payload):
            sends.append((topic, payload))
            return True

        async def stop(self):
            pass

    fake_mod = types.ModuleType("aiokafka")
    fake_mod.AIOKafkaProducer = lambda **kw: FakeProducer()
    monkeypatch.setitem(sys.modules, "aiokafka", fake_mod)
    while not qmod._mem_queue.empty():
        qmod._mem_queue.get()
    qmod._mem_bytes = 0
    qmod._inflight = 0
    qmod._producer = None
    qmod._producer_started = False
    try:
        asyncio.run(qmod.enqueue_email({"raw": b"one"}))
        asyncio.run(qmod.enqueue_email({"raw": b"two"}))
        assert len(starts) == 1
        assert len(sends) == 2

        assert qmod.queue_depth() == 2
        first = asyncio.run(qmod.dequeue_email())
        assert first["raw"] == b"one"
        qmod.ack_email()
    finally:
        while not qmod._mem_queue.empty():
            qmod._mem_queue.get()
        qmod._mem_bytes = 0
        qmod._inflight = 0
        qmod._producer = None
        qmod._producer_started = False
