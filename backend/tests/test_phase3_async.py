"""Phase 3 tests: Celery optional path, shared cache, WebSocket alerts."""
import uuid

from fastapi.testclient import TestClient

from app.config import get_settings


def _auth(c: TestClient, role: str = "Analyst") -> dict:
    uname = f"p3-{uuid.uuid4().hex[:8]}"
    tok = c.post("/api/v1/auth/register",
                 json={"username": uname, "password": "Str0ngPass!", "role": role}).json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}


def test_async_ingest_requires_broker(monkeypatch):
    from app.main import app

    settings = get_settings()
    monkeypatch.setattr(settings, "celery_broker_url", "")
    with TestClient(app) as c:
        h = _auth(c)
        r = c.post("/api/v1/emails/ingest?async_mode=true", headers=h, json={"raw": "hi"})
        assert r.status_code == 400 and "CELERY_BROKER_URL" in r.text
        assert c.get("/api/v1/tasks/abc123", headers=h).status_code == 400


def test_async_ingest_eager_roundtrip(monkeypatch):
    from app.main import app
    from app.services import tasks

    settings = get_settings()
    monkeypatch.setattr(settings, "celery_broker_url", "memory://")
    tasks.celery_app.conf.task_always_eager = True
    try:
        with TestClient(app) as c:
            h = _auth(c)
            r = c.post("/api/v1/emails/ingest?async_mode=true", headers=h, json={
                "raw": "From: a@b.test\nSubject: hi\n\nhello there friend"})
            assert r.status_code == 202, r.text
            tid = r.json()["task_id"]
            st = c.get(f"/api/v1/tasks/{tid}", headers=h).json()
            assert st["state"] == "SUCCESS"
            assert st["result"]["email_id"]
            # queued mail is analyzable like sync mail
            assert c.get(f"/api/v1/emails/{st['result']['email_id']}", headers=h).status_code == 200
            assert c.get("/api/v1/tasks/not-a-task!!", headers=h).status_code == 400
    finally:
        tasks.celery_app.conf.task_always_eager = False


def test_cache_backends_and_dashboard_invalidation(monkeypatch):
    from app.main import app
    from app.modules import cache

    cache.cache_clear()
    cache.cache_set("k", {"a": 1}, ttl=60)
    assert cache.cache_get("k") == {"a": 1}
    assert cache.cache_delete_prefix("k") == 1
    assert cache.cache_get("k") is None
    assert cache.backend_name() in ("redis", "memory")

    with TestClient(app) as c:
        h = _auth(c)
        before = c.get("/api/v1/dashboard", headers=h).json()["total_emails"]
        # second read is served from cache (same value even as scope allows)
        assert c.get("/api/v1/dashboard", headers=h).json()["total_emails"] == before
        c.post("/api/v1/emails/ingest", headers=h,
               json={"raw": "From: a@b.test\nSubject: cache probe\n\nhello"})
        after = c.get("/api/v1/dashboard", headers=h).json()["total_emails"]
        assert after == before + 1  # ingest invalidated the cached scope


def test_cache_geo_and_dns_wrappers(monkeypatch):
    from app.modules import cache
    from app.modules.traceability import geoip, whois_dns

    cache.cache_clear()
    geoip._geolocate_cached.cache_clear()
    g1 = geoip.geolocate("45.148.10.88")
    geoip._geolocate_cached.cache_clear()  # compute path gone, shared cache remains
    assert geoip.geolocate("45.148.10.88") == g1
    whois_dns.dns_lookup("example.com")  # offline shape, cached without crash
    assert whois_dns.dns_lookup("example.com")["domain"] == "example.com"


def test_websocket_push_on_high_risk(monkeypatch):
    from app.main import app
    import app.services.pipeline as pipe

    real_compute = pipe.compute_scores

    def _hot(*a, **k):
        out = real_compute(*a, **k)
        out.update(fraud_score=95.0, classification="High",
                   threat_classification="Phishing-High", action="JunkOrHold")
        return out

    monkeypatch.setattr(pipe, "compute_scores", _hot)
    with TestClient(app) as c:
        h = _auth(c)
        # P0: sockets need a short-lived ticket, not the access token.
        ticket = c.post("/api/v1/ws/ticket", headers=h).json()["ticket"]
        assert c.post("/api/v1/ws/ticket").status_code == 401
        with c.websocket_connect(f"/api/v1/ws/alerts?ticket={ticket}") as ws:
            c.post("/api/v1/emails/ingest", headers=h, json={
                "raw": ("From: \"CEO\" <ceo@xn--paypa1-secure.top>\nTo: f@c.test\n"
                        "Subject: Urgent wire transfer - verify account now\nMessage-ID: <w1@x.top>\n"
                        "Return-Path: <b@evil.test>\n"
                        "Received: from evil.test (evil.test [45.148.10.88]) by mx.c with ESMTPS\n"
                        "Content-Type: text/plain\n\nKindly wire $9000 to the new vendor immediately, "
                        "do not disclose. Verify your account now at http://malicious-example.com/login")})
            msg = ws.receive_json()
            assert msg["event"] == "high-risk-alert"
            assert msg["fraud_score"] >= 75 and msg["email_id"]
        # bad ticket closes; long-lived access tokens are NOT valid tickets
        try:
            with c.websocket_connect("/api/v1/ws/alerts?ticket=junk"):
                raise SystemExit("should have closed")
        except Exception:
            pass
        try:
            with c.websocket_connect(f"/api/v1/ws/alerts?ticket={h['Authorization'].split(' ', 1)[1]}"):
                raise SystemExit("access token must not open a socket")
        except Exception:
            pass


def test_websocket_org_isolation():
    from app.routers.ws import manager
    import asyncio

    received: list = []

    class FakeWS:
        async def accept(self):
            return None

        async def send_json(self, payload):
            received.append(payload)

    async def run():
        a, b = FakeWS(), FakeWS()
        await manager.connect(a, {"org": "org-a", "role": "Analyst", "user": "u1"})
        await manager.connect(b, {"org": "org-b", "role": "Analyst", "user": "u2"})
        try:
            n = await manager.broadcast_alert({"event": "x"}, "org-a")
            assert n == 1 and len(received) == 1
            # dead sockets pruned
            manager.disconnect(a)
            manager.disconnect(b)
            assert manager.count() == 0
        finally:
            manager.disconnect(a)
            manager.disconnect(b)

    asyncio.run(run())
