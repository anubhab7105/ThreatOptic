"""Step 2 (C3/C4/tenancy/RBAC/CaseUpdate/refresh-persist/client_id/rate-limit)."""
import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app import models
from app.config import get_settings



def _session():
    """Fresh session from the (possibly test-rebound) sessionmaker."""
    from app.database import SessionLocal
    return SessionLocal()


def _uname(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _register(c: TestClient, username: str, role: str | None = None) -> dict:
    body = {"username": username, "password": "Str0ngPass!"}
    if role:
        body["role"] = role
    r = c.post("/api/v1/auth/register", json=body)
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _make_org_with_user(c: TestClient, role: str = "Analyst") -> tuple[dict, str, str]:
    """Two-step: register, then move user into a fresh org. Returns (headers, user_id, org_id)."""
    uname = _uname("tenant")
    h = _register(c, uname, role=role)
    db = _session()
    try:
        u = db.query(models.User).filter_by(username=uname).first()
        org = models.Organization(name=f"org-{uname}", compliance_policy={})
        db.add(org)
        db.flush()
        u.organization_id = org.id
        db.commit()
        return h, u.id, org.id
    finally:
        db.close()


def test_oauth_state_expiry_and_allowlist(monkeypatch):
    from app.main import app

    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "gid")
    with TestClient(app) as c:
        h = _register(c, _uname("st"), role="Analyst")
        # non-allowlisted redirect rejected
        r = c.post("/api/v1/oauth/google/authorize", headers=h, json={
            "redirect_uri": "https://evil.test/cb", "client_id": "gid"})
        assert r.status_code == 400 and "allowlisted" in r.text
        # unknown state rejected
        r = c.get("/api/v1/oauth/google/callback", params={"code": "x", "state": "bogus-state"})
        assert r.status_code == 400 and "state" in r.text.lower()
        # expired state rejected
        db = _session()
        try:
            u = db.query(models.User).order_by(models.User.created_at.desc()).first()
            db.add(models.OAuthState(state="expired-state-123", user_id=u.id, provider="google",
                                     redirect_uri="http://localhost:5173/", client_id="gid",
                                     code_verifier="v",
                                     expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)))
            db.commit()
        finally:
            db.close()
        r = c.get("/api/v1/oauth/google/callback", params={"code": "x", "state": "expired-state-123"})
        assert r.status_code == 400 and "expired" in r.text.lower()
        db = _session()
        try:
            db.query(models.OAuthState).filter_by(state="expired-state-123").delete()
            db.commit()
        finally:
            db.close()


def test_tenant_isolation_emails_cases_dashboard():
    from app.main import app

    with TestClient(app) as c:
        ha, _a, org_a = _make_org_with_user(c)
        hb, _b, org_b = _make_org_with_user(c)
        marker = f"tenant-{uuid.uuid4().hex[:8]}@example.com"
        eid = c.post("/api/v1/emails/ingest", headers=ha,
                     json={"raw": f"From: {marker}\nTo: x@y.test\nSubject: A secret\n\nbody"}).json()["email_id"]
        cid = c.post("/api/v1/cases", headers=ha, json={"title": "A case"}).json()["id"]

        # B cannot see A's rows (404, not 403 — no existence leak)
        assert c.get(f"/api/v1/emails/{eid}", headers=hb).status_code == 404
        assert c.patch(f"/api/v1/cases/{cid}", headers=hb, json={"notes": "hijack"}).status_code == 404
        ids_b = [e["id"] for e in c.get("/api/v1/emails?limit=200", headers=hb).json()]
        assert eid not in ids_b
        assert all(x["id"] != cid for x in c.get("/api/v1/cases", headers=hb).json())
        dash_b = c.get("/api/v1/dashboard", headers=hb).json()
        assert dash_b["total_emails"] == 0
        # owner + admin can
        assert c.get(f"/api/v1/emails/{eid}", headers=ha).status_code == 200
        db = _session()
        try:
            admin = models.User(username=_uname("root"), password_hash="x", role="Admin", organization_id=org_b)
            db.add(admin)
            db.commit()
            db.refresh(admin)
            admin_id = admin.id
        finally:
            db.close()
        from app.modules.auth.security import create_access_token
        atok = create_access_token(admin_id, "root", "Admin", get_settings().secret_key, 20)
        dh = {"Authorization": f"Bearer {atok}"}
        assert c.get(f"/api/v1/emails/{eid}", headers=dh).status_code == 200
        assert c.get("/api/v1/dashboard", headers=dh).json()["total_emails"] >= 1
        # cleanup
        db = _session()
        try:
            for m, col in ((models.AnalysisResult, "email_id"), (models.TraceabilityData, "email_id")):
                db.query(m).filter(getattr(m, col) == eid).delete()
            db.query(models.EmailRecord).filter_by(id=eid).delete()
            db.query(models.InvestigationCase).filter_by(id=cid).delete()
            db.query(models.User).filter(models.User.username.like("tenant-%")).delete(synchronize_session=False)
            db.query(models.User).filter_by(id=admin_id).delete()
            db.query(models.Organization).filter(models.Organization.id.in_([org_a, org_b])).delete(synchronize_session=False)
            db.commit()
        finally:
            db.close()


def test_readonly_cannot_write():
    from app.main import app

    with TestClient(app) as c:
        h = _register(c, _uname("ro"))  # ReadOnly default
        assert c.get("/api/v1/emails", headers=h).status_code == 200
        assert c.get("/api/v1/dashboard", headers=h).status_code == 200
        assert c.post("/api/v1/emails/ingest", headers=h, json={"raw": "hi"}).status_code == 403
        assert c.post("/api/v1/cases", headers=h, json={"title": "x"}).status_code == 403
        # analyst can
        ha = _register(c, _uname("wr"), role="Analyst")
        assert c.post("/api/v1/cases", headers=ha, json={"title": "ok"}).status_code == 200


def test_case_update_schema():
    from app.main import app

    with TestClient(app) as c:
        h = _register(c, _uname("cu"), role="Analyst")
        cid = c.post("/api/v1/cases", headers=h, json={"title": "t"}).json()["id"]
        # unknown field rejected, bad types rejected
        assert c.patch(f"/api/v1/cases/{cid}", headers=h, json={"hacked": 1}).status_code == 422
        assert c.patch(f"/api/v1/cases/{cid}", headers=h, json={"email_ids": "nope"}).status_code == 422
        assert c.patch(f"/api/v1/cases/{cid}", headers=h, json={"title": "  "}).status_code == 400
        assert c.patch(f"/api/v1/cases/{cid}", headers=h, json={"assignee_id": "missing-id"}).status_code == 400
        r = c.patch(f"/api/v1/cases/{cid}", headers=h, json={"status": "Closed", "notes": "done"})
        assert r.status_code == 200 and r.json()["status"] == "Closed"


def test_provider_refresh_persisted(monkeypatch):
    import app.modules.ingestion.connectors as conn
    from app.modules.auth.vault import encrypt_secret, decrypt_secret
    from app.services import mailbox_poll

    async def _fake_refresh(refresh, cid, sec):
        return {"access_token": "new-access", "refresh_token": "1//rotated", "expires_in": 3600}

    async def _fake_fetch(token, query="newer_than:1d", max_results=25):
        return []

    monkeypatch.setattr(conn, "refresh_gmail_token", _fake_refresh)
    monkeypatch.setattr(conn, "fetch_gmail_messages", _fake_fetch)
    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "gid")
    monkeypatch.setattr(settings, "google_client_secret", "gsec")

    import asyncio
    db = _session()
    try:
        u = models.User(username=_uname("pol"), password_hash="x", role="Analyst")
        db.add(u)
        db.flush()
        conn_row = models.MailboxConnection(user_id=u.id, provider="google", account_email="p@t.test",
                                            encrypted_refresh_token=encrypt_secret("1//old"))
        db.add(conn_row)
        db.commit()
        cid = conn_row.id
        uid = u.id
    finally:
        db.close()
    out = asyncio.run(mailbox_poll.poll_connection_by_id(cid))
    assert out["errors"] == [] and out["synced"] == 0
    db = _session()
    try:
        row = db.query(models.MailboxConnection).filter_by(id=cid).first()
        assert decrypt_secret(row.encrypted_refresh_token) == "1//rotated"
        db.query(models.MailboxConnection).filter_by(id=cid).delete()
        db.query(models.User).filter_by(id=uid).delete()
        db.commit()
    finally:
        db.close()


def test_gmail_client_id_pinned_and_reused(monkeypatch):
    import app.modules.ingestion.connectors as conn
    from app.main import app

    seen = {}

    async def _fake_exchange(code, cid, sec, uri, code_verifier=""):
        return {"access_token": "a", "refresh_token": "1//g", "expires_in": 3600}

    async def _fake_profile(token):
        return "pin@gmail.com"

    async def _fake_refresh(refresh, cid, sec):
        seen["cid"] = cid
        return {"access_token": "b", "expires_in": 3600}

    async def _fake_fetch(token, query="newer_than:1d", max_results=25):
        return []

    monkeypatch.setattr(conn, "exchange_gmail_code", _fake_exchange)
    monkeypatch.setattr(conn, "get_gmail_profile_email", _fake_profile)
    monkeypatch.setattr(conn, "refresh_gmail_token", _fake_refresh)
    monkeypatch.setattr(conn, "fetch_gmail_messages", _fake_fetch)
    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "server-id")
    monkeypatch.setattr(settings, "google_client_secret", "server-sec")

    with TestClient(app) as c:
        h = _register(c, _uname("pin"), role="Analyst")
        # connect with an explicit client_id override (P0: via opaque state)
        au = c.post("/api/v1/gmail/auth-url", headers=h, json={
            "redirect_uri": "http://localhost:5173/", "client_id": "override-id"}).json()["auth_url"]
        from urllib.parse import parse_qs as _pqs, urlparse as _up
        _st = _pqs(_up(au).query)["state"][0]
        r = c.post("/api/v1/gmail/callback", headers=h, json={
            "code": "x", "state": _st, "redirect_uri": "http://localhost:5173/", "client_id": "override-id"})
        assert r.status_code == 200, r.text
        db = _session()
        try:
            u = db.query(models.User).order_by(models.User.created_at.desc()).first()
            acct = db.query(models.GmailAccount).filter_by(user_id=u.id).first()
            assert acct.client_id == "override-id"
            uid = u.id
        finally:
            db.close()
        # server secret changes afterwards: sync still uses the PINNED client_id
        monkeypatch.setattr(settings, "google_client_id", "other-id")
        assert c.post("/api/v1/gmail/sync", headers=h, json={}).status_code == 200
        assert seen.get("cid") == "override-id"
        db = _session()
        try:
            db.query(models.GmailAccount).filter_by(user_id=uid).delete()
            db.query(models.RefreshToken).filter_by(user_id=uid).delete()
            db.query(models.User).filter_by(id=uid).delete()
            db.commit()
        finally:
            db.close()


def test_rate_limit_and_lockout(monkeypatch):
    from app.config import get_settings as gs
    from app.main import app
    from app.modules.auth import rate_limit as rl

    settings = gs()
    monkeypatch.setattr(settings, "rate_limit_enabled", "1")
    rl.limiter.enabled = True
    rl.limiter._storage.reset()
    try:
        with TestClient(app) as c:
            uname = _uname("flood")
            c.post("/api/v1/auth/register", json={"username": uname, "password": "Str0ngPass!"})
            # lockout: 5 wrong -> 401s, 6th -> 429
            codes = [c.post("/api/v1/auth/login",
                            json={"username": uname, "password": "wrong-wrong"}).status_code for _ in range(6)]
            assert codes[:5] == [401] * 5 and codes[5] == 429
            rl.limiter._storage.reset()
            # slowapi: 11 rapid correct logins -> 11th is 429
            uname2 = _uname("steady")
            c.post("/api/v1/auth/register", json={"username": uname2, "password": "Str0ngPass!"})
            ok = [c.post("/api/v1/auth/login",
                         json={"username": uname2, "password": "Str0ngPass!"}).status_code for _ in range(11)]
            assert ok[:10] == [200] * 10 and ok[10] == 429
    finally:
        rl.limiter.enabled = False


def test_audit_log_emitted(caplog):
    import logging
    from app.modules.auth.rate_limit import audit
    with caplog.at_level(logging.INFO, logger="audit"):
        audit("test.event", user="u", detail="d")
    assert any("event=test.event" in r.message and "user=u" in r.message for r in caplog.records)


def test_scheduler_uses_service_layer():
    import pathlib
    p = pathlib.Path("backend/app/services/scheduler.py")
    if not p.exists():
        p = pathlib.Path("app/services/scheduler.py")
    src = p.read_text()
    assert "routers" not in src
    assert "mailbox_poll" in src


def test_case_linkage_validates_email_tenant():
    """P0: linked email IDs must exist in the caller's tenant (404 else)."""
    from app.main import app

    with TestClient(app) as c:
        ha, _a, _org_a = _make_org_with_user(c)
        hb, _b, _org_b = _make_org_with_user(c)
        eid_a = c.post("/api/v1/emails/ingest", headers=ha,
                       json={"raw": "From: a@x.test\nTo: y@y.test\nSubject: A\n\nbody"}).json()["email_id"]
        # cross-tenant link rejected on create and on patch (404, no leak)
        assert c.post("/api/v1/cases", headers=hb,
                      json={"title": "hijack", "email_ids": [eid_a]}).status_code == 404
        cid_b = c.post("/api/v1/cases", headers=hb, json={"title": "ok"}).json()["id"]
        assert c.patch(f"/api/v1/cases/{cid_b}", headers=hb,
                       json={"email_ids": [eid_a]}).status_code == 404
        # unknown IDs rejected the same way
        assert c.post("/api/v1/cases", headers=hb,
                      json={"title": "ghost", "email_ids": ["no-such-id"]}).status_code == 404
        # own mail links fine (deduped, order kept)
        eid_b = c.post("/api/v1/emails/ingest", headers=hb,
                       json={"raw": "From: b@x.test\nTo: y@y.test\nSubject: B\n\nbody"}).json()["email_id"]
        r = c.patch(f"/api/v1/cases/{cid_b}", headers=hb,
                    json={"email_ids": [eid_b, eid_b]})
        assert r.status_code == 200 and r.json()["email_ids"] == [eid_b]
