"""Mailbox OAuth tests (F7): vault, authorize, callback, sync-now, poller."""
import uuid

from fastapi.testclient import TestClient

RAW = b"""From: a@b.test
To: me@company.com
Subject: OAuth probe
Message-ID: <oauth-probe@test>
Content-Type: text/plain

Quarterly report draft ready for review.
"""


def _auth(c: TestClient) -> dict:
    uname = f"oauth-{uuid.uuid4().hex[:8]}"
    tok = c.post("/api/v1/auth/register", json={"username": uname, "password": "Str0ngPass!"}).json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}


def test_vault_roundtrip():
    from app.modules.auth.vault import decrypt_secret, encrypt_secret
    enc = encrypt_secret("1//refresh-token")
    assert enc != "1//refresh-token"
    assert decrypt_secret(enc) == "1//refresh-token"


def test_authorize_urls():
    from app.main import app

    with TestClient(app) as c:
        h = _auth(c)
        assert c.get("/api/v1/oauth/google/authorize", headers=h).status_code == 422  # redirect_uri required
        r = c.get("/api/v1/oauth/google/authorize", headers=h,
                  params={"redirect_uri": "http://localhost:5173/", "client_id": "gid"})
        assert r.status_code == 200, r.text
        assert "accounts.google.com" in r.json()["auth_url"]
        r = c.get("/api/v1/oauth/microsoft/authorize", headers=h,
                  params={"redirect_uri": "http://localhost:5173/", "client_id": "mid"})
        assert r.status_code == 200, r.text
        assert "login.microsoftonline.com" in r.json()["auth_url"]
        assert c.get("/api/v1/oauth/yahoo/authorize", headers=h).status_code in (400, 422)
        assert c.get("/api/v1/oauth/status").status_code == 401


async def _fake_g_exchange(code, cid, sec, uri):
    return {"access_token": "ya29.x", "refresh_token": "1//r-token", "expires_in": 3600}


async def _fake_g_profile(token):
    return "owner@gmail.com"


async def _fake_g_refresh(refresh, cid, sec):
    assert refresh == "1//r-token"
    return {"access_token": "ya29.fresh", "expires_in": 3600}


async def _fake_g_fetch(token, query="newer_than:1d", max_results=25):
    return [{"id": "m1", "raw": RAW}]


def test_callback_sync_disconnect(monkeypatch):
    from app.main import app
    from app.config import get_settings
    import app.modules.ingestion.connectors as conn
    from app.modules.auth.vault import decrypt_secret
    from app import models
    from app.database import SessionLocal

    monkeypatch.setattr(conn, "exchange_gmail_code", _fake_g_exchange)
    monkeypatch.setattr(conn, "get_gmail_profile_email", _fake_g_profile)
    monkeypatch.setattr(conn, "refresh_gmail_token", _fake_g_refresh)
    monkeypatch.setattr(conn, "fetch_gmail_messages", _fake_g_fetch)
    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "gid")
    monkeypatch.setattr(settings, "google_client_secret", "gsec")

    with TestClient(app) as c:
        h = _auth(c)
        # disconnect requires Analyst+: promote the freshly registered (ReadOnly) user
        dbp = SessionLocal()
        try:
            tok_user = dbp.query(models.User).order_by(models.User.created_at.desc()).first()
            tok_user.role = "Analyst"
            dbp.commit()
        finally:
            dbp.close()
        # hermetic: drop any leftover fixture row from interrupted runs
        db0 = SessionLocal()
        try:
            db0.query(models.MailboxConnection).filter_by(account_email="owner@gmail.com").delete()
            db0.commit()
        finally:
            db0.close()
        try:
            assert c.get("/api/v1/oauth/status", headers=h).json() == []
            r = c.get("/api/v1/oauth/google/callback", params={"code": "4/x", "redirect_uri": "http://localhost:5173/"}, follow_redirects=False)
            assert r.status_code == 302, r.text
            assert "/#/mailboxes?connected=" in r.headers["location"]

            db = SessionLocal()
            try:
                row = db.query(models.MailboxConnection).filter_by(account_email="owner@gmail.com").first()
                assert row is not None and decrypt_secret(row.encrypted_refresh_token) == "1//r-token"
                assert "1//r-token" not in row.encrypted_refresh_token
            finally:
                db.close()

            st = c.get("/api/v1/oauth/status", headers=h).json()
            assert len(st) == 1 and st[0]["account_email"] == "owner@gmail.com"

            r = c.post("/api/v1/oauth/sync-now", headers=h, json={"provider": "google", "max_results": 5})
            assert r.status_code == 200, r.text
            assert r.json()["synced"] == 1

            db = SessionLocal()
            try:
                mail = db.query(models.EmailRecord).filter_by(message_id="<oauth-probe@test>").first()
                assert mail is not None
                eid = mail.id
                db.query(models.AnalysisResult).filter_by(email_id=eid).delete()
                db.query(models.TraceabilityData).filter_by(email_id=eid).delete()
                db.query(models.EmailRecord).filter_by(id=eid).delete()
                db.commit()
            finally:
                db.close()

            assert c.delete("/api/v1/oauth/google", headers=h).status_code == 200
            assert c.get("/api/v1/oauth/status", headers=h).json() == []
            assert c.post("/api/v1/oauth/sync-now", headers=h, json={}).status_code == 404
        finally:
            # never leak the fixture row (disconnect deletes by provider only)
            dbf = SessionLocal()
            try:
                dbf.query(models.MailboxConnection).filter_by(account_email="owner@gmail.com").delete()
                dbf.commit()
            finally:
                dbf.close()
