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


async def _fake_g_exchange(code, cid, sec, uri, code_verifier=""):
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
            # full flow: authorize mints server-side state + PKCE, callback consumes it
            au = c.get("/api/v1/oauth/google/authorize", headers=h, params={
                "redirect_uri": "http://localhost:5173/", "client_id": "gid"}).json()["auth_url"]
            from urllib.parse import parse_qs, urlparse
            q = parse_qs(urlparse(au).query)
            assert "state" in q and "code_challenge" in q and q["code_challenge_method"] == ["S256"]
            r = c.get("/api/v1/oauth/google/callback",
                      params={"code": "4/x", "state": q["state"][0]}, follow_redirects=False)
            assert r.status_code == 302, r.text
            assert "/mailboxes?connected=" in r.headers["location"]
            # state is single-use: replay fails
            r2 = c.get("/api/v1/oauth/google/callback",
                       params={"code": "4/x", "state": q["state"][0]}, follow_redirects=False)
            assert r2.status_code == 400

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


def test_oauth_hijack_prevention(monkeypatch):
    """Attacker cannot hijack victim's OAuth flow by replaying state."""
    from app.main import app
    from app.config import get_settings
    import app.modules.ingestion.connectors as conn
    from app import models
    from app.database import SessionLocal

    monkeypatch.setattr(conn, "exchange_gmail_code", _fake_g_exchange)
    monkeypatch.setattr(conn, "get_gmail_profile_email", _fake_g_profile)
    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "gid")
    monkeypatch.setattr(settings, "google_client_secret", "gsec")

    with TestClient(app) as c:
        # Victim starts OAuth flow
        victim_h = _auth(c)
        victim_au = c.get("/api/v1/oauth/google/authorize", headers=victim_h, params={
            "redirect_uri": "http://localhost:5173/", "client_id": "gid"}).json()["auth_url"]
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(victim_au).query)
        victim_state = q["state"][0]

        # Attacker tries to use victim's state with their own session
        attacker_h = _auth(c)
        r = c.get("/api/v1/oauth/google/callback",
                  params={"code": "4/x", "state": victim_state}, follow_redirects=False)
        # Should fail because state is bound to victim's user_id
        assert r.status_code == 400, f"Expected 400 for hijack attempt, got {r.status_code}: {r.text}"


def test_cross_tenant_mailbox_access(monkeypatch):
    """Users cannot access mailboxes from other tenants."""
    from app.main import app
    from app.config import get_settings
    import app.modules.ingestion.connectors as conn
    from app import models
    from app.database import SessionLocal

    monkeypatch.setattr(conn, "exchange_gmail_code", _fake_g_exchange)
    monkeypatch.setattr(conn, "get_gmail_profile_email", _fake_g_profile)
    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "gid")
    monkeypatch.setattr(settings, "google_client_secret", "gsec")

    with TestClient(app) as c:
        # Create two users in different orgs
        h1 = _auth(c)
        db = SessionLocal()
        try:
            u1 = db.query(models.User).order_by(models.User.created_at.desc()).first()
            org1 = models.Organization(name=f"org-{u1.username}", compliance_policy={})
            db.add(org1)
            db.flush()
            u1.organization_id = org1.id
            db.commit()
            org1_id = org1.id
        finally:
            db.close()

        h2 = _auth(c)
        db = SessionLocal()
        try:
            u2 = db.query(models.User).order_by(models.User.created_at.desc()).first()
            org2 = models.Organization(name=f"org-{u2.username}", compliance_policy={})
            db.add(org2)
            db.flush()
            u2.organization_id = org2.id
            db.commit()
        finally:
            db.close()

        # User 1 connects a mailbox
        au1 = c.get("/api/v1/oauth/google/authorize", headers=h1, params={
            "redirect_uri": "http://localhost:5173/", "client_id": "gid"}).json()["auth_url"]
        q1 = parse_qs(urlparse(au1).query)
        state1 = q1["state"][0]
        r = c.get("/api/v1/oauth/google/callback",
                  params={"code": "4/x", "state": state1}, follow_redirects=False)
        assert r.status_code == 302

        # User 2 should NOT see user 1's mailbox in status
        st2 = c.get("/api/v1/oauth/status", headers=h2).json()
        assert len(st2) == 0, "User 2 should not see User 1's mailbox"

        # User 2 should NOT be able to disconnect user 1's mailbox
        r = c.delete("/api/v1/oauth/google", headers=h2)
        assert r.status_code == 200  # Returns 200 but removes 0
        assert r.json()["removed"] == 0

        # User 2 sync-now should return 404 (no mailbox)
        r = c.post("/api/v1/oauth/sync-now", headers=h2, json={"provider": "google", "max_results": 5})
        assert r.status_code == 404


def test_invalid_missing_state(monkeypatch):
    """Invalid or missing state parameters are rejected."""
    from app.main import app
    from app.config import get_settings
    import app.modules.ingestion.connectors as conn

    monkeypatch.setattr(conn, "exchange_gmail_code", _fake_g_exchange)
    monkeypatch.setattr(conn, "get_gmail_profile_email", _fake_g_profile)
    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "gid")
    monkeypatch.setattr(settings, "google_client_secret", "gsec")

    with TestClient(app) as c:
        h = _auth(c)
        # Missing state
        r = c.get("/api/v1/oauth/google/callback", params={"code": "4/x"})
        assert r.status_code == 400
        assert "state" in r.text.lower()

        # Invalid state (malformed)
        r = c.get("/api/v1/oauth/google/callback", params={"code": "4/x", "state": "not.valid.state"})
        assert r.status_code == 400

        # Expired state (old timestamp)
        import base64, json, hmac, hashlib, time
        payload = {"sub": "fake-user", "t": int(time.time()) - 2000, "flow": "oauth", "pkv": "verifier"}
        msg = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        sig = hmac.new(settings.secret_key.encode(), msg.encode(), hashlib.sha256).hexdigest()
        expired_state = f"{msg}.{sig}"
        r = c.get("/api/v1/oauth/google/callback", params={"code": "4/x", "state": expired_state})
        assert r.status_code == 400
        assert "expired" in r.text.lower()


def test_tampered_redirect_uri(monkeypatch):
    """Tampered redirect_uri is rejected."""
    from app.main import app
    from app.config import get_settings
    import app.modules.ingestion.connectors as conn

    monkeypatch.setattr(conn, "exchange_gmail_code", _fake_g_exchange)
    monkeypatch.setattr(conn, "get_gmail_profile_email", _fake_g_profile)
    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "gid")
    monkeypatch.setattr(settings, "google_client_secret", "gsec")

    with TestClient(app) as c:
        h = _auth(c)
        # Start flow with allowed redirect_uri
        au = c.get("/api/v1/oauth/google/authorize", headers=h, params={
            "redirect_uri": "http://localhost:5173/", "client_id": "gid"}).json()["auth_url"]
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(au).query)
        state = q["state"][0]

        # Try callback with different redirect_uri
        r = c.get("/api/v1/oauth/google/callback",
                  params={"code": "4/x", "state": state, "redirect_uri": "https://evil.com/cb"})
        assert r.status_code == 400
        assert "mismatch" in r.text.lower()
