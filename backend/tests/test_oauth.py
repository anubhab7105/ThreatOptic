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
        assert c.post("/api/v1/oauth/google/authorize", headers=h, json={}).status_code == 422  # redirect_uri required
        r = c.post("/api/v1/oauth/google/authorize", headers=h,
                   json={"redirect_uri": "http://localhost:5173/", "client_id": "gid"})
        assert r.status_code == 200, r.text
        assert "accounts.google.com" in r.json()["auth_url"]
        r = c.post("/api/v1/oauth/microsoft/authorize", headers=h,
                   json={"redirect_uri": "http://localhost:5173/", "client_id": "mid"})
        assert r.status_code == 200, r.text
        assert "login.microsoftonline.com" in r.json()["auth_url"]
        assert c.post("/api/v1/oauth/yahoo/authorize", headers=h, json={"redirect_uri": "http://localhost:5173/"}).status_code in (400, 422)
        assert c.get("/api/v1/oauth/status").status_code == 401


def test_authorize_rejects_query_param_secrets():
    """P0: authorize/auth-url accept secrets in POST body only — GET with
    query params must not exist (405), so secrets never land in URLs/logs."""
    from app.main import app

    with TestClient(app) as c:
        h = _auth(c)
        # GET authorize route removed: query-string secrets impossible
        assert c.get("/api/v1/oauth/google/authorize",
                     headers=h,
                     params={"redirect_uri": "http://localhost:5173/", "client_id": "gid",
                             "client_secret": "topsecret"}).status_code == 405
        # GET gmail auth-url route removed as well
        assert c.get("/api/v1/gmail/auth-url",
                     headers=h,
                     params={"redirect_uri": "http://localhost:5173/", "client_id": "gid",
                             "client_secret": "topsecret"}).status_code == 405


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
            au = c.post("/api/v1/oauth/google/authorize", headers=h, json={
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
        victim_au = c.post("/api/v1/oauth/google/authorize", headers=victim_h, json={
            "redirect_uri": "http://localhost:5173/", "client_id": "gid"}).json()["auth_url"]
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(victim_au).query)
        victim_state = q["state"][0]

        # P0: state is opaque — no embedded payload, no dot-separated blob.
        assert "." not in victim_state

        # Resolve the state owner server-side (browser never sees user_id).
        db0 = SessionLocal()
        try:
            row = db0.query(models.OAuthState).filter_by(state=victim_state).first()
            assert row is not None
            victim_user_id = row.user_id
        finally:
            db0.close()

        # Attacker tries to use victim's state with their own session
        # The mailbox should be attached to the VICTIM (state's user_id), not the attacker
        attacker_h = _auth(c)
        r = c.get("/api/v1/oauth/google/callback",
                  params={"code": "4/x", "state": victim_state}, follow_redirects=False)
        # Callback succeeds but mailbox is attached to victim (state's user_id)
        assert r.status_code == 302, f"Expected 302, got {r.status_code}: {r.text}"

        # Verify mailbox is attached to victim, not attacker
        from app.database import SessionLocal
        from app import models
        db = SessionLocal()
        try:
            conn = db.query(models.MailboxConnection).filter_by(account_email="owner@gmail.com").first()
            assert conn is not None, "Mailbox should be created"
            assert conn.user_id == victim_user_id, "Mailbox should be attached to victim (state's user_id)"
            db.query(models.MailboxConnection).filter_by(account_email="owner@gmail.com").delete()
            db.query(models.OAuthState).filter_by(state=victim_state).delete()
            db.commit()
        finally:
            db.close()


def test_opaque_state_carries_no_secrets(monkeypatch):
    """P0: authorize state is an opaque token — no secrets/PKCE/data inside."""
    from app.main import app
    from app.config import get_settings
    import app.modules.ingestion.connectors as conn
    from app import models
    from app.database import SessionLocal

    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "gid")
    monkeypatch.setattr(settings, "google_client_secret", "gsec")

    with TestClient(app) as c:
        h = _auth(c)
        au = c.post("/api/v1/oauth/google/authorize", headers=h, json={
            "redirect_uri": "http://localhost:5173/", "client_id": "gid"}).json()["auth_url"]
        from urllib.parse import parse_qs, urlparse
        import base64
        q = parse_qs(urlparse(au).query)
        state = q["state"][0]
        # Opaque: single token, no dot-separated signed blob to decode.
        assert "." not in state
        assert "csec" not in state and "pkv" not in state and "gsec" not in state
        try:
            base64.urlsafe_b64decode(state + "=" * (-len(state) % 4))
            decodes = True
        except Exception:
            decodes = False
        if decodes:
            raw = base64.urlsafe_b64decode(state + "=" * (-len(state) % 4)).decode("utf8", "ignore")
            assert "gsec" not in raw and "pkv" not in raw
        # Server holds the verifier + owner; browser got only the token.
        db = SessionLocal()
        try:
            row = db.query(models.OAuthState).filter_by(state=state).first()
            assert row is not None and row.code_verifier and row.user_id
            assert row.used is False
            db.query(models.OAuthState).filter_by(state=state).delete()
            db.commit()
        finally:
            db.close()


def test_cross_tenant_mailbox_access(monkeypatch):
    """Users cannot access mailboxes from other tenants."""
    from app.main import app
    from app.config import get_settings
    import app.modules.ingestion.connectors as conn
    from app import models
    from app.database import SessionLocal
    from urllib.parse import parse_qs, urlparse

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
        au1 = c.post("/api/v1/oauth/google/authorize", headers=h1, json={
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
        assert r.status_code == 403  # Forbidden - cannot access other tenant's mailbox

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

        # Invalid state (unknown opaque token)
        r = c.get("/api/v1/oauth/google/callback", params={"code": "4/x", "state": "bogus-opaque-state-token"})
        assert r.status_code == 400

        # Expired state (server-side row past expiry)
        from datetime import datetime, timedelta, timezone
        from app import models as _models
        from app.database import SessionLocal as _SessionLocal
        db = _SessionLocal()
        try:
            u = db.query(_models.User).order_by(_models.User.created_at.desc()).first()
            db.add(_models.OAuthState(state="expired-opaque-state", user_id=u.id, provider="google",
                                      redirect_uri="http://localhost:5173/", client_id="gid",
                                      code_verifier="v",
                                      expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)))
            db.commit()
        finally:
            db.close()
        r = c.get("/api/v1/oauth/google/callback", params={"code": "4/x", "state": "expired-opaque-state"})
        assert r.status_code == 400
        assert "expired" in r.text.lower()
        db = _SessionLocal()
        try:
            db.query(_models.OAuthState).filter_by(state="expired-opaque-state").delete()
            db.commit()
        finally:
            db.close()


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
        au = c.post("/api/v1/oauth/google/authorize", headers=h, json={
            "redirect_uri": "http://localhost:5173/", "client_id": "gid"}).json()["auth_url"]
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(au).query)
        state = q["state"][0]

        # Try callback with different redirect_uri
        r = c.get("/api/v1/oauth/google/callback",
                  params={"code": "4/x", "state": state, "redirect_uri": "https://evil.com/cb"})
        assert r.status_code == 400
        assert "mismatch" in r.text.lower()


def test_credential_fallback_never_crosses_tenant(monkeypatch):
    """P0: credential resolvers must not borrow another tenant's stored
    client_id/secret. Same-org members may share; outsiders fail closed."""
    from app.main import app
    from app.config import get_settings
    from app import models
    from app.database import SessionLocal
    from app.modules.auth.vault import encrypt_secret

    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "")
    monkeypatch.setattr(settings, "google_client_secret", "")

    with TestClient(app) as c:
        # Victim org A with a stored connection (client_id victim-cid)
        hv = _auth(c)
        db = SessionLocal()
        try:
            v = db.query(models.User).order_by(models.User.created_at.desc()).first()
            org_a = models.Organization(name=f"victim-org-{v.username}", compliance_policy={})
            db.add(org_a)
            db.flush()
            v.organization_id = org_a.id
            org_a_id = org_a.id
            db.add(models.MailboxConnection(
                user_id=v.id, organization_id=org_a_id, provider="google",
                account_email="victim@gmail.com",
                encrypted_refresh_token=encrypt_secret("1//victim"),
                encrypted_client_id=encrypt_secret("victim-cid"),
                encrypted_client_secret=encrypt_secret("victim-sec")))
            db.commit()
        finally:
            db.close()

        # Attacker in org B, no credentials anywhere -> fail closed (400),
        # must NOT silently use victim-cid.
        ha = _auth(c)
        db = SessionLocal()
        try:
            a = db.query(models.User).order_by(models.User.created_at.desc()).first()
            org_b = models.Organization(name=f"attacker-org-{a.username}", compliance_policy={})
            db.add(org_b)
            db.flush()
            a.organization_id = org_b.id
            db.commit()
        finally:
            db.close()
        r = c.post("/api/v1/oauth/google/authorize", headers=ha, json={
            "redirect_uri": "http://localhost:5173/"})
        assert r.status_code == 400, r.text
        assert "victim-cid" not in r.text

        # Same-org member with no explicit credentials MAY reuse org conn.
        hm = _auth(c)
        db = SessionLocal()
        try:
            m = db.query(models.User).order_by(models.User.created_at.desc()).first()
            m.organization_id = org_a_id
            db.commit()
        finally:
            db.close()
        r = c.post("/api/v1/oauth/google/authorize", headers=hm, json={
            "redirect_uri": "http://localhost:5173/"})
        assert r.status_code == 200, r.text
        assert "victim-cid" in r.json()["auth_url"]

        # Cleanup: drop fixture rows + orgs.
        db = SessionLocal()
        try:
            db.query(models.MailboxConnection).filter_by(account_email="victim@gmail.com").delete()
            db.query(models.OAuthState).delete()
            db.commit()
        finally:
            db.close()
