
import uuid

from fastapi.testclient import TestClient
from helpers import login

RAW = b"""From: "CFO" <cfo@xn--companny.top>
To: me@gmail.com
Subject: Urgent wire transfer
Message-ID: <g1@xn--companny.top>
Return-Path: <x@evil.test>
Received: from evil.test (evil.test [45.148.10.88]) by mx.google.com with ESMTPS id g
Content-Type: text/plain

Kindly wire $9000 immediately, do not disclose. Pay at http://malicious-example.com/pay
"""


def _auth(c: TestClient) -> tuple[dict, str]:
    h, user = login(email=f"gmail-{uuid.uuid4().hex[:8]}@test.local")
    return h, user.email


async def _fake_exchange(code, client_id, client_secret, redirect_uri, code_verifier=""):
    assert code and client_id and client_secret and redirect_uri
    return {"access_token": "ya29.fake", "refresh_token": "1//fake-refresh", "expires_in": 3600}


async def _fake_profile(access_token):
    assert access_token == "ya29.fake"
    return "demo@gmail.com"


async def _fake_refresh(refresh_token, client_id, client_secret):
    assert refresh_token == "1//fake-refresh"
    return {"access_token": "ya29.fresh", "expires_in": 3600}


async def _fake_fetch(access_token, query="newer_than:1d", max_results=25):
    assert access_token == "ya29.fresh"
    return [{"id": "msg1", "raw": RAW}]


def test_gmail_unauth_and_auth_url_validation():
    from app.main import app

    with TestClient(app) as c:
        assert c.get("/api/v1/gmail/status").status_code == 401
        h, _ = _auth(c)

        r = c.post("/api/v1/gmail/auth-url", headers=h, json={"redirect_uri": "http://localhost:5173/"})
        assert r.status_code == 400
        r = c.post("/api/v1/gmail/auth-url", headers=h,
                   json={"client_id": "demo-id.apps.googleusercontent.com", "redirect_uri": "http://localhost:5173/"})
        assert r.status_code == 200, r.text
        url = r.json()["auth_url"]
        assert "accounts.google.com" in url and "gmail.readonly" in url and "demo-id" in url


def test_gmail_auth_url_redirect_allowlisted(monkeypatch):

    from app.main import app
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "demo-id")

    with TestClient(app) as c:
        h, _ = _auth(c)
        r = c.post("/api/v1/gmail/auth-url", headers=h, json={
            "redirect_uri": "https://evil.test/cb", "client_id": "demo-id"})
        assert r.status_code == 400, r.text
        assert "allowlisted" in r.text


def test_gmail_callback_requires_state(monkeypatch):

    from app.main import app
    from app.config import get_settings
    import app.modules.ingestion.connectors as conn

    monkeypatch.setattr(conn, "exchange_gmail_code", _fake_exchange)
    monkeypatch.setattr(conn, "get_gmail_profile_email", _fake_profile)
    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "demo-id")
    monkeypatch.setattr(settings, "google_client_secret", "demo-secret")

    with TestClient(app) as c:
        h, _ = _auth(c)

        r = c.post("/api/v1/gmail/callback", headers=h, json={"code": "4/fake"})
        assert r.status_code == 422

        r = c.post("/api/v1/gmail/callback", headers=h, json={
            "code": "4/fake", "state": "bogus-opaque-state"})
        assert r.status_code == 400

        h2, _ = _auth(c)
        au = c.post("/api/v1/gmail/auth-url", headers=h2, json={
            "redirect_uri": "http://localhost:5173/", "client_id": "demo-id"}).json()["auth_url"]
        from urllib.parse import parse_qs, urlparse
        st = parse_qs(urlparse(au).query)["state"][0]
        r = c.post("/api/v1/gmail/callback", headers=h, json={
            "code": "4/fake", "state": st})
        assert r.status_code == 400


def test_gmail_connect_sync_disconnect(monkeypatch):
    from app.main import app
    from app.config import get_settings
    import app.modules.ingestion.connectors as conn

    monkeypatch.setattr(conn, "exchange_gmail_code", _fake_exchange)
    monkeypatch.setattr(conn, "get_gmail_profile_email", _fake_profile)
    monkeypatch.setattr(conn, "refresh_gmail_token", _fake_refresh)
    monkeypatch.setattr(conn, "fetch_gmail_messages", _fake_fetch)

    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "demo-id")
    monkeypatch.setattr(settings, "google_client_secret", "demo-secret")

    with TestClient(app) as c:
        h, _ = _auth(c)
        assert c.get("/api/v1/gmail/status", headers=h).json()["connected"] is False

        assert c.post("/api/v1/gmail/sync", headers=h, json={}).status_code == 404


        au = c.post("/api/v1/gmail/auth-url", headers=h, json={
            "redirect_uri": "http://localhost:5173/", "client_id": "demo-id"}).json()["auth_url"]
        from urllib.parse import parse_qs, urlparse
        st = parse_qs(urlparse(au).query)["state"][0]
        r = c.post("/api/v1/gmail/callback", headers=h, json={
            "code": "4/fake", "state": st, "redirect_uri": "http://localhost:5173/",
            "client_id": "demo-id",
        })
        assert r.status_code == 200, r.text
        assert r.json()["connected"] is True and r.json()["gmail_address"] == "demo@gmail.com"

        r = c.post("/api/v1/gmail/sync", headers=h, json={"max_results": 5})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["synced"] == 1 and len(body["email_ids"]) == 1 and body["errors"] == []


        eid = body["email_ids"][0]
        d = c.get(f"/api/v1/emails/{eid}", headers=h)
        assert d.status_code == 200 and d.json()["analysis"]["fraud_score"] >= 50

        assert c.delete("/api/v1/gmail/disconnect", headers=h).status_code == 200
        assert c.get("/api/v1/gmail/status", headers=h).json()["connected"] is False

        from app import models as _models
        from app.database import SessionLocal as _SessionLocal
        db = _SessionLocal()
        try:
            assert db.query(_models.GmailAccount).filter_by(gmail_address="demo@gmail.com").first() is None
            assert db.query(_models.MailboxConnection).filter_by(account_email="demo@gmail.com").first() is None
        finally:
            db.close()
        assert c.get("/api/v1/oauth/status", headers=h).json() == []
        assert c.post("/api/v1/oauth/sync-now", headers=h, json={}).status_code == 404


def test_gmail_sync_persists_client_id_for_future_refreshes(monkeypatch):
    from app.main import app
    from app.config import get_settings
    import app.modules.ingestion.connectors as conn
    from app import models
    from app.database import SessionLocal
    from app.modules.auth.vault import encrypt_secret

    monkeypatch.setattr(conn, "exchange_gmail_code", _fake_exchange)
    monkeypatch.setattr(conn, "get_gmail_profile_email", _fake_profile)
    monkeypatch.setattr(conn, "refresh_gmail_token", _fake_refresh)
    monkeypatch.setattr(conn, "fetch_gmail_messages", _fake_fetch)
    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "")
    monkeypatch.setattr(settings, "google_client_secret", "demo-secret")

    with TestClient(app) as c:
        h, _ = _auth(c)
        db = SessionLocal()
        try:
            user = db.query(models.User).order_by(models.User.created_at.desc()).first()
            db.add(models.GmailAccount(
                user_id=user.id,
                gmail_address="demo@gmail.com",
                refresh_token=encrypt_secret("1//fake-refresh"),
                client_id="",
                encrypted_client_id="",
                encrypted_client_secret="",
            ))
            db.commit()
        finally:
            db.close()

        r = c.post("/api/v1/gmail/sync", headers=h, json={"query": "is:unread", "max_results": 1, "client_id": "demo-id"})
        assert r.status_code == 200, r.text

        db = SessionLocal()
        try:
            acct = db.query(models.GmailAccount).filter_by(gmail_address="demo@gmail.com").first()
            assert acct is not None
            assert acct.client_id == "demo-id"
        finally:
            db.close()


def test_gmail_cross_user_hijack_blocked(monkeypatch):

    from app.main import app
    from app.config import get_settings
    import app.modules.ingestion.connectors as conn
    from app import models
    from app.database import SessionLocal
    from urllib.parse import parse_qs, urlparse

    monkeypatch.setattr(conn, "exchange_gmail_code", _fake_exchange)
    monkeypatch.setattr(conn, "get_gmail_profile_email", _fake_profile)
    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "demo-id")
    monkeypatch.setattr(settings, "google_client_secret", "demo-secret")

    def _flow(c, headers):
        au = c.post("/api/v1/gmail/auth-url", headers=headers, json={
            "redirect_uri": "http://localhost:5173/", "client_id": "demo-id"}).json()["auth_url"]
        st = parse_qs(urlparse(au).query)["state"][0]
        return c.post("/api/v1/gmail/callback", headers=headers, json={
            "code": "4/fake", "state": st, "redirect_uri": "http://localhost:5173/"})

    with TestClient(app) as c:
        hv, _ = _auth(c)
        assert _flow(c, hv).status_code == 200
        db = SessionLocal()
        try:
            victim = db.query(models.User).order_by(models.User.created_at.desc()).first()
            victim_id = victim.id
        finally:
            db.close()

        ha, _ = _auth(c)
        r = _flow(c, ha)
        assert r.status_code == 403, r.text

        db = SessionLocal()
        try:
            row = db.query(models.GmailAccount).filter_by(gmail_address="demo@gmail.com").first()
            assert row is not None and row.user_id == victim_id
            mrow = db.query(models.MailboxConnection).filter_by(account_email="demo@gmail.com").first()
            assert mrow is not None and mrow.user_id == victim_id
            db.query(models.GmailAccount).filter_by(gmail_address="demo@gmail.com").delete()
            db.query(models.MailboxConnection).filter_by(account_email="demo@gmail.com").delete()
            db.commit()
        finally:
            db.close()
