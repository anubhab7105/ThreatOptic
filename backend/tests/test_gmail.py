"""Gmail OAuth2 connector tests (Google HTTP calls mocked — fully offline)."""
import uuid

import pytest
from fastapi.testclient import TestClient

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
    uname = f"gmail-{uuid.uuid4().hex[:8]}"
    tok = c.post("/api/v1/auth/register", json={"username": uname, "password": "Str0ngPass!"}).json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}, uname


async def _fake_exchange(code, client_id, client_secret, redirect_uri):
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
        # no client_id anywhere -> helpful 400
        r = c.get("/api/v1/gmail/auth-url", headers=h, params={"redirect_uri": "http://localhost:5173/"})
        assert r.status_code == 400
        r = c.get("/api/v1/gmail/auth-url", headers=h,
                  params={"client_id": "demo-id.apps.googleusercontent.com", "redirect_uri": "http://localhost:5173/"})
        assert r.status_code == 200, r.text
        url = r.json()["auth_url"]
        assert "accounts.google.com" in url and "gmail.readonly" in url and "demo-id" in url


def test_gmail_connect_sync_disconnect(monkeypatch):
    from app.main import app
    import app.modules.ingestion.connectors as conn

    monkeypatch.setattr(conn, "exchange_gmail_code", _fake_exchange)
    monkeypatch.setattr(conn, "get_gmail_profile_email", _fake_profile)
    monkeypatch.setattr(conn, "refresh_gmail_token", _fake_refresh)
    monkeypatch.setattr(conn, "fetch_gmail_messages", _fake_fetch)

    with TestClient(app) as c:
        h, _ = _auth(c)
        assert c.get("/api/v1/gmail/status", headers=h).json()["connected"] is False
        # sync before connect
        assert c.post("/api/v1/gmail/sync", headers=h, json={}).status_code == 404

        r = c.post("/api/v1/gmail/callback", headers=h, json={
            "code": "4/fake", "redirect_uri": "http://localhost:5173/",
            "client_id": "demo-id", "client_secret": "demo-secret",
        })
        assert r.status_code == 200, r.text
        assert r.json()["connected"] is True and r.json()["gmail_address"] == "demo@gmail.com"

        r = c.post("/api/v1/gmail/sync", headers=h, json={"max_results": 5, "client_secret": "demo-secret"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["synced"] == 1 and len(body["email_ids"]) == 1 and body["errors"] == []

        # synced mail is analyzable through the normal API
        eid = body["email_ids"][0]
        d = c.get(f"/api/v1/emails/{eid}", headers=h)
        assert d.status_code == 200 and d.json()["analysis"]["fraud_score"] >= 50

        assert c.delete("/api/v1/gmail/disconnect", headers=h).status_code == 200
        assert c.get("/api/v1/gmail/status", headers=h).json()["connected"] is False
