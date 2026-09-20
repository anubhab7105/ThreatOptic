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
