"""Auth + RBAC tests for the Supabase-token posture.

Since the Supabase migration the backend owns no credentials at all:
sign-up/sign-in/refresh live in Supabase, and the API only verifies
Supabase-issued JWTs against the `users` mirror row. These tests pin that
contract — including the parts that must *stay* gone (no password
endpoint, no long-lived token in a URL) and the WebSocket ticket
replacement for query-string tokens.
"""
import uuid
from datetime import timedelta

import jwt
import pytest
from fastapi.testclient import TestClient

from helpers import auth_headers, login, make_user, mint_token
from app.config import get_settings
from app.modules.auth.security import create_ws_ticket, decode_token


def _session():
    """Fresh session from the (possibly test-rebound) sessionmaker."""
    from app.database import SessionLocal
    return SessionLocal()


def _uname(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# --- no credential endpoints -------------------------------------------------

def test_no_local_credential_endpoints():
    """The backend must not accept passwords or mint sessions (C1/C2).

    A 404 here is the guarantee: there is no surface where a password
    crosses the API, and no local refresh-token store to steal.
    """
    from app.main import app

    with TestClient(app) as c:
        for path, payload in (
            ("/api/v1/auth/register", {"username": "x", "password": "Str0ngPass!"}),
            ("/api/v1/auth/login", {"username": "x", "password": "Str0ngPass!"}),
            ("/api/v1/auth/refresh", {"refresh_token": "anything"}),
        ):
            assert c.post(path, json=payload).status_code == 404, path
        assert c.get("/api/v1/auth/users", headers=login()[0]).status_code == 404


# --- token verification ------------------------------------------------------

def test_me_returns_mirror_row():
    from app.main import app

    with TestClient(app) as c:
        headers, user = login(role="Analyst")
        r = c.get("/api/v1/auth/me", headers=headers)
        assert r.status_code == 200, r.text
        assert r.json()["id"] == user.id
        assert r.json()["email"] == user.email
        assert r.json()["role"] == "Analyst"


def test_protected_routes_require_auth():
    from app.main import app

    with TestClient(app) as c:
        assert c.get("/api/v1/emails").status_code == 401
        assert c.get("/api/v1/dashboard").status_code == 401
        assert c.post("/api/v1/emails/ingest", json={"raw": "hi"}).status_code == 401
        assert c.get("/api/v1/cases").status_code == 401
        assert c.get("/api/v1/graph/campaigns").status_code == 401
        # public surface still open
        assert c.get("/health").status_code == 200


@pytest.mark.parametrize(
    "headers",
    [
        {},                                                   # no credential
        {"Authorization": "Bearer "},                         # empty bearer
        {"Authorization": "Bearer not-a-jwt"},                # garbage
        {"Authorization": "Basic dXNlcjpwYXNz"},              # wrong scheme
        {"Authorization": "Bearer eyJhbGciOiJub25lIn0.e30."},  # alg=none
    ],
)
def test_malformed_credentials_rejected(headers):
    from app.main import app

    with TestClient(app) as c:
        assert c.get("/api/v1/emails", headers=headers).status_code == 401


def test_expired_token_rejected():
    from app.main import app

    bad = mint_token("nope", expires_in=timedelta(minutes=-1))
    with TestClient(app) as c:
        assert c.get("/api/v1/emails", headers={"Authorization": f"Bearer {bad}"}).status_code == 401


def test_token_signed_with_wrong_secret_rejected():
    from app.main import app

    forged = mint_token("some-user", secret="an-attacker-controlled-secret-value")
    with TestClient(app) as c:
        assert c.get("/api/v1/emails", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_token_with_wrong_audience_rejected():
    """Supabase issues aud=authenticated; a token minted for another service
    must not authenticate against this API."""
    from app.main import app

    wrong_aud = mint_token("some-user", aud="some-other-service")
    with TestClient(app) as c:
        assert c.get("/api/v1/emails", headers={"Authorization": f"Bearer {wrong_aud}"}).status_code == 401


def test_token_without_sub_rejected():
    from app.main import app

    no_sub = jwt.encode(
        {"aud": "authenticated", "role": "Admin", "sub": None},
        get_settings().supabase_jwt_secret,
        algorithm="HS256",
    )
    with TestClient(app) as c:
        assert c.get("/api/v1/emails", headers={"Authorization": f"Bearer {no_sub}"}).status_code == 401


def test_valid_token_for_unknown_user_rejected():
    """Signature valid but no mirror row: 401, never a 500 or a phantom user."""
    from app.main import app

    with TestClient(app) as c:
        r = c.get("/api/v1/emails", headers={"Authorization": f"Bearer {mint_token(str(uuid.uuid4()))}"})
        assert r.status_code == 401
        assert "user not found" in r.text


def test_role_claim_does_not_override_mirror_row():
    """A token claiming role=Admin must not escalate: the DB row is the
    single source of truth for authorization."""
    from app.main import app

    with TestClient(app) as c:
        headers, user = login(role="ReadOnly")
        assert user.role == "ReadOnly"
        # Re-mint with an Admin role claim for the same (ReadOnly) user.
        escalated = mint_token(user.id, email=user.email, role="Admin")
        h = {"Authorization": f"Bearer {escalated}"}
        r = c.post("/api/v1/cases", headers=h, json={"title": "escalation probe"})
        assert r.status_code == 403, r.text
        assert c.get("/api/v1/auth/me", headers=headers).json()["role"] == "ReadOnly"


# --- RBAC --------------------------------------------------------------------

def test_rbac_admin_only_delete():
    from app.main import app

    db = _session()
    try:
        admin = make_user(db, role="Admin")
        admin_h = auth_headers(admin)
    finally:
        db.close()

    with TestClient(app) as c:
        analyst_h, _user = login(role="Analyst")

        # analyst can ingest + create cases
        r = c.post("/api/v1/emails/ingest", headers=analyst_h, json={"raw": "From: a@b.com\nSubject: t\n\nhello"})
        assert r.status_code == 200, r.text
        r = c.post("/api/v1/cases", headers=analyst_h, json={"title": "rbac probe"})
        assert r.status_code == 200, r.text
        cid = r.json()["id"]

        # analyst cannot delete or run retention; admin can
        assert c.delete(f"/api/v1/cases/{cid}", headers=analyst_h).status_code == 403
        assert c.post("/api/v1/admin/retention", headers=analyst_h).status_code == 403
        assert c.delete(f"/api/v1/cases/{cid}", headers=admin_h).status_code == 200
        assert c.post("/api/v1/admin/retention", headers=admin_h).status_code == 200


# --- WebSocket tickets (P0: no long-lived credential in a URL) ----------------

def test_ws_ticket_is_short_lived_and_single_claim():
    secret = get_settings().secret_key
    ticket = create_ws_ticket("u-1", "a@test.local", "Analyst", secret)
    claims = decode_token(ticket, secret)
    assert claims["type"] == "ws-ticket"
    assert claims["sub"] == "u-1"
    assert claims["role"] == "Analyst"
    # 60s window: theft from a proxy log buys ~a minute, not a session
    assert 0 < (claims["exp"] - claims["iat"]) <= 60
    # an access token is not a ticket (different signing key entirely)
    with pytest.raises(jwt.PyJWTError):
        decode_token(mint_token("u-1"), secret)


def test_ws_ticket_endpoint_requires_auth_and_issues_ticket():
    from app.main import app

    with TestClient(app) as c:
        assert c.post("/api/v1/ws/ticket").status_code == 401
        headers, user = login(role="Analyst")
        r = c.post("/api/v1/ws/ticket", headers=headers)
        assert r.status_code == 200, r.text
        ticket = r.json()["ticket"]
        claims = decode_token(ticket, get_settings().secret_key)
        assert claims["sub"] == user.id
        assert claims["type"] == "ws-ticket"
