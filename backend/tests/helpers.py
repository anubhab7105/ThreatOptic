"""Shared test helpers: Supabase-style JWT minting + mirror-row provisioning.

The Supabase migration removed local password auth from the backend
(`app/modules/auth/security.py` now only mints short-lived WebSocket
tickets). The API trusts Supabase-issued JWTs and looks the user up in
the `users` mirror table, so tests do exactly what the
`on_auth_user_created` trigger does — insert the mirror row — and then
mint an equivalent HS256 token with SUPABASE_JWT_SECRET.

`deps.get_current_user` verifies `aud="authenticated"`, so the audience
claim is mandatory; tests that need a bad audience pass it explicitly.
"""
import os
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from sqlalchemy.orm import Session

from app import models

# Never used outside the suite: conftest pins the same value in the env so
# `get_settings()` (cached) and this module agree.
DEFAULT_JWT_SECRET = "pytest-supabase-jwt-secret-32-chars-min"


def jwt_secret() -> str:
    return os.environ.get("SUPABASE_JWT_SECRET") or DEFAULT_JWT_SECRET


def mint_token(
    user_id: str,
    *,
    email: str = "probe@test.local",
    role: str = "Analyst",
    secret: str | None = None,
    expires_in: timedelta = timedelta(minutes=20),
    **extra,
) -> str:
    """Mint a token shaped like a Supabase access token (HS256, aud=authenticated)."""
    now = datetime.now(timezone.utc)
    payload: dict = {
        "sub": user_id,
        "email": email,
        "role": role,
        "aud": "authenticated",
        "iat": now,
        "exp": now + expires_in,
    }
    payload.update(extra)
    return jwt.encode(payload, secret if secret is not None else jwt_secret(), algorithm="HS256")


def make_org(db: Session, name: str | None = None) -> models.Organization:
    org = models.Organization(name=name or f"Org-{uuid.uuid4().hex[:8]}")
    db.add(org)
    db.commit()
    return org


def make_user(
    db: Session,
    *,
    role: str = "Analyst",
    org_id: str | None = None,
    email: str | None = None,
) -> models.User:
    """Insert a `users` mirror row (what the Supabase trigger would create)."""
    uid = str(uuid.uuid4())
    user = models.User(
        id=uid,
        email=email or f"user-{uid[:8]}@test.local",
        role=role,
        organization_id=org_id,
    )
    db.add(user)
    db.commit()
    return user


def auth_headers(user: models.User) -> dict:
    """Authorization header for an existing mirror row."""
    return {
        "Authorization": f"Bearer {mint_token(user.id, email=user.email, role=user.role)}"
    }


def anonymous_token() -> str:
    """Valid-shaped token whose `sub` matches no user row (401 user-not-found path)."""
    return mint_token(str(uuid.uuid4()))


def login(
    role: str = "Analyst",
    org_id: str | None = None,
    email: str | None = None,
) -> tuple[dict, models.User]:
    """Provision a mirror row in the per-test DB and return (headers, user)."""
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        user = make_user(db, role=role, org_id=org_id, email=email)
        return auth_headers(user), user
    finally:
        db.close()
