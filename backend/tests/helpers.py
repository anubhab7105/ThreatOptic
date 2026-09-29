
import os
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from sqlalchemy.orm import Session

from app import models



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

    return {
        "Authorization": f"Bearer {mint_token(user.id, email=user.email, role=user.role)}"
    }


def anonymous_token() -> str:

    return mint_token(str(uuid.uuid4()))


def login(
    role: str = "Analyst",
    org_id: str | None = None,
    email: str | None = None,
) -> tuple[dict, models.User]:

    from app.database import SessionLocal

    db = SessionLocal()
    try:
        user = make_user(db, role=role, org_id=org_id, email=email)
        return auth_headers(user), user
    finally:
        db.close()
