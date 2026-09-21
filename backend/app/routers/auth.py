"""JWT auth endpoints: register / login / refresh / me (+ Admin user provisioning)."""
from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from .. import models, schemas
from ..config import get_settings
from ..database import get_db
from ..modules.auth.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    refresh_token_fingerprint,
    verify_password,
)
from .deps import get_current_user, require_roles

router = APIRouter(prefix="/auth", tags=["auth"])

SELF_REGISTER_ROLES = {"Analyst", "ReadOnly"}
ALL_ROLES = {"Admin", "Analyst", "ReadOnly"}
DEFAULT_REGISTER_ROLE = "ReadOnly"  # lowest privilege (C2)


def _valid_setup_token(provided: str | None) -> bool:
    expected = (get_settings().setup_token or "").strip()
    return bool(expected) and bool(provided) and provided.strip() == expected


def _pair(user: models.User, db: Session) -> schemas.TokenPair:
    """Mint tokens and persist the refresh-token fingerprint (single-use ledger)."""
    from datetime import timedelta
    from ..modules.auth.security import REFRESH_EXPIRE_DAYS

    settings = get_settings()
    access = create_access_token(user.id, user.username, user.role, settings.secret_key, settings.access_token_expire_minutes)
    refresh = create_refresh_token(user.id, settings.secret_key)
    db.add(models.RefreshToken(
        user_id=user.id,
        token_hash=refresh_token_fingerprint(refresh),
        expires_at=datetime.now(timezone.utc) + timedelta(days=REFRESH_EXPIRE_DAYS),
    ))
    db.commit()
    return schemas.TokenPair(access_token=access, refresh_token=refresh, token_type="bearer")


def _revoke_user_tokens(db: Session, user_id: str) -> None:
    db.query(models.RefreshToken).filter(models.RefreshToken.user_id == user_id).update(
        {"revoked": True}, synchronize_session=False
    )
    db.commit()


@router.post("/register", response_model=schemas.TokenPair, status_code=201)
def register(payload: schemas.RegisterIn, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(400, "username already taken")
    requested = (payload.role or "").strip()
    if requested == "Admin":
        # No first-registrant bootstrap (C2 TOCTOU): Admin requires the
        # out-of-band setup token, validated server-side.
        if not _valid_setup_token(payload.setup_token):
            raise HTTPException(403, "creating an Admin requires a valid setup token")
        role = "Admin"
    elif not requested:
        role = DEFAULT_REGISTER_ROLE
    elif requested not in SELF_REGISTER_ROLES:
        raise HTTPException(400, f"public registration allows roles: {sorted(SELF_REGISTER_ROLES)}")
    else:
        role = requested
    user = models.User(username=payload.username, password_hash=hash_password(payload.password), role=role)
    db.add(user)
    db.flush()
    # Every account belongs to a tenant: personal workspace org. Without
    # this, organization_id=None would break tenant isolation (Step 2).
    org = models.Organization(name=f"{payload.username}'s workspace", compliance_policy={})
    db.add(org)
    db.flush()
    user.organization_id = org.id
    db.commit()
    db.refresh(user)
    return _pair(user, db)


@router.post("/login", response_model=schemas.TokenPair)
def login(payload: schemas.LoginIn, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid username or password")
    return _pair(user, db)


@router.post("/refresh", response_model=schemas.TokenPair)
def refresh(payload: schemas.RefreshIn, db: Session = Depends(get_db)):
    settings = get_settings()
    try:
        data = decode_token(payload.refresh_token, settings.secret_key)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "refresh token expired")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid refresh token")
    if data.get("type") != "refresh" or not data.get("jti"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token type")
    row = db.query(models.RefreshToken).filter(
        models.RefreshToken.token_hash == refresh_token_fingerprint(payload.refresh_token)
    ).first()
    if row is None or row.user_id != data.get("sub"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown refresh token")
    if row.revoked:
        # Reuse of a rotated token: assume theft, kill the whole family.
        _revoke_user_tokens(db, row.user_id)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "refresh token reused")
    now = datetime.now(timezone.utc)
    expires = row.expires_at.replace(tzinfo=timezone.utc) if row.expires_at.tzinfo is None else row.expires_at
    if expires < now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "refresh token expired")
    user = db.query(models.User).filter(models.User.id == row.user_id).first()
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")
    # Rotate: single-use — revoke the presented token, link the replacement.
    new_pair = _pair(user, db)
    new_data = decode_token(new_pair.refresh_token, settings.secret_key)
    row.revoked = True
    row.replaced_by = new_data.get("jti")
    db.commit()
    return new_pair


@router.get("/me", response_model=schemas.UserOut)
def me(user: models.User = Depends(get_current_user)):
    return user


@router.post("/users", response_model=schemas.UserOut, status_code=201)
def create_user(
    payload: schemas.AdminCreateUserIn,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_roles("Admin")),
):
    """Admin-only provisioning (e.g. creating fellow Admins/analysts)."""
    if payload.role not in ALL_ROLES:
        raise HTTPException(400, f"role must be one of {sorted(ALL_ROLES)}")
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(400, "username already taken")
    user = models.User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
        organization_id=payload.organization_id or admin.organization_id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
