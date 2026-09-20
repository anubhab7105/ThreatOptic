"""JWT auth endpoints: register / login / refresh / me (+ Admin user provisioning)."""
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
    verify_password,
)
from .deps import get_current_user, require_roles

router = APIRouter(prefix="/auth", tags=["auth"])

SELF_REGISTER_ROLES = {"Analyst", "ReadOnly"}
ALL_ROLES = {"Admin", "Analyst", "ReadOnly"}


def _pair(user: models.User) -> schemas.TokenPair:
    settings = get_settings()
    return schemas.TokenPair(
        access_token=create_access_token(user.id, user.username, user.role, settings.secret_key, settings.access_token_expire_minutes),
        refresh_token=create_refresh_token(user.id, settings.secret_key),
        token_type="bearer",
    )


@router.post("/register", response_model=schemas.TokenPair, status_code=201)
def register(payload: schemas.RegisterIn, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(400, "username already taken")
    if db.query(models.User).count() == 0:
        # Bootstrap: the very first account becomes Admin so the org is manageable.
        role = "Admin"
    else:
        role = payload.role or "Analyst"
        if role not in SELF_REGISTER_ROLES:
            raise HTTPException(400, f"public registration allows roles: {sorted(SELF_REGISTER_ROLES)}")
    user = models.User(username=payload.username, password_hash=hash_password(payload.password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return _pair(user)


@router.post("/login", response_model=schemas.TokenPair)
def login(payload: schemas.LoginIn, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid username or password")
    return _pair(user)


@router.post("/refresh", response_model=schemas.TokenPair)
def refresh(payload: schemas.RefreshIn, db: Session = Depends(get_db)):
    settings = get_settings()
    try:
        data = decode_token(payload.refresh_token, settings.secret_key)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "refresh token expired")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid refresh token")
    if data.get("type") != "refresh":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token type")
    user = db.query(models.User).filter(models.User.id == data.get("sub")).first()
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")
    return _pair(user)


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
