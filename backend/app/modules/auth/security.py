"""Password hashing (passlib/bcrypt) + JWT access/refresh tokens (PyJWT).

Seeded users created before this module used a stdlib PBKDF2 format
("pbkdf2$<hex>"); verify_password still accepts those so existing local
DBs keep working, but all new hashes are bcrypt.
"""
import hashlib
from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"
REFRESH_EXPIRE_DAYS = 7


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def _verify_legacy_pbkdf2(password: str, stored: str) -> bool:
    try:
        scheme, hex_digest = stored.split("$", 1)
        if scheme != "pbkdf2":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), b"soc-demo-salt", 100_000).hex()
        return hashlib.compare_digest(calc, hex_digest)
    except Exception:
        return False


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    if password_hash.startswith("pbkdf2$"):
        return _verify_legacy_pbkdf2(password, password_hash)
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        return False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(user_id: str, username: str, role: str, secret: str, expires_minutes: int) -> str:
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "type": "access",
        "exp": _now() + timedelta(minutes=expires_minutes),
        "iat": _now(),
    }
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def create_refresh_token(user_id: str, secret: str, expires_days: int = REFRESH_EXPIRE_DAYS) -> str:
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": _now() + timedelta(days=expires_days),
        "iat": _now(),
    }
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def decode_token(token: str, secret: str) -> dict:
    return jwt.decode(token, secret, algorithms=[ALGORITHM])
