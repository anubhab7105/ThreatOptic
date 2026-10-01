"""Auth dependencies: Supabase JWT verification + RBAC."""
import jwt
from jwt import PyJWKClient
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from ..database import get_db
from .. import models
from ..config import get_settings

bearer_scheme = HTTPBearer()

# Cache the JWKS client so it's not recreated on every request.
# PyJWKClient fetches Supabase's public keys and supports both
# the new ECC P-256 (ES256) and legacy HS256 signing algorithms.
_jwks_client: PyJWKClient | None = None


def _get_jwks_client() -> PyJWKClient | None:
    """JWKS client, or None when Supabase Auth is not configured.

    Returning None (instead of a client pointed at a relative URI) keeps
    the HS256 fallback path from paying a doomed network round-trip on
    every request in deployments/tests without SUPABASE_URL.
    """
    global _jwks_client
    if _jwks_client is None:
        settings = get_settings()
        supabase_url = (settings.supabase_url or "").strip().rstrip("/")
        if not supabase_url:
            return None
        jwks_uri = f"{supabase_url}/auth/v1/.well-known/jwks.json"
        _jwks_client = PyJWKClient(jwks_uri, cache_keys=True)
    return _jwks_client


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    settings = get_settings()
    token = credentials.credentials
    try:
        # Try JWKS first (supports both new ECC/ES256 and legacy HS256).
        # Falls back to the shared secret if JWKS lookup fails (e.g. offline).
        try:
            jwks_client = _get_jwks_client()
            if jwks_client is None:
                raise RuntimeError("SUPABASE_URL not configured — no JWKS")
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["ES256", "RS256", "HS256"],
                audience="authenticated",
            )
        except Exception:
            # Fallback: legacy HS256 shared secret (for local dev or
            # if JWKS endpoint is temporarily unavailable).
            if not settings.supabase_jwt_secret:
                raise
            payload = jwt.decode(
                token,
                settings.supabase_jwt_secret,
                algorithms=["HS256"],
                audience="authenticated",
            )
    except (jwt.PyJWTError, Exception):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token: no sub")

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found — email not confirmed yet?")
    return user


def require_roles(*roles: str):
    def _check(user: models.User = Depends(get_current_user)) -> models.User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"requires role: {'/'.join(roles)}")
        return user
    return _check
