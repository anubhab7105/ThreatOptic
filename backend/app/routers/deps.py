
import jwt
from jwt import PyJWKClient
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from ..database import get_db
from .. import models
from ..config import get_settings

bearer_scheme = HTTPBearer()




_jwks_client: PyJWKClient | None = None


def _get_jwks_client() -> PyJWKClient | None:

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
            jwt_secret = settings.supabase_jwt_secret or (settings.secret_key if settings.is_development() else "")
            if not jwt_secret:
                raise
            payload = jwt.decode(
                token,
                jwt_secret,
                algorithms=["HS256"],
                audience="authenticated",
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token expired")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")

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
