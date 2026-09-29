
import uuid
from datetime import datetime, timedelta, timezone

import jwt

ALGORITHM = "HS256"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_ws_ticket(user_id: str, email: str, role: str, secret: str) -> str:

    now = _now()
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "type": "ws-ticket",
        "jti": uuid.uuid4().hex,
        "exp": now + timedelta(seconds=60),
        "iat": now,
    }
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def decode_token(token: str, secret: str) -> dict:
    return jwt.decode(token, secret, algorithms=[ALGORITHM])
