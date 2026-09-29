"""WebSocket tickets (PyJWT HS256). Password/token auth was removed in the
Supabase migration — sign-up/sign-in and session refresh are handled by
the Supabase client SDK; the backend only verifies Supabase JWTs (see
routers/deps.py) and mints short-lived WS tickets.
"""
import uuid
from datetime import datetime, timedelta, timezone

import jwt

ALGORITHM = "HS256"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_ws_ticket(user_id: str, email: str, role: str, secret: str) -> str:
    """Short-lived WebSocket ticket (P0).

    Exchanged via authenticated POST /ws/ticket, then presented as
    ?ticket= on the socket handshake. 60-second expiry bounds the
    exposure window of a credential appearing in a URL (proxy/access
    logs); theft laterally only buys a minute of read-only alert stream.
    """
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
