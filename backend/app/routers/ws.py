"""Real-time alert channel (Phase 3, item 12): FastAPI-native WebSocket.

Clients first POST /api/v1/ws/ticket (authenticated) for a short-lived
single-purpose ticket, then connect to /api/v1/ws/alerts?ticket=<ticket>.
Long-lived access tokens are NEVER accepted as a query parameter (they
leak to proxy/access logs); only 60-second ws-ticket JWTs are valid on
the handshake. Connections are tagged with the user's org + role;
broadcasts go to same-org sockets plus Admins. Dead sockets are pruned
on send failure.
"""
import logging
from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect

from .. import models
from ..config import get_settings
from .deps import get_current_user

log = logging.getLogger("ws")

router = APIRouter()


class ConnectionManager:
    def __init__(self) -> None:
        # websocket -> {"org": org_id|None, "role": role, "user": username}
        self._conns: dict[object, dict] = {}

    async def connect(self, ws: WebSocket, info: dict) -> None:
        await ws.accept()
        self._conns[ws] = info

    def disconnect(self, ws: WebSocket) -> None:
        self._conns.pop(ws, None)

    def count(self) -> int:
        return len(self._conns)

    async def broadcast_alert(self, payload: dict, organization_id: str | None) -> int:
        """Send to same-org sockets + Admins. Returns recipients; prunes dead."""
        dead: list = []
        delivered = 0
        for ws, info in list(self._conns.items()):
            if info.get("role") != "Admin" and info.get("org") != organization_id:
                continue
            try:
                await ws.send_json(payload)
                delivered += 1
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)
        return delivered


manager = ConnectionManager()


def _user_from_ticket(ticket: str):
    """Validate a short-lived ws-ticket (P0). Anything else — including a
    valid long-lived access token — fails closed (returns None)."""
    from ..database import SessionLocal
    from ..modules.auth.security import decode_token

    try:
        data = decode_token(ticket or "", get_settings().secret_key)
    except Exception:
        return None
    if data.get("type") != "ws-ticket":
        return None
    db = SessionLocal()
    try:
        return db.query(models.User).filter(models.User.id == data.get("sub")).first()
    finally:
        db.close()


@router.post("/ws/ticket")
def mint_ticket(user: models.User = Depends(get_current_user)):
    """Exchange auth for a 60-second WebSocket ticket (P0: tokens in URLs
    are bounded to a minute of read-only alert stream)."""
    from ..modules.auth.security import create_ws_ticket

    return {"ticket": create_ws_ticket(user.id, user.username, user.role, get_settings().secret_key)}


@router.websocket("/ws/alerts")
async def alerts_socket(ws: WebSocket, ticket: str = Query("")):
    user = _user_from_ticket(ticket)
    if not user:
        await ws.close(code=4401)
        return
    await manager.connect(ws, {"org": user.organization_id, "role": user.role, "user": user.username})
    try:
        while True:
            # keep-alive / client pings; we only push server -> client
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception:
        manager.disconnect(ws)
