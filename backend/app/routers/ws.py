"""Real-time alert channel (Phase 3, item 12): FastAPI-native WebSocket.

Clients connect to /api/v1/ws/alerts?token=<jwt-access-token> (browsers
cannot set Authorization headers on WebSocket handshakes). Connections
are tagged with the user's org + role; broadcasts go to same-org
sockets plus Admins. Dead sockets are pruned on send failure.
"""
import logging
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

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


def _user_from_token(token: str):
    from .. import models
    from ..config import get_settings
    from ..database import SessionLocal
    from ..modules.auth.security import decode_token

    try:
        data = decode_token(token or "", get_settings().secret_key)
    except Exception:
        return None
    if data.get("type") != "access":
        return None
    db = SessionLocal()
    try:
        return db.query(models.User).filter(models.User.id == data.get("sub")).first()
    finally:
        db.close()


@router.websocket("/ws/alerts")
async def alerts_socket(ws: WebSocket, token: str = Query("")):
    user = _user_from_token(token)
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
