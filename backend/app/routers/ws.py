
import logging
from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect

from .. import models
from ..config import get_settings
from .deps import get_current_user

log = logging.getLogger("ws")

router = APIRouter()


class ConnectionManager:
    def __init__(self) -> None:

        self._conns: dict[object, dict] = {}

    async def connect(self, ws: WebSocket, info: dict) -> None:
        await ws.accept()
        self._conns[ws] = info

    def disconnect(self, ws: WebSocket) -> None:
        self._conns.pop(ws, None)

    def count(self) -> int:
        return len(self._conns)

    async def broadcast_alert(self, payload: dict, organization_id: str | None) -> int:

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

    from ..modules.auth.security import create_ws_ticket

    return {"ticket": create_ws_ticket(user.id, user.email, user.role, get_settings().secret_key)}


@router.websocket("/ws/alerts")
async def alerts_socket(ws: WebSocket, ticket: str = Query("")):
    user = _user_from_ticket(ticket)
    if not user:
        await ws.close(code=4401)
        return
    await manager.connect(ws, {"org": user.organization_id, "role": user.role, "user": user.email})
    try:
        while True:

            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception:
        manager.disconnect(ws)
