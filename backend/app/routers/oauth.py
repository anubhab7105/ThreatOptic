"""Organization mailbox OAuth2 (F7): Google + Microsoft consent flow, encrypted
refresh-token storage, background polling into the forensic pipeline.

This is the persistent org-level connector. The per-user Gmail demo flow in
routers/gmail.py is intentionally left untouched.
"""
import asyncio
import logging
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from .. import models
from ..config import get_settings
from ..database import SessionLocal, get_db
from ..modules.auth.vault import decrypt_secret, encrypt_secret
from ..modules.ingestion import connectors
from ..services.pipeline import process_raw_email
from .deps import get_current_user, require_roles

log = logging.getLogger("oauth")
router = APIRouter(prefix="/oauth", tags=["oauth"])

PROVIDERS = ("google", "microsoft")


def _make_state(user_id: str) -> str:
    import base64, hashlib, hmac, json, time
    payload = {"sub": user_id, "t": int(time.time())}
    msg = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(get_settings().secret_key.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return f"{msg}.{sig}"


def _verify_state(state: str) -> str | None:
    import base64, hashlib, hmac, json, time
    try:
        msg, sig = state.split(".", 1)
        expected_sig = hmac.new(get_settings().secret_key.encode(), msg.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(msg.encode()).decode())
        if int(time.time()) - payload.get("t", 0) > 3600:
            return None
        return payload.get("sub")
    except Exception:
        return None


def _provider_or_400(provider: str) -> str:
    p = (provider or "").lower()
    if p not in PROVIDERS:
        raise HTTPException(400, f"unsupported provider '{provider}' (expected google | microsoft)")
    return p


def _client_id(provider: str, explicit: str | None) -> str:
    s = get_settings()
    cid = explicit or (s.google_client_id if provider == "google" else s.ms_client_id)
    if not cid:
        raise HTTPException(400, f"{provider} client_id required (configure in .env or pass client_id query)")
    return cid


def _client_secret(provider: str, explicit: str | None) -> str:
    s = get_settings()
    sec = explicit or (s.google_client_secret if provider == "google" else s.ms_client_secret)
    if not sec:
        raise HTTPException(400, f"{provider} client_secret required (configure in .env or pass client_secret query)")
    return sec


class SyncNowIn(BaseModel):
    provider: str | None = None
    max_results: int = Field(default=10, ge=1)


@router.get("/{provider}/authorize")
def authorize(
    provider: str,
    redirect_uri: str = Query(...),
    client_id: str | None = Query(None),
    user: models.User = Depends(get_current_user),
):
    """Return the provider consent URL; the frontend navigates there."""
    p = _provider_or_400(provider)
    cid = _client_id(p, client_id)
    state = _make_state(user.id)
    if p == "google":
        url = connectors.build_gmail_auth_url(cid, redirect_uri, state=state)
    else:
        url = connectors.build_microsoft_auth_url(cid, redirect_uri, state=state)
    return {"auth_url": url}


@router.get("/{provider}/callback")
async def callback(
    provider: str,
    code: str = Query(...),
    redirect_uri: str | None = Query(None),
    state: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """Provider redirects here (no auth header possible): exchange, store, bounce to UI."""
    p = _provider_or_400(provider)
    cid, sec = _client_id(p, None), _client_secret(p, None)
    r_uri = redirect_uri or (get_settings().google_redirect_uri if p == "google" else get_settings().frontend_url)
    try:
        if p == "google":
            tokens = await connectors.exchange_gmail_code(code, cid, sec, r_uri)
            address = await connectors.get_gmail_profile_email(tokens["access_token"])
        else:
            tokens = await connectors.exchange_microsoft_code(code, cid, sec, r_uri)
            address = await connectors.get_microsoft_profile_email(tokens["access_token"])
    except httpx.HTTPError as e:
        raise HTTPException(400, f"{p} token exchange failed: {e}")
    if not tokens.get("refresh_token"):
        raise HTTPException(400, "provider did not return a refresh token")
    # Bind to authenticated state initiator if present, otherwise latest active user
    owner = None
    if state:
        user_id = _verify_state(state)
        if user_id:
            owner = db.query(models.User).filter(models.User.id == user_id).first()
    if not owner:
        owner = db.query(models.User).order_by(models.User.created_at.desc()).first()
    if not owner:
        raise HTTPException(400, "no local user to own the mailbox connection")
    conn = db.query(models.MailboxConnection).filter(
        models.MailboxConnection.provider == p,
        models.MailboxConnection.account_email == address).first()
    if conn:
        conn.encrypted_refresh_token = encrypt_secret(tokens["refresh_token"])
        conn.user_id = owner.id
        conn.organization_id = owner.organization_id
    else:
        conn = models.MailboxConnection(
            user_id=owner.id, organization_id=owner.organization_id, provider=p,
            account_email=address, encrypted_refresh_token=encrypt_secret(tokens["refresh_token"]))
        db.add(conn)
    db.commit()
    base = get_settings().frontend_url.rstrip("/")
    return RedirectResponse(f"{base}/#/mailboxes?connected={p}:{address}", status_code=302)


@router.get("/status")
def status(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(models.MailboxConnection).all()
    return [{"provider": r.provider, "account_email": r.account_email,
             "last_poll_at": r.last_poll_at.isoformat() if r.last_poll_at else None} for r in rows]


@router.delete("/{provider}")
def disconnect(provider: str, user: models.User = Depends(require_roles("Admin", "Analyst")), db: Session = Depends(get_db)):
    p = _provider_or_400(provider)
    query = db.query(models.MailboxConnection).filter(models.MailboxConnection.provider == p)
    if user.role != "Admin" and user.organization_id:
        query = query.filter(models.MailboxConnection.organization_id == user.organization_id)
    n = query.delete()
    db.commit()
    return {"disconnected": p, "removed": n}


async def poll_connection(conn: models.MailboxConnection, db: Session, max_results: int = 25) -> dict:
    """Refresh tokens, fetch, and pipeline one mailbox. Shared by sync-now + poller."""
    provider = conn.provider
    if provider == "google":
        cid, sec = _client_id("google", None), _client_secret("google", None)
        fresh = await connectors.refresh_gmail_token(decrypt_secret(conn.encrypted_refresh_token), cid, sec)
        messages = await connectors.fetch_gmail_messages(fresh["access_token"], max_results=max_results)
    else:
        cid, sec = _client_id("microsoft", None), _client_secret("microsoft", None)
        fresh = await connectors.refresh_microsoft_token(decrypt_secret(conn.encrypted_refresh_token), cid, sec)
        messages = await connectors.fetch_o365_messages(fresh["access_token"], top=max_results)
    out = {"synced": 0, "email_ids": [], "errors": []}
    for m in messages:
        try:
            res = await process_raw_email(db, m["raw"], source=f"oauth-{provider}")
            out["email_ids"].append(res["email_id"])
        except Exception as e:
            log.warning("mailbox %s message failed: %s", conn.account_email, e)
            out["errors"].append(str(e)[:200])
        await asyncio.sleep(0)
    out["synced"] = len(out["email_ids"])
    conn.last_poll_at = datetime.utcnow()
    db.commit()
    return out


@router.post("/sync-now")
async def sync_now(
    payload: SyncNowIn,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(models.MailboxConnection)
    if payload.provider:
        query = query.filter(models.MailboxConnection.provider == _provider_or_400(payload.provider))
    conns = query.all()
    if not conns:
        raise HTTPException(404, "no mailbox connected")
    total = {"synced": 0, "email_ids": [], "errors": []}
    for conn in conns:
        try:
            r = await poll_connection(conn, db, max_results=payload.max_results)
        except httpx.HTTPError as e:
            total["errors"].append(f"{conn.account_email}: {e}"[:200])
            continue
        total["synced"] += r["synced"]
        total["email_ids"] += r["email_ids"]
        total["errors"] += r["errors"]
    return total


def poll_all_mailboxes(max_results: int = 25) -> dict:
    """Background-poller entrypoint (own session per run)."""
    db = SessionLocal()
    try:
        conns = db.query(models.MailboxConnection).all()
        import asyncio
        total = {"synced": 0, "email_ids": [], "errors": []}
        for conn in conns:
            try:
                r = asyncio.run(poll_connection(conn, db, max_results=max_results))
            except Exception as e:
                log.warning("poll failed for %s: %s", conn.account_email, e)
                total["errors"].append(f"{conn.account_email}: {e}"[:200])
                continue
            total["synced"] += r["synced"]
            total["email_ids"] += r["email_ids"]
            total["errors"] += r["errors"]
        log.info("mailbox poll: synced=%s errors=%s", total["synced"], len(total["errors"]))
        return total
    finally:
        db.close()
