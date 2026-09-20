"""Organization mailbox OAuth2 (F7): Google + Microsoft consent flow, encrypted
refresh-token storage, background polling into the forensic pipeline.

This is the persistent org-level connector. The per-user Gmail demo flow in
routers/gmail.py is intentionally left untouched.
"""
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
from .deps import get_current_user

log = logging.getLogger("oauth")
router = APIRouter(prefix="/oauth", tags=["oauth"])

PROVIDERS = ("google", "microsoft")


def _provider_or_400(provider: str) -> str:
    p = (provider or "").lower()
    if p not in PROVIDERS:
        raise HTTPException(400, f"provider must be one of {PROVIDERS}")
    return p


def _client_pair(provider: str, explicit_id: str | None, explicit_secret: str | None) -> tuple[str, str]:
    s = get_settings()
    if provider == "google":
        cid, sec = explicit_id or s.google_client_id, explicit_secret or s.google_client_secret
    else:
        cid, sec = explicit_id or s.ms_client_id, explicit_secret or s.ms_client_secret
    if not cid:
        raise HTTPException(400, f"{provider} OAuth client_id not configured")
    if not sec:
        raise HTTPException(400, f"{provider} OAuth client_secret not configured")
    return cid, sec


class SyncNowIn(BaseModel):
    provider: str | None = None
    max_results: int = Field(default=10, ge=1, le=50)


@router.get("/{provider}/authorize")
def authorize(
    provider: str,
    redirect_uri: str = Query(...),
    client_id: str | None = Query(None),
    user: models.User = Depends(get_current_user),
):
    """Return the provider consent URL; the frontend navigates there."""
    p = _provider_or_400(provider)
    cid, _ = _client_pair(p, client_id, "placeholder-allows-url-preview")
    if p == "google":
        url = connectors.build_gmail_auth_url(cid, redirect_uri)
    else:
        url = connectors.build_microsoft_auth_url(cid, redirect_uri)
    return {"auth_url": url}


@router.get("/{provider}/callback")
async def callback(
    provider: str,
    code: str = Query(...),
    redirect_uri: str = Query(...),
    db: Session = Depends(get_db),
):
    """Provider redirects here (no auth header possible): exchange, store, bounce to UI."""
    p = _provider_or_400(provider)
    cid, sec = _client_pair(p, None, None)
    try:
        if p == "google":
            tokens = await connectors.exchange_gmail_code(code, cid, sec, redirect_uri)
            address = await connectors.get_gmail_profile_email(tokens["access_token"])
        else:
            tokens = await connectors.exchange_microsoft_code(code, cid, sec, redirect_uri)
            address = await connectors.get_microsoft_profile_email(tokens["access_token"])
    except httpx.HTTPError as e:
        raise HTTPException(400, f"{p} token exchange failed: {e}")
    if not tokens.get("refresh_token"):
        raise HTTPException(400, "provider did not return a refresh token")
    # Attribute to an org by matching the mailbox domain is out of scope;
    # store against the most recently active user as the connector owner.
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
def disconnect(provider: str, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    p = _provider_or_400(provider)
    n = db.query(models.MailboxConnection).filter(models.MailboxConnection.provider == p).delete()
    db.commit()
    return {"disconnected": p, "removed": n}


async def poll_connection(conn: models.MailboxConnection, db: Session, max_results: int = 25) -> dict:
    """Refresh tokens, fetch, and pipeline one mailbox. Shared by sync-now + poller."""
    s = get_settings()
    provider = conn.provider
    if provider == "google":
        cid, sec = _client_pair("google", None, None)
        fresh = await connectors.refresh_gmail_token(decrypt_secret(conn.encrypted_refresh_token), cid, sec)
        messages = await connectors.fetch_gmail_messages(fresh["access_token"], max_results=max_results)
    else:
        cid, sec = _client_pair("microsoft", None, None)
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
