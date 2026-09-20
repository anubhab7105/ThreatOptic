"""Gmail OAuth2 live-demo connector: connect a mailbox, sync unread mail into the pipeline."""
import logging
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from .. import models, schemas
from ..config import get_settings
from ..database import get_db
from ..modules.ingestion import connectors
from ..services.pipeline import process_raw_email
from .deps import get_current_user

log = logging.getLogger("gmail")
router = APIRouter(prefix="/gmail", tags=["gmail"])


def _client_id(explicit: str | None) -> str:
    cid = explicit or get_settings().google_client_id
    if not cid:
        raise HTTPException(400, "Google OAuth client_id not configured (env GOOGLE_CLIENT_ID or request field)")
    return cid


def _client_secret(explicit: str | None) -> str:
    secret = explicit or get_settings().google_client_secret
    if not secret:
        raise HTTPException(400, "Google OAuth client_secret not configured (env GOOGLE_CLIENT_SECRET or request field)")
    return secret


def _redirect_uri(explicit: str | None) -> str:
    uri = explicit or get_settings().google_redirect_uri
    if not uri:
        raise HTTPException(400, "redirect_uri required (must match the URI registered in Google Cloud console)")
    return uri


@router.get("/status", response_model=schemas.GmailStatus)
def status(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _status_payload(user, db)


def _status_payload(user: models.User, db: Session) -> dict:
    acct = db.query(models.GmailAccount).filter(models.GmailAccount.user_id == user.id).first()
    return {
        "connected": acct is not None,
        "gmail_address": acct.gmail_address if acct else "",
        "last_sync_at": acct.last_sync_at.isoformat() if acct and acct.last_sync_at else None,
        "client_configured": bool(get_settings().google_client_id),
    }


@router.get("/auth-url", response_model=schemas.GmailAuthUrlOut)
def auth_url(
    client_id: str | None = Query(None),
    redirect_uri: str | None = Query(None),
    user: models.User = Depends(get_current_user),
):
    return {"auth_url": connectors.build_gmail_auth_url(_client_id(client_id), _redirect_uri(redirect_uri))}


@router.post("/callback", response_model=schemas.GmailStatus)
async def callback(
    payload: schemas.GmailCallbackIn,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    cid, secret, uri = _client_id(payload.client_id), _client_secret(payload.client_secret), _redirect_uri(payload.redirect_uri)
    try:
        tokens = await connectors.exchange_gmail_code(payload.code, cid, secret, uri)
    except httpx.HTTPError as e:
        raise HTTPException(400, f"Google token exchange failed: {e}")
    if not tokens.get("refresh_token"):
        raise HTTPException(400, "Google did not return a refresh token (use prompt=consent / a fresh code)")
    try:
        address = await connectors.get_gmail_profile_email(tokens["access_token"])
    except httpx.HTTPError as e:
        raise HTTPException(400, f"could not read Gmail profile: {e}")
    acct = db.query(models.GmailAccount).filter(models.GmailAccount.user_id == user.id).first()
    if acct:
        acct.gmail_address, acct.refresh_token = address, tokens["refresh_token"]
        db.commit()
    else:
        db.add(models.GmailAccount(user_id=user.id, gmail_address=address, refresh_token=tokens["refresh_token"]))
        db.commit()
    return _status_payload(user, db)


@router.post("/sync", response_model=schemas.GmailSyncResult)
async def sync(
    payload: schemas.GmailSyncIn,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    acct = db.query(models.GmailAccount).filter(models.GmailAccount.user_id == user.id).first()
    if not acct:
        raise HTTPException(404, "no Gmail account connected (POST /gmail/callback first)")
    settings = get_settings()
    try:
        fresh = await connectors.refresh_gmail_token(
            acct.refresh_token, settings.google_client_id or "", _client_secret(payload.client_secret)
        )
    except httpx.HTTPError as e:
        raise HTTPException(400, f"Gmail token refresh failed (reconnect mailbox): {e}")
    try:
        messages = await connectors.fetch_gmail_messages(
            fresh["access_token"], query=payload.query, max_results=payload.max_results
        )
    except httpx.HTTPError as e:
        raise HTTPException(502, f"Gmail fetch failed: {e}")
    out = schemas.GmailSyncResult()
    for m in messages:
        try:
            res = await process_raw_email(db, m["raw"], source="gmail")
            out.email_ids.append(res["email_id"])
        except Exception as e:
            log.warning("gmail message %s failed pipeline: %s", m.get("id"), e)
            out.errors.append(f"{m.get('id')}: {e}"[:200])
    out.synced = len(out.email_ids)
    acct.last_sync_at = datetime.utcnow()
    db.commit()
    return out


@router.delete("/disconnect")
def disconnect(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    acct = db.query(models.GmailAccount).filter(models.GmailAccount.user_id == user.id).first()
    if acct:
        db.delete(acct)
        db.commit()
    return {"connected": False}
