import asyncio
import logging
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import models, schemas
from ..config import get_settings
from ..database import get_db
from ..modules.auth import vault
from ..modules.ingestion import connectors
from ..services.pipeline import process_raw_email
from .deps import get_current_user

log = logging.getLogger("gmail")
router = APIRouter(prefix="/gmail", tags=["gmail"])


def _resolve_client_id(explicit: str | None, acct: models.GmailAccount | None = None,
                       db: Session | None = None, user: models.User | None = None) -> str:

    if explicit and explicit.strip():
        return explicit.strip()
    if acct and acct.encrypted_client_id:
        try:
            val = vault.decrypt_secret(acct.encrypted_client_id)
            if val.strip():
                return val.strip()
        except Exception:
            pass
    if db:
        from .oauth import _tenant_scope_conn
        conn_q = _tenant_scope_conn(db.query(models.MailboxConnection).filter(
            models.MailboxConnection.provider == "google",
            models.MailboxConnection.encrypted_client_id != ""
        ), user)
        conn = conn_q.order_by(models.MailboxConnection.updated_at.desc()).first()
        if conn and conn.encrypted_client_id:
            try:
                val = vault.decrypt_secret(conn.encrypted_client_id)
                if val.strip():
                    return val.strip()
            except Exception:
                pass
    cid = get_settings().google_client_id
    if not cid:
        raise HTTPException(400, "Google OAuth client_id not configured (enter in UI or set env GOOGLE_CLIENT_ID)")
    return cid


def _resolve_client_secret(explicit: str | None, acct: models.GmailAccount | None = None,
                           db: Session | None = None, user: models.User | None = None) -> str:

    if explicit and explicit.strip():
        return explicit.strip()
    if acct and acct.encrypted_client_secret:
        try:
            val = vault.decrypt_secret(acct.encrypted_client_secret)
            if val.strip():
                return val.strip()
        except Exception:
            pass
    if db:
        from .oauth import _tenant_scope_conn
        conn_q = _tenant_scope_conn(db.query(models.MailboxConnection).filter(
            models.MailboxConnection.provider == "google",
            models.MailboxConnection.encrypted_client_secret != ""
        ), user)
        conn = conn_q.order_by(models.MailboxConnection.updated_at.desc()).first()
        if conn and conn.encrypted_client_secret:
            try:
                val = vault.decrypt_secret(conn.encrypted_client_secret)
                if val.strip():
                    return val.strip()
            except Exception:
                pass
    secret = get_settings().google_client_secret
    if not secret:
        raise HTTPException(400, "Google OAuth client_secret not configured (enter in UI or set env GOOGLE_CLIENT_SECRET)")
    return secret


def _client_secret() -> str:
    secret = get_settings().google_client_secret
    if not secret:
        raise HTTPException(400, "Google OAuth client_secret not configured (env GOOGLE_CLIENT_SECRET)")
    return secret


def _redirect_uri(explicit: str | None) -> str:

    from .oauth import _redirect_or_400
    uri = (explicit or "").strip() or get_settings().google_redirect_uri or "http://localhost:5173/"
    return _redirect_or_400(uri)


@router.get("/status", response_model=schemas.GmailStatus)
def status(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _status_payload(user, db)


def _status_payload(user: models.User, db: Session) -> dict:
    from .oauth import _tenant_scope_conn
    acct = db.query(models.GmailAccount).filter(models.GmailAccount.user_id == user.id).first()
    has_stored = bool(acct and acct.encrypted_client_id)
    if not has_stored:

        has_stored = bool(_tenant_scope_conn(db.query(models.MailboxConnection).filter(
            models.MailboxConnection.provider == "google",
            models.MailboxConnection.encrypted_client_id != ""
        ), user).first())
    has_env = bool(get_settings().google_client_id)
    return {
        "connected": acct is not None,
        "gmail_address": acct.gmail_address if acct else "",
        "last_sync_at": acct.last_sync_at.isoformat() if acct and acct.last_sync_at else None,
        "client_configured": has_stored or has_env,
    }


@router.post("/auth-url", response_model=schemas.GmailAuthUrlOut)
def auth_url(
    payload: schemas.GmailAuthUrlIn,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from .oauth import create_oauth_state
    acct = db.query(models.GmailAccount).filter(models.GmailAccount.user_id == user.id).first()
    cid = _resolve_client_id(payload.client_id, acct, db=db, user=user)
    uri = _redirect_uri(payload.redirect_uri)
    secret = payload.client_secret or ""
    state, verifier = create_oauth_state(
        db, user_id=user.id, provider="google", redirect_uri=uri, client_id=cid, client_secret=secret,
    )
    challenge = connectors._pkce_challenge(verifier)
    return {"auth_url": connectors.build_gmail_auth_url(cid, uri, state=state, code_challenge=challenge)}


@router.post("/callback", response_model=schemas.GmailStatus)
async def callback(
    payload: schemas.GmailCallbackIn,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from .oauth import consume_oauth_state


    row = consume_oauth_state(db, state=payload.state, provider="google")
    if row.user_id != user.id:
        raise HTTPException(400, "OAuth state does not belong to this session — restart the connect flow")
    verifier = row.code_verifier or ""
    if not verifier:
        raise HTTPException(400, "invalid OAuth state: missing PKCE verifier")
    if payload.redirect_uri and payload.redirect_uri != (row.redirect_uri or ""):
        raise HTTPException(400, "redirect_uri mismatch — restart the connect flow")
    acct = db.query(models.GmailAccount).filter(models.GmailAccount.user_id == user.id).first()
    cid = (payload.client_id or row.client_id or "").strip() or _resolve_client_id(None, acct, db=db, user=user)
    
    state_secret = ""
    if getattr(row, "encrypted_client_secret", ""):
        try:
            state_secret = vault.decrypt_secret(row.encrypted_client_secret)
        except Exception:
            pass
    secret = (payload.client_secret or state_secret or "").strip() or _resolve_client_secret(None, acct, db=db, user=user)
    uri = _redirect_uri(payload.redirect_uri or row.redirect_uri)
    try:
        tokens = await connectors.exchange_gmail_code(payload.code, cid, secret, uri, code_verifier=verifier)
    except httpx.HTTPError as e:
        raise HTTPException(400, f"Google token exchange failed: {e}")
    if not tokens.get("refresh_token"):
        raise HTTPException(400, "Google did not return a refresh token (use prompt=consent / a fresh code)")
    try:
        address = await connectors.get_gmail_profile_email(tokens["access_token"])
    except httpx.HTTPError as e:
        raise HTTPException(400, f"could not read Gmail profile: {e}")

    encrypted_refresh = vault.encrypt_secret(tokens["refresh_token"])
    encrypted_cid = vault.encrypt_secret(cid) if cid else ""
    encrypted_sec = vault.encrypt_secret(secret) if secret else ""

    if acct:
        acct.gmail_address = address
        acct.refresh_token = encrypted_refresh
        acct.client_id = cid
        acct.encrypted_client_id = encrypted_cid
        acct.encrypted_client_secret = encrypted_sec
    else:
        acct = models.GmailAccount(
            user_id=user.id,
            gmail_address=address,
            refresh_token=encrypted_refresh,
            client_id=cid,
            encrypted_client_id=encrypted_cid,
            encrypted_client_secret=encrypted_sec,
        )
        db.add(acct)

    conn = db.query(models.MailboxConnection).filter(
        models.MailboxConnection.provider == "google",
        models.MailboxConnection.account_email == address,
    ).first()
    if conn:


        same_owner = conn.user_id == user.id
        same_org = bool(user.organization_id and conn.organization_id) \
            and conn.organization_id == user.organization_id
        if not (same_owner or same_org):
            raise HTTPException(403, "mailbox already connected to another organization")
        conn.encrypted_refresh_token = encrypted_refresh
        conn.encrypted_client_id = encrypted_cid
        conn.encrypted_client_secret = encrypted_sec
        conn.user_id = user.id
        conn.organization_id = user.organization_id
    else:
        db.add(models.MailboxConnection(
            user_id=user.id,
            organization_id=user.organization_id,
            provider="google",
            account_email=address,
            encrypted_refresh_token=encrypted_refresh,
            encrypted_client_id=encrypted_cid,
            encrypted_client_secret=encrypted_sec,
        ))

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
    cid = _resolve_client_id(payload.client_id, acct, db=db, user=user)
    secret = _resolve_client_secret(payload.client_secret, acct, db=db, user=user)
    if cid:
        acct.client_id = cid
        acct.encrypted_client_id = vault.encrypt_secret(cid)
    if secret:
        acct.encrypted_client_secret = vault.encrypt_secret(secret)
    db.commit()

    try:


        raw_token = vault.decrypt_secret(acct.refresh_token)
    except Exception:
        raise HTTPException(400, "stored Gmail credentials are invalid — please disconnect and reconnect the mailbox")


    cid = (acct.client_id or "").strip() or get_settings().google_client_id
    if not cid:
        log.error("gmail sync for user %s has no client_id (connect-time or settings)", user.id)
        raise HTTPException(400, "Google OAuth client_id not configured (env GOOGLE_CLIENT_ID)")
    try:
        fresh = await connectors.refresh_gmail_token(raw_token, cid, secret)
    except httpx.HTTPError as e:
        raise HTTPException(400, f"Gmail token refresh failed (reconnect mailbox): {e}")
    try:
        messages = await connectors.fetch_gmail_messages(
            fresh["access_token"], query=payload.query, max_results=payload.max_results
        )
    except httpx.HTTPError as e:
        raise HTTPException(502, f"Gmail fetch failed: {e}")
    email_ids: list[str] = []
    errors: list[str] = []
    sem = asyncio.Semaphore(8)

    async def _worker(m: dict):
        async with sem:
            from ..database import SessionLocal
            worker_db = SessionLocal()
            try:
                res = await process_raw_email(worker_db, m["raw"], source="gmail", organization_id=user.organization_id)
                return ("ok", res["email_id"])
            except Exception as e:
                log.warning("gmail message %s failed pipeline: %s", m.get("id"), e)
                return ("err", f"{m.get('id')}: {e}"[:200])
            finally:
                worker_db.close()

    results = await asyncio.gather(*[_worker(m) for m in messages])
    for status_str, val in results:
        if status_str == "ok":
            email_ids.append(val)
        else:
            errors.append(val)

    out = schemas.GmailSyncResult(
        synced=len(email_ids),
        email_ids=email_ids,
        errors=errors,
    )
    acct.last_sync_at = datetime.utcnow()
    db.commit()
    if out.synced:
        try:
            from ..modules.cache import cache_delete_prefix
            cache_delete_prefix("dash:")
        except Exception:
            pass
    from ..modules.auth.rate_limit import audit as _audit
    _audit("gmail.sync", user=user.email, synced=out.synced)
    return out


@router.delete("/disconnect")
def disconnect(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):

    acct = db.query(models.GmailAccount).filter(models.GmailAccount.user_id == user.id).first()
    raw_refresh: str | None = None
    if acct:
        try:
            raw_refresh = vault.decrypt_secret(acct.refresh_token)
        except Exception:
            raw_refresh = None
    if raw_refresh:
        try:
            import httpx as _httpx
            _httpx.post("https://oauth2.googleapis.com/revoke",
                        data={"token": raw_refresh}, timeout=5)
        except Exception as e:
            log.warning("google token revoke failed (local disconnect continues): %s", e)
    removed_mailboxes = db.query(models.MailboxConnection).filter(
        models.MailboxConnection.provider == "google",
        models.MailboxConnection.user_id == user.id,
    ).delete(synchronize_session=False)
    if acct:
        db.delete(acct)
    db.commit()
    from ..modules.auth.rate_limit import audit as _audit
    _audit("gmail.disconnect", user=user.email, removed=removed_mailboxes)
    return {"connected": False}
