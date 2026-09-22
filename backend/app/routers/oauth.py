"""Organization mailbox OAuth2 (F7): Google + Microsoft consent flow, encrypted
refresh-token storage, background polling into the forensic pipeline.

This is the persistent org-level connector.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime
from urllib.parse import urlparse

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


def _make_state(user_id: str, client_id: str = "", client_secret: str = "", redirect_uri: str = "", flow: str = "oauth") -> str:
    payload = {"sub": user_id, "t": int(time.time()), "flow": flow}
    if client_id:
        payload["cid"] = client_id
    if client_secret:
        payload["csec"] = client_secret
    if redirect_uri:
        payload["ruri"] = redirect_uri
    msg = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(get_settings().secret_key.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return f"{msg}.{sig}"


def _verify_state(state: str) -> dict | None:
    try:
        msg, sig = state.split(".", 1)
        expected_sig = hmac.new(get_settings().secret_key.encode(), msg.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        rem = len(msg) % 4
        padded = msg + ("=" * (4 - rem) if rem else "")
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
        # Allow up to 24h for user to complete OAuth consent
        if int(time.time()) - payload.get("t", 0) > 86400:
            return None
        return payload
    except Exception as e:
        log.warning("OAuth state verification failed: %s", e)
        return None


def _provider_or_400(provider: str) -> str:
    p = (provider or "").lower()
    if p not in PROVIDERS:
        raise HTTPException(400, f"unsupported provider '{provider}' (expected google | microsoft)")
    return p


def _resolve_client_id(provider: str, explicit: str | None, conn: models.MailboxConnection | None = None, db: Session | None = None) -> str:
    """Return client_id from: explicit > conn > other connections in DB > GmailAccount in DB > env fallback."""
    if explicit and explicit.strip():
        return explicit.strip()
    if conn and conn.encrypted_client_id:
        try:
            val = decrypt_secret(conn.encrypted_client_id)
            if val.strip():
                return val.strip()
        except Exception:
            pass
    if db:
        other_conn = db.query(models.MailboxConnection).filter(
            models.MailboxConnection.provider == provider,
            models.MailboxConnection.encrypted_client_id != ""
        ).order_by(models.MailboxConnection.updated_at.desc()).first()
        if other_conn and other_conn.encrypted_client_id:
            try:
                val = decrypt_secret(other_conn.encrypted_client_id)
                if val.strip():
                    return val.strip()
            except Exception:
                pass
        if provider == "google":
            acct = db.query(models.GmailAccount).filter(
                models.GmailAccount.encrypted_client_id != ""
            ).order_by(models.GmailAccount.updated_at.desc()).first()
            if acct and acct.encrypted_client_id:
                try:
                    val = decrypt_secret(acct.encrypted_client_id)
                    if val.strip():
                        return val.strip()
                except Exception:
                    pass
    s = get_settings()
    cid = s.google_client_id if provider == "google" else s.ms_client_id
    if not cid:
        raise HTTPException(400, f"{provider} client_id required (enter in UI or configure in .env)")
    return cid


def _resolve_client_secret(provider: str, explicit: str | None, conn: models.MailboxConnection | None = None, db: Session | None = None) -> str:
    """Return client_secret from: explicit > conn > other connections in DB > GmailAccount in DB > env fallback."""
    if explicit and explicit.strip():
        return explicit.strip()
    if conn and conn.encrypted_client_secret:
        try:
            val = decrypt_secret(conn.encrypted_client_secret)
            if val.strip():
                return val.strip()
        except Exception:
            pass
    if db:
        other_conn = db.query(models.MailboxConnection).filter(
            models.MailboxConnection.provider == provider,
            models.MailboxConnection.encrypted_client_secret != ""
        ).order_by(models.MailboxConnection.updated_at.desc()).first()
        if other_conn and other_conn.encrypted_client_secret:
            try:
                val = decrypt_secret(other_conn.encrypted_client_secret)
                if val.strip():
                    return val.strip()
            except Exception:
                pass
        if provider == "google":
            acct = db.query(models.GmailAccount).filter(
                models.GmailAccount.encrypted_client_secret != ""
            ).order_by(models.GmailAccount.updated_at.desc()).first()
            if acct and acct.encrypted_client_secret:
                try:
                    val = decrypt_secret(acct.encrypted_client_secret)
                    if val.strip():
                        return val.strip()
                except Exception:
                    pass
    s = get_settings()
    sec = s.google_client_secret if provider == "google" else s.ms_client_secret
    if not sec:
        raise HTTPException(400, f"{provider} client_secret required (enter in UI or configure in .env)")
    return sec


class SyncNowIn(BaseModel):
    provider: str | None = None
    max_results: int = Field(default=10, ge=1)
    client_id: str | None = None
    client_secret: str | None = None


@router.get("/{provider}/authorize")
def authorize(
    provider: str,
    redirect_uri: str = Query(...),
    client_id: str | None = Query(None),
    client_secret: str | None = Query(None),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return the provider consent URL; the frontend navigates there."""
    p = _provider_or_400(provider)
    cid = _resolve_client_id(p, client_id, db=db)
    sec = client_secret or (_resolve_client_secret(p, None, db=db) if (client_id or get_settings().google_client_secret or get_settings().ms_client_secret) else "")
    state = _make_state(user.id, client_id=cid, client_secret=sec, redirect_uri=redirect_uri, flow="oauth")
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
    client_id: str | None = Query(None),
    client_secret: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """Provider redirects here (no auth header possible): exchange, store, bounce to UI."""
    p = _provider_or_400(provider)
    state_data = _verify_state(state) if state else None
    state_cid = state_data.get("cid", "") if state_data else ""
    state_sec = state_data.get("csec", "") if state_data else ""
    state_ruri = state_data.get("ruri", "") if state_data else ""
    flow = state_data.get("flow", "oauth") if state_data else "oauth"

    cid_candidate = client_id or state_cid or None
    sec_candidate = client_secret or state_sec or None

    cid = _resolve_client_id(p, cid_candidate, db=db)
    sec = _resolve_client_secret(p, sec_candidate, db=db)
    r_uri = redirect_uri or state_ruri or (get_settings().google_redirect_uri if p == "google" else get_settings().frontend_url) or "http://localhost:5173/"

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
        raise HTTPException(400, "provider did not return a refresh token (re-approve consent)")

    # Bind to state initiator if valid, otherwise latest active user
    owner = None
    if state_data:
        user_id = state_data.get("sub")
        if user_id:
            owner = db.query(models.User).filter(models.User.id == user_id).first()
    if not owner:
        owner = db.query(models.User).order_by(models.User.created_at.desc()).first()
    if not owner:
        raise HTTPException(400, "no local user to own the mailbox connection")

    encrypted_refresh = encrypt_secret(tokens["refresh_token"])
    encrypted_cid = encrypt_secret(cid) if cid else ""
    encrypted_sec = encrypt_secret(sec) if sec else ""

    # Update/Create Organization Mailbox Connection
    conn = db.query(models.MailboxConnection).filter(
        models.MailboxConnection.provider == p,
        models.MailboxConnection.account_email == address).first()
    if conn:
        conn.encrypted_refresh_token = encrypted_refresh
        conn.encrypted_client_id = encrypted_cid
        conn.encrypted_client_secret = encrypted_sec
        conn.user_id = owner.id
        conn.organization_id = owner.organization_id
    else:
        conn = models.MailboxConnection(
            user_id=owner.id, organization_id=owner.organization_id, provider=p,
            account_email=address, encrypted_refresh_token=encrypted_refresh,
            encrypted_client_id=encrypted_cid, encrypted_client_secret=encrypted_sec)
        db.add(conn)

    # For Google provider, ALSO update/create user GmailAccount so Dashboard live import works immediately
    if p == "google":
        acct = db.query(models.GmailAccount).filter(models.GmailAccount.user_id == owner.id).first()
        if acct:
            acct.gmail_address = address
            acct.refresh_token = encrypted_refresh
            acct.encrypted_client_id = encrypted_cid
            acct.encrypted_client_secret = encrypted_sec
        else:
            db.add(models.GmailAccount(
                user_id=owner.id, gmail_address=address,
                refresh_token=encrypted_refresh,
                encrypted_client_id=encrypted_cid,
                encrypted_client_secret=encrypted_sec,
            ))

    db.commit()

    # Determine bounce URL
    base = get_settings().frontend_url.rstrip("/")
    if r_uri and (r_uri.startswith("http://") or r_uri.startswith("https://")):
        parsed = urlparse(r_uri)
        base = f"{parsed.scheme}://{parsed.netloc}"

    route_target = "/#/mailboxes" if flow == "oauth" else "/#/"
    return RedirectResponse(f"{base}{route_target}?connected={p}:{address}", status_code=302)


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


async def poll_connection(
    conn: models.MailboxConnection, db: Session, max_results: int = 25,
    explicit_client_id: str | None = None, explicit_client_secret: str | None = None,
) -> dict:
    """Refresh tokens, fetch, and pipeline one mailbox. Shared by sync-now + poller."""
    provider = conn.provider
    if explicit_client_id and explicit_client_secret:
        conn.encrypted_client_id = encrypt_secret(explicit_client_id)
        conn.encrypted_client_secret = encrypt_secret(explicit_client_secret)
        db.commit()

    cid = _resolve_client_id(provider, explicit_client_id, conn, db=db)
    sec = _resolve_client_secret(provider, explicit_client_secret, conn, db=db)

    if provider == "google":
        fresh = await connectors.refresh_gmail_token(decrypt_secret(conn.encrypted_refresh_token), cid, sec)
        messages = await connectors.fetch_gmail_messages(fresh["access_token"], max_results=max_results)
    else:
        fresh = await connectors.refresh_microsoft_token(decrypt_secret(conn.encrypted_refresh_token), cid, sec)
        messages = await connectors.fetch_o365_messages(fresh["access_token"], top=max_results)

    email_ids: list[str] = []
    errors: list[str] = []
    sem = asyncio.Semaphore(8)

    async def _worker(m: dict):
        async with sem:
            from ..database import SessionLocal
            worker_db = SessionLocal()
            try:
                res = await process_raw_email(worker_db, m["raw"], source=f"oauth-{provider}")
                return ("ok", res["email_id"])
            except Exception as e:
                log.warning("mailbox %s message failed: %s", conn.account_email, e)
                return ("err", str(e)[:200])
            finally:
                worker_db.close()

    results = await asyncio.gather(*[_worker(m) for m in messages])
    for status_str, val in results:
        if status_str == "ok":
            email_ids.append(val)
        else:
            errors.append(val)

    out = {"synced": len(email_ids), "email_ids": email_ids, "errors": errors}
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
            r = await poll_connection(
                conn, db, max_results=payload.max_results,
                explicit_client_id=payload.client_id, explicit_client_secret=payload.client_secret,
            )
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
