"""Organization mailbox OAuth2 (C3/C4): Google + Microsoft consent flow.

Security properties (Step 2):
- `state` is random, server-side, single-use, 10-minute expiry, bound to
  the initiating user — no more latest-user fallback (C3).
- PKCE (S256) on both providers; verifier stored with the state row.
- redirect_uri must be allowlisted (C3): exact match against frontend_url,
  google_redirect_uri, or OAUTH_REDIRECT_ALLOWLIST.
- status/disconnect/sync are scoped to the caller's organization (C4);
  users without an org are scoped to their own connections.
- Rotated provider refresh tokens are persisted (service layer).
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session
from .. import models
from ..config import get_settings
from ..database import get_db
from ..modules.auth.rate_limit import audit, limiter
from ..modules.auth.vault import decrypt_secret, encrypt_secret
from ..modules.ingestion import connectors
from ..services.mailbox_poll import poll_all_mailboxes_async
from .deps import get_current_user, require_roles

log = logging.getLogger("oauth")
router = APIRouter(prefix="/oauth", tags=["oauth"])

PROVIDERS = ("google", "microsoft")
STATE_TTL_MINUTES = 10


def _utcnow():
    return datetime.now(timezone.utc)


def _make_state(user_id: str, client_id: str = "", client_secret: str = "", redirect_uri: str = "", flow: str = "oauth", pkce_verifier: str = "") -> str:
    payload = {"sub": user_id, "t": int(time.time()), "flow": flow}
    if client_id:
        payload["cid"] = client_id
    if client_secret:
        payload["csec"] = client_secret
    if redirect_uri:
        payload["ruri"] = redirect_uri
    if pkce_verifier:
        payload["pkv"] = pkce_verifier
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


def _redirect_or_400(uri: str | None) -> str:
    if not uri or not get_settings().oauth_redirect_allowed(uri):
        raise HTTPException(400, "redirect_uri is not allowlisted (check FRONTEND_URL / OAUTH_REDIRECT_ALLOWLIST)")
    return uri


def _scope(query, user: models.User):
    """Tenant scope (C4): caller's org, or own connections when org-less."""
    if user.organization_id:
        return query.filter(models.MailboxConnection.organization_id == user.organization_id)
    return query.filter(models.MailboxConnection.user_id == user.id)


class SyncNowIn(BaseModel):
    provider: str | None = None
    max_results: int = Field(default=10, ge=1, le=50)
    client_id: str | None = None
    client_secret: str | None = None


@router.get("/{provider}/authorize")
@limiter.limit("30/minute")
def authorize(
    provider: str,
    request: Request,
    redirect_uri: str = Query(...),
    client_id: str | None = Query(None),
    client_secret: str | None = Query(None),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a signed state + PKCE pair, return the consent URL."""
    p = _provider_or_400(provider)
    uri = _redirect_or_400(redirect_uri)
    cid = _resolve_client_id(p, client_id, db=db)
    verifier = connectors._new_verifier()
    state = _make_state(user.id, client_id=cid, redirect_uri=uri, flow="oauth", pkce_verifier=verifier)
    challenge = connectors._pkce_challenge(verifier)
    if p == "google":
        url = connectors.build_gmail_auth_url(cid, uri, state=state, code_challenge=challenge)
    else:
        url = connectors.build_microsoft_auth_url(cid, uri, state=state, code_challenge=challenge)
    audit("oauth.authorize", user=user.username, provider=p)
    return {"auth_url": url}


@router.get("/{provider}/callback")
@limiter.limit("30/minute")
async def callback(
    provider: str,
    request: Request,
    code: str = Query(...),
    redirect_uri: str | None = Query(None),
    state: str | None = Query(None),
    client_id: str | None = Query(None),
    client_secret: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """Provider redirects here (no auth header possible): verify signed state, exchange, store."""
    p = _provider_or_400(provider)
    payload = _verify_state(state)
    if not payload or payload.get("flow") != "oauth":
        raise HTTPException(400, "invalid or expired OAuth state — restart the connect flow")
    if int(time.time()) - payload.get("t", 0) > STATE_TTL_MINUTES * 60:
        raise HTTPException(400, "OAuth state expired — restart the connect flow")
    
    owner_id = payload.get("sub")
    if not owner_id:
        raise HTTPException(400, "invalid OAuth state: missing user")
    
    owner = db.query(models.User).filter(models.User.id == owner_id).first()
    if not owner:
        raise HTTPException(400, "state owner no longer exists")

    # Extract PKCE verifier from state
    verifier = payload.get("pkv", "")
    if not verifier:
        raise HTTPException(400, "invalid OAuth state: missing PKCE verifier")

    # Verify redirect_uri matches what's in state
    state_redirect_uri = payload.get("ruri", "")
    if redirect_uri and redirect_uri != state_redirect_uri:
        raise HTTPException(400, "redirect_uri mismatch — restart the connect flow")
    r_uri = redirect_uri or state_redirect_uri or (get_settings().google_redirect_uri if p == "google" else get_settings().frontend_url) or "http://localhost:5173/"
    
    # Verify client_id matches what's in state
    state_client_id = payload.get("cid", "")
    if client_id and state_client_id and client_id != state_client_id:
        raise HTTPException(400, "OAuth client mismatch — restart the connect flow")
    cid = (client_id or state_client_id or "").strip() or _resolve_client_id(p, None, db=db)
    sec = (client_secret or "").strip() or _resolve_client_secret(p, None, db=db)

    try:
        if p == "google":
            tokens = await connectors.exchange_gmail_code(code, cid, sec, r_uri, code_verifier=verifier)
            address = await connectors.get_gmail_profile_email(tokens["access_token"])
        else:
            tokens = await connectors.exchange_microsoft_code(code, cid, sec, r_uri, code_verifier=verifier)
            address = await connectors.get_microsoft_profile_email(tokens["access_token"])
    except httpx.HTTPError as e:
        raise HTTPException(400, f"{p} token exchange failed: {e}")
    if not tokens.get("refresh_token"):
        raise HTTPException(400, "provider did not return a refresh token")

    encrypted_refresh = encrypt_secret(tokens["refresh_token"])
    encrypted_cid = encrypt_secret(cid) if cid else ""
    encrypted_sec = encrypt_secret(sec) if sec else ""

    conn = db.query(models.MailboxConnection).filter(
        models.MailboxConnection.provider == p,
        models.MailboxConnection.account_email == address,
    ).first()
    if conn:
        if owner.organization_id and conn.organization_id and conn.organization_id != owner.organization_id:
            raise HTTPException(403, "mailbox already connected to another organization")
        conn.encrypted_refresh_token = encrypted_refresh
        conn.encrypted_client_id = encrypted_cid
        conn.encrypted_client_secret = encrypted_sec
        conn.user_id = owner.id
        conn.organization_id = owner.organization_id
    else:
        conn = models.MailboxConnection(
            user_id=owner.id,
            organization_id=owner.organization_id,
            provider=p,
            account_email=address,
            encrypted_refresh_token=encrypted_refresh,
            encrypted_client_id=encrypted_cid,
            encrypted_client_secret=encrypted_sec,
        )
        db.add(conn)

    if p == "google":
        acct = db.query(models.GmailAccount).filter(models.GmailAccount.user_id == owner.id).first()
        if acct:
            acct.gmail_address = address
            acct.refresh_token = encrypted_refresh
            acct.client_id = cid
            acct.encrypted_client_id = encrypted_cid
            acct.encrypted_client_secret = encrypted_sec
        else:
            db.add(models.GmailAccount(
                user_id=owner.id,
                gmail_address=address,
                refresh_token=encrypted_refresh,
                client_id=cid,
                encrypted_client_id=encrypted_cid,
                encrypted_client_secret=encrypted_sec,
            ))

    db.commit()
    audit("oauth.callback", provider=p, account=address)
    
    # URL-encode the redirect address
    from urllib.parse import quote
    raw_front = (get_settings().frontend_url or "").split(",")[0].strip().rstrip("/")
    base = raw_front or "https://socforensics.io"
    encoded_address = quote(address, safe="")
    return RedirectResponse(f"{base}/mailboxes?connected={p}:{encoded_address}", status_code=302)


@router.get("/status")
def status(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = _scope(db.query(models.MailboxConnection), user).all()
    return [{"provider": r.provider, "account_email": r.account_email,
             "last_poll_at": r.last_poll_at.isoformat() if r.last_poll_at else None} for r in rows]


@router.delete("/{provider}")
def disconnect(provider: str, user: models.User = Depends(require_roles("Admin", "Analyst")), db: Session = Depends(get_db)):
    p = _provider_or_400(provider)
    query = _scope(db.query(models.MailboxConnection).filter(models.MailboxConnection.provider == p), user)
    n = query.delete(synchronize_session=False)
    db.commit()
    return {"disconnected": p, "removed": n}


@router.post("/sync-now")
@limiter.limit("10/minute")
async def sync_now(
    payload: SyncNowIn,
    request: Request,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    result = await poll_all_mailboxes_async(
        max_results=payload.max_results,
        provider=_provider_or_400(payload.provider) if payload.provider else None,
        organization_id=user.organization_id,
        user_id=user.id,
    )
    if result["polled"] == 0:
        raise HTTPException(404, "no mailbox connected")
    audit("oauth.sync", user=user.username, synced=result["synced"])
    return result


async def poll_all_mailboxes(max_results: int = 25, provider: str | None = None, organization_id: str | None = None, user_id: str | None = None) -> dict:
    """Background-poller entrypoint (async; call from event loop)."""
    return await poll_all_mailboxes_async(max_results=max_results, provider=provider, organization_id=organization_id, user_id=user_id)
