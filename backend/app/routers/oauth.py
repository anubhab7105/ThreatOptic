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
import logging
import secrets
from datetime import datetime, timedelta, timezone

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
from ..modules.auth.vault import encrypt_secret
from ..modules.ingestion import connectors
from ..services.mailbox_poll import poll_all_mailboxes_async
from .deps import get_current_user, require_roles

log = logging.getLogger("oauth")
router = APIRouter(prefix="/oauth", tags=["oauth"])

PROVIDERS = ("google", "microsoft")
STATE_TTL_MINUTES = 10


def _utcnow():
    return datetime.now(timezone.utc)


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


@router.get("/{provider}/authorize")
@limiter.limit("30/minute")
def authorize(
    provider: str,
    request: Request,
    redirect_uri: str = Query(...),
    client_id: str | None = Query(None),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a server-side state + PKCE pair, return the consent URL."""
    p = _provider_or_400(provider)
    uri = _redirect_or_400(redirect_uri)
    cid = _client_id(p, client_id)
    state = secrets.token_urlsafe(32)
    verifier = connectors._new_verifier()
    db.add(models.OAuthState(
        state=state, user_id=user.id, provider=p, redirect_uri=uri,
        client_id=cid, code_verifier=verifier,
        expires_at=_utcnow() + timedelta(minutes=STATE_TTL_MINUTES),
    ))
    db.commit()
    challenge = connectors._pkce_challenge(verifier)
    if p == "google":
        url = connectors.build_gmail_auth_url(cid, uri, state=state, code_challenge=challenge)
    else:
        url = connectors.build_microsoft_auth_url(cid, uri, state=state, code_challenge=challenge)
    audit("oauth.authorize", user=user.username, provider=p)
    return {"auth_url": url}


@router.get("/{provider}/callback")
async def callback(
    provider: str,
    code: str = Query(...),
    state: str = Query(...),
    db: Session = Depends(get_db),
):
    """Provider redirects here (no auth header possible): verify state, exchange, store."""
    p = _provider_or_400(provider)
    row = db.query(models.OAuthState).filter(
        models.OAuthState.state == state,
        models.OAuthState.provider == p,
        models.OAuthState.used == False,  # noqa: E712
    ).first()
    now = _utcnow()
    expires = row.expires_at.replace(tzinfo=timezone.utc) if row and row.expires_at.tzinfo is None else (row.expires_at if row else None)
    if not row or not expires or expires < now:
        raise HTTPException(400, "invalid or expired OAuth state — restart the connect flow")
    row.used = True
    db.commit()
    owner = db.query(models.User).filter(models.User.id == row.user_id).first()
    if not owner:
        raise HTTPException(400, "state owner no longer exists")
    cid, sec = _client_id(p, None), _client_secret(p, None)
    # client_id is pinned at authorize time; a swapped value is rejected
    if row.client_id and row.client_id != cid:
        raise HTTPException(400, "OAuth client mismatch — restart the connect flow")
    try:
        if p == "google":
            tokens = await connectors.exchange_gmail_code(code, cid, sec, row.redirect_uri, code_verifier=row.code_verifier)
            address = await connectors.get_gmail_profile_email(tokens["access_token"])
        else:
            tokens = await connectors.exchange_microsoft_code(code, cid, sec, row.redirect_uri, code_verifier=row.code_verifier)
            address = await connectors.get_microsoft_profile_email(tokens["access_token"])
    except httpx.HTTPError as e:
        raise HTTPException(400, f"{p} token exchange failed: {e}")
    if not tokens.get("refresh_token"):
        raise HTTPException(400, "provider did not return a refresh token")
    conn = db.query(models.MailboxConnection).filter(
        models.MailboxConnection.provider == p,
        models.MailboxConnection.account_email == address).first()
    if conn:
        if owner.organization_id and conn.organization_id and conn.organization_id != owner.organization_id:
            raise HTTPException(403, "mailbox already connected to another organization")
        conn.encrypted_refresh_token = encrypt_secret(tokens["refresh_token"])
        conn.user_id = owner.id
        conn.organization_id = owner.organization_id
    else:
        conn = models.MailboxConnection(
            user_id=owner.id, organization_id=owner.organization_id, provider=p,
            account_email=address, encrypted_refresh_token=encrypt_secret(tokens["refresh_token"]))
        db.add(conn)
    # prune consumed/expired states (housekeeping)
    db.query(models.OAuthState).filter(
        or_(models.OAuthState.used == True,  # noqa: E712
            models.OAuthState.expires_at < _utcnow())).delete(synchronize_session=False)
    db.commit()
    base = get_settings().frontend_url.rstrip("/")
    return RedirectResponse(f"{base}/#/mailboxes?connected={p}:{address}", status_code=302)


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
async def sync_now(
    payload: SyncNowIn,
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
    return result


def poll_all_mailboxes(max_results: int = 25) -> dict:
    """Background-poller entrypoint (scheduler thread: no running loop here)."""
    import asyncio

    return asyncio.run(poll_all_mailboxes_async(max_results=max_results))
