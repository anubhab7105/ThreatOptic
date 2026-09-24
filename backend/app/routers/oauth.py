"""Organization mailbox OAuth2 (C3/C4): Google + Microsoft consent flow.

Security properties (P0):
- `state` is an opaque, single-use, server-side-stored token (OAuthState
  row): 10-minute expiry, bound to the initiating user. The browser holds
  only this opaque identifier — never client secrets or PKCE verifiers.
- Client secrets are NEVER accepted from the client (body or query);
  they resolve server-side only (stored connection or env).
- PKCE (S256) on both providers; verifier stored server-side with state.
- redirect_uri must be allowlisted: checked at authorize time AND at
  callback time (fail closed if the allowlist changed in between).
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
from sqlalchemy.orm import Session
from .. import models
from ..config import get_settings
from ..database import get_db
from ..modules.auth.rate_limit import audit, limiter
from ..modules.auth.vault import decrypt_secret, encrypt_secret
from ..modules.ingestion import connectors
from ..services.mailbox_poll import poll_all_mailboxes
from .deps import get_current_user, require_roles

log = logging.getLogger("oauth")
router = APIRouter(prefix="/oauth", tags=["oauth"])

PROVIDERS = ("google", "microsoft")
STATE_TTL_MINUTES = 10


def _utcnow():
    return datetime.now(timezone.utc)


def _expires_at(dt: datetime | None) -> datetime | None:
    """Normalize a possibly-naive DB datetime to aware UTC for comparison."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def create_oauth_state(db: Session, *, user_id: str, provider: str,
                       redirect_uri: str, client_id: str = "") -> tuple[str, str]:
    """Mint an opaque single-use state token + PKCE verifier, stored server-side.

    Returns (state, code_verifier). The state is a random token with no
    embedded data — it only indexes the OAuthState row. No secrets or
    verifiers ever leave the server inside the state value.
    """
    opaque = secrets.token_urlsafe(32)
    verifier = connectors._new_verifier()
    db.add(models.OAuthState(
        state=opaque,
        user_id=user_id,
        provider=provider,
        redirect_uri=redirect_uri,
        client_id=client_id,
        code_verifier=verifier,
        expires_at=_utcnow() + timedelta(minutes=STATE_TTL_MINUTES),
    ))
    db.commit()
    return opaque, verifier


def consume_oauth_state(db: Session, *, state: str, provider: str) -> models.OAuthState:
    """Validate an opaque state token and consume it single-use (fail closed).

    Checks: row exists, provider matches, not already used, not expired.
    Marks used=True before returning so replays fail. Raises HTTPException
    400 on any mismatch — never returns a partial/ambiguous result.
    """
    row = db.query(models.OAuthState).filter(
        models.OAuthState.state == (state or ""),
        models.OAuthState.provider == provider,
        models.OAuthState.used == False,  # noqa: E712
    ).first()
    if row is None:
        raise HTTPException(400, "invalid or expired OAuth state — restart the connect flow")
    if _expires_at(row.expires_at) is None or _expires_at(row.expires_at) < _utcnow():  # type: ignore[operator]
        raise HTTPException(400, "OAuth state expired — restart the connect flow")
    row.used = True
    db.commit()
    return row


def _provider_or_400(provider: str) -> str:
    p = (provider or "").lower()
    if p not in PROVIDERS:
        raise HTTPException(400, f"unsupported provider '{provider}' (expected google | microsoft)")
    return p


def _tenant_scope_conn(query, user: models.User | None):
    """Scope a MailboxConnection query to the caller's tenant (P0).

    Org members share the org's connections; org-less users see only
    their own rows. user=None (background jobs) means no fallback —
    callers must pass an explicit row instead.
    """
    if user is None:
        return query.filter(models.MailboxConnection.id == "__none__")
    if user.organization_id:
        return query.filter(models.MailboxConnection.organization_id == user.organization_id)
    return query.filter(models.MailboxConnection.user_id == user.id)


def _resolve_client_id(provider: str, explicit: str | None, conn: models.MailboxConnection | None = None,
                       db: Session | None = None, user: models.User | None = None) -> str:
    """Return client_id from: explicit > conn > TENANT-SCOPED connections >
    own GmailAccount > env fallback (P0: never another tenant's credentials)."""
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
        other_conn = _tenant_scope_conn(db.query(models.MailboxConnection).filter(
            models.MailboxConnection.provider == provider,
            models.MailboxConnection.encrypted_client_id != ""
        ), user).order_by(models.MailboxConnection.updated_at.desc()).first()
        if other_conn and other_conn.encrypted_client_id:
            try:
                val = decrypt_secret(other_conn.encrypted_client_id)
                if val.strip():
                    return val.strip()
            except Exception:
                pass
        if provider == "google":
            acct_q = db.query(models.GmailAccount).filter(
                models.GmailAccount.encrypted_client_id != ""
            )
            if user is not None:
                # GmailAccount is per-user: never borrow another user's row.
                acct_q = acct_q.filter(models.GmailAccount.user_id == user.id)
            else:
                acct_q = acct_q.filter(models.GmailAccount.id == "__none__")
            acct = acct_q.order_by(models.GmailAccount.updated_at.desc()).first()
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


def _resolve_client_secret(provider: str, explicit: str | None, conn: models.MailboxConnection | None = None,
                           db: Session | None = None, user: models.User | None = None) -> str:
    """Return client_secret from: explicit > conn > TENANT-SCOPED connections >
    own GmailAccount > env fallback (P0: never another tenant's credentials)."""
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
        other_conn = _tenant_scope_conn(db.query(models.MailboxConnection).filter(
            models.MailboxConnection.provider == provider,
            models.MailboxConnection.encrypted_client_secret != ""
        ), user).order_by(models.MailboxConnection.updated_at.desc()).first()
        if other_conn and other_conn.encrypted_client_secret:
            try:
                val = decrypt_secret(other_conn.encrypted_client_secret)
                if val.strip():
                    return val.strip()
            except Exception:
                pass
        if provider == "google":
            acct_q = db.query(models.GmailAccount).filter(
                models.GmailAccount.encrypted_client_secret != ""
            )
            if user is not None:
                # GmailAccount is per-user: never borrow another user's row.
                acct_q = acct_q.filter(models.GmailAccount.user_id == user.id)
            else:
                acct_q = acct_q.filter(models.GmailAccount.id == "__none__")
            acct = acct_q.order_by(models.GmailAccount.updated_at.desc()).first()
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


class AuthorizeIn(BaseModel):
    # P0: client_id/redirect_uri travel in POST body over TLS, never as
    # query params (query strings leak to proxy/access logs). client_secret
    # is NEVER accepted from the client — it resolves server-side only.
    redirect_uri: str = Field(min_length=1, max_length=1024)
    client_id: str | None = Field(default=None, max_length=320)


@router.post("/{provider}/authorize")
@limiter.limit("30/minute")
def authorize(
    provider: str,
    payload: AuthorizeIn,
    request: Request,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create an opaque server-side state + PKCE pair, return the consent URL."""
    p = _provider_or_400(provider)
    uri = _redirect_or_400(payload.redirect_uri)
    cid = _resolve_client_id(p, payload.client_id, db=db)
    state, verifier = create_oauth_state(
        db, user_id=user.id, provider=p, redirect_uri=uri, client_id=cid,
    )
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
    db: Session = Depends(get_db),
):
    """Provider redirects here (no auth header possible): consume opaque
    server-side state, exchange the code with PKCE, store credentials.

    P0: `state` is an opaque token indexing the OAuthState row — it carries
    no data. Client secrets are never accepted here; they resolve
    server-side only. Unknown/expired/replayed states fail closed (400).
    """
    p = _provider_or_400(provider)
    if not state:
        raise HTTPException(400, "invalid or expired OAuth state — restart the connect flow")
    row = consume_oauth_state(db, state=state, provider=p)

    owner = db.query(models.User).filter(models.User.id == row.user_id).first()
    if not owner:
        # Fail closed: never attach a mailbox to a substitute user.
        raise HTTPException(400, "state owner no longer exists")

    verifier = row.code_verifier or ""
    if not verifier:
        raise HTTPException(400, "invalid OAuth state: missing PKCE verifier")

    # redirect_uri must match the stored value AND be allowlisted now
    # (fail closed if the allowlist changed since authorize time).
    if redirect_uri and redirect_uri != (row.redirect_uri or ""):
        raise HTTPException(400, "redirect_uri mismatch — restart the connect flow")
    r_uri = row.redirect_uri or ""
    if not r_uri or not get_settings().oauth_redirect_allowed(r_uri):
        raise HTTPException(400, "redirect_uri is not allowlisted (check FRONTEND_URL / OAUTH_REDIRECT_ALLOWLIST)")

    # client_id resolves from the stored row, then server-side fallbacks.
    # client_secret resolves server-side only — never from the request.
    cid = (row.client_id or "").strip() or _resolve_client_id(p, None, db=db)
    sec = _resolve_client_secret(p, None, db=db)

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
    base = raw_front or "http://localhost:5173"
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
    from ..services.mailbox_poll import poll_all_mailboxes
    result = await poll_all_mailboxes(
        max_results=payload.max_results,
        provider=_provider_or_400(payload.provider) if payload.provider else None,
        organization_id=user.organization_id,
        user_id=user.id,
    )
    if result["polled"] == 0:
        raise HTTPException(404, "no mailbox connected")
    audit("oauth.sync", user=user.username, synced=result["synced"])
    return result
