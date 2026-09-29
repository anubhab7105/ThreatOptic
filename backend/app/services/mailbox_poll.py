"""Mailbox polling service layer (Step 2).

Owns all mailbox-sync DB work so routers and the scheduler stay thin:
each mailbox gets an isolated session with commit/rollback, rotated
provider refresh tokens are persisted back, and failures in one mailbox
never abort the others.

P0 fan-out bounds: mailbox IDs stream in pages (never .all()), at most
MAX_MAILBOX_FANOUT connections poll concurrently, and per-mailbox
max_results is clamped server-side — one sync-now cannot fan out
unbounded work.
"""
import logging
from datetime import datetime, timezone

log = logging.getLogger("mailbox_poll")

MAX_MAILBOX_FANOUT = 8
MAILBOX_ID_PAGE = 200
POLL_MAX_RESULTS = 100


def _utcnow():
    return datetime.now(timezone.utc)


async def poll_connection_by_id(conn_id: str, max_results: int = 25) -> dict:
    """Poll one mailbox by id with an isolated session. Shared by sync-now + poller."""
    import httpx
    from ..config import get_settings
    from ..database import SessionLocal
    from .. import models
    from ..modules.auth.vault import decrypt_secret, encrypt_secret
    from ..modules.ingestion import connectors
    from .pipeline import process_raw_email

    max_results = max(1, min(int(max_results), POLL_MAX_RESULTS))
    settings = get_settings()
    db = SessionLocal()
    try:
        conn = db.query(models.MailboxConnection).filter(models.MailboxConnection.id == conn_id).first()
        if not conn:
            return {"synced": 0, "email_ids": [], "errors": ["mailbox not found"]}
        provider = conn.provider
        try:
            refresh_token = decrypt_secret(conn.encrypted_refresh_token)
        except Exception:
            return {"synced": 0, "email_ids": [],
                    "errors": [f"{conn.account_email}: stored credential invalid — reconnect the mailbox"]}
        try:
            if provider == "google":
                cid = ""
                if getattr(conn, "encrypted_client_id", None):
                    try:
                        cid = decrypt_secret(conn.encrypted_client_id)
                    except Exception:
                        pass
                cid = cid or settings.google_client_id
                sec = ""
                if getattr(conn, "encrypted_client_secret", None):
                    try:
                        sec = decrypt_secret(conn.encrypted_client_secret)
                    except Exception:
                        pass
                sec = sec or settings.google_client_secret
                if not cid or not sec:
                    return {"synced": 0, "email_ids": [],
                            "errors": [f"{conn.account_email}: google OAuth not configured"]}
                fresh = await connectors.refresh_gmail_token(refresh_token, cid, sec)
                messages = await connectors.fetch_gmail_messages(fresh["access_token"], max_results=max_results)
            elif provider == "microsoft":
                cid = ""
                if getattr(conn, "encrypted_client_id", None):
                    try:
                        cid = decrypt_secret(conn.encrypted_client_id)
                    except Exception:
                        pass
                cid = cid or settings.ms_client_id
                sec = ""
                if getattr(conn, "encrypted_client_secret", None):
                    try:
                        sec = decrypt_secret(conn.encrypted_client_secret)
                    except Exception:
                        pass
                sec = sec or settings.ms_client_secret
                if not cid or not sec:
                    return {"synced": 0, "email_ids": [],
                            "errors": [f"{conn.account_email}: microsoft OAuth not configured"]}
                fresh = await connectors.refresh_microsoft_token(refresh_token, cid, sec)
                messages = await connectors.fetch_o365_messages(fresh["access_token"], top=max_results)
            else:
                return {"synced": 0, "email_ids": [], "errors": [f"unsupported provider '{provider}'"]}
        except httpx.HTTPError as e:
            db.rollback()
            return {"synced": 0, "email_ids": [], "errors": [f"{conn.account_email}: {e}"[:200]]}
        # Persist provider-side rotation so sync doesn't silently break (Step 2).
        try:
            if fresh.get("refresh_token") and fresh["refresh_token"] != refresh_token:
                conn.encrypted_refresh_token = encrypt_secret(fresh["refresh_token"])
        except Exception as e:
            log.warning("could not persist rotated token for %s: %s", conn.account_email, e)
        out = {"synced": 0, "email_ids": [], "errors": []}
        for m in messages:
            try:
                res = await process_raw_email(db, m["raw"], source=f"oauth-{provider}",
                                              organization_id=conn.organization_id)
                out["email_ids"].append(res["email_id"])
            except Exception as e:
                log.warning("mailbox %s message failed: %s", conn.account_email, e)
                out["errors"].append(str(e)[:200])
        out["synced"] = len(out["email_ids"])
        conn.last_poll_at = _utcnow()
        db.commit()
        if out["synced"]:
            try:
                from ..modules.cache import cache_delete_prefix
                cache_delete_prefix("dash:")
            except Exception:
                pass
        return out
    except Exception as e:
        db.rollback()
        log.warning("poll failed: %s", e)
        return {"synced": 0, "email_ids": [], "errors": [str(e)[:200]]}
    finally:
        db.close()


async def poll_all_mailboxes(max_results: int = 25, provider: str | None = None,
                            organization_id: str | None | object = "__all__",
                            user_id: str | None = None) -> dict:
    """Poll mailboxes on the SHARED event loop (no asyncio.run per mailbox).

    organization_id="__all__" polls everything (scheduler); otherwise only
    that org's connections — or, for org-less users, only their own rows.

    P0: connection IDs stream in pages (never .all() unbounded) and at most
    MAX_MAILBOX_FANOUT mailboxes poll concurrently.
    """
    import asyncio
    from ..database import SessionLocal
    from .. import models

    max_results = max(1, min(int(max_results), POLL_MAX_RESULTS))
    sem = asyncio.Semaphore(MAX_MAILBOX_FANOUT)

    async def _bounded(conn_id: str) -> dict:
        async with sem:
            return await poll_connection_by_id(conn_id, max_results)

    total = {"polled": 0, "synced": 0, "email_ids": [], "errors": []}

    def _base_query(db):
        query = db.query(models.MailboxConnection.id)
        if provider:
            query = query.filter(models.MailboxConnection.provider == provider)
        if organization_id != "__all__":
            if organization_id is None and user_id:
                query = query.filter(models.MailboxConnection.organization_id.is_(None),
                                     models.MailboxConnection.user_id == user_id)
            else:
                query = query.filter(models.MailboxConnection.organization_id == organization_id)
        return query.order_by(models.MailboxConnection.id)

    offset = 0
    while True:
        db = SessionLocal()
        try:
            page = [row[0] for row in _base_query(db).limit(MAILBOX_ID_PAGE).offset(offset).all()]
        finally:
            db.close()
        if not page:
            break
        offset += len(page)
        for r in await asyncio.gather(*(_bounded(i) for i in page)):
            total["polled"] += 1
            total["synced"] += r["synced"]
            total["email_ids"] += r["email_ids"]
            total["errors"] += r["errors"]
        if len(page) < MAILBOX_ID_PAGE:
            break
    log.info("mailbox poll: synced=%s errors=%s", total["synced"], len(total["errors"]))
    return total