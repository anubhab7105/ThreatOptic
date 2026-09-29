
import json
import logging
import os
from datetime import datetime, timezone

log = logging.getLogger("scheduler")

AUDIT_LOG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "retention_audit.log")


def run_retention_job() -> dict:
    from ..config import get_settings
    from ..database import SessionLocal
    from ..modules.privacy.retention import apply_retention

    settings = get_settings()
    db = SessionLocal()
    try:
        result = apply_retention(db, settings.retention_clean_days, settings.retention_malicious_days)
    finally:
        db.close()
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "purged_body": result.get("purged_body", 0),
        "deleted": result.get("deleted", 0),
    }
    log.info("retention run: purged_body=%s deleted=%s", entry["purged_body"], entry["deleted"])
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        log.warning("could not append retention audit log: %s", e)
    return entry


def start_scheduler():

    import asyncio
    from ..config import get_settings
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger


    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    settings = get_settings()
    scheduler = AsyncIOScheduler(event_loop=loop)
    scheduler.add_job(
        run_retention_job,
        CronTrigger(hour=getattr(settings, "retention_hour", 3), minute=0),
        id="daily-retention",
        replace_existing=True,
    )
    minutes = getattr(settings, "mail_poll_minutes", 0) or 0
    if minutes > 0:
        from .mailbox_poll import poll_all_mailboxes
        scheduler.add_job(
            poll_all_mailboxes,
            IntervalTrigger(minutes=minutes),
            id="mailbox-poll",
            replace_existing=True,
        )
        log.info("scheduler: mailbox poll every %s min", minutes)
    scheduler.start()
    log.info("scheduler started: daily retention at %02d:00", getattr(settings, "retention_hour", 3))
    return scheduler
