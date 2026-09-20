"""Scheduled jobs (F9): daily data-retention enforcement with an audit trail.

Runs in-process via APScheduler so SQLite-first local dev needs no extra
infrastructure. Every run appends a JSONL line to retention_audit.log and
emits a structured log record: {timestamp, purged_body, deleted}.
"""
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
    """Daily 03:00 retention job. Returns the started scheduler.

    BackgroundScheduler (threads) is used instead of AsyncIOScheduler so the
    job also runs outside an event loop; the job itself is synchronous DB work.
    """
    from ..config import get_settings
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger

    settings = get_settings()
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_retention_job,
        CronTrigger(hour=getattr(settings, "retention_hour", 3), minute=0),
        id="daily-retention",
        replace_existing=True,
    )
    scheduler.start()
    log.info("scheduler started: daily retention at %02d:00", getattr(settings, "retention_hour", 3))
    return scheduler
