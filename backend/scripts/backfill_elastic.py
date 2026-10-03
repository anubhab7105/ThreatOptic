"""Elasticsearch Reindex / Backfill CLI Tool (Fix #7).

Backfills email records from the database into Elasticsearch when operators
connect or rebuild an Elasticsearch cluster.
Usage:
    python backend/scripts/backfill_elastic.py [--batch-size 500] [--limit 1000] [--dry-run]
"""
import argparse
import logging
import os
import sys

# Ensure backend root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("backfill_elastic")


def backfill(batch_size: int = 500, limit: int | None = None, dry_run: bool = False) -> int:
    from app.config import get_settings
    from app.database import SessionLocal
    from app import models
    from app.modules.privacy.masking import mask_text
    from app.modules.search.elastic_sync import _client, index_email

    settings = get_settings()
    if not settings.elasticsearch_url and not dry_run:
        log.error("ELASTICSEARCH_URL is not configured. Set ELASTICSEARCH_URL or run with --dry-run.")
        return 1

    if not dry_run:
        client = _client()
        if client is None:
            log.error("Failed to connect to Elasticsearch. Verify host credentials and network reachability.")
            return 1

    log.info("Starting Elasticsearch backfill (batch_size=%d, limit=%s, dry_run=%s)",
             batch_size, limit, dry_run)

    db = SessionLocal()
    total_indexed = 0
    total_failed = 0
    last_ts = None
    last_id = ""

    try:
        while True:
            q = db.query(models.EmailRecord)
            if last_ts is not None:
                q = q.filter(
                    (models.EmailRecord.timestamp > last_ts) |
                    ((models.EmailRecord.timestamp == last_ts) & (models.EmailRecord.id > last_id))
                )
            remaining = (limit - total_indexed) if limit is not None else batch_size
            fetch_size = min(batch_size, remaining) if limit is not None else batch_size
            if fetch_size <= 0:
                break

            batch = q.order_by(models.EmailRecord.timestamp, models.EmailRecord.id).limit(fetch_size).all()
            if not batch:
                break

            email_ids = [e.id for e in batch]
            analyses = {
                a.email_id: a
                for a in db.query(models.AnalysisResult).filter(models.AnalysisResult.email_id.in_(email_ids)).all()
            }

            for record in batch:
                analysis = analyses.get(record.id)
                email_doc = {
                    "subject": mask_text(record.subject or ""),
                    "sender_address": mask_text(record.sender_address or ""),
                    "recipient_address": mask_text(record.recipient_address or ""),
                    "body_text_masked": record.body_text_masked or "",
                    "organization_id": record.organization_id,
                }
                analysis_doc = {
                    "fraud_score": getattr(analysis, "fraud_score", 0) or 0,
                    "threat_classification": getattr(analysis, "threat_classification", "") or "",
                }

                if dry_run:
                    total_indexed += 1
                else:
                    res = index_email(record.id, email_doc, analysis_doc)
                    if res.get("indexed"):
                        total_indexed += 1
                    else:
                        total_failed += 1
                        log.warning("Failed to index %s: %s", record.id, res.get("error", "unknown"))

            last_ts = batch[-1].timestamp
            last_id = batch[-1].id
            log.info("Processed %d records (total indexed: %d, failed: %d)",
                     len(batch), total_indexed, total_failed)

            if limit is not None and total_indexed >= limit:
                break

    finally:
        db.close()

    log.info("Backfill completed. Indexed: %d, Failed: %d (dry_run=%s)",
             total_indexed, total_failed, dry_run)
    return 0


def main():
    parser = argparse.ArgumentParser(description="Backfill emails to Elasticsearch.")
    parser.add_argument("--batch-size", type=int, default=500, help="Batch size for DB querying (default: 500)")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of records to backfill")
    parser.add_argument("--dry-run", action="store_true", help="Scan and count records without sending to Elasticsearch")
    args = parser.parse_args()
    sys.exit(backfill(batch_size=args.batch_size, limit=args.limit, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
