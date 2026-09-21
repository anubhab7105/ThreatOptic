"""Retention: clean 7d metadata-only, malicious 90d then full delete (Rules.md).

Step 3: real batch deletion with per-batch commit/rollback across email
rows, analysis, traceability, ES docs, and graph nodes. Legacy rows that
still carry a raw body_text get it blanked; new rows never store raw
bodies at all (see pipeline).
"""
import logging
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from ...models import EmailRecord, AnalysisResult, TraceabilityData

log = logging.getLogger("retention")

BATCH = 500


def _utcnow():
    return datetime.now(timezone.utc)


def apply_retention(db: Session, clean_days: int = 7, malicious_days: int = 90) -> dict:
    now = _utcnow()
    clean_cut = now - timedelta(days=clean_days)
    mal_cut = now - timedelta(days=malicious_days)
    purged_body = 0
    deleted = 0
    from ..search.elastic_sync import delete_email
    from ..graph.store import remove_email_graph

    offset = 0
    while True:
        batch = (db.query(EmailRecord)
                 .filter(EmailRecord.timestamp < clean_cut)
                 .order_by(EmailRecord.timestamp)
                 .limit(BATCH).offset(offset).all())
        if not batch:
            break
        email_ids = [e.id for e in batch]
        analyses = {a.email_id: a for a in
                    db.query(AnalysisResult).filter(AnalysisResult.email_id.in_(email_ids)).all()}
        try:
            for e in batch:
                a = analyses.get(e.id)
                score = a.fraud_score if a else 0
                if score is None:
                    score = 0
                if score < 50:
                    if e.body_text or e.body_text_masked:
                        e.body_text = ""
                        e.body_text_masked = ""
                        purged_body += 1
                elif e.timestamp and (e.timestamp.replace(tzinfo=timezone.utc)
                                      if e.timestamp.tzinfo is None else e.timestamp) < mal_cut:
                    if e.body_text or e.body_text_masked:
                        purged_body += 1
                    if a:
                        db.delete(a)
                    db.query(TraceabilityData).filter(TraceabilityData.email_id == e.id).delete()
                    db.delete(e)
                    deleted += 1
                    delete_email(e.id)
                    try:
                        remove_email_graph(e.sender_address or "")
                    except Exception:
                        pass
            db.commit()
        except Exception:
            db.rollback()
            log.exception("retention batch failed, rolled back")
            raise
        offset += BATCH
    return {"purged_body": purged_body, "deleted": deleted}
