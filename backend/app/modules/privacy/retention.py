"""Retention, per Rules.md "Data Retention".

- Clean traffic: metadata retained for 7 days, body dropped immediately.
  Once past `clean_days` the whole row goes, PII included.
- Suspicious/malicious traffic: retained for 90 days for forensic
  investigation, after which body content is purged, leaving only
  aggregated threat intel indicators in the Graph DB. The row itself is
  KEPT so those indicators stay attributable.

Step 3: real batch deletion with per-batch commit/rollback across email
rows, analysis, traceability and ES docs. Legacy rows that still carry a raw
body_text get it blanked; new rows never store raw bodies at all (see
pipeline).
"""
import logging
from datetime import timedelta
from sqlalchemy.orm import Session
from ...models import EmailRecord, AnalysisResult, TraceabilityData

log = logging.getLogger("retention")

BATCH = 500


def apply_retention(db: Session, clean_days: int = 7, malicious_days: int = 90, dry_run: bool = False) -> dict:
    from ...database import as_utc, utcnow
    # Fail closed on nonsensical windows: a negative value silently inverts
    # every cutoff and can delete the whole corpus.
    if clean_days < 0 or malicious_days < 0:
        raise ValueError("clean_days and malicious_days must be >= 0")
    now = utcnow()
    mal_cut = now - timedelta(days=malicious_days)
    # SQLite stores datetimes as naive ISO strings: bind a naive cutoff so
    # lexicographic comparison stays correct across naive/aware mixes.
    clean_cut_db = (now - timedelta(days=clean_days)).replace(tzinfo=None)
    purged_body = 0
    deleted = 0
    es_failed = 0
    from ..search.elastic_sync import delete_email

    # Keyset pagination (no offset) — offset + delete caused row skips.
    # We page by (timestamp, id) cursor so deletions never cause gaps.
    last_ts = None
    last_id = ""
    while True:
        q = db.query(EmailRecord).filter(EmailRecord.timestamp < clean_cut_db)
        if last_ts is not None:
            q = q.filter(
                (EmailRecord.timestamp > last_ts) |
                ((EmailRecord.timestamp == last_ts) & (EmailRecord.id > last_id))
            )
        batch = q.order_by(EmailRecord.timestamp, EmailRecord.id).limit(BATCH).all()
        if not batch:
            break
        email_ids = [e.id for e in batch]
        analyses = {a.email_id: a for a in
                    db.query(AnalysisResult).filter(AnalysisResult.email_id.in_(email_ids)).all()}
        # Next cursor candidate (applied only after commit)
        next_ts = batch[-1].timestamp
        next_id = batch[-1].id
        try:
            for e in batch:
                a = analyses.get(e.id)
                score = a.fraud_score if a else 0
                if score is None:
                    score = 0
                if score < 50:
                    # Rules.md: clean traffic keeps metadata for `clean_days`
                    # only. Past that window the row is deleted outright --
                    # subject, sender, recipients and headers are PII too, so
                    # blanking just the body left PII retained indefinitely.
                    if e.body_text or e.body_text_masked:
                        purged_body += 1
                    if not dry_run:
                        if a:
                            db.delete(a)
                        db.query(TraceabilityData).filter(TraceabilityData.email_id == e.id).delete()
                        db.delete(e)
                        if not delete_email(e.id).get("deleted"):
                            # The row is gone from Postgres but the doc may
                            # still be searchable in Elasticsearch. Surface it
                            # rather than silently leaving a deleted message
                            # retrievable.
                            es_failed += 1
                    deleted += 1
                elif e.timestamp and as_utc(e.timestamp) < mal_cut:
                    # Rules.md: malicious traffic is RETAINED for 90 days and
                    # then has only its body purged, leaving aggregated threat
                    # intel indicators in the Graph DB. Deleting the row (as
                    # this did previously) destroyed exactly the indicators
                    # the policy exists to preserve.
                    if e.body_text or e.body_text_masked:
                        purged_body += 1
                        if not dry_run:
                            e.body_text = ""
                            e.body_text_masked = ""
            if not dry_run:
                db.commit()
            last_ts = next_ts
            last_id = next_id
        except Exception:
            if not dry_run:
                db.rollback()
            log.exception("retention batch failed, rolled back")
            raise
    res = {"purged_body": purged_body, "deleted": deleted}
    if es_failed:
        res["es_delete_failed"] = es_failed
    if dry_run:
        res["dry_run"] = True
    return res
