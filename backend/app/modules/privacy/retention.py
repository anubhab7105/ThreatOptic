"""Retention: clean 7d metadata-only, malicious 90d then purge body (Rules.md)."""
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from ...models import EmailRecord, AnalysisResult


def apply_retention(db: Session, clean_days: int = 7, malicious_days: int = 90) -> dict:
    now = datetime.utcnow()
    clean_cut = now - timedelta(days=clean_days)
    mal_cut = now - timedelta(days=malicious_days)
    purged_body = 0
    deleted = 0
    # clean: drop body immediately after 7d -> keep metadata only
    # clean: drop body immediately after 7d -> keep metadata only
    records = db.query(EmailRecord).filter(EmailRecord.timestamp < clean_cut).all()
    if not records:
        return {"purged_body": 0, "deleted": 0}
    email_ids = [e.id for e in records]
    analyses = {a.email_id: a for a in db.query(AnalysisResult).filter(AnalysisResult.email_id.in_(email_ids)).all()}
    for e in records:
        a = analyses.get(e.id)
        score = a.fraud_score if a else 0
        if score < 50:
            if e.body_text or e.body_text_masked:
                e.body_text = ""
                e.body_text_masked = ""
                purged_body += 1
        else:
            if e.timestamp < mal_cut:
                if e.body_text or e.body_text_masked:
                    e.body_text = ""
                    e.body_text_masked = ""
                    purged_body += 1
    db.commit()
    return {"purged_body": purged_body, "deleted": deleted}
