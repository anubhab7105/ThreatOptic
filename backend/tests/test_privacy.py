
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app import models
from app.modules.privacy.chain_of_custody import custody_manifest
from app.modules.privacy.masking import mask_text
from app.modules.privacy.retention import apply_retention


def test_masking_kinds():
    assert "[SSN-REDACTED]" in mask_text("ssn 123-45-6789 here")
    assert "[PHONE-REDACTED]" in mask_text("call +1 (555) 123-4567 now")
    assert "[PHONE-REDACTED]" in mask_text("ring +44 20 7946 0958 today")

    assert "1234567890123" in mask_text("ref 1234567890123 closed")
    assert "1234567890" in mask_text("ticket 1234567890 closed")
    assert mask_text("") == ""


def _db():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    return sessionmaker(bind=eng)()


def test_retention_purges_old_clean_body_only():
    db = _db()
    old = models.EmailRecord(subject="old", body_text="sensitive body",
                             timestamp=datetime.utcnow() - timedelta(days=30))
    new = models.EmailRecord(subject="new", body_text="keep me")
    db.add_all([old, new])
    db.flush()
    db.add(models.AnalysisResult(email_id=old.id, fraud_score=10.0))
    db.add(models.AnalysisResult(email_id=new.id, fraud_score=95.0))
    db.commit()
    out = apply_retention(db, clean_days=7, malicious_days=90)
    assert out == {"purged_body": 1, "deleted": 0}
    assert db.get(models.EmailRecord, old.id).body_text == ""
    assert db.get(models.EmailRecord, new.id).body_text == "keep me"


def test_custody_tamper_evidence():
    a = custody_manifest("emlhash", b"report-v1")
    b = custody_manifest("emlhash", b"report-v2")
    assert a["signature"] != b["signature"]
    assert len(a["signature"]) == 64 and a["eml_sha256"] == "emlhash"
