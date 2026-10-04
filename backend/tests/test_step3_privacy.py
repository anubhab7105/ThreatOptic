"""Step 3 privacy: no raw bodies persisted, masked reports, safe search, real deletion."""
import uuid
from datetime import datetime, timedelta

from fastapi.testclient import TestClient
from helpers import login

from app import models



def _session():
    """Fresh session from the (possibly test-rebound) sessionmaker."""
    from app.database import SessionLocal
    return SessionLocal()


def _auth(c: TestClient, role: str = "Analyst") -> dict:
    return login(role=role)[0]


def test_raw_body_never_persisted():
    from app.main import app

    with TestClient(app) as c:
        h = _auth(c)
        raw = ("From: a@b.test\nTo: c@d.test\nSubject: card inside\n\n"
               "my card 4111 1111 1111 1111 please charge it")
        eid = c.post("/api/v1/emails/ingest", headers=h, json={"raw": raw}).json()["email_id"]
        db = _session()
        try:
            row = db.query(models.EmailRecord).filter_by(id=eid).first()
            assert row.body_text == ""
            assert "[CARD-REDACTED]" in row.body_text_masked
            assert "4111" not in row.body_text_masked
        finally:
            db.close()


def test_report_returns_masked_only():
    from app.main import app

    with TestClient(app) as c:
        h = _auth(c)
        raw = ("From: alice@b.test\nTo: c@d.test\nSubject: <script>alert(1)</script> card 4111 1111 1111 1111\n\n"
               "body 4111 1111 1111 1111")
        eid = c.post("/api/v1/emails/ingest", headers=h, json={"raw": raw}).json()["email_id"]
        body = c.get(f"/api/v1/reports/{eid}.json", headers=h).json()
        dumped = __import__("json").dumps(body)
        assert "4111" not in dumped
        assert "[CARD-REDACTED]" in dumped
        # PDF builds with markup subject (no ReportLab crash)
        pdf = c.get(f"/api/v1/reports/{eid}.pdf", headers=h)
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")


def test_search_none_db_and_wildcard_escape():
    from app.modules.search.elastic_sync import search_emails
    from app.sql_utils import escape_like
    assert escape_like("%_\\") == "\\%\\_\\\\"
    assert search_emails("anything", db=None, organization_id="org-1") == {"backend": "none", "hits": []}

    from app.main import app
    with TestClient(app) as c:
        h = _auth(c)
        marker = f"zzq-{uuid.uuid4().hex[:6]}"
        c.post("/api/v1/emails/ingest", headers=h,
               json={"raw": f"From: a@b.test\nSubject: {marker} 100% coverage\n\nplain"})
        hits = c.get("/api/v1/search", headers=h, params={"q": "100%"}).json()["hits"]
        assert any(marker in (hit.get("email") or {}).get("subject", "") for hit in hits)
        # a lone wildcard must not become a full scan: only literal-% rows match
        wild = c.get("/api/v1/search", headers=h, params={"q": "%"}).json()["hits"]
        assert all("%" in (hit.get("email") or {}).get("subject", "") for hit in wild)


def test_retention_deletes_expired_clean_and_keeps_malicious():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base

    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    db = sessionmaker(bind=eng)()
    old_bad = models.EmailRecord(subject="bad", body_text="x", body_text_masked="y",
                                 timestamp=datetime.utcnow() - timedelta(days=100))
    old_clean = models.EmailRecord(subject="ok", body_text="keep?", body_text_masked="keep?",
                                   timestamp=datetime.utcnow() - timedelta(days=30))
    db.add_all([old_bad, old_clean])
    db.flush()
    db.add(models.AnalysisResult(email_id=old_bad.id, fraud_score=95.0))
    db.add(models.AnalysisResult(email_id=old_clean.id, fraud_score=10.0))
    db.add(models.TraceabilityData(email_id=old_clean.id, origin_ip="9.9.9.9"))
    db.commit()

    # Rules.md: expired CLEAN metadata is deleted outright (the row, its
    # analysis and its traceability), while expired MALICIOUS traffic keeps
    # its row so the aggregated Graph DB indicators stay attributable and
    # only has its body purged.
    from app.modules.privacy.retention import apply_retention
    out = apply_retention(db, clean_days=7, malicious_days=90)
    assert out["deleted"] == 1 and out["purged_body"] >= 1
    assert db.get(models.EmailRecord, old_clean.id) is None
    assert db.query(models.AnalysisResult).filter_by(email_id=old_clean.id).count() == 0
    assert db.query(models.TraceabilityData).filter_by(email_id=old_clean.id).count() == 0
    kept = db.get(models.EmailRecord, old_bad.id)
    assert kept is not None and kept.body_text == "" and kept.subject == "bad"
