"""Attachment/malware analysis tests (F6)."""
import asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app import models  # noqa
from app.modules.threat_intel.attachment_analyzer import (
    analyze_attachments,
    lookup_hash_virustotal,
    static_heuristics,
)
from app.modules.correlation.scoring import WEIGHTS, compute_scores


def test_macro_and_double_extension_flagged():
    assert "macro-enabled-document" in static_heuristics("invoice.docm", "application/vnd.ms-word.document.macroEnabled.12", "504b0304")
    assert "double-extension" in static_heuristics("report.pdf.exe", "application/octet-stream", "4d5a9000")
    assert "executable-attachment" in static_heuristics("update.scr", "application/octet-stream", "4d5a9000")


def test_clean_pdf_and_magic_mismatch():
    assert static_heuristics("notes.pdf", "application/pdf", "255044462d312e") == []
    assert any(r.startswith("magic-mismatch") for r in static_heuristics("notes.pdf", "application/pdf", "4d5a9000"))


def test_virustotal_skipped_without_key():
    assert lookup_hash_virustotal("ab" * 32) == {"source": "virustotal-file", "skipped": True}


def test_analyze_attachments_risk():
    res = analyze_attachments([
        {"filename": "a.pdf", "content_type": "application/pdf", "size": 10, "sha256": "00" * 32, "magic": "25504446"},
        {"filename": "payroll.docm", "content_type": "application/octet-stream", "size": 99, "sha256": "11" * 32, "magic": "504b0304"},
    ])
    assert res["risk"] >= 60.0
    assert len(res["findings"]) == 1 and res["findings"][0]["filename"] == "payroll.docm"
    clean = analyze_attachments([{"filename": "a.pdf", "content_type": "application/pdf", "size": 10, "sha256": "00" * 32, "magic": "25504446"}])
    assert clean == {"findings": [], "risk": 0.0, "malicious_count": 0}


def test_attachment_weight_in_score():
    nlp = {"ml_score": 0.0, "ml_label": "clean", "nlp_cues_detected": [], "impersonation_cues": []}
    auth = {"spf": {"status": "pass"}, "dkim": {"status": "pass"}, "dmarc": {"status": "found"}, "aligned": True}
    res = compute_scores(nlp, auth, {"count": 0, "malicious_count": 0}, [], [], None, False,
                         attachment={"risk": 100.0, "findings": [{}], "malicious_count": 0})
    assert WEIGHTS["attachment"] == 0.10
    sig = next(s for s in res["signals"] if s["signal_name"] == "attachment_risk")
    assert sig["contribution_to_score"] == 10.0
    assert res["breakdown"]["attachment"] == 100.0
    total = round(sum(s["contribution_to_score"] for s in res["signals"]), 2)
    assert abs(total - res["fraud_score"]) < 0.1


def test_pipeline_flags_macro_attachment():
    from app.services.pipeline import process_raw_email
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    db = sessionmaker(bind=eng)()
    raw = (b"From: a@b.com\r\nTo: c@d.com\r\nSubject: monthly report\r\n"
           b"Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n"
           b"--XYZ\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
           b"--XYZ\r\nContent-Type: application/octet-stream; name=report.docm\r\n"
           b"Content-Disposition: attachment; filename=report.docm\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\nUEsDBBQAAAAA\r\n--XYZ--\r\n")
    res = asyncio.run(process_raw_email(db, raw))
    row = db.query(models.AnalysisResult).filter(models.AnalysisResult.email_id == res["email_id"]).first()
    hits = [h for h in row.threat_intel_hits if h.get("type") == "attachment"]
    assert hits and "macro-enabled-document" in hits[0]["reasons"]
    sig = next(s for s in row.score_breakdown if s["signal_name"] == "attachment_risk")
    assert sig["contribution_to_score"] > 0
