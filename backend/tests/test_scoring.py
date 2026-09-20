"""Explainable scoring tests: signal schema, contributions sum to fraud_score."""
import asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app import models  # noqa
from app.modules.correlation.scoring import compute_scores
from app.services.pipeline import process_raw_email

REQUIRED_KEYS = {"signal_name", "weight", "value", "contribution_to_score"}


def _base_nlp():
    return {"ml_score": 0.8, "ml_label": "phishing",
            "nlp_cues_detected": ["urgency:2", "bec-pattern"],
            "impersonation_cues": ["ceo"]}


def _base_auth(spf="fail", dkim="fail"):
    return {"spf": {"status": spf}, "dkim": {"status": dkim},
            "dmarc": {"status": "none"}, "aligned": False}


def test_signals_sum_to_score():
    intel = {"count": 2, "malicious_count": 1}
    res = compute_scores(_base_nlp(), _base_auth(), intel, ["single-hop-suspicious"], ["reply-to-mismatch"], 10, True)
    assert "signals" in res and len(res["signals"]) == 7
    for s in res["signals"]:
        assert REQUIRED_KEYS <= set(s), s
    total = round(sum(s["contribution_to_score"] for s in res["signals"]), 2)
    assert abs(total - res["fraud_score"]) < 0.1, (total, res["fraud_score"])
    # new-domain + payment bonus fired
    bonus = next(s for s in res["signals"] if s["signal_name"] == "new_domain_payment_rule")
    assert bonus["contribution_to_score"] == 30.0
    assert res["fraud_score"] >= 75  # exec-spoof floor also fires here


def test_clean_email_zero_breakdown():
    nlp = {"ml_score": 0.0, "ml_label": "clean", "nlp_cues_detected": [], "impersonation_cues": []}
    auth = {"spf": {"status": "pass"}, "dkim": {"status": "pass"},
            "dmarc": {"status": "found"}, "aligned": True}
    res = compute_scores(nlp, auth, {"count": 0, "malicious_count": 0}, [], [], None, False)
    total = round(sum(s["contribution_to_score"] for s in res["signals"]), 2)
    assert abs(total - res["fraud_score"]) < 0.1
    assert res["fraud_score"] < 20
    assert all(s["contribution_to_score"] == 0 for s in res["signals"] if s["signal_name"] in
               ("new_domain_payment_rule", "exec_spoof_escalation"))


def test_clamp_adjustment_nonpositive():
    nlp = {"ml_score": 1.0, "ml_label": "phishing",
           "nlp_cues_detected": ["urgency:5"], "impersonation_cues": []}
    res = compute_scores(nlp, _base_auth(), {"count": 5, "malicious_count": 5},
                         ["a", "b", "c"], ["d", "e"], 5, True)
    clamp = next(s for s in res["signals"] if s["signal_name"] == "score_clamp")
    assert clamp["contribution_to_score"] <= 0
    assert res["fraud_score"] == 100.0
    total = round(sum(s["contribution_to_score"] for s in res["signals"]), 2)
    assert abs(total - 100.0) < 0.1


def test_pipeline_persists_breakdown():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    db = sessionmaker(bind=eng)()
    raw = b"From: x@y.top\nTo: z@w.com\nSubject: Urgent wire\n\nKindly wire money now http://malicious-example.com/p"
    res = asyncio.run(process_raw_email(db, raw))
    assert res["signals"] and len(res["signals"]) == 7
    row = db.query(models.AnalysisResult).filter(models.AnalysisResult.email_id == res["email_id"]).first()
    assert row is not None and len(row.score_breakdown) == 7
    total = round(sum(s["contribution_to_score"] for s in row.score_breakdown), 2)
    assert abs(total - row.fraud_score) < 0.1
