
import os
os.environ.setdefault("MODEL_TRUST_INSECURE", "1")
from app.modules.nlp.engine import analyze_text


def test_phish_cues_and_score():
    r = analyze_text(
        "Urgent: verify your account now",
        "Your account will be suspended. Click here to verify your password immediately.",
    )
    assert any(c.startswith("urgency") for c in r["nlp_cues_detected"])
    assert "credential-harvest" in r["nlp_cues_detected"]
    assert 0.0 <= r["ml_score"] <= 1.0




def test_clean_text_scores_low():
    r = analyze_text("Lunch tomorrow?", "Hi Bob, lunch tomorrow at noon? Let me know if the cafeteria works.")
    assert r["ml_label"] == "clean"
    assert r["ml_score"] < 0.5


def test_bec_and_impersonation_cues():
    r = analyze_text("Quick favor", "Kindly wire $9000 to the new vendor bank details, keep this confidential - CEO")
    assert "bec-pattern" in r["nlp_cues_detected"]
    assert "impersonation" in r["nlp_cues_detected"]


def test_empty_input_never_crashes():
    r = analyze_text("", "")
    assert r["nlp_cues_detected"] == [] and isinstance(r["ml_score"], float)
