"""NLP engine: urgency cues, impersonation language, BEC patterns + sklearn classifier.

Design (per Techspec):
- rule-based cue extractors (fast, explainable, used in fraud score)
- TF-IDF + LogisticRegression classifier trained on curated phishing/BEC/clean samples
  (scripts/train_nlp.py). Falls back to rules if model file missing.
- Optional HuggingFace transformer if TRANSFORMERS_MODEL env set and libs installed.
"""
import os
import re
from typing import Any

URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\basap\b", r"\bright away\b",
    r"\bact now\b", r"\b expires?\b", r"\bdeadline\b", r"\blast chance\b",
    r"\bverify (your|account)\b", r"\bsuspended\b", r"\blocked\b",
    r"\bwire (transfer|payment)\b", r"\bpayment (due|overdue|required)\b",
    r"\bconfidential\b", r"\bdo not (tell|disclose|share)\b",
]
IMPERSONATION_PATTERNS = [
    r"\bceo\b", r"\bcfo\b", r"\bchief executive\b", r"\bpresident\b",
    r"\bboard of directors\b", r"\bhr department\b", r"\bit (department|support|helpdesk)\b",
    r"\bbank\b", r"\bsecurity team\b", r"\bon behalf of\b",
]
BEC_PATTERNS = [
    r"\bkindly\b.*\b(pay|transfer|wire|send)\b",
    r"\bplease (process|handle|pay).*(invoice|payment|wire)\b",
    r"\bchange.*bank (details|account|information)\b",
    r"\bgift ?cards?\b", r"\bitunes\b.*\bcards?\b",
    r"\bnew vendor\b", r"\bupdated.*remittance\b",
]
CREDENTIAL_PATTERNS = [r"\blogin\b", r"\bpassword\b", r"\bverify\b.*\baccount\b", r"\bclick (here|below)\b.*\blogin\b"]

MODEL_PATH = os.environ.get("NLP_MODEL_PATH", os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml_models", "phishing_clf.joblib"))

_classifier = None


def _get_classifier():
    global _classifier
    if _classifier is not None:
        return _classifier
    try:
        if os.path.exists(MODEL_PATH):
            import joblib
            _classifier = joblib.load(MODEL_PATH)
            return _classifier
    except Exception:
        pass
    return None


def _find(patterns: list[str], text: str) -> list[str]:
    found = []
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            found.append(p.strip(r"\b"))
    return found


def analyze_text(subject: str, body: str) -> dict[str, Any]:
    text = f"{subject}\n{body}"
    urgency = _find(URGENCY_PATTERNS, text)
    imperson = _find(IMPERSONATION_PATTERNS, text)
    bec = _find(BEC_PATTERNS, text)
    cred = _find(CREDENTIAL_PATTERNS, text)

    cues: list[str] = []
    if urgency:
        cues.append(f"urgency:{len(urgency)}")
    if imperson:
        cues.append("impersonation")
    if bec:
        cues.append("bec-pattern")
    if cred:
        cues.append("credential-harvest")

    # ML score
    ml_score = 0.0
    ml_label = "clean"
    clf = _get_classifier()
    if clf is not None:
        try:
            proba = clf.predict_proba([text])[0]
            classes = list(clf.classes_)
            # assume classes contain 'phishing'/'malicious'
            best_i = int(proba.argmax())
            ml_label = str(classes[best_i])
            if "phish" in ml_label.lower() or "malic" in ml_label.lower() or "bec" in ml_label.lower():
                ml_score = float(proba[best_i])
            else:
                ml_score = float(1.0 - proba[best_i]) * 0.5 if len(proba) > 1 else 0.0
        except Exception:
            pass
    else:
        # rule fallback score
        ml_score = min(0.95, 0.15 * len(urgency) + 0.25 * len(bec) + 0.2 * len(imperson) + 0.15 * len(cred))

    # Optional transformer rerank
    t_model = os.environ.get("TRANSFORMERS_MODEL", "")
    if t_model:
        try:
            from transformers import pipeline
            pipe = pipeline("text-classification", model=t_model)
            r = pipe(text[:2000])[0]
            if "phish" in r["label"].lower() or r["label"].startswith("LABEL_1"):
                ml_score = max(ml_score, float(r["score"]))
        except Exception:
            pass

    return {
        "urgency_cues": urgency,
        "impersonation_cues": imperson,
        "bec_cues": bec,
        "credential_cues": cred,
        "nlp_cues_detected": cues,
        "ml_score": round(ml_score, 4),
        "ml_label": ml_label,
    }
