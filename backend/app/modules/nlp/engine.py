
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

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml_models")


PINNED_MODEL_PATH = os.path.abspath(os.path.join(MODEL_DIR, "phishing_clf.joblib"))
PINNED_SHA_PATH = PINNED_MODEL_PATH + ".sha256"


def _model_path() -> str:
    try:
        from ...config import get_settings
        dev = get_settings().is_development()
    except Exception:
        dev = True
    override = os.environ.get("NLP_MODEL_PATH", "").strip()
    if override and dev:
        import logging
        logging.getLogger("nlp").warning("using NLP_MODEL_PATH override (development only)")
        return override
    return PINNED_MODEL_PATH


def _verify_checksum(path: str) -> bool:

    import logging
    from ..model_trust import verify_model_artifact, ModelTrustError
    try:
        verify_model_artifact(path, purpose="nlp")
        return True
    except ModelTrustError as e:
        logging.getLogger("nlp").error("model trust failed — refusing to load: %s", e)
        return False


_classifier = None
_transformer_pipe = None


def warmup() -> None:

    _get_classifier()
    _get_transformer()


def _get_classifier():
    global _classifier
    if _classifier is not None:
        return _classifier
    path = _model_path()

    if not _verify_checksum(path):
        return None
    try:
        import joblib
        _classifier = joblib.load(path)
        return _classifier
    except Exception as e:
        import logging
        logging.getLogger("nlp").warning("nlp model load failed, using rule fallback: %s", e)
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


    ml_score = 0.0
    ml_label = "clean"
    clf = _get_classifier()
    if clf is not None:
        try:
            proba = clf.predict_proba([text])[0]
            classes = list(clf.classes_)

            best_i = int(proba.argmax())
            ml_label = str(classes[best_i])
            if "phish" in ml_label.lower() or "malic" in ml_label.lower() or "bec" in ml_label.lower():
                ml_score = float(proba[best_i])
            else:
                ml_score = float(1.0 - proba[best_i]) * 0.5 if len(proba) > 1 else 0.0
        except Exception:
            pass
    else:

        ml_score = min(0.95, 0.15 * len(urgency) + 0.25 * len(bec) + 0.2 * len(imperson) + 0.15 * len(cred))


    ml_score = _apply_transformer_rerank(text, ml_score)

    return {
        "urgency_cues": urgency,
        "impersonation_cues": imperson,
        "bec_cues": bec,
        "credential_cues": cred,
        "nlp_cues_detected": cues,
        "ml_score": round(ml_score, 4),
        "ml_label": ml_label,
    }


_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


def _get_transformer():

    global _transformer_pipe
    if _transformer_pipe is not None:
        return _transformer_pipe
    t_model = os.environ.get("TRANSFORMERS_MODEL", "").strip()
    if not t_model:
        return None
    try:
        from ...config import get_settings
        dev = get_settings().is_development()
    except Exception:
        dev = True
    t_rev = os.environ.get("TRANSFORMERS_REVISION", "").strip()
    if t_rev and not _REVISION_RE.match(t_rev):
        import logging
        logging.getLogger("nlp").error(
            "TRANSFORMERS_REVISION is not a 40-char commit hash — refusing transformer")
        return None
    if not t_rev:
        import logging
        if not dev:
            logging.getLogger("nlp").error(
                "TRANSFORMERS_MODEL without pinned TRANSFORMERS_REVISION — "
                "refusing transformer outside development")
            return None
        logging.getLogger("nlp").warning(
            "TRANSFORMERS_MODEL without pinned revision (development only)")
    try:
        from transformers import pipeline
        kwargs: dict[str, Any] = {"model": t_model}
        if t_rev:
            kwargs["revision"] = t_rev
        _transformer_pipe = pipeline("text-classification", **kwargs)
        return _transformer_pipe
    except Exception:
        return None


def _apply_transformer_rerank(text: str, ml_score: float) -> float:
    try:
        pipe = _get_transformer()
        if pipe is None:
            return ml_score
        r = pipe(text[:2000])[0]
        if "phish" in r["label"].lower() or r["label"].startswith("LABEL_1"):
            return max(ml_score, float(r["score"]))
    except Exception:
        pass
    return ml_score
