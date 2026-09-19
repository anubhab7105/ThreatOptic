"""Weighted fraud-score ensemble (0-100) + Rules.md thresholds & behavioral rules."""
from typing import Any

WEIGHTS = {"nlp": 0.35, "auth": 0.25, "intel": 0.25, "routing": 0.15}


def _clamp(x: float) -> float:
    return max(0.0, min(100.0, x))


def compute_scores(nlp: dict, auth: dict, intel: dict, routing_flags: list[str], header_flags: list[str],
                    domain_age_days: int | None, contains_payment: bool) -> dict[str, Any]:
    nlp_score = float(nlp.get("ml_score", 0.0)) * 100.0
    # auth: pass=0 risk, fail/none partial
    spf = auth.get("spf", {}).get("status", "")
    dkim = auth.get("dkim", {}).get("status", "")
    dmarc = auth.get("dmarc", {}).get("status", "")
    fails = sum(1 for s in [spf, dkim] if s in ("fail", "softfail", "none"))
    auth_score = min(100.0, fails * 45.0 + (0 if auth.get("aligned") else 15.0))
    intel_score = min(100.0, 40.0 * intel.get("count", 0) + 35.0 * intel.get("malicious_count", 0))
    routing_score = min(100.0, 30.0 * len(routing_flags) + 20.0 * len(header_flags))

    base = (WEIGHTS["nlp"] * nlp_score + WEIGHTS["auth"] * auth_score
            + WEIGHTS["intel"] * intel_score + WEIGHTS["routing"] * routing_score)

    extras: list[str] = []
    # Behavioral rule: new domain (<30d) + payment instructions => +30
    if domain_age_days is not None and domain_age_days < 30 and contains_payment:
        base += 30
        extras.append("new-domain+payment:+30")
    # SPF/DKIM fail + C-level claim => auto-escalate High
    c_level = any(k in str(nlp.get("impersonation_cues", [])).lower() for k in ["ceo", "cfo", "chief", "president"])
    force_high = False
    if spf in ("fail", "softfail") and dkim in ("fail",) and (c_level or "impersonation" in nlp.get("nlp_cues_detected", [])):
        force_high = True
        extras.append("exec-spoof-auth-fail:force-high")

    score = _clamp(base)
    if force_high and score < 75:
        score = 75.0

    if score >= 90:
        classification, action = ("Critical", "Quarantine")
    elif score >= 75:
        classification, action = ("High", "JunkOrHold")
    elif score >= 50:
        classification, action = ("Medium", "DeliverWithBanner")
    elif score >= 20:
        classification, action = ("Low-Suspicious", "Deliver")
    else:
        classification, action = ("Clean", "Deliver")

    # map to schema threat_classification vocabulary
    threat_label = classification
    if "bec" in str(nlp.get("nlp_cues_detected", [])).lower():
        threat_label = f"BEC-{classification}"
    elif nlp.get("ml_label", "") not in ("", "clean"):
        threat_label = f"{nlp.get('ml_label')}-{classification}"

    return {
        "fraud_score": round(score, 2),
        "classification": classification,
        "threat_classification": threat_label,
        "action": action,
        "breakdown": {
            "nlp": round(nlp_score, 2), "auth": round(auth_score, 2),
            "intel": round(intel_score, 2), "routing": round(routing_score, 2),
        },
        "rules_fired": extras,
    }
