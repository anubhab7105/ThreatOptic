"""Weighted fraud-score ensemble (0-100) + Rules.md thresholds & behavioral rules."""
from typing import Any

WEIGHTS = {"nlp": 0.30, "auth": 0.25, "intel": 0.20, "routing": 0.15, "attachment": 0.10}


def _clamp(x: float) -> float:
    return max(0.0, min(100.0, x))


def compute_scores(nlp: dict, auth: dict, intel: dict, routing_flags: list[str], header_flags: list[str],
                    domain_age_days: int | None, contains_payment: bool,
                    attachment: dict | None = None) -> dict[str, Any]:
    nlp_score = float(nlp.get("ml_score", 0.0)) * 100.0
    # auth: pass=0 risk, fail/none partial
    spf = auth.get("spf", {}).get("status", "")
    dkim = auth.get("dkim", {}).get("status", "")
    dmarc = auth.get("dmarc", {}).get("status", "")
    fails = sum(1 for s in [spf, dkim] if s in ("fail", "softfail", "none"))
    auth_score = min(100.0, fails * 45.0 + (0 if auth.get("aligned") else 15.0))
    intel_score = min(100.0, 40.0 * intel.get("count", 0) + 35.0 * intel.get("malicious_count", 0))
    routing_score = min(100.0, 30.0 * len(routing_flags) + 20.0 * len(header_flags))
    attachment = attachment or {}
    attachment_score = min(100.0, max(0.0, float(attachment.get("risk", 0.0))))

    base = (WEIGHTS["nlp"] * nlp_score + WEIGHTS["auth"] * auth_score
            + WEIGHTS["intel"] * intel_score + WEIGHTS["routing"] * routing_score
            + WEIGHTS["attachment"] * attachment_score)

    extras: list[str] = []
    # Behavioral rule: new domain (<30d) + payment instructions => +30
    bonus = 0.0
    if domain_age_days is not None and domain_age_days < 30 and contains_payment:
        bonus = 30.0
        extras.append("new-domain+payment:+30")
    # SPF/DKIM fail + C-level claim => auto-escalate High
    c_level = any(k in str(nlp.get("impersonation_cues", [])).lower() for k in ["ceo", "cfo", "chief", "president"])
    force_high = False
    if spf in ("fail", "softfail") and dkim in ("fail",) and (c_level or "impersonation" in nlp.get("nlp_cues_detected", [])):
        force_high = True
        extras.append("exec-spoof-auth-fail:force-high")

    pre_clamp = base + bonus
    score = _clamp(pre_clamp)
    floor_bump = 0.0
    if force_high and score < 75:
        floor_bump = round(75.0 - score, 2)
        score = 75.0
    clamp_adj = round(score - (base + bonus + floor_bump), 2)

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

    # --- Explainable breakdown: per-signal contributions sum to fraud_score ---
    contrib = {
        "nlp": round(WEIGHTS["nlp"] * nlp_score, 2),
        "auth": round(WEIGHTS["auth"] * auth_score, 2),
        "intel": round(WEIGHTS["intel"] * intel_score, 2),
        "routing": round(WEIGHTS["routing"] * routing_score, 2),
        "attachment": round(WEIGHTS["attachment"] * attachment_score, 2),
    }
    signals: list[dict[str, Any]] = [
        {
            "signal_name": "nlp_text_classifier",
            "weight": WEIGHTS["nlp"],
            "value": round(nlp_score, 2),
            "contribution_to_score": contrib["nlp"],
            "detail": f"ML={nlp.get('ml_label')} ({nlp.get('ml_score')}); cues={nlp.get('nlp_cues_detected', [])}",
        },
        {
            "signal_name": "auth_spf_dkim_dmarc",
            "weight": WEIGHTS["auth"],
            "value": round(auth_score, 2),
            "contribution_to_score": contrib["auth"],
            "detail": f"SPF={spf or 'n/a'} DKIM={dkim or 'n/a'} DMARC={dmarc or 'n/a'} aligned={auth.get('aligned')}",
        },
        {
            "signal_name": "threat_intel",
            "weight": WEIGHTS["intel"],
            "value": round(intel_score, 2),
            "contribution_to_score": contrib["intel"],
            "detail": f"intel_hits={intel.get('count', 0)} malicious_urls={intel.get('malicious_count', 0)}",
        },
        {
            "signal_name": "routing_anomalies",
            "weight": WEIGHTS["routing"],
            "value": round(routing_score, 2),
            "contribution_to_score": contrib["routing"],
            "detail": f"routing={routing_flags or []} header={header_flags or []}",
        },
        {
            "signal_name": "attachment_risk",
            "weight": WEIGHTS["attachment"],
            "value": round(attachment_score, 2),
            "contribution_to_score": contrib["attachment"],
            "detail": f"suspicious_attachments={len((attachment or {}).get('findings', []))}",
        },
        {
            "signal_name": "new_domain_payment_rule",
            "weight": 1.0,
            "value": "+30" if bonus else "not fired",
            "contribution_to_score": bonus,
            "detail": f"domain_age_days={domain_age_days} contains_payment={contains_payment}",
        },
        {
            "signal_name": "exec_spoof_escalation",
            "weight": 1.0,
            "value": f"floor→75 (+{floor_bump})" if floor_bump else "not fired",
            "contribution_to_score": floor_bump,
            "detail": "SPF/DKIM fail + executive impersonation forces High risk",
        },
        {
            "signal_name": "score_clamp",
            "weight": 1.0,
            "value": "clamped 0–100",
            "contribution_to_score": clamp_adj,
            "detail": "final clamp into the 0–100 range",
        },
    ]

    return {
        "fraud_score": round(score, 2),
        "classification": classification,
        "threat_classification": threat_label,
        "action": action,
        "breakdown": {
            "nlp": round(nlp_score, 2), "auth": round(auth_score, 2),
            "intel": round(intel_score, 2), "routing": round(routing_score, 2),
            "attachment": round(attachment_score, 2),
        },
        "rules_fired": extras,
        "signals": signals,
    }
