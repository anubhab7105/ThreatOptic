"""Attribution: confidence-based assessment linking email to known campaigns."""
from typing import Any
from .store import related_entities, find_campaigns


def attribute(email_addr: str, ip: str, domains: list[str]) -> dict[str, Any]:
    signals: list[str] = []
    confidence = 0.0
    campaign = None
    # shared infrastructure
    for c in find_campaigns():
        overlap = set(d.lower() for d in domains) & set((c.get("domains") or []))
        if overlap:
            campaign = f"infra-share:{c['ip']}"
            confidence += 0.4
            signals.append(f"shares-ip-{c['ip']}")
        if c.get("ip") == ip and domains:
            campaign = campaign or f"known-ip:{ip}"
            confidence += 0.3
            signals.append("known-malicious-ip")
    rel = related_entities(email_addr or ip or (domains[0] if domains else ""))
    if rel["nodes"]:
        confidence += min(0.3, 0.05 * len(rel["nodes"]))
        signals.append(f"graph-neighbours:{len(rel['nodes'])}")
    return {
        "campaign": campaign or "unknown",
        "confidence": round(min(0.99, confidence), 3),
        "signals": signals,
        "related": rel,
    }
