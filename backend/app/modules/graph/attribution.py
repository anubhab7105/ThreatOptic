
from typing import Any
from .store import related_entities, find_campaigns

W_ATTRIBUTION = {"infra": 0.45, "known_ip": 0.30, "density": 0.25}
_DENSITY_CAP = 12


def attribute(email_addr: str, ip: str, domains: list[str]) -> dict[str, Any]:
    signals: list[str] = []
    email_addr = (email_addr or "").lower()
    ip = (ip or "").strip()
    domains = [(d or "").lower().strip(".") for d in (domains or []) if d]
    domain_set = set(domains)

    best_campaign: str | None = None
    best_infra = 0.0
    known_ip = False
    for c in find_campaigns():
        c_domains = {str(d).lower().strip(".") for d in (c.get("domains") or []) if d}
        c_ip = str(c.get("ip") or "")
        if domain_set and c_domains:
            overlap = len(domain_set & c_domains) / max(len(domain_set | c_domains), 1)
            if overlap > best_infra:
                best_infra = overlap
                best_campaign = f"infra-share:{c_ip}" if c_ip else "infra-share:unknown-ip"
                signals = [s for s in signals if not s.startswith(("shares-ip-", "overlap="))]
                signals.append(f"shares-ip-{c_ip}" if c_ip else "shares-infra")
                signals.append(f"overlap={overlap:.2f}")
        if c_ip and ip and c_ip == ip:
            known_ip = True
    if known_ip:
        signals.append(f"known-malicious-ip:{ip}")
        best_campaign = best_campaign or f"known-ip:{ip}"

    rel = related_entities(email_addr or ip or (domains[0] if domains else ""))
    neighbours = len(rel.get("nodes", []))
    density = min(1.0, neighbours / _DENSITY_CAP) if neighbours else 0.0
    if neighbours:
        signals.append(f"graph-neighbours:{neighbours}")

    confidence = (
        W_ATTRIBUTION["infra"] * best_infra
        + W_ATTRIBUTION["known_ip"] * (1.0 if known_ip else 0.0)
        + W_ATTRIBUTION["density"] * density
    )
    return {
        "campaign": best_campaign or "unknown",
        "confidence": round(min(0.99, confidence), 3),
        "signals": signals,
        "related": rel,
    }
