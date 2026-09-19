"""WHOIS + DNS/MX lookups (Tracker Phase 2). Offline-safe with timeouts."""
from typing import Any
import socket


def whois_lookup(domain: str) -> dict[str, Any]:
    domain = (domain or "").strip().lower().lstrip("<>").split("@")[-1].strip(" <>")
    if not domain or "." not in domain:
        return {}
    try:
        import whois
        w = whois.whois(domain)
        creation = str(w.creation_date) if w.creation_date else ""
        return {
            "domain": domain,
            "registrar": str(w.registrar or ""),
            "creation_date": creation[:100],
            "expiration_date": str(w.expiration_date)[:100] if w.expiration_date else "",
            "name_servers": [str(x) for x in (w.name_servers or [])][:10],
        }
    except Exception as e:
        return {"domain": domain, "error": f"whois-unavailable: {e}"[:300]}


def dns_lookup(domain: str) -> dict[str, Any]:
    domain = (domain or "").strip().lower().split("@")[-1].strip(" <>")
    out: dict[str, Any] = {"domain": domain, "mx": [], "a": [], "txt_spf": ""}
    if not domain or "." not in domain:
        return out
    try:
        import dns.resolver
        try:
            mx = dns.resolver.resolve(domain, "MX", lifetime=5)
            out["mx"] = sorted([f"{r.preference} {r.exchange}" for r in mx])[:10]
        except Exception:
            pass
        try:
            a = dns.resolver.resolve(domain, "A", lifetime=5)
            out["a"] = [r.to_text() for r in a][:10]
        except Exception:
            pass
        try:
            txt = dns.resolver.resolve(domain, "TXT", lifetime=5)
            txts = [b"".join(r.strings).decode(errors="ignore") for r in txt]
            out["txt_spf"] = next((t for t in txts if "v=spf1" in t), "")[:500]
        except Exception:
            pass
    except Exception:
        pass
    # socket fallback for A
    if not out["a"]:
        try:
            out["a"] = [socket.gethostbyname(domain)]
        except Exception:
            pass
    return out


def domain_age_days(whois_data: dict) -> int | None:
    """Best-effort parse of creation_date to days. None if unknown."""
    from datetime import datetime, timezone
    raw = str(whois_data.get("creation_date", ""))[:100]
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(raw[: len(fmt)], fmt).replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - dt).days
        except Exception:
            continue
    return None
