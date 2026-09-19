"""WHOIS + DNS/MX lookups. Offline-safe; live lookups only when ENABLE_LIVE_LOOKUPS=1."""
import os
import socket
from functools import lru_cache
from typing import Any


def _live() -> bool:
    return os.environ.get("ENABLE_LIVE_LOOKUPS", "0").lower() not in ("", "0", "false", "no")


def whois_lookup(domain: str) -> dict[str, Any]:
    domain = (domain or "").strip().lower().lstrip("<>").split("@")[-1].strip(" <>")
    if not domain or "." not in domain:
        return {}
    if not _live():
        return {"domain": domain, "note": "live-lookups-disabled"}
    try:
        import whois
        # python-whois has no timeout; run with a socket-level guard.
        socket.setdefaulttimeout(4)
        try:
            w = whois.whois(domain)
        finally:
            socket.setdefaulttimeout(None)
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


@lru_cache(maxsize=1024)
def dns_lookup(domain: str) -> dict[str, Any]:
    domain = (domain or "").strip().lower().split("@")[-1].strip(" <>")
    out: dict[str, Any] = {"domain": domain, "mx": [], "a": [], "txt_spf": ""}
    if not domain or "." not in domain:
        return out
    if not _live():
        return out
    try:
        import dns.resolver
        try:
            mx = dns.resolver.resolve(domain, "MX", lifetime=2)
            out["mx"] = sorted([f"{r.preference} {r.exchange}" for r in mx])[:10]
        except Exception:
            pass
        try:
            a = dns.resolver.resolve(domain, "A", lifetime=2)
            out["a"] = [r.to_text() for r in a][:10]
        except Exception:
            pass
        try:
            txt = dns.resolver.resolve(domain, "TXT", lifetime=2)
            txts = [b"".join(r.strings).decode(errors="ignore") for r in txt]
            out["txt_spf"] = next((t for t in txts if "v=spf1" in t), "")[:500]
        except Exception:
            pass
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
