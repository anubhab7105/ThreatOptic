"""WHOIS + DNS/MX lookups. Offline-safe; live lookups only when ENABLE_LIVE_LOOKUPS=1."""
import os
from functools import lru_cache
from typing import Any


def _live() -> bool:
    if os.environ.get("ENABLE_LIVE_LOOKUPS", "").lower() in ("0", "false", "no"):
        return False
    try:
        from ...config import get_settings
        if get_settings().live_lookups:
            return True
    except Exception:
        pass
    return os.environ.get("ENABLE_LIVE_LOOKUPS", "0").lower() not in ("", "0", "false", "no")


@lru_cache(maxsize=1024)
def _whois_cached(domain: str) -> dict[str, Any]:
    try:
        import socket
        import whois
        # python-whois has no timeout parameter: run the blocking call in a
        # worker thread with join(timeout) instead of touching the process-
        # global socket.setdefaulttimeout (Step 4 — no global side effects).
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(whois.whois, domain)
            try:
                w = future.result(timeout=8)
            except concurrent.futures.TimeoutError:
                return {"domain": domain, "error": "whois-timeout"}
        creation = _stringify_date(w.creation_date)
        expiry = _stringify_date(w.expiration_date)
        return {
            "domain": domain,
            "registrar": str(w.registrar or ""),
            "creation_date": creation[:100],
            "expiration_date": expiry[:100],
            "name_servers": [str(x) for x in (w.name_servers or [])][:10],
        }
    except Exception as e:
        return {"domain": domain, "error": f"whois-unavailable: {e}"[:300]}


def _stringify_date(value: Any) -> str:
    """whois dates arrive as datetime | list[datetime] | str | None."""
    from datetime import datetime
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def whois_lookup(domain: str) -> dict[str, Any]:
    domain = (domain or "").strip().lower().lstrip("<>").split("@")[-1].strip(" <>")
    if not domain or "." not in domain:
        return {}
    if not _live():
        return {"domain": domain, "note": "live-lookups-disabled"}
    return dict(_whois_cached(domain))


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
    """Best-effort parse of creation_date to days. None if unknown.

    Handles date, datetime, ISO-Z strings, and list-valued whois fields.
    """
    from datetime import datetime, timezone
    raw_val = whois_data.get("creation_date", "")
    if isinstance(raw_val, (list, tuple)):
        raw_val = raw_val[0] if raw_val else ""
    raw = str(raw_val).strip()[:30]
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    try:  # full ISO first (covers offsets and fractional seconds)
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        pass
    for fmt, width in (("%Y-%m-%d", 10), ("%Y-%m-%d %H:%M:%S", 19), ("%Y-%m-%dT%H:%M:%S", 19)):
        try:
            dt = datetime.strptime(raw[:width], fmt).replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - dt).days
        except Exception:
            continue
    return None
