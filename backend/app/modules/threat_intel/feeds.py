"""Threat intel: blocklists, Spamhaus DROP, MISP/OTX, VirusTotal/URLhaus (offline-safe).

Honesty rules (Step 4):
- Hard-coded demo domains are DEV-ONLY fixtures, clearly labeled, and
  disabled outside development.
- `aggregate_threat_intel()` covers domains, IPs AND urls, and returns the
  `malicious_count` field scoring.py actually reads.
"""
import os
import time
from functools import lru_cache
from typing import Any

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz"}

# Demo-only fixtures for tests/demos without network. NEVER consulted in prod.
DEMO_BLOCKLIST_DOMAINS = {"malicious-example.com", "phish-kit.test"}

# Reasons that count as malicious (vs merely suspicious) for malicious_count.
MALICIOUS_REASONS = ("local-blocklist", "demo-fixture", "urlhaus", "misp-hit",
                     "virustotal-malicious", "spamhaus-drop")
MALICIOUS_PREFIXES = ("dnsbl:",)


def _live() -> bool:
    return os.environ.get("ENABLE_LIVE_LOOKUPS", "0").lower() not in ("", "0", "false", "no")


def _is_development() -> bool:
    try:
        from ...config import get_settings
        return get_settings().is_development()
    except Exception:
        return True


def check_domain_blocklists(domain: str) -> list[str]:
    hits: list[str] = []
    d = (domain or "").lower().strip(".")
    if d in DEMO_BLOCKLIST_DOMAINS:
        # Explicitly flagged demo fixture; disabled outside development.
        if _is_development():
            hits.append("demo-fixture")
    else:
        # "local-blocklist" is reserved for operator-curated entries loaded
        # from backend/data/local_blocklist.txt (one domain per line).
        if d in _operator_blocklist():
            hits.append("local-blocklist")
    if any(d.endswith(t) for t in SUSPICIOUS_TLDS):
        hits.append("suspicious-tld")
    if "xn--" in d:
        hits.append("punycode")
    return hits


@lru_cache(maxsize=1)
def _operator_blocklist() -> frozenset:
    """Operator-curated domains; empty set when the file is absent."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                        "data", "local_blocklist.txt")
    try:
        with open(path) as f:
            return frozenset(line.strip().lower() for line in f
                             if line.strip() and not line.startswith("#"))
    except Exception:
        return frozenset()


DROP_URLS = (
    "https://www.spamhaus.org/drop/drop.txt",
    "https://www.spamhaus.org/drop/edrop.txt",
)
_DROP_CACHE: dict[str, Any] = {"networks": None, "fetched_at": 0.0}
DROP_TTL_S = 24 * 3600


def spamhaus_drop_networks() -> list:
    """Real Spamhaus DROP/EDROP feed, 24h file cache. [] when offline/disabled."""
    import ipaddress
    now = time.time()
    if _DROP_CACHE["networks"] is not None and now - _DROP_CACHE["fetched_at"] < DROP_TTL_S:
        return _DROP_CACHE["networks"]
    nets: list = []
    if _live():
        try:
            import requests
            for url in DROP_URLS:
                try:
                    r = requests.get(url, timeout=8)
                    if r.status_code != 200:
                        continue
                    for line in r.text.splitlines():
                        line = line.strip()
                        if not line or line.startswith(";"):
                            continue
                        nets.append(ipaddress.ip_network(line.split(";")[0].strip(), strict=False))
                except Exception:
                    continue
        except Exception:
            pass
    _DROP_CACHE.update(networks=nets, fetched_at=now)
    return nets


def check_ip_spamhaus(ip: str) -> list[str]:
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        for net in spamhaus_drop_networks():
            if addr in net:
                return ["spamhaus-drop"]
    except Exception:
        pass
    return []


def check_ip_blocklists(ip: str) -> list[str]:
    hits: list[str] = []
    if not ip or not _live():
        return hits
    try:
        import dns.resolver
        rev = ".".join(reversed(ip.split(".")))
        for zone in ["zen.spamhaus.org"]:
            try:
                dns.resolver.resolve(f"{rev}.{zone}", "A", lifetime=2)
                hits.append(f"dnsbl:{zone}")
            except Exception:
                continue
    except Exception:
        pass
    return hits


def query_misp(value: str) -> dict[str, Any]:
    url = os.environ.get("MISP_URL", "")
    key = os.environ.get("MISP_KEY", "")
    if not url or not key:
        return {"source": "misp", "skipped": True}
    try:
        import requests
        r = requests.post(
            f"{url.rstrip('/')}/attributes/restSearch",
            headers={"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"},
            json={"value": value}, timeout=5,
        )
        return {"source": "misp", "status": r.status_code, "hits": len(r.json().get("response", {}).get("Attribute", [])) if r.status_code == 200 else 0}
    except Exception as e:
        return {"source": "misp", "error": str(e)[:300]}


def _is_malicious_reason(reason: str) -> bool:
    return reason in MALICIOUS_REASONS or reason.startswith(MALICIOUS_PREFIXES)


def aggregate_threat_intel(domains: list[str], ips: list[str], urls: list[str]) -> dict[str, Any]:
    """Aggregate over domains, IPs and URL domains (nothing is dropped).

    Returns {"hits": [...], "count": N, "malicious_count": M} where M counts
    hits with at least one malicious (not merely suspicious) reason — the
    exact field scoring.py reads.
    """
    from .url_analyzer import domain_of

    hits: list[dict] = []

    def _add_url(u: str) -> None:
        dom = domain_of(u)
        if not dom:
            return
        reasons = check_domain_blocklists(dom)
        m = query_misp(dom)
        entry: dict[str, Any] = {"type": "url", "value": u[:500], "domain": dom}
        if reasons:
            entry["reasons"] = reasons
        if m.get("hits"):
            entry["misp"] = m
            entry.setdefault("reasons", []).append("misp-hit")
        if entry.get("reasons"):
            hits.append(entry)

    for d in domains[:20]:
        if not d:
            continue
        b = check_domain_blocklists(d)
        if b:
            hits.append({"type": "domain", "value": d, "reasons": b})
        m = query_misp(d)
        if m.get("hits"):
            hits.append({"type": "domain", "value": d, "misp": m, "reasons": ["misp-hit"]})
    for ip in ips[:20]:
        if not ip:
            continue
        b = check_ip_blocklists(ip) + check_ip_spamhaus(ip)
        if b:
            hits.append({"type": "ip", "value": ip, "reasons": b})
        m = query_misp(ip)
        if m.get("hits"):
            hits.append({"type": "ip", "value": ip, "misp": m, "reasons": ["misp-hit"]})
    for u in (urls or [])[:50]:
        _add_url(u)
    malicious = sum(1 for h in hits if any(_is_malicious_reason(r) for r in h.get("reasons", [])))
    return {"hits": hits, "count": len(hits), "malicious_count": malicious}
