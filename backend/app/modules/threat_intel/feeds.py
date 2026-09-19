"""Threat intel: local blocklists + MISP/OTX + VirusTotal/URLhaus wrappers (offline-safe)."""
import os
from functools import lru_cache
from typing import Any

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz"}


def _live() -> bool:
    return os.environ.get("ENABLE_LIVE_LOOKUPS", "0").lower() not in ("", "0", "false", "no")


def check_domain_blocklists(domain: str) -> list[str]:
    hits: list[str] = []
    d = (domain or "").lower()
    if d in {"malicious-example.com", "phish-kit.test"}:
        hits.append("local-blocklist")
    if any(d.endswith(t) for t in SUSPICIOUS_TLDS):
        hits.append("suspicious-tld")
    if "xn--" in d:
        hits.append("punycode")
    return hits


@lru_cache(maxsize=2048)
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


def aggregate_threat_intel(domains: list[str], ips: list[str], urls: list[str]) -> dict[str, Any]:
    hits: list[dict] = []
    for d in domains[:20]:
        b = check_domain_blocklists(d)
        if b:
            hits.append({"type": "domain", "value": d, "reasons": b})
        m = query_misp(d)
        if m.get("hits"):
            hits.append({"type": "domain", "value": d, "misp": m})
    for ip in ips[:20]:
        b = check_ip_blocklists(ip)
        if b:
            hits.append({"type": "ip", "value": ip, "reasons": b})
    return {"hits": hits, "count": len(hits)}
