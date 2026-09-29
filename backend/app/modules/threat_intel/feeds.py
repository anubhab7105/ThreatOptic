
import os
import time
from functools import lru_cache
from typing import Any

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz"}


DEMO_BLOCKLIST_DOMAINS = {"malicious-example.com", "phish-kit.test"}


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

        if _is_development():
            hits.append("demo-fixture")
    else:


        if d in _operator_blocklist():
            hits.append("local-blocklist")
    if any(d.endswith(t) for t in SUSPICIOUS_TLDS):
        hits.append("suspicious-tld")
    if "xn--" in d:
        hits.append("punycode")
    return hits


@lru_cache(maxsize=1)
def _operator_blocklist() -> frozenset:

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

    v = (value or "").strip()
    if not v:
        return {"source": "misp", "skipped": True}
    url, key = _misp_config()
    if not url or not key:
        return {"source": "misp", "skipped": True}
    return {"source": "misp", "hits": query_misp_batch([v]).get(v, 0)}


def _misp_config() -> tuple[str, str]:
    url = os.environ.get("MISP_URL", "") or ""
    key = os.environ.get("MISP_KEY", "") or ""
    if not url or not key:
        try:
            from ...config import get_settings
            s = get_settings()
            url = url or s.misp_url or ""
            key = key or s.misp_key or ""
        except Exception:
            pass
    return url, key




_MISP_CACHE: dict[str, tuple[float, int]] = {}
MISP_CACHE_TTL_S = 15 * 60
MISP_VALUE_CAP = 30
MISP_TIMEOUT_S = 5.0


def _misp_cache_get(value: str, now: float) -> int | None:
    ent = _MISP_CACHE.get((value or "").lower())
    if ent and ent[0] > now:
        return ent[1]
    if ent:
        _MISP_CACHE.pop((value or "").lower(), None)
    return None


def query_misp_batch(values: list[str]) -> dict[str, int]:

    seen: list[str] = []
    for v in values or []:
        v = (v or "").strip()
        if v and v not in seen:
            seen.append(v)
    seen = seen[:MISP_VALUE_CAP]
    if not seen:
        return {}
    url, key = _misp_config()
    if not url or not key:
        return {}
    now = time.time()
    out: dict[str, int] = {}
    pending = [v for v in seen if (_misp_cache_get(v, now) is None)]
    for v in seen:
        cached = _misp_cache_get(v, now)
        if cached is not None:
            out[v] = cached
    if not pending:
        return out
    try:
        import requests
        r = requests.post(
            f"{url.rstrip('/')}/attributes/restSearch",
            headers={"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"},
            json={"value": pending, "limit": 100}, timeout=MISP_TIMEOUT_S,
        )
        counts: dict[str, int] = {v: 0 for v in pending}
        if r.status_code == 200:
            try:
                attrs = (r.json().get("response", {}) or {}).get("Attribute", []) or []
            except Exception:
                attrs = []
            wanted = {v.lower() for v in pending}
            for a in attrs:
                try:
                    av = str((a or {}).get("value", "")).strip().lower()
                except Exception:
                    continue
                if av in wanted:
                    counts[next(v for v in pending if v.lower() == av)] += 1
        for v in pending:
            out[v] = counts[v]
            _MISP_CACHE[v.lower()] = (now + MISP_CACHE_TTL_S, counts[v])
    except Exception:
        for v in pending:
            out[v] = 0
    return out


def _is_malicious_reason(reason: str) -> bool:
    return reason in MALICIOUS_REASONS or reason.startswith(MALICIOUS_PREFIXES)


def aggregate_threat_intel(domains: list[str], ips: list[str], urls: list[str]) -> dict[str, Any]:

    from .url_analyzer import domain_of

    hits: list[dict] = []
    url_list = [u for u in (urls or [])[:50]]
    url_doms = [d for d in (domain_of(u) for u in url_list) if d]
    dom_list = [d for d in domains[:20] if d]
    ip_list = [ip for ip in ips[:20] if ip]



    misp_hits = query_misp_batch([*dom_list, *ip_list, *url_doms])

    def _misp_entry(value: str) -> dict[str, Any] | None:
        n = misp_hits.get(value, 0)
        if n:
            return {"misp": {"source": "misp", "hits": n}}
        return None

    def _add_url(u: str) -> None:
        dom = domain_of(u)
        if not dom:
            return
        reasons = check_domain_blocklists(dom)
        m = _misp_entry(dom)
        entry: dict[str, Any] = {"type": "url", "value": u[:500], "domain": dom}
        if reasons:
            entry["reasons"] = reasons
        if m:
            entry["misp"] = m["misp"]
            entry.setdefault("reasons", []).append("misp-hit")
        if entry.get("reasons"):
            hits.append(entry)

    for d in dom_list:
        b = check_domain_blocklists(d)
        if b:
            hits.append({"type": "domain", "value": d, "reasons": b})
        m = _misp_entry(d)
        if m:
            hits.append({"type": "domain", "value": d, "misp": m["misp"], "reasons": ["misp-hit"]})
    for ip in ip_list:
        b = check_ip_blocklists(ip) + check_ip_spamhaus(ip)
        if b:
            hits.append({"type": "ip", "value": ip, "reasons": b})
        m = _misp_entry(ip)
        if m:
            hits.append({"type": "ip", "value": ip, "misp": m["misp"], "reasons": ["misp-hit"]})
    for u in url_list:
        _add_url(u)
    malicious = sum(1 for h in hits if any(_is_malicious_reason(r) for r in h.get("reasons", [])))
    return {"hits": hits, "count": len(hits), "malicious_count": malicious}
