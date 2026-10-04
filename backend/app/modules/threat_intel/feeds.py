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
    """Single-value MISP lookup (compat wrapper over the batched path)."""
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


# Batch MISP state (P0 reliability): per-value TTL cache + batched
# restSearch per mail instead of up to 90 sequential POSTs.
_MISP_CACHE: dict[str, tuple[float, int]] = {}
MISP_CACHE_TTL_S = 15 * 60
MISP_VALUE_CAP = 30
MISP_TIMEOUT_S = 5.0
# Hard ceiling on cache entries. Expiry alone does not bound this dict: an
# expired entry is dropped only when that same value is read again, so
# rotating indicators accumulated forever and the process grew without limit.
MISP_CACHE_MAX_ENTRIES = 5000


def _misp_cache_get(value: str, now: float) -> int | None:
    ent = _MISP_CACHE.get((value or "").lower())
    if ent and ent[0] > now:
        return ent[1]
    if ent:
        _MISP_CACHE.pop((value or "").lower(), None)
    return None


def _misp_cache_put(key: str, expires_at: float, hits: int, now: float) -> None:
    """Insert one entry, keeping the cache bounded.

    Expired entries are swept first; only if that is not enough are the
    soonest-to-expire entries evicted, so the live working set survives and
    stale indicators go first.
    """
    _MISP_CACHE[key] = (expires_at, hits)
    if len(_MISP_CACHE) <= MISP_CACHE_MAX_ENTRIES:
        return
    for k in [k for k, (exp, _) in _MISP_CACHE.items() if exp <= now]:
        _MISP_CACHE.pop(k, None)
    while len(_MISP_CACHE) > MISP_CACHE_MAX_ENTRIES:
        _MISP_CACHE.pop(min(_MISP_CACHE, key=lambda k: _MISP_CACHE[k][0]), None)


def _misp_restsearch(url: str, key: str, batch: list[str]) -> dict[str, int] | None:
    """One restSearch POST -> {value: hits}, or None on transport error."""
    try:
        import requests
        r = requests.post(
            f"{url.rstrip('/')}/attributes/restSearch",
            headers={"Authorization": key, "Accept": "application/json",
                     "Content-Type": "application/json"},
            json={"value": batch, "limit": 100}, timeout=MISP_TIMEOUT_S,
        )
        counts: dict[str, int] = {v: 0 for v in batch}
        if r.status_code == 200:
            try:
                attrs = (r.json().get("response", {}) or {}).get("Attribute", []) or []
            except Exception:
                attrs = []
            wanted = {v.lower(): v for v in batch}
            for a in attrs:
                try:
                    av = str((a or {}).get("value", "")).strip().lower()
                except Exception:
                    continue
                original = wanted.get(av)
                if original is not None:
                    counts[original] += 1
        return counts
    except Exception:
        return None


def query_misp_batch(values: list[str]) -> dict[str, int]:
    """Batched MISP restSearch for deduplicated values -> {value: hits}.

    P0: replaces up to 90 sequential per-indicator POSTs (each with its own
    5s timeout) with restSearch over the deduplicated values, served from a
    15-minute TTL cache when warm. Transport failure yields zero hits (same
    fail-open-per-mail as before); errors are NOT cached.

    Coverage is COMPLETE. Values are chunked into requests of at most
    MISP_VALUE_CAP rather than truncated to it: `seen[:MISP_VALUE_CAP]`
    silently dropped everything past the first 30 while the call site offers
    up to 90, so 60 indicators per mail were never looked up and could never
    contribute a MISP hit. Worst case is ceil(n / MISP_VALUE_CAP) requests at
    MISP_TIMEOUT_S each.
    """
    seen: list[str] = []
    for v in values or []:
        v = (v or "").strip()
        if v and v not in seen:
            seen.append(v)
    if not seen:
        return {}
    url, key = _misp_config()
    if not url or not key:
        return {}
    now = time.time()
    out: dict[str, int] = {}
    pending: list[str] = []
    for v in seen:
        cached = _misp_cache_get(v, now)
        if cached is None:
            pending.append(v)
        else:
            out[v] = cached
    for i in range(0, len(pending), MISP_VALUE_CAP):
        batch = pending[i:i + MISP_VALUE_CAP]
        counts = _misp_restsearch(url, key, batch)
        if counts is None:
            for v in batch:
                out[v] = 0
            continue
        for v in batch:
            out[v] = counts[v]
            _misp_cache_put(v.lower(), now + MISP_CACHE_TTL_S, counts[v], now)
    return out


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
    url_list = [u for u in (urls or [])[:50]]
    url_doms = [d for d in (domain_of(u) for u in url_list) if d]
    dom_list = [d for d in domains[:20] if d]
    ip_list = [ip for ip in ips[:20] if ip]

    # P0: a few batched, deduplicated, TTL-cached MISP queries per mail
    # instead of up to 90 sequential POSTs. Chunked, not truncated, so
    # every indicator offered here is actually looked up.
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
