"""URL extraction, defanging, threat-feed checks (VirusTotal, URLhaus, local blocklists)."""
from functools import lru_cache
import os
import re
from typing import Any
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"]+|www\.[^\s<>\"]+", re.IGNORECASE)

LOCAL_BLOCKLIST_DOMAINS = {
    "malicious-example.com", "phish-kit.test", "evil-relay.test",
}


def _live() -> bool:
    return os.environ.get("ENABLE_LIVE_LOOKUPS", "0").lower() not in ("", "0", "false", "no")


def extract_urls(text: str) -> list[str]:
    found = URL_RE.findall(text or "")
    # strip trailing punctuation that is rarely part of the URL
    return [u.rstrip(".,;:!)]}'\"") for u in found]


def defang(url: str) -> str:
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def domain_of(url: str) -> str:
    try:
        host = urlparse(url if "://" in url else "http://" + url).hostname or ""
        return host.lower()
    except Exception:
        return ""


def check_virustotal(url: str, api_key: str = "") -> dict[str, Any]:
    if not api_key:
        return {"source": "virustotal", "skipped": True}
    try:
        import requests
        r = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": api_key}, data={"url": url}, timeout=5,
        )
        return {"source": "virustotal", "status": r.status_code, "data": r.json() if r.status_code in (200, 201) else r.text[:500]}
    except Exception as e:
        return {"source": "virustotal", "error": str(e)[:300]}


@lru_cache(maxsize=1024)
def _check_urlhaus_cached(url: str) -> tuple[int, str]:
    import requests
    r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=1.5)
    return r.status_code, r.text


def check_urlhaus(url: str) -> dict[str, Any]:
    if not _live():
        return {"source": "urlhaus", "skipped": True}
    try:
        status_code, text = _check_urlhaus_cached(url)
        if status_code == 200:
            import json
            return {"source": "urlhaus", **json.loads(text)}
        return {"source": "urlhaus", "status": status_code}
    except Exception as e:
        return {"source": "urlhaus", "error": str(e)[:300]}


def analyze_urls(urls: list[str], vt_key: str = "") -> dict[str, Any]:
    hits: list[dict] = []
    for u in urls[:50]:
        dom = domain_of(u)
        entry: dict[str, Any] = {"url": u[:500], "domain": dom, "defanged": defang(u)}
        if dom in LOCAL_BLOCKLIST_DOMAINS:
            entry["blocklisted"] = True
            hits.append(entry)
            continue
        entry["blocklisted"] = False
        # live checks best-effort (only first few to avoid rate limits)
        if _live() and len(hits) < 3:
            uh = check_urlhaus(u)
            if uh.get("threat"):
                entry["urlhaus_hit"] = uh
                hits.append(entry)
                continue
        if vt_key:
            vt = check_virustotal(u, vt_key)
            malicious = vt.get("data", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) if isinstance(vt.get("data"), dict) else 0
            if malicious:
                entry["virustotal_hit"] = vt
                hits.append(entry)
    return {"urls": urls[:50], "hits": hits, "malicious_count": len(hits)}
