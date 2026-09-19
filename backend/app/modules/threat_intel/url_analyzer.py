"""URL extraction, defanging, threat-feed checks (VirusTotal, URLhaus, MISP, local blocklists)."""
import re
from typing import Any
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"]+|www\.[^\s<>\"]+", re.IGNORECASE)

LOCAL_BLOCKLIST_DOMAINS = {
    "malicious-example.com", "phish-kit.test", "evil-relay.test",
}


def extract_urls(text: str) -> list[str]:
    return URL_RE.findall(text or "")


def defang(url: str) -> str:
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def _domain_of(url: str) -> str:
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
            headers={"x-apikey": api_key}, data={"url": url}, timeout=10,
        )
        return {"source": "virustotal", "status": r.status_code, "data": r.json() if r.status_code in (200, 201) else r.text[:500]}
    except Exception as e:
        return {"source": "virustotal", "error": str(e)[:300]}


def check_urlhaus(url: str) -> dict[str, Any]:
    try:
        import requests
        r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=8)
        if r.status_code == 200:
            return {"source": "urlhaus", **r.json()}
        return {"source": "urlhaus", "status": r.status_code}
    except Exception as e:
        return {"source": "urlhaus", "error": str(e)[:300]}


def analyze_urls(urls: list[str], vt_key: str = "") -> dict[str, Any]:
    hits: list[dict] = []
    for u in urls[:50]:
        dom = _domain_of(u)
        entry: dict[str, Any] = {"url": u[:500], "domain": dom, "defanged": defang(u)}
        if dom in LOCAL_BLOCKLIST_DOMAINS:
            entry["blocklisted"] = True
            hits.append(entry)
            continue
        entry["blocklisted"] = False
        # live checks best-effort (only first few to avoid rate limits)
        if len(hits) < 5:
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
