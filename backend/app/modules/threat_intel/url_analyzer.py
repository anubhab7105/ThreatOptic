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


VT_MAX_URLS = 5
VT_MAX_POLLS = 3
VT_POLL_SECONDS = 2.0
# Async VT path (P0 reliability): shared per-mail deadline so VirusTotal can
# never stall the request path; polling uses asyncio.sleep (cancellable),
# never time.sleep in a thread. Sync helpers below stay for compat/tests.
VT_MAIL_DEADLINE_S = 8.0
VT_POLL_INTERVAL_S = 1.0


def submit_url_virustotal(url: str, api_key: str) -> dict[str, Any]:
    """Submit a URL for scanning. Returns {"analysis_id": ...} on success."""
    import requests
    r = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers={"x-apikey": api_key}, data={"url": url}, timeout=5,
    )
    if r.status_code in (200, 201):
        return {"analysis_id": r.json().get("data", {}).get("id", "")}
    return {"status": r.status_code, "error": r.text[:300]}


def poll_analysis_virustotal(analysis_id: str, api_key: str,
                             max_polls: int = VT_MAX_POLLS) -> dict[str, Any]:
    """Poll an analysis until completed; returns last_analysis_stats or {}."""
    import time
    import requests
    for _ in range(max(1, max_polls)):
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers={"x-apikey": api_key}, timeout=5,
            )
            if r.status_code != 200:
                return {}
            attrs = r.json().get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                return attrs.get("stats", {}) or attrs.get("last_analysis_stats", {}) or {}
        except Exception:
            return {}
        time.sleep(VT_POLL_SECONDS)
    return {}


def check_virustotal(url: str, api_key: str = "") -> dict[str, Any]:
    """Correct v3 flow: submit URL -> poll analysis -> read stats.

    (Previously the code read last_analysis_stats straight off the
    submission response, where it never exists — virustotal_hit never fired.)
    """
    if not api_key:
        return {"source": "virustotal", "skipped": True}
    try:
        sub = submit_url_virustotal(url, api_key)
        if not sub.get("analysis_id"):
            return {"source": "virustotal", **{k: v for k, v in sub.items() if k != "analysis_id"}}
        stats = poll_analysis_virustotal(sub["analysis_id"], api_key)
        if not stats:
            return {"source": "virustotal", "pending": True}
        return {"source": "virustotal",
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0))}
    except Exception as e:
        return {"source": "virustotal", "error": str(e)[:300]}


async def check_virustotal_async(url: str, api_key: str = "", *, deadline: float) -> dict[str, Any]:
    """Async VirusTotal v3 flow bounded by an absolute monotonic deadline.

    P0: submit + poll without blocking a thread (asyncio.sleep only, so
    cancellation actually stops the wait). Past the deadline — or on any
    transport error — returns pending/error instead of hanging the mail.
    `deadline` is a time.monotonic() timestamp shared across all URLs of
    one mail, so N URLs share one budget instead of N x timeout.
    """
    import asyncio
    import time
    import httpx
    if not api_key:
        return {"source": "virustotal", "skipped": True}
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": api_key}, data={"url": url},
            )
            if r.status_code not in (200, 201):
                return {"source": "virustotal", "status": r.status_code}
            try:
                analysis_id = (r.json().get("data", {}) or {}).get("id", "")
            except Exception:
                analysis_id = ""
            if not analysis_id:
                return {"source": "virustotal", "pending": True}
            while True:
                if time.monotonic() >= deadline:
                    return {"source": "virustotal", "pending": True}
                g = await client.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers={"x-apikey": api_key},
                )
                if g.status_code != 200:
                    return {"source": "virustotal", "status": g.status_code}
                try:
                    attrs = (g.json().get("data", {}) or {}).get("attributes", {}) or {}
                except Exception:
                    attrs = {}
                if attrs.get("status") == "completed":
                    stats = attrs.get("stats", {}) or attrs.get("last_analysis_stats", {}) or {}
                    if not stats:
                        return {"source": "virustotal", "pending": True}
                    return {"source": "virustotal",
                            "malicious": int(stats.get("malicious", 0)),
                            "suspicious": int(stats.get("suspicious", 0))}
                await asyncio.sleep(max(0.0, min(VT_POLL_INTERVAL_S, deadline - time.monotonic())))
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


def _demo_lists_on() -> bool:
    """Hard-coded demo domains only apply in development (Step 4 honesty)."""
    try:
        from ...config import get_settings
        return get_settings().is_development()
    except Exception:
        return True


def analyze_urls(urls: list[str], vt_key: str = "") -> dict[str, Any]:
    from .lookalikes import lookalike_of

    hits: list[dict] = []
    vt_checked = 0
    ml_phishing_count = 0
    for u in urls[:50]:
        dom = domain_of(u)
        entry: dict[str, Any] = {"url": u[:500], "domain": dom, "defanged": defang(u)}
        reasons: list[str] = []
        if dom in LOCAL_BLOCKLIST_DOMAINS:
            if _demo_lists_on():
                entry["blocklisted"] = True
                reasons.append("demo-fixture")
            else:
                entry["blocklisted"] = False
        else:
            entry["blocklisted"] = False
        # lookalike / homograph detection (suspicious, not standalone malicious)
        try:
            lk = lookalike_of(dom)
            if lk:
                reasons.append(f"lookalike:{lk['impersonates']}:{','.join(lk['via'])}")
                entry["lookalike"] = lk
        except Exception:
            pass
        if reasons:
            entry["reasons"] = reasons
            hits.append(entry)
            continue
        # ML-based URL phishing detection (offline, no API key needed)
        # Runs before live checks so zero-day phishing is caught even offline.
        # NOTE: This model was trained with 48 features, many requiring page content.
        # URL-only mode uses imputed medians for content features → lower accuracy.
        # Thresholds tuned for URL-only mode (legit ~0.08, phishing ~0.25-0.45).
        try:
            from .url_ml import predict_url
            ml_result = predict_url(u)
            entry["ml_url_score"] = ml_result["risk_score"]
            entry["ml_url_confidence"] = ml_result["confidence"]
            entry["ml_url_label"] = "phishing" if ml_result["is_phishing"] else "legitimate"
            # URL-only mode: top content features are imputed → max risk ~0.45.
            # Use lower threshold than full-page mode (0.70 → 0.35).
            if ml_result["risk_score"] >= 0.35:
                entry["ml_phishing"] = True
                entry["reasons"] = [f"ml-phishing:{ml_result['confidence']}%"]
                hits.append(entry)
                ml_phishing_count += 1
                continue
            elif ml_result["risk_score"] >= 0.25:
                # Suspicious range: keep signal but don't auto-count as malicious
                entry["ml_suspicious"] = True
                # Still add to hits as suspicious (not malicious_count) for UI visibility
                # Don't count toward malicious_count but preserve for analyst review
                entry["reasons"] = [f"ml-suspicious:{ml_result['confidence']}%"]
                hits.append(entry)
                continue
        except Exception:
            # Model unavailable or scoring failed → graceful fallback, continue without ML
            pass
        # live checks best-effort (capped to avoid rate limits / slow pipelines)
        if _live() and len(hits) < 3:
            uh = check_urlhaus(u)
            if uh.get("threat"):
                entry["urlhaus_hit"] = uh
                hits.append(entry)
                continue
        if vt_key and vt_checked < VT_MAX_URLS:
            vt_checked += 1
            vt = check_virustotal(u, vt_key)
            if vt.get("malicious"):
                entry["virustotal_hit"] = vt
                hits.append(entry)
    return {"urls": urls[:50], "hits": hits, "ml_phishing_count": ml_phishing_count, "malicious_count": sum(
        1 for h in hits if h.get("blocklisted") or h.get("urlhaus_hit") or h.get("virustotal_hit") or h.get("ml_phishing"))}


def _is_malicious_hit(h: dict[str, Any]) -> bool:
    return bool(h.get("blocklisted") or h.get("urlhaus_hit") or h.get("virustotal_hit") or h.get("ml_phishing"))


async def analyze_urls_async(urls: list[str], vt_key: str = "",
                             local_timeout_s: float = 5.0,
                             vt_deadline_s: float = VT_MAIL_DEADLINE_S) -> dict[str, Any]:
    """Request-path URL analysis (P0 reliability).

    Local signals (blocklist/lookalike/ML/urlhaus) run in a worker thread
    bounded by local_timeout_s; VirusTotal submit+poll runs concurrently
    on the event loop under ONE shared per-mail deadline. No time.sleep,
    no unbounded per-URL blocking: worst case the mail carries pending
    (not malicious) VT verdicts instead of stalling ingestion.
    """
    import asyncio
    import time
    loop = asyncio.get_running_loop()
    try:
        base = await asyncio.wait_for(
            loop.run_in_executor(None, analyze_urls, urls, ""), timeout=local_timeout_s)
        if not isinstance(base, dict):
            raise ValueError("bad base result")
    except Exception:
        base = {"urls": urls[:50], "hits": [], "ml_phishing_count": 0}
    hits: list[dict[str, Any]] = list(base.get("hits", []))
    if not vt_key:
        return {"urls": urls[:50], "hits": hits,
                "ml_phishing_count": int(base.get("ml_phishing_count", 0)),
                "malicious_count": sum(1 for h in hits if _is_malicious_hit(h))}
    deadline = time.monotonic() + max(0.5, vt_deadline_s)
    seen = {str(h.get("url", "")) for h in hits}
    candidates = [u for u in urls[:50] if u[:500] not in seen][:VT_MAX_URLS]

    async def _one(u: str) -> dict[str, Any] | None:
        try:
            vt = await check_virustotal_async(u, vt_key, deadline=deadline)
        except Exception:
            return None
        if vt.get("malicious"):
            return {"url": u[:500], "domain": domain_of(u), "defanged": defang(u),
                    "virustotal_hit": vt}
        return None

    for entry in await asyncio.gather(*(_one(u) for u in candidates)):
        if entry:
            hits.append(entry)
    return {"urls": urls[:50], "hits": hits,
            "ml_phishing_count": int(base.get("ml_phishing_count", 0)),
            "malicious_count": sum(1 for h in hits if _is_malicious_hit(h))}
