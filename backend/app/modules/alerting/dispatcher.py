
import logging
import re
import time
from typing import Any

log = logging.getLogger("alerts")

SLACK_PER_MINUTE = 10
PAGERDUTY_PER_MINUTE = 5
DEDUP_WINDOW_S = 15 * 60
MAX_ATTEMPTS = 3
BACKOFF_S = (1.0, 2.0)

_sent_dedup: dict[tuple[str, str], float] = {}
_channel_hits: dict[str, list[float]] = {}
_id_ok = re.compile(r"^[A-Za-z0-9\-]{1,64}$")


def evaluate_policy(score: float) -> tuple[str, str, str]:

    if score >= 90:
        return ("Critical", "Quarantine", "pagerduty+slack+dashboard")
    if score >= 75:
        return ("High", "JunkOrHold", "dashboard+slack")
    if score >= 50:
        return ("Medium", "DeliverWithBanner", "dashboard")
    return ("Low", "Deliver", "none")


def _safe_id(email_id: str) -> str:
    return email_id if _id_ok.match(email_id or "") else "unknown"


def _channel_allowed(channel: str, limit: int) -> bool:
    now = time.monotonic()
    hits = [t for t in _channel_hits.get(channel, []) if now - t < 60.0]
    _channel_hits[channel] = hits
    if len(hits) >= limit:
        return False
    hits.append(now)
    return True


def _post_with_backoff(url: str, payload: dict, timeout: int = 5) -> bool:
    import requests
    last_kind = "error"
    for attempt in range(MAX_ATTEMPTS):
        try:
            r = requests.post(url, json=payload, timeout=timeout)
            if r.status_code < 500:
                return True
            last_kind = f"http-{r.status_code}"
        except Exception as e:
            last_kind = type(e).__name__
        if attempt < MAX_ATTEMPTS - 1:
            time.sleep(BACKOFF_S[min(attempt, len(BACKOFF_S) - 1)])
    log.warning("alert post failed (%s)", last_kind)
    return False


def dispatch_alert(email_id: str, score: float, classification: str, summary: dict[str, Any]) -> dict[str, Any]:
    import os

    eid = _safe_id(email_id)
    sev, action, _ = evaluate_policy(score)
    sent: list[str] = []
    now = time.monotonic()
    last = _sent_dedup.get((eid, sev), 0.0)
    if now - last < DEDUP_WINDOW_S:
        return {"severity": sev, "action": action, "channel": "none", "sent": sent, "deduped": True}
    _sent_dedup[(eid, sev)] = now

    hook = os.environ.get("SLACK_WEBHOOK_URL", "")
    if hook and sev in ("Critical", "High"):
        if not _channel_allowed("slack", SLACK_PER_MINUTE):
            sent.append("slack-rate-limited")
        elif _post_with_backoff(hook, {"text": f"[{sev}] {classification} email={eid} score={score} action={action}"}):
            sent.append("slack")
        else:
            sent.append("slack-failed")
    pd_key = os.environ.get("PAGERDUTY_ROUTING_KEY", "")
    if pd_key and sev == "Critical":
        if not _channel_allowed("pagerduty", PAGERDUTY_PER_MINUTE):
            sent.append("pagerduty-rate-limited")
        elif _post_with_backoff("https://events.pagerduty.com/v2/enqueue", {
                "routing_key": pd_key, "event_action": "trigger",
                "payload": {"summary": f"Critical phishing {eid} score={score}",
                            "severity": "critical", "source": "email-forensics"}}):
            sent.append("pagerduty")
        else:
            sent.append("pagerduty-failed")
    return {"severity": sev, "action": action,
            "channel": "+".join(s for s in sent if not s.endswith(("failed", "limited"))) or "none",
            "sent": sent}
