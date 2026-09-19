"""Policy evaluation (Rules.md) + dispatch to UI/Slack/PagerDuty/email hooks."""
import os
from typing import Any


def evaluate_policy(score: float) -> tuple[str, str, str]:
    """Returns (severity, action, channel)."""
    if score >= 90:
        return ("Critical", "Quarantine", "pagerduty+slack+dashboard")
    if score >= 75:
        return ("High", "JunkOrHold", "dashboard+slack")
    if score >= 50:
        return ("Medium", "DeliverWithBanner", "dashboard")
    return ("Low", "Deliver", "none")


def dispatch_alert(email_id: str, score: float, classification: str, summary: dict[str, Any]) -> dict[str, Any]:
    sev, action, channel = evaluate_policy(score)
    sent: list[str] = ["dashboard"]
    # Slack
    hook = os.environ.get("SLACK_WEBHOOK_URL", "")
    if hook and sev in ("Critical", "High"):
        try:
            import requests
            requests.post(hook, json={"text": f"[{sev}] {classification} email={email_id} score={score} action={action}"}, timeout=5)
            sent.append("slack")
        except Exception as e:
            sent.append(f"slack-failed:{e}"[:100])
    # PagerDuty
    pd_key = os.environ.get("PAGERDUTY_ROUTING_KEY", "")
    if pd_key and sev == "Critical":
        try:
            import requests
            requests.post("https://events.pagerduty.com/v2/enqueue", json={
                "routing_key": pd_key, "event_action": "trigger",
                "payload": {"summary": f"Critical phishing {email_id} score={score}", "severity": "critical", "source": "email-forensics"},
            }, timeout=5)
            sent.append("pagerduty")
        except Exception as e:
            sent.append(f"pagerduty-failed:{e}"[:100])
    return {"severity": sev, "action": action, "channel": channel, "sent": sent}
