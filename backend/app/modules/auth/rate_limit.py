"""Rate limiting (slowapi), login lockout, and security audit logging (Step 2).

Limits are enforced per route + client IP. The limiter honors
RATE_LIMIT_ENABLED=0 (used by the test-suite default) via `limiter.enabled`.
Login lockout is a separate in-memory guard: 5 failed attempts for one
username within 15 minutes -> 429 until the window passes. Single-replica
note: both stores are in-process; put a shared Redis in front for
multi-replica deployments.
"""
import logging
import time
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=[])

audit_log = logging.getLogger("audit")

LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW_S = 15 * 60

# username_lower -> list[epoch] of recent failures (in-process, see note above)
_failed_logins: dict[str, list[float]] = {}


def audit(event: str, **fields: object) -> None:
    parts = " ".join(f"{k}={v}" for k, v in fields.items())
    audit_log.info("event=%s %s", event, parts)


def _prune(username: str, now: float) -> list[float]:
    attempts = [t for t in _failed_logins.get(username, []) if now - t < LOCKOUT_WINDOW_S]
    _failed_logins[username] = attempts
    return attempts


def check_login_allowed(username: str) -> bool:
    return len(_prune(username.strip().lower(), time.time())) < LOCKOUT_THRESHOLD


def record_login_failure(username: str) -> None:
    key = username.strip().lower()
    _failed_logins.setdefault(key, []).append(time.time())
    _prune(key, time.time())


def clear_login_failures(username: str) -> None:
    _failed_logins.pop(username.strip().lower(), None)


def apply_limiter_setting() -> None:
    """Sync slowapi's kill-switch with settings (called from lifespan)."""
    from ...config import get_settings

    limiter.enabled = str(get_settings().rate_limit_enabled).lower() not in ("", "0", "false", "no")
