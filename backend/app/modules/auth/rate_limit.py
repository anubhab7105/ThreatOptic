
import logging
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=[])

audit_log = logging.getLogger("audit")


def audit(event: str, **fields: object) -> None:
    parts = " ".join(f"{k}={v}" for k, v in fields.items())
    audit_log.info("event=%s %s", event, parts)


def apply_limiter_setting() -> None:

    from ...config import get_settings

    limiter.enabled = str(get_settings().rate_limit_enabled).lower() not in ("", "0", "false", "no")
