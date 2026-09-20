"""Chain of custody: SHA-256 of .eml + signed report manifest.

The HMAC key MUST be provisioned via CUSTODY_KEY (secrets manager in any
non-local deployment). A hardcoded dev fallback exists only when
APP_ENV=development; anything else without a key is a startup error (F4).
"""
import hashlib
import hmac
from datetime import datetime, timezone

DEV_FALLBACK_KEY = "dev-custody-key"


def _is_development() -> bool:
    from ...config import get_settings

    return get_settings().app_env.strip().lower() == "development"


def signing_key() -> bytes:
    from ...config import get_settings

    key = (get_settings().custody_key or "").strip()
    if key:
        return key.encode()
    if not _is_development():
        raise RuntimeError(
            "CUSTODY_KEY is not set and APP_ENV is not 'development': "
            "refusing to sign chain-of-custody reports with a public default. "
            "Provision CUSTODY_KEY from a secrets manager."
        )
    return DEV_FALLBACK_KEY.encode()


def require_custody_key() -> None:
    """Fail fast at startup (called from lifespan) when misconfigured."""
    signing_key()


def custody_manifest(eml_hash: str, report_bytes: bytes) -> dict:
    report_hash = hashlib.sha256(report_bytes).hexdigest()
    sig = hmac.new(signing_key(), f"{eml_hash}:{report_hash}".encode(), hashlib.sha256).hexdigest()
    return {
        "eml_sha256": eml_hash,
        "report_sha256": report_hash,
        "signature": sig,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "HMAC-SHA256",
    }
