"""Chain of custody: SHA-256 of .eml + signed report manifest.

Key policy: CUSTODY_KEY must be provisioned (secrets manager in any
non-local deployment). There is NO hardcoded fallback value. In
APP_ENV=development only, an ephemeral per-process key is generated so
local dev works; it cannot verify anything across restarts by design.

Manifest v1 binds purpose + version + timestamp into the HMAC payload.
Key rotation: set CUSTODY_KEY to the new key and CUSTODY_KEY_PREVIOUS to
the old one; verify_manifest() accepts either during the window.
See SECURITY.md for the rotation procedure.
"""
import hashlib
import hmac
import os
from datetime import datetime, timezone

PURPOSE = "chain-of-custody"
VERSION = "v1"


def _is_development() -> bool:
    from ...config import get_settings

    return get_settings().app_env.strip().lower() == "development"


_dev_key: bytes | None = None


def _dev_ephemeral_key() -> bytes:
    """Per-process random key for local development only (never persisted)."""
    global _dev_key
    import logging

    if _dev_key is None:
        _dev_key = os.urandom(32)
        logging.getLogger("custody").warning(
            "CUSTODY_KEY unset: using an ephemeral dev-only signing key. "
            "Manifests will NOT verify after restart. Set CUSTODY_KEY for anything real."
        )
    return _dev_key


def _candidate_keys() -> list[bytes]:
    from ...config import get_settings

    keys: list[bytes] = []
    current = (get_settings().custody_key or "").strip()
    if current:
        keys.append(current.encode())
    previous = (get_settings().custody_key_previous or "").strip()
    if previous and previous != current:
        keys.append(previous.encode())
    if not keys:
        if not _is_development():
            raise RuntimeError(
                "CUSTODY_KEY is not set and APP_ENV is not 'development': "
                "refusing to sign chain-of-custody reports without a key. "
                "Provision CUSTODY_KEY from a secrets manager."
            )
        keys.append(_dev_ephemeral_key())
    return keys


def signing_key() -> bytes:
    return _candidate_keys()[0]


def require_custody_key() -> None:
    """Fail fast at startup (called from lifespan) when misconfigured."""
    signing_key()


def _payload(eml_hash: str, report_hash: str, generated_at: str) -> bytes:
    return f"{PURPOSE}:{VERSION}:{eml_hash}:{report_hash}:{generated_at}".encode()


def custody_manifest(eml_hash: str, report_bytes: bytes) -> dict:
    report_hash = hashlib.sha256(report_bytes).hexdigest()
    generated_at = datetime.now(timezone.utc).isoformat()
    sig = hmac.new(signing_key(), _payload(eml_hash, report_hash, generated_at), hashlib.sha256).hexdigest()
    return {
        "purpose": PURPOSE,
        "version": VERSION,
        "eml_sha256": eml_hash,
        "report_sha256": report_hash,
        "generated_at": generated_at,
        "signature": sig,
        "algorithm": "HMAC-SHA256",
    }


def verify_manifest(manifest: dict, report_bytes: bytes) -> bool:
    """True iff the manifest signature validates under a current/previous key.

    Returns a bare boolean — never raises, never leaks key details.
    """
    try:
        eml_hash = manifest.get("eml_sha256", "")
        generated_at = manifest.get("generated_at", "")
        expected_report = manifest.get("report_sha256", "")
        if not eml_hash or not generated_at:
            return False
        if manifest.get("purpose") != PURPOSE or manifest.get("version") != VERSION:
            return False
        if hashlib.sha256(report_bytes).hexdigest() != expected_report:
            return False
        payload = _payload(eml_hash, expected_report, generated_at)
        want = manifest.get("signature", "")
        return any(hmac.compare_digest(
            hmac.new(k, payload, hashlib.sha256).hexdigest(), want
        ) for k in _candidate_keys())
    except Exception:
        return False
