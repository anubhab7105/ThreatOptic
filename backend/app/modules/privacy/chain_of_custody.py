"""Chain of custody: SHA-256 of .eml + signed report manifest."""
import hashlib
import hmac
import os
from datetime import datetime, timezone


def custody_manifest(eml_hash: str, report_bytes: bytes) -> dict:
    report_hash = hashlib.sha256(report_bytes).hexdigest()
    key = os.environ.get("CUSTODY_KEY", "dev-custody-key").encode()
    sig = hmac.new(key, f"{eml_hash}:{report_hash}".encode(), hashlib.sha256).hexdigest()
    return {
        "eml_sha256": eml_hash,
        "report_sha256": report_hash,
        "signature": sig,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "HMAC-SHA256",
    }
