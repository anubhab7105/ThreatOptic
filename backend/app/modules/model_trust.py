"""Model artifact trust verification (P0).

Unpickling a pickle/joblib file is remote code execution for anyone with
write access to it. Every model load in this codebase MUST pass through
verify_model_artifact() first:

1. Existence — missing file is an error (callers fall back gracefully).
2. Permissions — world-writable model files are refused outright
   (attacker-writable == RCE in any environment).
3. Ed25519 signature (MODEL_VERIFY_KEY, hex pubkey) — when provisioned,
   ``<artifact>.sig`` MUST exist and verify; anything else fails closed.
   This is the production-grade path: a checksum sidecar alone cannot
   stop an attacker who can rewrite both files.
4. SHA256 sidecar (``<artifact>.sha256``) — verified when present and no
   verify-key is provisioned; mismatch fails closed.
5. Neither — production fails closed; development allows loading ONLY
   with explicit MODEL_TRUST_INSECURE=1 plus a loud warning (logged dev
   override). Anything else fails closed.

"Fail closed" here means REFUSE TO UNPICKLE (callers use rule/heuristic
fallbacks) — never crash the process, never load unverified bytes.
"""

import hashlib
import logging
import os

log = logging.getLogger("model_trust")

_CHUNK = 65536


class ModelTrustError(RuntimeError):
    """Model artifact failed trust verification — do not unpickle."""


def _is_production() -> bool:
    try:
        from ..config import get_settings
        return not get_settings().is_development()
    except Exception:
        return os.environ.get("APP_ENV", "production").strip().lower() != "development"


def _check_permissions(path: str) -> None:
    if os.name == "nt":
        return
    try:
        mode = os.stat(path).st_mode
    except OSError as e:
        raise ModelTrustError(f"cannot stat model file: {e}")
    if mode & 0o002:
        raise ModelTrustError(
            f"refusing to load world-writable model file: {path} "
            "(fix permissions: chmod 644, owned by the service user)"
        )
    if mode & 0o020:
        log.warning("model file is group-writable: %s (prefer 644)", path)


def _sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_signature(path: str, pubkey_hex: str) -> None:
    """Verify detached Ed25519 ``<path>.sig`` (hex, 64 bytes). Raises."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as e:
        raise ModelTrustError(f"signature verification unavailable (cryptography missing): {e}")
    sig_path = path + ".sig"
    if not os.path.isfile(sig_path):
        raise ModelTrustError(f"MODEL_VERIFY_KEY is set but signature sidecar is missing: {sig_path}")
    try:
        pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex.strip()))
    except Exception:
        raise ModelTrustError("MODEL_VERIFY_KEY is not a valid Ed25519 public key (64 hex chars)")
    try:
        with open(sig_path, "r", encoding="utf-8") as f:
            signature = bytes.fromhex(f.read().strip().split()[0])
        if len(signature) != 64:
            raise ModelTrustError(f"bad signature length in {sig_path}")
        pubkey.verify(signature, _read_bytes(path))
    except ModelTrustError:
        raise
    except InvalidSignature:
        raise ModelTrustError(f"signature verification FAILED for {path} — refusing to load")
    except Exception as e:
        raise ModelTrustError(f"cannot verify signature for {path}: {e}")


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def verify_model_artifact(path: str, *, purpose: str = "model") -> None:
    """Gate before joblib.load()/pickle.load(). Raises ModelTrustError."""
    if not path or not os.path.isfile(path):
        raise ModelTrustError(f"{purpose} model file not found: {path}")
    _check_permissions(path)

    verify_key = (os.environ.get("MODEL_VERIFY_KEY", "") or "").strip()
    if verify_key:
        _verify_signature(path, verify_key)
        log.info("%s signature verified: %s", purpose, path)
        return

    sha_path = path + ".sha256"
    if os.path.isfile(sha_path):
        try:
            with open(sha_path, "r", encoding="utf-8") as f:
                expected = f.read().strip().split()[0]
        except Exception as e:
            raise ModelTrustError(f"cannot read checksum sidecar {sha_path}: {e}")
        actual = _sha256_of(path)
        if actual.lower() != expected.lower():
            raise ModelTrustError(
                f"{purpose} checksum mismatch for {path} — refusing to load "
                "(retrain/resign if the model was legitimately updated)"
            )
        log.info("%s checksum verified: %s", purpose, path)
        return

    # No key, no sidecar: fail closed except explicit logged dev override.
    if _is_production():
        raise ModelTrustError(
            f"{purpose} has no signature (.sig + MODEL_VERIFY_KEY) and no "
            f"checksum sidecar (.sha256) — refusing to load in production"
        )
    if os.environ.get("MODEL_TRUST_INSECURE", "").strip() != "1":
        raise ModelTrustError(
            f"{purpose} has no trust metadata — refusing to load. "
            "Set MODEL_TRUST_INSECURE=1 for an explicit (logged) dev bypass, "
            "or provision MODEL_VERIFY_KEY / .sha256 sidecar."
        )
    log.warning(
        "MODEL_TRUST_INSECURE=1 — loading UNVERIFIED %s model (development only): %s",
        purpose, path,
    )
