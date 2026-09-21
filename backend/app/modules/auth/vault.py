"""Encrypted vault for mailbox OAuth refresh tokens.

Fernet with a PBKDF2-HMAC-SHA256 derived key (600k iterations, random
16-byte salt per value, format `v1$<b64salt>$<fernet>`). Separate purpose
string from JWT signing (which uses secret_key directly as HMAC key).

Fail-closed: TOKEN_ENCRYPTION_KEY must be set with >= 32 chars or every
encrypt/decrypt raises VaultError. No deterministic fallback.
"""
import base64
import hashlib
import os

MIN_VAULT_KEY_CHARS = 32
_KDF_ITERATIONS = 600_000
_VAULT_PURPOSE = b"soc-mailbox-vault-v1:"


class VaultError(RuntimeError):
    """Generic vault failure — message carries no key material or internals."""


def _password() -> str:
    from ...config import get_settings

    pw = os.environ.get("TOKEN_ENCRYPTION_KEY", "") or get_settings().token_encryption_key or ""
    if len(pw.strip()) < MIN_VAULT_KEY_CHARS:
        raise VaultError("token vault is not configured")
    return pw.strip()


def _derive(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_VAULT_PURPOSE + salt,
        iterations=_KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_secret(plaintext: str) -> str:
    from cryptography.fernet import Fernet

    try:
        salt = os.urandom(16)
        token = Fernet(_derive(_password(), salt)).encrypt(plaintext.encode()).decode()
        return f"v1${base64.urlsafe_b64encode(salt).decode()}${token}"
    except VaultError:
        raise
    except Exception:
        raise VaultError("token vault encryption failed")


def decrypt_secret(stored: str) -> str:
    from cryptography.fernet import Fernet, InvalidToken

    try:
        version, b64salt, token = (stored or "").split("$", 2)
        if version != "v1" or not b64salt or not token:
            raise VaultError("stored credential needs re-authentication")
        salt = base64.urlsafe_b64decode(b64salt.encode())
        return Fernet(_derive(_password(), salt)).decrypt(token.encode()).decode()
    except VaultError:
        raise
    except (InvalidToken, ValueError):
        # Wrong key or tampered/corrupt ciphertext: force reconnect, no details.
        raise VaultError("stored credential is invalid — reconnect the mailbox")
    except Exception:
        raise VaultError("token vault decryption failed")
