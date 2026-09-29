
import base64
import os

MIN_VAULT_KEY_CHARS = 32
_KDF_ITERATIONS = 600_000
_VAULT_PURPOSE = b"soc-mailbox-vault-v1:"


class VaultError(RuntimeError):
    pass


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

    if (stored or "").startswith("gAAAAAB"):

        import hashlib
        from ...config import get_settings
        for mat in [os.environ.get("TOKEN_ENCRYPTION_KEY", ""), get_settings().token_encryption_key, get_settings().secret_key, "change-me-in-prod"]:
            if not mat:
                continue
            try:
                legacy_key = base64.urlsafe_b64encode(hashlib.sha256(mat.encode()).digest())
                return Fernet(legacy_key).decrypt((stored or "").encode()).decode()
            except Exception:
                pass
        raise VaultError("stored credential is invalid — reconnect the mailbox")

    try:
        version, b64salt, token = (stored or "").split("$", 2)
        if version != "v1" or not b64salt or not token:
            raise VaultError("stored credential needs re-authentication")
        salt = base64.urlsafe_b64decode(b64salt.encode())
        return Fernet(_derive(_password(), salt)).decrypt(token.encode()).decode()
    except VaultError:
        raise
    except (InvalidToken, ValueError):

        raise VaultError("stored credential is invalid — reconnect the mailbox")
    except Exception:
        raise VaultError("token vault decryption failed")
