"""Encrypted vault for mailbox OAuth refresh tokens (F7).

Fernet with a key derived from TOKEN_ENCRYPTION_KEY (preferred, from a
secrets manager) or the app secret_key as a local-dev fallback.
"""
import base64
import hashlib


def _fernet_key() -> bytes:
    import os
    from ...config import get_settings

    material = os.environ.get("TOKEN_ENCRYPTION_KEY", "") or get_settings().secret_key
    return base64.urlsafe_b64encode(hashlib.sha256(material.encode()).digest())


def encrypt_secret(plaintext: str) -> str:
    from cryptography.fernet import Fernet

    return Fernet(_fernet_key()).encrypt(plaintext.encode()).decode()


def decrypt_secret(token: str) -> str:
    from cryptography.fernet import Fernet

    return Fernet(_fernet_key()).decrypt(token.encode()).decode()
