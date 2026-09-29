
import uuid

import pytest
from fastapi.testclient import TestClient

from app import models
from app.config import get_settings
from helpers import login, make_user



def _session():

    from app.database import SessionLocal
    return SessionLocal()


def _uname(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _fresh_settings(monkeypatch, **overrides):
    for k, v in overrides.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    return get_settings()


def test_require_secrets_boot_gate(monkeypatch):
    from app.config import require_secrets

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "")
    get_settings.cache_clear()
    assert get_settings().app_env == "production"
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        require_secrets()

    _fresh_settings(monkeypatch, APP_ENV="production", SECRET_KEY="change-me-in-prod")
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        require_secrets()

    _fresh_settings(monkeypatch, APP_ENV="production", SECRET_KEY="short")
    with pytest.raises(RuntimeError, match="minimum is 32"):
        require_secrets()

    _fresh_settings(monkeypatch, APP_ENV="production", SECRET_KEY="x" * 40)
    require_secrets()

    _fresh_settings(monkeypatch, APP_ENV="production", SECRET_KEY="x" * 40,
                    ELASTICSEARCH_URL="http://es:9200")
    with pytest.raises(RuntimeError, match="ELASTICSEARCH_URL"):
        require_secrets()
    _fresh_settings(monkeypatch, APP_ENV="production", SECRET_KEY="x" * 40,
                    ELASTICSEARCH_URL="https://es:9200")
    require_secrets()

    _fresh_settings(monkeypatch, APP_ENV="development", SECRET_KEY="")
    require_secrets()
    get_settings.cache_clear()


def test_access_lifetime_default_20_minutes():
    from app.config import Settings
    assert Settings().access_token_expire_minutes == 20


def test_no_local_session_store():

    assert not hasattr(models, "RefreshToken")
    db = _session()
    try:
        names = set(db.execute(__import__("sqlalchemy").text(
            "SELECT name FROM sqlite_master WHERE type='table'")).scalars())
    finally:
        db.close()
    assert "refresh_tokens" not in names


def test_role_is_constrained_at_the_database():

    from sqlalchemy.exc import IntegrityError

    db = _session()
    try:
        db.execute(__import__("sqlalchemy").text(
            "INSERT INTO users (id, email, role) VALUES ('badrole', 'bad@test.local', 'Superuser')"))
        db.commit()
        raise AssertionError("unconstrained role value was accepted")
    except IntegrityError:
        db.rollback()
    finally:
        db.close()


def test_admin_role_is_not_self_assignable():

    from app.main import app

    with TestClient(app) as c:
        h, _user = login(role="ReadOnly")
        for method, path, body in (
            ("patch", "/api/v1/auth/me", {"role": "Admin"}),
            ("put", "/api/v1/auth/me", {"role": "Admin"}),
            ("post", "/api/v1/auth/me", {"role": "Admin"}),
        ):
            r = getattr(c, method)(path, headers=h, json=body)
            assert r.status_code in (404, 405, 422), (method, path, r.status_code)
        assert c.get("/api/v1/auth/me", headers=h).json()["role"] == "ReadOnly"


def test_vault_kdf_fail_closed(monkeypatch):
    from app.modules.auth import vault

    assert vault.encrypt_secret("hello").startswith("v1$")
    assert vault.decrypt_secret(vault.encrypt_secret("hello")) == "hello"

    monkeypatch.delenv("TOKEN_ENCRYPTION_KEY", raising=False)
    settings = get_settings()
    monkeypatch.setattr(settings, "token_encryption_key", "")
    with pytest.raises(vault.VaultError):
        vault.encrypt_secret("x")
    with pytest.raises(vault.VaultError):
        vault.decrypt_secret("v1$abcd$efgh")

    monkeypatch.setattr(settings, "token_encryption_key", "too-short")
    with pytest.raises(vault.VaultError):
        vault.encrypt_secret("x")

    monkeypatch.setattr(settings, "token_encryption_key", "x" * 40)
    with pytest.raises(vault.VaultError, match="reconnect"):
        vault.decrypt_secret("gAAAAABmZm9vYmFy")

    good = vault.encrypt_secret("secret!")
    bad = good[:-4] + ("AAAA" if not good.endswith("AAAA") else "BBBB")
    with pytest.raises(vault.VaultError) as ei:
        vault.decrypt_secret(bad)
    assert "secret!" not in str(ei.value)


def test_custody_v1_payload_and_rotation(monkeypatch):
    from app.modules.privacy import chain_of_custody as coc

    settings = get_settings()
    monkeypatch.setattr(settings, "custody_key", "k" * 40)
    monkeypatch.setattr(settings, "custody_key_previous", "")
    m = coc.custody_manifest("eml", b"report")
    assert m["purpose"] == "chain-of-custody" and m["version"] == "v1"
    assert coc.verify_manifest(m, b"report") is True
    assert coc.verify_manifest(m, b"tampered") is False
    tampered_ts = dict(m, generated_at="2000-01-01T00:00:00+00:00")
    assert coc.verify_manifest(tampered_ts, b"report") is False

    old = coc.custody_manifest("eml", b"report")
    monkeypatch.setattr(settings, "custody_key", "n" * 40)
    monkeypatch.setattr(settings, "custody_key_previous", "k" * 40)
    assert coc.verify_manifest(old, b"report") is True
    assert coc.verify_manifest(coc.custody_manifest("eml", b"report"), b"report") is True

    import inspect
    assert "dev-custody-key" not in inspect.getsource(coc)


def test_gmail_server_side_secret_and_corrupt_token(monkeypatch):
    from app.main import app

    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "demo-id")
    monkeypatch.setattr(settings, "google_client_secret", "")
    db = _session()
    try:
        user = make_user(db)
        uid = user.id
        headers = {"Authorization": f"Bearer {__import__('helpers').mint_token(uid)}"}
    finally:
        db.close()

    with TestClient(app) as c:


        au = c.post("/api/v1/gmail/auth-url", headers=headers, json={
            "redirect_uri": "http://localhost:5173/", "client_id": "demo-id"}).json()["auth_url"]
        from urllib.parse import parse_qs as _pqs, urlparse as _up
        _st = _pqs(_up(au).query)["state"][0]
        r = c.post("/api/v1/gmail/callback", headers=headers, json={
            "code": "x", "state": _st, "redirect_uri": "http://localhost:5173/"})
        assert r.status_code == 400 and "GOOGLE_CLIENT_SECRET" in r.text

        db = _session()
        try:
            db.add(models.GmailAccount(user_id=uid, gmail_address="x@y.test", refresh_token="not-a-vault-value"))
            db.commit()
        finally:
            db.close()
        monkeypatch.setattr(settings, "google_client_secret", "s" * 16)
        r = c.post("/api/v1/gmail/sync", headers=headers, json={})
        assert r.status_code == 400 and "reconnect" in r.text
        db = _session()
        try:
            db.query(models.GmailAccount).filter_by(user_id=uid).delete()
            db.delete(db.query(models.User).filter_by(id=uid).one())
            db.commit()
        finally:
            db.close()
