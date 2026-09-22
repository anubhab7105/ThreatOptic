"""Step 1 (C1/C2/C5/C6/C7): secrets boot gate, short JWTs + rotation/reuse
detection, setup-token bootstrap, vault KDF fail-closed, custody v1 payload,
server-side Gmail secrets."""
import uuid

import pytest
from fastapi.testclient import TestClient

from app import models
from app.config import get_settings



def _session():
    """Fresh session from the (possibly test-rebound) sessionmaker."""
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
    # production-safe default posture
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "")
    get_settings.cache_clear()
    assert get_settings().app_env == "production"
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        require_secrets()
    # default marker refused
    _fresh_settings(monkeypatch, APP_ENV="production", SECRET_KEY="change-me-in-prod")
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        require_secrets()
    # short secret refused
    _fresh_settings(monkeypatch, APP_ENV="production", SECRET_KEY="short")
    with pytest.raises(RuntimeError, match="minimum is 32"):
        require_secrets()
    # provisioned secret boots
    _fresh_settings(monkeypatch, APP_ENV="production", SECRET_KEY="x" * 40)
    require_secrets()
    # development warns but boots
    _fresh_settings(monkeypatch, APP_ENV="development", SECRET_KEY="")
    require_secrets()
    get_settings.cache_clear()


def test_access_lifetime_default_20_minutes():
    from app.config import Settings
    assert Settings().access_token_expire_minutes == 20


def test_refresh_rotation_and_reuse_detection():
    from app.main import app

    with TestClient(app) as c:
        uname = _uname("rot")
        pair = c.post("/api/v1/auth/register", json={"username": uname, "password": "Str0ngPass!"}).json()
        r1 = c.post("/api/v1/auth/refresh", json={"refresh_token": pair["refresh_token"]})
        assert r1.status_code == 200, r1.text
        rotated = r1.json()
        assert rotated["refresh_token"] != pair["refresh_token"]
        # old access token still valid until expiry
        assert c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {pair['access_token']}"}).status_code == 200
        # reuse of the rotated-out token -> 401 and family kill
        r2 = c.post("/api/v1/auth/refresh", json={"refresh_token": pair["refresh_token"]})
        assert r2.status_code == 401
        assert "reused" in r2.json()["detail"]
        # the rotated token is dead too (whole family revoked on reuse)
        r3 = c.post("/api/v1/auth/refresh", json={"refresh_token": rotated["refresh_token"]})
        assert r3.status_code == 401
        db = _session()
        try:
            u = db.query(models.User).filter_by(username=uname).first()
            rows = db.query(models.RefreshToken).filter_by(user_id=u.id).all()
            assert rows and all(r.revoked for r in rows)
        finally:
            db.close()
        # fresh login still works after the incident
        assert c.post("/api/v1/auth/login", json={"username": uname, "password": "Str0ngPass!"}).status_code == 200
        db = _session()
        try:
            u = db.query(models.User).filter_by(username=uname).first()
            db.query(models.RefreshToken).filter_by(user_id=u.id).delete()
            db.delete(u)
            db.commit()
        finally:
            db.close()


def test_setup_token_bootstrap(monkeypatch):
    from app.main import app

    _fresh_settings(monkeypatch, SETUP_TOKEN="s3tup-ok")
    with TestClient(app) as c:
        # no token -> Admin forbidden
        assert c.post("/api/v1/auth/register",
                      json={"username": _uname("a"), "password": "Str0ngPass!", "role": "Admin"}).status_code == 403
        # wrong token -> forbidden
        assert c.post("/api/v1/auth/register",
                      json={"username": _uname("b"), "password": "Str0ngPass!",
                            "role": "Admin", "setup_token": "wrong"}).status_code == 403
        # valid token -> Admin, default stays lowest privilege otherwise
        u = _uname("root")
        r = c.post("/api/v1/auth/register",
                   json={"username": u, "password": "Str0ngPass!", "role": "Admin", "setup_token": "s3tup-ok"})
        assert r.status_code == 201, r.text
        me = c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"}).json()
        assert me["role"] == "Admin"
        u2 = _uname("pleb")
        r2 = c.post("/api/v1/auth/register", json={"username": u2, "password": "Str0ngPass!"})
        assert r2.json() and c.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {r2.json()['access_token']}"}).json()["role"] == "ReadOnly"
        db = _session()
        try:
            for name in (u, u2):
                row = db.query(models.User).filter_by(username=name).first()
                if row:
                    db.query(models.RefreshToken).filter_by(user_id=row.id).delete()
                    db.delete(row)
            db.commit()
        finally:
            db.close()
    get_settings.cache_clear()


def test_vault_kdf_fail_closed(monkeypatch):
    from app.modules.auth import vault

    assert vault.encrypt_secret("hello").startswith("v1$")
    assert vault.decrypt_secret(vault.encrypt_secret("hello")) == "hello"
    # empty key fails closed (no deterministic sha256("") fallback)
    monkeypatch.delenv("TOKEN_ENCRYPTION_KEY", raising=False)
    settings = get_settings()
    monkeypatch.setattr(settings, "token_encryption_key", "")
    with pytest.raises(vault.VaultError):
        vault.encrypt_secret("x")
    with pytest.raises(vault.VaultError):
        vault.decrypt_secret("v1$abcd$efgh")
    # short key fails closed
    monkeypatch.setattr(settings, "token_encryption_key", "too-short")
    with pytest.raises(vault.VaultError):
        vault.encrypt_secret("x")
    # legacy raw-fernet format forces re-auth, message leaks nothing
    monkeypatch.setattr(settings, "token_encryption_key", "x" * 40)
    with pytest.raises(vault.VaultError, match="reconnect"):
        vault.decrypt_secret("gAAAAABmZm9vYmFy")
    # tampered ciphertext fails without internals
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
    # rotation: sign with new key, verify still accepts old-key manifests
    old = coc.custody_manifest("eml", b"report")
    monkeypatch.setattr(settings, "custody_key", "n" * 40)
    monkeypatch.setattr(settings, "custody_key_previous", "k" * 40)
    assert coc.verify_manifest(old, b"report") is True
    assert coc.verify_manifest(coc.custody_manifest("eml", b"report"), b"report") is True
    # no hardcoded public default remains
    import inspect
    assert "dev-custody-key" not in inspect.getsource(coc)


def test_gmail_server_side_secret_and_corrupt_token(monkeypatch):
    from app.main import app

    settings = get_settings()
    monkeypatch.setattr(settings, "google_client_id", "demo-id")
    monkeypatch.setattr(settings, "google_client_secret", "")
    with TestClient(app) as c:
        uname = _uname("gmailsec")
        tok = c.post("/api/v1/auth/register", json={"username": uname, "password": "Str0ngPass!"}).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        # server-side secret missing -> clear 400 (no per-request secret accepted anymore)
        r = c.post("/api/v1/gmail/callback", headers=h, json={"code": "x", "redirect_uri": "http://localhost:5173/"})
        assert r.status_code == 400 and "GOOGLE_CLIENT_SECRET" in r.text
        # corrupt stored credential -> forced re-auth, not silent plaintext fallback
        db = _session()
        try:
            u = db.query(models.User).filter_by(username=uname).first()
            db.add(models.GmailAccount(user_id=u.id, gmail_address="x@y.test", refresh_token="not-a-vault-value"))
            db.commit()
        finally:
            db.close()
        monkeypatch.setattr(settings, "google_client_secret", "s" * 16)
        r = c.post("/api/v1/gmail/sync", headers=h, json={})
        assert r.status_code == 400 and "reconnect" in r.text
        db = _session()
        try:
            u = db.query(models.User).filter_by(username=uname).first()
            db.query(models.GmailAccount).filter_by(user_id=u.id).delete()
            db.query(models.RefreshToken).filter_by(user_id=u.id).delete()
            db.delete(u)
            db.commit()
        finally:
            db.close()
