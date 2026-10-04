"""Tests for Category A audit recommendations (October 2026 Codebase Review)."""
import asyncio
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from app import models
from app.config import get_settings, DEFAULT_VERCEL_PREVIEW_REGEX
from helpers import login, make_user


def test_dkim_expiration_check():
    """Fix #9: Expired DKIM signatures (x=) must fail closed."""
    from app.modules.forensics.auth_validator import validate_dkim

    # Timestamp in the past (e.g., year 2001)
    expired_sig = "v=1; a=rsa-sha256; d=example.com; s=s1; x=1000000000; bh=abc; b=xyz"
    res = validate_dkim(b"From: test@example.com\r\n\r\nbody", raw_headers={"DKIM-Signature": expired_sig})
    assert res["status"] == "fail"
    assert res["detail"] == "dkim-signature-expired"


def test_model_trust_insecure_rejected_in_production(tmp_path, monkeypatch):
    """Fix #10: MODEL_TRUST_INSECURE=1 must be refused in production."""
    from app.modules.model_trust import verify_model_artifact, ModelTrustError

    monkeypatch.setattr(get_settings(), "app_env", "production")
    monkeypatch.setenv("MODEL_TRUST_INSECURE", "1")
    p = str(tmp_path / "test_model.pkl")
    with open(p, "wb") as f:
        f.write(b"model data")
    with pytest.raises(ModelTrustError, match="MODEL_TRUST_INSECURE is not permitted outside development"):
        verify_model_artifact(p, purpose="test")


def test_retention_cleans_expired_and_used_oauth_states():
    """Fix #13: Expired and used OAuthState rows must be purged by retention."""
    from app.services.scheduler import run_retention_job
    from app.database import SessionLocal

    db = SessionLocal()
    u = make_user(db)
    uid = u.id
    now = datetime.now(timezone.utc)
    try:
        st_exp = models.OAuthState(
            state="test-state-expired-rec",
            user_id=uid,
            expires_at=now - timedelta(hours=2),
            used=False,
        )
        st_used = models.OAuthState(
            state="test-state-used-rec",
            user_id=uid,
            expires_at=now + timedelta(hours=2),
            used=True,
        )
        st_valid = models.OAuthState(
            state="test-state-valid-rec",
            user_id=uid,
            expires_at=now + timedelta(hours=2),
            used=False,
        )
        db.add_all([st_exp, st_used, st_valid])
        db.commit()

        entry = run_retention_job()
        assert entry.get("oauth_states_cleaned", 0) >= 2

        # Verify only the valid unused state remains
        assert db.query(models.OAuthState).filter_by(state="test-state-expired-rec").first() is None
        assert db.query(models.OAuthState).filter_by(state="test-state-used-rec").first() is None
        assert db.query(models.OAuthState).filter_by(state="test-state-valid-rec").first() is not None
    finally:
        db.query(models.OAuthState).filter(
            models.OAuthState.state.in_(["test-state-expired-rec", "test-state-used-rec", "test-state-valid-rec"])
        ).delete(synchronize_session=False)
        db.query(models.User).filter_by(id=uid).delete()
        db.commit()
        db.close()


def test_retention_dry_run_preview():
    """Fix #12: Retention dry_run returns counts without mutating DB."""
    from app.modules.privacy.retention import apply_retention
    from app.database import SessionLocal

    db = SessionLocal()
    now = datetime.now(timezone.utc)
    email = models.EmailRecord(
        subject="retention dry run probe",
        body_text="secret payload before retention",
        body_text_masked="secret payload before retention",
        timestamp=now - timedelta(days=20),
    )
    db.add(email)
    db.commit()
    db.refresh(email)
    try:
        preview = apply_retention(db, clean_days=7, malicious_days=90, dry_run=True)
        assert preview["purged_body"] >= 1
        assert preview.get("dry_run") is True

        # Verify row was NOT modified
        reloaded = db.query(models.EmailRecord).filter_by(id=email.id).first()
        assert reloaded.body_text == "secret payload before retention"
    finally:
        db.query(models.EmailRecord).filter_by(id=email.id).delete()
        db.commit()
        db.close()


def test_search_sqlite_returns_snippet():
    """Fix #16: SQLite search fallback includes snippet around matched context."""
    from app.modules.search.elastic_sync import search_emails
    from app.database import SessionLocal

    db = SessionLocal()
    email = models.EmailRecord(
        subject="Audit Notification",
        body_text_masked="Notice of unusual cryptographic authorization transfer detected on primary relay.",
    )
    db.add(email)
    db.commit()
    db.refresh(email)
    try:
        res = search_emails("cryptographic authorization", db=db, all_orgs=True)
        assert res["backend"] == "sqlite"
        assert len(res["hits"]) > 0
        hit = next((h for h in res["hits"] if h["id"] == email.id), None)
        assert hit is not None
        assert "snippet" in hit
        assert "cryptographic authorization" in hit["snippet"].lower()
    finally:
        db.query(models.EmailRecord).filter_by(id=email.id).delete()
        db.commit()
        db.close()


def test_default_vercel_preview_regex():
    """Fix #18: Verify DEFAULT_VERCEL_PREVIEW_REGEX constant."""
    import re
    assert re.fullmatch(DEFAULT_VERCEL_PREVIEW_REGEX, "https://email-scanner-abc123.vercel.app")
    assert not re.fullmatch(DEFAULT_VERCEL_PREVIEW_REGEX, "https://evil.app")


def test_smtp_auth_hardened_in_production(monkeypatch):
    """Fix #4: SMTP_REQUIRE_AUTH must not be disabled in production."""
    from app.config import require_secrets

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "x" * 40)
    monkeypatch.setenv("TOKEN_ENCRYPTION_KEY", "k" * 40)
    monkeypatch.setenv("CUSTODY_KEY", "c" * 40)
    monkeypatch.setenv("SMTP_ENABLED", "1")
    monkeypatch.setenv("SMTP_REQUIRE_AUTH", "0")
    get_settings.cache_clear()

    with pytest.raises(RuntimeError, match="SMTP_REQUIRE_AUTH must be enabled"):
        require_secrets()

    # And with auth enabled, credentials are required
    monkeypatch.setenv("SMTP_REQUIRE_AUTH", "1")
    monkeypatch.setenv("SMTP_USERNAME", "")
    monkeypatch.setenv("SMTP_PASSWORD", "")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="SMTP_USERNAME and SMTP_PASSWORD must be configured"):
        require_secrets()

    get_settings.cache_clear()


def test_multi_replica_graph_guard(monkeypatch):
    """Fix #3: EXPECTED_REPLICAS > 1 requires NEO4J_URI in production."""
    from app.main import app, lifespan

    settings = get_settings()
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "secret_key", "x" * 40)
    monkeypatch.setattr(settings, "token_encryption_key", "k" * 40)
    monkeypatch.setattr(settings, "custody_key", "c" * 40)
    monkeypatch.setattr(settings, "expected_replicas", 2)
    monkeypatch.setattr(settings, "neo4j_uri", "")
    monkeypatch.delenv("NEO4J_URI", raising=False)

    with pytest.raises(RuntimeError, match="EXPECTED_REPLICAS > 1 requires NEO4J_URI"):
        asyncio.run(lifespan(app).__aenter__())
