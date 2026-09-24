"""Test-suite environment: explicit dev posture + test-only secrets.

Production defaults are fail-closed (Step 1/C1), so the suite pins a
development posture with synthetic secrets. Never point these at real
infrastructure.
"""
import os

os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SECRET_KEY", "pytest-only-secret-key-32-chars-minimum")
os.environ.setdefault("CUSTODY_KEY", "pytest-only-custody-key-32-chars-min")
os.environ.setdefault("TOKEN_ENCRYPTION_KEY", "pytest-only-vault-key-32-chars-min!")
os.environ.setdefault("SETUP_TOKEN", "pytest-setup-token")
# Rate limiting is opt-out in tests (per-test opt-in proves the gates).
os.environ.setdefault("RATE_LIMIT_ENABLED", "0")

import pytest


@pytest.fixture(autouse=True)
def _isolated_db(monkeypatch, tmp_path):
    """Every test gets a FRESH temp SQLite DB — prod/dev DBs are never touched.

    P1: isolation rides on TEST_DATABASE_URL + rebuild_engine(), i.e. the
    same fresh-settings path production uses — no object patching that a
    lifespan rebuild could silently clobber back to the dev database.
    """
    import app.database as dbmod

    url = f"sqlite:///{tmp_path}/test.db"
    monkeypatch.setenv("TEST_DATABASE_URL", url)
    dbmod.rebuild_engine()
    dbmod.Base.metadata.create_all(bind=dbmod.engine)
    yield dbmod.SessionLocal
    dbmod.engine.dispose()


@pytest.fixture(autouse=True)
def _clear_global_state():
    """Reset process-global stores between tests (graph, caches, buckets)."""
    yield
    try:
        from app.modules.graph.store import G
        G.clear()
    except Exception:
        pass
    try:
        from app.modules.cache import cache_clear
        cache_clear()
    except Exception:
        pass
    try:
        from app.modules.traceability.geoip import _geolocate_cached
        _geolocate_cached.cache_clear()
    except Exception:
        pass
    try:
        from app.modules.ingestion.smtp_server import _intake_hits
        _intake_hits.clear()
    except Exception:
        pass
    try:
        from app.modules.alerting.dispatcher import _sent_dedup, _channel_hits
        _sent_dedup.clear()
        _channel_hits.clear()
    except Exception:
        pass
    try:
        from app.routers.ws import manager
        for ws in list(manager._conns):
            manager.disconnect(ws)
    except Exception:
        pass
    try:
        from app.modules.auth import rate_limit as rl
        rl._failed_logins.clear()
        if hasattr(rl.limiter, "_storage"):
            try:
                rl.limiter._storage.reset()
            except Exception:
                pass
    except Exception:
        pass
    try:
        import app.modules.nlp.engine as nlp_eng
        nlp_eng._classifier = None
        nlp_eng._transformer_pipe = None
    except Exception:
        pass
    try:
        import app.modules.threat_intel.url_ml as url_ml
        if hasattr(url_ml, "_model"):
            url_ml._model = None
    except Exception:
        pass
    try:
        from app.modules.threat_intel import feeds as feeds_mod
        if hasattr(feeds_mod, "_feeds_cache"):
            feeds_mod._feeds_cache.clear()
        feeds_mod.aggregate_threat_intel.cache_clear() if hasattr(feeds_mod.aggregate_threat_intel, "cache_clear") else None
    except Exception:
        pass

