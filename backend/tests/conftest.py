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

    Rebinds the module-global engine + sessionmakers (all app code resolves
    SessionLocal lazily at call time, except app.main which is patched too),
    creates the schema, and deletes the file afterwards.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    import app.database as dbmod
    import app.main as mainmod

    url = f"sqlite:///{tmp_path}/test.db"
    engine = create_engine(url, connect_args={"check_same_thread": False}, future=True)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    monkeypatch.setattr(dbmod, "engine", engine)
    monkeypatch.setattr(dbmod, "SessionLocal", session_factory)
    monkeypatch.setattr(mainmod, "SessionLocal", session_factory)
    dbmod.Base.metadata.create_all(bind=engine)
    yield session_factory
    engine.dispose()


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

