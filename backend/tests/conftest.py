
import os

os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SECRET_KEY", "pytest-only-secret-key-32-chars-minimum")
os.environ.setdefault("CUSTODY_KEY", "pytest-only-custody-key-32-chars-min")
os.environ.setdefault("TOKEN_ENCRYPTION_KEY", "pytest-only-vault-key-32-chars-min!")
os.environ.setdefault("SETUP_TOKEN", "pytest-setup-token")



os.environ.setdefault("SUPABASE_JWT_SECRET", "pytest-supabase-jwt-secret-32-chars-min")
os.environ.pop("SUPABASE_URL", None)



os.environ.setdefault("CORS_ORIGINS", "http://localhost:5173")
os.environ.setdefault("FRONTEND_URL", "http://localhost:5173")
os.environ.setdefault("GOOGLE_REDIRECT_URI", "http://localhost:5173/")

os.environ.setdefault("RATE_LIMIT_ENABLED", "0")

import pytest


@pytest.fixture(autouse=True)
def _isolated_db(monkeypatch, tmp_path):

    import app.database as dbmod

    url = f"sqlite:///{tmp_path}/test.db"
    monkeypatch.setenv("TEST_DATABASE_URL", url)
    dbmod.rebuild_engine()
    dbmod.Base.metadata.create_all(bind=dbmod.engine)
    yield dbmod.SessionLocal
    dbmod.engine.dispose()


@pytest.fixture(autouse=True)
def _clear_global_state():

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
        from app.routers import deps
        deps._jwks_client = None
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
