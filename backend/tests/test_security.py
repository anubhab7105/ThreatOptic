"""Security posture tests: CORS lockdown (F2), custody-key gate (F4)."""
import os
import pytest
from fastapi.testclient import TestClient


def test_cors_allows_configured_origin_only():
    # Configure CORS to allow the test origin BEFORE importing app
    os.environ["CORS_ORIGINS"] = "http://localhost:5173"
    # Need to clear settings cache and re-import app
    from app.config import get_settings
    get_settings.cache_clear()
    from app.main import app

    with TestClient(app) as c:
        ok = c.get("/health", headers={"Origin": "http://localhost:5173"})
        assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
        evil = c.get("/health", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in evil.headers


def test_custody_key_gate():
    import os
    from app.config import get_settings
    from app.modules.privacy import chain_of_custody as coc

    get_settings.cache_clear()
    old_env, old_key = os.environ.get("APP_ENV"), os.environ.get("CUSTODY_KEY")
    try:
        os.environ["APP_ENV"] = "production"
        os.environ["CUSTODY_KEY"] = ""
        get_settings.cache_clear()
        with pytest.raises(RuntimeError, match="CUSTODY_KEY"):
            coc.require_custody_key()
        with pytest.raises(RuntimeError, match="CUSTODY_KEY"):
            coc.custody_manifest("a", b"b")
        # with a provisioned key, non-dev works
        os.environ["CUSTODY_KEY"] = "test-secret-from-manager"
        get_settings.cache_clear()
        coc.require_custody_key()
        m = coc.custody_manifest("a", b"b")
        assert m["algorithm"] == "HMAC-SHA256" and len(m["signature"]) == 64
        # development keeps the explicit dev fallback
        os.environ["APP_ENV"] = "development"
        os.environ["CUSTODY_KEY"] = ""
        get_settings.cache_clear()
        coc.require_custody_key()
    finally:
        if old_env is None:
            os.environ.pop("APP_ENV", None)
        else:
            os.environ["APP_ENV"] = old_env
        if old_key is None:
            os.environ.pop("CUSTODY_KEY", None)
        else:
            os.environ["CUSTODY_KEY"] = old_key
        get_settings.cache_clear()
