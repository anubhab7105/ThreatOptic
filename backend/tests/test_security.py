"""Security posture tests: CORS lockdown (F2), custody-key gate (F4).

The CORS block exists because split deploys (Vercel frontend + Railway API)
fail in exactly one way: the browser silently refuses the response and the
only symptom is `TypeError: Failed to fetch`. These tests pin both halves —
the allowlist stays narrow, and the effective allowlist is discoverable.
"""
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


# --- allowlist normalization -------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("https://a.app", ["https://a.app"]),
    ("https://a.app/", ["https://a.app"]),                      # trailing slash
    ("  https://a.app  ", ["https://a.app"]),                    # stray whitespace
    ("https://a.app,https://b.app", ["https://a.app", "https://b.app"]),
    ("https://a.app, https://b.app/", ["https://a.app", "https://b.app"]),
    ("https://a.app,https://a.app", ["https://a.app"]),          # dedupe
    ("HTTPS://A.App", ["https://a.app"]),                        # scheme/host case
    ("https://a.app,,", ["https://a.app"]),                       # empty entries
    ("", []),
])
def test_cors_origin_list_normalizes(raw, expected):
    """A trailing slash or capital letter in the env value is the difference
    between a working app and 'blocked by CORS' — browsers send a bare,
    lowercase origin."""
    from app.config import Settings
    assert Settings(cors_origins=raw).cors_origin_list == expected


# --- loopback-only detection (the actual misconfiguration) -------------------

@pytest.mark.parametrize("origins,remote", [
    ("https://email-scanner-chi.vercel.app", True),
    ("http://localhost:5173", False),
    ("http://127.0.0.1:5173", False),
    ("http://[::1]:5173", False),
    ("http://app.localhost:5173", False),
    ("http://localhost:5173,https://a.app", True),
    ("", False),
])
def test_cors_allows_remote_origins(origins, remote):
    from app.config import Settings
    assert Settings(cors_origins=origins).cors_allows_remote_origins() is remote


def test_loopback_only_allowlist_warns_at_startup(caplog, monkeypatch):
    """Loopback-only must be announced, not discovered in a browser console."""
    import asyncio
    import logging

    from app.config import get_settings
    from app.main import app, lifespan

    settings = get_settings()
    monkeypatch.setattr(settings, "cors_origins", "http://localhost:5173")
    monkeypatch.setattr(settings, "cors_origin_regex", "")
    with caplog.at_level(logging.INFO, logger="main"):
        try:
            asyncio.run(lifespan(app).__aenter__())
        except Exception:
            pass  # later startup steps may fail; the CORS gate already ran
    assert any("no non-loopback origin" in r.message for r in caplog.records), \
        [r.message for r in caplog.records]


# --- regex origins (opt-in) --------------------------------------------------

def test_cors_regex_is_combined_and_matches_preview_origin():
    from app.config import Settings
    s = Settings(cors_origins="https://prod.app",
                 cors_origin_regex=r"https://[a-z0-9-]+\.vercel\.app")
    assert s.cors_regex_pattern == r"https://[a-z0-9-]+\.vercel\.app"
    assert s.cors_allows("https://email-scanner-abc123.vercel.app")
    assert s.cors_allows("https://prod.app")
    # anchored: a lookalike host must not match
    assert not s.cors_allows("https://vercel.app")
    assert not s.cors_allows("https://evil.app")


def test_cors_regex_multiple_patterns_are_alternated():
    from app.config import Settings
    s = Settings(cors_origins="https://prod.app",
                 cors_origin_regex=r"https://a\.app,https://b\.app")
    assert s.cors_regex_pattern == r"(?:https://a\.app)|(?:https://b\.app)"


def test_cors_regex_multiple_patterns_all_match():
    from app.config import Settings
    s = Settings(cors_origins="https://prod.app",
                 cors_origin_regex=r"https://[a-z0-9-]+\.vercel\.app,https://preview\.internal")
    assert s.cors_allows("https://branch-1.vercel.app")
    assert s.cors_allows("https://preview.internal")
    assert not s.cors_allows("https://elsewhere.test")


def test_unbounded_cors_regex_detected():
    from app.config import Settings, cors_regex_is_unbounded
    for bad in (".*", r"https?://.*", r".+", r"https://.*\.invalid"):
        s = Settings(cors_origins="https://prod.app", cors_origin_regex=bad)
        assert cors_regex_is_unbounded(s) == bad, bad
    ok = Settings(cors_origins="https://prod.app",
                  cors_origin_regex=r"https://[a-z0-9-]+\.vercel\.app")
    assert cors_regex_is_unbounded(ok) is None


def test_unbounded_cors_regex_refuses_boot(monkeypatch):
    """A match-everything regex with credentials is '*' in disguise."""
    import asyncio
    from app.config import get_settings
    from app.main import app, lifespan

    settings = get_settings()
    monkeypatch.setattr(settings, "cors_origins", "https://prod.app")
    monkeypatch.setattr(settings, "cors_origin_regex", ".*")
    with pytest.raises(RuntimeError, match="CORS_ORIGIN_REGEX"):
        asyncio.run(lifespan(app).__aenter__())


# --- diagnosability ----------------------------------------------------------

def _cors_client(origins: str, regex: str | None = None) -> TestClient:
    """A minimal app wired with CORSMiddleware exactly as main.py does.

    The real app builds its middleware at import time, so it cannot be
    varied per-test; this exercises the same contract for arbitrary
    settings. test_app_cors_middleware_uses_configured_allowlist pins that
    the real app is wired from the configured values.
    """
    from fastapi.middleware.cors import CORSMiddleware
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from app.config import Settings

    s = Settings(cors_origins=origins, cors_origin_regex=regex or "")
    app = Starlette(routes=[
        Route("/api/v1/emails", lambda request: JSONResponse({"ok": True}),
              methods=["GET", "POST"]),
    ])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=s.cors_origin_list,
        allow_origin_regex=s.cors_regex_pattern,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return TestClient(app)


def test_preflight_succeeds_for_allowed_split_deploy_origin():
    """End-to-end: the exact call shape a Vercel-hosted SPA makes.

    The frontend sends `Authorization`, so the browser preflights. This is
    the request that fails when CORS_ORIGINS does not contain the frontend
    origin — the reported symptom being "TypeError: Failed to fetch" and
    "No 'Access-Control-Allow-Origin' header".
    """
    origin = "https://email-scanner-chi.vercel.app"
    with _cors_client(origin) as c:
        pre = c.options("/api/v1/emails", headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        })
        assert pre.status_code == 200
        assert pre.headers.get("access-control-allow-origin") == origin
        assert "authorization" in (pre.headers.get("access-control-allow-headers") or "").lower()
        assert "GET" in (pre.headers.get("access-control-allow-methods") or "")

        # And a foreign origin is still refused.
        evil = c.options("/api/v1/emails", headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        })
        assert "access-control-allow-origin" not in evil.headers


def test_preflight_matches_despite_trailing_slash_in_config():
    """A stray trailing slash in CORS_ORIGINS must not silently block the
    deployment — browsers send the origin without one."""
    origin = "https://email-scanner-chi.vercel.app"
    with _cors_client(origin + "/") as c:
        r = c.get("/api/v1/emails", headers={"Origin": origin})
        assert r.headers.get("access-control-allow-origin") == origin


def test_preflight_allows_via_regex_origin():
    origin = "https://email-scanner-abc123.vercel.app"
    with _cors_client("https://prod.app", regex=r"https://[a-z0-9-]+\.vercel\.app") as c:
        r = c.get("/api/v1/emails", headers={"Origin": origin})
        assert r.headers.get("access-control-allow-origin") == origin
        blocked = c.get("/api/v1/emails", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in blocked.headers


def test_app_cors_middleware_uses_configured_allowlist():
    """Pin the real app's wiring: allowlist, regex, and credentials-on."""
    from fastapi.middleware.cors import CORSMiddleware

    from app.config import get_settings
    from app.main import app

    settings = get_settings()
    cors = [m for m in app.user_middleware if m.cls is CORSMiddleware]
    assert cors, "CORSMiddleware is not installed"
    kw = cors[0].kwargs
    assert kw["allow_origins"] == settings.cors_origin_list
    assert kw["allow_origin_regex"] == settings.cors_regex_pattern
    assert kw["allow_credentials"] is True
    assert "*" not in kw["allow_origins"]


def test_health_reports_effective_allowlist():
    """/health is curlable, so a deployer can see what CORS actually allows
    without opening devtools against a blocked request."""
    from app.config import get_settings
    from app.main import app
    with TestClient(app) as c:
        body = c.get("/health").json()
    settings = get_settings()
    assert body["cors_origins"] == settings.cors_origin_list
    assert body["cors_allows_remote_origins"] == settings.cors_allows_remote_origins()
    assert "frontend_url" in body
    # No secret may leak through the diagnostic surface.
    assert settings.secret_key not in str(body)
    assert settings.token_encryption_key not in str(body)


def test_cors_allows_matches_middleware_decision():
    from app.config import Settings
    s = Settings(cors_origins="https://a.app,http://localhost:5173")
    assert s.cors_allows("https://a.app")
    assert s.cors_allows("https://a.app/")     # browser never sends this, be lenient
    assert s.cors_allows("http://localhost:5173")
    assert not s.cors_allows("https://b.app")
    assert not s.cors_allows("")
    assert not s.cors_allows(None)


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
