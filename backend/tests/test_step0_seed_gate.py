"""Step 0 ground rules: seed.py must never run outside explicit dev-only flag."""
import asyncio
import os

import pytest


def _run_main():
    from app import seed
    return asyncio.run(seed.main())


def test_seed_refuses_without_flag(monkeypatch):
    monkeypatch.delenv("ALLOW_SEED", raising=False)
    with pytest.raises(RuntimeError, match="Refusing to seed"):
        _run_main()


def test_seed_refuses_outside_development(monkeypatch):
    from app.config import get_settings
    monkeypatch.setenv("ALLOW_SEED", "1")
    monkeypatch.setenv("APP_ENV", "production")
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="Refusing to seed"):
            _run_main()
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


def test_seed_gate_allows_explicit_dev(monkeypatch):
    from app import seed
    monkeypatch.setenv("ALLOW_SEED", "1")
    monkeypatch.setenv("APP_ENV", "development")
    from app.config import get_settings
    get_settings.cache_clear()
    try:
        assert seed._seed_allowed() is True
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()
