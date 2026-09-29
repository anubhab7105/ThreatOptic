"""P0 model integrity: trust gate before unpickling, signature path,
missing-sidecar fail-closed, transformer revision pinning."""
import hashlib
import os
import stat
import sys
import types

import pytest

from app.modules import model_trust
from app.modules.model_trust import ModelTrustError, verify_model_artifact


def _write(path, data: bytes = b"model-bytes") -> str:
    with open(path, "wb") as f:
        f.write(data)
    return path


def _sidecar(path, data: bytes) -> None:
    with open(path + ".sha256", "w", encoding="utf-8") as f:
        f.write(hashlib.sha256(data).hexdigest())


def _as_prod(monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "app_env", "production")
    monkeypatch.delenv("MODEL_VERIFY_KEY", raising=False)
    monkeypatch.delenv("MODEL_TRUST_INSECURE", raising=False)


def _as_dev(monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "app_env", "development")
    monkeypatch.delenv("MODEL_VERIFY_KEY", raising=False)
    monkeypatch.delenv("MODEL_TRUST_INSECURE", raising=False)


def test_valid_sidecar_loads(tmp_path, monkeypatch):
    _as_prod(monkeypatch)
    p = _write(str(tmp_path / "m.pkl"))
    _sidecar(p, b"model-bytes")
    verify_model_artifact(p, purpose="test")  # no raise


def test_tampered_file_fails_closed(tmp_path, monkeypatch):
    _as_prod(monkeypatch)
    p = _write(str(tmp_path / "m.pkl"))
    _sidecar(p, b"model-bytes")
    with open(p, "ab") as f:
        f.write(b"evil")
    with pytest.raises(ModelTrustError, match="mismatch"):
        verify_model_artifact(p, purpose="test")


def test_missing_sidecar_fails_closed_prod(tmp_path, monkeypatch):
    _as_prod(monkeypatch)
    p = _write(str(tmp_path / "m.pkl"))
    with pytest.raises(ModelTrustError, match="no signature.*no.*checksum|refusing"):
        verify_model_artifact(p, purpose="test")


def test_missing_sidecar_dev_needs_explicit_bypass(tmp_path, monkeypatch, caplog):
    _as_dev(monkeypatch)
    p = _write(str(tmp_path / "m.pkl"))
    with pytest.raises(ModelTrustError, match="MODEL_TRUST_INSECURE"):
        verify_model_artifact(p, purpose="test")
    monkeypatch.setenv("MODEL_TRUST_INSECURE", "1")
    import logging
    with caplog.at_level(logging.WARNING, logger="model_trust"):
        verify_model_artifact(p, purpose="test")  # explicit logged override
    assert any("UNVERIFIED" in r.message for r in caplog.records)


def test_world_writable_always_refused(tmp_path, monkeypatch):
    _as_dev(monkeypatch)
    monkeypatch.setenv("MODEL_TRUST_INSECURE", "1")  # even explicit bypass
    p = _write(str(tmp_path / "m.pkl"))
    _sidecar(p, b"model-bytes")
    os.chmod(p, 0o666)
    # Mock os.name to test world-writable check (normally skipped on Windows)
    monkeypatch.setattr("app.modules.model_trust.os.name", "posix")
    try:
        with pytest.raises(ModelTrustError, match="world-writable"):
            verify_model_artifact(p, purpose="test")
    finally:
        os.chmod(p, 0o644)


def test_signature_path(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    _as_prod(monkeypatch)
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    data = b"signed-model-bytes"
    p = _write(str(tmp_path / "m.pkl"), data)
    with open(p + ".sig", "w", encoding="utf-8") as f:
        f.write(priv.sign(data).hex())
    monkeypatch.setenv("MODEL_VERIFY_KEY", pub_hex)
    verify_model_artifact(p, purpose="test")  # no raise
    # tampered bytes fail even with sidecar present
    with open(p, "ab") as f:
        f.write(b"x")
    with pytest.raises(ModelTrustError, match="FAILED"):
        verify_model_artifact(p, purpose="test")


def test_signature_missing_sidecar_fails_with_key_set(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    _as_prod(monkeypatch)
    pub_hex = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    monkeypatch.setenv("MODEL_VERIFY_KEY", pub_hex)
    p = _write(str(tmp_path / "m.pkl"))
    with pytest.raises(ModelTrustError, match="signature sidecar is missing"):
        verify_model_artifact(p, purpose="test")


def test_nlp_missing_sidecar_no_longer_verified(tmp_path, monkeypatch):
    """The exact reported hole: missing sidecar used to return True."""
    import shutil
    import app.modules.nlp.engine as eng
    _as_prod(monkeypatch)
    assert eng._verify_checksum(eng.PINNED_MODEL_PATH) is True
    copy = str(tmp_path / "nlp-copy.joblib")
    shutil.copyfile(eng.PINNED_MODEL_PATH, copy)
    os.chmod(copy, 0o644 & ~stat.S_IWGRP & ~stat.S_IWOTH)
    assert eng._verify_checksum(copy) is False  # no sidecar -> fail closed


def test_url_ml_gate_runs_before_unpickle(tmp_path, monkeypatch):
    import app.modules.threat_intel.url_ml as uml
    _as_prod(monkeypatch)
    monkeypatch.setattr(uml, "_MODEL_PATH", str(tmp_path / "missing.pkl"))
    uml._model_bundle = None
    uml._model_error = None
    try:
        with pytest.raises(uml.ModelUnavailableError):
            uml.predict_url("https://example.com/")
    finally:
        uml._model_bundle = None
        uml._model_error = None


def test_transformer_requires_pinned_revision(monkeypatch):
    import app.modules.nlp.engine as eng
    from app.config import get_settings
    eng._transformer_pipe = None
    try:
        # production + unpinned model -> refused without calling transformers
        monkeypatch.setattr(get_settings(), "app_env", "production")
        monkeypatch.setenv("TRANSFORMERS_MODEL", "some-model")
        monkeypatch.delenv("TRANSFORMERS_REVISION", raising=False)
        assert eng._get_transformer() is None
        # production + malformed revision -> refused
        monkeypatch.setenv("TRANSFORMERS_REVISION", "not-a-hash")
        assert eng._get_transformer() is None
        # production + pinned revision -> revision threaded through
        seen = {}
        fake_mod = types.ModuleType("transformers")

        def _fake_pipeline(task, **kwargs):
            seen.update(kwargs)
            raise RuntimeError("no network in tests")

        fake_mod.pipeline = _fake_pipeline
        monkeypatch.setitem(sys.modules, "transformers", fake_mod)
        monkeypatch.setenv("TRANSFORMERS_REVISION", "a" * 40)
        assert eng._get_transformer() is None  # lib stub raised
        assert seen.get("revision") == "a" * 40
        assert seen.get("model") == "some-model"
    finally:
        eng._transformer_pipe = None
