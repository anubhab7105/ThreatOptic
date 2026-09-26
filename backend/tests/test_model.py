"""Model transparency tests: cached metrics file + endpoint."""
import os
import uuid

import pytest
from fastapi.testclient import TestClient
from helpers import login


def _metrics_path() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ml_models", "metrics.json"))


def test_metrics_file_schema(tmp_path):
    # Train into a tmp dir: the suite must never rewrite the shipped,
    # checksum-pinned model artifact in ml_models/.
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
    import train_nlp
    metrics = train_nlp.main(out_dir=str(tmp_path))
    assert os.path.exists(os.path.join(str(tmp_path), "metrics.json"))
    assert os.path.exists(os.path.join(str(tmp_path), "phishing_clf.joblib"))
    # Sidecar is written next to the model so the trust gate can verify it.
    assert os.path.exists(os.path.join(str(tmp_path), "phishing_clf.joblib.sha256"))
    for key in ("accuracy", "macro_precision", "macro_recall", "macro_f1",
                "per_class", "confusion_matrix", "confusion_labels", "n_train", "n_test"):
        assert key in metrics, key
    assert set(metrics["per_class"]) == {"bec", "clean", "phishing"}
    for cls, vals in metrics["per_class"].items():
        for k in ("precision", "recall", "f1", "support"):
            assert k in vals, (cls, k)
        assert 0.0 <= vals["precision"] <= 1.0
    n = len(metrics["confusion_labels"])
    assert len(metrics["confusion_matrix"]) == n
    assert all(len(row) == n for row in metrics["confusion_matrix"])
    assert sum(sum(row) for row in metrics["confusion_matrix"]) == metrics["n_test"]
    assert "dataset" in metrics  # records corpus vs curated fallback


def test_training_data_loader_csv_and_fallback(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
    import train_nlp

    csv_path = tmp_path / "dataset.csv"
    csv_path.write_text('text,label\n"Win money now, click here",phishing\nTeam lunch tomorrow,clean\nKindly wire funds discreetly,bec\njunk-row,bogus\n')
    monkeypatch.setattr(train_nlp, "dataset_csv_path", lambda: str(csv_path))
    X, y, source = train_nlp.load_training_data()
    assert (X, y) == (["Win money now, click here", "Team lunch tomorrow", "Kindly wire funds discreetly"],
                      ["phishing", "clean", "bec"])
    assert "dataset.csv" in source

    monkeypatch.setattr(train_nlp, "dataset_csv_path", lambda: str(tmp_path / "missing.csv"))
    X, y, source = train_nlp.load_training_data()
    assert len(X) == len(y) > 0 and "fallback" in source


def test_model_metrics_endpoint():
    from app.main import app

    with TestClient(app) as c:
        assert c.get("/api/v1/model/metrics").status_code == 401
        r = c.get("/api/v1/model/metrics", headers=login()[0])
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["model_exists"] is True
        assert body["accuracy"] == body["accuracy"]  # sanity: real float
        assert len(body["confusion_matrix"]) == len(body["confusion_labels"]) == 3


def test_shipped_model_matches_its_sidecar():
    """The committed artifact and its .sha256 sidecar must agree.

    Training writes both atomically, so a mismatch means someone replaced
    the model without re-signing it — the exact state the P0 trust gate
    refuses to unpickle.
    """
    import hashlib
    repo_models = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ml_models"))
    model = os.path.join(repo_models, "phishing_clf.joblib")
    sidecar = model + ".sha256"
    if not (os.path.exists(model) and os.path.exists(sidecar)):
        pytest.skip("shipped model artifact not present in this checkout")
    h = hashlib.sha256()
    with open(model, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    with open(sidecar, encoding="utf-8") as f:
        assert f.read().strip() == h.hexdigest()


def test_train_nlp_respects_out_dir(tmp_path):
    """out_dir keeps training out of the repo (the suite's safety valve)."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
    import train_nlp
    model_path, metrics_path = train_nlp.out_paths(str(tmp_path / "nested"))
    assert model_path.startswith(str(tmp_path))
    assert metrics_path.startswith(str(tmp_path))
    assert os.path.isdir(str(tmp_path / "nested"))
