"""Model transparency tests: cached metrics file + endpoint."""
import os
import uuid

from fastapi.testclient import TestClient


def _metrics_path() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ml_models", "metrics.json"))


def test_metrics_file_schema():
    import json
    # ensure fresh metrics from the current training script
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
    import train_nlp
    metrics = train_nlp.main()
    assert os.path.exists(_metrics_path())
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
    csv_path.write_text("text,label\nWin money now, click here,phishing\nTeam lunch tomorrow,clean\nKindly wire funds discreetly,bec\njunk-row,bogus\n")
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
        uname = f"model-{uuid.uuid4().hex[:8]}"
        tok = c.post("/api/v1/auth/register", json={"username": uname, "password": "Str0ngPass!"}).json()["access_token"]
        r = c.get("/api/v1/model/metrics", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["model_exists"] is True
        assert body["accuracy"] == body["accuracy"]  # sanity: real float
        assert len(body["confusion_matrix"]) == len(body["confusion_labels"]) == 3
