"""Elastic mirror + search endpoint tests (F10)."""
import uuid

from fastapi.testclient import TestClient
from helpers import login


def _auth(c: TestClient) -> dict:
    return login()[0]


def test_index_skipped_without_es():
    import app.modules.search.elastic_sync as sync
    assert sync.index_email("x", {}, {}) == {"indexed": False, "skipped": True}


def test_search_falls_back_to_sqlite():
    from app.main import app

    with TestClient(app) as c:
        h = _auth(c)
        c.post("/api/v1/emails/ingest", headers=h,
               json={"raw": "From: zed@fallen.test\nSubject: zebra fallback probe\n\nplain body"})
        r = c.get("/api/v1/search", headers=h, params={"q": "zebra fallback probe"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["backend"] == "sqlite"
        assert any("zebra" in (hit.get("email") or {}).get("subject", "") for hit in body["hits"])
        assert c.get("/api/v1/search", headers=h).status_code == 422  # q required
        assert c.get("/api/v1/search").status_code == 401


def test_search_uses_elastic_when_configured(monkeypatch):
    import app.modules.search.elastic_sync as sync

    calls = {}

    class FakeES:
        def index(self, index, id, document):
            calls["index"] = (index, id, document)
            return {"result": "created"}

        def search(self, index, query, size):
            calls["search"] = (index, query, size)
            return {"hits": {"hits": [{"_id": "abc", "_source": {"email": {"subject": "hit"}}}]}}

    monkeypatch.setattr(sync, "_client", lambda: FakeES())
    assert sync.index_email("abc", {"subject": "hit"}, {}) == {"indexed": True}
    assert calls["index"][0] == "emails"
    out = sync.search_emails("hit", db=None)
    assert out["backend"] == "elasticsearch" and out["hits"][0]["id"] == "abc"
    assert "multi_match" in calls["search"][1]
