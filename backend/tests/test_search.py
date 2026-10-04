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
    out = sync.search_emails("hit", db=None, organization_id="org-1")
    assert out["backend"] == "elasticsearch" and out["hits"][0]["id"] == "abc"
    # The multi_match is now nested inside a tenant filter rather than being
    # the whole query -- assert both the match and the scoping.
    sent = calls["search"][1]
    assert "multi_match" in str(sent)
    assert "org-1" in str(sent), "explicit org scope must reach the ES query"


# ---------------------------------------------------------------------------
# C7: the tenant scope must be explicit; omitting it used to search all orgs.
# ---------------------------------------------------------------------------

def test_search_refuses_implicit_all_tenants_scope():
    """A caller that forgets the tenant scope must fail closed.

    The old signature was `organization_id="__all__"`, so any new caller that
    omitted the argument silently searched every organization in both the ES
    and the SQLite path.
    """
    from app.modules.search.elastic_sync import search_emails
    import pytest

    with pytest.raises(ValueError, match="explicit organization_id"):
        search_emails("anything", db=None)


def test_search_scopes_to_requesting_tenant(monkeypatch):
    """SQLite path: a tenant search must not return another org's mail."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base
    from app import models
    from app.modules.search import elastic_sync as sync

    monkeypatch.setattr(sync, "_client", lambda: None)  # force SQLite path
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    db = sessionmaker(bind=eng)()

    mine = models.EmailRecord(subject="acme payroll", body_text_masked="secret",
                              organization_id="org-A")
    theirs = models.EmailRecord(subject="acme payroll", body_text_masked="secret",
                                organization_id="org-B")
    db.add_all([mine, theirs])
    db.commit()

    hits = sync.search_emails("payroll", db=db, organization_id="org-A")["hits"]
    assert [h["id"] for h in hits] == [mine.id], "cross-tenant row leaked"

    admin_hits = sync.search_emails("payroll", db=db, all_orgs=True)["hits"]
    assert len(admin_hits) == 2, "Admin cross-tenant search must see both"


def test_admin_search_is_not_limited_to_orgless_rows(monkeypatch):
    """Admin passed organization_id=None, meaning 'no org assigned'.

    In both backends that is `IS NULL` / `must_not exists`, so an Admin
    searching saw none of the real tenants' mail. Cross-tenant search is now
    requested explicitly with all_orgs=True.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base
    from app import models
    from app.modules.search import elastic_sync as sync

    monkeypatch.setattr(sync, "_client", lambda: None)
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    db = sessionmaker(bind=eng)()
    db.add(models.EmailRecord(subject="acme payroll", body_text_masked="x",
                              organization_id="org-A"))
    db.commit()

    scoped = sync.search_emails("payroll", db=db, organization_id=None)["hits"]
    assert scoped == [], "organization_id=None still means 'no org assigned'"
    across = sync.search_emails("payroll", db=db, all_orgs=True)["hits"]
    assert len(across) == 1


def test_search_limit_is_clamped(monkeypatch):
    """The SQLite path applied `limit` unclamped while ES capped at 100."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base
    from app import models
    from app.modules.search import elastic_sync as sync

    monkeypatch.setattr(sync, "_client", lambda: None)
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    db = sessionmaker(bind=eng)()
    db.add_all([models.EmailRecord(subject=f"payroll {i}", body_text_masked="x",
                                   raw_eml_hash=f"hash{i:04d}",
                                   organization_id="org-A") for i in range(150)])
    db.commit()

    assert len(sync.search_emails("payroll", limit=5000, db=db,
                                  organization_id="org-A")["hits"]) <= 100
