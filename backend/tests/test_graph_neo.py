"""Graph consistency tests (F8): Neo4j-first reads with networkx fallback."""
import app.modules.graph.store as store


class FakeSession:
    def __init__(self, script):
        self._script = script

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def run(self, query, params=None, **kw):
        merged = dict(params or {})
        merged.update(kw)
        return self._script(query, merged)


class FakeDriver:
    def __init__(self, script):
        self._script = script

    def session(self):
        return FakeSession(self._script)


def _neo_script(query, params):
    if "collect(DISTINCT d.name)" in query:
        return [{"ip": "9.9.9.9", "domains": ["a.test", "b.test"], "size": 2}]
    if "UNWIND nodes(p)" in query:
        return [
            {"labels": ["Email_Address"], "props": {"address": "x@a.test"}},
            {"labels": ["IP_Address"], "props": {"ip": "9.9.9.9"}},
            {"labels": ["Domain"], "props": {"name": "a.test"}},
        ]
    if "UNWIND relationships(p)" in query:
        return [
            {"t": "SENT_FROM", "slab": ["Email_Address"], "sprops": {"address": "x@a.test"},
             "elab": ["IP_Address"], "eprops": {"ip": "9.9.9.9"}},
            {"t": "HOSTS", "slab": ["IP_Address"], "sprops": {"ip": "9.9.9.9"},
             "elab": ["Domain"], "eprops": {"name": "a.test"}},
        ]
    # root lookup
    return [{"labels": ["Email_Address"], "props": {"address": "x@a.test"}}]


def test_neo_reads_win_when_configured(monkeypatch):
    monkeypatch.setattr(store, "_neo", lambda: FakeDriver(_neo_script))
    camps = store.find_campaigns()
    assert camps == [{"ip": "9.9.9.9", "domains": ["a.test", "b.test"], "size": 2}]
    rel = store.related_entities("x@a.test")
    ids = {n["id"] for n in rel["nodes"]}
    assert ids == {"email:x@a.test", "ip:9.9.9.9", "domain:a.test"}
    assert {e["rel"] for e in rel["edges"]} == {"SENT_FROM", "HOSTS"}


def test_neo_unknown_root_returns_empty(monkeypatch):
    monkeypatch.setattr(store, "_neo", lambda: FakeDriver(lambda q, p: []))
    assert store.related_entities("nobody@nowhere.test") == {"nodes": [], "edges": []}


def test_neo_error_falls_back_to_memory(monkeypatch):
    class Boom:
        def session(self):
            raise ConnectionError("neo down")
    monkeypatch.setattr(store, "_neo", lambda: Boom())
    store.upsert_email_graph("fb@mem.test", "10.10.10.10", ["mem.test"])
    # error in reads -> networkx fallback still answers from local graph
    rel = store.related_entities("fb@mem.test")
    assert any(n["id"] == "email:fb@mem.test" for n in rel["nodes"])
    assert store.find_campaigns(min_shared=99) == []


def test_consistency_note(monkeypatch):
    from app.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "expected_replicas", 3)
    monkeypatch.delenv("NEO4J_URI", raising=False)
    monkeypatch.setattr(settings, "neo4j_uri", "")
    assert store.graph_consistency_note() is not None
    monkeypatch.setattr(settings, "expected_replicas", 1)
    assert store.graph_consistency_note() is None


def test_neo_mirror_batched_statements(monkeypatch):
    """P0: one mail mirrors in a handful of statements, not ~62."""
    calls: list = []

    def _script(query, params):
        calls.append((query, params))
        return []

    monkeypatch.setattr(store, "_neo", lambda: FakeDriver(_script))
    store.upsert_email_graph(
        "batch@test.local", "9.9.9.9",
        [f"d{i}.test" for i in range(10)], campaign="camp-x")
    assert len(calls) <= 5, calls
    unwinds = [p for q, p in calls if "UNWIND" in q]
    assert unwinds, "domains must go as UNWIND batches"
    assert any(len(p.get("ds", [])) == 10 for p in unwinds)


def test_hydration_paginated_and_capped(monkeypatch):
    """P0: hydration pages through rows and respects the total cap."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base
    from app import models
    import app.modules.graph.store as store_mod

    store.G.clear()
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    db = sessionmaker(bind=eng)()
    try:
        for i in range(12):
            db.add(models.EmailRecord(
                message_id=f"<h{i}@t.local>", sender_address=f"u{i}@t.local",
                recipient_address="r@t.local", subject="s"))
        db.commit()
        monkeypatch.setattr(store_mod, "HYDRATE_BATCH_ROWS", 5)
        monkeypatch.setattr(store_mod, "HYDRATE_MAX_ROWS", 8)
        store_mod.ensure_graph_hydrated(db)
        emails = [n for n in store_mod.G.nodes if str(n).startswith("email:")]
        assert len(emails) == 8, emails
    finally:
        db.close()
        store.G.clear()


def test_related_depth_clamped_and_output_capped(monkeypatch):
    """P0: absurd depth cannot hang the request or dump the graph."""
    monkeypatch.setattr(store, "_neo", lambda: None)
    store.G.clear()
    try:
        for i in range(30):
            store.upsert_email_graph(f"u{i}@t.local", "9.9.9.9", [f"d{i}.test"])
        rel = store.related_entities("9.9.9.9", depth=999)
        assert len(rel["nodes"]) <= store.NX_MAX_NODES
        assert len(rel["edges"]) <= store.NX_MAX_EDGES
        # garbage depth falls back instead of crashing
        rel2 = store.related_entities("9.9.9.9", depth="abc")  # type: ignore[arg-type]
        assert rel2["nodes"]
    finally:
        store.G.clear()
