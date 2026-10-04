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
    # 10 passed domains + the sender's own domain, in as few batches as possible
    assert sum(len(p.get("ds", [])) for p in unwinds) >= 10
    assert max(len(p.get("ds", [])) for p in unwinds) >= 10


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
        senders = [n for n in store_mod.G.nodes
                   if str(n).startswith("email:u") and str(n).endswith("@t.local")]
        assert len(senders) == 8, senders
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


# ---------------------------------------------------------------------------
# C7: related_entities' DB-hydration branch reads EmailRecord directly, so
# the tenant scope has to reach the query -- not just the post-filter the
# router applies to the response.
#
# Note the shared graph itself is deliberately cross-tenant (ensure_graph_hydrated
# loads every org; the router strips foreign email nodes). These tests isolate
# the one branch that was unscoped by pre-seeding the graph so hydration
# short-circuits, leaving only related_entities' own DB read in play.
# ---------------------------------------------------------------------------

def _two_org_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base
    from app import models

    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    db = sessionmaker(bind=eng)()
    db.add(models.EmailRecord(
        sender_address="ceo@acme.test", recipient_address="cfo@acme.test",
        subject="acme wire transfer", organization_id="org-A"))
    db.add(models.EmailRecord(
        sender_address="payroll@othercorp.test", recipient_address="hr@othercorp.test",
        subject="othercorp payroll", organization_id="org-B"))
    db.commit()
    return db


def _isolate_hydration():
    """Keep ensure_graph_hydrated() a no-op so only the branch under test runs."""
    store.G.clear()
    store.upsert_email_graph("seed@present.test", "", ["present.test"])


def test_email_id_pivot_cannot_reach_another_tenants_row(monkeypatch):
    """Passing a foreign email_id used to hydrate + root the traversal there."""
    from app import models
    monkeypatch.setattr(store, "_neo", lambda: None)
    _isolate_hydration()
    db = _two_org_db()
    try:
        foreign_id = db.query(models.EmailRecord).filter_by(
            organization_id="org-B").first().id

        # "unknown@..." resolves only via email_id, never via a substring match.
        rel = store.related_entities("unknown@nowhere.test", db=db, email_id=foreign_id,
                                     organization_id="org-A")
        assert not any("othercorp" in n["id"] for n in rel["nodes"]), rel["nodes"]

        # The same call with the explicit cross-tenant sentinel does resolve the
        # row -- so the assertion above proves scoping, not a broken lookup.
        _isolate_hydration()
        wide = store.related_entities("unknown@nowhere.test", db=db, email_id=foreign_id,
                                      organization_id=store.ALL_TENANTS)
        assert any("othercorp" in n["id"] for n in wide["nodes"]), wide
    finally:
        db.close()
        store.G.clear()


def test_sender_substring_fallback_is_tenant_scoped(monkeypatch):
    """The ILIKE '%value%' fallback picked .first() from *any* organization."""
    monkeypatch.setattr(store, "_neo", lambda: None)
    _isolate_hydration()
    db = _two_org_db()
    try:
        # "payroll" appears only on org-B's row.
        rel = store.related_entities("payroll", db=db, organization_id="org-A")
        assert not any("othercorp" in n["id"] for n in rel["nodes"]), rel["nodes"]

        wide = store.related_entities("payroll", db=db, organization_id=store.ALL_TENANTS)
        assert any("othercorp" in n["id"] for n in wide["nodes"]), wide
    finally:
        db.close()
        store.G.clear()


def test_org_sentinel_semantics():
    """ALL_TENANTS widens; a real id pins; None (no org) matches nothing."""
    from sqlalchemy import select
    from app import models

    def _sql(org):
        return str(
            select(models.EmailRecord)
            .where(store._org_clause(models.EmailRecord, org))
            .compile(compile_kwargs={"literal_binds": True})
        )

    assert "org-A" in _sql("org-A")
    assert "false" in _sql(None).lower() or "1 = 0" in _sql(None), \
        "organization_id=None must match nothing, not everything"


def test_unmatched_short_value_returns_empty_not_500(monkeypatch):
    """`nx.ego_graph(None)` raised NodeNotFound for any value that matched
    nothing and had no '@' -- GET /graph/related?value=a was a 500 for every
    authenticated caller."""
    monkeypatch.setattr(store, "_neo", lambda: None)
    store.G.clear()
    try:
        for v in ("a", "%", "zz", "___"):
            assert store.related_entities(v) == {"nodes": [], "edges": []}, v
    finally:
        store.G.clear()


def test_like_wildcards_in_search_value_are_escaped(monkeypatch):
    """`sender_address ILIKE '%<value>%'` treated % and _ as wildcards, so a
    search for "%" matched every sender and hydrated from whichever row
    .first() returned -- of any organization."""
    monkeypatch.setattr(store, "_neo", lambda: None)
    _isolate_hydration()
    db = _two_org_db()
    try:
        # '%' as a literal substring matches no address.
        assert store.related_entities("%", db=db,
                                      organization_id=store.ALL_TENANTS)["nodes"] == []
        # '_' is a single-character wildcard: this must not match "acme.test".
        assert store.related_entities("a_cme.test", db=db,
                                      organization_id=store.ALL_TENANTS)["nodes"] == []
        # Sanity: the literal search still works.
        assert store.related_entities("acme.test", db=db,
                                      organization_id=store.ALL_TENANTS)["nodes"] != []
    finally:
        db.close()
        store.G.clear()


def test_graph_related_never_leaks_via_email_id():
    """End-to-end: a tenant cannot pivot onto another tenant's email by id."""
    from fastapi.testclient import TestClient

    from app import models
    from app.database import SessionLocal
    from app.main import app
    from helpers import auth_headers, login

    def _user_in_new_org():
        s = SessionLocal()
        try:
            _, user = login()
            org = models.Organization(name=f"gneo-{user.id[:8]}", compliance_policy={})
            s.add(org)
            s.flush()
            row = s.query(models.User).filter_by(id=user.id).first()
            row.organization_id = org.id
            s.commit()
            return auth_headers(row), org.id
        finally:
            s.close()

    with TestClient(app) as c:
        ha, _ = _user_in_new_org()
        hb, org_b = _user_in_new_org()
        r = c.post("/api/v1/emails/ingest", headers=hb, json={
            "raw": "From: payroll@othercorp.test\nTo: hr@othercorp.test\n"
                   "Subject: othercorp payroll\n\nbody"})
        assert r.status_code == 200, r.text
        foreign_id = r.json()["email_id"]
        params = {"value": "unknown@nowhere.test", "email_id": foreign_id}

        # The owning tenant gets their own graph.
        store.G.clear()
        own = c.get("/api/v1/graph/related", headers=hb, params=params)
        assert "email:payroll@othercorp.test" in {n["id"] for n in own.json()["nodes"]}, own.json()

        # A different tenant pivoting on the same id gets nothing.
        store.G.clear()
        piv = c.get("/api/v1/graph/related", headers=ha, params=params)
        assert piv.status_code == 200, piv.text
        assert not any("othercorp" in n["id"] for n in piv.json()["nodes"]), piv.json()
