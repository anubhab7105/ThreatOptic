
import asyncio
import uuid

from helpers import login, make_user


def _mk_user_with_conn(db, tag, provider="google", email=None):
    from app import models
    from app.modules.auth.vault import encrypt_secret
    u = make_user(db)
    conn = models.MailboxConnection(
        user_id=u.id, provider=provider,
        account_email=email or f"{tag}@t.local",
        encrypted_refresh_token=encrypt_secret("1//tok"))
    db.add(conn)
    db.commit()
    return u.id, conn.id


def test_fetch_clamps_counts_and_pages(monkeypatch):

    import httpx
    import app.modules.ingestion.connectors as conn_mod

    list_calls: list = []

    class Resp:
        def __init__(self, payload):
            self.status_code = 200
            self._payload = payload

        def json(self):
            return self._payload

        def raise_for_status(self):
            return None

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None, params=None):
            if "messages" in url and "/messages/" not in url and "graph" not in url:
                list_calls.append(params)

                return Resp({"messages": [{"id": f"m{n}"} for n in range(500)],
                             "nextPageToken": "tok"})
            if "graph.microsoft.com" in url and "$value" not in url and "messages" in url:
                list_calls.append(url)
                return Resp({"value": [{"id": f"g{n}"} for n in range(100)],
                             "@odata.nextLink": url + "&skip=100"})
            return Resp({})

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    out = asyncio.run(conn_mod.fetch_gmail_messages("tok", max_results=1000000))

    assert len(out) == conn_mod.SERVER_MAX_RESULTS, len(out)
    assert len(list_calls) <= conn_mod.MAX_LIST_PAGES, list_calls
    out2 = asyncio.run(conn_mod.fetch_o365_messages("tok", top=1000000))
    assert len(list_calls) <= 2 * conn_mod.MAX_LIST_PAGES


def test_poll_all_bounded_fanout_and_clamped_results(monkeypatch):

    from app.database import SessionLocal
    from app import models
    import app.services.mailbox_poll as mp

    db = SessionLocal()
    try:
        uids, cids = [], []
        for i in range(12):
            uid, cid = _mk_user_with_conn(db, f"fan-{uuid.uuid4().hex[:6]}-{i}")
            uids.append(uid)
            cids.append(cid)
    finally:
        db.close()

    current = {"n": 0, "max": 0}
    seen_max_results: list = []

    async def _fake_poll(conn_id, max_results=25):
        seen_max_results.append(max_results)
        current["n"] += 1
        current["max"] = max(current["max"], current["n"])
        await asyncio.sleep(0.01)
        current["n"] -= 1
        return {"synced": 0, "email_ids": [], "errors": []}

    monkeypatch.setattr(mp, "poll_connection_by_id", _fake_poll)
    try:
        out = asyncio.run(mp.poll_all_mailboxes(max_results=1000000))
        assert out["polled"] == 12
        assert current["max"] <= mp.MAX_MAILBOX_FANOUT, current
        assert current["max"] > 1
        assert all(m <= mp.POLL_MAX_RESULTS for m in seen_max_results)
    finally:
        db = SessionLocal()
        try:
            for cid in cids:
                db.query(models.MailboxConnection).filter_by(id=cid).delete()
            for uid in uids:
                db.query(models.User).filter_by(id=uid).delete()
            db.commit()
        finally:
            db.close()


def test_gmail_sync_rejects_huge_max_results():

    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as c:
        h = login()[0]
        r = c.post("/api/v1/gmail/sync", headers=h, json={"max_results": 1000000})
        assert r.status_code == 422, r.text
