
import uuid

from fastapi.testclient import TestClient
from helpers import login

A_TMPL = """From: crew@{dom}
To: victim@company.com
Subject: Invoice update {n}
Message-ID: <{n}@{dom}>
Return-Path: <b@{dom}>
Received: from relay{relay}.evil ({dom} [203.0.113.99]) by mx.company.com with ESMTPS id {n}
Content-Type: text/plain

Please pay invoice {n} urgently, wire transfer needed.
"""

B_TMPL = """From: crew@{dom}
To: victim@company.com
Subject: Payment reminder {n}
Message-ID: <{n}@{dom}>
Return-Path: <b@{dom}>
Received: from other.evil ({dom} [198.51.100.7]) by mx.company.com with ESMTPS id {n}
Content-Type: text/plain

Quarterly report draft ready for review, no action needed.
"""


def _auth(c: TestClient) -> dict:
    return login()[0]


def test_campaign_cards_and_detail():
    from app.main import app

    with TestClient(app) as c:
        h = _auth(c)

        for dom, n, relay in (("evilcamp1.test", "c1", "a"), ("evilcamp2.test", "c2", "b"),
                              ("lonely.test", "c3", "c")):
            tmpl = A_TMPL if relay in ("a", "b") else B_TMPL
            r = c.post("/api/v1/emails/ingest", headers=h, json={"raw": tmpl.format(dom=dom, n=n, relay=relay)})
            assert r.status_code == 200, r.text

        r = c.get("/api/v1/campaigns", headers=h)
        assert r.status_code == 200, r.text
        cards = r.json()
        card = next((k for k in cards if k["ip"] == "203.0.113.99"), None)
        assert card is not None, cards
        assert set(card["domains"]) >= {"evilcamp1.test", "evilcamp2.test"}
        assert card["email_count"] == 2
        assert 0 < card["confidence"] <= 0.95
        assert card["first_seen"] and card["last_seen"]

        d = c.get(f"/api/v1/campaigns/{card['id']}", headers=h)
        assert d.status_code == 200, d.text
        detail = d.json()
        assert detail["card"]["id"] == card["id"]
        assert len(detail["emails"]) == 2
        assert detail["graph"]["nodes"]
        subjects = [e["subject"] for e in detail["emails"]]
        assert any("Invoice update" in s for s in subjects)
        for e in detail["emails"]:
            assert e["id"] and "fraud_score" in e and "classification" in e

        assert c.get("/api/v1/campaigns/nope", headers=h).status_code == 404
        assert c.get("/api/v1/campaigns").status_code == 401


def _auth_org(c, role="Analyst"):

    from app import models
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        h, user = login(role=role)
        org = models.Organization(name=f"tcamp-{user.id[:8]}", compliance_policy={})
        db.add(org)
        db.flush()
        row = db.query(models.User).filter_by(id=user.id).first()
        row.organization_id = org.id
        db.commit()
        return h, org.id
    finally:
        db.close()


def _ingest(c, headers, sender, ip, n):
    raw = (f"From: {sender}\nTo: v@company.com\nSubject: t{n}\n"
           f"Message-ID: <{n}@x.test>\nReturn-Path: <b@x.test>\n"
           f"Received: from r.evil ({sender.split('@')[-1]} [{ip}]) by mx.c with ESMTPS id {n}\n"
           f"Content-Type: text/plain\n\nhello {n}")
    r = c.post("/api/v1/emails/ingest", headers=headers, json={"raw": raw})
    assert r.status_code == 200, r.text


def test_org_less_user_sees_only_null_org_campaigns():

    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        hx, org_x = _auth_org(c)
        _ingest(c, hx, "x@orgx1.test", "203.0.113.90", "x1")
        _ingest(c, hx, "x@orgx2.test", "203.0.113.90", "x2")
        hn = _auth(c)
        _ingest(c, hn, "n@null1.test", "203.0.113.91", "n1")
        _ingest(c, hn, "n@null2.test", "203.0.113.91", "n2")

        cards_n = c.get("/api/v1/campaigns", headers=hn).json()
        ips_n = {k["ip"] for k in cards_n}
        assert "203.0.113.91" in ips_n, cards_n
        assert "203.0.113.90" not in ips_n, cards_n
        for k in cards_n:
            assert k["email_count"] >= 0
            for e in c.get(f"/api/v1/campaigns/{k['id']}", headers=hn).json()["emails"]:
                assert e["sender"].endswith(("@null1.test", "@null2.test")), e

        cards_x = c.get("/api/v1/campaigns", headers=hx).json()
        assert "203.0.113.90" in {k["ip"] for k in cards_x}


def test_graph_related_hides_foreign_email_nodes():

    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        ha, _ = _auth_org(c)
        _ingest(c, ha, "aaa@aten.test", "203.0.113.92", "ga1")
        hb, _ = _auth_org(c)
        _ingest(c, hb, "bbb@bten.test", "203.0.113.92", "gb1")

        rel = c.get("/api/v1/graph/related", headers=ha,
                    params={"value": "203.0.113.92"}).json()
        ids = {n["id"] for n in rel["nodes"]}
        assert "email:aaa@aten.test" in ids, ids
        assert "email:bbb@bten.test" not in ids, ids
        assert "ip:203.0.113.92" in ids, ids

        for e in rel["edges"]:
            assert e["source"] in ids and e["target"] in ids


        cards = c.get("/api/v1/campaigns", headers=ha).json()
        card = next(k for k in cards if k["ip"] == "203.0.113.92")
        detail = c.get(f"/api/v1/campaigns/{card['id']}", headers=ha).json()
        gids = {n["id"] for n in detail["graph"]["nodes"]}
        assert "email:aaa@aten.test" in gids, gids
        assert "email:bbb@bten.test" not in gids, gids
        assert all(e["sender"].endswith("@aten.test") for e in detail["emails"])
