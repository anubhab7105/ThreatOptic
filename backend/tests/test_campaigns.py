"""Campaign view tests: shared-IP clusters surface as cards with email lists."""
import uuid

from fastapi.testclient import TestClient

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
    uname = f"campaign-{uuid.uuid4().hex[:8]}"
    tok = c.post("/api/v1/auth/register", json={"username": uname, "password": "Str0ngPass!", "role": "Analyst"}).json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}


def test_campaign_cards_and_detail():
    from app.main import app

    with TestClient(app) as c:
        h = _auth(c)
        # two domains sharing one IP -> one cluster; third mail on another IP stays out
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
