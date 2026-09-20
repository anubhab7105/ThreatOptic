import asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app import models  # noqa
from app.services.pipeline import process_raw_email

PHISH = b"""From: "CFO" <cfo@xn--companny.top>
To: ap@company.com
Subject: Urgent wire transfer - confidential
Message-ID: <t1@xn--companny.top>
Return-Path: <x@evil.test>
Received: from evil.test (evil.test [45.148.10.88]) by mx.company.com with ESMTPS id a
Content-Type: text/plain

Kindly wire $9000 to new vendor immediately, do not disclose. Pay at http://malicious-example.com/pay
"""
CLEAN = b"""From: Alice <alice@company.com>
To: bob@company.com
Subject: Standup notes
Message-ID: <c1@company.com>
Return-Path: <alice@company.com>
Received: from mail.company.com (mail.company.com [93.184.216.34]) by mx.company.com with ESMTPS id b
Content-Type: text/plain

Here are the notes from standup, no action needed.
"""


def _db():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    return sessionmaker(bind=eng)()


def test_phish_scores_high():
    db = _db()
    res = asyncio.run(process_raw_email(db, PHISH))
    assert res["fraud_score"] >= 50, res
    assert res["action"] in ("Quarantine", "JunkOrHold", "DeliverWithBanner")


def test_clean_scores_low():
    db = _db()
    res = asyncio.run(process_raw_email(db, CLEAN))
    assert res["fraud_score"] < 50, res


def test_received_chain_and_geo():
    from app.modules.forensics.received_chain import reconstruct_path
    from app.modules.traceability.ip_extractor import extract_origin_ip
    raw = {b"Received": b"from a ([45.1.1.1]) by b; from internal ([10.0.0.1]) by a"}
    # minimal dict form
    h = {"Received": "from evil.test (evil.test [45.148.10.88]) by mx.company.com with ESMTPS\nfrom internal ([10.0.0.5]) by evil.test"}
    path = reconstruct_path(h)
    assert len(path) == 2
    assert extract_origin_ip(path) == "45.148.10.88"


def test_pii_masking():
    from app.modules.privacy.masking import mask_text
    assert "[CARD-REDACTED]" in mask_text("card 4111 1111 1111 1111 here")
    assert "***@" in mask_text("contact alice@example.com")


def test_report_pdf():
    from app.modules.reporting.generator import build_report_pdf
    pdf = build_report_pdf({"subject": "t", "sender_address": "a@b.c"}, {"fraud_score": 95, "threat_classification": "Critical", "nlp_cues_detected": [], "authentication_results": {}, "action_taken": "Quarantine"}, {"origin_ip": "1.1.1.1", "geolocation": {}, "relay_chain": [], "isp_asn": "", "is_vpn_tor": False}, {"campaign": "unknown", "confidence": 0, "signals": []})
    assert pdf[:4] == b"%PDF"


def test_graph_related_no_crash():
    from app.modules.graph.store import upsert_email_graph, related_entities
    upsert_email_graph("ceo@xn--paypa1-secure.top", "45.148.10.88", ["xn--paypa1-secure.top"])
    rel = related_entities("ceo@xn--paypa1-secure.top")
    assert len(rel["nodes"]) >= 2
    # full display-name header must also resolve (API extracts bare email)
    import re
    m = re.search(r"[\w.\-+]+@[\w.\-]+\.\w+", '"CEO" <ceo@xn--paypa1-secure.top>')
    assert m and related_entities(m.group(0))["nodes"]


def test_api_validation():
    import uuid
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        # unauthenticated requests are rejected before validation
        assert c.post("/api/v1/emails/ingest", json={"raw": ""}).status_code == 401
        assert c.get("/api/v1/emails/does-not-exist").status_code == 401
        assert c.post("/api/v1/cases", json={"title": ""}).status_code == 401

        uname = f"validator-{uuid.uuid4().hex[:8]}"
        tok = c.post("/api/v1/auth/register", json={"username": uname, "password": "Str0ngPass!"}).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        assert c.post("/api/v1/emails/ingest", headers=h, json={"raw": ""}).status_code == 422
        assert c.get("/api/v1/emails/does-not-exist", headers=h).status_code == 404
        assert c.post("/api/v1/cases", headers=h, json={"title": ""}).status_code == 400
