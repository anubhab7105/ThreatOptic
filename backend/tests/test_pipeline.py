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
