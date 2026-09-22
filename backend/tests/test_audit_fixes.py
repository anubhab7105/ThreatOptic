"""Tests verifying the Phase 1 audit remediation fixes."""
from fastapi.testclient import TestClient
from app.main import app
from app.modules.forensics.received_chain import detect_routing_anomalies
from app.modules.reporting.generator import build_report_pdf


def _auth(client: TestClient) -> dict:
    import uuid
    uname = f"audit-{uuid.uuid4().hex[:8]}"
    tok = client.post("/api/v1/auth/register", json={"username": uname, "password": "Str0ngPassword!", "role": "Analyst"}).json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}


def test_pdf_report_with_xml_special_characters():
    """Ensure email headers with <, >, and & do not crash ReportLab XML parser."""
    email = {
        "subject": "<Urgent> Wire Transfer & Account Verification",
        "sender_address": '"Security Team" <security@bank.test>',
        "recipient_address": '"Victim" <ceo@corp.test>',
        "message_id": "<msg-12345&6789@mail.test>",
        "raw_eml_hash": "a" * 64,
    }
    analysis = {
        "fraud_score": 95.0,
        "threat_classification": "Phishing",
        "action_taken": "Quarantine",
        "nlp_cues_detected": ["<urgency>", "bank & wire"],
        "authentication_results": {"spf": "fail", "dkim": "fail"},
    }
    trace = {
        "origin_ip": "198.51.100.1",
        "geolocation": {"country": "Test & Land"},
        "is_vpn_tor": False,
        "isp_asn": "AS12345 <ISP & Co>",
        "relay_chain": [
            {"from_host": "<relay1.test>", "by_host": "<mx.corp.test>", "ips": ["198.51.100.1"]}
        ],
    }
    attribution = {"campaign": "Wire-Fraud & Co", "confidence": 0.9, "signals": ["ip-cluster"]}

    pdf_bytes = build_report_pdf(email, analysis, trace, attribution)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")


def test_message_id_subdomain_not_flagged():
    """Valid organizational subdomains should not trigger message-id-mismatch."""
    headers = {
        "From": "Finance <billing@paypal.com>",
        "Message-ID": "<20260920.12345@mail.paypal.com>",
        "Received": "from mail.paypal.com by mx.google.com with ESMTPS",
    }
    flags = detect_routing_anomalies([{"from_host": "mail.paypal.com", "by_host": "mx.google.com", "ips": []}, {"from_host": "relay", "by_host": "mx", "ips": []}], headers)
    assert "message-id-mismatch" not in flags

    # Genuinely spoofed Message-ID domain SHOULD trigger flag
    spoofed = {
        "From": "Finance <billing@paypal.com>",
        "Message-ID": "<20260920.12345@evil-attacker.com>",
        "Received": "from evil-attacker.com by mx.google.com with ESMTPS",
    }
    spoof_flags = detect_routing_anomalies([{"from_host": "evil-attacker.com", "by_host": "mx.google.com", "ips": []}, {"from_host": "relay", "by_host": "mx", "ips": []}], spoofed)
    assert "message-id-mismatch" in spoof_flags


def test_list_emails_batch_includes_scores():
    """GET /api/v1/emails should return fraud_score and threat_classification directly."""
    with TestClient(app) as c:
        headers = _auth(c)
        # Ingest a sample email
        raw = "From: hr@legit.test\nTo: user@corp.test\nSubject: Standup tomorrow\n\nSee you at 10am."
        ingest_res = c.post("/api/v1/emails/ingest", headers=headers, json={"raw": raw}).json()
        eid = ingest_res["email_id"]

        r = c.get("/api/v1/emails?limit=10", headers=headers)
        assert r.status_code == 200
        emails = r.json()
        assert len(emails) >= 1
        found = next((e for e in emails if e["id"] == eid), None)
        assert found is not None
        assert found["fraud_score"] is not None
        assert found["threat_classification"] is not None


def test_case_status_validation():
    """PATCH /api/v1/cases/{id} should reject invalid statuses."""
    with TestClient(app) as c:
        headers = _auth(c)
        case_res = c.post("/api/v1/cases", headers=headers, json={"title": "Test Investigation"}).json()
        cid = case_res["id"]

        # Valid status
        r1 = c.patch(f"/api/v1/cases/{cid}", headers=headers, json={"status": "InProgress"})
        assert r1.status_code == 200
        assert r1.json()["status"] == "InProgress"

        # Invalid status (validated enum -> 422)
        r2 = c.patch(f"/api/v1/cases/{cid}", headers=headers, json={"status": "Exploded"})
        assert r2.status_code == 422
