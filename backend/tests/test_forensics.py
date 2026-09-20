"""Forensics module unit tests (F11): header parsing edge cases."""
from app.modules.forensics.header_parser import parse_headers
from app.modules.forensics.received_chain import detect_routing_anomalies, reconstruct_path


def test_reconstruct_empty_and_single():
    assert reconstruct_path({}) == []
    one = {"Received": "from a ([1.2.3.4]) by b with SMTP"}
    path = reconstruct_path(one)
    assert len(path) == 1 and path[0]["ips"] == ["1.2.3.4"]


def test_reconstruct_chronological_order():
    h = {"Received": "from c ([9.9.9.9]) by d\nfrom a ([1.1.1.1]) by b"}
    path = reconstruct_path(h)
    assert [p["ips"] for p in path] == [["1.1.1.1"], ["9.9.9.9"]]


def test_routing_anomaly_flags():
    assert "missing-received-chain" in detect_routing_anomalies([], {})
    assert "single-hop-suspicious" in detect_routing_anomalies([{"ips": []}], {})
    forged = {"Return-Path": "<bounce@evil.test>", "From": "CEO <ceo@company.com>",
              "Message-ID": "<x@other.test>"}
    flags = detect_routing_anomalies([{"ips": ["1.1.1.1"]}, {"ips": ["2.2.2.2"]}], forged)
    assert "return-path-mismatch" in flags and "message-id-mismatch" in flags
    clean = {"Return-Path": "<a@c.com>", "From": "A <a@c.com>", "Message-ID": "<y@c.com>"}
    assert detect_routing_anomalies([{"ips": []}, {"ips": []}], clean) == []


def test_header_parser_spoof_signals():
    r = parse_headers({"From": '"ceo@company.com" <attacker@evil.test>'})
    assert "display-name-spoof" in r["flags"]
    r = parse_headers({"From": "A <a@c.com>", "Reply-To": "x@evil.test"})
    assert "reply-to-mismatch" in r["flags"]
    r = parse_headers({"From": "X <x@xn--paypa1.top>"})
    assert "punycode-domain" in r["flags"]
    r = parse_headers({"From": "Alice <alice@c.com>"})
    assert r["from_addr"] == "alice@c.com" and r["flags"] == []


def test_auth_validator_offline_shape():
    from app.modules.forensics.auth_validator import validate_all
    out = validate_all(b"raw", {"From": "a@b.com"}, "127.0.0.1", "")
    assert set(out) == {"spf", "dkim", "dmarc", "aligned"}
    assert out["spf"]["status"] in ("none", "pass", "fail", "temperror", "softfail", "neutral")
