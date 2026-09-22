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
    # brand display name from an unowned domain
    r = parse_headers({"From": '"PayPal Security" <notice@evil.test>'})
    assert "display-name-spoof" in r["flags"]
    r = parse_headers({"From": '"PayPal Security" <notice@paypal.com>'})
    assert "display-name-spoof" not in r["flags"]
    # multiple From identities
    r = parse_headers({"From": "a@x.test\nb@y.test"})
    assert "multiple-from" in r["flags"]
    # homoglyph sender domain flagged via shared lookalike module
    r = parse_headers({"From": "X <x@micros0ft.com>"})
    assert any(f.startswith("lookalike-domain") for f in r["flags"])


def test_received_ip_validation_and_folding():
    from app.modules.forensics.received_chain import parse_received_hop, split_received
    # invalid octets rejected, IPv6 accepted
    hop = parse_received_hop("from a ([999.999.999.999]) by b ([2001:db8::1])")
    assert hop["ips"] == ["2001:db8::1"]
    # folded continuation lines must NOT become fake hops
    folded = {"Received": "from a ([1.1.1.1])\n\tby b with SMTP\nfrom c ([2.2.2.2]) by d"}
    parts = split_received(folded)
    assert len(parts) == 2
    assert [p["ips"] for p in reconstruct_path(folded)] == [["2.2.2.2"], ["1.1.1.1"]]


def test_auth_validator_offline_shape():
    from app.modules.forensics.auth_validator import validate_all
    out = validate_all(b"raw", {"From": "a@b.com"}, "127.0.0.1", "")
    assert {"spf", "dkim", "dmarc", "aligned"} <= set(out)
    # offline statuses are distinguishable from real failures
    assert out["spf"]["status"] == "unverifiable"
    # no loopback substitution: missing IP is explicit, not vouched
    out2 = validate_all(b"raw", {"From": "a@b.com"}, "", "")
    assert out2["spf"]["status"] == "unverifiable" and "no sender IP" in out2["spf"]["detail"]
    # envelope (Return-Path), not display From, drives SPF domain
    assert out["spf_domain"] in ("", "b.com")


def test_auth_domain_cleaning_and_alignment():
    from app.modules.forensics.auth_validator import _clean_domain, validate_all
    assert _clean_domain("<a@Y.COM>") == "y.com"  # no trailing '>' (lstrip bug)
    out = validate_all(b"raw", {"From": "a@b.com", "DKIM-Signature": "v=1; d=evil.test; s=x"}, "", "")
    assert out["dkim_domain"] == "evil.test" and out["aligned"] is False
