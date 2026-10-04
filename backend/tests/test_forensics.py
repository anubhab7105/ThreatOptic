"""Forensics module unit tests (F11): header parsing edge cases."""
from app.modules.forensics.header_parser import parse_headers
from app.modules.forensics.received_chain import detect_routing_anomalies, reconstruct_path
from app.modules.ingestion.parser import parse_eml


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


def test_auth_validator_offline_shape(monkeypatch):
    monkeypatch.setattr("app.modules.forensics.auth_validator._live", lambda: False)
    from app.modules.forensics.auth_validator import validate_all
    out = validate_all(b"raw", {"From": "a@b.com"}, "127.0.0.1", "")
    assert {"spf", "dkim", "dmarc", "aligned"} <= set(out)
    # No envelope sender (Return-Path) => SPF has no identity: "none",
    # never the display From domain and never "unverifiable".
    assert out["spf"]["status"] == "none"
    assert out["spf_domain"] == ""
    # no loopback substitution: missing IP is explicit, not vouched.
    # (No envelope either, so SPF reports "none" — no identity to check.)
    out2 = validate_all(b"raw", {"From": "a@b.com"}, "", "")
    assert out2["spf"]["status"] == "none" and "no-return-path" in out2["spf"]["detail"]
    out2b = validate_all(b"raw", {"From": "a@b.com", "Return-Path": "<b@env.test>"}, "", "")
    assert out2b["spf"]["status"] == "unverifiable" and "no sender IP" in out2b["spf"]["detail"]
    # envelope (Return-Path), not display From, drives SPF domain
    out3 = validate_all(b"raw", {"From": "a@b.com", "Return-Path": "<bounce@env.test>"}, "127.0.0.1", "")
    assert out3["spf_domain"] == "env.test"


def test_auth_domain_cleaning_and_alignment():
    from app.modules.forensics.auth_validator import _clean_domain, validate_all
    assert _clean_domain("<a@Y.COM>") == "y.com"  # no trailing '>' (lstrip bug)
    out = validate_all(b"raw", {"From": "a@b.com", "DKIM-Signature": "v=1; d=evil.test; s=x"}, "", "")
    assert out["dkim_domain"] == "evil.test" and out["aligned"] is False


def test_upstream_untrusted_by_default(monkeypatch):
    """P0: attacker-stamped Authentication-Results are ignored offline —
    claims attached for provenance but never honored as verdicts."""
    monkeypatch.setattr("app.modules.forensics.auth_validator._live", lambda: False)
    monkeypatch.delenv("TRUSTED_RELAY_HOSTS", raising=False)
    from app.modules.forensics.auth_validator import validate_all
    headers = {
        "From": "CEO <ceo@company.com>",
        "Return-Path": "<bounce@evil.test>",
        "Authentication-Results": "evil-relay.test; spf=pass; dkim=pass; dmarc=pass",
    }
    out = validate_all(b"raw", headers, "45.148.10.88", "")
    assert out["upstream_trusted"] is False
    assert out["spf"]["status"] == "unverifiable" and "live-lookups-disabled" in out["spf"]["detail"]
    assert out["dkim"]["status"] == "none"  # no signature header present
    assert out["dmarc"]["status"] == "unverifiable"
    # ... but the claims are preserved for the analyst, not dropped.
    assert out["spf"]["upstream"]["status"] == "pass"


def test_upstream_trusted_via_relay_boundary(monkeypatch):
    """P0: upstream claims ARE honored when the stamper is our relay."""
    monkeypatch.setattr("app.modules.forensics.auth_validator._live", lambda: False)
    monkeypatch.setenv("TRUSTED_RELAY_HOSTS", "mx.ours.test")
    from app.modules.forensics.auth_validator import validate_all
    headers = {
        "From": "a@b.com",
        "Return-Path": "<bounce@b.com>",
        "Authentication-Results": "mx.ours.test; spf=pass; dkim=pass; dmarc=pass",
    }
    out = validate_all(b"raw", headers, "93.184.216.34", "")
    assert out["upstream_trusted"] is True
    assert out["spf"]["status"] == "pass" and "trusted-upstream" in out["spf"]["detail"]
    assert out["dmarc"]["status"] == "pass" and "trusted-upstream" in out["dmarc"]["detail"]


def test_trusted_upstream_never_overrides_live_fail(monkeypatch):
    """P0: a live hard failure stands even against a trusted upstream pass."""
    import sys
    import types
    import app.modules.forensics.auth_validator as av
    monkeypatch.setattr(av, "_live", lambda: True)
    monkeypatch.setenv("TRUSTED_RELAY_HOSTS", "mx.ours.test")
    fake_spf = types.ModuleType("spf")
    fake_spf.check2 = lambda **kw: ("fail", "simulated hard fail")
    monkeypatch.setitem(sys.modules, "spf", fake_spf)
    out = av.validate_all(
        b"raw",
        {"From": "a@b.com", "Return-Path": "<bounce@b.com>",
         "Authentication-Results": "mx.ours.test; spf=pass"},
        "93.184.216.34", "")
    assert out["spf"]["status"] == "fail"
    assert out["spf"]["upstream"]["status"] == "pass"  # provenance kept


def test_no_global_resolver_mutation():
    """P0: the module must not mutate the global DNS resolver."""
    import app.modules.forensics.auth_validator as av
    assert not hasattr(av, "_ensure_dns_resolver")


# ---------------------------------------------------------------------------
# C2: Authentication-Results must never upgrade a locally-attempted verdict.
# ---------------------------------------------------------------------------

def _fake_spf(monkeypatch, result):
    """Install a stub `spf` module whose check2 returns `result`."""
    import sys
    import types
    fake = types.ModuleType("spf")
    fake.check2 = lambda **kw: (result, "simulated")
    monkeypatch.setitem(sys.modules, "spf", fake)


def test_temperror_is_not_upgraded_to_upstream_pass(monkeypatch):
    """C2/P0: a transient DNS failure must stay `temperror`.

    The pre-fix code substituted the trusted upstream status here, so a
    `temperror` (lookup never completed) was reported as `pass` -- the exact
    fail-open the audit flagged.
    """
    import app.modules.forensics.auth_validator as av
    monkeypatch.setattr(av, "_live", lambda: True)
    monkeypatch.setenv("TRUSTED_RELAY_HOSTS", "mx.ours.test")
    _fake_spf(monkeypatch, "temperror")

    out = av.validate_all(
        b"raw",
        {"From": "a@b.com", "Return-Path": "<bounce@b.com>",
         "Authentication-Results": "mx.ours.test; spf=pass"},
        "93.184.216.34", "")

    assert out["upstream_trusted"] is True, "precondition: upstream IS trusted here"
    assert out["spf"]["status"] == "temperror", "temperror must not become pass"
    # The claim is still visible to the analyst, just not authoritative.
    assert out["spf"]["upstream"]["status"] == "pass"


def test_spf_none_is_not_upgraded_to_upstream_pass(monkeypatch):
    """C2/P0: `none` (no SPF record published) is a definitive local result."""
    import app.modules.forensics.auth_validator as av
    monkeypatch.setattr(av, "_live", lambda: True)
    monkeypatch.setenv("TRUSTED_RELAY_HOSTS", "mx.ours.test")
    _fake_spf(monkeypatch, "none")

    out = av.validate_all(
        b"raw",
        {"From": "a@b.com", "Return-Path": "<bounce@b.com>",
         "Authentication-Results": "mx.ours.test; spf=pass"},
        "93.184.216.34", "")

    assert out["spf"]["status"] == "none"
    assert out["spf"]["upstream"]["status"] == "pass"


def test_spf_permerror_is_not_upgraded_to_upstream_pass(monkeypatch):
    """C2/P0: a permanent error must never be reported as a pass either."""
    import app.modules.forensics.auth_validator as av
    monkeypatch.setattr(av, "_live", lambda: True)
    monkeypatch.setenv("TRUSTED_RELAY_HOSTS", "mx.ours.test")
    _fake_spf(monkeypatch, "permerror")

    out = av.validate_all(
        b"raw",
        {"From": "a@b.com", "Return-Path": "<bounce@b.com>",
         "Authentication-Results": "mx.ours.test; spf=pass"},
        "93.184.216.34", "")

    assert out["spf"]["status"] == "permerror"


def test_spf_library_crash_stays_temperror_not_upstream_pass(monkeypatch):
    """C2/P0: a crashing validator must not be reported as a pass.

    It stays `temperror` rather than `unverifiable` on purpose: scoring
    weights unverifiable (5.0) far below temperror (15.0), so collapsing the
    two would quietly lower the risk score for a broken deployment.
    """
    import sys
    import types
    import app.modules.forensics.auth_validator as av
    monkeypatch.setattr(av, "_live", lambda: True)
    monkeypatch.setenv("TRUSTED_RELAY_HOSTS", "mx.ours.test")

    exploding = types.ModuleType("spf")

    def _boom(**kw):
        raise RuntimeError("resolver exploded")

    exploding.check2 = _boom
    monkeypatch.setitem(sys.modules, "spf", exploding)

    out = av.validate_all(
        b"raw",
        {"From": "a@b.com", "Return-Path": "<bounce@b.com>",
         "Authentication-Results": "mx.ours.test; spf=pass"},
        "93.184.216.34", "")

    assert out["upstream_trusted"] is True, "precondition: upstream IS trusted"
    assert out["spf"]["status"] == "temperror", "a crash must not become pass"
    assert "spf-unavailable" in out["spf"]["detail"]


def test_dkim_missing_signature_is_not_upgraded_to_upstream_pass(monkeypatch):
    """C2/P0: no DKIM-Signature is `none`; an upstream pass would mean the
    signature was stripped in transit, which is evidence, not a fallback."""
    import app.modules.forensics.auth_validator as av
    monkeypatch.setattr(av, "_live", lambda: False)
    monkeypatch.setenv("TRUSTED_RELAY_HOSTS", "mx.ours.test")

    out = av.validate_all(
        b"raw",
        {"From": "a@b.com", "Return-Path": "<bounce@b.com>",
         "Authentication-Results": "mx.ours.test; dkim=pass; spf=pass"},
        "93.184.216.34", "")

    assert out["upstream_trusted"] is True
    assert out["dkim"]["status"] == "none"
    assert out["dkim"]["upstream"]["status"] == "pass"
    # spf here is `unverifiable` (live lookups off), so it MAY be substituted.
    assert out["spf"]["status"] == "pass"


def test_dmarc_absent_record_is_not_upgraded_to_upstream_pass(monkeypatch):
    """C2/P0: RFC 7489 6.6.3 -- no _dmarc record is `none`, not a gap."""
    import app.modules.forensics.auth_validator as av
    monkeypatch.setattr(av, "_live", lambda: True)
    monkeypatch.setenv("TRUSTED_RELAY_HOSTS", "mx.ours.test")
    monkeypatch.setattr(av, "_txt_records", lambda name: [])

    out = av.validate_all(
        b"raw",
        {"From": "a@b.com", "Return-Path": "<bounce@b.com>",
         "Authentication-Results": "mx.ours.test; dmarc=pass; spf=pass"},
        "93.184.216.34", "")

    assert out["dmarc"]["status"] == "none"
    assert out["dmarc"]["upstream"]["status"] == "pass"


def test_authserv_id_and_claims_come_from_the_same_header():
    """C2/P0: attribution and claims must not be read from different headers.

    Pre-fix, `_authserv_id()` returned the first AR header found while
    `parse_auth_headers()` regex-scanned a join of all of them, so a planted
    `x-authentication-results` could supply the trusted authserv-id while the
    status claims came from an attacker-authored header.
    """
    from app.modules.forensics.auth_validator import _authserv_id, parse_auth_headers

    headers = {
        # Attacker-controlled, first in header order:
        "x-authentication-results": "mx.ours.test; spf=pass",
        # Ours, appended last by our own MTA:
        "authentication-results": "evil-relay.test; spf=fail",
    }
    assert _authserv_id(headers) == "evil-relay.test"
    assert parse_auth_headers(headers)["spf"]["status"] == "fail"


def test_attacker_cannot_forge_trusted_authserv_id_by_prepending(monkeypatch):
    """C2/P0: prepending a trusted-looking AR header must not win.

    Our own MTA stamps last, so the bottom-most header is authoritative. An
    attacker prepending `Authentication-Results: mx.ours.test; spf=pass`
    therefore gets ignored rather than believed.
    """
    import app.modules.forensics.auth_validator as av
    monkeypatch.setenv("TRUSTED_RELAY_HOSTS", "mx.ours.test")

    from app.modules.forensics.auth_validator import _upstream_trusted
    headers = {
        "Authentication-Results": "mx.ours.test; spf=pass",   # attacker, prepended
        "ARC-Authentication-Results": "evil-relay.test; spf=fail",  # actually the boundary
    }
    trusted, sid = _upstream_trusted(headers)
    assert sid == "evil-relay.test", "claims follow the bottom-most header"
    assert trusted is False, (
        "a prepended header must not make the attacker the speaker for our "
        "boundary, even with the boundary configured")


def test_trusted_upstream_still_substitutes_for_unverifiable(monkeypatch):
    """C2 regression guard: the narrow legitimate substitution still works.

    Without this the module would silently ignore every relay-forwarded
    verdict, which is the feature the trusted-relay config exists for.
    """
    import app.modules.forensics.auth_validator as av
    monkeypatch.setattr(av, "_live", lambda: False)
    monkeypatch.setenv("TRUSTED_RELAY_HOSTS", "mx.ours.test")

    out = av.validate_all(
        b"raw",
        {"From": "a@b.com", "Return-Path": "<bounce@b.com>",
         "Authentication-Results": "mx.ours.test; spf=softfail"},
        "", "")  # no sender IP -> unverifiable

    assert out["upstream_trusted"] is True
    assert out["spf"]["status"] == "softfail"
    assert "trusted-upstream" in out["spf"]["detail"]


# ---------------------------------------------------------------------------
# Header names are case-insensitive (RFC 5322 2.2). msg.raw_items() preserves
# the sender's casing, so `fROM:` / `rECEIVED:` used to blank the parsed value
# and silently disable every detection derived from that header.
# ---------------------------------------------------------------------------

_CASING_VARIANTS = ["From", "fROM", "FrOm", "FROM", "from"]


def _raw(from_name="From", recv_name="Received"):
    return (
        f"{from_name}: attacker@evil.test\n"
        "Reply-To: ceo@bank.co.uk\n"
        "Return-Path: <bounce@evil-relay.test>\n"
        f"{recv_name}: from a.evil.test (a.evil.test [203.0.113.7]) by mx.good.test;\n"
        "Subject: wire transfer\n\nbody"
    ).encode()


def test_from_header_casing_does_not_blind_header_forensics():
    for name in _CASING_VARIANTS:
        out = parse_headers(parse_eml(_raw(from_name=name))["raw_headers"])
        assert out["from_addr"] == "attacker@evil.test", (name, out)
        # every From-derived check must still fire
        assert "reply-to-mismatch" in out["flags"], (name, out["flags"])
        # and the From/Return-Path comparison in the routing checks
        assert "return-path-mismatch" in detect_routing_anomalies(
            [{"ips": ["1.1.1.1"]}],
            parse_eml(_raw(from_name=name))["raw_headers"]), name


def test_received_header_casing_does_not_hide_the_hop_chain():
    for name in ["Received", "rECEIVED", "received", "RECEIVED"]:
        p = parse_eml(_raw(recv_name=name))
        hops = reconstruct_path(p["raw_headers"])
        assert len(hops) == 1, (name, hops)
        assert hops[0]["ips"] == ["203.0.113.7"], (name, hops)


def test_duplicate_from_with_differing_case_is_still_multiple_from():
    """Exact-case key comparison split `From:` and `fROM:` into two entries,
    so the spoofing signal the duplicate itself represents was lost."""
    raw = b"From: victim@bank.co.uk\nfROM: attacker@evil.test\nSubject: t\n\nb"
    out = parse_headers(parse_eml(raw)["raw_headers"])
    assert "multiple-from" in out["flags"], out


def test_header_value_is_case_insensitive_for_stored_rows():
    """Rows persisted before parse_eml normalised the keys must still resolve."""
    from app.modules.forensics.header_parser import header_value

    stored = {"fROM": "attacker@evil.test", "rECEIVED": "from a ([1.2.3.4])"}
    assert header_value(stored, "From") == "attacker@evil.test"
    assert header_value(stored, "Received") == "from a ([1.2.3.4])"
    assert header_value(stored, "Missing") == ""
    assert header_value(None, "From") == ""
    assert header_value({"From": ["a@x.test", "b@x.test"]}, "From") == "a@x.test\nb@x.test"


def test_ip_extraction_ignores_header_name_casing():
    from app.modules.traceability.ip_extractor import _extract_header_ips

    for name in ["X-Originating-IP", "x-originating-ip", "X-ORIGINATING-IP"]:
        assert _extract_header_ips({name: "203.0.113.9"}) == ["203.0.113.9"], name
    for name in ["Authentication-Results", "authentication-results"]:
        got = _extract_header_ips({name: "mx.g.test; client-ip=203.0.113.10"})
        assert got == ["203.0.113.10"], (name, got)
