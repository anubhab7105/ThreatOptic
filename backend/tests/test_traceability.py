"""Traceability module unit tests (F11): IP extraction, GeoIP, infra flags, WHOIS/DNS."""
from app.modules.traceability.geoip import geolocate, has_coords, _geolocate_cached, geolocate_country, get_country_centroid
from app.modules.traceability.ip_extractor import extract_origin_ip, extract_all_ips
from app.modules.traceability.vpn_tor import flag_infrastructure, is_tor_exit
from app.modules.traceability.whois_dns import dns_lookup, domain_age_days, whois_lookup


def test_origin_ip_last_external_in_wire_order():
    # chronological [private, public]: wire order puts public first -> it wins
    path = [{"ips": ["10.0.0.1"]}, {"ips": ["45.1.1.1"]}]
    assert extract_origin_ip(path) == "45.1.1.1"
    assert extract_origin_ip([{"ips": ["10.0.0.5"]}]) == "10.0.0.5"
    assert extract_origin_ip([]) == ""
    assert extract_origin_ip([{"ips": []}]) == ""


def test_origin_ip_trust_boundary():
    # our MX on top: origin is the nearest public IP below it, not spoofed lines above
    wire = [
        {"by_host": "mx.ours.test", "ips": ["8.8.8.8"]},
        {"by_host": "evil.test", "ips": ["1.1.1.1"]},
        {"by_host": "mx.ours.test", "ips": ["9.9.9.9"]},
    ]
    path = list(reversed(wire))  # chronological
    import os
    os.environ["TRUSTED_RELAY_HOSTS"] = "mx.ours.test"
    try:
        assert extract_origin_ip(path) == "1.1.1.1"
    finally:
        del os.environ["TRUSTED_RELAY_HOSTS"]


def test_origin_ip_from_forensic_headers():
    # When Received chain is private or empty, extract from explicit headers
    headers_x_orig = {"X-Originating-IP": "[198.51.100.22]"}
    assert extract_origin_ip([], raw_headers=headers_x_orig) == "198.51.100.22"

    headers_spf = {"Received-SPF": "pass (google.com: domain of test designates 198.51.100.33 as permitted sender) client-ip=198.51.100.33;"}
    assert extract_origin_ip([], raw_headers=headers_spf) == "198.51.100.33"

    headers_auth = {"Authentication-Results": "mx.google.com; spf=pass sender IP is 198.51.100.44"}
    assert extract_origin_ip([], raw_headers=headers_auth) == "198.51.100.44"


def test_geolocate_offline_shapes(monkeypatch):
    monkeypatch.setattr("app.modules.traceability.geoip._live", lambda: False)
    _geolocate_cached.cache_clear()
    assert geolocate("")["source"] == "none"
    static = geolocate("45.148.10.88")
    assert static["source"] == "static-fallback" and static["country"] == "DE"
    # unknown IP yields honest unresolved (no 0,0/UNKNOWN), fast
    stub = geolocate("203.0.113.199")
    assert stub["source"] == "unresolved" and stub["lat"] is None and stub["country"] == ""
    assert not has_coords(stub) and has_coords(static)
    # cache returns copies: mutating one result must not poison the next
    a = geolocate("45.148.10.88")
    a["country"] = "XX"
    assert geolocate("45.148.10.88")["country"] == "DE"
    # invalid IP never interpolated anywhere
    assert geolocate("999.999.999.999")["source"] == "invalid-ip"


def test_geolocate_private_ip_and_centroids():
    # Private / Localhost IP handling
    priv = geolocate("192.168.1.100")
    assert priv["source"] == "private-ip" and priv.get("is_private") is True and priv["lat"] is None
    loop = geolocate("127.0.0.1")
    assert loop["source"] == "loopback" and loop.get("is_private") is True

    # Country centroids
    us_centroid = get_country_centroid("US")
    assert us_centroid is not None and len(us_centroid) == 2
    geo_us = geolocate_country("US")
    assert has_coords(geo_us) and geo_us["country"] == "US"


def test_infrastructure_flags():
    assert is_tor_exit("1.2.3.4") is False  # live DNS check disabled offline
    out = flag_infrastructure("1.2.3.4", isp="Amazon Technologies", asn="AS16509 Amazon")
    assert out["is_vpn_tor"] is False and "cloud-hosted" in out["infra_flags"]
    out = flag_infrastructure("", "", "")
    assert out == {"is_vpn_tor": False, "infra_flags": []}


def test_whois_dns_offline_and_parsing():
    w = whois_lookup("example.com")
    assert w.get("domain") == "example.com"  # live detail or disabled note, never crash
    assert whois_lookup("notadomain") == {}
    d = dns_lookup("example.com")
    assert d["domain"] == "example.com" and isinstance(d["mx"], list)
    assert domain_age_days({"creation_date": "2020-01-01"}) and domain_age_days({"creation_date": "2020-01-01"}) > 1000
    assert domain_age_days({}) is None and domain_age_days({"creation_date": "garbage"}) is None


# ---------------------------------------------------------------------------
# ReDoS: the IP candidate patterns were quadratic in the length of a run.
# ---------------------------------------------------------------------------

def test_ip_regex_is_linear_on_hostile_hex_run():
    """A colon-free hex run must not be re-scanned once per character.

    The old `[0-9a-fA-F:]{2,}(?::[0-9a-fA-F:]*)+` nested quantifier made
    findall restart the whole run at every offset (~28s at 64KB). The
    lookbehind pins matches to run boundaries. Budget is deliberately loose
    so this catches a return to quadratic behaviour, not microseconds.
    """
    import time
    from app.modules.forensics.received_chain import IP_CANDIDATE_RE

    small, large = "a" * 20_000, "a" * 400_000
    t0 = time.perf_counter()
    IP_CANDIDATE_RE.findall(small)
    t_small = time.perf_counter() - t0

    t0 = time.perf_counter()
    IP_CANDIDATE_RE.findall(large)
    t_large = time.perf_counter() - t0

    # 20x the input must not cost anywhere near 400x the time.
    assert t_large < max(t_small * 20, 0.5), (
        f"IP pattern looks super-linear: {t_small:.4f}s -> {t_large:.4f}s")


def test_extract_all_ips_survives_hostile_received_header():
    """End-to-end: a hostile header must be fast AND still yield real IPs."""
    import time
    from app.modules.forensics.received_chain import parse_received_hop

    header = "from evil.test (evil.test [a" * 20_000 + ") by mx.test"
    t0 = time.perf_counter()
    hop = parse_received_hop(header)
    elapsed = time.perf_counter() - t0
    assert elapsed < 2.0, f"hostile Received header took {elapsed:.2f}s"
    assert hop["from_host"].startswith("evil.test")


def test_ip_candidate_pattern_still_extracts_valid_addresses():
    """The linear pattern must not lose coverage."""
    from app.modules.traceability.ip_extractor import _extract_header_ips
    from app.modules.forensics.received_chain import parse_received_hop

    ips = _extract_header_ips({"X-Originating-IP": "45.148.10.88"})
    assert "45.148.10.88" in ips

    hop = parse_received_hop("from a.com (a.com [1.2.3.4]) by mx.test")
    assert "1.2.3.4" in hop["ips"]

    hop6 = parse_received_hop("from a.com (a.com [2001:db8::dead:beef]) by mx.test")
    assert "2001:db8::dead:beef" in hop6["ips"]

    # `::1` was previously missed entirely: the old pattern required two
    # characters before the colon group.
    assert "::1" in parse_received_hop("from a (a [::1]) by b")["ips"]


def test_ip_pattern_rejects_junk_and_trailing_hex():
    """Guards the boundary lookbehind: junk is rejected, real IPs survive."""
    from app.modules.forensics.received_chain import parse_received_hop

    assert parse_received_hop("from a (a [999.999.999.999]) by b")["ips"] == []
    assert parse_received_hop("from a (a [not-an-ip]) by b")["ips"] == []
    # A hex suffix after a valid quad must not swallow the quad.
    assert "1.2.3.4" in parse_received_hop("from a (a [1.2.3.4abc]) by b")["ips"]
