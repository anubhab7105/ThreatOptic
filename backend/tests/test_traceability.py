"""Traceability module unit tests (F11): IP extraction, GeoIP, infra flags, WHOIS/DNS."""
from app.modules.traceability.geoip import geolocate
from app.modules.traceability.ip_extractor import extract_origin_ip
from app.modules.traceability.vpn_tor import flag_infrastructure, is_tor_exit
from app.modules.traceability.whois_dns import dns_lookup, domain_age_days, whois_lookup


def test_origin_ip_public_first_then_private_fallback():
    path = [{"ips": ["10.0.0.1"]}, {"ips": ["45.1.1.1"]}]
    assert extract_origin_ip(path) == "45.1.1.1"
    assert extract_origin_ip([{"ips": ["10.0.0.5"]}]) == "10.0.0.5"
    assert extract_origin_ip([]) == ""
    assert extract_origin_ip([{"ips": []}]) == ""


def test_geolocate_offline_shapes(monkeypatch):
    monkeypatch.setattr("app.modules.traceability.geoip._live", lambda: False)
    geolocate.cache_clear()
    assert geolocate("")["source"] == "none"
    static = geolocate("45.148.10.88")
    assert static["source"] == "static-fallback" and static["country"] == "DE"
    # live lookups off by default -> unknown IP yields the offline stub, fast
    stub = geolocate("203.0.113.199")
    assert stub["source"] == "offline-stub" and stub["lat"] == 0.0


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
