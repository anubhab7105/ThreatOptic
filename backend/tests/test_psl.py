
from app.modules.forensics.psl import (
    is_subdomain_of,
    public_suffix,
    registrable_domain,
    same_organization,
)


def test_registrable_domain_basics():
    assert registrable_domain("mail.google.com") == "google.com"
    assert registrable_domain("paypal.com") == "paypal.com"
    assert registrable_domain("WWW.Example.COM.") == "example.com"
    assert registrable_domain("localhost") == "localhost"
    assert registrable_domain("") == ""
    assert registrable_domain("192.168.1.1") == "192.168.1.1"


def test_registrable_domain_multi_label_suffix():

    assert registrable_domain("a.b.mail.co.uk") == "mail.co.uk"
    assert registrable_domain("evil.co.uk") == "evil.co.uk"
    assert registrable_domain("bank.co.uk") == "bank.co.uk"
    assert public_suffix("a.b.mail.co.uk") == "co.uk"


def test_same_organization():
    assert same_organization("mail.company.com", "company.com") is True
    assert same_organization("company.com", "company.com") is True
    assert same_organization("evil.co.uk", "bank.co.uk") is False
    assert same_organization("a.co.uk", "b.co.uk") is False

    assert same_organization("", "x.com") is False
    assert same_organization("x.com", "") is False
    assert same_organization("", "") is False


def test_is_subdomain_of():
    assert is_subdomain_of("a.b.c", "b.c") is True
    assert is_subdomain_of("b.c", "b.c") is True
    assert is_subdomain_of("x.com", "y.com") is False
    assert is_subdomain_of("", "y.com") is False


def test_reply_to_subdomain_not_flagged():

    from app.modules.forensics.header_parser import parse_headers
    r = parse_headers({"From": "A <a@company.com>", "Reply-To": "help@mail.company.com"})
    assert "reply-to-mismatch" not in r["flags"]
    r = parse_headers({"From": "A <a@bank.co.uk>", "Reply-To": "x@evil.co.uk"})
    assert "reply-to-mismatch" in r["flags"]


def test_return_path_subdomain_not_flagged():

    from app.modules.forensics.received_chain import detect_routing_anomalies
    path = [{"ips": ["1.1.1.1"]}, {"ips": ["2.2.2.2"]}]
    ok = {"Return-Path": "<bounce@mail.company.com>", "From": "A <a@company.com>",
          "Message-ID": "<x@mail.company.com>"}
    assert detect_routing_anomalies(path, ok) == []
    bad = {"Return-Path": "<bounce@evil.co.uk>", "From": "A <a@bank.co.uk>",
           "Message-ID": "<x@evil.co.uk>"}
    flags = detect_routing_anomalies(path, bad)
    assert "return-path-mismatch" in flags and "message-id-mismatch" in flags
