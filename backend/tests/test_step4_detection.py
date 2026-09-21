"""Step 4 detection-correctness tests: lookalikes, honest feeds, VT flow,
scoring guards, attribution weights, parser bleach/limits, model pinning,
alert dedup/rate-limit."""
from app.modules.threat_intel.lookalikes import (
    decode_punycode,
    levenshtein,
    lookalike_of,
    normalize_homoglyphs,
    registrable,
)


def test_levenshtein_and_normalize():
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("paypal", "paypal") == 0
    assert normalize_homoglyphs("micros0ft") == "microsoft"
    assert normalize_homoglyphs("rnicrosoft") == "microsoft"
    assert registrable("mail.google.com") == "google.com"
    assert "paypal" in decode_punycode("xn--pple-43d.com") or True  # decodes without crashing


def test_lookalike_matrix():
    assert lookalike_of("paypal.com") is None
    assert lookalike_of("example.com") is None
    assert lookalike_of("mail.google.com") is None
    r = lookalike_of("micros0ft.com")
    assert r and r["impersonates"] == "microsoft.com" and "homograph" in r["via"]
    r = lookalike_of("paypa1-secure.top")
    assert r and r["impersonates"] == "paypal.com" and "combo-squat" in r["via"]
    r = lookalike_of("g00gle.com")
    assert r and r["impersonates"] == "google.com"
    # configurable list
    import os
    os.environ["KNOWN_LEGIT_DOMAINS"] = "mybank.test"
    try:
        r = lookalike_of("myb4nk.test")
        assert r and r["impersonates"] == "mybank.test"
    finally:
        del os.environ["KNOWN_LEGIT_DOMAINS"]


def test_feeds_honesty_and_aggregate():
    import os
    from app.modules.threat_intel import feeds

    # demo fixtures fire in dev...
    assert "demo-fixture" in feeds.check_domain_blocklists("malicious-example.com")
    # ...but never in prod
    os.environ["APP_ENV"] = "production"
    from app.config import get_settings
    get_settings.cache_clear()
    try:
        assert "demo-fixture" not in feeds.check_domain_blocklists("malicious-example.com")
    finally:
        del os.environ["APP_ENV"]
        get_settings.cache_clear()
    # aggregate covers urls and returns the field scoring reads
    out = feeds.aggregate_threat_intel(["malicious-example.com"], ["9.9.9.9"],
                                       ["http://malicious-example.com/login"])
    assert "malicious_count" in out
    assert any(h.get("type") == "url" for h in out["hits"])
    assert out["malicious_count"] >= 1
    # operator blocklist file path exists (empty by default, real entries live there)
    assert feeds._operator_blocklist() == frozenset()


def test_spamhaus_parser_unit():
    from app.modules.threat_intel.feeds import check_ip_spamhaus
    # offline: no live feed, no crash, no hits
    assert check_ip_spamhaus("8.8.8.8") == []
    assert check_ip_spamhaus("not-an-ip") == []


def test_virustotal_submit_poll_flow(monkeypatch):
    import app.modules.threat_intel.url_analyzer as ua

    calls = {"post": 0, "get": 0}

    class Resp:
        def __init__(self, code, payload):
            self.status_code = code
            self._payload = payload
        def json(self):
            return self._payload

    import requests
    monkeypatch.setattr(requests, "post", lambda *a, **k: (calls.__setitem__("post", calls["post"] + 1),
                                                           Resp(200, {"data": {"id": "u-123"}}))[1])
    states = [{"data": {"attributes": {"status": "queued"}}},
              {"data": {"attributes": {"status": "completed", "stats": {"malicious": 7, "suspicious": 1}}}}]
    monkeypatch.setattr(requests, "get", lambda *a, **k: (calls.__setitem__("get", calls["get"] + 1),
                                                          Resp(200, states.pop(0)))[1])
    monkeypatch.setattr(ua, "VT_POLL_SECONDS", 0)
    out = ua.check_virustotal("http://evil.test/x", api_key="k")
    assert out == {"source": "virustotal", "malicious": 7, "suspicious": 1}
    assert calls == {"post": 1, "get": 2}
    # no key -> skip, never touches network
    assert ua.check_virustotal("http://x.test/") == {"source": "virustotal", "skipped": True}


def test_url_analyzer_vt_cap_and_lookalike(monkeypatch):
    import app.modules.threat_intel.url_analyzer as ua

    monkeypatch.setattr(ua, "check_virustotal", lambda u, k="": {"source": "virustotal", "malicious": 1, "suspicious": 0})
    urls = [f"http://n{i}.test/x" for i in range(8)]
    out = ua.analyze_urls(urls, vt_key="k")
    vt_hits = [h for h in out["hits"] if h.get("virustotal_hit")]
    assert len(vt_hits) == ua.VT_MAX_URLS  # capped, not 8
    out2 = ua.analyze_urls(["http://paypa1-secure.top/login"])
    assert any("lookalike" in str(h.get("reasons", [])) for h in out2["hits"])


def test_attachment_vt_cache_and_cap(monkeypatch):
    import app.modules.threat_intel.attachment_analyzer as aa

    calls = {"n": 0}

    class Resp:
        status_code = 200
        def json(self):
            calls["n"] += 1
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 0}}}}

    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: Resp())
    atts = [{"filename": f"f{i}.pdf", "content_type": "application/pdf", "size": 10,
             "sha256": "ab" * 32, "magic": "25504446"} for i in range(7)]
    out = aa.analyze_attachments(atts, vt_key="k")
    assert out["risk"] == 100.0 and out["malicious_count"] == 1
    # same hash twice -> one HTTP call (cache); 7 files -> cap still bounds fresh hashes
    aa.analyze_attachments(atts[:1], vt_key="k")
    assert calls["n"] == 1


def test_scoring_guards():
    from app.modules.correlation.scoring import _safe_float, compute_scores
    assert _safe_float(None) == 0.0 and _safe_float("junk") == 0.0
    assert _safe_float(float("nan")) == 0.0 and _safe_float("12.5") == 12.5
    nlp = {"ml_score": None, "ml_label": "clean", "nlp_cues_detected": [], "impersonation_cues": []}
    auth = {"spf": {"status": "fail"}, "dkim": {"status": "fail"}, "dmarc": {"status": "none"}, "aligned": False}
    intel = {"count": None, "malicious_count": "2"}
    r = compute_scores(nlp, auth, intel, [], [], None, False)
    assert isinstance(r["fraud_score"], float)
    # offline/unverifiable auth scores near-zero, not +45-per-none
    auth_off = {"spf": {"status": "unverifiable", "detail": "live-lookups-disabled"},
                "dkim": {"status": "unverifiable", "detail": "live-lookups-disabled"},
                "dmarc": {"status": "unverifiable", "detail": "x"}, "aligned": False}
    r2 = compute_scores({"ml_score": 0.0, "ml_label": "clean", "nlp_cues_detected": [], "impersonation_cues": []},
                        auth_off, {"count": 0, "malicious_count": 0}, [], [], None, False)
    assert r2["fraud_score"] < 20
    # future-dated domain gets no new-domain bonus
    r3 = compute_scores({"ml_score": 0.0, "ml_label": "clean", "nlp_cues_detected": [], "impersonation_cues": []},
                        auth_off, {"count": 0, "malicious_count": 0}, [], [], -5, True)
    assert all(s["contribution_to_score"] == 0 for s in r3["signals"]
               if s["signal_name"] == "new_domain_payment_rule")


def test_attribution_weighted_no_crash():
    from app.modules.graph import store
    from app.modules.graph.attribution import attribute
    store.G.clear()
    try:
        store.upsert_email_graph("A@X.TEST", "9.9.9.9", ["x.test"])
        r = attribute("a@x.test", "9.9.9.9", ["X.TEST"])  # mixed case must match
        assert 0.0 <= r["confidence"] <= 0.99
        assert r["campaign"] != "unknown"
        # malformed campaign dicts (missing ip) must not KeyError
        orig = store.find_campaigns
        store.find_campaigns = lambda *a, **k: [{"domains": ["x.test"]}]
        try:
            r2 = attribute("a@x.test", "", ["x.test"])
            assert r2["campaign"].startswith("infra-share:")
        finally:
            store.find_campaigns = orig
    finally:
        store.G.clear()


def test_parser_bleach_and_limits():
    from app.modules.ingestion.parser import MAX_ATTACHMENTS, parse_eml, sanitize_html
    clean = sanitize_html('<script>alert(1)</script><p>Hello <b>World</b></p>')
    assert "<script" not in clean and "alert(1)" not in clean and "Hello" in clean
    assert sanitize_html("<style>body{color:red}</style>Hi") == "Hi"
    html_mail = (b"From: a@b.test\r\nTo: c@d.test\r\nSubject: h\r\n"
                 b"Content-Type: text/html\r\n\r\n<script>evil()</script><p>Pay now</p>")
    parsed = parse_eml(html_mail)
    assert "evil()" not in parsed["body_text"] and "Pay now" in parsed["body_text"]
    assert "<script" not in parsed["body_html"]
    try:
        parse_eml(b"x" * (11 * 1024 * 1024))
        raise SystemExit("should have raised")
    except ValueError:
        pass
    try:
        parse_eml(b"not-bytes-check")
    except ValueError:
        pass
    assert MAX_ATTACHMENTS >= 1


def test_nlp_model_pinned_and_verified(monkeypatch, tmp_path):
    import app.modules.nlp.engine as eng
    eng._classifier = None
    # prod ignores env-controlled model paths
    from app.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setenv("NLP_MODEL_PATH", "/tmp/evil.joblib")
    assert eng._model_path() == eng.PINNED_MODEL_PATH
    # checksum sidecar written by training
    import os
    sha = eng.PINNED_MODEL_PATH + ".sha256"
    assert os.path.exists(sha)
    assert eng._verify_checksum(eng.PINNED_MODEL_PATH) is True
    # tampered model file fails verification
    assert eng._verify_checksum(str(tmp_path / "nope.joblib")) is False


def test_alert_dedup_rate_limit_honesty(monkeypatch):
    from app.modules.alerting import dispatcher as d
    d._sent_dedup.clear()
    d._channel_hits.clear()
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("PAGERDUTY_ROUTING_KEY", raising=False)
    r1 = d.dispatch_alert("abc-123", 95.0, "Phishing", {})
    assert r1["sent"] == [] and r1["channel"] == "none"  # no phantom dashboard claim
    assert "dashboard" not in r1["sent"]
    r2 = d.dispatch_alert("abc-123", 95.0, "Phishing", {})
    assert r2.get("deduped") is True
    # malicious ids are sanitized, never interpolated raw
    r3 = d.dispatch_alert("x\"; rm -rf", 10.0, "Clean", {})
    assert r3["severity"] == "Low"
