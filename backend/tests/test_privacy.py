"""Privacy module unit tests (F11): masking, retention, custody tamper-evidence."""
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app import models  # noqa
from app.modules.privacy.chain_of_custody import custody_manifest
from app.modules.privacy.masking import mask_text
from app.modules.privacy.retention import apply_retention


def test_masking_kinds():
    assert "[SSN-REDACTED]" in mask_text("ssn 123-45-6789 here")
    assert "[PHONE-REDACTED]" in mask_text("call +1 (555) 123-4567 now")
    assert "[PHONE-REDACTED]" in mask_text("ring +44 20 7946 0958 today")
    # Luhn-invalid digit runs are NOT cards; bare 10-digit IDs are NOT phones
    assert "1234567890123" in mask_text("ref 1234567890123 closed")
    assert "1234567890" in mask_text("ticket 1234567890 closed")
    assert mask_text("") == ""


# ---------------------------------------------------------------------------
# E164_RE: the separator class contained \s, so a match ran across lines.
# ---------------------------------------------------------------------------

def test_e164_does_not_swallow_the_next_line():
    """`[\d.\s\-()]*` matched \\n, so 'call +1\\n2025550123' lost its newline
    and the masked body no longer reflected the message's line structure."""
    out = mask_text("call +1\n2025550123 now")
    assert "\n" in out, out
    assert "2025550123" in out, out


def test_e164_over_long_run_no_longer_leaks_interior_numbers():
    """A run over 15 digits was returned verbatim, so BOTH phone numbers in
    '+12025550123 15551234567' survived masking."""
    out = mask_text("+12025550123 15551234567")
    assert "12025550123" not in out, out
    assert "15551234567" not in out, out


def test_e164_short_plus_token_is_not_a_phone():
    """The 7-digit floor stays: '+1' must not be redacted everywhere."""
    assert mask_text("sum +1 = 2 ok") == "sum +1 = 2 ok"
    assert mask_text("call +1 now") == "call +1 now"


def test_e164_boundary_digits_still_masked():
    for txt in ("+1202555", "+12025550"):
        assert "[PHONE-REDACTED]" in mask_text(txt), txt


def test_card_pattern_stays_bounded_on_adversarial_input():
    """Guard, not a claim of a live ReDoS: measured <0.05ms across five
    shapes up to 400 repetitions. `(?:\d[ \\-.]*){13,19}` is the classic
    nested-quantifier shape, so pin it against a future regression."""
    import time

    from app.modules.privacy.masking import CARD_CANDIDATE_RE

    shapes = (
        " ".join(["1" * 13] * 400) + " ",
        ("1 1 1 1 1 1 1 1 1 1 1 1 1 " * 400) + " ",
        "1234567890123" + " " * 400 + "!",
        "1." * 400 + "1",
        ("1234567890123 -" * 400),
    )
    for shape in shapes:
        t0 = time.perf_counter()
        CARD_CANDIDATE_RE.search(shape)
        assert time.perf_counter() - t0 < 1.0, "card pattern became superlinear"


def _db():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    return sessionmaker(bind=eng)()


def test_retention_deletes_expired_clean_row_entirely():
    """Rules.md: clean metadata is retained for `clean_days` only.

    Previously only the body was blanked and the row kept forever, so
    subject/sender/recipients/headers stayed in the DB indefinitely.
    """
    db = _db()
    old = models.EmailRecord(subject="old", body_text="sensitive body",
                             timestamp=datetime.utcnow() - timedelta(days=30))
    new = models.EmailRecord(subject="new", body_text="keep me")
    db.add_all([old, new])
    db.flush()
    db.add(models.AnalysisResult(email_id=old.id, fraud_score=10.0))
    db.add(models.AnalysisResult(email_id=new.id, fraud_score=95.0))
    db.commit()
    old_id = old.id
    out = apply_retention(db, clean_days=7, malicious_days=90)
    assert out["deleted"] == 1
    assert out["purged_body"] == 1
    # The whole row is gone, not just its body.
    assert db.get(models.EmailRecord, old_id) is None
    assert db.query(models.AnalysisResult).filter_by(email_id=old_id).first() is None
    assert db.get(models.EmailRecord, new.id).body_text == "keep me"


def test_retention_keeps_expired_malicious_row_and_only_purges_body():
    """Rules.md: malicious traffic keeps its row so the aggregated Graph DB
    indicators stay attributable; only the body is purged after 90 days.

    Previously the row was deleted outright here, destroying exactly the
    indicators the retention policy exists to preserve.
    """
    db = _db()
    mal = models.EmailRecord(subject="phish", body_text="secret payload",
                             timestamp=datetime.utcnow() - timedelta(days=120))
    db.add(mal)
    db.flush()
    db.add(models.AnalysisResult(email_id=mal.id, fraud_score=95.0))
    db.commit()
    mal_id = mal.id
    out = apply_retention(db, clean_days=7, malicious_days=90)
    assert out["purged_body"] == 1
    assert out["deleted"] == 0
    kept = db.get(models.EmailRecord, mal_id)
    assert kept is not None, "malicious rows must survive for forensic intel"
    assert kept.body_text == "" and kept.body_text_masked == ""
    assert kept.subject == "phish", "metadata retained alongside the indicators"


def test_retention_keeps_malicious_row_inside_forensic_window():
    """A malicious email under 90 days old is still under investigation."""
    db = _db()
    mal = models.EmailRecord(subject="phish", body_text="under investigation",
                             timestamp=datetime.utcnow() - timedelta(days=30))
    db.add(mal)
    db.flush()
    db.add(models.AnalysisResult(email_id=mal.id, fraud_score=95.0))
    db.commit()
    out = apply_retention(db, clean_days=7, malicious_days=90)
    assert out == {"purged_body": 0, "deleted": 0}
    assert db.get(models.EmailRecord, mal.id).body_text == "under investigation"


def test_retention_does_not_touch_shared_graph_sender_node():
    """Deleting one org's email must not strip another tenant's graph intel.

    Retention used to call remove_email_graph(sender_address) on the
    malicious branch. That issues a DETACH DELETE on a globally shared
    Email_Address node, wiping edges belonging to other tenants and to
    emails that still exist -- and destroying the aggregated indicators
    Rules.md says should survive. A malicious row is used so the old code
    path is actually exercised.
    """
    calls = []
    import app.modules.graph.store as store
    orig = getattr(store, "remove_email_graph", None)
    store.remove_email_graph = lambda addr: calls.append(addr)
    try:
        db = _db()
        mal = models.EmailRecord(subject="phish", body_text="b",
                                 sender_address="shared.sender@corp.test",
                                 timestamp=datetime.utcnow() - timedelta(days=120))
        db.add(mal)
        db.flush()
        db.add(models.AnalysisResult(email_id=mal.id, fraud_score=95.0))
        db.commit()
        apply_retention(db, clean_days=7, malicious_days=90)
    finally:
        if orig is not None:
            store.remove_email_graph = orig
    assert calls == [], "retention must not delete shared graph nodes"


def test_retention_rejects_negative_windows():
    """Fail closed: a negative window inverts every cutoff."""
    db = _db()
    for kwargs in ({"clean_days": -1}, {"malicious_days": -1}):
        try:
            apply_retention(db, **kwargs)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {kwargs}")


def test_retention_reports_es_delete_failure():
    """A row deleted from Postgres but still indexed in ES must be surfaced."""
    import app.modules.privacy.retention as ret
    import app.modules.search.elastic_sync as es
    orig = es.delete_email
    es.delete_email = lambda email_id: {"deleted": False, "error": "es down"}
    try:
        db = _db()
        old = models.EmailRecord(subject="old", body_text="b",
                                 timestamp=datetime.utcnow() - timedelta(days=30))
        db.add(old)
        db.flush()
        db.add(models.AnalysisResult(email_id=old.id, fraud_score=10.0))
        db.commit()
        out = apply_retention(db, clean_days=7, malicious_days=90)
    finally:
        es.delete_email = orig
    assert out["es_delete_failed"] == 1
    assert db.get(models.EmailRecord, old.id) is None


def test_custody_tamper_evidence():
    a = custody_manifest("emlhash", b"report-v1")
    b = custody_manifest("emlhash", b"report-v2")
    assert a["signature"] != b["signature"]
    assert len(a["signature"]) == 64 and a["eml_sha256"] == "emlhash"
