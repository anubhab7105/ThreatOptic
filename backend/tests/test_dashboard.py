
import threading
import uuid

from fastapi.testclient import TestClient
from helpers import login


def _auth(c: TestClient, role: str = "Analyst") -> dict:
    return login(role=role)[0]


def _seed_scored_mail(db, org_id, band_scores):

    from app import models
    from datetime import datetime, timezone
    for i, score in enumerate(band_scores):
        rec = models.EmailRecord(
            message_id=f"<dash-{uuid.uuid4().hex[:8]}@t.local>",
            sender_address="a@t.local", recipient_address="b@t.local",
            subject=f"s{i}", timestamp=datetime.now(timezone.utc),
            raw_eml_hash=uuid.uuid4().hex,
            organization_id=org_id)
        db.add(rec)
        db.flush()
        cls = ("Critical" if score >= 90 else "High" if score >= 75
               else "Medium" if score >= 50 else "Low")
        db.add(models.AnalysisResult(
            email_id=rec.id, fraud_score=float(score),
            threat_classification=cls, action_taken="Deliver"))
    db.commit()


def test_dashboard_aggregates_match_bands():
    from app.main import app
    from app.database import SessionLocal

    with TestClient(app) as c:
        h = _auth(c)
        db = SessionLocal()
        try:
            from app import models
            me = db.query(models.User).order_by(models.User.created_at.desc()).first()
            _seed_scored_mail(db, me.organization_id, [95, 80, 60, 10])

            from app.modules.cache import cache_delete_prefix
            cache_delete_prefix("dash:")
            stats = c.get("/api/v1/dashboard", headers=h).json()
        finally:
            db.close()
        assert stats["total_emails"] >= 4
        assert stats["blocked_threats"] >= 2
        d = stats["score_distribution"]
        assert d["critical"] >= 1 and d["high"] >= 1
        assert d["medium"] >= 1 and d["low"] >= 1
        assert sum(d.values()) >= 4


def test_dashboard_concurrent_miss_singleflight():

    from app.main import app

    with TestClient(app) as c:
        h = _auth(c)
        from app.modules.cache import cache_delete_prefix
        cache_delete_prefix("dash:")
        results, errors = [], []

        def _hit():
            try:
                r = c.get("/api/v1/dashboard", headers=h)
                results.append((r.status_code, r.json().get("total_emails")))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_hit) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert not errors, errors
        assert len(results) == 5 and all(s == 200 for s, _ in results)
        assert len({total for _, total in results}) == 1


def test_singleflight_helpers():
    from app.routers.api import _singleflight_begin, _singleflight_end

    owner, ev = _singleflight_begin("t-key")
    assert owner is True
    owner2, ev2 = _singleflight_begin("t-key")
    assert owner2 is False and ev2 is ev
    _singleflight_end("t-key", ev)
    assert ev.is_set()
    owner3, _ = _singleflight_begin("t-key")
    assert owner3 is True
    _singleflight_end("t-key", _singleflight_begin("t-key")[1])


def test_email_detail_offline_no_system_dns(monkeypatch):

    import socket
    from app.main import app

    def _boom(host):
        raise SystemExit(f"system resolver touched offline: {host}")

    monkeypatch.setattr(socket, "gethostbyname", _boom)
    with TestClient(app) as c:
        h = _auth(c)
        eid = c.post("/api/v1/emails/ingest", headers=h, json={
            "raw": "From: a@t.local\nTo: b@t.local\nSubject: d\n\nhello"}).json()["email_id"]
        r = c.get(f"/api/v1/emails/{eid}", headers=h)
        assert r.status_code == 200, r.text
        assert r.json()["email"]["id"] == eid
