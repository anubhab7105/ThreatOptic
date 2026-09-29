"""Retention scheduler tests (F9): job runs, returns counts, appends audit log."""
import json


def test_retention_job_logs_audit(tmp_path, monkeypatch):
    import app.services.scheduler as sched

    audit = tmp_path / "retention_audit.log"
    monkeypatch.setattr(sched, "AUDIT_LOG", str(audit))
    entry = sched.run_retention_job()
    assert {"timestamp", "purged_body", "deleted"} <= set(entry)
    assert audit.exists()
    line = json.loads(audit.read_text().strip().splitlines()[-1])
    assert line["purged_body"] == entry["purged_body"] and "timestamp" in line


def test_scheduler_starts_with_daily_job():
    import app.services.scheduler as sched

    s = sched.start_scheduler()
    try:
        jobs = s.get_jobs()
        assert [j.id for j in jobs] == ["daily-retention"]
    finally:
        s.shutdown(wait=False)
