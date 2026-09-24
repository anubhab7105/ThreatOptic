"""P1 database.py: fresh engine rebuild, rollback, pragmas, no silent fallback."""
import os


def test_rebuild_engine_picks_up_fresh_settings(monkeypatch, tmp_path):
    """P1: post-import env changes must not stay frozen in the engine."""
    import app.database as dbmod

    url = f"sqlite:///{tmp_path}/fresh.db"
    monkeypatch.setenv("TEST_DATABASE_URL", url)
    try:
        dbmod.rebuild_engine()
        assert str(dbmod.engine.url) == url
        assert dbmod.SessionLocal.kw["bind"] is dbmod.engine
    finally:
        monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
        dbmod.rebuild_engine()


def test_get_db_rolls_back_on_exception():
    """P1: a failed request must not poison the session for the next user."""
    import pytest
    import app.database as dbmod
    from app import models

    gen = dbmod.get_db()
    db = next(gen)
    db.add(models.Organization(name="rollback-probe-org", compliance_policy={}))
    db.flush()
    with pytest.raises(RuntimeError, match="boom"):
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            gen.throw(RuntimeError("boom"))
    # the uncommitted row was rolled back: invisible to a fresh session
    db2 = dbmod.SessionLocal()
    try:
        assert db2.query(models.Organization).filter_by(name="rollback-probe-org").first() is None
    finally:
        db2.close()


def test_sqlite_pragmas_and_fk_enforcement(tmp_path, monkeypatch):
    """P1: WAL + busy timeout + foreign keys ON; cascades actually work."""
    import sqlite3
    from sqlalchemy import text
    import app.database as dbmod

    url = f"sqlite:///{tmp_path}/prag.db"
    monkeypatch.setenv("TEST_DATABASE_URL", url)
    try:
        dbmod.rebuild_engine()
        with dbmod.engine.begin() as conn:
            mode = conn.execute(text("PRAGMA journal_mode")).scalar()
            assert mode and mode.lower() == "wal", mode
            assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1
            assert conn.execute(text("PRAGMA busy_timeout")).scalar() == 5000
        # ondelete=CASCADE enforced: user delete removes refresh tokens
        from app import models
        from app.database import Base
        Base.metadata.create_all(bind=dbmod.engine)
        db = dbmod.SessionLocal()
        try:
            u = models.User(username="fkprobe", password_hash="x", role="Analyst")
            db.add(u)
            db.flush()
            from datetime import datetime, timezone, timedelta
            db.add(models.RefreshToken(
                user_id=u.id, token_hash="abc123",
                expires_at=datetime.now(timezone.utc) + timedelta(days=1)))
            db.commit()
            assert db.query(models.RefreshToken).filter_by(user_id=u.id).count() == 1
            db.delete(u)
            db.commit()
            assert db.query(models.RefreshToken).filter_by(user_id=u.id).count() == 0
        finally:
            db.close()
    finally:
        monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
        dbmod.rebuild_engine()


def test_managed_db_refuses_silent_fallback(monkeypatch):
    """P1: failed migrations on Postgres fail boot loudly (no create_all)."""
    import app.database as dbmod

    monkeypatch.setenv(
        "TEST_DATABASE_URL", "postgresql://u:p@localhost:5432/db")
    monkeypatch.setattr(dbmod, "_alembic_upgrade", lambda: False)
    try:
        import pytest
        with pytest.raises(RuntimeError, match="migrations failed"):
            dbmod.init_db()
    finally:
        monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
        dbmod.rebuild_engine()


def test_sqlite_backfill_adds_missing_columns(tmp_path, monkeypatch):
    """P0-backfill contract preserved: legacy tables gain new columns."""
    import sqlite3
    import app.database as dbmod
    from app import models  # noqa: F401

    path = tmp_path / "legacy.db"
    con = sqlite3.connect(str(path))
    try:
        con.execute("CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, username VARCHAR(255))")
        con.commit()
    finally:
        con.close()
    monkeypatch.setenv("TEST_DATABASE_URL", f"sqlite:///{path}")
    try:
        dbmod.init_db()
        con = sqlite3.connect(str(path))
        try:
            cols = {r[1] for r in con.execute("PRAGMA table_info(users)").fetchall()}
        finally:
            con.close()
        assert "password_hash" in cols and "role" in cols
    finally:
        monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
        dbmod.rebuild_engine()
