
import os


def test_rebuild_engine_picks_up_fresh_settings(monkeypatch, tmp_path):

    import app.database as dbmod

    url = f"sqlite:///{tmp_path}/fresh.db"
    monkeypatch.setenv("TEST_DATABASE_URL", url)
    try:
        dbmod.rebuild_engine()
        assert str(dbmod.engine.url) == url
        assert dbmod.SessionLocal.kw["bind"] is dbmod.engine
    finally:
        monkeypatch.delenv("TEST_DATABASE_URL", raising=False)

        monkeypatch.setenv("TEST_DATABASE_URL", url)
        dbmod.rebuild_engine()


def test_get_db_rolls_back_on_exception():

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

    db2 = dbmod.SessionLocal()
    try:
        assert db2.query(models.Organization).filter_by(name="rollback-probe-org").first() is None
    finally:
        db2.close()


def test_sqlite_pragmas_and_fk_enforcement(tmp_path, monkeypatch):

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

        from app import models
        from app.database import Base
        Base.metadata.create_all(bind=dbmod.engine)
        db = dbmod.SessionLocal()
        try:
            import uuid
            u = models.User(id=str(uuid.uuid4()), email="fkprobe@test.local", role="Analyst")
            db.add(u)
            db.flush()

            ga = models.GmailAccount(
                id=str(uuid.uuid4()), user_id=u.id, gmail_address="test@gmail.com"
            )
            db.add(ga)
            db.commit()
            assert db.query(models.GmailAccount).filter_by(user_id=u.id).count() == 1
            db.delete(u)
            db.commit()
            assert db.query(models.GmailAccount).filter_by(user_id=u.id).count() == 0
        finally:
            db.close()
    finally:

        monkeypatch.setenv("TEST_DATABASE_URL", url)
        dbmod.rebuild_engine()


def test_managed_db_refuses_silent_fallback(monkeypatch):

    import app.database as dbmod

    monkeypatch.setenv(
        "TEST_DATABASE_URL", "postgresql://u:p@localhost:5432/db")
    monkeypatch.setattr(dbmod, "_alembic_upgrade", lambda: False)
    try:
        import pytest
        with pytest.raises(RuntimeError, match="migrations failed"):
            dbmod.init_db()
    finally:

        monkeypatch.setenv("TEST_DATABASE_URL", "sqlite:///:memory:")
        dbmod.rebuild_engine()


def test_sqlite_backfill_adds_missing_columns(tmp_path, monkeypatch):

    import sqlite3
    import app.database as dbmod
    from app import models

    path = tmp_path / "legacy.db"
    con = sqlite3.connect(str(path))
    try:
        con.execute("CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, email VARCHAR(320), role VARCHAR(32))")
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

        assert "email" in cols and "role" in cols
    finally:

        monkeypatch.setenv("TEST_DATABASE_URL", f"sqlite:///{path}")
        dbmod.rebuild_engine()
