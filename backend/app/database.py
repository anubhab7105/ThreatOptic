"""SQLAlchemy engine/session/Base. SQLite by default, Postgres via DATABASE_URL."""
from datetime import datetime, timezone
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base
from .config import get_settings


def utcnow() -> datetime:
    """Timezone-aware UTC now — the single source for stored timestamps (Step 5)."""
    return datetime.now(timezone.utc)


def as_utc(dt: datetime | None) -> datetime | None:
    """Normalize a possibly-naive stored timestamp to aware UTC for comparison."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


STATEMENT_TIMEOUT_MS = 15_000
CONNECT_TIMEOUT_S = 5
SQLITE_BUSY_TIMEOUT_MS = 5_000


def _make_engine():
    """Build from FRESH settings (called at startup/test time, not frozen)."""
    settings = get_settings()
    url = settings.resolved_db_url()
    is_sqlite = url.startswith("sqlite")
    connect_args: dict = {}
    pool_kwargs: dict = {}
    execution_options: dict = {}
    if is_sqlite:
        connect_args = {"check_same_thread": False, "timeout": CONNECT_TIMEOUT_S}
    else:
        # Fail fast on dead DB / runaway queries instead of hanging workers.
        connect_args = {"connect_timeout": CONNECT_TIMEOUT_S,
                        "options": f"-c statement_timeout={STATEMENT_TIMEOUT_MS}"}
        # Supabase via PgBouncer (port 6543, ?pgbouncer=true) uses transaction mode;
        # keep pool small and pre-ping to avoid stale connections.
        if "pgbouncer=true" in url or "supabase" in url or ":6543" in url:
            pool_kwargs = {"pool_size": 5, "max_overflow": 5, "pool_recycle": 300}
    engine = create_engine(
        url,
        connect_args=connect_args,
        future=True,
        pool_pre_ping=True,
        execution_options=execution_options,
        **pool_kwargs,
    )
    if is_sqlite:
        # WAL for concurrent readers + busy timeout instead of instant
        # "database is locked"; foreign keys ON so ondelete=CASCADE in the
        # models actually enforces (SQLite defaults it OFF).
        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):
            try:
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
                cur.execute("PRAGMA foreign_keys=ON")
                cur.close()
            except Exception:
                pass
    return engine


def _make_session_factory(bind):
    return sessionmaker(bind=bind, autoflush=False, autocommit=False, future=True)


# Import-time defaults so `from app.database import engine` keeps working
# (and stays monkeypatchable in tests); init_db() rebuilds both from fresh
# settings at startup so post-import env changes are never frozen in.
engine = _make_engine()
SessionLocal = _make_session_factory(engine)
Base = declarative_base()


def rebuild_engine():
    """Rebuild engine + sessionmaker from current settings (startup path)."""
    global engine, SessionLocal
    engine = _make_engine()
    SessionLocal = _make_session_factory(engine)
    return engine


def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _alembic_upgrade() -> bool:
    """Managed-database path: real Alembic migrations. True on success.

    False lets the caller fail boot loudly — there is intentionally no
    create_all fallback on managed databases (it masks failed migrations).
    """
    import logging
    import os

    try:
        from alembic import command
        from alembic.config import Config

        ini = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "alembic.ini")
        if not os.path.exists(ini):
            return False
        cfg = Config(ini)
        cfg.set_main_option("script_location", os.path.join(os.path.dirname(ini), "alembic"))
        command.upgrade(cfg, "head")
        return True
    except Exception as e:
        logging.getLogger("database").warning("alembic upgrade failed, using create_all fallback: %s", type(e).__name__)
        return False


def init_db():
    from . import models  # noqa: F401
    from sqlalchemy import text
    from .config import get_settings

    # Rebuild from fresh settings first: the import-time engine may predate
    # post-import env changes (tests, containers).
    rebuild_engine()

    if not get_settings().resolved_db_url().startswith("sqlite"):
        # Managed Postgres etc: real migrations, no silent fallback — a
        # failed migration must fail boot loudly instead of being masked by
        # create_all (which also cannot add/alter columns safely there).
        if not _alembic_upgrade():
            raise RuntimeError(
                "Database migrations failed and create_all fallback is disabled "
                "on managed databases — fix Alembic state before booting."
            )
        return
    Base.metadata.create_all(bind=engine)
    # Additive migration for pre-existing SQLite files: create_all never adds
    # columns to tables that already exist, so backfill any missing ones.
    # (NOT NULL/DEFAULT/FK changes still require a real Alembic revision.)
    # Identifiers are dialect-quoted — never interpolated raw.
    try:
        from sqlalchemy import inspect as _inspect
        with engine.begin() as conn:
            insp = _inspect(conn)
            qp = engine.dialect.identifier_preparer.quote
            existing = {t: {c["name"] for c in insp.get_columns(t)} for t in insp.get_table_names()}
            for table in Base.metadata.sorted_tables:
                missing = [c for c in table.columns if c.name not in existing.get(table.name, set())]
                for col in missing:
                    coltype = col.type.compile(dialect=engine.dialect)
                    conn.execute(text(f"ALTER TABLE {qp(table.name)} ADD COLUMN {qp(col.name)} {coltype}"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_email_records_timestamp ON email_records (timestamp)"))
    except Exception:
        pass  # fresh DBs need nothing
