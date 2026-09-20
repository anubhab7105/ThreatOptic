"""SQLAlchemy engine/session/Base. SQLite by default, Postgres via DATABASE_URL."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from .config import get_settings


def _make_engine():
    settings = get_settings()
    url = settings.resolved_db_url()
    is_sqlite = url.startswith("sqlite")
    connect_args = {"check_same_thread": False} if is_sqlite else {}
    # Supabase via PgBouncer (port 6543, ?pgbouncer=true) uses transaction mode;
    # keep pool small and pre-ping to avoid stale connections.
    pool_kwargs = {}
    if not is_sqlite:
        if "pgbouncer=true" in url or "supabase" in url or ":6543" in url:
            pool_kwargs = {"pool_size": 5, "max_overflow": 5, "pool_recycle": 300}
    return create_engine(
        url,
        connect_args=connect_args,
        future=True,
        pool_pre_ping=True,
        **pool_kwargs,
    )


engine = _make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from . import models  # noqa: F401
    from sqlalchemy import inspect, text
    Base.metadata.create_all(bind=engine)
    # Additive migration for pre-existing SQLite files: create_all never adds
    # columns to tables that already exist, so backfill any missing ones.
    try:
        with engine.begin() as conn:
            existing = {t: {c["name"] for c in inspect(conn).get_columns(t)} for t in inspect(conn).get_table_names()}
            for table in Base.metadata.sorted_tables:
                missing = [c for c in table.columns if c.name not in existing.get(table.name, set())]
                for col in missing:
                    coltype = col.type.compile(dialect=engine.dialect)
                    conn.execute(text(f"ALTER TABLE {table.name} ADD COLUMN {col.name} {coltype}"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_email_records_timestamp ON email_records (timestamp)"))
    except Exception:
        pass  # fresh DBs / non-sqlite backends need nothing
