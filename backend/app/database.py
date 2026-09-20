"""SQLAlchemy engine/session/Base. SQLite by default, Postgres via DATABASE_URL."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from .config import get_settings


def _make_engine():
    settings = get_settings()
    url = settings.resolved_db_url()
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    # SQLite needs generous timeout for concurrent dashboard + ingest; pool tuned for local dev.
    return create_engine(
        url,
        connect_args=connect_args,
        future=True,
        pool_pre_ping=True,
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
    except Exception:
        pass  # fresh DBs / non-sqlite backends need nothing
