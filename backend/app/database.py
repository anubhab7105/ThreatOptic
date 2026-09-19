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
    Base.metadata.create_all(bind=engine)
