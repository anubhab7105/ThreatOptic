
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from .config import get_settings


def utcnow() -> datetime:

    return datetime.now(timezone.utc)


def as_utc(dt: datetime | None) -> datetime | None:

    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


STATEMENT_TIMEOUT_MS = 15_000
CONNECT_TIMEOUT_S = 5


def _make_engine():

    settings = get_settings()
    url = settings.resolved_db_url()
    if url.startswith("sqlite"):


        def _sqlite_connect(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()
        
        from sqlalchemy import event
        engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            future=True,
            pool_pre_ping=True,
        )
        event.listen(engine, "connect", _sqlite_connect)
        return engine
    connect_args = {"connect_timeout": CONNECT_TIMEOUT_S,
                    "options": f"-c statement_timeout={STATEMENT_TIMEOUT_MS}"}
    pool_kwargs = {}
    if "pgbouncer=true" in url or "supabase" in url or ":6543" in url:
        pool_kwargs = {"pool_size": 5, "max_overflow": 5, "pool_recycle": 300}
    return create_engine(url, connect_args=connect_args, future=True,
                         pool_pre_ping=True, **pool_kwargs)


def _make_session_factory(bind):
    return sessionmaker(bind=bind, autoflush=False, autocommit=False, future=True)








try:
    engine = _make_engine()
except RuntimeError:
    engine = create_engine("sqlite:///:memory:", future=True, pool_pre_ping=True)
SessionLocal = _make_session_factory(engine)
Base = declarative_base()


def rebuild_engine():

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
        logging.getLogger("database").warning("alembic upgrade failed: %s", type(e).__name__)
        return False


def init_db():

    from . import models
    rebuild_engine()
    if get_settings().resolved_db_url().startswith("sqlite"):
        Base.metadata.create_all(bind=engine)
        return
    if not _alembic_upgrade():
        raise RuntimeError(
            "Database migrations failed. Fix Alembic state before booting."
        )
