"""Alembic environment: managed (non-SQLite) databases upgrade via revisions.

SQLite dev keeps the fast create_all path in init_db; Postgres/Supabase
deployments should run `alembic upgrade head` (or rely on init_db, which
attempts it first and falls back).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.engine.url import make_url

from app.config import get_settings
from app.database import Base
from app import models  # noqa: F401 — register all tables

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    """Resolve the target database, most explicit source first.

    Previously this returned `resolved_db_url()` unconditionally, ignoring
    both `sqlalchemy.url` from alembic.ini and an `-x url=...` override. An
    operator therefore had no way to say *which* database to migrate other
    than editing the environment, and a stray DATABASE_URL would silently
    win. That is how a scratch migration once ran against the development
    database here and left it stamped with a revision that was later deleted.

    Precedence: `-x url=` > `sqlalchemy.url` > resolved_db_url().
    """
    explicit = context.get_x_argument(as_dictionary=True).get("url")
    if explicit:
        return explicit
    ini_url = config.get_main_option("sqlalchemy.url", None)
    if ini_url:
        return ini_url
    return get_settings().resolved_db_url()


def _require_migratable_target() -> None:
    """Refuse to migrate a missing or placeholder target (fail closed)."""
    url = _url()
    if not url or not url.strip():
        raise RuntimeError(
            "Refusing to run migrations: no database URL. Set DATABASE_URL, "
            "or pass one explicitly with `-x url=postgresql://...`."
        )
    lowered = url.lower()
    for marker in ("<", ">", "placeholder", "changeme", "your-password", "xxx"):
        if marker in lowered:
            raise RuntimeError(
                "Refusing to run migrations: the database URL still contains a "
                f"placeholder ({marker!r}). Provision the real value first."
            )


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def _redact(url: str) -> str:
    """Render a database URL with the password masked."""
    try:
        return make_url(url).render_as_string(hide_password=True)
    except Exception:
        return "<unprintable>"


def run_migrations_online() -> None:
    url = _url()
    _require_migratable_target()
    # Say which database is being changed, password redacted. Migrating the
    # wrong database is not recoverable, so this line is worth having.
    print(f"alembic: migrating {_redact(url)}")
    engine = create_engine(url, future=True, pool_pre_ping=True)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
