"""Alembic environment: managed (non-SQLite) databases upgrade via revisions.

SQLite dev keeps the fast create_all path in init_db; Postgres/Supabase
deployments should run `alembic upgrade head` (or rely on init_db, which
attempts it first and falls back).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from alembic import context
from sqlalchemy import create_engine

from app.config import get_settings
from app.database import Base
from app import models  # noqa: F401 — register all tables

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    return get_settings().resolved_db_url()


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url(), future=True, pool_pre_ping=True)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
