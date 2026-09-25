"""Guards on the RLS migration (P1).

`c9e8f7a6b3d2_add_rls_policies` writes policies against Supabase's
`auth.uid()` and grants them `TO authenticated`. Neither exists in a plain
PostgreSQL server — only inside a Supabase project. Before the guard below,
pointing the app at any other Postgres aborted the whole upgrade chain with
`role "authenticated" does not exist`, and `init_db()` turns a failed upgrade
into a hard boot failure, so the app would not start at all.

The policies are inert without those constructs regardless (the app connects
as a single service role, for which `auth.uid()` is NULL and the table owner
bypasses RLS), so skipping them off-Supabase is a no-op for enforcement.
"""
from __future__ import annotations

import importlib.util
import pathlib
import types

import pytest

MIGRATION = (
    pathlib.Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "c9e8f7a6b3d2_add_rls_policies.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("rls_migration", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rls = _load()


class _FakeResult:
    def __init__(self, value: bool):
        self._value = value

    def scalar(self):
        return self._value


class _FakeBind:
    """Minimal stand-in for an Alembic bind, recording executed SQL."""

    def __init__(self, dialect: str, has_auth_uid: bool):
        self.dialect = types.SimpleNamespace(name=dialect)
        self.statements: list[str] = []

    def execute(self, clause):
        text = str(getattr(clause, "text", clause))
        self.statements.append(text)
        return _FakeResult(self._has_auth_uid)

    # set by the factory below
    _has_auth_uid = False


def _bind(dialect: str, has_auth_uid: bool) -> _FakeBind:
    b = _FakeBind(dialect, has_auth_uid)
    b._has_auth_uid = has_auth_uid
    return b


@pytest.fixture
def patched_op(monkeypatch):
    """Point the migration's `op` at a fake bind for the duration of a test."""
    holder = types.SimpleNamespace(bind=None)
    monkeypatch.setattr(rls, "op", types.SimpleNamespace(
        get_bind=lambda: holder.bind,
        execute=lambda sql: holder.bind.execute(sql),
    ))
    return holder


# --- the guard ---------------------------------------------------------------


def test_not_applied_on_sqlite(patched_op):
    patched_op.bind = _bind("sqlite", has_auth_uid=False)
    assert rls._is_postgres() is False
    assert rls._should_apply() is False


def test_not_applied_on_plain_postgres_without_supabase_auth(patched_op):
    """The regression: PostgreSQL alone is not sufficient."""
    patched_op.bind = _bind("postgresql", has_auth_uid=False)
    assert rls._is_postgres() is True
    assert rls._is_supabase() is False
    assert rls._should_apply() is False


def test_applied_on_supabase_postgres(patched_op):
    patched_op.bind = _bind("postgresql", has_auth_uid=True)
    assert rls._is_supabase() is True
    assert rls._should_apply() is True


def test_supabase_probe_asks_for_auth_uid_not_the_role(patched_op):
    """Probe the function, so a renamed/dropped `authenticated` role also
    counts as non-Supabase instead of failing at policy creation."""
    patched_op.bind = _bind("postgresql", has_auth_uid=False)
    rls._is_supabase()
    sql = patched_op.bind.statements[-1]
    assert "auth" in sql and "uid" in sql
    assert "pg_proc" in sql


# --- upgrade() must be a silent no-op off Supabase ---------------------------


def _mutations(statements: list[str]) -> list[str]:
    """Statements that change schema or data. The Supabase probe is a
    read-only SELECT, so it is not a mutation and is allowed to run."""
    return [s for s in statements if not s.strip().upper().startswith("SELECT")]


@pytest.mark.parametrize(
    "dialect,has_auth_uid",
    [("sqlite", False), ("postgresql", False)],
)
def test_upgrade_is_a_noop_off_supabase(patched_op, dialect, has_auth_uid):
    patched_op.bind = _bind(dialect, has_auth_uid)
    rls.upgrade()  # must not raise
    assert _mutations(patched_op.bind.statements) == [], "must not alter the database"


def test_sqlite_short_circuits_before_even_probing(patched_op):
    patched_op.bind = _bind("sqlite", has_auth_uid=False)
    rls.upgrade()
    assert patched_op.bind.statements == []


def test_downgrade_is_a_noop_off_supabase(patched_op):
    patched_op.bind = _bind("postgresql", has_auth_uid=False)
    rls.downgrade()
    assert _mutations(patched_op.bind.statements) == []


def test_upgrade_enables_rls_and_creates_a_policy_per_table_on_supabase(patched_op):
    patched_op.bind = _bind("postgresql", has_auth_uid=True)
    rls.upgrade()
    sql = " ".join(patched_op.bind.statements)
    for table in rls.TABLES:
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in sql
        assert f"{table}_tenant_isolation" in sql or f"{table}_user_isolation" in sql
    assert "TO authenticated" in sql
    assert "auth.uid()" in sql


# --- the policies must never be wider than the application -------------------


def test_org_less_rows_are_not_widened_to_every_authenticated_user():
    """`organization_id IS NULL OR ...` would hand every authenticated user
    all org-less rows, which is strictly wider than the app allows."""
    assert "IS NULL OR" not in rls._ORG_RULE
    assert "organization_id IS NOT NULL" in rls._ORG_RULE


@pytest.mark.parametrize("rule", [rls._ORG_RULE, rls._EMAIL_RULE, rls._USER_RULE])
def test_every_rule_fails_closed_for_a_service_role_connection(rule):
    """The app connects as a single service role, so auth.uid() is NULL for
    every query it issues. Each rule must therefore match nothing."""
    assert "auth.uid() IS NOT NULL" in rule
    assert "USING (" in rule and "WITH CHECK (" in rule
