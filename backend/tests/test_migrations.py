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
import os
import pathlib
import re
import types

import pytest
import sqlalchemy as sa
from sqlalchemy.sql.elements import TextClause as RawSQL

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


# --- the policy SQL must be type-compatible with the schema -------------------
#
# The bug this pins: every identifier in this application is `String(36)`, so
# users.id / organization_id / user_id are all `varchar`, while auth.uid()
# returns `uuid`. Postgres has no `varchar = uuid` operator, so the uncast form
# failed at CREATE POLICY with
#
#     UndefinedFunction: operator does not exist: character varying = uuid
#
# That is fatal in exactly the same way the missing `authenticated` role was:
# init_db() turns a failed upgrade into a hard boot failure, so a deployment
# could not start. The tests above all use a fake bind and never execute the
# SQL, so none of them could have caught it — hence a structural check that
# does not need a database at all.

_UNCAST_UID = re.compile(r"auth\.uid\(\)(?!::text)")


def _non_null_comparisons(rule: str) -> str:
    """Rule text with the legitimate `auth.uid() IS [NOT] NULL` guards removed.

    A NULL test is valid on a uuid: `auth.uid() IS NOT NULL` is true or false
    for any type. What is invalid is *comparing* the uuid to a varchar column,
    so those are the occurrences that must carry a cast.
    """
    return re.sub(r"auth\.uid\(\)\s+IS\s+(NOT\s+)?NULL", "", rule)


@pytest.mark.parametrize(
    "rule_name", ["_ORG_RULE", "_EMAIL_RULE", "_USER_RULE"]
)
def test_no_uuid_is_compared_against_a_varchar_column(rule_name):
    """Every auth.uid() used as a value must be cast to text.

    Cast the function, never the column: `uuid::text` cannot fail, whereas
    `users.id::uuid` raises on any row whose id is not a well-formed UUID.
    """
    rule = getattr(rls, rule_name)
    bare = _UNCAST_UID.findall(_non_null_comparisons(rule))
    assert bare == [], (
        f"{rule_name} compares auth.uid() (uuid) to a varchar column without a "
        f"::text cast; Postgres has no varchar = uuid operator, so CREATE POLICY "
        f"fails and the app cannot boot"
    )


def test_identifier_columns_are_varchar_so_the_cast_is_required():
    """Ties the cast to the schema: if these ever become uuid, the ::text casts
    become redundant (still valid) and this test should be revisited."""
    models = (MIGRATION.parents[2] / "app" / "models.py").read_text()
    for column in ("id", "organization_id", "user_id"):
        assert f"{column}: Mapped[str" in models or f"{column}: Mapped[str |" in models, (
            f"expected {column} to be a str-backed column in models.py"
        )
    assert "String(36)" in models


# --- integration: actually execute the migration against a Supabase-like DB ---
#
# Enabled by pointing RLS_TEST_DATABASE_URL at a scratch PostgreSQL that has
# been prepared with Supabase's constructs. Skipped otherwise, so the default
# SQLite-only suite is unaffected. To reproduce the original failure by hand:
#
#   CREATE SCHEMA auth;
#   CREATE ROLE authenticated NOLOGIN;
#   CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE
#     AS $$ SELECT NULL::uuid $$;


@pytest.fixture
def supabase_bind():
    """A scratch PostgreSQL with Supabase's constructs AND the app's tables.

    Point RLS_TEST_DATABASE_URL at a database you do not mind losing. It must
    already have `auth.uid()` and the `authenticated` role; the tables are
    created here from the real metadata, so the varchar identifier columns the
    policies compare against are genuinely in place. If the tables already
    exist they are reused, which is what the second test in this file wants
    (it asserts on the state a prior upgrade() left behind).
    """
    url = os.environ.get("RLS_TEST_DATABASE_URL")
    if not url:
        pytest.skip("set RLS_TEST_DATABASE_URL to a Supabase-like PostgreSQL")

    from app.database import Base  # noqa: PLC0415 - needs settings/env in place
    import app.models  # noqa: F401,PLC0415 - registers every table on Base

    engine = sa.create_engine(url)
    try:
        # autocommit: DDL such as CREATE POLICY must not sit in an implicit
        # transaction that the test never commits, or the assertions below read
        # a different database state than the one left behind.
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            has_auth = conn.execute(
                sa.text(
                    "SELECT EXISTS (SELECT 1 FROM pg_proc p"
                    " JOIN pg_namespace n ON n.oid = p.pronamespace"
                    " WHERE n.nspname = 'auth' AND p.proname = 'uid')"
                )
            ).scalar()
            if not has_auth:
                pytest.skip("database has no auth.uid(); not Supabase-like")
            Base.metadata.create_all(conn)
            # GRANT is not policy, and RLS is not access control: without table
            # privileges `authenticated` gets InsufficientPrivilege instead of
            # an empty result set, so the fail-closed assertions below would
            # never reach the policy. Supabase grants these to its roles.
            for role in ("authenticated", "anon"):
                conn.exec_driver_sql(f"GRANT USAGE ON SCHEMA public TO {role}")
                for table in Base.metadata.sorted_tables:
                    conn.exec_driver_sql(
                        f"GRANT SELECT, INSERT, UPDATE, DELETE ON "
                        f"\"{table.name}\" TO {role}"
                    )
            yield _SupabaseSim(conn)
    finally:
        engine.dispose()


class _SupabaseSim:
    """A Supabase-shaped connection whose auth.uid() a test can steer.

    Real Supabase derives auth.uid() from the verified JWT on the connection.
    Here it reads a session GUC, so a test can act as a specific user, as a
    user in a specific org, or as nobody at all. The type is `uuid` exactly as
    on Supabase, which is what makes the varchar/uuid mismatch reproducible.
    """

    #: Matches the signature tests/test_migrations.py probes for.
    _UID_FN = (
        "CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid "
        "LANGUAGE sql STABLE AS $$ "
        "SELECT NULLIF(current_setting('soc.test_uid', true), '')::uuid $$"
    )

    def __init__(self, conn):
        self._conn = conn
        conn.exec_driver_sql(self._UID_FN)

    # -- steering ------------------------------------------------------------
    def as_user(self, uid: str | None):
        """Return a context manager acting as `uid` (None = no JWT)."""
        return _ActingAs(self._conn, uid)

    # -- pass-through --------------------------------------------------------
    def execute(self, *a, **kw):
        return self._conn.execute(*a, **kw)

    def exec_driver_sql(self, *a, **kw):
        return self._conn.exec_driver_sql(*a, **kw)

    @property
    def dialect(self):
        return self._conn.dialect

    @property
    def info(self):
        return self._conn.info

    def __getattr__(self, name):
        return getattr(self._conn, name)


class _ActingAs:
    def __init__(self, conn, uid: str | None):
        self._conn = conn
        self._uid = uid

    def __enter__(self):
        # The GUC must be set *after* SET ROLE: authenticated cannot write
        # arbitrary settings, whereas the owner can set one that then survives
        # the role switch for the policy expression to read.
        self._conn.exec_driver_sql("SET ROLE authenticated")
        self._conn.execute(
            sa.text("SELECT set_config('soc.test_uid', :u, false)"),
            {"u": self._uid or ""},
        )
        return self._conn

    def __exit__(self, *exc):
        self._conn.execute(
            sa.text("SELECT set_config('soc.test_uid', '', false)"), {}
        )
        self._conn.exec_driver_sql("RESET ROLE")
        return False


def _columns(bind, table: str) -> list[dict]:
    return bind.execute(
        sa.text(
            "SELECT column_name AS name, is_nullable FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = :t"
        ),
        {"t": table},
    ).mappings().all()


def _has_default(bind, table: str, column: str) -> bool:
    row = bind.execute(
        sa.text(
            "SELECT column_default FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = :t AND column_name = :c"
        ),
        {"t": table, "c": column},
    ).first()
    return bool(row and row[0])


def _policy_names() -> list[str]:
    """Policy name per table, matching how upgrade() names them."""
    return [
        f"{t}_tenant_isolation"
        if t in rls._ORG_TABLES + rls._EMAIL_TABLES
        else f"{t}_user_isolation"
        for t in rls.TABLES
    ]


def _reset_policies(bind) -> None:
    """CREATE POLICY has no OR REPLACE, so each test needs a clean slate.

    Drops only the policies, leaving the tables and the auth schema in place.
    """
    for table, policy in zip(rls.TABLES, _policy_names()):
        bind.exec_driver_sql(f'DROP POLICY IF EXISTS "{policy}" ON "{table}"')


def test_policies_are_created_for_real(supabase_bind, monkeypatch):
    """The whole point: CREATE POLICY must actually execute, type-check and
    stick. A fake bind cannot prove that."""
    monkeypatch.setattr(rls, "op", types.SimpleNamespace(
        get_bind=lambda: supabase_bind,
        execute=lambda sql: supabase_bind.exec_driver_sql(sql),
    ))
    _reset_policies(supabase_bind)
    rls.upgrade()

    created = supabase_bind.execute(
        sa.text("SELECT count(*) FROM pg_policies WHERE schemaname = 'public'")
    ).scalar()
    assert created == len(rls.TABLES), (
        f"expected one policy per table ({len(rls.TABLES)}), found {created}"
    )

    enabled = supabase_bind.execute(
        sa.text("SELECT count(*) FROM pg_class WHERE relrowsecurity")
    ).scalar()
    assert enabled == len(rls.TABLES)


def test_policies_are_bound_to_authenticated_and_not_public(supabase_bind, monkeypatch):
    monkeypatch.setattr(rls, "op", types.SimpleNamespace(
        get_bind=lambda: supabase_bind,
        execute=lambda sql: supabase_bind.exec_driver_sql(sql),
    ))
    _reset_policies(supabase_bind)
    rls.upgrade()
    roles = supabase_bind.execute(
        sa.text("SELECT DISTINCT unnest(roles) AS r FROM pg_policies")
    ).scalars().all()
    assert set(roles) == {"authenticated"}, (
        "policies must not be granted to PUBLIC, which would apply them to the "
        "service-role connection the app actually uses"
    )


def test_a_policy_expression_plans_without_a_type_error(supabase_bind, monkeypatch):
    """Postgres validates a policy expression when the policy is created, but
    executing a real query as `authenticated` is what proves the cast resolves
    against a live varchar column rather than merely parsing. The tenancy
    assertions below cover what that query returns."""
    monkeypatch.setattr(rls, "op", types.SimpleNamespace(
        get_bind=lambda: supabase_bind,
        execute=lambda sql: supabase_bind.exec_driver_sql(sql),
    ))
    _reset_policies(supabase_bind)
    rls.upgrade()

    # SET ROLE applies RLS for real; the table owner bypasses it, so without
    # this the query would never evaluate a policy expression.
    with supabase_bind.as_user(None) as conn:
        assert conn.execute(sa.text("SELECT id FROM email_records")).fetchall() == []

def _insert(bind, table: str, values: dict) -> None:
    """INSERT built from the live schema.

    Every NOT NULL column without a default must be supplied, otherwise this
    raises rather than silently writing a row the policy assertions would then
    misread. Timestamps fall back to now() because the application layer, not
    the database, is what normally writes them.
    """
    cols, vals = [], []
    for col in _columns(bind, table):
        name, nullable = col["name"], col["is_nullable"]
        if name in values:
            cols.append(name)
            vals.append(values[name])
        elif nullable == "YES" or _has_default(bind, table, name):
            continue
        elif name.endswith("_at") or name == "timestamp":
            cols.append(name)
            vals.append(RawSQL("now()"))
        else:
            raise AssertionError(
                f"{table}.{name} is NOT NULL with no default and no test value; "
                f"add one so the fixture stays valid"
            )

    def lit(v):
        if v is None:
            return "NULL"
        if isinstance(v, RawSQL):
            return v.text
        if isinstance(v, str):
            escaped = v.replace("'", "''")
            return f"'{escaped}'"
        return str(v)

    sql = (
        f"INSERT INTO {table} ({', '.join(cols)}) VALUES "
        f"({', '.join(lit(v) for v in vals)})"
    )
    if "id" in cols:
        sql += " ON CONFLICT (id) DO NOTHING"
    bind.exec_driver_sql(sql)


# Identities used by the tenancy tests below.
UID_ALICE = "00000000-0000-0000-0000-0000000000a1"   # Analyst, org A
UID_BOB   = "00000000-0000-0000-0000-0000000000b2"   # Analyst, org B
UID_LONE  = "00000000-0000-0000-0000-0000000000c3"   # Analyst, no org
UID_ADMIN = "00000000-0000-0000-0000-0000000000d4"   # Admin, org A
ORG_A     = "00000000-0000-0000-0000-0000000000a0"
ORG_B     = "00000000-0000-0000-0000-0000000000b0"
MAIL_A    = "00000000-0000-0000-0000-000000000e0a"
MAIL_B    = "00000000-0000-0000-0000-000000000e0b"
MAIL_LONE = "00000000-0000-0000-0000-000000000e0c"


def _seed_tenancy(bind) -> None:
    """Two tenants plus an org-less user, one email row each.

    Written as the table owner, which bypasses RLS by design — the same reason
    the application's own service-role connection is not subject to these
    policies.
    """
    for org_id, name in ((ORG_A, "org-a"), (ORG_B, "org-b")):
        _insert(bind, "organizations", {
            "id": org_id, "name": name, "compliance_policy": RawSQL("'{}'::json"),
        })
    _insert(bind, "users", {"id": UID_ALICE, "email": "alice@example.invalid",
                            "role": "Analyst", "organization_id": ORG_A})
    _insert(bind, "users", {"id": UID_BOB, "email": "bob@example.invalid",
                            "role": "Analyst", "organization_id": ORG_B})
    _insert(bind, "users", {"id": UID_LONE, "email": "lone@example.invalid",
                            "role": "Analyst", "organization_id": None})
    _insert(bind, "users", {"id": UID_ADMIN, "email": "admin@example.invalid",
                            "role": "Admin", "organization_id": ORG_A})
    for mail_id, org in ((MAIL_A, ORG_A), (MAIL_B, ORG_B), (MAIL_LONE, None)):
        _insert(bind, "email_records", {
            "id": mail_id,
            "message_id": f"<{mail_id}@example.invalid>",
            "sender_address": "sender@example.invalid",
            "recipient_address": "victim@example.invalid",
            "subject": f"probe {org}",
            "body_text": "probe",
            "body_text_masked": "probe",
            "raw_headers": "{}",
            "attachments_metadata": "[]",
            "raw_eml_hash": "0" * 64,
            "organization_id": org,
        })


def _visible_ids(bind) -> set:
    with bind.as_user(_CURRENT_UID[0]) as conn:
        return {r[0] for r in conn.execute(sa.text("SELECT id FROM email_records"))}


# Steered by the tests below; `as_user` reads it at each call.
_CURRENT_UID = [None]


@pytest.fixture
def tenancy(supabase_bind, monkeypatch):
    """A migrated, seeded, two-tenant database."""
    monkeypatch.setattr(rls, "op", types.SimpleNamespace(
        get_bind=lambda: supabase_bind,
        execute=lambda sql: supabase_bind.exec_driver_sql(sql),
    ))
    _reset_policies(supabase_bind)
    rls.upgrade()
    # Clear rows left by an earlier test in the same scratch database; the
    # database is reused across tests by design (recreating it per test would
    # cost a migration chain each time).
    for table in ("email_records", "users", "organizations"):
        supabase_bind.exec_driver_sql(f"DELETE FROM {table}")
    _seed_tenancy(supabase_bind)
    return supabase_bind


def test_an_unauthenticated_caller_sees_nothing(tenancy):
    _CURRENT_UID[0] = None
    assert _visible_ids(tenancy) == set()


def test_a_user_sees_only_their_own_organizations_mail(tenancy):
    _CURRENT_UID[0] = UID_ALICE
    assert _visible_ids(tenancy) == {MAIL_A}


def test_a_user_cannot_see_another_tenants_mail(tenancy):
    """The core isolation claim, checked against the database.

    `_ORG_RULE` is what enforces this when queries run as `authenticated`
    rather than as the service role, so it has to be exercised as a real
    SELECT, not asserted as a substring.
    """
    _CURRENT_UID[0] = UID_BOB
    assert _visible_ids(tenancy) == {MAIL_B}


def test_org_less_rows_are_not_widened_to_every_authenticated_user(tenancy):
    """`organization_id IS NULL OR ...` would hand the org-less row to every
    user. The application does not: org-less rows are private scope, so even a
    user with no organization of their own must not see someone else's."""
    _CURRENT_UID[0] = UID_LONE
    assert MAIL_LONE not in _visible_ids(tenancy)


def test_an_admin_sees_across_tenants(tenancy):
    """Admin is deliberately cross-tenant, applied the same way in the
    application layer and here. If this ever fails, the two have diverged —
    which is the bug worth catching, since the app's own _org_filter grants it."""
    _CURRENT_UID[0] = UID_ADMIN
    assert _visible_ids(tenancy) == {MAIL_A, MAIL_B, MAIL_LONE}, (
        "an Admin must see across tenants and must see org-less rows; that is "
        "the deliberate cross-tenant role the application also grants"
    )

