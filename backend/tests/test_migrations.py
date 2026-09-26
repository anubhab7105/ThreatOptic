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


DRIFT_MIGRATION = (
    pathlib.Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "e5a1c93d7b28_add_missing_encrypted_columns_and_indexes.py"
)


def _load_drift_migration():
    """Import the drift revision so its declared scope can be asserted.

    Safe to import: `alembic.op` is a proxy that only needs a live context
    when an operation is actually invoked, and nothing here invokes one.
    """
    spec = importlib.util.spec_from_file_location("drift_migration", DRIFT_MIGRATION)
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



# ---------------------------------------------------------------------------
# models-vs-migrations drift
# ---------------------------------------------------------------------------
#
# The initial revision `834dc871451e` predates the OAuth/mailbox vault work and
# was never updated. Five columns the ORM selects on every request
# (`app/routers/gmail.py` reads three of them, `app/services/mailbox_poll.py`
# decrypts them) existed in `app/models.py` but in no revision, so a database
# built purely from migrations booted, served /health, and then 500'd on every
# mailbox operation with `UndefinedColumn`. Nothing caught it because nothing
# compared the two.
#
# These tests are the CI check that does. They read the migration sources
# rather than a live database, so they run in the default SQLite suite and in
# every PR — the alternative (autogenerate against a scratch database) is
# opt-in and only runs when `MIGRATION_DRIFT_DATABASE_URL` is set.

VERSIONS_DIR = MIGRATION.parent

_CREATE_TABLE = re.compile(r"""op\.create_table\(\s*['"](?P<table>[A-Za-z0-9_]+)['"]""")
_ADD_COLUMN = re.compile(
    r"""op\.add_column\(\s*['\"](?P<table>[A-Za-z0-9_]+)['\"]\s*,\s*"""
    r"""sa\.Column\(\s*['\"](?P<column>[A-Za-z0-9_]+)['\"]"""
)
_SA_COLUMN = re.compile(r"""sa\.Column\(\s*['\"](?P<column>[A-Za-z0-9_]+)['\"]""")
_OP_CALL = re.compile(r"^\s*op\.[a-z_]+\(")
# b7c2d1a9e4f5 adds users.email through Alembic's batch_alter_table helper,
# where the table is named once and the columns are added to the batch
# afterwards, so the column name appears without a table name beside it.
_BATCH_TABLE = re.compile(r"""batch_alter_table\(\s*['\"](?P<table>[A-Za-z0-9_]+)['\"]""")
_BATCH_ADD = re.compile(
    r"""batch\.add_column\(\s*sa\.Column\(\s*['\"](?P<column>[A-Za-z0-9_]+)['\"]"""
)

# The five columns this finding is about, named individually so a regression
# names the exact column rather than reporting a set difference.
_VAULT_COLUMNS = {
    "gmail_accounts": ("encrypted_client_id", "encrypted_client_secret"),
    "mailbox_connections": ("encrypted_client_id", "encrypted_client_secret"),
    "oauth_states": ("encrypted_client_secret",),
}

_MISSING_INDEXES = {
    "users": "ix_users_organization_id",
    "email_records": "ix_email_records_timestamp",
    "mailbox_connections": "ix_mailbox_connections_organization_id",
}


def _created_columns() -> dict[str, set[str]]:
    """table -> every column the migration chain creates, across all revisions.

    Combines two passes because the three forms are written differently in
    practice: `op.create_table` is scanned line by line (a create_table body
    ends at the next `op.` call at any indentation, which is enough structure
    for these files and avoids a real AST walk), while `op.add_column` and
    `batch.add_column` are matched against the whole source with
    whitespace-tolerant patterns — alembic's own formatter wraps a call across
    three lines (`op.add_column(\n  'table',\n  sa.Column('c',`), so a
    per-line match silently misses it.

    Known limit: a column added in a loop over unquoted variables is invisible
    to this scan. Revisions must therefore spell out their `op.add_column`
    calls, which `test_the_drift_fix_covers_exactly_the_five_vault_columns`
    enforces for the revision that closes this finding.
    """
    created: dict[str, set[str]] = {}
    for path in sorted(VERSIONS_DIR.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        current: str | None = None
        batch_table: str | None = None
        for line in source.splitlines():
            # create_table must be matched *before* the generic op-call check:
            # `op.create_table(` is itself an op call, so testing for a
            # terminating op call first silently drops every table after the
            # first one.
            started = _CREATE_TABLE.search(line)
            if started:
                current = started.group("table")
                created.setdefault(current, set())
                for col in _SA_COLUMN.finditer(line):
                    created[current].add(col.group("column"))
                continue
            batched = _BATCH_TABLE.search(line)
            if batched:
                batch_table = batched.group("table")
                created.setdefault(batch_table, set())
                continue
            batch_add = _BATCH_ADD.search(line)
            if batch_add and batch_table:
                created.setdefault(batch_table, set()).add(batch_add.group("column"))
                continue
            if current is not None:
                if _OP_CALL.match(line):
                    current = None  # previous create_table body is finished
                    continue
                col = _SA_COLUMN.search(line)
                if col:
                    created[current].add(col.group("column"))
        for match in _ADD_COLUMN.finditer(source):
            created.setdefault(match.group("table"), set()).add(match.group("column"))
    return created


def _orm_columns() -> dict[str, set[str]]:
    from app import models  # noqa: F401  (populates Base.metadata)
    from app.database import Base

    return {t.name: {c.name for c in t.columns} for t in Base.metadata.tables.values()}


@pytest.mark.parametrize(
    "table,column",
    [(t, c) for t, cols in _VAULT_COLUMNS.items() for c in cols],
)
def test_vault_column_is_created_by_the_migration_chain(table: str, column: str) -> None:
    """Each vault column the ORM selects must exist after `alembic upgrade head`.

    This is the direct regression test for the fresh-deploy breakage: before
    the fix every one of these five was absent from every revision.
    """
    assert column in _created_columns().get(table, set()), (
        f"{table}.{column} is declared in app/models.py and read by "
        f"app/routers/gmail.py and app/services/mailbox_poll.py, but no Alembic "
        f"revision creates it — a database built from migrations will raise "
        f"UndefinedColumn on the first mailbox request"
    )


@pytest.mark.parametrize("table,index", sorted(_MISSING_INDEXES.items()))
def test_declared_index_is_created_by_the_migration_chain(table: str, index: str) -> None:
    """An index=True column with no matching index is a silent full scan."""
    source = "\n".join(p.read_text(encoding="utf-8") for p in sorted(VERSIONS_DIR.glob("*.py")))
    assert index in source, (
        f"{index} is declared via index=True in app/models.py but no revision "
        f"creates it; every {table} query filtering on that column degrades "
        f"to a sequential scan"
    )


def test_every_orm_column_exists_in_the_migration_chain() -> None:
    """The general form of the check: no ORM column may be migration-absent.

    Deliberately excludes nothing. The naive-DateTime and
    `uq_email_hash_org` findings are separate revisions, but they differ from
    the models in *type*/*constraint shape* rather than in column presence, so
    they do not trip this test — column presence was exactly the gap here.
    """
    created = _created_columns()
    missing = {
        table: sorted(cols - created.get(table, set()))
        for table, cols in _orm_columns().items()
        if cols - created.get(table, set())
    }
    assert not missing, (
        "columns declared in app/models.py but never created by any Alembic "
        f"revision (fresh deploys will break on these): {missing}"
    )


def test_every_orm_table_is_created_by_the_migration_chain() -> None:
    """A whole missing table is the same bug, one level up."""
    created = _created_columns()
    assert set(_orm_columns()) <= set(created), (
        f"tables in app/models.py with no create_table in any revision: "
        f"{sorted(set(_orm_columns()) - set(created))}"
    )


def test_case_status_check_constraint_is_created_by_the_migration_chain() -> None:
    """`investigation_cases.status` must be constrained to the fixed enum.

    Alembic's autogenerate does not emit CHECK-constraint diffs, so this gap
    survives a models-vs-database diff and has to be pinned structurally.
    Without it a database built purely from migrations accepts any status
    string, while the ORM claims a three-value enum.
    """
    source = "\n".join(p.read_text(encoding="utf-8") for p in sorted(VERSIONS_DIR.glob("*.py")))
    assert "ck_cases_status" in source, (
        "app/models.py:54 declares CheckConstraint(..., name='ck_cases_status') "
        "but no revision creates it, so investigation_cases.status is "
        "unconstrained on a migrated database"
    )


def test_the_drift_fix_covers_exactly_the_five_vault_columns() -> None:
    """Pin the finding's scope in the revision itself, not in prose.

    Production was created before these columns existed, so one may have been
    added out of band since; an unguarded `ADD COLUMN` would abort the upgrade
    chain with `column ... already exists`, and init_db() turns a failed
    upgrade into a hard boot failure. So the add must be inspector-guarded.
    """
    mod = _load_drift_migration()
    assert set(mod._VAULT_COLUMNS) == {
        ("gmail_accounts", "encrypted_client_id"),
        ("gmail_accounts", "encrypted_client_secret"),
        ("mailbox_connections", "encrypted_client_id"),
        ("mailbox_connections", "encrypted_client_secret"),
        ("oauth_states", "encrypted_client_secret"),
    }

    src = DRIFT_MIGRATION.read_text(encoding="utf-8")
    upgrade_body = src.split("def upgrade", 1)[1].split("def downgrade", 1)[0]

    # Every declared column must have a literal, guarded op.add_column, or the
    # structural drift scan above cannot see it and the gap silently returns.
    for table, column in mod._VAULT_COLUMNS:
        guard = f'"{column}" not in _columns(_inspector(), "{table}")'
        assert guard in upgrade_body, (
            f"{table}.{column} has no inspector guard in upgrade(); an "
            f"unconditional add aborts the upgrade chain wherever the column "
            f"already exists"
        )
        assert f'"{table}"' in upgrade_body, f"{table} add is missing"

    assert upgrade_body.count("op.add_column(") == 5, (
        "the finding is exactly five columns; a sixth or a fourth means this "
        "revision and its test have drifted apart"
    )
    # NOT NULL adds need a server default or they fail on any populated table.
    assert upgrade_body.count("server_default=sa.text") == 5, (
        "every NOT NULL add needs a server default so existing rows backfill; "
        "a bare ADD COLUMN NOT NULL fails as soon as the table has one row"
    )
    assert upgrade_body.count("server_default=None") == 5, (
        "every server default must be dropped afterwards, or the schema never "
        "matches Base.metadata and this drift check fails forever"
    )


# ---------------------------------------------------------------------------
# the backfill path, against a real populated database
# ---------------------------------------------------------------------------
#
# Production sits at `b7c2d1a9e4f5` with rows already in gmail_accounts,
# mailbox_connections and oauth_states, and none of the five columns this
# revision adds. That makes the populated-table path the one that actually
# ships, and it is exactly where the obvious implementation dies:
# `ADD COLUMN ... NOT NULL` fails on Postgres the moment the table holds a
# single row. The server default is the whole fix, so it is worth proving
# rather than asserting.
#
# Opt-in: point DRIFT_TEST_DATABASE_URL at a scratch PostgreSQL. It is
# dropped and rebuilt, so use a database you do not mind losing.

DRIFT_URL = os.environ.get("DRIFT_TEST_DATABASE_URL")


def _run_migrations(url: str, revision: str) -> None:
    """Run the migration chain against `url` in a subprocess.

    Deliberately not `alembic.command.upgrade()` in-process. `env.py:23-24`
    resolves its own URL from `get_settings().resolved_db_url()` and ignores
    both `sqlalchemy.url` in the config and `-x` on the command line, so a
    Config pointed at a scratch database silently migrates whatever
    DATABASE_URL the ambient settings hold. That already happened once during
    this work: the scratch fixture stamped the developer's local database with
    a revision that no longer existed and left it unbootable.

    A subprocess with DATABASE_URL set in its own environment cannot inherit
    the parent's cached settings, so the URL passed in is provably the URL
    used. A mismatch is asserted, not assumed.

    `TEST_DATABASE_URL` is removed from that environment as well, and this is
    not incidental: `config.resolved_db_url()` (config.py:254-257) prefers
    `TEST_DATABASE_URL` over `DATABASE_URL` for pytest isolation. Inheriting
    it makes alembic migrate a throwaway SQLite file, exit 0, and leave the
    named PostgreSQL untouched — a green test that asserts nothing.
    """
    import subprocess
    import sys

    root = pathlib.Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["DATABASE_URL"] = url
    env.pop("TEST_DATABASE_URL", None)
    env["PYTHONPATH"] = str(root)
    # alembic only needs a URL here; the app's own secret checks are not in
    # scope for this fixture and would only add a way to fail.
    env.setdefault("SECRET_KEY", "drift-test-secret-key-not-a-real-secret")
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", revision],
        cwd=str(root),
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"alembic upgrade {revision} failed against {url}:\n"
        f"{result.stdout}\n{result.stderr}"
    )


@pytest.fixture
def populated_db():
    """A database migrated to `b7c2d1a9e4f5` and seeded with real rows.

    Deliberately not reusing the RLS fixture: this one needs the *migration
    chain* to have run, then rows inserted, then the chain resumed — which is
    the production sequence and cannot be reproduced by create_all.
    """
    if not DRIFT_URL:
        pytest.skip("set DRIFT_TEST_DATABASE_URL to a scratch PostgreSQL")
    if not DRIFT_URL.startswith("postgresql"):
        pytest.skip("DRIFT_TEST_DATABASE_URL must be PostgreSQL: ADD COLUMN "
                    "NOT NULL backfill is Postgres-specific")

    engine = sa.create_engine(DRIFT_URL, future=True)
    with engine.begin() as conn:
        assert conn.execute(sa.text("SELECT current_database()")).scalar() in DRIFT_URL, (
            "refusing to run: the engine is not connected to the database named "
            "in DRIFT_TEST_DATABASE_URL"
        )
        conn.execute(sa.text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    engine.dispose()

    _run_migrations(DRIFT_URL, "b7c2d1a9e4f5")

    # Prove the chain landed here before seeding, so a misdirected migration
    # fails on this line rather than as a confusing UndefinedTable further down.
    engine = sa.create_engine(DRIFT_URL, future=True)
    with engine.connect() as conn:
        stamped = conn.execute(
            sa.text("SELECT version_num FROM alembic_version")
        ).scalar()
    assert stamped == "b7c2d1a9e4f5", (
        f"expected the chain to be at b7c2d1a9e4f5, found {stamped!r} — the "
        f"migration ran against a different database than DRIFT_TEST_DATABASE_URL"
    )

    engine = sa.create_engine(DRIFT_URL, future=True)
    with engine.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO users (id, role, email, created_at) "
            "VALUES ('u1', 'analyst', 'a@x.test', now())"
        ))
        conn.execute(sa.text(
            "INSERT INTO gmail_accounts (id, user_id, gmail_address, refresh_token, "
            "client_id, last_sync_at, created_at, updated_at) "
            "VALUES ('g1', 'u1', 'a@x.test', 'v1$abc', '', NULL, now(), now())"
        ))
        conn.execute(sa.text(
            "INSERT INTO mailbox_connections (id, user_id, provider, account_email, "
            "encrypted_refresh_token, last_poll_at, created_at, updated_at) "
            "VALUES ('m1', 'u1', 'google', 'a@x.test', 'v1$xyz', NULL, now(), now())"
        ))
        conn.execute(sa.text(
            "INSERT INTO oauth_states (id, state, user_id, provider, redirect_uri, "
            "client_id, code_verifier, expires_at, used, created_at) "
            "VALUES ('o1', 'st1', 'u1', 'google', 'http://x.test', 'ci', 'cv', "
            "now() + interval '1 hour', false, now())"
        ))
    engine.dispose()
    return _cfg


@pytest.mark.parametrize(
    "table,column",
    [
        ("gmail_accounts", "encrypted_client_id"),
        ("gmail_accounts", "encrypted_client_secret"),
        ("mailbox_connections", "encrypted_client_id"),
        ("mailbox_connections", "encrypted_client_secret"),
        ("oauth_states", "encrypted_client_secret"),
    ],
)
def test_not_null_add_backfills_existing_rows(populated_db, table: str, column: str) -> None:
    """The new column must exist and be '' on rows written before the upgrade.

    Two failure modes this catches, both fatal in production: the upgrade
    aborting outright (`ADD COLUMN ... NOT NULL` on a populated table), and
    the add succeeding while leaving NULLs that the NOT NULL promise forbids
    and that `coalesce(..., "")` in the application would silently mask.
    """
    _run_migrations(DRIFT_URL, "head")

    engine = sa.create_engine(DRIFT_URL, future=True)
    with engine.connect() as conn:
        value = conn.execute(
            sa.text(f"SELECT {column} FROM {table}")
        ).scalar()
    engine.dispose()
    assert value == "", (
        f"{table}.{column} should be backfilled to '' on pre-existing rows, "
        f"got {value!r}"
    )


def test_existing_rows_survive_the_drift_migration(populated_db) -> None:
    """A schema migration must not disturb the data already in the table."""
    _run_migrations(DRIFT_URL, "head")
    engine = sa.create_engine(DRIFT_URL, future=True)
    with engine.connect() as conn:
        token, address = conn.execute(
            sa.text("SELECT refresh_token, gmail_address FROM gmail_accounts")
        ).one()
    engine.dispose()
    assert (token, address) == ("v1$abc", "a@x.test"), (
        "the vault ciphertext and address of a pre-existing row were altered by "
        "the migration"
    )


def test_case_status_is_constrained_on_a_migrated_database(populated_db) -> None:
    """`ck_cases_status` must actually reject a bad status after the upgrade."""
    _run_migrations(DRIFT_URL, "head")
    engine = sa.create_engine(DRIFT_URL, future=True)
    with engine.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO investigation_cases (id, title, status, email_ids, "
            "notes, created_at, updated_at) "
            "VALUES ('c1', 'T', 'Open', '[]', '', now(), now())"
        ))
    with pytest.raises(sa.exc.IntegrityError, match="ck_cases_status"):
        with engine.begin() as conn:
            conn.execute(sa.text(
                "INSERT INTO investigation_cases (id, title, status, email_ids, "
                "notes, created_at, updated_at) "
                "VALUES ('c2', 'T', 'Bogus', '[]', '', now(), now())"
            ))
    engine.dispose()


def test_the_drift_migration_is_idempotent(populated_db) -> None:
    """Re-running upgrade() must be a no-op, not `column already exists`.

    This is what the inspector guards buy, and it is the difference between a
    migration that is safe to retry and one that bricks the boot: init_db()
    turns a failed `alembic upgrade` into a hard startup failure.
    """
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    import alembic.op as alembic_op

    _run_migrations(DRIFT_URL, "head")
    mod = _load_drift_migration()

    engine = sa.create_engine(DRIFT_URL, future=True)
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn)
        previous = getattr(alembic_op, "_proxy", None)
        alembic_op._proxy = Operations(ctx)
        try:
            mod.upgrade()  # must not raise
        finally:
            alembic_op._proxy = previous
    engine.dispose()
