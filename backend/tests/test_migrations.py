
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


    def __init__(self, dialect: str, has_auth_uid: bool):
        self.dialect = types.SimpleNamespace(name=dialect)
        self.statements: list[str] = []

    def execute(self, clause):
        text = str(getattr(clause, "text", clause))
        self.statements.append(text)
        return _FakeResult(self._has_auth_uid)


    _has_auth_uid = False


def _bind(dialect: str, has_auth_uid: bool) -> _FakeBind:
    b = _FakeBind(dialect, has_auth_uid)
    b._has_auth_uid = has_auth_uid
    return b


@pytest.fixture
def patched_op(monkeypatch):

    holder = types.SimpleNamespace(bind=None)
    monkeypatch.setattr(rls, "op", types.SimpleNamespace(
        get_bind=lambda: holder.bind,
        execute=lambda sql: holder.bind.execute(sql),
    ))
    return holder





def test_not_applied_on_sqlite(patched_op):
    patched_op.bind = _bind("sqlite", has_auth_uid=False)
    assert rls._is_postgres() is False
    assert rls._should_apply() is False


def test_not_applied_on_plain_postgres_without_supabase_auth(patched_op):

    patched_op.bind = _bind("postgresql", has_auth_uid=False)
    assert rls._is_postgres() is True
    assert rls._is_supabase() is False
    assert rls._should_apply() is False


def test_applied_on_supabase_postgres(patched_op):
    patched_op.bind = _bind("postgresql", has_auth_uid=True)
    assert rls._is_supabase() is True
    assert rls._should_apply() is True


def test_supabase_probe_asks_for_auth_uid_not_the_role(patched_op):

    patched_op.bind = _bind("postgresql", has_auth_uid=False)
    rls._is_supabase()
    sql = patched_op.bind.statements[-1]
    assert "auth" in sql and "uid" in sql
    assert "pg_proc" in sql





def _mutations(statements: list[str]) -> list[str]:

    return [s for s in statements if not s.strip().upper().startswith("SELECT")]


@pytest.mark.parametrize(
    "dialect,has_auth_uid",
    [("sqlite", False), ("postgresql", False)],
)
def test_upgrade_is_a_noop_off_supabase(patched_op, dialect, has_auth_uid):
    patched_op.bind = _bind(dialect, has_auth_uid)
    rls.upgrade()
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





def test_org_less_rows_are_not_widened_to_every_authenticated_user():

    assert "IS NULL OR" not in rls._ORG_RULE
    assert "organization_id IS NOT NULL" in rls._ORG_RULE


@pytest.mark.parametrize("rule", [rls._ORG_RULE, rls._EMAIL_RULE, rls._USER_RULE])
def test_every_rule_fails_closed_for_a_service_role_connection(rule):

    assert "auth.uid() IS NOT NULL" in rule
    assert "USING (" in rule and "WITH CHECK (" in rule

















_UNCAST_UID = re.compile(r"auth\.uid\(\)(?!::text)")


def _non_null_comparisons(rule: str) -> str:

    return re.sub(r"auth\.uid\(\)\s+IS\s+(NOT\s+)?NULL", "", rule)


@pytest.mark.parametrize(
    "rule_name", ["_ORG_RULE", "_EMAIL_RULE", "_USER_RULE"]
)
def test_no_uuid_is_compared_against_a_varchar_column(rule_name):

    rule = getattr(rls, rule_name)
    bare = _UNCAST_UID.findall(_non_null_comparisons(rule))
    assert bare == [], (
        f"{rule_name} compares auth.uid() (uuid) to a varchar column without a "
        f"::text cast; Postgres has no varchar = uuid operator, so CREATE POLICY "
        f"fails and the app cannot boot"
    )


def test_identifier_columns_are_varchar_so_the_cast_is_required():

    models = (MIGRATION.parents[2] / "app" / "models.py").read_text()
    for column in ("id", "organization_id", "user_id"):
        assert f"{column}: Mapped[str" in models or f"{column}: Mapped[str |" in models, (
            f"expected {column} to be a str-backed column in models.py"
        )
    assert "String(36)" in models














@pytest.fixture
def supabase_bind():

    url = os.environ.get("RLS_TEST_DATABASE_URL")
    if not url:
        pytest.skip("set RLS_TEST_DATABASE_URL to a Supabase-like PostgreSQL")

    from app.database import Base
    import app.models

    engine = sa.create_engine(url)
    try:



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



    _UID_FN = (
        "CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid "
        "LANGUAGE sql STABLE AS $$ "
        "SELECT NULLIF(current_setting('soc.test_uid', true), '')::uuid $$"
    )

    def __init__(self, conn):
        self._conn = conn
        conn.exec_driver_sql(self._UID_FN)


    def as_user(self, uid: str | None):

        return _ActingAs(self._conn, uid)


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

    return [
        f"{t}_tenant_isolation"
        if t in rls._ORG_TABLES + rls._EMAIL_TABLES
        else f"{t}_user_isolation"
        for t in rls.TABLES
    ]


def _reset_policies(bind) -> None:

    for table, policy in zip(rls.TABLES, _policy_names()):
        bind.exec_driver_sql(f'DROP POLICY IF EXISTS "{policy}" ON "{table}"')


def test_policies_are_created_for_real(supabase_bind, monkeypatch):

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

    monkeypatch.setattr(rls, "op", types.SimpleNamespace(
        get_bind=lambda: supabase_bind,
        execute=lambda sql: supabase_bind.exec_driver_sql(sql),
    ))
    _reset_policies(supabase_bind)
    rls.upgrade()



    with supabase_bind.as_user(None) as conn:
        assert conn.execute(sa.text("SELECT id FROM email_records")).fetchall() == []

def _insert(bind, table: str, values: dict) -> None:

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



UID_ALICE = "00000000-0000-0000-0000-0000000000a1"
UID_BOB   = "00000000-0000-0000-0000-0000000000b2"
UID_LONE  = "00000000-0000-0000-0000-0000000000c3"
UID_ADMIN = "00000000-0000-0000-0000-0000000000d4"
ORG_A     = "00000000-0000-0000-0000-0000000000a0"
ORG_B     = "00000000-0000-0000-0000-0000000000b0"
MAIL_A    = "00000000-0000-0000-0000-000000000e0a"
MAIL_B    = "00000000-0000-0000-0000-000000000e0b"
MAIL_LONE = "00000000-0000-0000-0000-000000000e0c"


def _seed_tenancy(bind) -> None:

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



_CURRENT_UID = [None]


@pytest.fixture
def tenancy(supabase_bind, monkeypatch):

    monkeypatch.setattr(rls, "op", types.SimpleNamespace(
        get_bind=lambda: supabase_bind,
        execute=lambda sql: supabase_bind.exec_driver_sql(sql),
    ))
    _reset_policies(supabase_bind)
    rls.upgrade()



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

    _CURRENT_UID[0] = UID_BOB
    assert _visible_ids(tenancy) == {MAIL_B}


def test_org_less_rows_are_not_widened_to_every_authenticated_user(tenancy):

    _CURRENT_UID[0] = UID_LONE
    assert MAIL_LONE not in _visible_ids(tenancy)


def test_an_admin_sees_across_tenants(tenancy):

    _CURRENT_UID[0] = UID_ADMIN
    assert _visible_ids(tenancy) == {MAIL_A, MAIL_B, MAIL_LONE}, (
        "an Admin must see across tenants and must see org-less rows; that is "
        "the deliberate cross-tenant role the application also grants"
    )




















VERSIONS_DIR = MIGRATION.parent

_CREATE_TABLE = re.compile(r"""op\.create_table\(\s*['"](?P<table>[A-Za-z0-9_]+)['"]""")
_ADD_COLUMN = re.compile(
    r"""op\.add_column\(\s*['\"](?P<table>[A-Za-z0-9_]+)['\"]\s*,\s*"""
    r"""sa\.Column\(\s*['\"](?P<column>[A-Za-z0-9_]+)['\"]"""
)
_SA_COLUMN = re.compile(r"""sa\.Column\(\s*['\"](?P<column>[A-Za-z0-9_]+)['\"]""")
_OP_CALL = re.compile(r"^\s*op\.[a-z_]+\(")



_BATCH_TABLE = re.compile(r"""batch_alter_table\(\s*['\"](?P<table>[A-Za-z0-9_]+)['\"]""")
_BATCH_ADD = re.compile(
    r"""batch\.add_column\(\s*sa\.Column\(\s*['\"](?P<column>[A-Za-z0-9_]+)['\"]"""
)



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

    created: dict[str, set[str]] = {}
    for path in sorted(VERSIONS_DIR.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        current: str | None = None
        batch_table: str | None = None
        for line in source.splitlines():




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
                    current = None
                    continue
                col = _SA_COLUMN.search(line)
                if col:
                    created[current].add(col.group("column"))
        for match in _ADD_COLUMN.finditer(source):
            created.setdefault(match.group("table"), set()).add(match.group("column"))
    return created


def _orm_columns() -> dict[str, set[str]]:
    from app import models
    from app.database import Base

    return {t.name: {c.name for c in t.columns} for t in Base.metadata.tables.values()}


@pytest.mark.parametrize(
    "table,column",
    [(t, c) for t, cols in _VAULT_COLUMNS.items() for c in cols],
)
def test_vault_column_is_created_by_the_migration_chain(table: str, column: str) -> None:

    assert column in _created_columns().get(table, set()), (
        f"{table}.{column} is declared in app/models.py and read by "
        f"app/routers/gmail.py and app/services/mailbox_poll.py, but no Alembic "
        f"revision creates it — a database built from migrations will raise "
        f"UndefinedColumn on the first mailbox request"
    )


@pytest.mark.parametrize("table,index", sorted(_MISSING_INDEXES.items()))
def test_declared_index_is_created_by_the_migration_chain(table: str, index: str) -> None:

    source = "\n".join(p.read_text(encoding="utf-8") for p in sorted(VERSIONS_DIR.glob("*.py")))
    assert index in source, (
        f"{index} is declared via index=True in app/models.py but no revision "
        f"creates it; every {table} query filtering on that column degrades "
        f"to a sequential scan"
    )


def test_every_orm_column_exists_in_the_migration_chain() -> None:

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

    created = _created_columns()
    assert set(_orm_columns()) <= set(created), (
        f"tables in app/models.py with no create_table in any revision: "
        f"{sorted(set(_orm_columns()) - set(created))}"
    )


def test_case_status_check_constraint_is_created_by_the_migration_chain() -> None:

    source = "\n".join(p.read_text(encoding="utf-8") for p in sorted(VERSIONS_DIR.glob("*.py")))
    assert "ck_cases_status" in source, (
        "app/models.py:54 declares CheckConstraint(..., name='ck_cases_status') "
        "but no revision creates it, so investigation_cases.status is "
        "unconstrained on a migrated database"
    )


def test_the_drift_fix_covers_exactly_the_five_vault_columns() -> None:

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

    assert upgrade_body.count("server_default=sa.text") == 5, (
        "every NOT NULL add needs a server default so existing rows backfill; "
        "a bare ADD COLUMN NOT NULL fails as soon as the table has one row"
    )
    assert upgrade_body.count("server_default=None") == 5, (
        "every server default must be dropped afterwards, or the schema never "
        "matches Base.metadata and this drift check fails forever"
    )


    assert 'if op.get_bind().dialect.name != "sqlite":' in upgrade_body, (
        "the default drop must be dialect-guarded: SQLite has no ALTER TABLE "
        "... ALTER COLUMN and would raise NotImplementedError, breaking the "
        "fresh-SQLite migration test"
    )

















DRIFT_URL = os.environ.get("DRIFT_TEST_DATABASE_URL")


def _run_migrations(url: str, revision: str) -> None:

    import subprocess
    import sys

    root = pathlib.Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["DATABASE_URL"] = url
    env.pop("TEST_DATABASE_URL", None)
    env["PYTHONPATH"] = str(root)


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
    return DRIFT_URL


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
            mod.upgrade()
        finally:
            alembic_op._proxy = previous
    engine.dispose()
