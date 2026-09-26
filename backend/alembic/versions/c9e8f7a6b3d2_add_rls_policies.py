"""add_rls_policies

Row Level Security policies for tenant isolation (defense-in-depth).

IMPORTANT — what this migration does and does not buy you
---------------------------------------------------------
Application-level tenant checks (`_org_filter` / `_scope` in the routers)
remain the ONLY enforced isolation for the backend's own connection: the
app authenticates to Postgres with a single service connection string, not
as a per-user Postgres role, so `auth.uid()` is NULL for every query it
issues. A table owner also bypasses RLS by default.

So these policies are inert unless queries run under a Postgres role that
carries a Supabase JWT (`TO authenticated`). They are kept because they
become real enforcement the moment that is true, and because they fail
*closed* (zero rows) rather than open in the meantime. Do not treat them
as a substitute for the application-layer checks.

Two correctness rules this revision must keep:
1. Dialect-guarded. `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` is
   PostgreSQL-only; without the guard a SQLite dev/CI database fails the
   whole upgrade chain with a syntax error.
2. Never wider than the application. The application treats
   `organization_id IS NULL` as *private org-less scope* visible only to
   the owning user; a policy that says `organization_id IS NULL OR ...`
   would hand every authenticated user all org-less rows — strictly
   wider than the app allows. Org-less rows are therefore Admin-only here.

A third, added after this revision broke a plain-Postgres dev setup: being
PostgreSQL is not sufficient. Every policy here is written against Supabase's
`auth.uid()` and granted `TO authenticated` — a role that exists only inside a
Supabase project. On any other Postgres server the statement fails outright
with `role "authenticated" does not exist`, which aborts the upgrade chain and
takes the whole application down at boot. Since the policies are inert without
those constructs anyway (see above), skipping them off-Supabase loses nothing
and is strictly better than an unbootable database.

A fourth, added when the same revision turned out to be broken on Supabase
itself: every `auth.uid()` comparison below is cast with `::text`. The
application stores identifiers as `String(36)` — `users.id`, `organization_id`,
`user_id` are all `varchar` — while `auth.uid()` returns `uuid`. Postgres has
no `varchar = uuid` operator, so the uncast form died at CREATE POLICY with

    UndefinedFunction: operator does not exist: character varying = uuid

which is just as fatal as the missing role: init_db() turns a failed upgrade
into a hard boot failure. Cast the function, never the column — `uuid::text`
cannot fail, whereas `users.id::uuid` would raise on any row whose id is not a
well-formed UUID. Do not remove these casts; they are load-bearing.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "c9e8f7a6b3d2"
down_revision: Union[str, None] = "b7c2d1a9e4f5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLES = [
    "email_records",
    "analysis_results",
    "traceability_data",
    "investigation_cases",
    "mailbox_connections",
    "gmail_accounts",
    "oauth_states",
]

# Same visibility rule as the application, minus the org-less clause:
# same org, or Admin. `auth.uid() IS NOT NULL` keeps a NULL uid
# (service-role / unauthenticated connection) from matching anything.
_ORG_RULE = """
    USING (
        auth.uid() IS NOT NULL
        AND (
            organization_id IS NOT NULL
            AND organization_id = (
                SELECT organization_id FROM users WHERE id = auth.uid()::text
            )
            OR (SELECT role FROM users WHERE id = auth.uid()::text) = 'Admin'
        )
    )
    WITH CHECK (
        auth.uid() IS NOT NULL
        AND (
            organization_id IS NOT NULL
            AND organization_id = (
                SELECT organization_id FROM users WHERE id = auth.uid()::text
            )
            OR (SELECT role FROM users WHERE id = auth.uid()::text) = 'Admin'
        )
    )
"""

# Child tables inherit visibility from their parent email row.
_EMAIL_RULE = """
    USING (
        auth.uid() IS NOT NULL
        AND email_id IN (
            SELECT id FROM email_records
            WHERE organization_id IS NOT NULL
              AND organization_id = (
                  SELECT organization_id FROM users WHERE id = auth.uid()::text
              )
              OR (SELECT role FROM users WHERE id = auth.uid()::text) = 'Admin'
        )
    )
    WITH CHECK (
        auth.uid() IS NOT NULL
        AND email_id IN (
            SELECT id FROM email_records
            WHERE organization_id IS NOT NULL
              AND organization_id = (
                  SELECT organization_id FROM users WHERE id = auth.uid()::text
              )
              OR (SELECT role FROM users WHERE id = auth.uid()::text) = 'Admin'
        )
    )
"""

# Per-user tables have no organization_id.
_USER_RULE = """
    USING (
        auth.uid() IS NOT NULL
        AND (
            user_id = auth.uid()::text
            OR (SELECT role FROM users WHERE id = auth.uid()::text) = 'Admin'
        )
    )
    WITH CHECK (
        auth.uid() IS NOT NULL
        AND (
            user_id = auth.uid()::text
            OR (SELECT role FROM users WHERE id = auth.uid()::text) = 'Admin'
        )
    )
"""

_ORG_TABLES = (
    "email_records",
    "investigation_cases",
    "mailbox_connections",
)
_EMAIL_TABLES = ("analysis_results", "traceability_data")
_USER_TABLES = ("gmail_accounts", "oauth_states")


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _is_supabase() -> bool:
    """True only on a Supabase-managed Postgres.

    The policies reference `auth.uid()` and are granted to the `authenticated`
    role. Both are installed by Supabase, not by PostgreSQL. Probe for the
    function rather than the role so a project that renamed or dropped the role
    is treated as non-Supabase too — the policies could not be created there.
    """
    return bool(
        op.get_bind().execute(
            sa.text(
                "SELECT EXISTS ("
                "  SELECT 1 FROM pg_proc p"
                "  JOIN pg_namespace n ON n.oid = p.pronamespace"
                "  WHERE n.nspname = 'auth' AND p.proname = 'uid'"
                ")"
            )
        ).scalar()
    )


def _should_apply() -> bool:
    # SQLite (CI / pytest) has no RLS; plain Postgres (a local dev server, or
    # any non-Supabase managed instance) has no auth.uid() and no
    # `authenticated` role. In both cases the application-layer tenant checks
    # are the enforcement, exactly as on Supabase.
    return _is_postgres() and _is_supabase()


def upgrade() -> None:
    if not _should_apply():
        return
    for table in TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    for table in _ORG_TABLES:
        op.execute(
            f"CREATE POLICY {table}_tenant_isolation ON {table} "
            f"FOR ALL TO authenticated {_ORG_RULE}"
        )
    for table in _EMAIL_TABLES:
        op.execute(
            f"CREATE POLICY {table}_tenant_isolation ON {table} "
            f"FOR ALL TO authenticated {_EMAIL_RULE}"
        )
    for table in _USER_TABLES:
        op.execute(
            f"CREATE POLICY {table}_user_isolation ON {table} "
            f"FOR ALL TO authenticated {_USER_RULE}"
        )


def downgrade() -> None:
    if not _should_apply():
        return
    for table in TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_user_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
