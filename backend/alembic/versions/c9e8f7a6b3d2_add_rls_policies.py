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
"""
from typing import Sequence, Union

from alembic import op

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
                SELECT organization_id FROM users WHERE id = auth.uid()
            )
            OR (SELECT role FROM users WHERE id = auth.uid()) = 'Admin'
        )
    )
    WITH CHECK (
        auth.uid() IS NOT NULL
        AND (
            organization_id IS NOT NULL
            AND organization_id = (
                SELECT organization_id FROM users WHERE id = auth.uid()
            )
            OR (SELECT role FROM users WHERE id = auth.uid()) = 'Admin'
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
                  SELECT organization_id FROM users WHERE id = auth.uid()
              )
              OR (SELECT role FROM users WHERE id = auth.uid()) = 'Admin'
        )
    )
    WITH CHECK (
        auth.uid() IS NOT NULL
        AND email_id IN (
            SELECT id FROM email_records
            WHERE organization_id IS NOT NULL
              AND organization_id = (
                  SELECT organization_id FROM users WHERE id = auth.uid()
              )
              OR (SELECT role FROM users WHERE id = auth.uid()) = 'Admin'
        )
    )
"""

# Per-user tables have no organization_id.
_USER_RULE = """
    USING (
        auth.uid() IS NOT NULL
        AND (
            user_id = auth.uid()
            OR (SELECT role FROM users WHERE id = auth.uid()) = 'Admin'
        )
    )
    WITH CHECK (
        auth.uid() IS NOT NULL
        AND (
            user_id = auth.uid()
            OR (SELECT role FROM users WHERE id = auth.uid()) = 'Admin'
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


def upgrade() -> None:
    if not _is_postgres():
        # SQLite (local dev / CI) has no RLS; the application-layer tenant
        # checks are the enforcement there.
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
    if not _is_postgres():
        return
    for table in TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_user_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
