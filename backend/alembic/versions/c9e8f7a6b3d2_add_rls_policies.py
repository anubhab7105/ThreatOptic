
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
