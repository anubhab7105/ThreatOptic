"""add_rls_policies

Row Level Security policies for tenant isolation (defense-in-depth).
Application-level checks in _org_filter() remain the primary enforcement;
RLS provides a second layer at the database level.

Supabase requires RLS to be enabled per table, then policies created.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'c9e8f7a6b3d2'
down_revision: Union[str, None] = 'b7c2d1a9e4f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enable RLS on all tenant-scoped tables
    for table in [
        'email_records',
        'analysis_results',
        'traceability_data',
        'investigation_cases',
        'mailbox_connections',
        'gmail_accounts',
        'oauth_states',
    ]:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")

    # Policy: users can only see/modify their own org's data
    # Using current_setting('app.current_user_id') and current_setting('app.current_user_role')
    # which would be set by a PostgreSQL function or middleware.
    # For Supabase, we use auth.uid() and check against user table.

    # email_records: users can access rows where organization_id matches their org
    op.execute("""
        CREATE POLICY email_records_tenant_isolation ON email_records
        FOR ALL
        USING (
            organization_id IS NULL
            OR organization_id = (
                SELECT organization_id FROM users WHERE id = auth.uid()
            )
            OR (SELECT role FROM users WHERE id = auth.uid()) = 'Admin'
        )
    """)

    # analysis_results: cascade via email_records
    op.execute("""
        CREATE POLICY analysis_results_tenant_isolation ON analysis_results
        FOR ALL
        USING (
            email_id IN (
                SELECT id FROM email_records WHERE
                    organization_id IS NULL
                    OR organization_id = (
                        SELECT organization_id FROM users WHERE id = auth.uid()
                    )
                    OR (SELECT role FROM users WHERE id = auth.uid()) = 'Admin'
            )
        )
    """)

    # traceability_data: cascade via email_records
    op.execute("""
        CREATE POLICY traceability_data_tenant_isolation ON traceability_data
        FOR ALL
        USING (
            email_id IN (
                SELECT id FROM email_records WHERE
                    organization_id IS NULL
                    OR organization_id = (
                        SELECT organization_id FROM users WHERE id = auth.uid()
                    )
                    OR (SELECT role FROM users WHERE id = auth.uid()) = 'Admin'
            )
        )
    """)

    # investigation_cases: org-scoped
    op.execute("""
        CREATE POLICY investigation_cases_tenant_isolation ON investigation_cases
        FOR ALL
        USING (
            organization_id IS NULL
            OR organization_id = (
                SELECT organization_id FROM users WHERE id = auth.uid()
            )
            OR (SELECT role FROM users WHERE id = auth.uid()) = 'Admin'
        )
    """)

    # mailbox_connections: org-scoped
    op.execute("""
        CREATE POLICY mailbox_connections_tenant_isolation ON mailbox_connections
        FOR ALL
        USING (
            organization_id IS NULL
            OR organization_id = (
                SELECT organization_id FROM users WHERE id = auth.uid()
            )
            OR (SELECT role FROM users WHERE id = auth.uid()) = 'Admin'
        )
    """)

    # gmail_accounts: per-user (not org-scoped)
    op.execute("""
        CREATE POLICY gmail_accounts_user_isolation ON gmail_accounts
        FOR ALL
        USING (
            user_id = auth.uid()
            OR (SELECT role FROM users WHERE id = auth.uid()) = 'Admin'
        )
    """)

    # oauth_states: per-user
    op.execute("""
        CREATE POLICY oauth_states_user_isolation ON oauth_states
        FOR ALL
        USING (
            user_id = auth.uid()
            OR (SELECT role FROM users WHERE id = auth.uid()) = 'Admin'
        )
    """)


def downgrade() -> None:
    for table in [
        'email_records',
        'analysis_results',
        'traceability_data',
        'investigation_cases',
        'mailbox_connections',
        'gmail_accounts',
        'oauth_states',
    ]:
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_user_isolation ON {table}")