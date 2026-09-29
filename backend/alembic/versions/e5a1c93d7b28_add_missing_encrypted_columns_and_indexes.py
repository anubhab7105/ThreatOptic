
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "e5a1c93d7b28"
down_revision: Union[str, None] = "c9e8f7a6b3d2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None



_VAULT_COLUMNS: tuple[tuple[str, str], ...] = (
    ("gmail_accounts", "encrypted_client_id"),
    ("gmail_accounts", "encrypted_client_secret"),
    ("mailbox_connections", "encrypted_client_id"),
    ("mailbox_connections", "encrypted_client_secret"),
    ("oauth_states", "encrypted_client_secret"),
)



_MISSING_INDEXES: tuple[tuple[str, str, list[str]], ...] = (
    ("ix_users_organization_id", "users", ["organization_id"]),
    ("ix_email_records_timestamp", "email_records", ["timestamp"]),
    ("ix_mailbox_connections_organization_id", "mailbox_connections", ["organization_id"]),
)





_CHECK_NAME = "ck_cases_status"
_CHECK_SQL = "status IN ('Open', 'InProgress', 'Closed')"


def _inspector() -> sa.Inspector:
    return sa.inspect(op.get_bind())


def _table_exists(inspector: sa.Inspector, table: str) -> bool:
    return table in inspector.get_table_names()


def _columns(inspector: sa.Inspector, table: str) -> set[str]:
    if not _table_exists(inspector, table):
        return set()
    return {c["name"] for c in inspector.get_columns(table)}


def _indexes(inspector: sa.Inspector, table: str) -> set[str]:
    if not _table_exists(inspector, table):
        return set()
    return {ix["name"] for ix in inspector.get_indexes(table) if ix.get("name")}


def upgrade() -> None:













    if "encrypted_client_id" not in _columns(_inspector(), "gmail_accounts"):
        op.add_column(
            "gmail_accounts",
            sa.Column(
                "encrypted_client_id", sa.Text(), nullable=False, server_default=sa.text("''")
            ),
        )
    if "encrypted_client_secret" not in _columns(_inspector(), "gmail_accounts"):
        op.add_column(
            "gmail_accounts",
            sa.Column(
                "encrypted_client_secret", sa.Text(), nullable=False, server_default=sa.text("''")
            ),
        )
    if "encrypted_client_id" not in _columns(_inspector(), "mailbox_connections"):
        op.add_column(
            "mailbox_connections",
            sa.Column(
                "encrypted_client_id", sa.Text(), nullable=False, server_default=sa.text("''")
            ),
        )
    if "encrypted_client_secret" not in _columns(_inspector(), "mailbox_connections"):
        op.add_column(
            "mailbox_connections",
            sa.Column(
                "encrypted_client_secret", sa.Text(), nullable=False, server_default=sa.text("''")
            ),
        )
    if "encrypted_client_secret" not in _columns(_inspector(), "oauth_states"):
        op.add_column(
            "oauth_states",
            sa.Column(
                "encrypted_client_secret", sa.Text(), nullable=False, server_default=sa.text("''")
            ),
        )





    if op.get_bind().dialect.name != "sqlite":
        op.alter_column(
            "gmail_accounts", "encrypted_client_id", server_default=None, existing_type=sa.Text()
        )
        op.alter_column(
            "gmail_accounts", "encrypted_client_secret", server_default=None, existing_type=sa.Text()
        )
        op.alter_column(
            "mailbox_connections", "encrypted_client_id", server_default=None, existing_type=sa.Text()
        )
        op.alter_column(
            "mailbox_connections",
            "encrypted_client_secret",
            server_default=None,
            existing_type=sa.Text(),
        )
        op.alter_column(
            "oauth_states", "encrypted_client_secret", server_default=None, existing_type=sa.Text()
        )

    for name, table, columns in _MISSING_INDEXES:
        if name in _indexes(_inspector(), table):
            continue
        op.create_index(op.f(name), table, columns, unique=False)




    if op.get_bind().dialect.name == "postgresql":
        existing = {
            c.get("name")
            for c in _inspector().get_check_constraints("investigation_cases")
        }
        if _CHECK_NAME not in existing:
            op.create_check_constraint(
                _CHECK_NAME, "investigation_cases", sa.text(_CHECK_SQL)
            )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.drop_constraint(_CHECK_NAME, "investigation_cases", type_="check")
    for name, table, _columns_list in reversed(_MISSING_INDEXES):
        op.drop_index(op.f(name), table_name=table)
    for table, column in reversed(_VAULT_COLUMNS):
        op.drop_column(table, column)
