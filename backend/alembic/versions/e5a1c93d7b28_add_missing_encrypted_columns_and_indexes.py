"""add_missing_encrypted_columns_and_indexes

Closes a models-vs-migrations drift that made a fresh deploy impossible.

The initial revision `834dc871451e` was written before the OAuth/mailbox vault
work landed, and was never updated to match. Five columns the ORM reads on
every request existed in `app/models.py` but in no revision:

    gmail_accounts.encrypted_client_id / .encrypted_client_secret
    mailbox_connections.encrypted_client_id / .encrypted_client_secret
    oauth_states.encrypted_client_secret

`app/routers/gmail.py` selects these columns directly (and
`app/services/mailbox_poll.py` decrypts them), so on any database built purely
from migrations the Gmail/mailbox/OAuth-callback paths fail at query time with
`UndefinedColumn`. A fresh Postgres deploy therefore produced an application
that booted, served /health, and then 500'd on every mailbox operation. Three
indexes the ORM relies on were missing for the same reason, and so was the
`ck_cases_status` CHECK constraint limiting `investigation_cases.status` to a
fixed enum — that one is invisible to Alembic's autogenerate, which does not
emit CHECK-constraint diffs, so it has to be added by hand.

Two details this revision must keep:

1. Every add is inspector-guarded. Production was created from migrations
   before these columns existed, and a column may have been added out of band
   since; an unconditional `ADD COLUMN` would abort the upgrade chain with
   `column "..." already exists`. `init_db()` turns a failed upgrade into a
   hard boot failure, so an idempotent add is strictly safer than a bare one.
   This is also what lets the drift test below re-run the upgrade chain.

2. NOT NULL columns are added with a server default, then the default is
   dropped. The ORM declares these as `nullable=False` with a Python-side
   default of `""`. A bare `ADD COLUMN ... NOT NULL` fails on Postgres as soon
   as the target table holds a single row, so the default is what backfills
   existing rows to ''. Dropping it afterwards leaves a schema identical to
   `Base.metadata` — which is the point: a lingering server default would make
   the drift check in `tests/test_migrations.py` fail forever.

Deliberately NOT in this revision, to keep one finding per commit:
  * `timestamp` -> `timestamptz` on every column (the naive-DateTime finding).
  * `uq_email_hash_org` becoming a partial unique index rather than a table
    constraint (the nullable-org uniqueness finding).
Both are already correct in the ORM; the drift test reports them, and each gets
its own revision.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "e5a1c93d7b28"
down_revision: Union[str, None] = "c9e8f7a6b3d2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (table, column) pairs the ORM declares but no revision has ever created.
_VAULT_COLUMNS: tuple[tuple[str, str], ...] = (
    ("gmail_accounts", "encrypted_client_id"),
    ("gmail_accounts", "encrypted_client_secret"),
    ("mailbox_connections", "encrypted_client_id"),
    ("mailbox_connections", "encrypted_client_secret"),
    ("oauth_states", "encrypted_client_secret"),
)

# (index name, table, columns) the ORM declares via index=True but no revision
# has ever created.
_MISSING_INDEXES: tuple[tuple[str, str, list[str]], ...] = (
    ("ix_users_organization_id", "users", ["organization_id"]),
    ("ix_email_records_timestamp", "email_records", ["timestamp"]),
    ("ix_mailbox_connections_organization_id", "mailbox_connections", ["organization_id"]),
)

# app/models.py:54 constrains investigation_cases.status to a fixed enum, but
# the initial revision never created the constraint, so a database built from
# migrations accepts any status string. Alembic's autogenerate does not emit
# CHECK-constraint diffs, so this gap is invisible to the usual drift check.
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
    # These five are the finding, so they are spelled out one call per column
    # rather than looped over a table of pairs: the models-vs-migrations drift
    # check in tests/test_migrations.py reads these sources, and a call built
    # from unquoted loop variables is invisible to it. Five explicit calls stay
    # honest about what they create.
    #
    # Each add needs three things, repeated deliberately rather than factored
    # into a helper for the reason above:
    #   * an inspector guard, because production predates these columns and one
    #     may have been added out of band, which would abort the chain;
    #   * a server default, because `ADD COLUMN ... NOT NULL` fails on Postgres
    #     as soon as the table holds one row. The default is what backfills
    #     existing rows to ''; it is dropped again below.
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

    # Drop the backfill default so the schema matches Base.metadata exactly.
    # SQLite has no `ALTER TABLE ... ALTER COLUMN`, so the default is left in
    # place there; that is harmless, because the SQLite path is dev/test only
    # and builds its schema from Base.metadata rather than from this chain.
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

    # PostgreSQL-only, like the RLS revision: SQLite has no
    # `ALTER TABLE ... ADD CONSTRAINT`, and the SQLite test path builds the
    # schema from Base.metadata, so it already carries the constraint.
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
