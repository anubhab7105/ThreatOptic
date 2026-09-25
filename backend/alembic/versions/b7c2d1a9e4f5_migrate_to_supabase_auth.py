"""migrate_to_supabase_auth

Supabase migration: local password auth is removed. Supabase owns
sign-up/sign-in/session refresh; public.users mirrors auth.users via the
on_auth_user_created trigger (see backend/supabase_handle_new_user.sql).

- Drops `refresh_tokens` table (Supabase manages sessions)
- users: drops `username`, drops `password_hash`, adds unique `email`

Revision ID: b7c2d1a9e4f5
Revises: 834dc871451e
Create Date: 2026-09-25
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b7c2d1a9e4f5'
down_revision: Union[str, None] = '834dc871451e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Drop the server-side refresh-token ledger (Supabase manages sessions).
    op.drop_index(op.f('ix_refresh_tokens_token_hash'), table_name='refresh_tokens')
    op.drop_index(op.f('ix_refresh_tokens_user_id'), table_name='refresh_tokens')
    op.drop_table('refresh_tokens')

    # 2. users.username -> users.email (backfill from username where possible).
    # batch_alter_table keeps this working on SQLite (dev/test) as well as
    # Postgres (Supabase), where plain ALTER COLUMN ... SET NOT NULL is used.
    with op.batch_alter_table('users') as batch:
        batch.add_column(sa.Column('email', sa.String(length=320), nullable=True))
    op.execute(sa.text("UPDATE users SET email = username WHERE email IS NULL"))
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    with op.batch_alter_table('users') as batch:
        batch.alter_column('email', existing_type=sa.String(length=320), nullable=False)
        batch.drop_column('password_hash')
        batch.drop_column('username')


def downgrade() -> None:
    with op.batch_alter_table('users') as batch:
        batch.add_column(sa.Column('username', sa.String(length=255), nullable=True))
    op.execute(sa.text("UPDATE users SET username = email WHERE username IS NULL"))
    with op.batch_alter_table('users') as batch:
        batch.alter_column('username', existing_type=sa.String(length=255), nullable=False)
        batch.add_column(sa.Column('password_hash', sa.String(length=255), nullable=True))
    op.drop_index(op.f('ix_users_email'), table_name='users')
    with op.batch_alter_table('users') as batch:
        batch.drop_column('email')
    op.create_table('refresh_tokens',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('revoked', sa.Boolean(), nullable=False),
        sa.Column('replaced_by', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_refresh_tokens_user_id'), 'refresh_tokens', ['user_id'], unique=False)
    op.create_index(op.f('ix_refresh_tokens_token_hash'), 'refresh_tokens', ['token_hash'], unique=True)
