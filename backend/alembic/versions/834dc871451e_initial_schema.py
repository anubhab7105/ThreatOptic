
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '834dc871451e'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:

    op.create_table('organizations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('compliance_policy', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('email_records',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('message_id', sa.String(length=1024), nullable=False),
    sa.Column('sender_address', sa.String(length=512), nullable=False),
    sa.Column('recipient_address', sa.String(length=512), nullable=False),
    sa.Column('subject', sa.Text(), nullable=False),
    sa.Column('raw_headers', sa.JSON(), nullable=False),
    sa.Column('body_text', sa.Text(), nullable=False),
    sa.Column('body_text_masked', sa.Text(), nullable=False),
    sa.Column('attachments_metadata', sa.JSON(), nullable=False),
    sa.Column('raw_eml_hash', sa.String(length=64), nullable=False),
    sa.Column('organization_id', sa.String(length=36), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('raw_eml_hash', 'organization_id', name='uq_email_hash_org')
    )
    op.create_index(op.f('ix_email_records_organization_id'), 'email_records', ['organization_id'], unique=False)
    op.create_index(op.f('ix_email_records_sender_address'), 'email_records', ['sender_address'], unique=False)
    op.create_table('users',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('username', sa.String(length=255), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=32), nullable=False),
    sa.Column('organization_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('analysis_results',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('email_id', sa.String(length=36), nullable=False),
    sa.Column('fraud_score', sa.Float(), nullable=False),
    sa.Column('threat_classification', sa.String(length=64), nullable=False),
    sa.Column('nlp_cues_detected', sa.JSON(), nullable=False),
    sa.Column('authentication_results', sa.JSON(), nullable=False),
    sa.Column('trace_summary', sa.JSON(), nullable=False),
    sa.Column('threat_intel_hits', sa.JSON(), nullable=False),
    sa.Column('action_taken', sa.String(length=64), nullable=False),
    sa.Column('score_breakdown', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['email_id'], ['email_records.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_analysis_results_email_id'), 'analysis_results', ['email_id'], unique=False)
    op.create_index(op.f('ix_analysis_results_fraud_score'), 'analysis_results', ['fraud_score'], unique=False)
    op.create_table('gmail_accounts',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=False),
    sa.Column('gmail_address', sa.String(length=320), nullable=False),
    sa.Column('refresh_token', sa.Text(), nullable=False),
    sa.Column('client_id', sa.String(length=320), nullable=False),
    sa.Column('last_sync_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_gmail_accounts_user_id'), 'gmail_accounts', ['user_id'], unique=True)
    op.create_table('investigation_cases',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('title', sa.String(length=512), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('assignee_id', sa.String(length=36), nullable=True),
    sa.Column('organization_id', sa.String(length=36), nullable=True),
    sa.Column('email_ids', sa.JSON(), nullable=False),
    sa.Column('notes', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['assignee_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_investigation_cases_organization_id'), 'investigation_cases', ['organization_id'], unique=False)
    op.create_table('mailbox_connections',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=False),
    sa.Column('organization_id', sa.String(length=36), nullable=True),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('account_email', sa.String(length=320), nullable=False),
    sa.Column('encrypted_refresh_token', sa.Text(), nullable=False),
    sa.Column('last_poll_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('provider', 'account_email', name='uq_mailbox_provider_email')
    )
    op.create_index(op.f('ix_mailbox_connections_user_id'), 'mailbox_connections', ['user_id'], unique=False)
    op.create_table('oauth_states',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('state', sa.String(length=128), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=False),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('redirect_uri', sa.String(length=1024), nullable=False),
    sa.Column('client_id', sa.String(length=320), nullable=False),
    sa.Column('code_verifier', sa.String(length=256), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('used', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_oauth_states_state'), 'oauth_states', ['state'], unique=True)
    op.create_index(op.f('ix_oauth_states_user_id'), 'oauth_states', ['user_id'], unique=False)
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
    op.create_index(op.f('ix_refresh_tokens_token_hash'), 'refresh_tokens', ['token_hash'], unique=True)
    op.create_index(op.f('ix_refresh_tokens_user_id'), 'refresh_tokens', ['user_id'], unique=False)
    op.create_table('traceability_data',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('email_id', sa.String(length=36), nullable=False),
    sa.Column('origin_ip', sa.String(length=64), nullable=False),
    sa.Column('relay_chain', sa.JSON(), nullable=False),
    sa.Column('geolocation', sa.JSON(), nullable=False),
    sa.Column('isp_asn', sa.String(length=255), nullable=False),
    sa.Column('is_vpn_tor', sa.Boolean(), nullable=False),
    sa.Column('whois_data', sa.JSON(), nullable=False),
    sa.Column('dns_data', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['email_id'], ['email_records.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_traceability_data_email_id'), 'traceability_data', ['email_id'], unique=False)



def downgrade() -> None:

    op.drop_index(op.f('ix_traceability_data_email_id'), table_name='traceability_data')
    op.drop_table('traceability_data')
    op.drop_index(op.f('ix_refresh_tokens_user_id'), table_name='refresh_tokens')
    op.drop_index(op.f('ix_refresh_tokens_token_hash'), table_name='refresh_tokens')
    op.drop_table('refresh_tokens')
    op.drop_index(op.f('ix_oauth_states_user_id'), table_name='oauth_states')
    op.drop_index(op.f('ix_oauth_states_state'), table_name='oauth_states')
    op.drop_table('oauth_states')
    op.drop_index(op.f('ix_mailbox_connections_user_id'), table_name='mailbox_connections')
    op.drop_table('mailbox_connections')
    op.drop_index(op.f('ix_investigation_cases_organization_id'), table_name='investigation_cases')
    op.drop_table('investigation_cases')
    op.drop_index(op.f('ix_gmail_accounts_user_id'), table_name='gmail_accounts')
    op.drop_table('gmail_accounts')
    op.drop_index(op.f('ix_analysis_results_fraud_score'), table_name='analysis_results')
    op.drop_index(op.f('ix_analysis_results_email_id'), table_name='analysis_results')
    op.drop_table('analysis_results')
    op.drop_table('users')
    op.drop_index(op.f('ix_email_records_sender_address'), table_name='email_records')
    op.drop_index(op.f('ix_email_records_organization_id'), table_name='email_records')
    op.drop_table('email_records')
    op.drop_table('organizations')
