"""DB models — mirrors Shema.md (Postgres relational + document tables in SQL for dev).

Relational: User, Organization, InvestigationCase
Document (stored in SQL for local dev, mirrored to Elastic when configured):
  EmailRecord, AnalysisResult, TraceabilityData
Graph entities are in Neo4j / networkx, not here.
"""
import uuid
from datetime import datetime
from sqlalchemy import CheckConstraint, Index, String, Text, Float, Boolean, DateTime, ForeignKey, JSON, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base, utcnow

# Timezone-aware timestamps everywhere (P1): TIMESTAMPTZ on Postgres,
# ISO8601 on SQLite (offset stripped on store, as_utc() on read).
TZDateTime = DateTime(timezone=True)


def _uuid() -> str:
    return str(uuid.uuid4())


USER_ROLES = ("Admin", "Analyst", "ReadOnly")
CASE_STATUSES = ("Open", "InProgress", "Closed")


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    compliance_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    users: Mapped[list["User"]] = relationship(back_populates="organization")


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="Analyst")  # Admin, Analyst, ReadOnly
    organization_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    organization: Mapped[Organization | None] = relationship(back_populates="users")


class RefreshToken(Base):
    """Server-side refresh-token ledger for rotation + reuse detection (C1).

    Only the SHA-256 fingerprint of each token is stored — never the token.
    A row is single-use: rotation marks it revoked and links the replacement.
    Re-presenting a revoked token signals theft: the whole family is revoked.
    """
    __tablename__ = "refresh_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    replaced_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class InvestigationCase(Base):
    __tablename__ = "investigation_cases"
    __table_args__ = (
        CheckConstraint("status IN ('Open', 'InProgress', 'Closed')", name="ck_cases_status"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="Open")  # Open, InProgress, Closed
    assignee_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    organization_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=True, index=True)
    email_ids: Mapped[list] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, onupdate=utcnow)


class EmailRecord(Base):
    __tablename__ = "email_records"
    __table_args__ = (
        # Partial unique index (P1): enforced only for real tenants; NULL-org
        # rows dedup via the app's IS NULL query (NULLs never compare equal).
        Index("uq_email_hash_org", "raw_eml_hash", "organization_id", unique=True,
              postgresql_where=text("organization_id IS NOT NULL"),
              sqlite_where=text("organization_id IS NOT NULL")),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    message_id: Mapped[str] = mapped_column(String(1024), default="")
    sender_address: Mapped[str] = mapped_column(String(512), default="", index=True)
    recipient_address: Mapped[str] = mapped_column(String(512), default="")
    subject: Mapped[str] = mapped_column(Text, default="")
    raw_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    body_text: Mapped[str] = mapped_column(Text, default="")
    body_text_masked: Mapped[str] = mapped_column(Text, default="")
    attachments_metadata: Mapped[list] = mapped_column(JSON, default=list)
    raw_eml_hash: Mapped[str] = mapped_column(String(64), default="")
    organization_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, index=True)


class AnalysisResult(Base):
    __tablename__ = "analysis_results"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email_id: Mapped[str] = mapped_column(String(36), ForeignKey("email_records.id", ondelete="CASCADE"), nullable=False, index=True)
    fraud_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    threat_classification: Mapped[str] = mapped_column(String(64), default="Clean")
    nlp_cues_detected: Mapped[list] = mapped_column(JSON, default=list)
    authentication_results: Mapped[dict] = mapped_column(JSON, default=dict)
    trace_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    threat_intel_hits: Mapped[list] = mapped_column(JSON, default=list)
    action_taken: Mapped[str] = mapped_column(String(64), default="Deliver")
    score_breakdown: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class TraceabilityData(Base):
    __tablename__ = "traceability_data"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email_id: Mapped[str] = mapped_column(String(36), ForeignKey("email_records.id", ondelete="CASCADE"), nullable=False, index=True)
    origin_ip: Mapped[str] = mapped_column(String(64), default="")
    relay_chain: Mapped[list] = mapped_column(JSON, default=list)
    geolocation: Mapped[dict] = mapped_column(JSON, default=dict)
    isp_asn: Mapped[str] = mapped_column(String(255), default="")
    is_vpn_tor: Mapped[bool] = mapped_column(Boolean, default=False)
    whois_data: Mapped[dict] = mapped_column(JSON, default=dict)
    dns_data: Mapped[dict] = mapped_column(JSON, default=dict)


class GmailAccount(Base):
    """One connected Gmail mailbox per user (OAuth2 refresh token vault)."""
    __tablename__ = "gmail_accounts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    gmail_address: Mapped[str] = mapped_column(String(320), default="")
    # Vault ciphertext (Fernet v1$...), NOT plaintext — name kept for migration stability.
    refresh_token: Mapped[str] = mapped_column(Text, default="")
    client_id: Mapped[str] = mapped_column(String(320), default="")
    encrypted_client_id: Mapped[str] = mapped_column(Text, default="")
    encrypted_client_secret: Mapped[str] = mapped_column(Text, default="")
    last_sync_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, onupdate=utcnow)


class MailboxConnection(Base):
    """Organization-level mailbox connection for background polling (F7).

    Refresh tokens are Fernet-encrypted (modules/auth/vault.py).
    """
    __tablename__ = "mailbox_connections"
    __table_args__ = (UniqueConstraint("provider", "account_email", name="uq_mailbox_provider_email"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=True, index=True)
    provider: Mapped[str] = mapped_column(String(32), default="google")  # google | microsoft
    account_email: Mapped[str] = mapped_column(String(320), default="")
    encrypted_refresh_token: Mapped[str] = mapped_column(Text, default="")
    encrypted_client_id: Mapped[str] = mapped_column(Text, default="")
    encrypted_client_secret: Mapped[str] = mapped_column(Text, default="")
    last_poll_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, onupdate=utcnow)


class OAuthState(Base):
    """Server-side OAuth state + PKCE store (C3).

    Single-use, short-lived: authorize() creates a row, callback() verifies
    the state belongs to a live session, checks expiry, then consumes it.
    """
    __tablename__ = "oauth_states"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    state: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), default="google")
    redirect_uri: Mapped[str] = mapped_column(String(1024), default="")
    client_id: Mapped[str] = mapped_column(String(320), default="")
    encrypted_client_secret: Mapped[str] = mapped_column(Text, default="")
    code_verifier: Mapped[str] = mapped_column(String(256), default="")
    expires_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
