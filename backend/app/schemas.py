"""Pydantic schemas for API."""
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class OrganizationOut(BaseModel):
    id: str
    name: str
    compliance_policy: dict = {}
    model_config = {"from_attributes": True}


class UserOut(BaseModel):
    id: str
    username: str
    role: str
    organization_id: str | None = None
    created_at: datetime
    model_config = {"from_attributes": True}


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[\w.\-@]+$")
    password: str = Field(min_length=8, max_length=128)
    role: str | None = None


class AdminCreateUserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[\w.\-@]+$")
    password: str = Field(min_length=8, max_length=128)
    role: str = "Analyst"
    organization_id: str | None = None


class LoginIn(BaseModel):
    username: str
    password: str


class RefreshIn(BaseModel):
    refresh_token: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class EmailIngestResponse(BaseModel):
    email_id: str
    fraud_score: float
    classification: str
    action: str


class AnalysisOut(BaseModel):
    id: str
    email_id: str
    fraud_score: float
    threat_classification: str
    nlp_cues_detected: list = []
    authentication_results: dict = {}
    trace_summary: dict = {}
    threat_intel_hits: list = []
    action_taken: str
    score_breakdown: list = []
    created_at: datetime
    model_config = {"from_attributes": True}


class EmailOut(BaseModel):
    id: str
    message_id: str = ""
    sender_address: str = ""
    recipient_address: str = ""
    subject: str = ""
    body_text_masked: str = ""
    attachments_metadata: list = []
    raw_eml_hash: str = ""
    timestamp: datetime
    model_config = {"from_attributes": True}


class EmailDetail(BaseModel):
    email: EmailOut
    analysis: AnalysisOut | None = None
    trace: dict | None = None


class CaseIn(BaseModel):
    title: str
    email_ids: list[str] = []
    assignee_id: str | None = None
    notes: str = ""


class CaseOut(BaseModel):
    id: str
    title: str
    status: str
    assignee_id: str | None = None
    email_ids: list = []
    notes: str = ""
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}


class DashboardStats(BaseModel):
    total_emails: int = 0
    blocked_threats: int = 0
    active_campaigns: int = 0
    by_classification: dict = {}
    recent: list[dict] = []
    score_distribution: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0}


class CampaignCard(BaseModel):
    id: str
    name: str
    ip: str
    domains: list = []
    asn: str = ""
    confidence: float = 0.0
    email_count: int = 0
    first_seen: str | None = None
    last_seen: str | None = None


class CampaignEmail(BaseModel):
    id: str
    subject: str = ""
    sender: str = ""
    timestamp: str | None = None
    fraud_score: float = 0.0
    classification: str = "—"


class CampaignDetail(BaseModel):
    card: CampaignCard
    graph: dict = {}
    emails: list[CampaignEmail] = []


class GmailStatus(BaseModel):
    connected: bool = False
    gmail_address: str = ""
    last_sync_at: str | None = None
    client_configured: bool = False


class GmailAuthUrlOut(BaseModel):
    auth_url: str


class GmailCallbackIn(BaseModel):
    code: str = Field(min_length=1)
    redirect_uri: str | None = None
    client_id: str | None = None
    client_secret: str | None = None


class GmailSyncIn(BaseModel):
    max_results: int = Field(default=10, ge=1, le=50)
    query: str = Field(default="is:unread", max_length=200)
    client_secret: str | None = None


class GmailSyncResult(BaseModel):
    synced: int = 0
    email_ids: list[str] = []
    errors: list[str] = []
