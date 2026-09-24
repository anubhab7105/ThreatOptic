"""Pydantic schemas for API."""
from datetime import datetime, timezone
from pydantic import BaseModel, Field, field_serializer


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
    # Out-of-band bootstrap secret; required ONLY when requesting Admin (C2).
    setup_token: str | None = None


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


class AsyncIngestResponse(BaseModel):
    task_id: str
    status: str = "queued"


class AsyncTaskStatus(BaseModel):
    task_id: str
    state: str
    result: dict | None = None
    error: str | None = None


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
    fraud_score: float | None = None
    threat_classification: str | None = None
    model_config = {"from_attributes": True}

    @field_serializer("timestamp")
    def serialize_timestamp(self, dt: datetime, _info):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()


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


class GmailAuthUrlIn(BaseModel):
    # P0: client_id/redirect_uri travel in POST body over TLS, never as
    # query params (query strings leak to proxy/access logs). client_secret
    # is NEVER accepted from the client — it resolves server-side only.
    redirect_uri: str = Field(min_length=1, max_length=1024)
    client_id: str | None = Field(default=None, max_length=320)


class GmailCallbackIn(BaseModel):
    code: str = Field(min_length=1)
    # P0: opaque server-side state token (CSRF + PKCE binding). Required —
    # the callback verifies it belongs to the caller before exchanging.
    state: str = Field(min_length=1, max_length=256)
    redirect_uri: str | None = None
    client_id: str | None = None


class GmailSyncIn(BaseModel):
    max_results: int = Field(default=10, ge=1)
    query: str = Field(default="is:unread", max_length=200)
    client_id: str | None = None


class GmailSyncResult(BaseModel):
    synced: int = 0
    email_ids: list[str] = []
    errors: list[str] = []
