"""Pydantic schemas for API."""
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class OrganizationOut(BaseModel):
    id: str
    name: str
    compliance_policy: dict = {}
    model_config = {"from_attributes": True}


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
