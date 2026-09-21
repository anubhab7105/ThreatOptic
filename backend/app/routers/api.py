"""REST API: ingest, analysis, cases, dashboard, reports (per Design.md + AppFlow.md)."""
import enum
import logging
from datetime import timezone
from fastapi import APIRouter, Depends, Request, UploadFile, File, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import desc, or_
from sqlalchemy.orm import Session
from ..database import get_db
from .. import models, schemas
from ..services.pipeline import process_raw_email
from ..modules.auth.rate_limit import audit, limiter
from ..modules.graph.store import related_entities, find_campaigns
from ..modules.privacy.retention import apply_retention
from .deps import get_current_user, require_roles

log = logging.getLogger("api")
router = APIRouter()

MAX_RAW_BYTES = 5 * 1024 * 1024

# ReadOnly = read-only; Analyst = ingest + edit cases; Admin = all + delete/retention/provisioning.
READ_WRITE = ("Admin", "Analyst")


def _org_filter(query, model, user: models.User):
    """Tenant isolation: Admins see all; everyone else sees their own org
    (NULL org matches NULL org via IS NULL comparison)."""
    if user.role == "Admin":
        return query
    return query.filter(model.organization_id == user.organization_id)


class CaseStatus(str, enum.Enum):
    Open = "Open"
    InProgress = "InProgress"
    Closed = "Closed"


class CaseUpdate(BaseModel):
    """Whitelisted, validated case edits (no mass assignment)."""
    title: str | None = Field(default=None, min_length=1, max_length=512)
    status: CaseStatus | None = None
    assignee_id: str | None = None
    email_ids: list[str] | None = None
    notes: str | None = None

    model_config = {"extra": "forbid"}


class IngestBody(BaseModel):
    raw: str = Field(min_length=1, max_length=MAX_RAW_BYTES)
    source: str = "api"


@router.post("/emails/ingest", response_model=schemas.EmailIngestResponse | schemas.AsyncIngestResponse,
               status_code=200)
@limiter.limit("60/minute")
async def ingest_text(payload: IngestBody, request: Request, async_mode: bool = Query(False),
                      db: Session = Depends(get_db),
                      user: models.User = Depends(require_roles(*READ_WRITE))):
    if async_mode:
        from ..services.tasks import analyze_email_task, broker_configured
        if not broker_configured():
            raise HTTPException(400, "async processing not configured (CELERY_BROKER_URL unset)")
        import base64
        task = analyze_email_task.delay(base64.b64encode(payload.raw.encode()).decode(),
                                        payload.source or "api", "", user.organization_id)
        audit("email.ingest.queued", user=user.username, task_id=task.id)
        return JSONResponse({"task_id": task.id, "status": "queued"}, status_code=202)
    try:
        res = await process_raw_email(db, payload.raw.encode(), source=payload.source or "api",
                                      organization_id=user.organization_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        log.exception("ingest failed")
        raise HTTPException(500, "analysis failed")
    audit("email.ingest", user=user.username, email_id=res["email_id"], score=res["fraud_score"])
    from ..modules.cache import cache_delete_prefix
    cache_delete_prefix("dash:")
    return {"email_id": res["email_id"], "fraud_score": res["fraud_score"],
            "classification": res["classification"], "action": res["action"]}


@router.post("/emails/upload", response_model=schemas.EmailIngestResponse)
@limiter.limit("60/minute")
async def ingest_upload(request: Request, f: UploadFile = File(...), db: Session = Depends(get_db),
                        user: models.User = Depends(require_roles(*READ_WRITE))):
    raw = await f.read()
    if not raw or not raw.strip():
        raise HTTPException(400, "empty file")
    if len(raw) > MAX_RAW_BYTES:
        raise HTTPException(413, "file too large (max 5MB)")
    try:
        res = await process_raw_email(db, raw, source="upload", organization_id=user.organization_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        log.exception("upload ingest failed")
        raise HTTPException(500, "analysis failed")
    audit("email.upload", user=user.username, email_id=res["email_id"], score=res["fraud_score"])
    from ..modules.cache import cache_delete_prefix
    cache_delete_prefix("dash:")
    return {"email_id": res["email_id"], "fraud_score": res["fraud_score"],
            "classification": res["classification"], "action": res["action"]}


@router.get("/emails", response_model=list[schemas.EmailOut])
def list_emails(limit: int = Query(50, ge=1, le=200), q: str = Query("", max_length=200),
                db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    query = _org_filter(db.query(models.EmailRecord), models.EmailRecord, user)
    if q:
        from ..modules.search.elastic_sync import _escape_like
        like = f"%{_escape_like(q)}%"
        query = query.filter(or_(
            models.EmailRecord.subject.ilike(like, escape="\\"),
            models.EmailRecord.sender_address.ilike(like, escape="\\"),
            models.EmailRecord.recipient_address.ilike(like, escape="\\"),
            models.EmailRecord.body_text_masked.ilike(like, escape="\\"),
        ))
    records = query.order_by(desc(models.EmailRecord.timestamp)).limit(limit).all()
    if not records:
        return []
    email_ids = [r.id for r in records]
    analyses = {a.email_id: a for a in db.query(models.AnalysisResult).filter(models.AnalysisResult.email_id.in_(email_ids)).all()}
    out = []
    for r in records:
        item = schemas.EmailOut.model_validate(r)
        a = analyses.get(r.id)
        if a:
            item.fraud_score = a.fraud_score
            item.threat_classification = a.threat_classification
        out.append(item)
    return out


@router.get("/emails/{email_id}", response_model=schemas.EmailDetail)
def email_detail(email_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    e = db.query(models.EmailRecord).filter(models.EmailRecord.id == email_id).first()
    if not e:
        raise HTTPException(404, "email not found")
    if user.role != "Admin" and e.organization_id != user.organization_id:
        # Same 404 as missing: cross-tenant existence must not leak.
        raise HTTPException(404, "email not found")
    a = db.query(models.AnalysisResult).filter(models.AnalysisResult.email_id == email_id).first()
    t = db.query(models.TraceabilityData).filter(models.TraceabilityData.email_id == email_id).first()
    if t:
        modified = False
        geo = t.geolocation or {}
        from ..modules.traceability.geoip import geolocate, has_coords
        if not has_coords(geo) or geo.get("source") in ("offline-stub", "fallback", "none", "unresolved"):
            new_geo = geolocate(t.origin_ip) if t.origin_ip else None
            if not has_coords(new_geo):
                for hop in (t.relay_chain or []):
                    for hop_ip in hop.get("ips", []):
                        g = geolocate(hop_ip)
                        if has_coords(g):
                            new_geo = g
                            break
                    if has_coords(new_geo):
                        break
            if (not new_geo or (new_geo.get("lat") == 0.0 and new_geo.get("lon") == 0.0)) and e.sender_address:
                try:
                    import socket
                    domain = e.sender_address.split("@")[-1].strip(" <>")
                    if domain:
                        dip = socket.gethostbyname(domain)
                        g = geolocate(dip)
                        if has_coords(g):
                            new_geo = {**g, "source": "approx-domain-ip"}
                except Exception:
                    pass

            if has_coords(new_geo) or (new_geo or {}).get("country"):
                t.geolocation = new_geo
                if new_geo.get("isp") or new_geo.get("asn"):
                    t.isp_asn = f"{new_geo.get('isp', '')} {new_geo.get('asn', '')}".strip()
                modified = True

        whois = t.whois_data or {}
        if (not whois or whois.get("note") == "live-lookups-disabled") and e.sender_address:
            from ..modules.traceability.whois_dns import whois_lookup
            domain = e.sender_address.split("@")[-1].strip(" <>")
            if domain:
                new_w = whois_lookup(domain)
                if new_w and new_w.get("note") != "live-lookups-disabled":
                    t.whois_data = new_w
                    modified = True

        dnsd = t.dns_data or {}
        if (not dnsd or (not dnsd.get("mx") and not dnsd.get("a"))) and e.sender_address:
            from ..modules.traceability.whois_dns import dns_lookup
            domain = e.sender_address.split("@")[-1].strip(" <>")
            if domain:
                new_d = dns_lookup(domain)
                if new_d and (new_d.get("mx") or new_d.get("a")):
                    t.dns_data = new_d
                    modified = True

        if modified:
            try:
                db.commit()
                db.refresh(t)
            except Exception:
                db.rollback()

    return {
        "email": e,
        "analysis": a,
        "trace": {"origin_ip": t.origin_ip, "geolocation": t.geolocation, "relay_chain": t.relay_chain,
                  "isp_asn": t.isp_asn, "is_vpn_tor": t.is_vpn_tor,
                  "whois": t.whois_data, "dns": t.dns_data} if t else None,
    }


@router.get("/dashboard", response_model=schemas.DashboardStats)
def dashboard(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    from ..modules.cache import cache_get, cache_set
    scope = "admin" if user.role == "Admin" else (user.organization_id or "none")
    hit = cache_get(f"dash:{scope}")
    if isinstance(hit, dict):
        return hit
    from ..services.campaigns import _ensure_graph
    _ensure_graph(db)
    email_q = _org_filter(db.query(models.EmailRecord), models.EmailRecord, user)
    total = email_q.count()
    email_ids = [r[0] for r in email_q.with_entities(models.EmailRecord.id).all()]
    analyses = db.query(models.AnalysisResult).filter(models.AnalysisResult.email_id.in_(email_ids)).all() if email_ids else []
    blocked = sum(1 for a in analyses if (a.fraud_score or 0) >= 75)
    by: dict[str, int] = {}
    for a in analyses:
        by[a.threat_classification or "Unknown"] = by.get(a.threat_classification or "Unknown", 0) + 1
    recent_rows = (
        _org_filter(db.query(
            models.EmailRecord.id,
            models.EmailRecord.subject,
            models.EmailRecord.sender_address,
            models.EmailRecord.timestamp,
        ), models.EmailRecord, user)
        .order_by(desc(models.EmailRecord.timestamp))
        .limit(10)
        .all()
    )
    recent = [
        {"id": rid, "subject": (subj or "")[:80], "sender": (sender or "")[:80],
         "ts": (ts.replace(tzinfo=timezone.utc) if ts and ts.tzinfo is None else ts).isoformat() if ts else ""}
        for rid, subj, sender, ts in recent_rows
    ]
    # score histogram for the UI distribution chart (tenant-scoped analyses)
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in analyses:
        try:
            v = float(a.fraud_score or 0)
        except Exception:
            v = 0
        if v >= 90:
            dist["critical"] += 1
        elif v >= 75:
            dist["high"] += 1
        elif v >= 50:
            dist["medium"] += 1
        else:
            dist["low"] += 1
    stats = {"total_emails": total, "blocked_threats": blocked,
             "active_campaigns": len(find_campaigns()), "by_classification": by,
             "recent": recent, "score_distribution": dist}
    cache_set(f"dash:{scope}", stats, 300)
    return stats


@router.get("/search")
def search(q: str = Query(..., min_length=1, max_length=200), limit: int = Query(50, ge=1, le=100),
           db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Full-text forensic search: Elasticsearch when configured, SQLite fallback (F10)."""
    from ..modules.search.elastic_sync import search_emails
    return search_emails(q, limit=limit, db=db, organization_id=None if user.role == "Admin" else user.organization_id)


@router.get("/graph/related")
def graph_related(value: str = Query(..., min_length=1, max_length=320)):
    import re
    # Accept full "Name <addr>" headers — extract bare email for lookup.
    m = re.search(r"[\w.\-+]+@[\w.\-]+\.\w+", value or "")
    key = m.group(0) if m else value
    return related_entities(key)


@router.get("/graph/campaigns")
def graph_campaigns():
    return find_campaigns()


@router.get("/campaigns", response_model=list[schemas.CampaignCard])
def list_campaigns(db: Session = Depends(get_db)):
    from ..services.campaigns import campaign_cards
    return campaign_cards(db)


@router.get("/campaigns/{cid}", response_model=schemas.CampaignDetail)
def get_campaign(cid: str, db: Session = Depends(get_db)):
    from ..services.campaigns import campaign_detail
    detail = campaign_detail(db, cid)
    if not detail:
        raise HTTPException(404, "campaign not found")
    return detail


@router.post("/cases", response_model=schemas.CaseOut)
def create_case(payload: schemas.CaseIn, db: Session = Depends(get_db),
                user: models.User = Depends(require_roles(*READ_WRITE))):
    if not payload.title or not payload.title.strip():
        raise HTTPException(400, "title is required")
    if payload.assignee_id and not db.query(models.User).filter(models.User.id == payload.assignee_id).first():
        raise HTTPException(400, "assignee not found")
    c = models.InvestigationCase(title=payload.title.strip(), email_ids=payload.email_ids or [],
                                 assignee_id=payload.assignee_id, notes=payload.notes or "",
                                 organization_id=user.organization_id)
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


@router.get("/cases", response_model=list[schemas.CaseOut])
def list_cases(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return _org_filter(db.query(models.InvestigationCase), models.InvestigationCase, user).order_by(
        desc(models.InvestigationCase.created_at)).all()


VALID_CASE_STATUSES = {"Open", "InProgress", "Closed"}


@router.patch("/cases/{case_id}", response_model=schemas.CaseOut)
def update_case(case_id: str, payload: CaseUpdate, db: Session = Depends(get_db),
                user: models.User = Depends(require_roles(*READ_WRITE))):
    c = db.query(models.InvestigationCase).filter(models.InvestigationCase.id == case_id).first()
    if not c:
        raise HTTPException(404, "case not found")
    if user.role != "Admin" and c.organization_id != user.organization_id:
        raise HTTPException(404, "case not found")
    if payload.status is not None:
        c.status = payload.status.value
    if payload.title is not None:
        title = payload.title.strip()
        if not title:
            raise HTTPException(400, "title must not be blank")
        c.title = title
    if payload.notes is not None:
        c.notes = str(payload.notes)
    if payload.assignee_id is not None:
        if payload.assignee_id and not db.query(models.User).filter(models.User.id == payload.assignee_id).first():
            raise HTTPException(400, "assignee not found")
        c.assignee_id = payload.assignee_id
    if payload.email_ids is not None:
        c.email_ids = payload.email_ids
    db.commit()
    db.refresh(c)
    return c


@router.delete("/cases/{case_id}")
def delete_case(
    case_id: str,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_roles("Admin")),
):
    c = db.query(models.InvestigationCase).filter(models.InvestigationCase.id == case_id).first()
    if not c:
        raise HTTPException(404, "case not found")
    db.delete(c)
    db.commit()
    return {"deleted": case_id}


def _report_context(email_id: str, db: Session):
    e = db.query(models.EmailRecord).filter(models.EmailRecord.id == email_id).first()
    if not e:
        raise HTTPException(404, "email not found")
    a = db.query(models.AnalysisResult).filter(models.AnalysisResult.email_id == email_id).first()
    t = db.query(models.TraceabilityData).filter(models.TraceabilityData.email_id == email_id).first()
    return e, a, t


@router.get("/reports/{email_id}.json")
def report_json(email_id: str, db: Session = Depends(get_db)):
    from ..modules.reporting.generator import build_report_json
    from ..modules.graph.attribution import attribute
    e, a, t = _report_context(email_id, db)
    email_d = {"subject": e.subject, "sender_address": e.sender_address, "recipient_address": e.recipient_address,
               "message_id": e.message_id, "raw_eml_hash": e.raw_eml_hash, "body_text": e.body_text_masked}
    analysis_d = {"fraud_score": a.fraud_score, "threat_classification": a.threat_classification,
                  "nlp_cues_detected": a.nlp_cues_detected, "authentication_results": a.authentication_results,
                  "action_taken": a.action_taken, "score_breakdown": a.score_breakdown or []} if a else {}
    trace_d = {"origin_ip": t.origin_ip, "geolocation": t.geolocation, "relay_chain": t.relay_chain} if t else {}
    return build_report_json(email_d, analysis_d, trace_d,
                             attribute(e.sender_address, t.origin_ip if t else "", []))


@router.get("/reports/{email_id}.pdf")
def report_pdf(email_id: str, db: Session = Depends(get_db)):
    from ..modules.reporting.generator import build_report_pdf
    from ..modules.graph.attribution import attribute
    e, a, t = _report_context(email_id, db)
    email_d = {"subject": e.subject, "sender_address": e.sender_address, "recipient_address": e.recipient_address,
               "message_id": e.message_id, "raw_eml_hash": e.raw_eml_hash}
    analysis_d = {"fraud_score": a.fraud_score if a else 0,
                  "threat_classification": a.threat_classification if a else "",
                  "nlp_cues_detected": a.nlp_cues_detected if a else [],
                  "authentication_results": a.authentication_results if a else {},
                  "action_taken": a.action_taken if a else ""}
    trace_d = {"origin_ip": t.origin_ip if t else "", "geolocation": t.geolocation if t else {},
               "relay_chain": t.relay_chain if t else [], "isp_asn": t.isp_asn if t else "",
               "is_vpn_tor": t.is_vpn_tor if t else False}
    pdf = build_report_pdf(email_d, analysis_d, trace_d, attribute(e.sender_address, trace_d["origin_ip"], []))
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=forensic-{email_id}.pdf"})


@router.post("/admin/retention")
def run_retention(
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_roles("Admin")),
):
    from ..config import get_settings
    settings = get_settings()
    return apply_retention(db, settings.retention_clean_days, settings.retention_malicious_days)


@router.get("/model/metrics")
def model_metrics():
    """NLP classifier transparency: held-out precision/recall/F1/confusion matrix.

    Metrics are computed and cached by backend/scripts/train_nlp.py.
    """
    import json
    import os
    metrics_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "ml_models", "metrics.json"))
    model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "ml_models", "phishing_clf.joblib"))
    if not os.path.exists(metrics_path):
        raise HTTPException(404, "metrics not computed yet (run: python backend/scripts/train_nlp.py)")
    with open(metrics_path) as f:
        metrics = json.load(f)
    metrics["model_exists"] = os.path.exists(model_path)
    return metrics
