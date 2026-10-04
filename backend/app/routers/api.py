"""REST API: ingest, analysis, cases, dashboard, reports (per Design.md + AppFlow.md)."""
import enum
import logging
import re
import threading
from datetime import timezone
from fastapi import APIRouter, Depends, Request, UploadFile, File, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import desc, or_
from sqlalchemy.orm import Session
from ..database import get_db
from .. import models, schemas
from ..services.pipeline import process_raw_email
from ..modules.auth.rate_limit import audit, limiter
from ..modules.graph.store import ALL_TENANTS, related_entities, find_campaigns
from ..modules.privacy.retention import apply_retention
from .deps import get_current_user, require_roles

log = logging.getLogger("api")
router = APIRouter()

# P0 singleflight for expensive cached endpoints (dashboard): concurrent
# cache misses for one scope compute once; waiters read the winner's
# entry instead of stampeding the DB. Plain threading primitives — these
# are sync (threadpool) endpoints.
_sf_lock = threading.Lock()
_sf_inflight: dict[str, threading.Event] = {}


def _singleflight_begin(key: str) -> tuple[bool, threading.Event]:
    """Returns (is_owner, event). Non-owners wait on the owner's event."""
    with _sf_lock:
        existing = _sf_inflight.get(key)
        if existing is not None:
            return False, existing
        event = threading.Event()
        _sf_inflight[key] = event
        return True, event


def _singleflight_end(key: str, event: threading.Event) -> None:
    with _sf_lock:
        if _sf_inflight.get(key) is event:
            _sf_inflight.pop(key, None)
    event.set()

MAX_RAW_BYTES = 5 * 1024 * 1024

# Re-exported from deps so every router shares one definition.
from .deps import READ_WRITE  # noqa: F401


def _org_filter(query, model, user: models.User):
    """Tenant isolation: Admins see all; everyone else sees their own org
    (NULL org matches NULL org via IS NULL comparison)."""
    if user.role == "Admin":
        return query
    return query.filter(model.organization_id == user.organization_id)


TASK_OWNER_TTL_S = 3600


def _record_task_owner(task_id: str, user: models.User) -> None:
    """Bind a Celery task to its submitter (P0: task polling is otherwise
    cross-tenant readable). Best-effort cache write; a missing record
    fails closed as 404 on poll."""
    try:
        from ..modules.cache import cache_set
        cache_set(f"task-owner:{task_id}",
                  {"user_id": user.id, "org": user.organization_id}, TASK_OWNER_TTL_S)
    except Exception:
        pass


def _task_owner(task_id: str) -> dict | None:
    try:
        from ..modules.cache import cache_get
        owner = cache_get(f"task-owner:{task_id}")
        return owner if isinstance(owner, dict) else None
    except Exception:
        return None


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


def _validate_case_emails(db: Session, user: models.User, email_ids: list[str] | None) -> list[str]:
    """Validate linked mail belongs to the caller's tenant (P0).

    Every ID must exist AND be tenant-visible (same org, or Admin);
    anything else is 404 indistinguishable from missing — no
    cross-tenant existence inference via linkage. Dedupes, preserves
    order.
    """
    ids = list(dict.fromkeys(email_ids or []))
    if not ids:
        return []
    rows = dict(db.query(models.EmailRecord.id, models.EmailRecord.organization_id
                         ).filter(models.EmailRecord.id.in_(ids)).all())
    for eid in ids:
        if eid not in rows:
            raise HTTPException(404, "email not found")
        if user.role != "Admin" and rows[eid] != user.organization_id:
            raise HTTPException(404, "email not found")
    return ids


@router.post("/emails/ingest", response_model=schemas.EmailIngestResponse | schemas.AsyncIngestResponse,
               status_code=200)
@limiter.limit("60/minute")
async def ingest_text(payload: IngestBody, request: Request, async_mode: bool = Query(False),
                      db: Session = Depends(get_db),
                      user: models.User = Depends(require_roles(*READ_WRITE))):
    raw_bytes = payload.raw.encode("utf-8")
    if len(raw_bytes) > MAX_RAW_BYTES:
        raise HTTPException(413, f"email payload exceeds maximum size of {MAX_RAW_BYTES} bytes")
    if async_mode:
        from ..services.tasks import analyze_email_task, broker_configured
        if not broker_configured():
            raise HTTPException(400, "async processing not configured (CELERY_BROKER_URL unset)")
        import base64
        task = analyze_email_task.delay(base64.b64encode(raw_bytes).decode(),
                                        payload.source or "api", "", user.organization_id)
        _record_task_owner(task.id, user)
        audit("email.ingest.queued", user=user.email, task_id=task.id)
        return JSONResponse({"task_id": task.id, "status": "queued"}, status_code=202)
    try:
        res = await process_raw_email(db, raw_bytes, source=payload.source or "api",
                                      organization_id=user.organization_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        log.exception("ingest failed")
        raise HTTPException(500, "analysis failed")
    audit("email.ingest", user=user.email, email_id=res["email_id"], score=res["fraud_score"])
    from ..modules.cache import cache_delete_prefix
    cache_delete_prefix("dash:")
    return {"email_id": res["email_id"], "fraud_score": res["fraud_score"],
            "classification": res["classification"], "action": res["action"]}


@router.post("/emails/upload", response_model=schemas.EmailIngestResponse | schemas.AsyncIngestResponse)
@limiter.limit("60/minute")
async def ingest_upload(request: Request, f: UploadFile = File(...), async_mode: bool = Query(False),
                        db: Session = Depends(get_db),
                        user: models.User = Depends(require_roles(*READ_WRITE))):
    # Validate file type - only allow email formats
    allowed_types = {'message/rfc822', 'application/octet-stream', 'text/plain', 'application/mime'}
    content_type = (f.content_type or '').lower()
    filename = (f.filename or '').lower()
    allowed_exts = ('.eml', '.txt', '.mime')
    
    if content_type not in allowed_types and not any(filename.endswith(ext) for ext in allowed_exts):
        raise HTTPException(400, "unsupported file type (expected .eml, .txt or .mime)")
    
    raw = await f.read()
    if not raw or not raw.strip():
        raise HTTPException(400, "empty file")
    if len(raw) > MAX_RAW_BYTES:
        raise HTTPException(413, "file too large (max 5MB)")
    if async_mode:
        from ..services.tasks import analyze_email_task, broker_configured
        if not broker_configured():
            raise HTTPException(400, "async processing not configured (CELERY_BROKER_URL unset)")
        import base64
        task = analyze_email_task.delay(base64.b64encode(raw).decode(), "upload", "", user.organization_id)
        _record_task_owner(task.id, user)
        audit("email.upload.queued", user=user.email, task_id=task.id)
        return JSONResponse({"task_id": task.id, "status": "queued"}, status_code=202)
    try:
        res = await process_raw_email(db, raw, source="upload", organization_id=user.organization_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception:
        log.exception("upload ingest failed")
        raise HTTPException(500, "analysis failed")
    audit("email.upload", user=user.email, email_id=res["email_id"], score=res["fraud_score"])
    from ..modules.cache import cache_delete_prefix
    cache_delete_prefix("dash:")
    return {"email_id": res["email_id"], "fraud_score": res["fraud_score"],
            "classification": res["classification"], "action": res["action"]}


@router.get("/tasks/{task_id}", response_model=schemas.AsyncTaskStatus)
def task_status(task_id: str, db: Session = Depends(get_db),
                user: models.User = Depends(get_current_user)):
    """Poll a Celery ingestion task (202 flow).

    P0: requires auth and task ownership — same user, same org, or Admin.
    Anything else is 404 (indistinguishable from missing: no existence
    or tenant leak).
    """
    from ..services.tasks import broker_configured, celery_app
    if not broker_configured():
        raise HTTPException(400, "async processing not configured (CELERY_BROKER_URL unset)")
    if not re.match(r"^[A-Za-z0-9\-]{1,64}$", task_id or ""):
        raise HTTPException(400, "invalid task id")
    owner = _task_owner(task_id)
    if owner is None:
        raise HTTPException(404, "task not found")
    same_user = owner.get("user_id") == user.id
    same_org = bool(owner.get("org") and user.organization_id) and owner.get("org") == user.organization_id
    if not (same_user or same_org or user.role == "Admin"):
        raise HTTPException(404, "task not found")
    res = celery_app.AsyncResult(task_id)
    out: dict = {"task_id": task_id, "state": res.state}
    if res.state == "SUCCESS":
        out["result"] = res.result if isinstance(res.result, dict) else {"result": str(res.result)}
    elif res.state == "FAILURE":
        out["error"] = str(res.result)[:300]
    return out


@router.get("/emails", response_model=list[schemas.EmailOut])
def list_emails(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                q: str = Query("", max_length=200),
                db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    query = _org_filter(db.query(models.EmailRecord), models.EmailRecord, user)
    if q:
        from ..sql_utils import escape_like
        like = f"%{escape_like(q)}%"
        query = query.filter(or_(
            models.EmailRecord.subject.ilike(like, escape="\\"),
            models.EmailRecord.sender_address.ilike(like, escape="\\"),
            models.EmailRecord.recipient_address.ilike(like, escape="\\"),
            models.EmailRecord.body_text_masked.ilike(like, escape="\\"),
        ))
    rows = (
        query.outerjoin(models.AnalysisResult, models.AnalysisResult.email_id == models.EmailRecord.id)
        .add_columns(models.AnalysisResult.fraud_score, models.AnalysisResult.threat_classification)
        .order_by(desc(models.EmailRecord.timestamp))
        .limit(limit)
        .offset(offset)
        .all()
    )
    out = []
    for r, score, cls in rows:
        item = schemas.EmailOut.model_validate(r)
        if score is not None:
            item.fraud_score = score
            item.threat_classification = cls
        out.append(item)
    return out


@router.get("/emails/{email_id}", response_model=schemas.EmailDetail)
def email_detail(email_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    if not re.match(r"^[A-Za-z0-9\-]{1,64}$", email_id or ""):
        raise HTTPException(400, "invalid email id")
    e = db.query(models.EmailRecord).filter(models.EmailRecord.id == email_id).first()
    if not e:
        raise HTTPException(404, "email not found")
    if user.role != "Admin" and e.organization_id != user.organization_id:
        # Same 404 as missing: cross-tenant existence must not leak.
        raise HTTPException(404, "email not found")
    a = db.query(models.AnalysisResult).filter(models.AnalysisResult.email_id == email_id).first()
    t = db.query(models.TraceabilityData).filter(models.TraceabilityData.email_id == email_id).first()

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
    key = f"dash:{scope}"
    hit = cache_get(key)
    if isinstance(hit, dict):
        return hit
    # P0 singleflight: concurrent cache misses for one scope compute once;
    # waiters read the winner's cache entry instead of stampeding the DB.
    owner, event = _singleflight_begin(key)
    if not owner:
        event.wait(timeout=30)
        hit = cache_get(key)
        if isinstance(hit, dict):
            return hit
        # Winner failed: fall through and compute (never propagate its error).
    try:
        stats = _compute_dashboard(db, user)
        cache_set(key, stats, 300)
        return stats
    finally:
        _singleflight_end(key, event)


def _compute_dashboard(db: Session, user: models.User) -> dict:
    """Dashboard stats via SQL aggregates (P0): COUNT/GROUP BY only — the
    full analysis set is never loaded into Python."""
    from sqlalchemy import case, func
    from ..services.campaigns import _ensure_graph
    _ensure_graph(db)
    email_q = _org_filter(db.query(models.EmailRecord), models.EmailRecord, user)
    total = email_q.count()
    aq = (db.query(models.AnalysisResult.fraud_score, models.AnalysisResult.threat_classification)
          .join(models.EmailRecord, models.AnalysisResult.email_id == models.EmailRecord.id))
    if user.role != "Admin":
        aq = aq.filter(models.EmailRecord.organization_id == user.organization_id)
    blocked = aq.filter(models.AnalysisResult.fraud_score >= 75).count()
    by: dict[str, int] = {}
    for cls, n in aq.with_entities(
            models.AnalysisResult.threat_classification, func.count()).group_by(
            models.AnalysisResult.threat_classification).all():
        by[cls or "Unknown"] = int(n)
    bucket = case(
        (models.AnalysisResult.fraud_score >= 90, "critical"),
        (models.AnalysisResult.fraud_score >= 75, "high"),
        (models.AnalysisResult.fraud_score >= 50, "medium"),
        else_="low")
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for b, n in aq.with_entities(bucket, func.count()).group_by(bucket).all():
        if b in dist:
            dist[b] = int(n)
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
    from ..services.campaigns import campaign_cards as _campaign_cards
    scope_org = None if user.role == "Admin" else user.organization_id
    try:
        active = len(_campaign_cards(db, organization_id=scope_org, is_admin=(user.role == "Admin")))
    except Exception:
        active = 0
    stats = {"total_emails": total, "blocked_threats": blocked,
             "active_campaigns": active, "by_classification": by,
             "recent": recent, "score_distribution": dist}
    return stats


@router.get("/search")
@limiter.limit("30/minute")
def search(request: Request, q: str = Query(..., min_length=1, max_length=200), limit: int = Query(50, ge=1, le=100),
           db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Full-text forensic search: Elasticsearch when configured, SQLite fallback (F10)."""
    from ..modules.search.elastic_sync import search_emails
    # Admins search across every org deliberately; everyone else is pinned to
    # their own. Passing organization_id=None for Admin used to mean "rows with
    # no org", which silently hid all real tenants from them.
    return search_emails(
        q, limit=limit, db=db,
        all_orgs=(user.role == "Admin"),
        organization_id=None if user.role == "Admin" else user.organization_id,
    )


@router.get("/graph/related")
def graph_related(value: str = Query(..., min_length=1, max_length=320),
                 email_id: str | None = Query(None),
                 db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    from ..services.campaigns import _filter_graph_emails, _tenant_email_addresses
    # Hydration reads EmailRecord directly (tenant PII + campaign labels),
    # so the scope has to be pushed down, not only filtered afterwards.
    graph = related_entities(
        value, db=db, email_id=email_id,
        organization_id=ALL_TENANTS if user.role == "Admin" else user.organization_id,
    )
    if user.role == "Admin":
        return graph
    # P0: traversal runs on the shared global graph — strip foreign email
    # nodes (addresses are tenant PII); infra nodes stay as shared intel.
    return _filter_graph_emails(
        graph, _tenant_email_addresses(db, user.organization_id))


@router.get("/graph/campaigns")
def graph_campaigns(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Shared infrastructure clusters (P0 documented access control).

    Returns IP/domain clusters only — no email addresses, subjects, or
    other tenant-attributable metadata. Cluster membership derives from
    the global graph (shared threat intel); email-level detail stays
    tenant-scoped behind /campaigns and /graph/related.
    """
    return find_campaigns()


@router.get("/campaigns", response_model=list[schemas.CampaignCard])
def list_campaigns(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    from ..services.campaigns import campaign_cards
    scope = None if user.role == "Admin" else user.organization_id
    return campaign_cards(db, organization_id=scope, is_admin=(user.role == "Admin"))


@router.get("/campaigns/{cid}", response_model=schemas.CampaignDetail)
def get_campaign(cid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    from ..services.campaigns import campaign_detail
    scope = None if user.role == "Admin" else user.organization_id
    detail = campaign_detail(db, cid, organization_id=scope, is_admin=(user.role == "Admin"))
    if not detail:
        raise HTTPException(404, "campaign not found")
    return detail


@router.post("/cases", response_model=schemas.CaseOut)
def create_case(payload: schemas.CaseIn, db: Session = Depends(get_db),
                user: models.User = Depends(require_roles(*READ_WRITE))):
    if not payload.title or not payload.title.strip():
        raise HTTPException(400, "title is required")
    if payload.assignee_id:
        assignee = db.query(models.User).filter(models.User.id == payload.assignee_id).first()
        if not assignee:
            raise HTTPException(400, "assignee not found")
        if user.role != "Admin" and assignee.organization_id != user.organization_id:
            raise HTTPException(400, "assignee not found in organization")
    c = models.InvestigationCase(title=payload.title.strip(),
                                 email_ids=_validate_case_emails(db, user, payload.email_ids or []),
                                 assignee_id=payload.assignee_id, notes=payload.notes or "",
                                 organization_id=user.organization_id)
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


@router.get("/cases", response_model=list[schemas.CaseOut])
def list_cases(limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0),
               db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return _org_filter(db.query(models.InvestigationCase), models.InvestigationCase, user).order_by(
        desc(models.InvestigationCase.created_at)).limit(limit).offset(offset).all()


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
        if payload.assignee_id:
            assignee = db.query(models.User).filter(models.User.id == payload.assignee_id).first()
            if not assignee:
                raise HTTPException(400, "assignee not found")
            if user.role != "Admin" and assignee.organization_id != user.organization_id:
                raise HTTPException(400, "assignee not found in organization")
        c.assignee_id = payload.assignee_id
    if payload.email_ids is not None:
        c.email_ids = _validate_case_emails(db, user, payload.email_ids)
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


def _report_context(email_id: str, db: Session, user: models.User | None = None):
    e = db.query(models.EmailRecord).filter(models.EmailRecord.id == email_id).first()
    if not e:
        raise HTTPException(404, "email not found")
    if user is not None and user.role != "Admin" and e.organization_id != user.organization_id:
        raise HTTPException(404, "email not found")
    a = db.query(models.AnalysisResult).filter(models.AnalysisResult.email_id == email_id).first()
    t = db.query(models.TraceabilityData).filter(models.TraceabilityData.email_id == email_id).first()
    return e, a, t


@router.get("/reports/{email_id}.json")
def report_json(email_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    from ..modules.reporting.generator import build_report_json
    from ..modules.graph.attribution import attribute
    e, a, t = _report_context(email_id, db, user)
    email_d = {"subject": e.subject, "sender_address": e.sender_address, "recipient_address": e.recipient_address,
               "message_id": e.message_id, "raw_eml_hash": e.raw_eml_hash, "body_text": e.body_text_masked}
    analysis_d = {"fraud_score": a.fraud_score, "threat_classification": a.threat_classification,
                  "nlp_cues_detected": a.nlp_cues_detected, "authentication_results": a.authentication_results,
                  "action_taken": a.action_taken, "score_breakdown": a.score_breakdown or []} if a else {}
    trace_d = {"origin_ip": t.origin_ip, "geolocation": t.geolocation, "relay_chain": t.relay_chain} if t else {}
    return build_report_json(email_d, analysis_d, trace_d,
                             attribute(e.sender_address, t.origin_ip if t else "", []))


@router.get("/reports/{email_id}.pdf")
def report_pdf(email_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    from ..modules.reporting.generator import build_report_pdf
    from ..modules.graph.attribution import attribute
    if not re.match(r"^[A-Za-z0-9\-]{1,64}$", email_id or ""):
        # email_id lands in Content-Disposition: reject anything else.
        raise HTTPException(400, "invalid report id")
    e, a, t = _report_context(email_id, db, user)
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


@router.get("/admin/retention/preview")
@limiter.limit("5/minute")
def preview_retention(
    request: Request,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_roles("Admin")),
):
    from ..config import get_settings
    settings = get_settings()
    audit("admin.retention.preview", user=admin.email)
    return apply_retention(db, settings.retention_clean_days, settings.retention_malicious_days, dry_run=True)


@router.post("/admin/retention")
@limiter.limit("5/minute")
def run_retention(
    request: Request,
    dry_run: bool = Query(False),
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_roles("Admin")),
):
    from ..config import get_settings
    settings = get_settings()
    audit("admin.retention", user=admin.email, dry_run=dry_run)
    return apply_retention(db, settings.retention_clean_days, settings.retention_malicious_days, dry_run=dry_run)


@router.get("/model/metrics")
def model_metrics():
    """NLP classifier transparency: held-out precision/recall/F1/confusion matrix.

    Metrics are computed and cached by backend/scripts/train_nlp.py.
    """
    return _load_model_metrics()


def _load_model_metrics(metrics_path: str | None = None, model_path: str | None = None) -> dict:
    import json
    import os
    if metrics_path is None:
        metrics_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "ml_models", "metrics.json"))
    if model_path is None:
        model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "ml_models", "phishing_clf.joblib"))
    if not os.path.exists(metrics_path):
        raise HTTPException(404, "metrics not computed yet (run: python backend/scripts/train_nlp.py)")
    try:
        with open(metrics_path, encoding="utf-8") as f:
            metrics = json.load(f)
    except (OSError, ValueError) as e:
        log.warning("metrics.json unreadable: %s", type(e).__name__)
        raise HTTPException(500, "model metrics unavailable")
    metrics["model_exists"] = os.path.exists(model_path)
    return metrics
