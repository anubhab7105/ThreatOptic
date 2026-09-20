"""REST API: ingest, analysis, cases, dashboard, reports (per Design.md + AppFlow.md)."""
import logging
from datetime import timezone
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import desc, or_
from sqlalchemy.orm import Session
from ..database import get_db
from .. import models, schemas
from ..services.pipeline import process_raw_email
from ..modules.graph.store import related_entities, find_campaigns
from ..modules.privacy.retention import apply_retention
from .deps import require_roles

log = logging.getLogger("api")
router = APIRouter()

MAX_RAW_BYTES = 5 * 1024 * 1024


class IngestBody(BaseModel):
    raw: str = Field(min_length=1, max_length=MAX_RAW_BYTES)
    source: str = "api"


@router.post("/emails/ingest", response_model=schemas.EmailIngestResponse)
async def ingest_text(payload: IngestBody, db: Session = Depends(get_db)):
    try:
        res = await process_raw_email(db, payload.raw.encode(), source=payload.source or "api")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        log.exception("ingest failed")
        raise HTTPException(500, f"analysis failed: {e}")
    return {"email_id": res["email_id"], "fraud_score": res["fraud_score"],
            "classification": res["classification"], "action": res["action"]}


@router.post("/emails/upload", response_model=schemas.EmailIngestResponse)
async def ingest_upload(f: UploadFile = File(...), db: Session = Depends(get_db)):
    raw = await f.read()
    if not raw or not raw.strip():
        raise HTTPException(400, "empty file")
    if len(raw) > MAX_RAW_BYTES:
        raise HTTPException(413, "file too large (max 5MB)")
    try:
        res = await process_raw_email(db, raw, source="upload")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        log.exception("upload ingest failed")
        raise HTTPException(500, f"analysis failed: {e}")
    return {"email_id": res["email_id"], "fraud_score": res["fraud_score"],
            "classification": res["classification"], "action": res["action"]}


@router.get("/emails", response_model=list[schemas.EmailOut])
def list_emails(limit: int = Query(50, ge=1, le=200), q: str = Query("", max_length=200),
                db: Session = Depends(get_db)):
    query = db.query(models.EmailRecord)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(
            models.EmailRecord.subject.ilike(like),
            models.EmailRecord.sender_address.ilike(like),
            models.EmailRecord.recipient_address.ilike(like),
            models.EmailRecord.body_text_masked.ilike(like),
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
def email_detail(email_id: str, db: Session = Depends(get_db)):
    e = db.query(models.EmailRecord).filter(models.EmailRecord.id == email_id).first()
    if not e:
        raise HTTPException(404, "email not found")
    a = db.query(models.AnalysisResult).filter(models.AnalysisResult.email_id == email_id).first()
    t = db.query(models.TraceabilityData).filter(models.TraceabilityData.email_id == email_id).first()
    if t:
        modified = False
        geo = t.geolocation or {}
        if not geo or (geo.get("lat") == 0.0 and geo.get("lon") == 0.0) or geo.get("source") in ("offline-stub", "fallback", "none"):
            from ..modules.traceability.geoip import geolocate
            new_geo = geolocate(t.origin_ip) if t.origin_ip else None
            if not new_geo or (new_geo.get("lat") == 0.0 and new_geo.get("lon") == 0.0):
                for hop in (t.relay_chain or []):
                    for hop_ip in hop.get("ips", []):
                        g = geolocate(hop_ip)
                        if g and (g.get("lat") != 0.0 or g.get("lon") != 0.0):
                            new_geo = g
                            break
                    if new_geo and (new_geo.get("lat") != 0.0 or new_geo.get("lon") != 0.0):
                        break
            if (not new_geo or (new_geo.get("lat") == 0.0 and new_geo.get("lon") == 0.0)) and e.sender_address:
                try:
                    import socket
                    domain = e.sender_address.split("@")[-1].strip(" <>")
                    if domain:
                        dip = socket.gethostbyname(domain)
                        g = geolocate(dip)
                        if g and (g.get("lat") != 0.0 or g.get("lon") != 0.0):
                            new_geo = {**g, "source": "approx-domain-ip"}
                except Exception:
                    pass

            if new_geo and (new_geo.get("lat") != 0.0 or new_geo.get("lon") != 0.0 or new_geo.get("country") not in ("", "UNKNOWN")):
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
def dashboard(db: Session = Depends(get_db)):
    from ..services.campaigns import _ensure_graph
    _ensure_graph(db)
    total = db.query(models.EmailRecord).count()
    blocked = db.query(models.AnalysisResult).filter(models.AnalysisResult.fraud_score >= 75).count()
    by: dict[str, int] = {}
    for (c,) in db.query(models.AnalysisResult.threat_classification).all():
        by[c or "Unknown"] = by.get(c or "Unknown", 0) + 1
    recent_rows = (
        db.query(
            models.EmailRecord.id,
            models.EmailRecord.subject,
            models.EmailRecord.sender_address,
            models.EmailRecord.timestamp,
        )
        .order_by(desc(models.EmailRecord.timestamp))
        .limit(10)
        .all()
    )
    recent = [
        {"id": rid, "subject": (subj or "")[:80], "sender": (sender or "")[:80],
         "ts": (ts.replace(tzinfo=timezone.utc) if ts and ts.tzinfo is None else ts).isoformat() if ts else ""}
        for rid, subj, sender, ts in recent_rows
    ]
    # score histogram for the UI distribution chart
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for (s,) in db.query(models.AnalysisResult.fraud_score).all():
        try:
            v = float(s or 0)
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
    return {"total_emails": total, "blocked_threats": blocked,
            "active_campaigns": len(find_campaigns()), "by_classification": by,
            "recent": recent, "score_distribution": dist}


@router.get("/search")
def search(q: str = Query(..., min_length=1, max_length=200), limit: int = Query(50, ge=1, le=100),
           db: Session = Depends(get_db)):
    """Full-text forensic search: Elasticsearch when configured, SQLite fallback (F10)."""
    from ..modules.search.elastic_sync import search_emails
    return search_emails(q, limit=limit, db=db)


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
def create_case(payload: schemas.CaseIn, db: Session = Depends(get_db)):
    if not payload.title or not payload.title.strip():
        raise HTTPException(400, "title is required")
    c = models.InvestigationCase(title=payload.title.strip(), email_ids=payload.email_ids or [],
                                 assignee_id=payload.assignee_id, notes=payload.notes or "")
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


@router.get("/cases", response_model=list[schemas.CaseOut])
def list_cases(db: Session = Depends(get_db)):
    return db.query(models.InvestigationCase).order_by(desc(models.InvestigationCase.created_at)).all()


VALID_CASE_STATUSES = {"Open", "InProgress", "Closed"}


@router.patch("/cases/{case_id}", response_model=schemas.CaseOut)
def update_case(case_id: str, payload: dict, db: Session = Depends(get_db)):
    c = db.query(models.InvestigationCase).filter(models.InvestigationCase.id == case_id).first()
    if not c:
        raise HTTPException(404, "case not found")
    if "status" in payload:
        st = str(payload["status"]).strip()
        if st not in VALID_CASE_STATUSES:
            raise HTTPException(400, f"invalid status '{st}', must be one of {sorted(VALID_CASE_STATUSES)}")
        c.status = st
    if "title" in payload and payload["title"]:
        c.title = str(payload["title"]).strip()
    if "notes" in payload:
        c.notes = str(payload["notes"])
    if "assignee_id" in payload:
        c.assignee_id = payload["assignee_id"]
    if "email_ids" in payload and isinstance(payload["email_ids"], list):
        c.email_ids = payload["email_ids"]
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
               "message_id": e.message_id, "raw_eml_hash": e.raw_eml_hash, "body_text": e.body_text}
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
    return apply_retention(db)


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
