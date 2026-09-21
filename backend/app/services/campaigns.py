"""Campaign cards built on graph clusters + SQLite forensic records.

No graph rewrites: uses store.find_campaigns() for the domain cluster behind
each shared IP, then joins EmailRecord/AnalysisResult/TraceabilityData to add
email counts, shared ASN, confidence, and first/last seen timestamps.
"""
from collections import Counter
from sqlalchemy.orm import Session
from .. import models
from ..modules.graph.store import find_campaigns, related_entities


def _cid_for_ip(ip: str) -> str:
    return "ip-" + (ip or "unknown").replace(".", "-").replace(":", "-")


def _ensure_graph(db: Session) -> None:
    from ..modules.graph.store import G, upsert_email_graph
    if G.number_of_nodes() == 0:
        rows = (
            db.query(models.EmailRecord.sender_address, models.TraceabilityData.origin_ip)
            .join(models.TraceabilityData, models.EmailRecord.id == models.TraceabilityData.email_id)
            .all()
        )
        for sender, ip in rows:
            if sender and ip:
                domain = sender.split("@")[-1].strip(" <>")
                upsert_email_graph(sender, ip, [domain] if domain else [])


def campaign_cards(db: Session, organization_id: str | None = None) -> list[dict]:
    _ensure_graph(db)
    clusters = find_campaigns()
    if not clusters:
        return []
    # Tenant isolation: scope emails/traces to caller's org unless Admin (None)
    if organization_id is None:
        emails = db.query(models.EmailRecord.id, models.EmailRecord.sender_address, models.EmailRecord.timestamp).all()
        traces = {t.email_id: t for t in db.query(models.TraceabilityData.email_id, models.TraceabilityData.origin_ip, models.TraceabilityData.isp_asn).all()}
    else:
        emails = db.query(models.EmailRecord.id, models.EmailRecord.sender_address, models.EmailRecord.timestamp).filter(
            models.EmailRecord.organization_id == organization_id).all()
        traces = {t.email_id: t for t in db.query(models.TraceabilityData.email_id, models.TraceabilityData.origin_ip, models.TraceabilityData.isp_asn
            ).join(models.EmailRecord, models.TraceabilityData.email_id == models.EmailRecord.id
            ).filter(models.EmailRecord.organization_id == organization_id).all()}

    cards: list[dict] = []
    for c in clusters:
        ip = c.get("ip") or ""
        domains = [d for d in (c.get("domains") or []) if d]
        if not ip or not domains:
            continue
        matched = []
        for e in emails:
            sender = (e.sender_address or "").lower()
            if any(sender.endswith("@" + d.lower()) or sender.endswith("@" + d.lower() + ">") for d in domains):
                matched.append(e)
                continue
            t = traces.get(e.id)
            if t and t.origin_ip == ip:
                matched.append(e)
        asns = Counter((traces[e.id].isp_asn or "").strip() for e in matched if traces.get(e.id) and (traces[e.id].isp_asn or "").strip())
        stamps = sorted(e.timestamp for e in matched if e.timestamp)
        email_count = len(matched)
        confidence = round(min(0.95, 0.45 + 0.10 * len(domains) + 0.03 * email_count), 2)
        cards.append({
            "id": _cid_for_ip(ip),
            "name": f"Campaign via {ip}",
            "ip": ip,
            "domains": sorted(domains),
            "asn": asns.most_common(1)[0][0] if asns else "",
            "confidence": confidence,
            "email_count": email_count,
            "first_seen": stamps[0].isoformat() if stamps else None,
            "last_seen": stamps[-1].isoformat() if stamps else None,
        })
    return sorted(cards, key=lambda k: (-k["email_count"], -k["confidence"]))


def campaign_detail(db: Session, cid: str, organization_id: str | None = None) -> dict | None:
    card = next((c for c in campaign_cards(db, organization_id=organization_id) if c["id"] == cid), None)
    if not card:
        return None
    if organization_id is None:
        emails = db.query(models.EmailRecord.id, models.EmailRecord.subject, models.EmailRecord.sender_address, models.EmailRecord.timestamp).all()
        traces = {t.email_id: t for t in db.query(models.TraceabilityData.email_id, models.TraceabilityData.origin_ip).all()}
        analyses = {a.email_id: a for a in db.query(models.AnalysisResult.email_id, models.AnalysisResult.fraud_score, models.AnalysisResult.threat_classification).all()}
    else:
        emails = db.query(models.EmailRecord.id, models.EmailRecord.subject, models.EmailRecord.sender_address, models.EmailRecord.timestamp).filter(
            models.EmailRecord.organization_id == organization_id).all()
        traces = {t.email_id: t for t in db.query(models.TraceabilityData.email_id, models.TraceabilityData.origin_ip
            ).join(models.EmailRecord, models.TraceabilityData.email_id == models.EmailRecord.id
            ).filter(models.EmailRecord.organization_id == organization_id).all()}
        analyses = {a.email_id: a for a in db.query(models.AnalysisResult.email_id, models.AnalysisResult.fraud_score, models.AnalysisResult.threat_classification
            ).join(models.EmailRecord, models.AnalysisResult.email_id == models.EmailRecord.id
            ).filter(models.EmailRecord.organization_id == organization_id).all()}
    rows = []
    for e in emails:
        sender = (e.sender_address or "").lower()
        hit = any(sender.endswith("@" + d.lower()) or sender.endswith("@" + d.lower() + ">") for d in card["domains"])
        t = traces.get(e.id)
        if not hit and not (t and t.origin_ip == card["ip"]):
            continue
        a = analyses.get(e.id)
        rows.append({
            "id": e.id,
            "subject": e.subject or "",
            "sender": e.sender_address or "",
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "fraud_score": a.fraud_score if a else 0.0,
            "classification": a.threat_classification if a else "—",
        })
    rows.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    return {"card": card, "graph": related_entities(card["ip"]), "emails": rows}
