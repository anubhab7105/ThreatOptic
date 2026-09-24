"""Campaign cards built on graph clusters + SQLite forensic records.

No graph rewrites: uses store.find_campaigns() for the domain cluster behind
each shared IP, then joins EmailRecord/AnalysisResult/TraceabilityData to add
email counts, shared ASN, confidence, and first/last seen timestamps.

Tenant model (P0): the graph CLUSTERS are shared cross-tenant threat intel
(infra-level IPs/domains — no addresses/subjects), but every piece of
email-level metadata (cards' email lists/counts, embedded graph email
nodes) is scoped to the caller's org. Admins (is_admin=True) see all;
org-less non-admins see only null-org mail — never the global view.
Pass is_admin explicitly: organization_id=None alone means "org-less
user", NOT "admin".
"""
from collections import Counter
from sqlalchemy.orm import Session
from .. import models
from ..modules.graph.store import find_campaigns, related_entities

# Cap on addresses pulled for graph email-node filtering (fail closed
# beyond: unlisted addresses are hidden, never leaked).
GRAPH_EMAIL_ALLOWLIST_CAP = 20000


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


def _tenant_email_addresses(db: Session, organization_id: str | None) -> set[str]:
    """Exact sender/recipient addresses for one org (None => null-org mail).

    Used to hide foreign Email_Address nodes from graph output. Capped;
    beyond the cap unlisted addresses are hidden (fail closed).
    """
    from ..modules.graph.store import _clean_email
    rows = (db.query(models.EmailRecord.sender_address, models.EmailRecord.recipient_address)
            .filter(models.EmailRecord.organization_id == organization_id)
            .limit(GRAPH_EMAIL_ALLOWLIST_CAP).all())
    out: set[str] = set()
    for sender, recipient in rows:
        for raw in (sender, recipient):
            clean = _clean_email(raw or "")
            if clean:
                out.add(clean)
    return out


def _filter_graph_emails(graph: dict, allowed: set[str] | None) -> dict:
    """Drop Email_Address nodes not attributable to the caller.

    allowed=None (Admin) returns the graph unchanged. IP/Domain/Campaign
    nodes are shared threat intel and always stay; edges touching dropped
    nodes are removed so no dangling references leak.
    """
    if allowed is None or not isinstance(graph, dict):
        return graph
    nodes = []
    keep: set[str] = set()
    for n in graph.get("nodes", []) or []:
        if not isinstance(n, dict):
            continue
        nid = str(n.get("id", ""))
        if n.get("kind") == "Email_Address" or nid.startswith("email:"):
            addr = nid.split("email:", 1)[-1].lower() if "email:" in nid else ""
            if addr not in allowed:
                continue
        nodes.append(n)
        keep.add(nid)
    edges = [e for e in graph.get("edges", []) or []
             if isinstance(e, dict) and e.get("source") in keep and e.get("target") in keep]
    return {"nodes": nodes, "edges": edges}


def campaign_cards(db: Session, organization_id: str | None = None, *, is_admin: bool = False) -> list[dict]:
    _ensure_graph(db)
    clusters = find_campaigns()
    if not clusters:
        return []
    # Tenant isolation: Admin sees all; everyone else (including org-less
    # users, whose organization_id is None) sees only their own org scope.
    if is_admin:
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
