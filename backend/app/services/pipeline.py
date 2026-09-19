"""End-to-end pipeline: AppFlow.md Ingest -> Process -> Correlate/Score -> Alert -> Store."""
import re
from sqlalchemy.orm import Session
from ..models import EmailRecord, AnalysisResult, TraceabilityData
from ..modules.ingestion.parser import parse_eml
from ..modules.forensics.received_chain import reconstruct_path, detect_routing_anomalies
from ..modules.forensics.header_parser import parse_headers
from ..modules.forensics.auth_validator import validate_all
from ..modules.traceability.ip_extractor import extract_origin_ip
from ..modules.traceability.geoip import geolocate
from ..modules.traceability.whois_dns import whois_lookup, dns_lookup, domain_age_days
from ..modules.traceability.vpn_tor import flag_infrastructure
from ..modules.nlp.engine import analyze_text
from ..modules.threat_intel.url_analyzer import extract_urls, analyze_urls
from ..modules.threat_intel.feeds import aggregate_threat_intel
from ..modules.correlation.scoring import compute_scores
from ..modules.graph.store import upsert_email_graph
from ..modules.graph.attribution import attribute
from ..modules.privacy.masking import mask_text
from ..modules.alerting.dispatcher import dispatch_alert


def _sender_domain(from_addr: str) -> str:
    m = re.search(r"@([\w.\-]+)", from_addr or "")
    return m.group(1).lower() if m else ""


async def process_raw_email(db: Session, raw: bytes, source: str = "api", envelope_from: str = "", unmask: bool = False) -> dict:
    parsed = parse_eml(raw)
    headers = parsed["raw_headers"]
    path = reconstruct_path(headers)
    hinfo = parse_headers(headers)
    routing_flags = detect_routing_anomalies(path, headers)
    origin_ip = extract_origin_ip(path)
    geo = geolocate(origin_ip)
    domain = _sender_domain(hinfo.get("from_addr") or parsed["sender_address"])
    whois = whois_lookup(domain)
    dnsd = dns_lookup(domain)
    age = domain_age_days(whois)
    infra = flag_infrastructure(origin_ip, str(geo.get("isp", "")), str(geo.get("asn", "")))
    auth = validate_all(raw, headers, origin_ip or "127.0.0.1", envelope_from or hinfo.get("return_path"))
    nlp = analyze_text(parsed["subject"], parsed["body_text"])
    urls = extract_urls(parsed["body_text"] + "\n" + parsed.get("body_html", ""))
    url_res = analyze_urls(urls)
    intel = aggregate_threat_intel([domain], [origin_ip] if origin_ip else [], urls)
    intel["malicious_count"] = url_res.get("malicious_count", 0)
    intel_hits = intel.get("hits", []) + [{"type": "url", **h} for h in url_res.get("hits", [])]
    contains_payment = bool(re.search(r"pay|wire|transfer|invoice|bank|payment", parsed["body_text"], re.I))
    scoring = compute_scores(nlp, auth, intel, routing_flags, hinfo.get("flags", []), age, contains_payment)

    masked_body = mask_text(parsed["body_text"], unmask=unmask)
    email_row = EmailRecord(
        message_id=parsed["message_id"], sender_address=parsed["sender_address"],
        recipient_address=parsed["recipient_address"], subject=parsed["subject"],
        raw_headers=headers, body_text=parsed["body_text"], body_text_masked=masked_body,
        attachments_metadata=parsed["attachments_metadata"], raw_eml_hash=parsed["raw_eml_hash"],
    )
    db.add(email_row)
    db.flush()

    trace_row = TraceabilityData(
        email_id=email_row.id, origin_ip=origin_ip, relay_chain=path,
        geolocation=geo, isp_asn=f"{geo.get('isp','')} {geo.get('asn','')}".strip(),
        is_vpn_tor=infra["is_vpn_tor"], whois_data=whois, dns_data=dnsd,
    )
    db.add(trace_row)
    analysis_row = AnalysisResult(
        email_id=email_row.id, fraud_score=scoring["fraud_score"],
        threat_classification=scoring["threat_classification"],
        nlp_cues_detected=nlp["nlp_cues_detected"] + routing_flags + hinfo.get("flags", []),
        authentication_results=auth,
        trace_summary={"origin_ip": origin_ip, "geo": geo, "relay_hops": len(path)},
        threat_intel_hits=intel_hits, action_taken=scoring["action"],
    )
    db.add(analysis_row)
    db.commit()

    attribution = attribute(hinfo.get("from_addr"), origin_ip, [domain] + [_d for _d in [u.split("/")[2] for u in urls[:10] if "://" in u] if "." in _d])
    upsert_email_graph(hinfo.get("from_addr"), origin_ip, [domain], campaign=str(attribution.get("campaign", "")))
    alert = dispatch_alert(email_row.id, scoring["fraud_score"], scoring["threat_classification"], scoring["breakdown"])

    return {
        "email_id": email_row.id, "fraud_score": scoring["fraud_score"],
        "classification": scoring["threat_classification"], "action": scoring["action"],
        "breakdown": scoring["breakdown"], "origin_ip": origin_ip, "geo": geo,
        "alert": alert, "attribution": attribution,
    }
