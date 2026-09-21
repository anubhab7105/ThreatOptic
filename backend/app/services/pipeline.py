"""End-to-end pipeline: AppFlow.md Ingest -> Process -> Correlate/Score -> Alert -> Store.

Robustness contract: a single enrichment failing (DNS down, lib missing, weird
MIME) must NEVER fail the whole ingestion. Each stage is guarded; blocking
network lookups run in threads with tight timeouts and are disabled by default
(ENABLE_LIVE_LOOKUPS=1 to opt in).
"""
import asyncio
from datetime import datetime, timezone
import logging
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
from ..modules.threat_intel.url_analyzer import extract_urls, analyze_urls, domain_of
from ..modules.threat_intel.attachment_analyzer import analyze_attachments
from ..modules.threat_intel.feeds import aggregate_threat_intel
from ..modules.correlation.scoring import compute_scores
from ..modules.graph.store import upsert_email_graph
from ..modules.graph.attribution import attribute
from ..modules.privacy.masking import mask_text
from ..modules.alerting.dispatcher import dispatch_alert

log = logging.getLogger("pipeline")


def _sender_domain(from_addr: str) -> str:
    m = re.search(r"@([\w.\-]+)", from_addr or "")
    return m.group(1).lower().rstrip(".") if m else ""


def _url_domains(urls: list[str]) -> list[str]:
    out: list[str] = []
    for u in urls[:10]:
        try:
            d = domain_of(u)
            if d and "." in d and d not in out:
                out.append(d)
        except Exception:
            continue
    return out


async def _to_thread(fn, *args, **kwargs):
    try:
        return await asyncio.to_thread(fn, *args, **kwargs)
    except Exception as e:
        log.warning("enrichment %s failed: %s", getattr(fn, "__name__", fn), e)
        return None


async def process_raw_email(db: Session, raw: bytes, source: str = "api", envelope_from: str = "",
                      organization_id: str | None = None) -> dict:
    if not raw or not raw.strip():
        raise ValueError("empty email payload")

    parsed = parse_eml(raw)
    headers = parsed.get("raw_headers", {})

    try:
        path = reconstruct_path(headers)
    except Exception as e:
        log.warning("reconstruct_path failed: %s", e)
        path = []
    try:
        hinfo = parse_headers(headers)
    except Exception as e:
        log.warning("parse_headers failed: %s", e)
        hinfo = {"from_addr": parsed.get("sender_address", ""), "return_path": "", "flags": []}
    try:
        routing_flags = detect_routing_anomalies(path, headers)
    except Exception:
        routing_flags = []

    try:
        origin_ip = extract_origin_ip(path) or ""
    except Exception:
        origin_ip = ""

    # Blocking enrichment concurrently in threads (each is internally guarded).
    geo, whois, dnsd, infra, auth = await asyncio.gather(
        _to_thread(geolocate, origin_ip),
        _to_thread(whois_lookup, _sender_domain(hinfo.get("from_addr") or parsed.get("sender_address", ""))),
        _to_thread(dns_lookup, _sender_domain(hinfo.get("from_addr") or parsed.get("sender_address", ""))),
        _to_thread(flag_infrastructure, origin_ip, "", ""),
        _to_thread(validate_all, raw, headers, origin_ip or "127.0.0.1", envelope_from or hinfo.get("return_path", "")),
    )
    geo = geo or {"lat": 0.0, "lon": 0.0, "country": "", "city": "", "source": "fallback"}
    whois = whois or {}
    dnsd = dnsd or {}
    infra = infra or {"is_vpn_tor": False, "infra_flags": []}
    auth = auth or {"spf": {}, "dkim": {}, "dmarc": {}, "aligned": False}

    domain = _sender_domain(hinfo.get("from_addr") or parsed.get("sender_address", ""))

    # If origin_ip gave no coordinates, try relay hops or sender domain IP for approximate geolocation
    if not geo or (geo.get("lat") == 0.0 and geo.get("lon") == 0.0):
        for hop in (path or []):
            for hop_ip in hop.get("ips", []):
                g = geolocate(hop_ip)
                if g and (g.get("lat") != 0.0 or g.get("lon") != 0.0):
                    geo = g
                    break
            if geo and (geo.get("lat") != 0.0 or geo.get("lon") != 0.0):
                break
    if not geo or (geo.get("lat") == 0.0 and geo.get("lon") == 0.0):
        try:
            import socket
            if domain:
                dip = socket.gethostbyname(domain)
                g = geolocate(dip)
                if g and (g.get("lat") != 0.0 or g.get("lon") != 0.0):
                    geo = {**g, "source": "approx-domain-ip"}
        except Exception:
            pass

    # geo may lack isp/asn when offline — refresh infra flags with what we have
    try:
        infra = flag_infrastructure(origin_ip, str(geo.get("isp", "")), str(geo.get("asn", "")))
    except Exception:
        pass
    try:
        age = domain_age_days(whois)
    except Exception:
        age = None

    try:
        urls = extract_urls((parsed.get("body_text") or "") + "\n" + (parsed.get("body_html") or ""))
    except Exception:
        urls = []

    import os
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")

    nlp_res, url_res, attach_res = await asyncio.gather(
        _to_thread(analyze_text, parsed.get("subject", ""), parsed.get("body_text", "")),
        _to_thread(analyze_urls, urls, vt_key),
        _to_thread(analyze_attachments, parsed.get("attachments_metadata", []), vt_key),
        return_exceptions=True,
    )
    nlp = nlp_res if isinstance(nlp_res, dict) else {"ml_score": 0.0, "ml_label": "clean", "nlp_cues_detected": [], "impersonation_cues": []}
    url_res = url_res if isinstance(url_res, dict) else {"urls": urls[:50], "hits": [], "malicious_count": 0}
    attach_res = attach_res if isinstance(attach_res, dict) else {"findings": [], "risk": 0.0, "malicious_count": 0}

    try:
        intel = await _to_thread(aggregate_threat_intel, [domain] if domain else [], [origin_ip] if origin_ip else [], urls)
    except Exception as e:
        log.warning("threat intel failed: %s", e)
        intel = {"hits": [], "count": 0}
    intel["malicious_count"] = url_res.get("malicious_count", 0)
    intel_hits = intel.get("hits", []) + [{"type": "url", **h} for h in url_res.get("hits", [])]
    intel_hits += [{"type": "attachment", **f} for f in attach_res.get("findings", [])]

    body = parsed.get("body_text", "") or ""
    contains_payment = bool(re.search(r"pay|wire|transfer|invoice|bank|payment", body, re.I))
    try:
        scoring = compute_scores(nlp, auth, intel, routing_flags, hinfo.get("flags", []), age, contains_payment,
                                 attachment=attach_res)
    except Exception as e:
        log.warning("scoring failed: %s", e)
        scoring = {"fraud_score": 0.0, "classification": "Clean", "threat_classification": "Clean",
                   "action": "Deliver", "breakdown": {}, "signals": []}

    masked_body = mask_text(body)
    email_row = EmailRecord(
        message_id=parsed.get("message_id", ""), sender_address=parsed.get("sender_address", ""),
        recipient_address=parsed.get("recipient_address", ""), subject=parsed.get("subject", ""),
        # Step 3: raw body_text is NEVER persisted — only the masked version.
        # The raw body lives in memory for this run (scoring/masking) and is dropped.
        raw_headers=headers, body_text="", body_text_masked=masked_body,
        attachments_metadata=parsed.get("attachments_metadata", []), raw_eml_hash=parsed.get("raw_eml_hash", ""),
        timestamp=parsed.get("timestamp") or datetime.now(timezone.utc),
        organization_id=organization_id,
    )
    db.add(email_row)
    db.flush()

    trace_row = TraceabilityData(
        email_id=email_row.id, origin_ip=origin_ip, relay_chain=path,
        geolocation=geo, isp_asn=f"{geo.get('isp','')} {geo.get('asn','')}".strip(),
        is_vpn_tor=bool(infra.get("is_vpn_tor")), whois_data=whois, dns_data=dnsd,
    )
    db.add(trace_row)
    analysis_row = AnalysisResult(
        email_id=email_row.id, fraud_score=scoring["fraud_score"],
        threat_classification=scoring["threat_classification"],
        nlp_cues_detected=list(nlp.get("nlp_cues_detected", [])) + list(routing_flags) + list(hinfo.get("flags", [])),
        authentication_results=auth,
        trace_summary={"origin_ip": origin_ip, "geo": geo, "relay_hops": len(path)},
        threat_intel_hits=intel_hits, action_taken=scoring["action"],
        score_breakdown=scoring.get("signals", []),
    )
    db.add(analysis_row)
    db.commit()

    try:
        attribution = attribute(hinfo.get("from_addr", ""), origin_ip, ([domain] if domain else []) + _url_domains(urls))
    except Exception as e:
        log.warning("attribution failed: %s", e)
        attribution = {"campaign": "unknown", "confidence": 0.0, "signals": []}
    try:
        from ..modules.search.elastic_sync import index_email
        index_email(email_row.id,
                    {"subject": email_row.subject, "sender_address": email_row.sender_address,
                     "recipient_address": email_row.recipient_address, "body_text_masked": masked_body,
                     "organization_id": email_row.organization_id},
                    {"fraud_score": scoring["fraud_score"],
                     "threat_classification": scoring["threat_classification"]})
    except Exception as e:
        log.warning("elastic mirror failed: %s", e)
    try:
        upsert_email_graph(hinfo.get("from_addr", ""), origin_ip, [domain] if domain else [],
                           campaign=str(attribution.get("campaign", "")))
    except Exception as e:
        log.warning("graph upsert failed: %s", e)
    try:
        alert = dispatch_alert(email_row.id, scoring["fraud_score"], scoring["threat_classification"], scoring.get("breakdown", {}))
    except Exception as e:
        log.warning("alert dispatch failed: %s", e)
        alert = {"severity": "Low", "action": scoring.get("action", "Deliver"), "sent": ["dashboard"]}

    return {
        "email_id": email_row.id, "fraud_score": scoring["fraud_score"],
        "classification": scoring["threat_classification"], "action": scoring["action"],
        "breakdown": scoring.get("breakdown", {}), "signals": scoring.get("signals", []),
        "origin_ip": origin_ip, "geo": geo,
        "alert": alert, "attribution": attribution,
    }
