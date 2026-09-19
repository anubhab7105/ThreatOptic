"""Forensic report generator: PDF (reportlab) + JSON, with PII masking + custody manifest."""
import io
import json
from typing import Any
from ..privacy.masking import mask_text
from ..privacy.chain_of_custody import custody_manifest


def build_report_json(email: dict, analysis: dict, trace: dict, attribution: dict, unmask: bool = False) -> dict:
    mail_masked = dict(email)
    if "body_text" in mail_masked:
        mail_masked["body_text"] = mask_text(mail_masked.get("body_text", ""), unmask=unmask)
    return {
        "email": mail_masked,
        "analysis": analysis,
        "traceability": trace,
        "attribution": attribution,
    }


def build_report_pdf(email: dict, analysis: dict, trace: dict, attribution: dict) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Email Forensic Report — Chain of Custody Compliant", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Subject: {email.get('subject','')[:300]}", styles["Normal"]),
        Paragraph(f"From: {mask_text(email.get('sender_address',''))} | To: {mask_text(email.get('recipient_address',''))}", styles["Normal"]),
        Paragraph(f"Message-ID: {email.get('message_id','')} | SHA256: {email.get('raw_eml_hash','')}", styles["Normal"]),
        Spacer(1, 12),
        Paragraph(f"Fraud Score: {analysis.get('fraud_score')} ({analysis.get('threat_classification')}) — Action: {analysis.get('action_taken')}", styles["Heading2"]),
        Paragraph(f"Cues: {', '.join(analysis.get('nlp_cues_detected', []))}", styles["Normal"]),
        Paragraph(f"Auth: {json.dumps(analysis.get('authentication_results', {}))[:1000]}", styles["Normal"]),
        Spacer(1, 12),
        Paragraph("Traceability", styles["Heading2"]),
        Paragraph(f"Origin IP: {trace.get('origin_ip')} | Geo: {json.dumps(trace.get('geolocation', {}))[:500]}", styles["Normal"]),
        Paragraph(f"VPN/TOR: {trace.get('is_vpn_tor')} | ISP/ASN: {trace.get('isp_asn','')}", styles["Normal"]),
        Spacer(1, 6),
        Paragraph("Relay chain:", styles["Heading3"]),
    ]
    rows = [["#", "From", "By", "IPs"]]
    for i, h in enumerate(trace.get("relay_chain", [])[:20]):
        rows.append([i, str(h.get("from_host",""))[:40], str(h.get("by_host",""))[:40], ",".join(h.get("ips", []))[:40]])
    story.append(Table(rows, colWidths=[20, 150, 150, 150], style=TableStyle([("BACKGROUND", (0,0), (-1,0), colors.grey), ("GRID", (0,0), (-1,-1), 0.5, colors.black)])))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Attribution: {attribution.get('campaign')} (conf={attribution.get('confidence')}) signals={attribution.get('signals')}", styles["Normal"]))
    doc.build(story)
    return buf.getvalue()


def build_full_report(email: dict, analysis: dict, trace: dict, attribution: dict) -> tuple[bytes, bytes, dict]:
    j = build_report_json(email, analysis, trace, attribution)
    j_bytes = json.dumps(j, indent=2, default=str).encode()
    pdf = build_report_pdf(email, analysis, trace, attribution)
    manifest = custody_manifest(email.get("raw_eml_hash", ""), pdf)
    return pdf, j_bytes, manifest
