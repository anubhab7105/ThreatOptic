
import io
import json
from ..privacy.masking import mask_text
from ..privacy.chain_of_custody import custody_manifest


def build_report_json(email: dict, analysis: dict, trace: dict, attribution: dict) -> dict:
    mail_masked = dict(email)
    if "body_text" in mail_masked:
        mail_masked["body_text"] = mask_text(mail_masked.get("body_text", ""))

    for key in ("subject", "sender_address", "recipient_address"):
        if key in mail_masked:
            mail_masked[key] = mask_text(mail_masked.get(key, "") or "")
    return {
        "email": mail_masked,
        "analysis": analysis,
        "traceability": trace,
        "attribution": attribution,
    }


def build_report_pdf(email: dict, analysis: dict, trace: dict, attribution: dict) -> bytes:
    import html
    from datetime import datetime, timezone
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors

    def _esc(val) -> str:
        return html.escape(str(val or ""))

    def _auth_val(auth: dict, key: str) -> str:
        v = auth.get(key, "NONE")
        if isinstance(v, dict):
            v = v.get("status") or v.get("result") or "NONE"
        return str(v).upper()

    def _geo_str(geo: dict) -> str:
        if not isinstance(geo, dict) or not geo:
            return "Unknown / Offline Fallback"
        parts = [geo.get("city"), geo.get("region"), geo.get("country")]
        parts = [p for p in parts if p and p.strip()]
        return ", ".join(parts) if parts else "Unknown"

    def _format_cue(cue: str) -> str:
        s = str(cue)
        if s.startswith("urgency:"):
            return f"High Urgency Language (Level {s.split(':')[-1]}/10)"
        if s.startswith("lookalike-domain:"):
            parts = s.split(":")
            return f"Lookalike Domain Spoofing (target: {parts[1] if len(parts) > 1 else 'brand'})"
        cues_map = {
            "impersonation": "Executive / VIP Impersonation",
            "bec-pattern": "Business Email Compromise (BEC) Wire Pattern",
            "credential-harvest": "Credential Harvesting / Suspicious Login Prompt",
            "return-path-mismatch": "Return-Path / From Header Inconsistency",
            "display-name-spoof": "Display Name Spoofing Detected",
            "punycode-domain": "Punycode (IDN) Lookalike Domain",
            "suspicious-attachment": "Suspicious / Macro Attachment Payload",
        }
        return cues_map.get(s, s.replace("-", " ").title())

    fraud_score = float(analysis.get("fraud_score") or 0.0)
    threat_class = str(analysis.get("threat_classification") or "Unclassified")
    action_taken = str(analysis.get("action_taken") or "Review")


    if fraud_score >= 70 or "high" in threat_class.lower() or "critical" in threat_class.lower():
        risk_color = colors.HexColor("#DC2626")
        risk_bg = colors.HexColor("#FEE2E2")
        risk_label = "HIGH RISK"
    elif fraud_score >= 35 or "medium" in threat_class.lower() or "suspicious" in threat_class.lower():
        risk_color = colors.HexColor("#D97706")
        risk_bg = colors.HexColor("#FEF3C7")
        risk_label = "SUSPICIOUS"
    else:
        risk_color = colors.HexColor("#16A34A")
        risk_bg = colors.HexColor("#DCFCE7")
        risk_label = "LOW RISK"

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=32,
        bottomMargin=32,
    )

    styles = getSampleStyleSheet()


    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=18,
        textColor=colors.HexColor("#0F172A"),
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#64748B"),
    )
    section_head = ParagraphStyle(
        "SectionHead",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=8,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#334155"),
    )
    bold_label = ParagraphStyle(
        "BoldLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#1E293B"),
    )
    mono_style = ParagraphStyle(
        "MonoStyle",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#0F172A"),
    )

    story = []


    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header_data = [
        [
            Paragraph("EMAIL FORENSIC INTELLIGENCE & THREAT REPORT", title_style),
            Paragraph(f"<b>Classification:</b> RESTRICTED / SOC<br/><b>Generated:</b> {now_str}", subtitle_style),
        ]
    ]
    header_table = Table(header_data, colWidths=[340, 183])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0F172A"), spaceBefore=2, spaceAfter=8))


    exec_summary_text = (
        f"<b>Executive Summary:</b> Email evaluated with a fraud score of <b>{fraud_score:.1f}/100</b> "
        f"and classified as <b>{_esc(threat_class)}</b>. "
    )
    if fraud_score >= 70:
        exec_summary_text += "Urgent security risk detected. Significant anomalies present in sender headers, message semantics, or routing hops. Recommend immediate quarantine or blocking."
    elif fraud_score >= 35:
        exec_summary_text += "Elevated suspicion score. Routing anomalies or authentication gaps detected. Exercise caution and verify out-of-band."
    else:
        exec_summary_text += "No prominent threat indicators detected. Standard email authentication and routing parameters observed."

    kpi_data = [
        [
            Paragraph("<font size=7 color='#64748B'>THREAT CLASSIFICATION</font><br/>"
                      f"<b><font size=11 color='{risk_color.hexval()}'>{_esc(threat_class)}</font></b>", body_style),
            Paragraph("<font size=7 color='#64748B'>FRAUD SCORE</font><br/>"
                      f"<b><font size=12 color='{risk_color.hexval()}'>{fraud_score:.1f} / 100</font></b>", body_style),
            Paragraph("<font size=7 color='#64748B'>RECOMMENDED ACTION</font><br/>"
                      f"<b><font size=11 color='#1E293B'>{_esc(action_taken)}</font></b>", body_style),
        ],
        [
            Paragraph(exec_summary_text, body_style),
            "",
            "",
        ]
    ]
    kpi_table = Table(kpi_data, colWidths=[174, 174, 175])
    kpi_table.setStyle(TableStyle([
        ("SPAN", (0, 1), (2, 1)),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 1, risk_color),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, colors.HexColor("#E2E8F0")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 10))


    story.append(Paragraph("1. Email Identity & Metadata", section_head))
    
    subject_val = _esc(mask_text(email.get("subject", "(no subject)"))[:120])
    sender_val = _esc(mask_text(email.get("sender_address", "Unknown")))
    recipient_val = _esc(mask_text(email.get("recipient_address", "Unknown")))
    msg_id_val = _esc(email.get("message_id", "N/A")[:55])
    hash_val = _esc(email.get("raw_eml_hash", "N/A"))

    meta_data = [
        [Paragraph("Subject", bold_label), Paragraph(subject_val, body_style),
         Paragraph("Date / Time", bold_label), Paragraph(_esc(str(email.get("timestamp", "N/A"))[:19]), body_style)],
        [Paragraph("From (Sender)", bold_label), Paragraph(sender_val, body_style),
         Paragraph("To (Recipient)", bold_label), Paragraph(recipient_val, body_style)],
        [Paragraph("Message-ID", bold_label), Paragraph(msg_id_val, mono_style),
         Paragraph("Origin IP", bold_label), Paragraph(_esc(trace.get("origin_ip", "Unresolved")), mono_style)],
        [Paragraph("SHA-256 Hash", bold_label), Paragraph(hash_val, mono_style), "", ""],
    ]
    meta_table = Table(meta_data, colWidths=[75, 185, 75, 188])
    meta_table.setStyle(TableStyle([
        ("SPAN", (1, 3), (3, 3)),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F1F5F9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))


    story.append(Paragraph("2. Authentication & Threat Indicators", section_head))
    auth_data = analysis.get("authentication_results") or {}
    spf_res = _auth_val(auth_data, "spf")
    dkim_res = _auth_val(auth_data, "dkim")
    dmarc_res = _auth_val(auth_data, "dmarc")
    aligned_res = "YES (Aligned)" if auth_data.get("aligned") else "NO (Unaligned)"

    def _auth_badge_color(st: str) -> str:
        s_upper = str(st or "").upper()
        if any(w in s_upper for w in ("PASS", "YES (ALIGNED)", "ALIGNED", "FOUND")):
            return "#16A34A"
        if any(w in s_upper for w in ("FAIL", "REJECT", "UNALIGNED", "NO (UNALIGNED)")):
            return "#DC2626"
        if any(w in s_upper for w in ("SOFTFAIL", "NEUTRAL", "TEMPERROR", "PERMERROR")):
            return "#D97706"
        return "#64748B"

    auth_table_data = [
        [
            Paragraph(f"<b>SPF:</b> <font color='{_auth_badge_color(spf_res)}'>{_esc(spf_res)}</font>", body_style),
            Paragraph(f"<b>DKIM:</b> <font color='{_auth_badge_color(dkim_res)}'>{_esc(dkim_res)}</font>", body_style),
            Paragraph(f"<b>DMARC:</b> <font color='{_auth_badge_color(dmarc_res)}'>{_esc(dmarc_res)}</font>", body_style),
            Paragraph(f"<b>Domain Alignment:</b> <font color='{_auth_badge_color(aligned_res)}'>{_esc(aligned_res)}</font>", body_style),
        ]
    ]
    auth_table = Table(auth_table_data, colWidths=[130, 130, 130, 133])
    auth_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 6))


    cues = analysis.get("nlp_cues_detected") or []
    if cues:
        cues_formatted = [_format_cue(c) for c in cues]
        cues_text = " · ".join(cues_formatted)
        story.append(Paragraph(f"<b>Detected Threat Cues:</b> <font color='#991B1B'>{_esc(cues_text)}</font>", body_style))
    else:
        story.append(Paragraph("<b>Detected Threat Cues:</b> None (no NLP deception patterns identified)", body_style))
    story.append(Spacer(1, 10))


    story.append(Paragraph("3. Origin Geolocation & Infrastructure Trace", section_head))
    geo_data = trace.get("geolocation") or {}
    geo_loc = _geo_str(geo_data)
    isp_asn = str(trace.get("isp_asn") or "Not Identified")
    vpn_tor_val = "FLAGGED (VPN / Tor / Proxy Detected)" if trace.get("is_vpn_tor") else "None (Direct ISP Route)"
    camp_val = attribution.get("campaign") or "None (Isolated / Uncorrelated)"
    conf_val = f"{float(attribution.get('confidence', 0))*100:.0f}%" if attribution.get("confidence") else "N/A"

    trace_summary_data = [
        [Paragraph("True Origin IP", bold_label), Paragraph(_esc(trace.get("origin_ip", "N/A")), mono_style),
         Paragraph("Geolocation", bold_label), Paragraph(_esc(geo_loc), body_style)],
        [Paragraph("ISP / Organization", bold_label), Paragraph(_esc(isp_asn[:40]), body_style),
         Paragraph("Anonymizer Check", bold_label), Paragraph(f"<font color='{'#DC2626' if trace.get('is_vpn_tor') else '#16A34A'}'>{_esc(vpn_tor_val)}</font>", body_style)],
        [Paragraph("Campaign Cluster", bold_label), Paragraph(f"{_esc(camp_val)} (Confidence: {_esc(conf_val)})", body_style), "", ""],
    ]
    trace_table = Table(trace_summary_data, colWidths=[100, 160, 95, 168])
    trace_table.setStyle(TableStyle([
        ("SPAN", (1, 2), (3, 2)),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F1F5F9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(trace_table)
    story.append(Spacer(1, 10))


    relays = trace.get("relay_chain") or []
    if relays:
        story.append(Paragraph("4. Server Routing & Relay Chain Hops", section_head))
        relay_rows = [
            [
                Paragraph("<b>#</b>", bold_label),
                Paragraph("<b>From Server</b>", bold_label),
                Paragraph("<b>By Server</b>", bold_label),
                Paragraph("<b>IP Addresses</b>", bold_label),
            ]
        ]
        for i, h in enumerate(relays[:6]):
            from_h = str(h.get("from_host") or h.get("from_info") or "—")[:32]
            by_h = str(h.get("by_host") or "—")[:32]
            ips_str = ", ".join(h.get("ips") or [])[:30] or "—"
            relay_rows.append([
                Paragraph(str(i + 1), body_style),
                Paragraph(_esc(from_h), mono_style),
                Paragraph(_esc(by_h), mono_style),
                Paragraph(_esc(ips_str), mono_style),
            ])
        relay_table = Table(relay_rows, colWidths=[20, 165, 165, 173])
        relay_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("PADDING", (0, 0), (-1, -1), 3.5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(relay_table)
        story.append(Spacer(1, 12))


    footer_text = (
        f"<b>Chain of Custody Notice:</b> This forensic intelligence report was generated automatically by the "
        f"SOC Threat Detection Platform. Evidence integrity verified via SHA-256 custody tree ({hash_val[:24]}...). "
        f"Strictly confidential and restricted to authorized security analysts."
    )
    story.append(KeepTogether([
        HRFlowable(width="100%", thickness=0.8, color=colors.HexColor("#94A3B8"), spaceBefore=4, spaceAfter=4),
        Paragraph(footer_text, ParagraphStyle("Footer", parent=styles["Normal"], fontName="Helvetica", fontSize=7, leading=9, textColor=colors.HexColor("#64748B"))),
    ]))

    doc.build(story)
    return buf.getvalue()



def build_full_report(email: dict, analysis: dict, trace: dict, attribution: dict) -> tuple[bytes, bytes, dict]:
    j = build_report_json(email, analysis, trace, attribution)
    j_bytes = json.dumps(j, indent=2, default=str).encode()
    pdf = build_report_pdf(email, analysis, trace, attribution)

    import hashlib
    pdf_hash = hashlib.sha256(pdf).hexdigest()
    json_hash = hashlib.sha256(j_bytes).hexdigest()

    manifest = custody_manifest(email.get("raw_eml_hash", ""), pdf + j_bytes)
    manifest["pdf_sha256"] = pdf_hash
    manifest["json_sha256"] = json_hash
    manifest["combined_report_hash"] = hashlib.sha256(pdf + j_bytes).hexdigest()
    return pdf, j_bytes, manifest
