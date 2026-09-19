"""Header parsing helpers + Received-chain traversal (Tracker Phase 2)."""
import re
from typing import Any

IP_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
# e.g. from mail.example.com (host [1.2.3.4]) by mx.google.com with ESMTPS id ...
RECEIVED_FROM_RE = re.compile(r"from\s+([^\s\(\)]+)?\s*(?:\(([^\)]*)\))?", re.IGNORECASE)
RECEIVED_BY_RE = re.compile(r"\bby\s+([^\s;]+)", re.IGNORECASE)


def split_received(raw_headers: dict[str, Any]) -> list[str]:
    """Return Received headers in wire order (top-most first)."""
    val = raw_headers.get("Received", "")
    if isinstance(val, list):
        return [str(v) for v in val]
    # parser joins duplicates with newline
    parts = [p.strip() for p in str(val).split("\n") if p.strip()]
    return parts if parts else []


def parse_received_hop(header: str) -> dict[str, Any]:
    ips = IP_RE.findall(header)
    m_from = RECEIVED_FROM_RE.search(header)
    m_by = RECEIVED_BY_RE.search(header)
    return {
        "raw": header,
        "from_host": (m_from.group(1) if m_from else "") or "",
        "from_info": (m_from.group(2) if m_from else "") or "",
        "by_host": (m_by.group(1) if m_by else "") or "",
        "ips": ips,
    }


def reconstruct_path(raw_headers: dict[str, Any]) -> list[dict[str, Any]]:
    """Chronological path: reverse wire order (origin first)."""
    wire = split_received(raw_headers)
    hops = [parse_received_hop(h) for h in wire]
    hops.reverse()
    return hops


def detect_routing_anomalies(path: list[dict], raw_headers: dict) -> list[str]:
    flags: list[str] = []
    if len(path) == 0:
        flags.append("missing-received-chain")
    if len(path) == 1:
        flags.append("single-hop-suspicious")
    # forged sender: From domain vs Return-Path domain mismatch
    rp = str(raw_headers.get("Return-Path", "")).lower()
    frm = str(raw_headers.get("From", "")).lower()
    import re as _re
    rp_dom = (_re.search(r"@([\w\.\-]+)", rp) or [None, ""])[1]
    frm_dom = (_re.search(r"@([\w\.\-]+)", frm) or [None, ""])[1]
    if rp_dom and frm_dom and rp_dom.strip("<> ") != frm_dom.strip("<> "):
        flags.append("return-path-mismatch")
    # Message-ID domain vs From domain
    mid = str(raw_headers.get("Message-ID", "")).lower()
    mid_dom = (_re.search(r"@([\w\.\-]+)", mid) or [None, ""])[1]
    if mid_dom and frm_dom and mid_dom.strip("> ") not in frm_dom:
        flags.append("message-id-mismatch")
    return flags
