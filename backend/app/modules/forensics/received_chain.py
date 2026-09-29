"""Header parsing helpers + Received-chain traversal (Tracker Phase 2)."""
import ipaddress
import re
from typing import Any

# Candidate IPs (v4 + v6); every candidate is validated with ipaddress —
# 999.999.999.999 and friends never survive (Step 4).
IP_CANDIDATE_RE = re.compile(
    r"\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,}(?::[0-9a-fA-F:]*)+)\]?"
)
# e.g. from mail.example.com (host [1.2.3.4]) by mx.google.com with ESMTPS id ...
RECEIVED_FROM_RE = re.compile(r"from\s+([^\s\(\)]+)?\s*(?:\(([^\)]*)\))?", re.IGNORECASE)
RECEIVED_BY_RE = re.compile(r"\bby\s+([^\s;]+)", re.IGNORECASE)


def _valid_ip(candidate: str) -> str | None:
    try:
        return str(ipaddress.ip_address(candidate.strip("[]")))
    except ValueError:
        return None


def split_received(raw_headers: dict[str, Any]) -> list[str]:
    """Return Received headers in wire order (top-most first).

    Unfolds RFC 5322 continuations first, then splits ONLY on real header
    boundaries (a newline followed by a non-whitespace char) so folded
    multi-line Received headers don't become fake hops (Step 4).
    """
    val = raw_headers.get("Received", "")
    if isinstance(val, list):
        return [str(v).replace("\r\n", "\n").replace("\r", "\n").strip()
                for v in val if str(v).strip()]
    text = str(val).replace("\r\n", "\n").replace("\r", "\n")
    # unfold: newline + whitespace is a continuation, not a boundary
    unfolded = re.sub(r"\n[ \t]+", " ", text)
    # split on real boundaries: newline followed by non-whitespace
    parts = [p.strip() for p in re.split(r"\n(?=\S)", unfolded) if p.strip()]
    return parts


def parse_received_hop(header: str) -> dict[str, Any]:
    ips = [ip for ip in (_valid_ip(c) for c in IP_CANDIDATE_RE.findall(header)) if ip]
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


def _registrable(domain: str) -> str:
    from .psl import registrable_domain
    return registrable_domain(domain)


def _clean_domain(raw: str) -> str:
    m = re.search(r"@([\w.\-]+)", (raw or "").lower())
    return (m.group(1).strip("<> ") if m else "").rstrip(".")


def detect_routing_anomalies(path: list[dict], raw_headers: dict) -> list[str]:
    flags: list[str] = []
    if len(path) == 0:
        flags.append("missing-received-chain")
    if len(path) == 1:
        flags.append("single-hop-suspicious")
    # forged sender: From domain vs Return-Path domain mismatch
    rp_dom = _clean_domain(str(raw_headers.get("Return-Path", "")))
    frm_dom = _clean_domain(str(raw_headers.get("From", "")))
    from .psl import same_organization
    # Same-organization comparison (PSL-aware): bounce@mail.company.com vs
    # ceo@company.com is legitimate; bounce@evil.test vs ceo@company.com
    # is not. Exact-match false-positived on legitimate subdomains.
    if rp_dom and frm_dom and not same_organization(rp_dom, frm_dom):
        flags.append("return-path-mismatch")
    # Message-ID domain vs From domain, compared by REGISTRABLE domain so
    # mail.paypal.com vs paypal.com no longer false-positives (Step 4).
    mid_dom = _clean_domain(str(raw_headers.get("Message-ID", "")))
    if mid_dom and frm_dom and not same_organization(mid_dom, frm_dom):
        flags.append("message-id-mismatch")
    return flags
