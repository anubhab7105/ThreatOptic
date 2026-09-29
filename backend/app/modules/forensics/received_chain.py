
import ipaddress
import re
from typing import Any



IP_CANDIDATE_RE = re.compile(
    r"\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,}(?::[0-9a-fA-F:]*)+)\]?"
)

RECEIVED_FROM_RE = re.compile(r"from\s+([^\s\(\)]+)?\s*(?:\(([^\)]*)\))?", re.IGNORECASE)
RECEIVED_BY_RE = re.compile(r"\bby\s+([^\s;]+)", re.IGNORECASE)


def _valid_ip(candidate: str) -> str | None:
    try:
        return str(ipaddress.ip_address(candidate.strip("[]")))
    except ValueError:
        return None


def split_received(raw_headers: dict[str, Any]) -> list[str]:

    val = raw_headers.get("Received", "")
    if isinstance(val, list):
        return [str(v).replace("\r\n", "\n").replace("\r", "\n").strip()
                for v in val if str(v).strip()]
    text = str(val).replace("\r\n", "\n").replace("\r", "\n")

    unfolded = re.sub(r"\n[ \t]+", " ", text)

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

    rp_dom = _clean_domain(str(raw_headers.get("Return-Path", "")))
    frm_dom = _clean_domain(str(raw_headers.get("From", "")))
    from .psl import same_organization



    if rp_dom and frm_dom and not same_organization(rp_dom, frm_dom):
        flags.append("return-path-mismatch")


    mid_dom = _clean_domain(str(raw_headers.get("Message-ID", "")))
    if mid_dom and frm_dom and not same_organization(mid_dom, frm_dom):
        flags.append("message-id-mismatch")
    return flags
