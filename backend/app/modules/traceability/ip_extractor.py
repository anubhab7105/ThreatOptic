"""Originating IP extraction with trust-boundary logic (Step 4 + Extended Forensic Headers).

Received headers are prepended by each relay, so the EARLIEST hops are the
most spoofable: anyone can invent `Received` lines above their own. The
trustworthy signal is the LAST-EXTERNAL hop — the first relay in wire
order (top-most) that is not ours: our own infrastructure's `by` host (or
a host/IP we recognize) marks the trust boundary, and the hop just below
it is the last IP the attacker could not forge.

When Received headers lack public IPs or are absent, we inspect explicit
originating headers (X-Originating-IP, X-Sender-IP, X-Client-IP, X-Real-IP,
X-Forwarded-For) and SPF / Authentication-Results client-ip signatures.
"""
import ipaddress
import os
import re
from typing import Any

# Candidate IPs (v4 + v6). The lookbehind pins each match to the start of a
# run so findall cannot re-scan it per offset; without it a long colon-free
# hex run is quadratic (~28s at 64KB). Every candidate is validated by
# _valid_ip()/ipaddress, so this stays a candidate scanner, not a matcher.
IP_REGEX = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:]*)"
)


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.strip("[] "))
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except Exception:
        return True


def _valid_ip(candidate: str) -> str | None:
    try:
        return str(ipaddress.ip_address(str(candidate).strip("[] ")))
    except Exception:
        return None


def _known_ours() -> tuple[set[str], set[str]]:
    """(host suffixes, ips) identifying our own infrastructure."""
    hosts = {h.strip().lower() for h in os.environ.get("TRUSTED_RELAY_HOSTS", "").split(",") if h.strip()}
    ips = {i.strip() for i in os.environ.get("TRUSTED_RELAY_IPS", "").split(",") if i.strip()}
    try:
        from ...config import get_settings
        s = get_settings()
        hosts |= {h.strip().lower() for h in str(getattr(s, "trusted_relay_hosts", "") or "").split(",") if h.strip()}
        ips |= {i.strip() for i in str(getattr(s, "trusted_relay_ips", "") or "").split(",") if i.strip()}
    except Exception:
        pass
    return hosts, ips


def _extract_header_ips(raw_headers: dict[str, Any] | None) -> list[str]:
    """Extract candidate IPs from explicit originating/SPF/Auth headers."""
    if not raw_headers or not isinstance(raw_headers, dict):
        return []
    candidates: list[str] = []

    # 1. Standard forensic header names
    header_keys = [
        "X-Originating-IP",
        "X-Sender-IP",
        "X-Client-IP",
        "X-Real-IP",
        "X-Forwarded-For",
        "X-Original-Client-IP",
        "CF-Connecting-IP",
        "True-Client-IP",
    ]
    for k in header_keys:
        val = raw_headers.get(k) or raw_headers.get(k.lower())
        if val:
            if isinstance(val, list):
                for v in val:
                    candidates.extend(IP_REGEX.findall(str(v)))
            else:
                candidates.extend(IP_REGEX.findall(str(val)))

    # 2. Authentication-Results and Received-SPF client-ip values
    auth_keys = ["Received-SPF", "Authentication-Results", "ARC-Authentication-Results"]
    for k in auth_keys:
        val = raw_headers.get(k) or raw_headers.get(k.lower())
        if val:
            text = " ".join(val) if isinstance(val, list) else str(val)
            for m in re.finditer(r"(?:client-ip|sender IP is)\s*=?\s*([^\s;,\)]+)", text, re.I):
                candidates.append(m.group(1).strip("[]'\""))

    valid_ips: list[str] = []
    for c in candidates:
        vip = _valid_ip(c)
        if vip and vip not in valid_ips:
            valid_ips.append(vip)
    return valid_ips


def _collect_ips(path: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for hop in path or []:
        for ip in hop.get("ips", []) or []:
            norm = _valid_ip(ip)
            if norm and norm not in out:
                out.append(norm)
    return out


def extract_origin_ip(
    path: list[dict[str, Any]] | None = None,
    _wire_order: bool = True,
    raw_headers: dict[str, Any] | None = None,
) -> str:
    """Best-effort origin IP. `path` is chronological (origin first).

    1. If a trust boundary is recognizable (our host/IP in a `by` field),
       return the nearest public IP BELOW it (last-external-hop).
    2. Check forensic originating headers (X-Originating-IP, SPF client-ip).
    3. Return the last public IP in wire order (closest to us).
    4. Fallbacks: first public IP, then first IP overall, else "".
    """
    path = path or []
    wire = list(reversed(path))  # wire order: top-most (ours) first
    hosts, ips = _known_ours()

    def _is_ours(hop: dict) -> bool:
        from ..forensics.psl import is_subdomain_of
        by_host = str(hop.get("by_host", "") or "").lower().rstrip(".")
        if by_host and any(is_subdomain_of(by_host, h) for h in hosts):
            return True
        return any(ip in ips for ip in hop.get("ips", []) or [])

    # 1. Trust boundary: first relay hop below our trusted relay
    boundary = next((i for i, hop in enumerate(wire) if _is_ours(hop)), None)
    if boundary is not None:
        for hop in wire[boundary + 1:]:
            for ip in hop.get("ips", []) or []:
                vip = _valid_ip(ip)
                if vip and not _is_private(vip):
                    return vip

    # 2. Check forensic originating headers for public IP (e.g. X-Originating-IP)
    header_ips = _extract_header_ips(raw_headers)
    for hip in header_ips:
        if not _is_private(hip):
            return hip

    # 3. Last public IP in wire order from Received chain
    for hop in wire:
        for ip in hop.get("ips", []) or []:
            vip = _valid_ip(ip)
            if vip and not _is_private(vip):
                return vip

    # 4. If only private IPs exist in headers or path, prefer forensic header IP, then hop IP
    for hip in header_ips:
        return hip

    for hop in wire:
        hop_ips = hop.get("ips", []) or []
        for ip in hop_ips:
            vip = _valid_ip(ip)
            if vip:
                return vip

    return ""


def extract_all_ips(path: list[dict[str, Any]]) -> list[str]:
    """All validated IPs in wire order (top-most first)."""
    return _collect_ips(list(reversed(path or [])))
