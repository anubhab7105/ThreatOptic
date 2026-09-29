
import ipaddress
import os
import re
from typing import Any


IP_REGEX = re.compile(
    r"\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,}(?::[0-9a-fA-F:]*)+)\]?"
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

    if not raw_headers or not isinstance(raw_headers, dict):
        return []
    candidates: list[str] = []


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

    path = path or []
    wire = list(reversed(path))
    hosts, ips = _known_ours()

    def _is_ours(hop: dict) -> bool:
        from ..forensics.psl import is_subdomain_of
        by_host = str(hop.get("by_host", "") or "").lower().rstrip(".")
        if by_host and any(is_subdomain_of(by_host, h) for h in hosts):
            return True
        return any(ip in ips for ip in hop.get("ips", []) or [])


    boundary = next((i for i, hop in enumerate(wire) if _is_ours(hop)), None)
    if boundary is not None:
        for hop in wire[boundary + 1:]:
            for ip in hop.get("ips", []) or []:
                vip = _valid_ip(ip)
                if vip and not _is_private(vip):
                    return vip


    header_ips = _extract_header_ips(raw_headers)
    for hip in header_ips:
        if not _is_private(hip):
            return hip


    for hop in wire:
        for ip in hop.get("ips", []) or []:
            vip = _valid_ip(ip)
            if vip and not _is_private(vip):
                return vip


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

    return _collect_ips(list(reversed(path or [])))
