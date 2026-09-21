"""Originating IP extraction with trust-boundary logic (Step 4).

Received headers are prepended by each relay, so the EARLIEST hops are the
most spoofable: anyone can invent `Received` lines above their own. The
trustworthy signal is the LAST-EXTERNAL hop — the first relay in wire
order (top-most) that is not ours: our own infrastructure's `by` host (or
a host/IP we recognize) marks the trust boundary, and the hop just below
it is the last IP the attacker could not forge.

Without any known-ours signal we fall back to the last public IP in wire
order (closest to our MX), never the first — the exact opposite of the
old first-external heuristic.
"""
import ipaddress
import os
from typing import Any


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


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


def _collect_ips(path: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for hop in path or []:
        for ip in hop.get("ips", []) or []:
            try:
                norm = str(ipaddress.ip_address(ip))
            except ValueError:
                continue
            if norm not in out:
                out.append(norm)
    return out


def extract_origin_ip(path: list[dict[str, Any]], _wire_order: bool = True) -> str:
    """Best-effort origin IP. `path` is chronological (origin first).

    1. If a trust boundary is recognizable (our host/IP in a `by` field),
       return the nearest public IP BELOW it (last-external-hop).
    2. Otherwise return the last public IP in wire order (closest to us).
    3. Fallbacks: first IP overall, else "".
    """
    if not path:
        return ""
    wire = list(reversed(path))  # wire order: top-most (ours) first
    hosts, ips = _known_ours()

    def _is_ours(hop: dict) -> bool:
        by_host = str(hop.get("by_host", "") or "").lower().rstrip(".")
        if by_host and any(by_host == h or by_host.endswith("." + h) for h in hosts):
            return True
        return any(ip in ips for ip in hop.get("ips", []) or [])

    boundary = next((i for i, hop in enumerate(wire) if _is_ours(hop)), None)
    if boundary is not None:
        for hop in wire[boundary + 1:]:
            for ip in hop.get("ips", []) or []:
                if not _is_private(ip):
                    return ip
    # no boundary (or nothing public below it): last public IP in wire order
    for hop in wire:
        for ip in hop.get("ips", []) or []:
            if not _is_private(ip):
                return ip
    for hop in wire:
        hop_ips = hop.get("ips", []) or []
        if hop_ips:
            return hop_ips[0]
    return ""


def extract_all_ips(path: list[dict[str, Any]]) -> list[str]:
    """All validated IPs in wire order (top-most first)."""
    return _collect_ips(list(reversed(path or [])))
