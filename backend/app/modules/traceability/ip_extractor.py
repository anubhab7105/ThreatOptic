"""Originating IP extraction: first external IP in chronological Received path."""
import ipaddress
from typing import Any


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


def extract_origin_ip(path: list[dict[str, Any]]) -> str:
    """path is chronological (origin first). Return first public IP, else first IP, else ''."""
    for hop in path:
        for ip in hop.get("ips", []):
            if not _is_private(ip):
                return ip
    for hop in path:
        ips = hop.get("ips", [])
        if ips:
            return ips[0]
    return ""
