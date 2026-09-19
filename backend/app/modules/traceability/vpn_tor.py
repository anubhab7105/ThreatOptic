"""VPN / TOR / proxy / cloud-hosted detection (best-effort, offline-safe)."""
import ipaddress
import os
from functools import lru_cache

# Public TOR exit list is fetched live when possible; static fallback hints:
CLOUD_ASN_HINTS = ("amazon", "aws", "google", "microsoft", "azure", "cloudflare", "digitalocean", "ovh", "hetzner", "alibaba")
TOR_DNS_SUFFIX = "dnsel.torproject.org"


@lru_cache(maxsize=2048)
def is_tor_exit(ip: str) -> bool:
    """Reverse-DNS TOR exit check via dnsel.torproject.org (only when live lookups enabled)."""
    if os.environ.get("ENABLE_LIVE_LOOKUPS", "0").lower() in ("", "0", "false", "no"):
        return False
    if not ip:
        return False
    try:
        import dns.resolver
        rev = ".".join(reversed(ip.split(".")))
        q = f"{rev}.80.443.{rev}.{TOR_DNS_SUFFIX}"  # common ports heuristic
        dns.resolver.resolve(q, "A", lifetime=2)
        return True
    except Exception:
        return False


def flag_infrastructure(ip: str, isp: str = "", asn: str = "") -> dict:
    flags: list[str] = []
    tor = is_tor_exit(ip or "")
    if tor:
        flags.append("tor-exit")
    blob = f"{isp} {asn}".lower()
    if any(h in blob for h in CLOUD_ASN_HINTS):
        flags.append("cloud-hosted")
    try:
        if ip and ipaddress.ip_address(ip).is_global:
            pass
    except Exception:
        pass
    # open-relay heuristic can't be proven passively; expose field for intel feeds
    return {"is_vpn_tor": tor, "infra_flags": flags}
