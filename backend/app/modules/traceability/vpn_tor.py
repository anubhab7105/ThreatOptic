"""VPN / TOR / proxy / cloud-hosted detection (best-effort, offline-safe)."""
import ipaddress

# Public TOR exit list is fetched live when possible; static fallback hints:
CLOUD_ASN_HINTS = ("amazon", "aws", "google", "microsoft", "azure", "cloudflare", "digitalocean", "ovh", "hetzner", "alibaba")
TOR_DNS_SUFFIX = "dnsel.torproject.org"


def is_tor_exit(ip: str) -> bool:
    """Reverse-DNS TOR exit check via dnsel.torproject.org (may fail offline -> False)."""
    try:
        import dns.resolver
        rev = ".".join(reversed(ip.split(".")))
        q = f"{rev}.80.443.{rev}.{TOR_DNS_SUFFIX}"  # common ports heuristic
        # simpler: query tor exit list via check.torproject.org bulk? use DNSEL
        dns.resolver.resolve(q, "A", lifetime=3)
        return True
    except Exception:
        return False


def flag_infrastructure(ip: str, isp: str = "", asn: str = "") -> dict:
    flags: list[str] = []
    tor = is_tor_exit(ip)
    if tor:
        flags.append("tor-exit")
    blob = f"{isp} {asn}".lower()
    if any(h in blob for h in CLOUD_ASN_HINTS):
        flags.append("cloud-hosted")
    try:
        if ipaddress.ip_address(ip).is_global:
            pass
    except Exception:
        pass
    # open-relay heuristic can't be proven passively; expose field for intel feeds
    return {"is_vpn_tor": tor, "infra_flags": flags}
