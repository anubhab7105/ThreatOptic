"""VPN / TOR / proxy / cloud-hosted detection (best-effort, offline-safe).

- Tor exit detection uses the Tor Project bulk exit list (cached 24h),
  not a malformed single-IP DNSEL guess.
- The old dead `if is_global: pass` branch is gone: global-unicast is now
  a precondition for Tor-list membership (private IPs can't be exits).
- Cloud-hosting hints come from ISP/ASN strings (imprecise by nature and
  labeled as hints, not verdicts).
"""
import ipaddress
import os
import time
from functools import lru_cache

CLOUD_ASN_HINTS = ("amazon", "aws", "google", "microsoft", "azure", "cloudflare", "digitalocean", "ovh", "hetzner", "alibaba")
TOR_BULK_URL = "https://check.torproject.org/torbulkexitlist"
TOR_DNS_SUFFIX = "dnsel.torproject.org"  # used by is_tor_exit_via_dnsel()
TOR_TTL_S = 24 * 3600

_cache_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                          ".cache")
_TOR_CACHE: dict[str, object] = {"exits": None, "fetched_at": 0.0}


def _live() -> bool:
    if os.environ.get("ENABLE_LIVE_LOOKUPS", "").lower() in ("0", "false", "no"):
        return False
    try:
        from ...config import get_settings
        if get_settings().live_lookups:
            return True
    except Exception:
        pass
    return os.environ.get("ENABLE_LIVE_LOOKUPS", "0").lower() not in ("", "0", "false", "no")


def _tor_exit_set() -> set[str]:
    """Tor bulk exit list, 24h file cache. Empty set when offline/disabled."""
    now = time.time()
    if _TOR_CACHE["exits"] is not None and now - float(_TOR_CACHE["fetched_at"]) < TOR_TTL_S:
        return _TOR_CACHE["exits"]  # type: ignore[return-value]
    exits: set[str] = set()
    path = os.path.join(_cache_dir, "torbulkexitlist.txt")
    if _live():
        try:
            import requests
            r = requests.get(TOR_BULK_URL, timeout=10)
            if r.status_code == 200:
                exits = {ln.strip() for ln in r.text.splitlines() if ln.strip() and not ln.startswith("#")}
                try:
                    os.makedirs(_cache_dir, exist_ok=True)
                    with open(path, "w") as f:
                        f.write("\n".join(sorted(exits)))
                except Exception:
                    pass
        except Exception:
            pass
    if not exits:
        try:
            with open(path) as f:
                exits = {ln.strip() for ln in f if ln.strip() and not ln.startswith("#")}
        except Exception:
            pass
    _TOR_CACHE.update(exits=exits, fetched_at=now)
    return exits


def is_tor_exit_via_dnsel(client_ip: str, server_ip: str, port: int = 25) -> bool:
    """Correct DNSEL query form: <rev-client>.<port>.<rev-server>.dnsel.torproject.org.

    Kept for callers that know the server endpoint; the passive pipeline
    uses the bulk list instead (it has no server context).
    """
    try:
        import dns.resolver
        rev_c = ".".join(reversed(ipaddress.ip_address(client_ip).exploded.split(":")[-1].split(".")))
        rev_s = ".".join(reversed(server_ip.split(".")))
        q = f"{rev_c}.{int(port)}.{rev_s}.dnsel.torproject.org"
        dns.resolver.resolve(q, "A", lifetime=2)
        return True
    except Exception:
        return False


@lru_cache(maxsize=2048)
def is_tor_exit(ip: str) -> bool:
    """True iff ip is a currently-listed Tor exit (live list required)."""
    if not _live() or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        if not (addr.is_global and not addr.is_reserved and not addr.is_multicast):
            return False
    except ValueError:
        return False
    return str(addr) in _tor_exit_set()


def flag_infrastructure(ip: str, isp: str = "", asn: str = "") -> dict:
    flags: list[str] = []
    tor = is_tor_exit(ip or "")
    if tor:
        flags.append("tor-exit")
    blob = f"{isp} {asn}".lower()
    if any(h in blob for h in CLOUD_ASN_HINTS):
        flags.append("cloud-hosted")
    return {"is_vpn_tor": tor, "infra_flags": flags}
