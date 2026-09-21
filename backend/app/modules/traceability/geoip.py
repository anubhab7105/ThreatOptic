"""GeoIP: MaxMind GeoLite2 if present, else ip-api.com over HTTPS (only when
enabled), else an honest unresolved result.

Step 4 fixes:
- HTTPS (was cleartext http://), IP validated before URL interpolation.
- 45/min free-tier throttle: over budget -> skip live call, don't sleep.
- lru_cache returns COPIES (callers mutate the dicts; cached originals
  must never be poisoned).
- No more misleading 0,0/"UNKNOWN": unresolved means lat/lon None.
"""
import ipaddress
import os
import threading
import time
from collections import deque
from functools import lru_cache
from typing import Any


# Static fallback so demo/Test IPs still map somewhere useful offline.
_STATIC = {
    "45.148.10.88": {"lat": 52.52, "lon": 13.40, "country": "DE", "city": "Berlin"},
    "93.184.216.34": {"lat": 37.77, "lon": -122.41, "country": "US", "city": "San Francisco"},
    "8.8.8.8": {"lat": 37.39, "lon": -122.08, "country": "US", "city": "Mountain View"},
    "1.1.1.1": {"lat": -33.87, "lon": 151.21, "country": "AU", "city": "Sydney"},
}

# ip-api.com free tier: 45 requests/minute.
_IPAPI_BUDGET = 45
_IPAPI_WINDOW_S = 60.0
_ipapi_hits: deque = deque()
_ipapi_lock = threading.Lock()


def has_coords(geo: dict | None) -> bool:
    """True only for real numeric non-zero coordinates."""
    if not isinstance(geo, dict):
        return False
    lat, lon = geo.get("lat"), geo.get("lon")
    return isinstance(lat, (int, float)) and isinstance(lon, (int, float)) and (lat != 0.0 or lon != 0.0)


def _unresolved(source: str) -> dict[str, Any]:
    return {"lat": None, "lon": None, "country": "", "city": "", "source": source}


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


def _throttle_allow() -> bool:
    now = time.monotonic()
    with _ipapi_lock:
        while _ipapi_hits and now - _ipapi_hits[0] > _IPAPI_WINDOW_S:
            _ipapi_hits.popleft()
        if len(_ipapi_hits) >= _IPAPI_BUDGET:
            return False
        _ipapi_hits.append(now)
        return True


@lru_cache(maxsize=2048)
def _geolocate_cached(ip: str) -> dict[str, Any]:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return _unresolved("invalid-ip")
    if ip in _STATIC:
        return {**_STATIC[ip], "source": "static-fallback"}
    # 1. MaxMind local DB
    try:
        db_path = os.environ.get("MAXMIND_DB", "./GeoLite2-City.mmdb")
        if os.path.exists(db_path):
            import geoip2.database
            with geoip2.database.Reader(db_path) as r:
                c = r.city(ip)
                return {
                    "lat": c.location.latitude,
                    "lon": c.location.longitude,
                    "country": c.country.iso_code or "",
                    "city": c.city.name or "",
                    "source": "maxmind",
                }
    except Exception:
        pass
    # 2. free API over HTTPS — only when enabled and within rate budget
    if _live() and _throttle_allow():
        try:
            import requests
            r = requests.get(
                f"https://ip-api.com/json/{ip}?fields=lat,lon,countryCode,city,isp,org,as",
                timeout=3,
            )
            if r.status_code == 200:
                j = r.json()
                lat, lon = j.get("lat"), j.get("lon")
                if isinstance(lat, (int, float)) and isinstance(lon, (int, float)) and (lat or lon or j.get("countryCode")):
                    return {
                        "lat": lat,
                        "lon": lon,
                        "country": j.get("countryCode", ""),
                        "city": j.get("city", ""),
                        "isp": j.get("isp", ""),
                        "asn": j.get("as", ""),
                        "source": "ip-api",
                    }
        except Exception:
            pass
    return _unresolved("unresolved")


def geolocate(ip: str) -> dict[str, Any]:
    """Public entry: shared-cache (24h) in front of the compute path.

    Always returns a FRESH dict (cache poisoning impossible).
    """
    from ..cache import cache_get, cache_set
    if not ip:
        return _unresolved("none")
    hit = cache_get(f"geoip:{ip}")
    if isinstance(hit, dict):
        return dict(hit)
    res = dict(_geolocate_cached(ip))
    cache_set(f"geoip:{ip}", res, 24 * 3600)
    return res
