"""GeoIP: MaxMind GeoLite2 if present, else multi-provider live lookup
(ipwho.is HTTPS -> ip-api.com HTTP fallback), with country centroids and
graceful private/internal IP detection.
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

# Country centroids (lat, lon) for fallback coordinate approximation
COUNTRY_CENTROIDS: dict[str, tuple[float, float]] = {
    "US": (37.0902, -95.7129),
    "GB": (55.3781, -3.4360),
    "DE": (51.1657, 10.4515),
    "FR": (46.2276, 2.2137),
    "IN": (20.5937, 78.9629),
    "CA": (56.1304, -106.3468),
    "AU": (-25.2744, 133.7751),
    "JP": (36.2048, 138.2529),
    "CN": (35.8617, 104.1954),
    "BR": (-14.2350, -51.9253),
    "RU": (61.5240, 105.3188),
    "IT": (41.8719, 12.5674),
    "ES": (40.4637, -3.7492),
    "NL": (52.1326, 5.2913),
    "SE": (60.1282, 18.6435),
    "CH": (46.8182, 8.2275),
    "SG": (1.3521, 103.8198),
    "ZA": (-30.5595, 22.9375),
    "MX": (23.6345, -102.5528),
    "KR": (35.9078, 127.7669),
    "IE": (53.1424, -7.6921),
    "PL": (51.9194, 19.1451),
    "NO": (60.4720, 8.4689),
    "FI": (61.9241, 25.7482),
    "DK": (56.2639, 9.5018),
    "NZ": (-40.9006, 174.8860),
    "IL": (31.0461, 34.8516),
    "AE": (23.4241, 53.8478),
    "SA": (23.8859, 45.0792),
    "TR": (38.9637, 35.2433),
    "UA": (48.3794, 31.1656),
    "AT": (47.5162, 14.5501),
    "BE": (50.5039, 4.4699),
    "PT": (39.3999, -8.2245),
    "RO": (45.9432, 24.9668),
    "CZ": (49.8175, 15.4730),
    "HU": (47.1625, 19.5033),
    "GR": (39.0742, 21.8243),
    "AR": (-38.4161, -63.6167),
    "CL": (-35.6751, -71.5430),
    "CO": (4.5709, -74.2973),
    "ID": (-0.7893, 113.9213),
    "MY": (4.2105, 101.9758),
    "TH": (15.8700, 100.9925),
    "VN": (14.0583, 108.2772),
    "PH": (12.8797, 121.7740),
    "PK": (30.3753, 69.3451),
    "BD": (23.6850, 90.3563),
    "NG": (9.0820, 8.6753),
    "EG": (26.8206, 30.8025),
    "KE": (-0.0236, 37.9062),
}

# Live lookup rate throttle
_IPAPI_BUDGET = 60
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


def get_country_centroid(country_code: str) -> tuple[float, float] | None:
    """Return (lat, lon) centroid for an ISO country code, if available."""
    if not country_code:
        return None
    return COUNTRY_CENTROIDS.get(country_code.strip().upper())


def geolocate_country(country_code: str, source: str = "country-centroid") -> dict[str, Any]:
    """Provide country-level centroid coordinates when city-level coords are unavailable."""
    code = (country_code or "").strip().upper()
    coords = get_country_centroid(code)
    if coords:
        return {
            "lat": coords[0],
            "lon": coords[1],
            "country": code,
            "city": "",
            "source": source,
        }
    return _unresolved("country-unknown")


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


_RFC1918_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
_LINK_LOCAL_NET = ipaddress.ip_network("169.254.0.0/16")


@lru_cache(maxsize=2048)
def _geolocate_cached(ip: str) -> dict[str, Any]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return _unresolved("invalid-ip")

    if ip in _STATIC:
        return {**_STATIC[ip], "source": "static-fallback"}

    # Handle loopback, private RFC1918, and link-local IP spaces explicitly
    if addr.is_loopback:
        return {
            "lat": None,
            "lon": None,
            "country": "Localhost",
            "city": "Loopback (127.0.0.1)",
            "source": "loopback",
            "is_private": True,
        }

    if any(addr in net for net in _RFC1918_NETS):
        return {
            "lat": None,
            "lon": None,
            "country": "Private Network",
            "city": "Internal LAN (RFC1918)",
            "source": "private-ip",
            "is_private": True,
        }

    if addr in _LINK_LOCAL_NET:
        return {
            "lat": None,
            "lon": None,
            "country": "Link-Local",
            "city": "Link-Local (169.254.x.x)",
            "source": "link-local",
            "is_private": True,
        }

    # 1. MaxMind local DB (if file present)
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

    # 2. Multi-provider live lookup over HTTPS / HTTP
    if _live() and _throttle_allow():
        import requests

        # Provider A: ipwho.is (Free HTTPS API, fast, rich metadata)
        try:
            r = requests.get(f"https://ipwho.is/{ip}", timeout=2.5)
            if r.status_code == 200:
                j = r.json()
                if j.get("success") is True:
                    lat = j.get("latitude")
                    lon = j.get("longitude")
                    conn = j.get("connection") or {}
                    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                        return {
                            "lat": lat,
                            "lon": lon,
                            "country": j.get("country_code", "") or j.get("country", ""),
                            "city": j.get("city", ""),
                            "region": j.get("region", ""),
                            "isp": conn.get("isp", ""),
                            "asn": f"AS{conn.get('asn', '')}".strip("AS"),
                            "org": conn.get("org", ""),
                            "source": "ipwho.is",
                        }
        except Exception:
            pass

        # Provider B: ip-api.com over HTTP (Free HTTP endpoint)
        try:
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,message,countryCode,country,regionName,city,lat,lon,isp,org,as",
                timeout=2.5,
            )
            if r.status_code == 200:
                j = r.json()
                if j.get("status") == "success":
                    lat, lon = j.get("lat"), j.get("lon")
                    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                        return {
                            "lat": lat,
                            "lon": lon,
                            "country": j.get("countryCode", ""),
                            "city": j.get("city", ""),
                            "region": j.get("regionName", ""),
                            "isp": j.get("isp", ""),
                            "asn": j.get("as", ""),
                            "org": j.get("org", ""),
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
    clean_ip = str(ip).strip("[] ")
    hit = cache_get(f"geoip:{clean_ip}")
    if isinstance(hit, dict):
        return dict(hit)
    res = dict(_geolocate_cached(clean_ip))
    cache_set(f"geoip:{clean_ip}", res, 24 * 3600)
    return res
