"""GeoIP: MaxMind GeoLite2 if present, else ip-api.com (only when enabled), else offline stub."""
import os
from functools import lru_cache
from typing import Any


# Static fallback so demo/Test IPs still map somewhere useful offline.
_STATIC = {
    "45.148.10.88": {"lat": 52.52, "lon": 13.40, "country": "DE", "city": "Berlin"},
    "93.184.216.34": {"lat": 37.77, "lon": -122.41, "country": "US", "city": "San Francisco"},
    "8.8.8.8": {"lat": 37.39, "lon": -122.08, "country": "US", "city": "Mountain View"},
    "1.1.1.1": {"lat": -33.87, "lon": 151.21, "country": "AU", "city": "Sydney"},
}


@lru_cache(maxsize=2048)
def geolocate(ip: str) -> dict[str, Any]:
    if not ip:
        return {"lat": 0.0, "lon": 0.0, "country": "", "city": "", "source": "none"}
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
                    "lat": c.location.latitude or 0.0,
                    "lon": c.location.longitude or 0.0,
                    "country": c.country.iso_code or "",
                    "city": c.city.name or "",
                    "source": "maxmind",
                }
    except Exception:
        pass
    # 2. free API — only when explicitly enabled (slow + rate-limited otherwise)
    enabled = os.environ.get("ENABLE_LIVE_LOOKUPS", "0").lower() not in ("", "0", "false", "no")
    if enabled:
        try:
            import requests
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=lat,lon,countryCode,city,isp,org,as",
                timeout=2,
            )
            if r.status_code == 200:
                j = r.json()
                return {
                    "lat": j.get("lat", 0.0),
                    "lon": j.get("lon", 0.0),
                    "country": j.get("countryCode", ""),
                    "city": j.get("city", ""),
                    "isp": j.get("isp", ""),
                    "asn": j.get("as", ""),
                    "source": "ip-api",
                }
        except Exception:
            pass
    return {"lat": 0.0, "lon": 0.0, "country": "UNKNOWN", "city": "", "source": "offline-stub"}
