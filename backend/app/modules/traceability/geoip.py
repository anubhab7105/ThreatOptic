"""GeoIP: MaxMind GeoLite2 if present, else ip-api.com, else offline stub."""
import os
from typing import Any


def geolocate(ip: str) -> dict[str, Any]:
    if not ip:
        return {"lat": 0.0, "lon": 0.0, "country": "", "city": "", "source": "none"}
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
    # 2. free API (best effort, short timeout)
    try:
        import requests
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=lat,lon,countryCode,city,isp,org,as", timeout=4)
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
