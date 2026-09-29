
import json
import sqlite3
import time
import os
import sys


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ["ENABLE_LIVE_LOOKUPS"] = "1"

from app.modules.traceability.geoip import geolocate, has_coords

db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "email_forensics.db"))
con = sqlite3.connect(db_path)
rows = con.execute("SELECT email_id, origin_ip, geolocation FROM traceability_data").fetchall()
print(f"Total traceability records found: {len(rows)}")

updated = 0
for email_id, ip, geo_str in rows:
    try:
        geo = json.loads(geo_str) if geo_str else {}
    except Exception:
        geo = {}

    if not has_coords(geo) and ip:
        new_geo = geolocate(ip)
        if has_coords(new_geo):
            isp_asn = f"{new_geo.get('isp', '')} {new_geo.get('asn', '')}".strip()
            con.execute(
                "UPDATE traceability_data SET geolocation = ?, isp_asn = ? WHERE email_id = ?",
                (json.dumps(new_geo), isp_asn, email_id),
            )
            updated += 1
            print(f"[{updated}] Updated {email_id[:8]} ({ip}) -> {new_geo.get('city')}, {new_geo.get('country')} (lat: {new_geo.get('lat')}, lon: {new_geo.get('lon')})")
        time.sleep(0.05)

con.commit()
con.close()
print(f"Finished backfill. Updated {updated} records.")
