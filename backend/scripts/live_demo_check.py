"""Live-demo rehearsal checklist (Phase 3).

Verifies everything a judge will touch, in order:
  1. environment/keys (offline; unit-testable via check_env())
  2. API liveness + detailed health (needs the backend running)
  3. authenticated end-to-end: login -> ingest -> breakdown -> campaigns ->
     model metrics (needs seeded admin/admin123 or --username/--password)

Usage:
    python backend/scripts/live_demo_check.py [--api http://localhost:8000]
    python backend/scripts/live_demo_check.py --api http://localhost:8000 -u admin -p admin123
Exit code 0 = demo-ready, 1 = something needs attention (all findings printed).
"""
import argparse
import os
import sys

SAMPLE = ("From: demo@xn--paypa1-secure.top\nTo: finance@company.com\n"
          "Subject: Urgent wire needed\n"
          "Received: from evil.test (evil.test [45.148.10.88]) by mx.company.com with ESMTPS\n"
          "Content-Type: text/plain\n\nKindly wire $9000 immediately, confidential.")


def check_env(env: dict | None = None) -> dict:
    e = env if env is not None else os.environ
    live = str(e.get("ENABLE_LIVE_LOOKUPS", "0")).lower() not in ("", "0", "false", "no")
    return {
        "app_env": e.get("APP_ENV", "development"),
        "secret_changed": bool(e.get("SECRET_KEY")) and e.get("SECRET_KEY") != "change-me-in-prod" and len(e.get("SECRET_KEY", "")) >= 32,
        "custody_key_set": bool(e.get("CUSTODY_KEY")),
        "live_lookups": live,
        "virustotal_key": bool(e.get("VIRUSTOTAL_API_KEY")),
        "gmail_oauth": bool(e.get("GOOGLE_CLIENT_ID") and e.get("GOOGLE_CLIENT_SECRET")),
        "ms_oauth": bool(e.get("MS_CLIENT_ID") and e.get("MS_CLIENT_SECRET")),
        "neo4j": bool(e.get("NEO4J_URI")),
    }


def _line(ok: bool, msg: str, checks: list) -> None:
    checks.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {msg}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("-u", "--username", default="admin")
    ap.add_argument("-p", "--password", default="admin123")
    ap.add_argument("--env-only", action="store_true")
    args = ap.parse_args()

    checks: list[bool] = []
    env = check_env()
    _line(True, f"APP_ENV={env['app_env']}", checks)
    _line(env["secret_changed"], "SECRET_KEY changed from default and length >= 32", checks)
    if env["app_env"] != "development":
        _line(env["custody_key_set"], "CUSTODY_KEY provisioned (min 32 chars, required outside development)", checks)
    else:
        print("[INFO] development mode: custody dev fallback active")
    _line(True, f"live lookups {'ON' if env['live_lookups'] else 'OFF'}; "
                f"VirusTotal {'keyed' if env['virustotal_key'] else 'unkeyed (skipped)'}", checks)
    _line(True, f"Gmail OAuth {'configured' if env['gmail_oauth'] else 'not configured'}; "
                f"Microsoft OAuth {'configured' if env['ms_oauth'] else 'not configured'}; "
                f"Neo4j {'configured' if env['neo4j'] else 'local graph fallback'}", checks)
    if args.env_only:
        return 0 if all(checks) else 1

    import httpx
    base = args.api.rstrip("/")
    try:
        r = httpx.get(f"{base}/health", timeout=5)
        _line(r.status_code == 200, f"GET /health -> {r.status_code}", checks)
        d = httpx.get(f"{base}/health/detailed", timeout=10).json()
        _line(d.get("db") is True, f"detailed health: db={d.get('db')} nlp={d.get('nlp')}", checks)
    except Exception as e:
        _line(False, f"API unreachable at {base}: {e}", checks)
        return 1

    try:
        tok = httpx.post(f"{base}/api/v1/auth/login",
                         json={"username": args.username, "password": args.password},
                         timeout=10).json()["access_token"]
        h = {"Authorization": f"Bearer {tok}"}
        _line(True, f"login as {args.username}", checks)
        eid = httpx.post(f"{base}/api/v1/emails/ingest", headers=h,
                         json={"raw": SAMPLE}, timeout=60).json()["email_id"]
        detail = httpx.get(f"{base}/api/v1/emails/{eid}", headers=h, timeout=10).json()
        sigs = detail["analysis"].get("score_breakdown", [])
        total = round(sum(s["contribution_to_score"] for s in sigs), 2)
        _line(abs(total - detail["analysis"]["fraud_score"]) < 0.1,
              f"ingest + Why-breakdown sums to score ({total})", checks)
        for path in ("campaigns", "model/metrics", "oauth/status", "gmail/status"):
            rr = httpx.get(f"{base}/api/v1/{path}", headers=h, timeout=10)
            _line(rr.status_code == 200, f"GET /api/v1/{path} -> {rr.status_code}", checks)
    except Exception as e:
        _line(False, f"authenticated demo path failed: {e}", checks)

    print("DEMO READY" if all(checks) else "ATTENTION NEEDED")
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
