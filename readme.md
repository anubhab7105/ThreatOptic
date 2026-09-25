# AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

## Overview
This repository contains the architecture, documentation, and source code for the AI-Powered Email Threat Detection, GeoLocation, and Forensic Intelligence Platform. 

The platform is designed to move beyond static, signature-based email filtering by utilizing Natural Language Processing (NLP), Graph-based identity correlation, and deep header forensics. It aims to accurately detect sophisticated phishing, impersonation, and BEC (Business Email Compromise) attacks, trace their true geographical origins, and provide actionable forensic intelligence for SOC analysts and law enforcement.

## Documentation Index
Please refer to the following markdown files in this repository to understand the system comprehensively:
1. [Product Requirements Document (PRD)](PRD.md) - Problem statement, proposed solutions, and key components.
2. [Technical Specification (Techspec)](Techspec.md) - Tech stack and core module breakdown.
3. [Application Flow (AppFlow)](AppFlow.md) - Step-by-step data lifecycle from ingestion to alerting.
4. [System Design (Design)](Design.md) - Architectural diagrams and UI/UX approach.
5. [Database Schema (Shema)](Shema.md) - Data models across relational, document, and graph databases.
6. [Implementation Plan](Implementationplan.md) - Phased roadmap for development and rollout.
7. [Project Tracker (Tracker)](Tracker.md) - Actionable checklist of tasks.
8. [System Rules (Rules)](Rules.md) - Detection thresholds, privacy safeguards, and compliance policies.
9. [Security Runbook (SECURITY)](SECURITY.md) - compromise assumption, out-of-band secret rotation, verification.

## Getting Started (Developer Setup)

You need **Python 3.11+**, **Node 22+**, a **Postgres** database, and a
**Supabase project** (Supabase owns all authentication — there is no local
password login). Both Postgres and Supabase have free tiers; a throwaway
Supabase project is the fastest route.

### 1. Backend

The backend reads **`backend/.env`**, not a repo-root `.env` — `config.py`
anchors the path to its own directory, so cwd does not matter. A `.env` in
the repo root is read by *nothing* and is the most common cause of "it boots
as production and refuses to start".

```bash
cp .env.example backend/.env
$EDITOR backend/.env          # see the table below for what must be set
```

Minimum viable `backend/.env`:

```env
APP_ENV=development          # REQUIRED. The default is "production" and boot is refused.
DATABASE_URL=postgresql://USER:PASS@127.0.0.1:5432/socdev
CORS_ORIGINS=http://localhost:5173
FRONTEND_URL=http://localhost:5173
GOOGLE_REDIRECT_URI=http://localhost:5173
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_JWT_SECRET=...      # Supabase → Settings → API → JWT Settings
```

There is **no SQLite fallback for the app** (only the pytest escape hatch via
`TEST_DATABASE_URL`); `DATABASE_URL` is required and migrations run
automatically at boot, so there is no `alembic upgrade head` step.

```bash
cd backend
python3 -m pip install -r requirements.txt
# optional: train the classifiers. Skipped => rules-only fallback, still works.
python3 scripts/train_nlp.py
PYTHONPATH=. APP_ENV=development uvicorn app.main:app --reload --port 8000
# API docs: http://localhost:8000/docs
```

### 2. Frontend

```bash
cd frontend
cp .env.example .env         # then set the two Supabase values below
npm install
npm run dev                  # UI: http://localhost:5173
```

Set in `frontend/.env`:

```env
VITE_API_URL=                # LEAVE EMPTY locally
VITE_SUPABASE_URL=https://xxxx.supabase.co
VITE_SUPABASE_ANON_KEY=...
```

**Leave `VITE_API_URL` empty.** The Vite dev server proxies `/api` and
`/health` to `http://localhost:8000`, so the browser calls its own origin and
CORS never applies. If you point it at a deployed backend instead, you are
testing production from localhost and must add `http://localhost:5173` to that
backend's `CORS_ORIGINS`. `frontend/.env.example` ships with the production
Railway URL in it — overwrite it.

### 3. Sign up

Authentication is Supabase. Use **Sign up** on the login page, confirm the
email, and a database trigger mirrors the row into the app's `users` table
with role `Analyst` and a personal organization. There is no
`/auth/register` or `/auth/login` endpoint to call directly; the only auth
route left is `GET /auth/me`.

### 4. Optional services

Neo4j, Elasticsearch and Kafka are all optional — leave them unset and the app
degrades gracefully (networkx instead of Neo4j, SQLite search instead of ES,
synchronous pipeline instead of Celery). `docker compose up --build` starts
them, but note it reads the **repo-root** `.env`; point that at a local
database first or you will run local containers against production data.

### Key API (all `/api/v1/*` require a Supabase JWT bearer token)
- Auth: `GET /auth/me` (there is no local register/login — see §3)
- POST /api/v1/emails/ingest {"raw": "<rfc822>"} | POST /api/v1/emails/upload (.eml)
- GET /api/v1/emails/{id} (includes `score_breakdown`) | GET /api/v1/dashboard
- GET /api/v1/campaigns | GET /api/v1/campaigns/{id}
- GET /api/v1/model/metrics
- Gmail demo: GET /api/v1/gmail/status | GET /api/v1/gmail/auth-url | POST /api/v1/gmail/callback | POST /api/v1/gmail/sync | DELETE /api/v1/gmail/disconnect
- GET /api/v1/reports/{id}.pdf / .json | GET /api/v1/graph/related?value=...
- POST /api/v1/cases | PATCH /api/v1/cases/{id} | DELETE /api/v1/cases/{id} (Admin)

Demo accounts (seeded): `admin / admin123` (Admin), `analyst / analyst123` (Analyst).
Public self-registration creates **ReadOnly** accounts by default (Analyst also allowed); creating an Admin requires the out-of-band `SETUP_TOKEN`. Access tokens live 20 minutes with rotating single-use refresh tokens (reuse kills the whole token family). Roles: ReadOnly reads, Analyst ingests + edits cases, Admin deletes + retention + provisioning. Every account gets a personal workspace org; all email/case/dashboard/search queries are tenant-scoped (Admins see all).

### Gmail live demo
1. Google Cloud console → enable Gmail API → OAuth client (**Web**), redirect URI = your frontend origin (e.g. `http://localhost:5173/` locally, `https://<app>.vercel.app/` when deployed — must match exactly, trailing slash included).
2. Set `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` in `backend/.env` (both must belong to the same OAuth client; the secret is server-side only and is never accepted per-request).
3. Dashboard → "Gmail live import" → fill client ID → Connect Gmail → approve. Google redirects back to a new app tab, which **auto-captures the `?code=` from the URL and finishes the connection by itself** (no visible code field; Finish connection is only a retry). Then **Sync now** pulls unread mail through the pipeline. (The OAuth client secret lives server-side in `GOOGLE_CLIENT_SECRET` only — the UI never sends it.)

Default SQLite file: `backend/email_forensics.db` (auto-created). Copy `backend/.env.example` to `backend/.env` to enable VirusTotal/MISP/Slack/Neo4j/Kafka.

### NLP model dataset
```bash
python3 backend/scripts/fetch_datasets.py  # SpamAssassin ham/spam + curated BEC -> backend/ml_models/dataset.csv
python3 backend/scripts/train_nlp.py       # 80/20 stratified split, metrics -> ml_models/metrics.json
```
Without the download (offline), training falls back to the curated lists. No public BEC corpus is freely available, so BEC rows stay curated — see the Model Info page for per-class metrics.
> Present stage: no `dataset.csv` ships in this checkout, so the live model is the 120-row curated fallback (accuracy 0.9583, macro F1 0.9582; phishing F1 1.0 / bec 0.9412 / clean 0.9333 on 24 held-out). Run `fetch_datasets.py` first if you want the 3,012-row SpamAssassin+BEC corpus figures.

### Attachment analysis
Attachments are hash-checked against VirusTotal (skipped without `VIRUSTOTAL_API_KEY`) plus offline heuristics: macro-enabled Office docs, double extensions, executables, and magic-byte mismatches feed an `attachment_risk` score weight (0.10).

### Privacy model
Raw email bodies are **never persisted** — only the masked version is stored (cards/SSN/phones/email-localparts redacted; names/addresses/IPs are not masked). Forensic reports mask subject/sender/recipient as well. Search escapes LIKE wildcards and indexes masked fields only.

### Retention
`services/scheduler.py` runs `apply_retention()` daily at 03:00 (`RETENTION_HOUR`), logging purged counts + timestamp to `backend/retention_audit.log`. Old clean mail is body-blanked (metadata kept); old malicious mail is fully deleted (email + analysis + trace + ES doc + graph node) in batches with per-batch rollback. Manual run: `POST /api/v1/admin/retention` (Admin).

### Secrets (compose / k8s)
No credentials are committed. For compose: `cp backend/.env.example .env`, fill in `*_PASSWORD`/`*_KEY` values, then `docker compose up --build` (compose fails fast if a required secret is missing). For Kubernetes: create `soc-secrets` per `k8s/secret.yaml.example` (template only — never apply real values from a file). Elasticsearch ships with `xpack.security.enabled=true`; set `ELASTICSEARCH_URL/USER/PASSWORD` to wire the full-text mirror, otherwise search transparently falls back to SQLite.

### Mailbox polling
Organization connectors live under "Mailboxes" in the UI (Google/Microsoft OAuth, encrypted refresh tokens). `MAIL_POLL_MINUTES=0` (default) means manual "Sync now" only; set e.g. `60` for hourly background polling.

### Full-text search
`GET /api/v1/search?q=...` queries Elasticsearch (`email.subject^3`, sender, body) when configured, else the same SQLite search as the email list — the endpoint always works locally.

### Code quality gates
Backend: `ruff check backend --select E9,F`, `pip-audit -r backend/requirements.txt`, `pytest backend/tests`. Frontend: `npm run lint`, `npm audit --omit=dev --audit-level=high`, `npm test` (Vitest), `npm run build`. All run in `.github/workflows/ci.yml`.

### Live-demo rehearsal
```bash
PYTHONPATH=backend uvicorn app.main:app --port 8000   # terminal 1
python3 backend/scripts/live_demo_check.py            # terminal 2 (uses admin/admin123)
```
The script checks env/keys, API health, login, an ingest roundtrip whose Why-breakdown must sum to the score, plus campaigns/model/oauth/gmail endpoints, and exits non-zero with FAIL lines for anything needing attention. For a fully live demo set `ENABLE_LIVE_LOOKUPS=1` with real keys (`VIRUSTOTAL_API_KEY`, MaxMind DB at `GeoLite2-City.mmdb`, `MISP_URL/KEY`) and `SECRET_KEY`/`CUSTODY_KEY` from your secrets manager — rehearse the script once with those set.

### Configuration
- `ENABLE_LIVE_LOOKUPS=1` — **recommended for any live deployment**: opt into live enrichment (ip-api over HTTPS, WHOIS, DNS, DNSBL, URLhaus, SPF/DKIM/DMARC DNS). Default `0` = fast offline mode with static GeoIP fallback, so ingestion takes <1s and works without network. Offline, auth checks report `unverifiable` (distinct from real failures) and score near-zero.
- `TRUSTED_RELAY_HOSTS` / `TRUSTED_RELAY_IPS` (comma-separated) — your own relays, used as the trust boundary for origin-IP extraction.
- `CELERY_BROKER_URL` (e.g. `redis://localhost:6379/0`) — enables the optional Celery async path (`?async_mode` + `GET /tasks/{id}`); unset keeps the synchronous pipeline. `CELERY_RESULT_BACKEND` defaults to in-memory cache.
- `REDIS_URL` — shared cache for GeoIP (24h), WHOIS (24h), DNS (1h) and dashboard (5min, invalidated on writes); unset keeps an in-process dict cache with the same TTLs.
- High-risk mail (score ≥75) is pushed over WebSocket `/api/v1/ws/alerts?token=<jwt>` to same-org clients (Admins get all); the nav bell shows the live stream.
- `KNOWN_LEGIT_DOMAINS` (comma-separated) — extra brands for lookalike-domain detection, appended to the built-in list.
- Operator blocklist lives in `backend/data/local_blocklist.txt` (one domain per line), not in code; hard-coded demo domains only fire in development.
- `CORS_ORIGINS` — comma-separated browser origins allowed to call the API (default `https://email-scanner-chi.vercel.app`, the deployed frontend). Origins are matched on scheme + host + port, case-insensitively, with trailing slashes stripped; `*` is refused at boot because `allow_credentials` is on. `CORS_ORIGIN_REGEX` adds opt-in patterns (e.g. Vercel preview hosts), `fullmatch`ed against the whole origin and refused at boot if a pattern would match every origin. **`GET /health` reports the effective allowlist** — the fastest way to diagnose "blocked by CORS policy" in a split deploy, since the browser says nothing useful. `DEPLOY.md` §4.1 has the full triage runbook.
- `CUSTODY_KEY` — HMAC key for chain-of-custody report signatures. **Must be provisioned from a secrets manager in any non-local deployment**; the app refuses to start when `APP_ENV` is not `development` and no key is set. (`APP_ENV=development` is the local default and keeps an explicit dev fallback.)
- `SMTP_ENABLED=1` (+ `SMTP_HOST`/`SMTP_PORT`, default `127.0.0.1:1025`) — start the inline SMTP relay; received mail is queued and analyzed by a background consumer task. Harden with `SMTP_REQUIRE_AUTH=1` + `SMTP_USERNAME`/`SMTP_PASSWORD`, `SMTP_TLS_CERT`/`SMTP_TLS_KEY` (STARTTLS), `SMTP_DATA_LIMIT_BYTES`.
- Managed Postgres: `alembic upgrade head` from `backend/` (SQLite dev uses the fast built-in path). Ingest is idempotent per tenant (duplicate bytes return the stored verdict).
- `VITE_API_URL` (frontend) — backend base URL for split hosting; same-origin by default. See `frontend/.env.example`.
- Health: `GET /health` (liveness) and `GET /health/detailed` (DB + NLP status).

### Present-Stage Notes (September 2026)
- "AI" scope: the running ML is TF-IDF + LogisticRegression (30% of fraud score) plus hand-written linguistic cues; transformer reranking is a dormant hook, not installed. See PRD § Present-Stage Scope Note.
- Accounts come from Supabase, not from a seed script: sign up in the UI, and a trigger mirrors the row into the app's `users` table (which is where role and organization are read from — never from the token). There is no `app.seed` module; if you were told to run one, it was removed in the Supabase migration.
- Quirk: API returns transient 500s while `uvicorn --reload` restarts on file saves — wait ~10s and retry.
- Sync speed: large real emails take tens of seconds each through the pipeline; multi-mail syncs complete but slowly (background-job fix queued).
- Split deploy (Vercel + Railway): set `VITE_API_URL` to the Railway backend (baked at build time — editing the variable requires a Vercel rebuild, not just a redeploy); register `https://<app>.vercel.app` as the Google OAuth redirect URI; mirror that exact origin in `GOOGLE_REDIRECT_URI`, `FRONTEND_URL` and `CORS_ORIGINS`. Copying a `[your-app]` placeholder literally into `CORS_ORIGINS` is the usual cause of a total frontend outage — the app builds, health checks pass, and only browsers fail.
- Tests: `cd backend && APP_ENV=development python -m pytest tests/ -q` (231 passing; `APP_ENV=development` is required or startup refuses). `cd frontend && npm test && npm run build` (40 passing).

## Contributing
Please adhere to the coding standards defined in the repository wiki. Ensure all commits referencing feature additions are tied to tasks in `Tracker.md`.

## License
Proprietary / Confidential. All rights reserved.
