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

### Option A — local (SQLite, no infra)
```bash
python3 backend/scripts/train_nlp.py
PYTHONPATH=backend uvicorn app.main:app --reload --port 8000
# in another shell:
cd frontend && npm install && npm run dev
# API: http://localhost:8000/docs  UI: http://localhost:5173
```

### Option B — full stack (Postgres, Neo4j, Elastic, Kafka)
```bash
docker compose up --build
# backend http://localhost:8000/docs  frontend http://localhost:5173
```

### Key API (all `/api/v1/*` except `/auth/*` require a JWT bearer token)
- Auth: POST `/auth/register` | POST `/auth/login` | POST `/auth/refresh` | GET `/auth/me` | POST `/auth/users` (Admin)
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

### Retention
`services/scheduler.py` runs `apply_retention()` daily at 03:00 (`RETENTION_HOUR`), logging purged counts + timestamp to `backend/retention_audit.log`. Manual run: `POST /api/v1/admin/retention` (Admin).

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
- `ENABLE_LIVE_LOOKUPS=1` — opt into live enrichment (ip-api, WHOIS, DNS, DNSBL, URLhaus, SPF/DMARC DNS). Default `0` = fast offline mode with static GeoIP fallback, so ingestion takes <1s and works without network.
- `CORS_ORIGINS` — comma-separated browser origins allowed to call the API (default `http://localhost:5173`).
- `CUSTODY_KEY` — HMAC key for chain-of-custody report signatures. **Must be provisioned from a secrets manager in any non-local deployment**; the app refuses to start when `APP_ENV` is not `development` and no key is set. (`APP_ENV=development` is the local default and keeps an explicit dev fallback.)
- `SMTP_ENABLED=1` (+ `SMTP_HOST`/`SMTP_PORT`, default `127.0.0.1:1025`) — start the inline SMTP relay; received mail is queued and analyzed by a background consumer task.
- `VITE_API_URL` (frontend) — backend base URL for split hosting; same-origin by default. See `frontend/.env.example`.
- Health: `GET /health` (liveness) and `GET /health/detailed` (DB + NLP status).

### Present-Stage Notes (September 2026)
- "AI" scope: the running ML is TF-IDF + LogisticRegression (30% of fraud score) plus hand-written linguistic cues; transformer reranking is a dormant hook, not installed. See PRD § Present-Stage Scope Note.
- Seed demo accounts when missing: `ALLOW_SEED=1 APP_ENV=development PYTHONPATH=backend python -m app.seed` (creates `admin/admin123`, `analyst/analyst123`; refuses to run otherwise).
- Quirk: API returns transient 500s while `uvicorn --reload` restarts on file saves — wait ~10s and retry.
- Sync speed: large real emails take tens of seconds each through the pipeline; multi-mail syncs complete but slowly (background-job fix queued).
- Split deploy (Vercel + Render): set `VITE_API_URL` to the Render backend; register exactly `https://<app>.vercel.app/` as the Google OAuth redirect URI; mirror it in `GOOGLE_REDIRECT_URI`, `FRONTEND_URL`, `CORS_ORIGINS`.
- Tests: 64 passing; `test_gmail`/`test_oauth` validation tests fail only with real Google credentials/mailbox rows in dev `.env`/DB (environment-dependent).

## Contributing
Please adhere to the coding standards defined in the repository wiki. Ensure all commits referencing feature additions are tied to tasks in `Tracker.md`.

## License
Proprietary / Confidential. All rights reserved.
