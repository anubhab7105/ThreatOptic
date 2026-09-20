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
Public self-registration creates Analyst accounts (first-ever account becomes Admin).

### Gmail live demo
1. Google Cloud console → enable Gmail API → OAuth client (Web), redirect URI = your frontend origin (e.g. `http://localhost:5173/`).
2. Set `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` env (or paste per-request in the UI).
3. Dashboard → "Gmail live import" → Connect Gmail → approve → paste code → Finish → **Sync now** pulls unread mail through the pipeline.

Default SQLite file: `backend/email_forensics.db` (auto-created). Copy `backend/.env.example` to `backend/.env` to enable VirusTotal/MISP/Slack/Neo4j/Kafka.

### NLP model dataset
```bash
python3 backend/scripts/fetch_datasets.py  # SpamAssassin ham/spam + curated BEC -> backend/ml_models/dataset.csv
python3 backend/scripts/train_nlp.py       # 80/20 stratified split, metrics -> ml_models/metrics.json
```
Without the download (offline), training falls back to the curated lists. No public BEC corpus is freely available, so BEC rows stay curated — see the Model Info page for per-class metrics.

### Attachment analysis
Attachments are hash-checked against VirusTotal (skipped without `VIRUSTOTAL_API_KEY`) plus offline heuristics: macro-enabled Office docs, double extensions, executables, and magic-byte mismatches feed an `attachment_risk` score weight (0.10).

### Retention
`services/scheduler.py` runs `apply_retention()` daily at 03:00 (`RETENTION_HOUR`), logging purged counts + timestamp to `backend/retention_audit.log`. Manual run: `POST /api/v1/admin/retention` (Admin).
- `ENABLE_LIVE_LOOKUPS=1` — opt into live enrichment (ip-api, WHOIS, DNS, DNSBL, URLhaus, SPF/DMARC DNS). Default `0` = fast offline mode with static GeoIP fallback, so ingestion takes <1s and works without network.
- `CORS_ORIGINS` — comma-separated browser origins allowed to call the API (default `http://localhost:5173`).
- `CUSTODY_KEY` — HMAC key for chain-of-custody report signatures. **Must be provisioned from a secrets manager in any non-local deployment**; the app refuses to start when `APP_ENV` is not `development` and no key is set. (`APP_ENV=development` is the local default and keeps an explicit dev fallback.)
- `SMTP_ENABLED=1` (+ `SMTP_HOST`/`SMTP_PORT`, default `127.0.0.1:1025`) — start the inline SMTP relay; received mail is queued and analyzed by a background consumer task.
- `VITE_API_URL` (frontend) — backend base URL for split hosting; same-origin by default. See `frontend/.env.example`.
- Health: `GET /health` (liveness) and `GET /health/detailed` (DB + NLP status).

## Contributing
Please adhere to the coding standards defined in the repository wiki. Ensure all commits referencing feature additions are tied to tasks in `Tracker.md`.

## License
Proprietary / Confidential. All rights reserved.
