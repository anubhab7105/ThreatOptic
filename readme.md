# ThreatOptic — AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

> See the attack behind every email. ThreatOptic detects phishing, spoofed, impersonated and fraudulent emails, traces their transmission path, estimates sender origin with geolocation, and produces court-ready forensic intelligence for analysts, administrators and investigators.

- **Live demo:** https://email-scanner-chi.vercel.app/
- **Problem Statement ID:** 26106 — *AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform*
- **Organization:** All India Council for Technical Education (Cyber Security Cell) · **Category:** Software · **Theme:** Blockchain & Cybersecurity

## Table of Contents

1. [Overview](#1-overview)
2. [Problem Statement Mapping](#2-problem-statement-mapping)
3. [Features](#3-features)
4. [How It Works](#4-how-it-works)
5. [Product Tour](#5-product-tour)
6. [Tech Stack](#6-tech-stack)
7. [Repository Structure](#7-repository-structure)
8. [Getting Started](#8-getting-started)
9. [Configuration Reference](#9-configuration-reference)
10. [API Reference](#10-api-reference)
11. [Machine Learning Models](#11-machine-learning-models)
12. [Privacy, Retention & Compliance](#12-privacy-retention--compliance)
13. [Testing & Quality Gates](#13-testing--quality-gates)
14. [Deployment](#14-deployment)
15. [Documentation Index](#15-documentation-index)
16. [Project Info](#16-project-info)

## 1. Overview

Email remains the most exploited attack vector for phishing, impersonation, business email compromise (BEC), financial fraud, credential theft and malware delivery. Attackers use AI-generated language, domain lookalikes, display-name spoofing, hidden redirect chains and relay manipulation to defeat spam filters, static blacklists and rule-based signatures.

ThreatOptic moves beyond filtering/blocking. It is an investigation platform that:

- **Detects** suspicious mail with an NLP + ML ensemble (linguistic cues, header-auth results, URL/attachment intelligence, routing anomalies) producing a transparent 0–100 fraud score.
- **Traces** the full relay path from `Received` chains, extracts the earliest reliable origin IP, and maps it to country/region/city/ISP with VPN/Tor/relay indicators.
- **Correlates** senders, domains, IPs and campaigns in a relationship graph to reveal shared infrastructure and campaign-level attribution.
- **Reports** with signed, chain-of-custody PDF/JSON forensic reports, real-time high-risk alerts, and a case-management board for triage to closure.

## 2. Problem Statement Mapping

Every key component of PS-26106 maps to a concrete ThreatOptic module:

| Problem Statement Component | ThreatOptic Implementation |
|---|---|
| Fraudulent Email Detection Engine (NLP, phishing/BEC classification) | `backend/app/modules/nlp/` TF-IDF + LogisticRegression ensemble + linguistic cues; `backend/app/modules/correlation/scoring.py` weighted verdict (NLP 0.30 / auth 0.25 / intel 0.20 / routing 0.15 / attachment 0.10) |
| Email Header & Protocol Analysis (SPF/DKIM/DMARC, routing anomalies) | `backend/app/modules/forensics/` — header parser, auth validator, `Received`-chain reconstruction, lookalike-domain detection |
| Origin Traceability & Location Analysis (IP extraction, geolocation, WHOIS/DNS) | `backend/app/modules/traceability/` — origin-IP extractor, GeoIP (offline fallback + live), VPN/Tor/open-relay signals, WHOIS/DNS/MX intelligence |
| Identity Correlation & Attribution Support (graph, campaigns, confidence) | `backend/app/modules/graph/` + `backend/app/services/campaigns.py` — sender/IP/domain graph (Neo4j or networkx fallback), campaign clustering, confidence-scored assessment |
| Alerting, Dashboard & Forensic Reporting (real-time alerts, trace maps, reports, case management) | React dashboard (score, spoofing indicators, trace path, geo map, attribution confidence), WebSocket high-risk alerts, HMAC-signed PDF/JSON reports, Cases kanban, Gmail/Microsoft live import |
| Privacy, Legal & Compliance Safeguards (masking, chain-of-custody, retention) | `backend/app/modules/privacy/` — PII masking (raw bodies never persisted), HMAC chain-of-custody, configurable retention with audit log |

## 3. Features

- **Fraud scoring (0–100):** transparent factor breakdown — every point of the score is explained in the UI (`score_breakdown`).
- **Risk bands:** Critical ≥ 90 (immediate triage), High ≥ 75 (blocked threat), Medium 50–74, Low < 50.
- **Header forensics:** Return-Path / Reply-To / Message-ID analysis, SPF/DKIM/DMARC validation (`unverifiable` when offline vs real failures), forged-field and relay-manipulation detection.
- **Origin tracing:** earliest-reliable-IP extraction behind a configurable trusted-relay boundary, GeoIP mapping (country/region/city/ISP/hosting/proxy), Tor/VPN/botnet/cloud-hosting correlation.
- **Domain intelligence:** WHOIS, DNS, MX records, registrar details, lookalike-domain detection (extra brands via `KNOWN_LEGIT_DOMAINS`), local operator blocklist.
- **URL & attachment analysis:** redirect-chain unwinding, URL ML model, VirusTotal hash checks (optional), offline heuristics (macros, double extensions, executables, magic-byte mismatches).
- **Campaign clustering:** emails grouped by shared infrastructure with a campaign-detail view and graph visualization.
- **Live mailbox import:** Google/Microsoft OAuth connectors with encrypted refresh tokens, manual or scheduled polling, Gmail search-query sync.
- **Real-time alerts:** WebSocket push for score ≥ 75 with a live bell in the navbar (ticket-based auth, token never in the URL).
- **Forensic reports:** one-click PDF/JSON export with SHA-256 + HMAC chain-of-custody signatures.
- **Case management:** kanban board (Open / InProgress / Closed) grouping related emails into investigations.
- **Roles & tenancy:** ReadOnly / Analyst / Admin with per-organization isolation (Admins see all); 20-minute access tokens with rotating single-use refresh tokens.
- **Full-text search:** Elasticsearch when configured, transparent SQLite fallback — the endpoint always works locally.

## 4. How It Works

```
Ingest (paste raw RFC822 / upload .eml / Gmail sync / SMTP relay / OAuth poll)
  → Parse & normalize (headers, body, attachments, URLs)
  → Header & protocol analysis (SPF/DKIM/DMARC, Received-chain, spoofing checks)
  → NLP + ML scoring (subject/body urgency, impersonation language, BEC patterns)
  → Threat intel (URLhaus, DNSBL, VirusTotal, blocklists, lookalikes)
  → Origin tracing (origin IP → GeoIP → VPN/Tor/relay signals → WHOIS/DNS)
  → Graph correlation (sender ↔ IP ↔ domain ↔ campaign attribution)
  → Weighted verdict 0–100 + action (allow / flag / block) + alert + report
```

Score weights (`scoring.py`): NLP 0.30 · auth 0.25 · intel 0.20 · routing 0.15 · attachment 0.10. Strong standalone signals (e.g. confirmed credential-harvesting) floor the score at 75 so a single damning indicator cannot be averaged away.

## 5. Product Tour

| Page | Route | What you get |
|---|---|---|
| Landing | `/` (logged out) | Product overview, live pipeline demo visuals, feature tour |
| Sign in / Register | `/login` | Supabase auth; offline dev accepts `admin` / `analyst` |
| Threat Dashboard | `/dashboard` (also `/`) | KPIs, ingest panel (paste / upload / Gmail), severity analytics, recent-threats table, activity feed |
| Email Analysis | `/email/:id` | Score breakdown, header forensics, relay path, geolocation map, graph, PDF/JSON export |
| Campaigns | `/campaigns`, `/campaign/:id` | Infrastructure clusters + campaign detail with related emails |
| Cases | `/cases` | Kanban investigation board |
| Mailboxes | `/mailboxes` | Google/Microsoft OAuth connectors, sync, disconnect |
| Model Info | `/model` | Transparency: accuracy, per-class metrics, confusion matrix |
| Privacy / Terms | `/privacy`, `/terms` | Data-handling policy and acceptable-use terms |

## 6. Tech Stack

- **Backend:** Python 3.11+, FastAPI, SQLAlchemy, Alembic, Pydantic; Supabase (Postgres + Auth JWT); optional Neo4j, Elasticsearch, Celery + Redis.
- **ML/NLP:** scikit-learn (TF-IDF + LogisticRegression), custom linguistic-cue engine, URL phishing model, MaxMind-compatible GeoIP.
- **Frontend:** React 18, Vite 6, React Router 7, Supabase JS, lazy-loaded 3D landing scenes.
- **Infra:** Docker + docker-compose, Vercel (frontend), Railway (backend), Kubernetes manifests in `k8s/`, GitHub Actions CI (lint, audit, pytest, Vitest, build).

## 7. Repository Structure

```
.
├── backend/                 # FastAPI service
│   ├── app/
│   │   ├── main.py          # App factory, lifespan, router wiring
│   │   ├── config.py        # Env-driven settings (fail-closed in production)
│   │   ├── models.py / schemas.py / database.py
│   │   ├── routers/         # api, auth, gmail, oauth, ws
│   │   ├── services/        # pipeline, campaigns, mailbox_poll, scheduler, tasks
│   │   └── modules/         # nlp, forensics, traceability, threat_intel,
│   │                        # correlation, graph, privacy, reporting, alerting, search
│   ├── alembic/             # DB migrations (auto-run at boot)
│   ├── scripts/             # train_nlp, fetch_datasets, live_demo_check, sign_model
│   ├── tests/               # pytest suite (isolated temp SQLite DB per test)
│   ├── ml_models/           # Trained classifiers + metrics (raw corpora optional)
│   └── supabase_handle_new_user.sql  # Auth → app users mirror trigger
├── frontend/                # React + Vite SPA
│   ├── src/
│   │   ├── main.tsx         # Shell, routing, nav, error boundaries
│   │   ├── pages.tsx        # All product pages
│   │   ├── auth.tsx         # Supabase session + profile hydration
│   │   ├── api.ts           # Typed API client, IdP-redirect guard
│   │   └── landing/         # Public landing experience
│   ├── public/              # SEO files (sitemap, robots, llms.txt, OG assets)
│   └── scripts/             # OG render, lighthouse, smoke-preview helpers
├── k8s/                     # Deployment + secret template (production)
├── docker-compose.yml       # Full local stack (backend, frontend, neo4j, es, kafka)
├── *.md                     # PRD, design, flow, schema, rules, deploy guides
├── vercel.json / railway.json  # Hosting wiring
└── start.bat / start.ps1    # One-click local launchers (Windows)
```

## 8. Getting Started

Prerequisites: **Python 3.11+**, **Node 22+**, a **Postgres** database, and a **Supabase project** (Supabase owns all authentication).

### 8.1 Backend

The backend reads the **repo-root `.env`** (the same file `docker-compose.yml` injects), so local runs and containers agree. `config.py` anchors the path to its own location, so cwd does not matter.

```bash
cp .env.example .env
# edit .env — minimum viable values:
```

```env
APP_ENV=development          # REQUIRED. Default is "production" and boot is refused.
DATABASE_URL=postgresql://USER:PASS@127.0.0.1:5432/threatoptic
CORS_ORIGINS=http://localhost:5173
FRONTEND_URL=http://localhost:5173
GOOGLE_REDIRECT_URI=http://localhost:5173
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_JWT_SECRET=...      # Supabase → Settings → API → JWT Settings
```

> Keep development values in this file. Production does not read it: Railway and Vercel supply variables from their own environments. A root `.env` holding production credentials means a local run touches the live database — the `APP_ENV=development` gate exists to prevent that.

There is **no SQLite fallback for the app** (only the pytest escape hatch via `TEST_DATABASE_URL`); `DATABASE_URL` is required and migrations run automatically at boot.

```bash
cd backend
python3 -m pip install -r requirements.txt
python3 scripts/train_nlp.py   # optional; skipped => rules-only fallback, still works
PYTHONPATH=. APP_ENV=development uvicorn app.main:app --reload --port 8000
# API docs: http://localhost:8000/docs
```

Or launch everything on Windows with `start.bat` / `start.ps1` from the repo root.

### 8.2 Frontend

```bash
cd frontend
npm install
npm run dev                  # UI: http://localhost:5173
```

The frontend loads the **repo-root `.env`** (`vite.config.ts` sets `envDir: '..'`), so there is one set of values to maintain. Only `VITE_*` keys reach the browser:

```env
VITE_API_URL=                # LEAVE EMPTY locally (dev proxy handles /api + /health)
VITE_SUPABASE_URL=https://xxxx.supabase.co
VITE_SUPABASE_ANON_KEY=...
```

**Leave `VITE_API_URL` empty locally.** The Vite dev server proxies `/api` and `/health` to `http://localhost:8000`, so the browser calls its own origin and CORS never applies.

### 8.3 Sign up & sign in

Authentication is Supabase. Use **Register** on the login page, confirm the email, and a database trigger (`supabase_handle_new_user.sql`) mirrors the row into the app's `users` table with role `Analyst` and a personal organization. There are no local `/auth/register` or `/auth/login` endpoints; the only auth route is `GET /auth/me`.

- **Offline local dev** (Supabase unconfigured): sign in with `admin` / `analyst` dev logins.
- **Roles:** ReadOnly reads · Analyst ingests + edits cases · Admin deletes + retention + provisioning. Public self-registration creates Analyst-accessible accounts; creating an Admin requires the out-of-band `SETUP_TOKEN`.

### 8.4 Optional services

Neo4j, Elasticsearch, Kafka/Redis and Celery are all optional — leave them unset and the app degrades gracefully (networkx instead of Neo4j, SQLite search instead of ES, synchronous pipeline instead of background tasks). `docker compose up --build` starts them; note it reads the **repo-root** `.env`, so point that at a local database first.

### 8.5 Gmail live import

1. Google Cloud console → enable Gmail API → OAuth client (**Web**); redirect URI = your frontend origin exactly (locally `http://localhost:5173/`, deployed `https://email-scanner-chi.vercel.app/` — trailing slash included).
2. Set `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` in `.env` (server-side only, never accepted per-request).
3. Dashboard → Gmail live import → Connect Gmail → approve. The app auto-captures the `?code=` from the redirect and finishes the connection itself, then **Sync now** pulls mail through the pipeline.

## 9. Configuration Reference

| Variable | Purpose / default |
|---|---|
| `APP_ENV` | `development` locally; anything else enforces production secrets |
| `DATABASE_URL` | Postgres DSN (required; Supabase Postgres in production) |
| `CORS_ORIGINS` | Allowed browser origins (default `https://email-scanner-chi.vercel.app`) |
| `SUPABASE_URL` / `SUPABASE_JWT_SECRET` | Auth verification |
| `VITE_API_URL` | Backend origin for split hosting (empty = same-origin; bakes at build time) |
| `ENABLE_LIVE_LOOKUPS=1` | Live enrichment (GeoIP, WHOIS, DNS, DNSBL, URLhaus, SPF/DKIM/DMARC DNS). Default `0` = fast offline mode |
| `TRUSTED_RELAY_HOSTS` / `TRUSTED_RELAY_IPS` | Own relays = trust boundary for origin-IP extraction |
| `KNOWN_LEGIT_DOMAINS` | Extra brands for lookalike-domain detection |
| `CELERY_BROKER_URL` | Enables async ingest (`?async_mode` + `GET /tasks/{id}`); unset = synchronous |
| `REDIS_URL` | Shared cache (GeoIP 24h, WHOIS 24h, DNS 1h, dashboard 5min) |
| `CUSTODY_KEY` | HMAC key for report signatures (secrets manager in non-local deploys) |
| `RETENTION_HOUR` | Daily retention run (default 03:00) |
| `MAIL_POLL_MINUTES` | Background mailbox polling (`0` = manual Sync only) |
| `SMTP_ENABLED=1` (+ `SMTP_HOST/PORT`, auth/TLS opts) | Inline SMTP relay feeding the pipeline |
| Health | `GET /health` (liveness) · `GET /health/ready` (readiness) · `GET /health/detailed` (operator diagnostic) |

## 10. API Reference

All `/api/v1/*` routes require a Supabase JWT bearer token.

- Auth: `GET /auth/me`
- Ingest: `POST /api/v1/emails/ingest {"raw": "<rfc822>"}` · `POST /api/v1/emails/upload` (.eml/.txt/.mime, ≤ 5 MB)
- Retrieve: `GET /api/v1/emails/{id}` (includes `score_breakdown`) · `GET /api/v1/emails?limit=100&q=...` · `GET /api/v1/dashboard`
- Campaigns: `GET /api/v1/campaigns` · `GET /api/v1/campaigns/{id}` · `GET /api/v1/graph/related?value=...`
- Model: `GET /api/v1/model/metrics`
- Gmail: `GET /api/v1/gmail/status` · `GET /api/v1/gmail/auth-url` · `POST /api/v1/gmail/callback` · `POST /api/v1/gmail/sync` · `DELETE /api/v1/gmail/disconnect`
- OAuth (Microsoft + generic): authorize/callback under `/api/v1/oauth/{provider}/`
- Reports: `GET /api/v1/reports/{id}.pdf` / `.json`
- Cases: `POST /api/v1/cases` · `PATCH /api/v1/cases/{id}` · `DELETE /api/v1/cases/{id}` (Admin)
- Search: `GET /api/v1/search?q=...` · Tasks: `GET /api/v1/tasks/{id}` · Admin: `POST /api/v1/admin/retention`
- Alerts: `POST /api/v1/ws/ticket` → `WS /api/v1/ws/alerts?ticket=...` (high-risk push, score ≥ 75)

## 11. Machine Learning Models

```bash
python3 backend/scripts/fetch_datasets.py  # SpamAssassin ham/spam + curated BEC -> ml_models/dataset.csv
python3 backend/scripts/train_nlp.py       # 80/20 stratified split, metrics -> ml_models/metrics.json
```

- Without the download (offline), training falls back to curated lists — no public BEC corpus is freely available, so BEC rows stay curated (see the Model Info page for per-class metrics).
- The live model contributes 30% of the fraud score; hand-written linguistic, auth, routing and attachment signals contribute the rest, so the system degrades to a rules-only verdict with no model files present.
- Model artifacts are checksummed (`*.sha256`, `scripts/sign_model.py`).

## 12. Privacy, Retention & Compliance

- **Raw email bodies are never persisted** — only the masked version is stored (cards/SSN/phones/email-localparts redacted); forensic reports mask subject/sender/recipient as well. Search indexes masked fields only.
- **Chain-of-custody:** every ingested mail is SHA-256 hashed; reports carry HMAC signatures (`CUSTODY_KEY`).
- **Retention:** `services/scheduler.py` runs `apply_retention()` daily (`RETENTION_HOUR`, default 03:00), body-blanking old clean mail and fully deleting old malicious mail in batches with per-batch rollback; counts + timestamps go to `backend/retention_audit.log`. Manual run: `POST /api/v1/admin/retention` (Admin).
- **Secrets:** never committed — `.env.example` templates only; compose fails fast on missing secrets; Kubernetes uses the `threatoptic-secrets` template (`k8s/secret.yaml.example`).

## 13. Testing & Quality Gates

```bash
cd backend && APP_ENV=development python -m pytest tests/ -q   # isolated temp DB per test
cd frontend && npm test && npm run build                        # Vitest + production build
```

- Backend: `ruff check backend --select E9,F`, `pip-audit -r backend/requirements.txt`, `pytest backend/tests`.
- Frontend: `npm run lint`, `npm audit --omit=dev --audit-level=high`, `npm test` (Vitest), `npm run build`. All run in `.github/workflows/ci.yml`.
- Live-demo rehearsal: `python3 backend/scripts/live_demo_check.py` (with the API running) checks env/keys, health, login, an ingest roundtrip whose factor breakdown must sum to the score, plus campaigns/model/oauth/gmail endpoints.

## 14. Deployment

- **Frontend (Vercel):** root `vercel.json` builds `frontend/` and rewrites all non-asset paths to `index.html` (SPA). Set `VITE_API_URL` to the Railway backend — it bakes at build time, so changing it needs a rebuild. Live URL: https://email-scanner-chi.vercel.app/
- **Backend (Railway):** `railway.json` builds `backend/Dockerfile`. Register the Vercel origin in `GOOGLE_REDIRECT_URI`, `FRONTEND_URL` and `CORS_ORIGINS` (a literal `[your-app]` placeholder there is the classic total-frontend-outage cause — `GET /health` reports the effective allowlist).
- **Docker Compose:** `docker compose up --build` (reads repo-root `.env`; fail-fast on missing secrets).
- **Kubernetes:** manifests in `k8s/` (hardened, non-root, read-only FS); create `threatoptic-secrets` per the example template and set the ingress host to your API domain.
- See `DEPLOY.md` §4.1 for the CORS triage runbook.

## 15. Documentation Index

1. [Product Requirements Document (PRD)](PRD.md) — problem statement, proposed solution, key components.
2. [Technical Specification (Techspec)](Techspec.md) — tech stack and core module breakdown.
3. [Application Flow (AppFlow)](AppFlow.md) — step-by-step data lifecycle from ingestion to alerting.
4. [System Design (Design)](Design.md) — architecture diagrams and UI/UX approach.
5. [Landing Design (Landing_Design)](Landing_Design.md) — public landing experience spec.
6. [Database Schema (Schema)](Schema.md) — data models across relational, document and graph stores.
7. [Implementation Tracker (Tracker)](Tracker.md) — phased roadmap checklist.
8. [System Rules (Rules)](Rules.md) — detection thresholds, privacy safeguards, compliance policies.
9. [Security Runbook (SECURITY)](SECURITY.md) — compromise assumption, out-of-band secret rotation, verification.
10. [Deploy Guide (DEPLOY)](DEPLOY.md) — environments, CORS triage, release notes.

## 16. Project Info

- **Project:** ThreatOptic — built for AICTE Problem Statement 26106 (Cyber Security Cell, Software category, Blockchain & Cybersecurity theme).
- **Status:** working demo — rule + ML hybrid detection, Supabase auth, Vercel + Railway deployment, offline-capable pipeline. Known limits: transformer reranking is a dormant hook (TF-IDF + LogisticRegression in production), large real emails ingest slowly, transient 500s during `uvicorn --reload` restarts.
- **Contact:** hello@threatoptic.io (replace with your team's inbox before evaluation).
- **License:** Proprietary / Confidential. All rights reserved.
