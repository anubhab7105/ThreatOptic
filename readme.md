# AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

## Overview
This repository contains the architecture, documentation, and source code for the AI-Powered Email Threat Detection, GeoLocation, and Forensic Intelligence Platform.

The platform moves beyond static, signature-based email filtering by utilizing Natural Language Processing (NLP), graph-based identity correlation, and deep header forensics. It detects sophisticated phishing, impersonation, and BEC (Business Email Compromise) attacks, traces their true geographical origins, and provides actionable forensic intelligence for SOC analysts and law enforcement.

What the running code actually does (per `backend/app/` + `frontend/src/`):
- **Ingest:** paste raw RFC822 (`POST /api/v1/emails/ingest`), upload `.eml/.txt/.mime` (`POST /api/v1/emails/upload`), Gmail OAuth2 sync, org mailbox polling (Google/Microsoft), or inline SMTP relay.
- **Analyze:** header forensics (SPF/DKIM/DMARC/ARC), relay-chain reconstruction, origin-IP extraction, GeoIP/WHOIS/DNS, URL + attachment intel, TF-IDF/LogReg NLP + linguistic cues, weighted fraud score 0–100 with `score_breakdown`.
- **Correlate:** identity graph (networkx locally, Neo4j when configured), campaign clustering, related-entity traversal.
- **Act:** dashboard, cases, full-text search, chain-of-custody PDF/JSON reports, Slack/PagerDuty alerts, WebSocket high-risk stream, retention purges.
- **UI:** React + Vite SPA (`frontend/src/`): Landing, Login, Dashboard, Email detail, Campaigns, Cases, Mailboxes, Model Info, Privacy/Terms, plus alert bell, global search, keyboard shortcuts, light/dark theme.

## Documentation Index
Please refer to the following markdown files in this repository to understand the system comprehensively:
1. [Product Requirements Document (PRD)](PRD.md) - Problem statement, proposed solutions, and key components.
2. [Technical Specification (Techspec)](Techspec.md) - Tech stack and core module breakdown.
3. [Application Flow (AppFlow)](AppFlow.md) - Step-by-step data lifecycle from ingestion to alerting.
4. [System Design (Design)](Design.md) - Architectural diagrams and UI/UX approach.
5. [Database Schema (Shema)](Shema.md) / [Schema](Schema.md) - Data models across relational, document, and graph databases.
6. [Implementation Plan](Implementationplan.md) - Phased roadmap for development and rollout.
7. [Project Tracker (Tracker)](Tracker.md) - Actionable checklist of tasks.
8. [System Rules (Rules)](Rules.md) - Detection thresholds, privacy safeguards, and compliance policies.
9. [Security Runbook (SECURITY)](SECURITY.md) - Compromise assumption, out-of-band secret rotation, verification.
10. [Deploy Guide (DEPLOY)](DEPLOY.md) - Vercel (frontend) + Railway (backend) + Supabase (Auth + Postgres) split deploy.

## Repository layout
```
backend/                 FastAPI service (app/main.py, lifespan boot gates)
  app/config.py          Single settings object; reads backend/.env then repo-root .env
  app/routers/           auth.py (/auth/me) · api.py (emails/cases/campaigns/search/reports/admin/model)
  │                      gmail.py (personal Gmail) · oauth.py (org Google/Microsoft) · ws.py (alerts) · deps.py (JWT + RBAC)
  app/modules/           auth/ · ingestion/ · forensics/ · traceability/ · nlp/ · threat_intel/
  │                      correlation/ · graph/ · reporting/ · privacy/ · search/ · alerting/ · cache.py · model_trust.py
  app/services/          pipeline.py · campaigns.py · mailbox_poll.py · scheduler.py · tasks.py (Celery)
  app/models.py          User/Organization/InvestigationCase/EmailRecord/AnalysisResult/TraceabilityData/GmailAccount/MailboxConnection/OAuthState
  scripts/               train_nlp.py · fetch_datasets.py · live_demo_check.py · sign_model.py · backfill_geo.py
  ml_models/             phishing_clf.joblib + .sha256 · url_phishing_model.pkl + .sha256 · metrics.json (dataset.csv is gitignored)
  alembic/               834dc871451e initial schema → b7c2d1a9e4f5 Supabase-auth migration (auto-run at boot)
  supabase_handle_new_user.sql  One-time trigger: mirror confirmed Supabase users → public.users (Analyst + personal org)
frontend/                Vite + React + TypeScript SPA (vite.config.ts, envDir: '..')
  src/main.tsx           Shell, routes, OAuth callback handler, alert bell (WS ticket flow), theme
  src/pages.tsx          Landing/Login/Dashboard/EmailView/Cases/Campaigns/Mailboxes/ModelInfo/Privacy/Terms
  src/auth.tsx           Supabase session + dev-token fallback; src/supabaseClient.ts; src/api.ts (BASE/API client)
docker-compose.yml       backend + frontend + neo4j + elasticsearch + kafka (reads repo-root .env; no local postgres — Supabase)
k8s/                     backend.yaml + secret.yaml.example (template only)
railway.json / vercel.json / backend/Dockerfile / frontend/Dockerfile+nginx.conf
start.bat / start.ps1    Local convenience launchers
```

## Getting Started (Developer Setup)

You need **Python 3.11+**, **Node 22+**, and a **Supabase project** (Supabase owns all authentication — there is no local password login; Postgres comes from Supabase via the Transaction Pooler). Neo4j, Elasticsearch, Kafka/Redis/Celery are all optional with graceful local fallbacks.

Run `backend/supabase_handle_new_user.sql` **once** in Supabase → SQL Editor so confirmed signups get a `public.users` row (role `Analyst` + personal `<email>'s workspace` org). Without it, `GET /auth/me` returns 401 "user not found — email not confirmed yet?".

### 1. Backend

The backend reads the **repo-root `.env`** — the same file `docker-compose.yml` injects, so a locally-run backend and the container stack agree instead of drifting apart. `config.py` anchors the path to its own location, so cwd does not matter.

```bash
cp .env.example .env
$EDITOR .env                   # see the table below for what must be set
```

`backend/.env` is also read, and takes precedence, if you need the backend to diverge from the shared file (for example a local Postgres nothing else uses). You normally do not need it.

Minimum viable `.env`:

```env
APP_ENV=development          # REQUIRED. The default is "production" and boot is refused.
DATABASE_URL=postgresql://USER:PASS@127.0.0.1:5432/socdev
CORS_ORIGINS=http://localhost:5173
FRONTEND_URL=http://localhost:5173
GOOGLE_REDIRECT_URI=http://localhost:5173/
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_JWT_SECRET=...      # Supabase → Settings → API → JWT Settings
```

> **Keep development values in this file.** Production does not read it: Railway and Vercel supply variables from their own environment. A root `.env` left holding production credentials means a local `uvicorn` run connects to the live database, runs migrations against it, and authenticates real users — the failure mode `APP_ENV=development` exists to prevent.

There is **no SQLite fallback for the app** (only the pytest escape hatch via `TEST_DATABASE_URL`); `DATABASE_URL` is required and migrations run automatically at boot via `init_db()` → Alembic, so there is no manual `alembic upgrade head` step for normal dev.

```bash
cd backend
python3 -m pip install -r requirements.txt
# optional: train the classifiers. Skipped => rules-only fallback, still works.
python3 scripts/train_nlp.py
PYTHONPATH=. APP_ENV=development uvicorn app.main:app --reload --port 8000
# API docs: http://localhost:8000/docs
```

### 2. Frontend

The frontend reads the **repo-root `.env`** too (`vite.config.ts` sets `envDir: '..'`). Do **not** create `frontend/.env` — `frontend/.env.example` is a reference-only document listing the `VITE_*` keys the browser bundle cares about. Put values in the repo-root `.env` (dev) or in Vercel → Environment Variables (production). Only `VITE_`-prefixed keys reach the browser; server secrets in the same file are never shipped to the client.

```bash
cd frontend
npm install
npm run dev                  # UI: http://localhost:5173
```

Set in the **repo-root** `.env` (dev):

```env
VITE_API_URL=                # LEAVE EMPTY locally
VITE_PROXY_TARGET=http://localhost:8000
VITE_SUPABASE_URL=https://xxxx.supabase.co
VITE_SUPABASE_ANON_KEY=...
```

**Leave `VITE_API_URL` empty.** The Vite dev server proxies `/api` and `/health` to `VITE_PROXY_TARGET` (`http://localhost:8000`), so the browser calls its own origin and CORS never applies. If you point it at a deployed backend instead, you are testing production from localhost and must add `http://localhost:5173` to that backend's `CORS_ORIGINS`. For split hosting (Vercel + Railway) set `VITE_API_URL` to the Railway backend origin with no trailing slash — Vite bakes `VITE_*` in at **build** time, so changing it requires a Vercel rebuild, not just a redeploy. `frontend/src/api.ts` falls back to the Railway production host only when served from `*.vercel.app` with `VITE_API_URL` unset.

### 3. Sign up

Authentication is Supabase. Use **Sign up** on the login page, confirm the email, and the `handle_new_user()` trigger mirrors the row into the app's `users` table with role **`Analyst`** and a personal organization. There is no `/auth/register`, `/auth/login`, or `/auth/refresh` endpoint to call directly (they were removed in the Supabase migration; the `refresh_tokens` table is dropped by migration `b7c2d1a9e4f5` — Supabase manages sessions); the only auth route is `GET /auth/me`, which reads role/org from `public.users`, never from the token.

**Demo accounts (dev only):** the login page offers ⚡ Quick Login `admin` / `analyst` (passwords `admin123` / `analyst123`). These are frontend `DEV_TOKENS` (`src/auth.tsx`) verified against the dev HS256 fallback in `routers/deps.py` — they work when Supabase is unconfigured, or whenever the username is literally `admin`/`analyst`. They are not Supabase users and do not exist in production.

### 4. Optional services

Neo4j, Elasticsearch, Kafka/Redis/Celery are all optional — leave them unset and the app degrades gracefully (networkx instead of Neo4j, SQLite search instead of ES, synchronous pipeline instead of Celery, in-process dict cache instead of Redis). `docker compose up --build` starts them, but note it reads the **repo-root** `.env`; point that at a local database first or you will run local containers against production data. Production uses Supabase Postgres — there is no local `postgres` service in `docker-compose.yml`.

### Key API (all `/api/v1/*` require a Supabase JWT bearer token except where noted)
- Auth: `GET /auth/me` (only auth route — Supabase owns login/register/refresh)
- Emails: `POST /emails/ingest {"raw": "<rfc822>"}` (`?async_mode=true` → 202 + `GET /tasks/{id}` when `CELERY_BROKER_URL` is set) · `POST /emails/upload` (`.eml/.txt/.mime`, 5 MB max) · `GET /emails?limit=&offset=&q=` · `GET /emails/{id}` (email + analysis + trace, includes `score_breakdown`)
- Dashboard/search/graph: `GET /dashboard` (5-min cache, tenant-scoped) · `GET /search?q=` (ES when configured, else SQLite) · `GET /graph/related?value=...` · `GET /graph/campaigns` (infra clusters only, no tenant PII)
- Campaigns: `GET /campaigns` · `GET /campaigns/{id}`
- Cases: `GET /cases` · `POST /cases` (Analyst+) · `PATCH /cases/{id}` (Analyst+, enum status → 422) · `DELETE /cases/{id}` (Admin only)
- Reports: `GET /reports/{id}.json` · `GET /reports/{id}.pdf` (chain-of-custody, `Content-Disposition` filename)
- Model/admin: `GET /model/metrics` (from `ml_models/metrics.json`) · `POST /admin/retention` (Admin only)
- Realtime: `POST /ws/ticket` (60-s ticket; long-lived tokens are never in URLs) → `WS /ws/alerts?ticket=` (same-org + Admin broadcast, score ≥75)
- Gmail (personal, per-user vault): `GET /gmail/status` · `POST /gmail/auth-url` · `POST /gmail/callback` · `POST /gmail/sync` · `DELETE /gmail/disconnect`
- Org mailboxes (Google + Microsoft, tenant-scoped): `POST /oauth/{google|microsoft}/authorize` · `GET /oauth/{provider}/callback` (server-side opaque state + PKCE, allowlisted `redirect_uri`) · `GET /oauth/status` · `POST /oauth/sync-now` · `DELETE /oauth/{provider}`
- Health (public): `GET /health` (includes effective `cors_origins` — curl this first for CORS triage) · `GET /health/detailed` (DB + NLP + URL-ML status) · `GET /` (app/docs/api pointers)

Roles: **ReadOnly** reads; **Analyst** ingests + edits cases + syncs mailboxes; **Admin** deletes cases + runs retention + sees all tenants. New Supabase signups default to **Analyst** with a personal workspace org (see `supabase_handle_new_user.sql` + `models.py`); all email/case/dashboard/search queries are tenant-scoped (Admins see all, cross-tenant reads return 404, not 403). The remaining "refresh tokens" in the codebase are **provider OAuth refresh tokens** (Gmail/Microsoft, Fernet-encrypted via `TOKEN_ENCRYPTION_KEY`), not login-session tokens.

### Gmail live demo + org mailboxes
1. Google Cloud console → enable Gmail API → OAuth client (**Web**), redirect URI = your frontend origin (e.g. `http://localhost:5173/` locally, `https://<app>.vercel.app/` when deployed — must match exactly, trailing slash included, and be allowlisted via `FRONTEND_URL` / `GOOGLE_REDIRECT_URI` / `OAUTH_REDIRECT_ALLOWLIST`).
2. Set `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` in `.env` (both must belong to the same OAuth client; the secret is server-side only and is never accepted per-request on the org flow).
3. Dashboard → "Gmail live import" (personal `GmailAccount` vault) → Connect Gmail → approve. Google redirects back to a new app tab, which **auto-captures the `?code=` + `state` from the URL and finishes the connection by itself** (Finish connection is only a retry). Then **Sync now** pulls unread mail through the pipeline.
4. Organization connectors live under "Mailboxes" in the UI (Google/Microsoft OAuth, encrypted refresh tokens, `POST /oauth/...`). `MAIL_POLL_MINUTES=0` (default) means manual "Sync now" only; set e.g. `60` for hourly background polling via `services/mailbox_poll.py`.

Optional integrations (VirusTotal/MISP/Slack/PagerDuty/Neo4j/Kafka) are off when unset — fill the relevant keys in `.env` to enable them.

### NLP model dataset
```bash
python3 backend/scripts/fetch_datasets.py  # SpamAssassin ham/spam + curated BEC -> backend/ml_models/dataset.csv (gitignored)
python3 backend/scripts/train_nlp.py       # 80/20 stratified split, metrics -> ml_models/metrics.json + phishing_clf.joblib (+ .sha256)
```
`dataset.csv` is **not** committed, but the trained artifacts are: this checkout ships `phishing_clf.joblib` + `url_phishing_model.pkl` (each with a `.sha256` sidecar, verified at load; production can pin `MODEL_VERIFY_KEY` for Ed25519 and refuses unpinned transformers). Committed `metrics.json` (3012-row SpamAssassin+BEC corpus): accuracy **0.9934**, macro F1 **0.6593** (clean F1 0.998 / phishing 0.98 / BEC 0.0 on support=2 — severe BEC imbalance, see Model Info page + confusion matrix). Without the download (offline), `train_nlp.py` falls back to the ~120-row curated lists. Verify/sign offline with `backend/scripts/sign_model.py`.

### Attachment analysis
Attachments are hash-checked against VirusTotal (skipped without `VIRUSTOTAL_API_KEY`) plus offline heuristics: macro-enabled Office docs, double extensions, executables, and magic-byte mismatches feed an `attachment_risk` score weight (0.10).

### URL intelligence
`modules/threat_intel/url_ml.py` ships a second sklearn model (`url_phishing_model.pkl`): lexical URL features (length, entropy, IP-literal, punycode, suspicious TLD, shortening service, …). Warmed at boot, reported in `/health/detailed`, and folded into the fraud score alongside the text classifier.

### Privacy model
Raw email bodies are **never persisted** — only the masked version is stored (cards/SSN/phones/email-localparts redacted; names/addresses/IPs are not masked). Forensic reports mask subject/sender/recipient as well. Search escapes LIKE wildcards and indexes masked fields only.

### Retention
`services/scheduler.py` runs `apply_retention()` daily at 03:00 (`RETENTION_HOUR`), logging purged counts + timestamp to `backend/retention_audit.log`. Old clean mail is body-blanked (metadata kept); old malicious mail is fully deleted (email + analysis + trace + ES doc + graph node) in batches with per-batch rollback. Manual run: `POST /api/v1/admin/retention` (Admin). Tunables: `RETENTION_CLEAN_DAYS=7`, `RETENTION_MALICIOUS_DAYS=90`.

### Secrets (compose / k8s)
No credentials are committed. For compose: `cp .env.example .env`, fill in `*_PASSWORD`/`*_KEY` values, then `docker compose up --build` (compose fails fast if a required secret is missing). This is the same file the backend reads, so there is one set of values to maintain. For Kubernetes: create `soc-secrets` per `k8s/secret.yaml.example` (template only — never apply real values from a file). Elasticsearch ships with `xpack.security.enabled=true`; set `ELASTICSEARCH_URL/USER/PASSWORD` to wire the full-text mirror, otherwise search transparently falls back to SQLite.

### Mailbox polling
Organization connectors live under "Mailboxes" in the UI (Google/Microsoft OAuth, encrypted refresh tokens via `TOKEN_ENCRYPTION_KEY`, Fernet). `MAIL_POLL_MINUTES=0` (default) means manual "Sync now" only; set e.g. `60` for hourly background polling.

### Full-text search
`GET /api/v1/search?q=...` queries Elasticsearch (`email.subject^3`, sender, body) when configured, else the same SQLite search as the email list — the endpoint always works locally.

### Code quality gates
Backend: `ruff check backend --select E9,F`, `pip-audit -r backend/requirements.txt`, `pytest backend/tests` (`pytest.ini`: `pythonpath=.`, `testpaths=tests`; 30+ test modules incl. `test_step*_*.py`). Frontend: `npm run lint`, `npm audit --omit=dev --audit-level=high`, `npm test` (Vitest), `npm run build`. All run in `.github/workflows/ci.yml`.

### Live-demo rehearsal
```bash
PYTHONPATH=backend uvicorn app.main:app --port 8000   # terminal 1 (or: cd backend + PYTHONPATH=. ... )
python3 backend/scripts/live_demo_check.py            # terminal 2 (uses admin/analyst dev tokens)
```
The script checks env/keys, API health, login, an ingest roundtrip whose Why-breakdown must sum to the score, plus campaigns/model/oauth/gmail endpoints, and exits non-zero with FAIL lines for anything needing attention. For a fully live demo set `ENABLE_LIVE_LOOKUPS=1` with real keys (`VIRUSTOTAL_API_KEY`, MaxMind DB at `GeoLite2-City.mmdb`, `MISP_URL/KEY`) and `SECRET_KEY`/`CUSTODY_KEY` from your secrets manager — rehearse the script once with those set.

### Configuration
- `ENABLE_LIVE_LOOKUPS=1` — **recommended for any live deployment**: opt into live enrichment (ip-api over HTTPS, WHOIS, DNS, DNSBL, URLhaus, SPF/DKIM/DMARC DNS). Default `0` = fast offline mode with static GeoIP fallback, so ingestion takes <1s and works without network. Offline, auth checks report `unverifiable` (distinct from real failures) and score near-zero.
- `TRUSTED_RELAY_HOSTS` / `TRUSTED_RELAY_IPS` (comma-separated) — your own relays, used as the trust boundary for origin-IP extraction.
- `CELERY_BROKER_URL` (e.g. `redis://localhost:6379/0`) — enables the optional Celery async path (`?async_mode` + `GET /tasks/{id}`, ownership-checked per tenant); unset keeps the synchronous pipeline. `CELERY_RESULT_BACKEND` defaults to in-memory cache.
- `REDIS_URL` — shared cache for GeoIP (24h), WHOIS (24h), DNS (1h) and dashboard (5min, invalidated on writes); unset keeps an in-process dict cache with the same TTLs.
- High-risk mail (score ≥75) is pushed over WebSocket (`POST /ws/ticket` → `/ws/alerts?ticket=`) to same-org clients (Admins get all); the nav bell shows the live stream.
- `KNOWN_LEGIT_DOMAINS` (comma-separated) — extra brands for lookalike-domain detection, appended to the built-in list.
- Operator blocklist lives in `backend/data/local_blocklist.txt` (one domain per line), not in code; hard-coded demo domains only fire in development.
- `MODEL_VERIFY_KEY` (64-hex Ed25519 pubkey) — production model-signature verification for `<artifact>.sig`; without it, loads fall back to `.sha256` sidecars, and with neither production refuses to unpickle. Never set `MODEL_TRUST_INSECURE=1` outside local dev.
- `CORS_ORIGINS` — comma-separated browser origins allowed to call the API (default `https://email-scanner-chi.vercel.app`, the deployed frontend). Origins are matched on scheme + host + port, case-insensitively, with trailing slashes stripped; `*` is refused at boot because `allow_credentials` is on. `CORS_ORIGIN_REGEX` adds opt-in patterns (e.g. Vercel preview hosts), `fullmatch`ed against the whole origin and refused at boot if a pattern would match every origin. **`GET /health` reports the effective allowlist** — the fastest way to diagnose "blocked by CORS policy" in a split deploy, since the browser says nothing useful. `DEPLOY.md` §4.1 has the full triage runbook.
- `CUSTODY_KEY` (+ optional `CUSTODY_KEY_PREVIOUS` rotation window) — HMAC key for chain-of-custody report signatures. **Must be provisioned from a secrets manager in any non-local deployment**; the app refuses to start when `APP_ENV` is not `development` and no key is set. (`APP_ENV=development` is the local default and keeps an explicit dev fallback.)
- `TOKEN_ENCRYPTION_KEY` — Fernet/PBKDF2 vault key for mailbox OAuth tokens (min 32 chars); fail-closed when empty.
- `SECRET_KEY` — HMAC key for WebSocket tickets (min 32 chars outside dev); the app refuses to boot in production without it.
- `SMTP_ENABLED=1` (+ `SMTP_HOST`/`SMTP_PORT`, default `127.0.0.1:1025`) — start the inline SMTP relay; received mail is queued (bounded `SMTP_QUEUE_MAX` count + bytes, overflow answers 452) and analyzed by a background consumer task. Harden with `SMTP_REQUIRE_AUTH=1` + `SMTP_USERNAME`/`SMTP_PASSWORD`, `SMTP_TLS_CERT`/`SMTP_TLS_KEY` (STARTTLS), `SMTP_DATA_LIMIT_BYTES`.
- Rate limits (slowapi, kill-switch `RATE_LIMIT_ENABLED`): 60/min ingest, 30/min OAuth, 10/min sync — Supabase owns login throttling server-side.
- Managed Postgres: `alembic upgrade head` from `backend/` (SQLite dev uses the fast built-in path). Ingest is idempotent per tenant (duplicate bytes return the stored verdict).
- `VITE_API_URL` (frontend) — backend base URL for split hosting; same-origin by default. See repo-root `.env` + `frontend/.env.example` (reference only).
- `EXPECTED_REPLICAS` — set >1 with `NEO4J_URI` or replicas diverge on the in-memory graph.
- Health: `GET /health` (liveness + CORS allowlist) and `GET /health/detailed` (DB + NLP + URL-ML status).

### Deploy
See [DEPLOY.md](DEPLOY.md) for the full Vercel + Railway + Supabase runbook (env tables, CORS triage, migration notes). Quick map: `railway.json` → `backend/Dockerfile`; Vercel root directory `frontend` (`npm run build` → `dist`, Node 22.x); `docker-compose.yml` for local full-stack (no Supabase-local postgres); `k8s/backend.yaml` + `k8s/secret.yaml.example` for cluster deploys.

### Present-Stage Notes (September 2026)
- "AI" scope: the running ML is TF-IDF + LogisticRegression text classifier (30% of fraud score) + a lexical URL classifier plus hand-written linguistic cues; transformer reranking is a dormant opt-in hook (`TRANSFORMERS_MODEL` + pinned `TRANSFORMERS_REVISION`), refused in production when unpinned. See PRD § Present-Stage Scope Note.
- Accounts come from Supabase, not from a seed script: sign up in the UI (with the trigger in `backend/supabase_handle_new_user.sql` applied), and the row is mirrored into the app's `users` table (which is where role and organization are read from — never from the token). There is no `app.seed` module; if you were told to run one, it was removed in the Supabase migration. New users default to **Analyst**, not ReadOnly.
- Dev quick-logins (`admin`/`analyst`) are a local/offline convenience (Login page ⚡ buttons + `DEV_TOKENS`), not production accounts.
- Quirk: API returns transient 500s while `uvicorn --reload` restarts on file saves — wait ~10s and retry.
- Sync speed: large real emails take tens of seconds each through the pipeline; multi-mail syncs complete but slowly (background-job fix queued — use `?async_mode` + Celery when configured).
- Split deploy (Vercel + Railway): set `VITE_API_URL` to the Railway backend (baked at build time — editing the variable requires a Vercel rebuild, not just a redeploy); register `https://<app>.vercel.app` as the Google OAuth redirect URI; mirror that exact origin in `GOOGLE_REDIRECT_URI`, `FRONTEND_URL` and `CORS_ORIGINS`. Copying a `[your-app]` placeholder literally into `CORS_ORIGINS` is the usual cause of a total frontend outage — the app builds, health checks pass, and only browsers fail.
- Tests: `cd backend && APP_ENV=development python -m pytest tests/ -q` (`APP_ENV=development` is required or startup refuses). `cd frontend && npm test && npm run build` (Vitest).

## Contributing
Please adhere to the coding standards defined in the repository wiki. Ensure all commits referencing feature additions are tied to tasks in `Tracker.md`.

## License
Proprietary / Confidential. All rights reserved.
