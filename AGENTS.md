# AGENTS.md — Email Threat Detection Platform

Monorepo: `backend/` (FastAPI, entry `backend/app/main.py`) + `frontend/` (Vite + React + TS SPA). Prod is Vercel (frontend) + Railway (backend) + Supabase (Postgres + Auth). No local postgres service.

## Env — single repo-root `.env`
- Backend (`app/config.py`) and frontend (`vite.config.ts` `envDir: '..'`) both read **repo-root `.env`**. Path is anchored to file location, cwd-independent.
- Do NOT create `frontend/.env` — `frontend/.env.example` is reference-only. `backend/.env` is an optional override (takes precedence); normally don't create it.
- `cp .env.example .env`, set `APP_ENV=development`. Default `app_env` is `production` and boot **refuses** without `SECRET_KEY` (32+ chars), `CUSTODY_KEY`, `DATABASE_URL`. Dev only logs warnings.
- `CORS_ORIGINS` comma-separated exact origins, no trailing slash; `*` or match-everything `CORS_ORIGIN_REGEX` refuses boot (credentials on). Triage with `curl <api>/health` — it echoes effective `cors_origins`.
- Local frontend: leave `VITE_API_URL` **empty** (dev proxy forwards `/api`, `/health` to `VITE_PROXY_TARGET=http://localhost:8000`, no CORS). Prod: set to Railway origin, no trailing slash/no `/api/v1`; Vite bakes `VITE_*` at **build** time — changing it needs a Vercel rebuild.

## Run
```bash
cd backend && python -m pip install -r requirements.txt
PYTHONPATH=. APP_ENV=development uvicorn app.main:app --reload --port 8000  # docs at /docs
cd frontend && npm install && npm run dev  # http://localhost:5173
```
- Windows: `start.ps1` / `start.bat` opens both. Railway root dir must stay **blank** (Dockerfile does `COPY backend/...` from repo root).
- `DATABASE_URL` (Supabase pooler `:6543`) required — no SQLite fallback in app. Migrations auto-run at boot via `init_db()` → Alembic; no manual upgrade for dev.
- Auth is Supabase-only: no `/auth/register|login|refresh` routes (removed). Only `GET /auth/me` (role/org from `public.users`). Run `backend/supabase_handle_new_user.sql` **once** in Supabase or signups 401. Dev quick-logins `admin`/`analyst` (`admin123`/`analyst123`, `DEV_TOKENS` in `src/auth.tsx` ↔ HS256 fallback in `routers/deps.py`) work only locally/offline.
- Neo4j / Elasticsearch / Kafka+Redis+Celery are all optional with local fallbacks (networkx, SQLite search, sync pipeline, dict cache). `docker compose up --build` reads repo-root `.env` — point it at a local DB first or containers hit prod. `MAIL_POLL_MINUTES=0` default = manual sync only. `ENABLE_LIVE_LOOKUPS=0` default = fast offline mode; `1` enables ip-api/WHOIS/DNS/DNSBL/URLhaus.

## Verify (mirrors `.github/workflows/ci.yml`)
```bash
ruff check backend --select E9,F
pip-audit -r backend/requirements.txt
python backend/scripts/train_nlp.py          # CI trains before testing
PYTHONPATH=backend pytest backend/tests -v   # or: cd backend && APP_ENV=development python -m pytest tests/ -q
cd frontend && npm run lint && npm audit --omit=dev --audit-level=high && npm test && npm run build
```
- `backend/pytest.ini`: `pythonpath=.`, `testpaths=tests`. `tests/conftest.py` forces `APP_ENV=development`, synthetic secrets, `RATE_LIMIT_ENABLED=0`, and gives **each test a fresh tmp SQLite DB** via `TEST_DATABASE_URL` + `rebuild_engine()` — never point tests at a real DB. Frontend `npm test` = `vitest run`.
- Deps: exact pins in `backend/requirements.in`; regenerate lock with `backend/.venv/bin/pip-compile --generate-hashes --python-version 311 --output-file=backend/requirements.txt backend/requirements.in`.

## Conventions / gotchas
- RBAC: ReadOnly reads; Analyst ingests/edits cases/syncs; Admin deletes cases + `POST /api/v1/admin/retention`. New signups default **Analyst** + personal org. All email/case/dashboard/search queries tenant-scoped; cross-tenant reads return **404, not 403**. Ingest idempotent per tenant on `(raw_eml_hash, org)`.
- Upload: `.eml/.txt/.mime` only, 5 MB max (`frontend/src/api.ts` + backend agree). Reports download via authed fetch blob, not anchor links. OAuth `redirect_uri` must exactly match allowlist incl. trailing slash (`FRONTEND_URL`/`GOOGLE_REDIRECT_URI`/`OAUTH_REDIRECT_ALLOWLIST`).
- ML artifacts (`backend/ml_models/*.joblib|*.pkl` + `.sha256` + `metrics.json`) are committed; `dataset.csv` is gitignored. Build with `python backend/scripts/fetch_datasets.py && python backend/scripts/train_nlp.py`; sign with `scripts/sign_model.py`. Prod refuses unpickling without `.sha256`/`.sig` (`MODEL_VERIFY_KEY`); never set `MODEL_TRUST_INSECURE=1` outside dev. Score weights: nlp .30 / auth .25 / intel .20 / routing .15 / attachment .10; `score_breakdown` must sum to score.
- Raw email bodies are never persisted (only masked `body_text_masked`); search indexes masked fields only. Retention runs daily 03:00 (`RETENTION_HOUR`): clean body-blanked at 7d, malicious fully deleted at 90d.
- `uvicorn --reload` serves transient 500s during restart — wait ~10s and retry. Full docs: `readme.md` (index), `DEPLOY.md` §4.1 (CORS triage), `Rules.md` (scoring/RBAC), `SECURITY.md` (secret rotation).
