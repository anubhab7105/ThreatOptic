# Deploy Guide — Vercel (Frontend) + Railway (Backend) + Supabase (Auth + Postgres)

This repo is a monorepo: `frontend/` is a Vite + React SPA, `backend/` is a FastAPI service. Production stack:

- **Frontend → Vercel** (static, edge-cached, SPA rewrites)
- **Backend → Railway** (Docker, health checks)
- **Database + Auth → Supabase** (Postgres via Transaction Pooler + Supabase Auth JWT)

---

## 0. Prerequisites

- GitHub account and this repo pushed to GitHub
- Vercel account (https://vercel.com) linked to GitHub
- Railway account (https://railway.app) linked to GitHub
- Supabase project (https://supabase.com) — **do NOT add Railway Postgres addon**
- Domain (optional — you can use Vercel's `*.vercel.app` and Railway's `*.up.railway.app`)

### 0.1 Verify `.env` was never committed

```bash
git log --all --full-history -- .env
# If any commits appear, rotate secrets immediately in Supabase dashboard
```

### 0.2 Generate missing secrets locally (for Railway Variables)

```powershell
# SECRET_KEY (WebSocket ticket HMAC, 32+ chars)
python -c "import secrets; print(secrets.token_urlsafe(32))"

# CUSTODY_KEY (chain-of-custody signing, 32+ chars)
python -c "import secrets; print(secrets.token_urlsafe(32))"

# TOKEN_ENCRYPTION_KEY (Fernet key for OAuth token encryption)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 0.3 Supabase — verify prerequisites

1. Log into Supabase → your project
2. **Authentication → Email** → ✅ Confirm "Enable Email Confirmations" is ON
3. **Authentication → URL Configuration** → Add `http://localhost:5173` to Redirect URLs for local dev
4. **SQL Editor** → Run the `on_auth_user_created` trigger SQL (from Supabase Migration Plan). Verify it exists under **Database → Functions**
5. Collect these values (needed for Railway + Vercel):
   - `DATABASE_URL` (Transaction Pooler, port 6543, `?pgbouncer=true`) — already in `.env`
   - `SUPABASE_JWT_SECRET` — already in `.env`
   - `SUPABASE_URL` + `SUPABASE_ANON_KEY` (from **Project Settings → API**) — needed for frontend

---

## 1. Fix `docker-compose.yml` for Local Dev (Optional)

Since production uses Supabase Postgres, the local `postgres` service has been removed. Neo4j, Elasticsearch, and Kafka remain for optional local use.

Run locally:
```bash
docker compose up -d
# Backend at http://localhost:8000 (reads Supabase DATABASE_URL from .env)
# Frontend at http://localhost:5173 (proxies to backend)
```

---

## 2. Deploy Backend to Railway

### 2.1 Create the Railway Project

1. Go to railway.app → **New Project** → **Deploy from GitHub repo**
2. Select your `Email_Scanner` repository
3. Railway detects `railway.json` at repo root → uses `backend/Dockerfile`
4. ⚠️ **Critical:** Under **Service → Settings → Source → Root Directory** — confirm it is **blank/empty**. Do NOT set it to `backend`. The Dockerfile uses `COPY backend/requirements.txt` which requires repo-root context.

### 2.2 Do NOT add a Railway Postgres addon

> **WARNING:** If you add a Railway Postgres database, Railway will inject its own `DATABASE_URL` variable which will silently overwrite your Supabase connection string. Skip the Postgres addon entirely.

### 2.3 Set Environment Variables

Go to **Railway Service → Variables → Raw Editor** → paste all of the following:

```env
APP_ENV=production
# Database — Supabase Transaction Pooler
DATABASE_URL=postgresql://postgres.lwdlgmwuqbfjeqxaxcck:[YOUR-PASSWORD]@aws-0-ap-south-1.pooler.supabase.com:6543/postgres?pgbouncer=true
# Supabase Auth JWT verification
SUPABASE_JWT_SECRET=[your-supabase-jwt-secret]
# App Secrets (generate fresh values for production — see Phase 0.2)
SECRET_KEY=[your-32-char-secret-key]
CUSTODY_KEY=[your-32-char-custody-key]
TOKEN_ENCRYPTION_KEY=[your-fernet-key]
# CORS — update AFTER you get your Vercel URL in Phase 3
CORS_ORIGINS=https://[your-app].vercel.app
# Frontend URL (for OAuth redirect allowlisting)
FRONTEND_URL=https://[your-app].vercel.app
# Optional features — leave empty to disable
NEO4J_URI=
NEO4J_PASSWORD=
ELASTICSEARCH_URL=
VIRUSTOTAL_API_KEY=
SLACK_WEBHOOK_URL=
PAGERDUTY_ROUTING_KEY=
ENABLE_LIVE_LOOKUPS=0
SMTP_ENABLED=0
# Gmail / Microsoft OAuth (leave empty if not using)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=
MS_CLIENT_ID=
MS_CLIENT_SECRET=
```

> **Note:** `SECRET_KEY` is now only used for WebSocket tickets (`create_ws_ticket()`). It is no longer used for JWT login. Still required — the app refuses to boot without it in production.

### 2.4 Deploy and Get Your Railway URL

1. Railway auto-deploys on every push to `main`. Watch **Deployments** — should turn **Active** in ~3-4 minutes (first build is slower due to pip + ML model training in the Dockerfile)
2. Go to **Service → Settings → Networking → Generate Domain**
3. Copy your Railway domain: `https://[something].up.railway.app`
4. Verify:
   ```bash
   curl https://[your-railway-domain]/health
   # Expected: {"status":"ok","app":"Email Threat & Forensics Platform"}

   curl https://[your-railway-domain]/health/detailed
   # Expected: {"status":"ok","db":true, ...}
   ```
   If `"db":true` — Supabase Postgres is connected. ✅

### 2.5 Run Alembic Migrations

The `backend/alembic/versions/` directory has two revisions:
- `834dc871451e` — initial schema
- `b7c2d1a9e4f5` — Supabase auth migration

These run automatically on startup because `init_db()` calls `_alembic_upgrade()`. Watch the Railway deployment logs for:
```
INFO  [alembic.runtime.migration] Running upgrade 834dc871451e -> b7c2d1a9e4f5
```

> **Tip:** If you need to run migrations manually (e.g., to debug), use the Railway CLI:
> ```bash
> npm i -g @railway/cli
> railway login
> railway link
> railway run --service backend -- alembic upgrade head
> ```

---

## 3. Deploy Frontend to Vercel

### 3.1 Import the Project

1. Go to vercel.com → **Add New** → **Project** → Import `Email_Scanner` from GitHub
2. **Framework Preset:** Vite
3. **Root Directory:** Click **Edit** → set to `frontend`
4. **Build Command:** `npm run build` (runs `tsc -b && vite build`)
5. **Output Directory:** `dist`
6. **Node Version:** In Project Settings → General → set to `22.x`

### 3.2 Set Environment Variables

In Vercel → Project → **Settings → Environment Variables** → add:

| Key | Value | Environments |
|-----|-------|--------------|
| `VITE_API_URL` | `https://[your-railway-domain].up.railway.app` | Production, Preview, Development |
| `VITE_SUPABASE_URL` | `https://[your-project-ref].supabase.co` | Production, Preview, Development |
| `VITE_SUPABASE_ANON_KEY` | `[your-supabase-anon-key]` | Production, Preview, Development |

> **Important:** `VITE_API_URL` must have **no trailing slash** and **no `/api/v1` suffix**. The frontend appends `/api/v1` automatically via `api.ts`.

### 3.3 Deploy

1. Click **Deploy** — Vercel builds in ~45 seconds
2. Your frontend will be live at: `https://email-scanner-[hash].vercel.app` (or your project name slug)
3. Open DevTools → Network — confirm API calls go to your Railway domain, not localhost

---

## 4. Wire Vercel ↔ Railway ↔ Supabase Together

### 4.1 Update Railway CORS (REQUIRED)

Now that you have your Vercel URL, go back to **Railway → Variables** and update:

```env
CORS_ORIGINS=https://[your-app].vercel.app
FRONTEND_URL=https://[your-app].vercel.app
```

Then redeploy the Railway backend (click **Redeploy** in the Deployments tab).

### 4.2 Update Supabase Redirect URLs

Go to **Supabase → Authentication → URL Configuration**:

- **Site URL:** `https://[your-app].vercel.app`
- **Redirect URLs:** Add `https://[your-app].vercel.app/**`

This is critical — Supabase will reject email confirmation redirects that point to unlisted domains.

### 4.3 End-to-End Test Checklist

- ✅ Visit `https://[your-app].vercel.app`
- ✅ Register with a real email address
- ✅ Check inbox — confirmation email arrives from Supabase
- ✅ Click confirm link — redirected back to your Vercel app
- ✅ Login with email + password
- ✅ Dashboard loads with your user data
- ✅ Upload a test `.eml` file — analyze completes
- ✅ Logout — session cleared

---

## 5. CI/CD (Auto-Deploy on Push)

Both platforms auto-deploy on git push to `main`. No additional setup needed.

```bash
# The one-liner that deploys both frontend and backend:
git add . && git commit -m "deploy: <description>" && git push
```

- **Vercel** → detects changes in `frontend/` → rebuilds in ~45s
- **Railway** → detects any push → rebuilds the Docker image in ~3-4 min

---

## 6. Environment Variables Master Reference

### Backend (Railway Variables)

| Variable | Required | Source |
|----------|----------|--------|
| `APP_ENV` | ✅ | `production` |
| `DATABASE_URL` | ✅ | Supabase Transaction Pooler URL |
| `SUPABASE_JWT_SECRET` | ✅ | Supabase → Settings → API → JWT Settings |
| `SECRET_KEY` | ✅ | Generate: `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `CUSTODY_KEY` | ✅ | Generate: same as above |
| `TOKEN_ENCRYPTION_KEY` | ✅ (if OAuth) | Generate: `from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())` |
| `CORS_ORIGINS` | ✅ | Your Vercel URL |
| `FRONTEND_URL` | ✅ | Your Vercel URL |
| `GOOGLE_CLIENT_ID/SECRET` | ⬜ Optional | For Gmail OAuth |
| `MS_CLIENT_ID/SECRET` | ⬜ Optional | For Microsoft OAuth |
| `VIRUSTOTAL_API_KEY` | ⬜ Optional | For live threat intel |
| `ENABLE_LIVE_LOOKUPS` | ⬜ | `0` (offline) default |

### Frontend (Vercel Environment Variables)

| Variable | Required | Source |
|----------|----------|--------|
| `VITE_API_URL` | ✅ | Your Railway domain |
| `VITE_SUPABASE_URL` | ✅ | Supabase → Settings → API |
| `VITE_SUPABASE_ANON_KEY` | ✅ | Supabase → Settings → API |

---

## 7. Known Non-Blockers (Fix Anytime)

| Issue | Impact | Fix |
|-------|--------|-----|
| `index.html` canonical URL hardcoded to `socforensics.io` | SEO only — app still works | Update when you get your domain |
| `frontend/public/CNAME` says `socforensics.io` | Only matters for GitHub Pages (not used) | Ignore or delete the file |
| `DEPLOY.md` references SQLite fallback + old auth routes | Documentation drift | Updated in this file |
| `docker-compose.yml` had a local postgres service | Local dev only — doesn't affect Railway | Fixed in Phase 1 above |

---

## 8. Recommended First Deployment Order

1. **Phase 0** → Secure secrets, verify Supabase
2. **Phase 2** → Deploy Backend to Railway
3. **Phase 3** → Deploy Frontend to Vercel
4. **Phase 4** → Wire them together (CORS, Supabase redirects)
5. **Phase 1** → Fix `docker-compose.yml` (only if doing local dev)

Skip Phase 1 for now if you're not using it locally — it doesn't affect cloud deployment at all.