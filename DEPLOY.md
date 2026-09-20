# Deploy Guide — Vercel (Frontend) + Railway (Backend)

This repo is a monorepo: `frontend/` is a Vite + React SPA, `backend/` is a FastAPI service. The recommended production split is:

- **Frontend → Vercel** (static, edge-cached, SPA rewrites)
- **Backend → Railway** (Docker, Postgres, health checks)

Custom domain used throughout: `https://socforensics.io` (CNAME `socforensics.io` in `frontend/public/CNAME`, canonical in `frontend/index.html:11`). Replace with your own domain if needed.

---

## 0. Prerequisites

- GitHub account and this repo pushed to GitHub
- Vercel account (https://vercel.com) linked to GitHub
- Railway account (https://railway.app) linked to GitHub
- Domain purchased (e.g., socforensics.io on Cloudflare / Namecheap / Route53)
- `SECRET_KEY`, `CUSTODY_KEY` generated locally (see below)

Generate secrets:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
# first -> SECRET_KEY, second -> CUSTODY_KEY (min 32 bytes)
```

---

## 1. Push to GitHub (if not already)

```bash
git init
git add .
git commit -m "chore: vercel+railway deploy config"
git branch -M main
git remote add origin https://github.com/<your-user>/Email_Scanner.git
git push -u origin main
```

---

## 2. Deploy Backend to Railway

### 2.1 Create project
1. Railway → **New Project** → **Deploy from GitHub repo** → select `Email_Scanner`
2. When prompted for service, choose **backend** (Railway auto-detects `backend/Dockerfile` via `railway.json:4` and `backend/railway.toml:1`)
3. **Root Directory:** leave **empty** (repo root `.`) — **do NOT set to `backend`**. `backend/Dockerfile:6` expects repo-root context (`COPY backend/requirements.txt`). If you set Root Directory to `backend`, the build will fail with `"/scripts": not found`.
   - If you already set it to `backend`, go to Service → Settings → Source → Root Directory → clear it → Redeploy.

### 2.2 Add Postgres (and optionally Redis/Neo4j)
1. In Railway project → **New** → **Database** → **PostgreSQL** → Add
2. Railway injects `DATABASE_URL` automatically as `postgresql://...` - **copy its internal URL**. For public, use the `DATABASE_URL` variable shown in Postgres → Variables.
3. If you need Neo4j/Elastic: add them the same way, or leave empty to use SQLite fallback (not recommended for production).

### 2.3 Set environment variables
Railway → Service `backend` → **Variables** → **Raw Editor** → paste:

```
APP_ENV=production
SECRET_KEY=<your-generated-secret-key>
CUSTODY_KEY=<your-generated-custody-key>
CORS_ORIGINS=https://socforensics.io,https://www.socforensics.io,https://<your-vercel-url>.vercel.app
DATABASE_URL=${{Postgres.DATABASE_URL}}
# or manually paste postgres URL if not using reference:
# DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/railway
FRONTEND_URL=https://socforensics.io
# Optional - leave empty for offline mode:
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
MS_CLIENT_ID=
MS_CLIENT_SECRET=
TOKEN_ENCRYPTION_KEY=<generate with python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
ENABLE_LIVE_LOOKUPS=0
NEO4J_URI=
NEO4J_PASSWORD=
ELASTICSEARCH_URL=
```

> **Important:** `CORS_ORIGINS` must include your final Vercel URL. Update it after step 3.4 (you can add both the vercel preview URL and your custom domain).

### 2.4 Deploy & get URL
1. Railway auto-deploys on push. Watch **Deployments** → should turn **Active** in ~2 min.
2. Go to **Settings** → **Networking** → **Generate Domain** → copy the Railway domain, e.g. `email-scanner-backend-production.up.railway.app`
3. Test health:

```bash
curl https://<railway-domain>/health
# {"status":"ok","app":"Email Threat & Forensics Platform"}

curl https://<railway-domain>/health/detailed
```

If `/health/detailed` shows `db: true`, Postgres is wired.

### 2.5 Railway notes
- `backend/Dockerfile:12` uses JSON form `CMD ["sh","-c","uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]` so it respects Railway’s injected `$PORT` and handles OS signals correctly (fixes `JSONArgsRecommended` warning).
- `railway.json:8` sets `healthcheckPath` to `/health` — Railway will restart on failure.
- `docker-compose.yml:5` now uses `context: .` + `dockerfile: ./backend/Dockerfile` so local `docker compose up` and Railway (root context) use the **same** Dockerfile. Do not build with `docker build ./backend` — use `docker build -f backend/Dockerfile .` from repo root.
- No `DATABASE_URL`? Backend falls back to SQLite (`sqlite:///./email_forensics.db`) — data will be ephemeral. Use Postgres for persistence.

---

## 3. Deploy Frontend to Vercel

### 3.1 Import project
1. Vercel → **Add New...** → **Project** → **Import Git Repository** → select `Email_Scanner`
2. **Framework Preset:** Vite
3. **Root Directory:** `frontend` ← click **Edit** and set to `frontend` (important, otherwise build fails)
4. If you import from root with `vercel.json:1` at repo root, you can keep Root Directory empty and Vercel will use `vercel.json:4` `buildCommand: cd frontend && npm install && npm run build` and `outputDirectory: frontend/dist`. Either way works — pick one:
   - **Option A (recommended):** Root Directory = `frontend` + leave `vercel.json` in `frontend/vercel.json:1` for SPA rewrite
   - **Option B:** Root Directory = `./` (root) + rely on root `vercel.json:1`

### 3.2 Build settings (if Root = frontend)
- **Build Command:** `npm run build` (runs `tsc -b && vite build` → `frontend/package.json:8`, `sourcemap:false` `frontend/vite.config.ts:12`)
- **Output Directory:** `dist`
- **Install Command:** `npm install`
- **Node Version:** 22.x (set in Vercel → Settings → General → Node Version)

### 3.3 Environment variables
Vercel → Project → **Settings** → **Environment Variables** → add:

| Key | Value | Env |
|-----|-------|-----|
| `VITE_API_URL` | `https://<railway-domain>` (from 2.4, no trailing slash, e.g. `https://email-scanner-backend-production.up.railway.app`) | Production, Preview, Development |
| `VITE_PROXY_TARGET` | leave empty (dev only) | — |

> `frontend/src/api.ts:3` reads `VITE_API_URL` at build time. Changing it requires a redeploy (Vercel auto-redeploys on env change).

### 3.4 Deploy
1. Click **Deploy** → Vercel builds in ~45s → you get `https://email-scanner-xxx.vercel.app`
2. Visit it, open DevTools → Network → should call `https://<railway-domain>/api/v1/...` not `localhost`.
3. Go back to Railway → update `CORS_ORIGINS` to include the new Vercel URL and redeploy backend:

```
CORS_ORIGINS=https://socforensics.io,https://www.socforensics.io,https://email-scanner-xxx.vercel.app
```

### 3.5 SPA rewrites
- Root `vercel.json:7` and `frontend/vercel.json:1` both rewrite `/(.*)` → `/index.html` so hash routes (`#/campaigns`, `#/privacy`) and direct hits to `/sitemap.xml` still work. No extra config needed.

---

## 4. Custom Domain (socforensics.io)

### 4.1 Frontend domain on Vercel
1. Vercel → Project → **Settings** → **Domains** → Add `socforensics.io` and `www.socforensics.io`
2. Vercel shows DNS records:
   - Type `A` → `76.76.21.21` (or CNAME `cname.vercel-dns.com` — follow Vercel’s prompt)
   - For `www`, add CNAME `www` → `cname.vercel-dns.com`
3. Add records at Cloudflare:
   - If using Cloudflare proxy, set to **DNS only** (grey cloud) for Vercel to issue cert, then you can re-enable proxy.
   - `frontend/public/CNAME:1` already contains `socforensics.io` for GitHub Pages-style, also used as documentation for Vercel.
4. Wait for cert → Vercel shows **Valid Configuration**
5. Update `frontend/index.html:11` canonical and `vercel.json:1` headers already point to `https://socforensics.io/` — redeploy if you changed domain.

### 4.2 Backend custom domain (optional)
If you want `api.socforensics.io` instead of Railway’s `*.up.railway.app`:
1. Railway → Backend → **Settings** → **Networking** → **Custom Domain** → add `api.socforensics.io`
2. Add CNAME `api` → `<railway-domain>` at DNS
3. Update Vercel env `VITE_API_URL=https://api.socforensics.io` → redeploy frontend
4. Update Railway `CORS_ORIGINS` to include `https://socforensics.io`

### 4.3 Keep domain in code consistent
Search-replace `socforensics.io` if you use a different domain:
- `frontend/index.html:11,20,47`
- `frontend/public/CNAME:1`
- `frontend/public/sitemap.xml:4`
- `frontend/public/robots.txt:5`
- `frontend/public/llms.txt:8`
- `frontend/src/main.tsx:17`, `frontend/src/pages.tsx:7`
- `frontend/nginx.conf:3`

---

## 5. Local test before pushing

```bash
# Backend (needs Postgres or falls back to SQLite)
cd backend
cp .env.example .env
# fill SECRET_KEY, CUSTODY_KEY, DATABASE_URL
pip install -r requirements.txt
python scripts/train_nlp.py || true
uvicorn app.main:app --reload --port 8000
# http://localhost:8000/health , http://localhost:8000/docs

# Frontend (in another terminal)
cd frontend
npm install
VITE_API_URL=http://localhost:8000 npm run dev
# http://localhost:5173

# Production build check (no sourcemaps, split chunks)
npm run build
npm run lint
npm test
# dist/ should have no *.map, favicon.svg, sitemap.xml, etc.
```

---

## 6. CI / Auto-deploy

- **Vercel:** auto-deploys on every `git push` to `main` (preview deploys for PRs).
- **Railway:** auto-deploys on every `git push` to `main` (watch Railway → Deployments). You can also `railway up` via CLI.

Install CLIs (optional):

```bash
npm i -g vercel
vercel login
vercel --prod

npm i -g @railway/cli
railway login
railway link
railway up
```

---

## 7. Environment variable cheat sheet

### Backend (Railway → Variables)
| Var | Required | Example |
|-----|----------|---------|
| `APP_ENV` | yes | `production` |
| `SECRET_KEY` | yes | `k8s...32bytes...` |
| `CUSTODY_KEY` | yes | `hmac...32bytes...` |
| `DATABASE_URL` | yes prod | `postgresql+psycopg2://soc:pass@postgres:5432/soc` (Railway provides) |
| `CORS_ORIGINS` | yes | `https://socforensics.io,https://<vercel>.vercel.app` |
| `FRONTEND_URL` | yes | `https://socforensics.io` |
| `TOKEN_ENCRYPTION_KEY` | if using OAuth | Fernet key |
| `GOOGLE_CLIENT_ID/SECRET` | optional | Gmail OAuth |
| `MS_CLIENT_ID/SECRET` | optional | Microsoft OAuth |
| `ENABLE_LIVE_LOOKUPS` | optional | `0` (offline) or `1` |

### Frontend (Vercel → Environment Variables)
| Var | Required | Example |
|-----|----------|---------|
| `VITE_API_URL` | yes | `https://<railway-domain>` |
| `VITE_PROXY_TARGET` | no (dev) | `http://localhost:8000` |

---

## 8. Troubleshooting

- **Railway build: `"/scripts": not found`** → you set Root Directory to `backend`. Clear it: Service → Settings → Source → Root Directory = (empty) → Redeploy. `backend/Dockerfile:6` uses `COPY backend/requirements.txt` which needs repo-root context (`docker-compose.yml:5` shows `context: .`). Logs also show `uploading snapshot 137.4 KB` before the error — that confirms wrong context.
- **Dockerfile warning `JSONArgsRecommended`:** fixed by `backend/Dockerfile:13` using `["sh","-c","uvicorn ... ${PORT}"]` (JSON form with shell for env expansion and signal handling).
- **CORS error in browser:** `CORS_ORIGINS` on Railway does not include Vercel URL → add it, redeploy backend.
- **Vite build fails `tsc -b`:** check `frontend/tsconfig.json:11` has `noEmit:true`; run `npm run build` locally first.
- **Railway healthcheck fails:** check Logs → `require_custody_key()` fails if `CUSTODY_KEY` empty and `APP_ENV!=development`.
- **404 on refresh:** ensure `vercel.json:7` rewrite `/(.*)` → `/index.html` exists (root or `frontend/vercel.json:1`).
- **Frontend shows `API unreachable`:** `VITE_API_URL` must be the Railway public domain with `https`, no `/api` suffix (frontend appends `/api/v1` via `frontend/src/api.ts:5`).
- **Mixed content:** always use `https` for both.

---

## 9. What was added for deployment

- `vercel.json:1` (root) + `frontend/vercel.json:1` — SPA rewrites, cache headers, Vite build
- `railway.json:1` + `backend/railway.toml:1` — Dockerfile builder, `$PORT` healthcheck
- `backend/Dockerfile:12` — now respects `${PORT:-8000}` for Railway
- This `DEPLOY.md:1` — step-by-step

Your static SEO assets (`frontend/public/sitemap.xml:1`, `robots.txt`, `llms.txt`, `favicon.svg`, `og-image.svg`) are already output to `frontend/dist` and served by Vercel edge, no extra config.

---

## 10. One-line redeploy

```bash
git add . && git commit -m "deploy: update" && git push
# Vercel + Railway both rebuild automatically
```
