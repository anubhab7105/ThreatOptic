# Security Runbook — Compromise Assumption & Secret Rotation

> **Assumption: the current deployment (if any) is compromised.**
> Plaintext-era Gmail refresh tokens and forgeable-default secrets have
> existed in this codebase's history (see `REMEDIATION_LOG.md`). Mailbox
> OAuth tokens are now Fernet-encrypted (`modules/auth/vault.py`,
> PBKDF2/600k + random salt, `v1$` format, fail-closed on empty/short
> `TOKEN_ENCRYPTION_KEY`), and Supabase owns login sessions — but follow
> this runbook **before** presenting any deployment as hardened.

## 1. Back up

```bash
# SQLite
cp backend/email_forensics.db "backups/email_forensics-$(date +%F).db"
# Postgres (compose/k8s)
pg_dump "$DATABASE_URL" > "backups/soc-$(date +%F).sql"
```

Keep the backup offline; it contains PII and old credential hashes.

## 2. Rotate out-of-band (never as a code change)

Generate fresh values and store them in the secrets manager / `.env`
(which is gitignored). Minimum lengths are enforced by the app at startup.

| Secret | Length | Commands |
|---|---|---|
| `SECRET_KEY` (WebSocket-ticket HMAC — **not** login JWT; Supabase signs those) | ≥ 32 chars | `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `CUSTODY_KEY` (chain-of-custody HMAC) | ≥ 32 chars | same as above |
| `TOKEN_ENCRYPTION_KEY` (mailbox vault — **Fernet key**, separate from `SECRET_KEY`) | Fernet key | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `SUPABASE_JWT_SECRET` (Supabase JWT verification fallback) | from dashboard | Supabase → Settings → API → JWT Settings |
| OAuth client secrets (Google + Microsoft) | — | rotate in Cloud Console / Entra, update env |
| DB password (`POSTGRES_PASSWORD`) | strong | `openssl rand -base64 32` |
| `ELASTIC_PASSWORD`, Neo4j (`NEO4J_PASSWORD`) | strong | same |

`APP_ENV` must be `production` (or anything except `development`) so the
startup checks refuse to boot on defaults.

## 3. Invalidate old sessions and tokens

1. Supabase owns login sessions: rotate/revoke via the Supabase dashboard (Auth → Users) and have users sign in again. Deploying a new `SECRET_KEY` only invalidates **WebSocket tickets** (`POST /ws/ticket` → 60-s `ws-ticket` JWTs in `routers/ws.py`) — it is no longer a login-JWT signing key. (The old server-side `refresh_tokens` ledger was dropped by migration `b7c2d1a9e4f5`; if a stale `refresh_tokens` table still exists from a pre-Supabase deploy, it is cryptographically dead — `DELETE FROM refresh_tokens;` after deploy if desired. `SECRET_KEY`/`SUPABASE_JWT_SECRET` must still be ≥32 chars / provisioned or the app refuses to boot outside `development` via `require_secrets()`.)
2. Custody key rotation without downtime: set `CUSTODY_KEY` to the new
   key and keep the old value in `CUSTODY_KEY_PREVIOUS` — new manifests
   sign with the new key while `verify_manifest()` still accepts the old
   one. Remove `CUSTODY_KEY_PREVIOUS` after one retention window.
3. Mailbox OAuth: delete rows from `mailbox_connections` and
   `gmail_accounts`, then have owners reconnect (forces fresh provider
   refresh tokens; old Bearer tokens die with the provider revocation).
   Corrupt/undecryptable vault rows already force reconnect with a
   `400 ... please disconnect and reconnect` error — do not attempt to
   recover them.
4. Postgres/ES/Neo4j: `ALTER USER ... PASSWORD`, restart dependents.

## 4. Verify

```bash
python3 backend/scripts/live_demo_check.py --api https://<host>
```

Expected: `SECRET_KEY changed from default: PASS`, custody gate PASS,
login + ingest roundtrip PASS.
