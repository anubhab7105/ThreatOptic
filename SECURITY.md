# Security Runbook — Compromise Assumption & Secret Rotation

> **Assumption: the current deployment (if any) is compromised.**
> Plaintext Gmail refresh tokens (C5) and a forgeable default JWT secret
> (C1) have existed in this codebase. Follow this runbook **before**
> presenting any deployment as hardened.

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
| `SECRET_KEY` (JWT signing) | ≥ 32 random bytes | `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `CUSTODY_KEY` (chain-of-custody HMAC) | ≥ 32 random bytes | same as above |
| `TOKEN_ENCRYPTION_KEY` (mailbox vault) | ≥ 32 random bytes | same as above |
| OAuth client secrets (Google + Microsoft) | — | rotate in Cloud Console / Entra, update env |
| DB password (`POSTGRES_PASSWORD`) | strong | `openssl rand -base64 32` |
| `ELASTIC_PASSWORD`, Neo4j (`NEO4J_PASSWORD`) | strong | same |

`APP_ENV` must be `production` (or anything except `development`) so the
startup checks refuse to boot on defaults.

## 3. Invalidate old sessions and tokens

1. Deploy with the new `SECRET_KEY` — **all previously issued JWTs
   (access + refresh) immediately fail signature verification.** No DB
   migration needed; log everyone out by telling users to sign in again.
2. Mailbox OAuth: delete rows from `mailbox_connections` and
   `gmail_accounts`, then have owners reconnect (forces fresh provider
   refresh tokens; old Bearer tokens die with the provider revocation).
3. Postgres/ES/Neo4j: `ALTER USER ... PASSWORD`, restart dependents.

## 4. Verify

```bash
python3 backend/scripts/live_demo_check.py --api https://<host>
```

Expected: `SECRET_KEY changed from default: PASS`, custody gate PASS,
login + ingest roundtrip PASS.
