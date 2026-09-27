# Database Schema Design

This document outlines the high-level schema for the primary data stores. Source of truth is `backend/app/models.py` (Alembic chain `834dc871451e → b7c2d1a9e4f5`, auto-run at boot).

## Relational Database (PostgreSQL via Supabase)

> Postgres-only. SQLite exists solely as the pytest escape hatch (`TEST_DATABASE_URL`); the app fails closed without `DATABASE_URL`. Local `backend/email_forensics.db*` files are legacy dev artifacts, not the runtime path. Elasticsearch is an optional full-text **mirror** (`modules/search/elastic_sync.py`), Neo4j an optional graph backend (else networkx in-process).

### `User` (mirror of `auth.users` — Supabase owns identity)
- `id`: String(36), PK — **Supabase auth UUID** (`sub` claim), set by the `handle_new_user()` trigger, no default
- `email`: String(320), unique, indexed
- `role`: Enum (Admin, Analyst, ReadOnly), default **`Analyst`** (set by `backend/supabase_handle_new_user.sql`, which also creates the personal `<email>'s workspace` org)
- `organization_id`: String(36), nullable, FK → Organization, indexed
- `created_at`: TZDateTime (TIMESTAMPTZ on Postgres; naive-ISO on SQLite tests, normalized by `as_utc()`)

### `Organization`
- `id`: UUID (Primary Key)
- `name`: String, unique (e.g. `<email>'s workspace`)
- `compliance_policy`: JSON (Settings for data retention and PII masking)
- `created_at`: TZDateTime

### `InvestigationCase`
- `id`: UUID (Primary Key)
- `title`: String(512), required
- `status`: Enum (Open, InProgress, Closed), CHECK constraint `ck_cases_status`
- `assignee_id`: UUID, nullable (FK → User, existence-validated)
- `organization_id`: UUID, nullable (FK → Organization, tenant scope; Admin bypass)
- `email_ids`: JSON list (each ID tenant-validated, 404-no-leak)
- `notes`: Text
- `created_at` / `updated_at`: TZDateTime

---

## Document-shaped tables (Postgres rows; mirrored to Elastic when configured)
*Relational rows with JSON columns; ES is a best-effort full-text mirror, not the store. Raw bodies are never persisted — only `body_text_masked`.*

### `EmailRecord`
- `_id`: UUID
- `message_id`: String (from email headers)
- `sender_address`: String, indexed
- `recipient_address`: String
- `subject`: String
- `raw_headers`: JSON object
- `body_text`: Text — legacy/blanked only (new rows never store raw; retention blanks old clean rows)
- `body_text_masked`: String (PII-masked; the only indexed/searched body)
- `attachments_metadata`: JSON array (incl. 8-byte magic)
- `raw_eml_hash`: String(64) SHA-256 — idempotent ingest key in partial unique index `uq_email_hash_org(raw_eml_hash, organization_id)` (non-null orgs only)
- `organization_id`: UUID, nullable, FK → Organization, indexed (tenant scope)
- `timestamp`: TZDateTime, indexed

### `AnalysisResult`
- `_id`: UUID
- `email_id`: UUID, FK → EmailRecord (CASCADE), indexed
- `fraud_score`: Float (0-100), indexed
- `threat_classification`: String (Critical / High / Medium / Low-Suspicious + BEC / Phishing / Clean family)
- `nlp_cues_detected`: Array of Strings
- `authentication_results`: Object (SPF, DKIM, DMARC status + `aligned`; `unverifiable` when offline)
- `trace_summary`: JSON object
- `threat_intel_hits`: JSON array (feeds + URL/attachment findings)
- `action_taken`: String (Quarantine / JunkOrHold / DeliverWithBanner / Deliver)
- `score_breakdown`: Array of `{signal_name, weight, value, contribution_to_score}` (explainability; sums to fraud_score)
- `created_at`: TZDateTime

### `GmailAccount` (personal Gmail vault — Fernet ciphertext, names kept for migration stability)
- `id`: UUID (Primary Key)
- `user_id`: UUID (FK → User, **unique** — one mailbox per user, CASCADE)
- `gmail_address`: String
- `refresh_token`: Text (vault ciphertext, NOT plaintext)
- `client_id` / `encrypted_client_id` / `encrypted_client_secret`: Text (client pinned at connect, reused at sync)
- `last_sync_at`: Timestamp, nullable
- `created_at` / `updated_at`: TZDateTime

### `MailboxConnection` (org mailboxes, Google + Microsoft)
- `id`: UUID (Primary Key)
- `user_id`: UUID (FK → User, CASCADE, indexed)
- `organization_id`: UUID, nullable (FK → Organization, indexed; org members share, org-less scoped to owner)
- `provider`: String (`google` | `microsoft`)
- `account_email`: String — unique together with provider (`uq_mailbox_provider_email`)
- `encrypted_refresh_token`: Text (Fernet-encrypted at rest; rotated tokens persisted by `services/mailbox_poll.py`)
- `encrypted_client_id` / `encrypted_client_secret`: Text
- `last_poll_at`: Timestamp, nullable
- `created_at` / `updated_at`: TZDateTime

### `OAuthState` (server-side OAuth state + PKCE, single-use, 10-min TTL)
- `id`: UUID (Primary Key)
- `state`: String(128), unique, indexed (opaque browser token — no embedded data)
- `user_id`: UUID (FK → User, CASCADE, indexed; callback fails closed if owner is gone)
- `provider`: String (`google` | `microsoft`)
- `redirect_uri`: String(1024) (allowlisted at authorize AND callback time)
- `client_id`: String(320) (pinned) / `encrypted_client_secret`: Text
- `code_verifier`: String(256) (PKCE S256)
- `expires_at`: TZDateTime / `used`: Boolean (replays fail)
- `created_at`: TZDateTime

> Auth history note: the old `refresh_tokens` login-session ledger was dropped by migration `b7c2d1a9e4f5` (Supabase manages sessions). Remaining "refresh tokens" are provider OAuth tokens above.

### `TraceabilityData`
- `_id`: UUID
- `email_id`: UUID, FK → EmailRecord (CASCADE), indexed
- `origin_ip`: String (last-external-hop via `TRUSTED_RELAY_HOSTS/IPS` boundary)
- `relay_chain`: JSON array (parsed `Received` hops)
- `geolocation`: Object (`lat`, `lon`, `country`, `city`, `isp`, `asn`, `source`: offline-stub / ip-api / MaxMind / relay-hop / approx-mx-ip / whois-country-approx …)
- `isp_asn`: String
- `is_vpn_tor`: Boolean
- `whois_data` / `dns_data`: JSON objects (`mx`/`a` records, registrar, creation date for `domain_age_days`)

---

## Graph Database (Neo4j)
*Nodes and edges for correlation.*

### Nodes
- `IP_Address` {ip, country, is_malicious}
- `Domain` {name, registrar, creation_date}
- `Email_Address` {address, is_compromised}
- `Threat_Campaign` {name, signature_type}

### Edges
- `(Email_Address)-[:SENT_FROM]->(IP_Address)`
- `(IP_Address)-[:HOSTS]->(Domain)`
- `(Domain)-[:PART_OF]->(Threat_Campaign)`
