# Remediation log

Audit findings remediated from `Email_Scanner_Audit_Report.docx` (2026-09-25),
one commit per finding or tight cluster. Every entry lists the test that would
have caught the original issue.

## Phase 0

### P0-1 — Alembic chain did not match the ORM; fresh deploys were broken

**Status:** resolved
**Severity:** Critical (deployment-blocking)

**Files**

- `backend/alembic/versions/e5a1c93d7b28_add_missing_encrypted_columns_and_indexes.py` (new)
- `backend/tests/test_migrations.py` (drift check + opt-in integration tests)

**Issue**

The initial revision `834dc871451e` predates the OAuth/mailbox vault work and
was never updated. Five columns the ORM reads on every request existed only in
`app/models.py`:

| Table | Missing columns |
| --- | --- |
| `gmail_accounts` | `encrypted_client_id`, `encrypted_client_secret` |
| `mailbox_connections` | `encrypted_client_id`, `encrypted_client_secret` |
| `oauth_states` | `encrypted_client_secret` |

`app/routers/gmail.py:26-75` selects these columns and
`app/services/mailbox_poll.py` decrypts them, so a database built purely from
migrations booted, served `/health`, and then raised `UndefinedColumn` on every
mailbox operation. Three indexes declared via `index=True` in the models were
also absent, as was the `ck_cases_status` CHECK constraint limiting
`investigation_cases.status` to a fixed enum.

Nothing caught it because nothing compared the models against the migrations,
and the test suite builds its SQLite schema from `Base.metadata` rather than
from the chain.

**What changed**

Revision `e5a1c93d7b28` adds the five columns, the three indexes, and the check
constraint. Three details are load-bearing:

- Every add is inspector-guarded. Production was created from migrations before
  these columns existed, so one may have been added out of band; an
  unconditional `ADD COLUMN` would abort the upgrade chain, and `init_db()`
  turns a failed upgrade into a hard boot failure.
- The `NOT NULL` columns are added with `server_default=''` and the default is
  dropped immediately after. The default is what backfills existing rows — a
  bare `ADD COLUMN ... NOT NULL` fails on Postgres as soon as the table holds
  one row, and production holds rows. Dropping it afterwards leaves a schema
  identical to `Base.metadata`.
- The default drop is dialect-guarded. SQLite has no `ALTER TABLE ... ALTER
  COLUMN`, and `tests/test_step5_reliability.py::test_alembic_upgrade_fresh_db`
  migrates a fresh SQLite database.

**Tests added** (`backend/tests/test_migrations.py`)

- `test_vault_column_is_created_by_the_migration_chain` (5 params) — each vault
  column must be created by the chain.
- `test_declared_index_is_created_by_the_migration_chain` (3 params).
- `test_case_status_check_constraint_is_created_by_the_migration_chain` —
  pinned structurally, because Alembic's autogenerate does not emit
  CHECK-constraint diffs.
- `test_every_orm_column_exists_in_the_migration_chain` — the general form; no
  ORM column may be migration-absent.
- `test_every_orm_table_is_created_by_the_migration_chain`.
- `test_the_drift_fix_covers_exactly_the_five_vault_columns` — pins the
  revision's scope, its guards, and its server-default handling.
- Opt-in, gated on `DRIFT_TEST_DATABASE_URL`:
  `test_not_null_add_backfills_existing_rows` (5 params),
  `test_existing_rows_survive_the_drift_migration`,
  `test_case_status_is_constrained_on_a_migrated_database`,
  `test_the_drift_migration_is_idempotent`. These migrate a scratch PostgreSQL
  to `b7c2d1a9e4f5` — the revision production is actually on — seed real rows,
  then resume the chain.

Verified by reverting the revision: **11 of the new tests fail** without it.

**Deliberately deferred to their own revisions** (already correct in the ORM, so
they differ in type/constraint shape rather than column presence):

- `timestamp` → `timestamptz` on 14 columns (the naive-DateTime finding).
- `uq_email_hash_org` becoming a partial unique index rather than a table
  constraint (the nullable-org uniqueness finding).

**Operator action required**

Production is stamped `b7c2d1a9e4f5`. It will run `c9e8f7a6b3d2` then
`e5a1c93d7b28` on the next deploy. `c9e8f7a6b3d2` has never been applied in
production and failed there previously; verify the deploy rather than assuming.

## Still open in Phase 0

Recorded in the handover notes; status re-verified against the code September 2026 (items that have since been addressed are marked ✅):

- Secret enforcement does not cover the Alembic entrypoint. `alembic upgrade
  head` succeeds with `SECRET_KEY`, `CUSTODY_KEY` and `TOKEN_ENCRYPTION_KEY`
  all empty, because `alembic/env.py` never calls `require_secrets()`. The
  Celery worker (`app/services/tasks.py:15-28`) is likewise ungated, though no
  worker is deployed in any compose/k8s/Dockerfile target today. — **still open** (verified: `alembic/env.py` only resolves the DB URL).
- `require_secrets()` validates only `SECRET_KEY` and `ELASTICSEARCH_URL`. The
  vault key and the custody key are checked later, or lazily at use time. — **still open by design** (fail-closed at use/boot of the owning subsystem: vault on decrypt, custody via `require_custody_key()` in lifespan).
- No gitleaks pre-commit hook and no CI guard against tracked `.env` files.
  (No `.env` is currently tracked and `.gitignore:4-6` covers the pattern, so
  this is preventative.) — **still open** (preventative).
- `k8s/backend.yaml`: readiness probe polls `/health/detailed` every 15s, which
  runs unauthenticated model inference and returns `live_lookups`; `replicas:
  2` with no shared state; image pinned to a tag rather than a digest. — **partially addressed**: liveness is now lightweight `/health` with readiness on `/health/detailed` (intended — readiness gates traffic on DB+NLP); `replicas: 2` is now paired with `EXPECTED_REPLICAS: "2"` + the F8 no-shared-state comment + `graph_consistency_note()` startup warning (shared Neo4j required past 1 replica); release-tag + digest-pin process is documented in the manifest comments (digest substituted at release).
- `Tracker.md:4` still claims `seed.py` exists and is gated behind
  `ALLOW_SEED=1`. The file and its test were removed. — ✅ **fixed**: `Tracker.md` now carries a code-truth notice marking the seed/refresh/SETUP_TOKEN/ReadOnly-default entries as superseded by the Supabase migration.

## Verification appendix (September 2026 — doc-to-code sweep)
- Migration chain is now four revisions: `834dc871451e` (initial) → `b7c2d1a9e4f5` (Supabase auth, drops `refresh_tokens`) → `c9e8f7a6b3d2` (RLS policies, defense-in-depth, fail-closed) → `e5a1c93d7b28` (vault columns/indexes/CHECK). `DEPLOY.md` §2.5 updated accordingly (was: two revisions).
- P0-1 drift fix verified present (`e5a1c93d7b28` in `backend/alembic/versions/`); the "verify the deploy" operator action stands for any DB still stamped `b7c2d1a9e4f5`.
- Auth model across docs aligned to Supabase: only `GET /auth/me`; `refresh_tokens` references are historical; `SECRET_KEY` = WS-ticket HMAC only; default role Analyst + personal org (trigger).
- Model metrics across docs aligned to the committed `ml_models/metrics.json` (3012-row corpus: acc 0.9934, macro F1 0.6593, BEC F1 0.0/support=2); `dataset.csv` gitignored; artifacts + `.sha256` committed.
