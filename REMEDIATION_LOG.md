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

### P0-2 — Authentication-Results fail-open and authserv-id path binding

**Status:** resolved
**Severity:** Critical (fail-open on email authentication)

**Files**

- `backend/app/modules/forensics/auth_validator.py`
- `backend/tests/test_forensics.py`

**Issue**

Two independent defects let an attacker forge a passing authentication result.

*1. Locally-attempted verdicts were replaced by the upstream claim.* Five
sites substituted a trusted upstream status over a local result:

| Site | Local result | Was replaced by |
| --- | --- | --- |
| `auth_validator.py:192` | `temperror` / `none` | upstream status, possibly `pass` |
| `auth_validator.py:198` | validator crash (`temperror`) | upstream status |
| `auth_validator.py:213` | `none` (no DKIM-Signature) | upstream status |
| `auth_validator.py:325` | `none` (no `_dmarc` record) | upstream status |

Only `unverifiable` genuinely means "we could not attempt the check". Every
other value is a result we reached, and reaching it means the upstream claim
cannot improve on it:

- `temperror` / `permerror` — RFC 7208 reserves these for DNS lookup
  problems. Reporting `pass` for a lookup that never completed is the
  fail-open the audit described.
- `none` — we read the headers and there is no `DKIM-Signature`, or
  `_dmarc.<domain>` publishes no record (RFC 7489 §6.6.3). An upstream
  `pass` in that situation means the signature or record was *stripped in
  transit*, which is evidence of tampering rather than a fallback reading.

*2. The authserv-id had no path binding.* `_authserv_id()` returned the
first `Authentication-Results`-style header found in the dict, while
`parse_auth_headers()` regex-scanned a join of *all* of them. Both read
the same attacker-reachable header block, and they could disagree:

- An attacker who prepends `Authentication-Results: mx.our-relay.example;
  spf=pass` is believed for attribution, because our own MTA stamps last
  and the prepended header is seen first.
- Worse, the two functions can pick *different* headers, so a planted
  `x-authentication-results` could supply the trusted authserv-id while the
  status claims were harvested from an attacker-authored
  `authentication-results`.

**Change**

- Added `_trusted_upstream_verdict()`. Substitution now requires BOTH an
  attributable stamp (`trust_upstream`, already computed by
  `_upstream_trusted()`) AND a local status of exactly `unverifiable`;
  neither defaults to satisfied. Upstream status strings are validated
  against `_VERDICT_STATUSES`, so junk in a header is never a verdict.
- Every locally-attempted result now goes through `_with_upstream()`, which
  attaches the upstream claim for analyst provenance without letting it
  change the verdict. Nothing is lost — analysts still see both readings.
- Added `_boundary_ar_header()`. Attribution *and* claim extraction now read
  the single bottom-most `Authentication-Results` header, the one stamped by
  our own MTAs. If that header is not inside the trusted boundary the
  message is not trusted at all; no earlier header gets a vote. This also
  removes the attribution/claims disagreement above by construction.
- Relabelled a crashing SPF validator from `temperror` to `unverifiable`
  during review, then reverted it: `scoring.py:_auth_part` weights
  `unverifiable` 5.0 against `temperror` 15.0, so the change silently
  lowered the risk score for a broken deployment. It stays `temperror`,
  which also blocks substitution automatically.

**Tests**

Seven tests in `tests/test_forensics.py`, verified to fail against the
pre-fix module and pass after:

- `test_temperror_is_not_upgraded_to_upstream_pass`
- `test_spf_none_is_not_upgraded_to_upstream_pass`
- `test_spf_permerror_is_not_upgraded_to_upstream_pass`
- `test_spf_library_crash_stays_temperror_not_upstream_pass`
- `test_dkim_missing_signature_is_not_upgraded_to_upstream_pass`
- `test_dmarc_absent_record_is_not_upgraded_to_upstream_pass`
- `test_authserv_id_and_claims_come_from_the_same_header`
- `test_attacker_cannot_forge_trusted_authserv_id_by_prepending`
- `test_trusted_upstream_still_substitutes_for_unverifiable` (guards against
  over-correcting into ignoring every relay-forwarded verdict)

### P0-3 — Retention violated the documented policy in both directions

**Status:** resolved
**Severity:** Critical (GDPR / data-integrity)

**Files**

- `backend/app/modules/privacy/retention.py`
- `backend/tests/test_privacy.py`
- `backend/tests/test_step3_privacy.py`

**Issue**

`Rules.md` "Data Retention" specifies two different regimes, and the code
implemented neither:

| Traffic | `Rules.md` requires | Code did |
| --- | --- | --- |
| Clean (`score < 50`) | metadata retained for **7 days**, body dropped immediately | body blanked, row kept **forever** |
| Malicious (`score >= 50`) | retained **90 days**, then body purged, **leaving aggregated threat intel indicators in the Graph DB** | full row deleted |

So clean traffic PII (subject, sender, recipients, `headers`,
`raw_headers`) was retained indefinitely, while malicious evidence — the
indicators the retention policy explicitly exists to preserve — was
destroyed at 90 days.

**Change**

- Clean traffic past `clean_days` is now deleted outright, cascading to
  `AnalysisResult`, `TraceabilityData` and the Elasticsearch document.
- Malicious traffic past `malicious_days` keeps its row and has only its
  body purged, so the graph indicators remain attributable.
- Removed `remove_email_graph(e.sender_address)`. It issued
  `MATCH (e:Email_Address {address:$a}) DETACH DELETE e` against a
  **globally shared** node, so one tenant's retention run deleted graph
  edges belonging to other tenants and to emails that still exist.
  Per-email graph removal needs per-email nodes and tenancy, which the
  graph model does not have yet; removing the unsafe call is the correct
  interim behaviour.
- `clean_days`/`malicious_days` are now rejected when negative. A negative
  value inverts every cutoff and can delete the whole corpus.
- The `delete_email()` result is now checked. A row removed from Postgres
  whose ES document survives was previously invisible; it is counted and
  returned as `es_delete_failed`.

**Tests**

Six tests, verified to fail against the pre-fix module:

- `test_retention_deletes_expired_clean_row_entirely`
- `test_retention_keeps_expired_malicious_row_and_only_purges_body`
- `test_retention_keeps_malicious_row_inside_forensic_window`
- `test_retention_does_not_touch_shared_graph_sender_node`
- `test_retention_rejects_negative_windows`
- `test_retention_reports_es_delete_failure`

Two existing tests asserted the non-compliant behaviour and were rewritten to
the policy: `test_retention_purges_old_clean_body_only` (now
`test_retention_deletes_expired_clean_row_entirely`) and
`test_retention_full_delete_malicious` (now
`test_retention_deletes_expired_clean_and_keeps_malicious`).

### P0-4 — ReadOnly role could reach every credential and ingest mutation

**Status:** resolved
**Severity:** High (RBAC)

**Files**

- `backend/app/routers/deps.py` (holds `READ_WRITE` now)
- `backend/app/routers/api.py` (re-exports it)
- `backend/app/routers/gmail.py`
- `backend/app/routers/oauth.py`
- `backend/tests/test_gmail.py`

**Issue**

`api.py` gated its mutating endpoints on `require_roles(*READ_WRITE)`
(`Admin`, `Analyst`), but six endpoints in the mail-connector routers were
gated on `get_current_user` alone:

| Endpoint | Action a ReadOnly user could take |
| --- | --- |
| `POST /gmail/auth-url` | mint an OAuth consent URL + server-side state |
| `POST /gmail/callback` | attach a mailbox and persist credentials |
| `POST /gmail/sync` | trigger ingestion |
| `DELETE /gmail/disconnect` | destroy the connection and its credentials |
| `POST /oauth/{provider}/authorize` | mint org OAuth state |
| `POST /oauth/sync-now` | trigger a mailbox poll for the whole org |

`POST /oauth/{provider}/callback` is unauthenticated by necessity (the IdP
redirects the browser there), which is why its authorisation is enforced
server-side against the state row instead — that path was already correct.

**Change**

`READ_WRITE` moved to `deps.py`, next to `require_roles`, and is re-exported
from `api.py` so existing imports keep working while every router gates on a
single definition of "may write". All six endpoints now use
`require_roles(*READ_WRITE)`. `oauth.py:403` `DELETE /{provider}` was already
correct and is unchanged.

**Tests**

- `test_readonly_cannot_reach_mutating_gmail_endpoints` — 403 on all four
  Gmail endpoints, and `GET /gmail/status` still 200 so the gate does not
  over-restrict reads.
- `test_readonly_cannot_reach_mutating_oauth_endpoints` — 403 on both OAuth
  endpoints.
- `test_analyst_can_still_reach_gmail_auth_url` — positive control against
  locking out legitimate writers.

Both 403 tests were verified to fail against the un-gated routers.

### P0-5 — Three quadratic regexes (ReDoS) reachable from unauthenticated upload

**Status:** resolved
**Severity:** Critical (single-request CPU DoS)

**Files**

- `backend/app/modules/ingestion/parser.py`
- `backend/app/modules/traceability/ip_extractor.py`
- `backend/app/modules/forensics/received_chain.py`
- `backend/tests/test_step4_detection.py`
- `backend/tests/test_traceability.py`

**Issue**

All three patterns were measured, not assumed. Each is quadratic in the
length of a single attacker-supplied run:

| Pattern | Site | Input | Before | After |
| --- | --- | --- | --- | --- |
| `<(script\|style)\b.*?</\1\s*>` (`DOTALL`) | `parser.py:22` | `"<script>" * 32000` (256KB) | **23.8s** | 0.001s |
| `[0-9a-fA-F:]{2,}(?::[0-9a-fA-F:]*)+` | `ip_extractor.py:20`, `received_chain.py:8` | `"a" * 64000` | **28.3s** | 0.0007s |

Scaling is clean 4×-per-2×. `parser.py` runs on every uploaded message and
`MAX_EML_BYTES` is 10MB, so a single unauthenticated upload projects to
roughly **10 hours** of CPU in one request. The IP patterns run once per
`Received` header per hop.

**Change**

- `strip_script_style()` replaces the regex in `parser.py`. It walks the
  string with `str.find`, visiting each element once. An unterminated
  `<script>`/`<style>` now drops to end-of-string instead of being left in
  place — strictly safer, since the tail would otherwise survive as text.
- Both IP patterns became
  `(?<![0-9A-Fa-f:.])(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:]*)`.
  The **lookbehind is load-bearing**: `findall` restarts at every offset, so
  without it each position re-scans the remaining run. Pinning matches to run
  boundaries removes the nested quantifiers entirely. An atomic group was
  tried first and does *not* help — it prevents backtracking within one
  attempt but the scan is still repeated per start position.
- `ipaddress` validation is unchanged, so both remain candidate scanners.

Behaviour was diffed against the old patterns across 16 inputs. Output is
identical except `::1`, which the old `{2,}` prefix could never match and the
new pattern now finds — a coverage gain.

**Tests**

- `test_strip_script_style_is_linear_on_unterminated_tags`
- `test_strip_script_style_removes_element_and_content`
- `test_sanitize_html_still_strips_tags_and_scripts`
- `test_ip_regex_is_linear_on_hostile_hex_run` — budgets compare a small input
  against a 20× larger one so a return to quadratic behaviour fails rather
  than merely being slow
- `test_extract_all_ips_survives_hostile_received_header` — end-to-end, 2s cap
- `test_ip_candidate_pattern_still_extracts_valid_addresses` — includes the
  `1.2.3.4abc` and `::1` cases
- `test_ip_pattern_rejects_junk_and_trailing_hex`

Against the vulnerable patterns these tests do not fail quickly — they hang
(confirmed: killed at 150s and 600s). That is the ReDoS reproducing.

## Still open in Phase 0

Recorded in the handover notes; not yet started.

- Secret enforcement does not cover the Alembic entrypoint. `alembic upgrade
  head` succeeds with `SECRET_KEY`, `CUSTODY_KEY` and `TOKEN_ENCRYPTION_KEY`
  all empty, because `alembic/env.py` never calls `require_secrets()`. The
  Celery worker (`app/services/tasks.py:15-28`) is likewise ungated, though no
  worker is deployed in any compose/k8s/Dockerfile target today.
- `require_secrets()` validates only `SECRET_KEY` and `ELASTICSEARCH_URL`. The
  vault key and the custody key are checked later, or lazily at use time.
- No gitleaks pre-commit hook and no CI guard against tracked `.env` files.
  (No `.env` is currently tracked and `.gitignore:4-6` covers the pattern, so
  this is preventative.)
- `k8s/backend.yaml`: readiness probe polls `/health/detailed` every 15s, which
  runs unauthenticated model inference and returns `live_lookups`; `replicas:
  2` with no shared state; image pinned to a tag rather than a digest.
- `Tracker.md:4` still claims `seed.py` exists and is gated behind
  `ALLOW_SEED=1`. The file and its test were removed.
