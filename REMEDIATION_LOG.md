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

### P0-6 — Search tenant scope was implicit and fail-open; Admin scope was wrong

**Status:** resolved
**Severity:** Critical (tenant isolation, latent)

**Files**

- `backend/app/modules/search/elastic_sync.py`
- `backend/app/routers/api.py`
- `backend/tests/test_search.py`, `test_audit_recommendations.py`, `test_step3_privacy.py`

**Issue**

`search_emails(query, limit=50, db=None, organization_id="__all__")` — the
default scope was the literal `"__all__"`, and both the ES branch
(`if organization_id != "__all__"`) and the SQLite branch
(`if organization_id != "__all__"`) skipped the tenant filter entirely for
it. Any new caller that omitted the argument would have searched every
organization.

This was latent, not exploitable: the only caller,
`api.py:375 /search`, always passed an explicit value.

A second defect sat behind it. `api.py` passed
`organization_id=None if user.role == "Admin" else user.organization_id`,
but `None` is the legitimate value for "row has no organization". In the ES
branch it became `must_not exists organization_id` and in the SQLite branch
`organization_id IS NULL` — both meaning *org-less rows only*. An Admin
searching therefore saw none of the real tenants' mail, which is a
functional bug that would mask cross-tenant over-exposure if "fixed" by
simply widening the filter.

**Change**

- The scope is now mandatory. Omitting it raises `ValueError` instead of
  quietly returning everything.
- Added an explicit `all_orgs: bool = False`. Cross-tenant search is a
  deliberate act, and `api.py` now requests it for Admin via
  `all_orgs=True`.
- `limit` is clamped to 1..100 on both paths; previously only the ES branch
  clamped it while SQLite applied the raw value.

**Tests**

- `test_search_refuses_implicit_all_tenants_scope`
- `test_search_scopes_to_requesting_tenant` — asserts an org-A search cannot
  return org-B's row
- `test_admin_search_is_not_limited_to_orgless_rows` — pins `None` as
  "org-less" and `all_orgs=True` as cross-tenant
- `test_search_limit_is_clamped`

Three existing tests called `search_emails` without a scope, i.e. they were
relying on the unsafe default; each now states its scope.
`test_search_uses_elastic_when_configured` asserted `multi_match` was the
whole query, which is no longer true once the query is correctly wrapped in
a tenant filter — it now asserts the match *and* that `org-1` reached the ES
query.

### P0-7 — Alembic entrypoint could only target the ambient DATABASE_URL

**Status:** resolved
**Severity:** High (deployment safety)

**Files**

- `backend/alembic/env.py`
- `backend/tests/test_migrations.py`

**Issue**

`_url()` returned `get_settings().resolved_db_url()` unconditionally. It
ignored both an `-x url=...` override and `sqlalchemy.url` from
`alembic.ini`, so the only way to choose a database was to mutate the
environment — and an ambient or stale `DATABASE_URL` silently won.

This is not theoretical. A scratch migration run during earlier remediation
targeted the **development** database `socdev` instead of the scratch
database and left it stamped with a revision that was later deleted,
producing `Can't locate revision identified by '90458c1163e2'`. Nothing in
the tool reported which database it was touching.

**Change**

- Precedence is now `-x url=` > `sqlalchemy.url` > `resolved_db_url()`.
- `_require_migratable_target()` fails closed on an empty URL or one still
  containing a placeholder (`<`, `>`, `placeholder`, `changeme`,
  `your-password`, `xxx`), so migrations cannot run against a
  half-provisioned target.
- Every online migration prints the target with the password redacted
  (`alembic: migrating postgresql://user:***@host/db`).

A note on the originally proposed change: this does **not** add
`require_secrets()` to the Alembic entrypoint. A migration reads no JWT
secret, so gating it on `SECRET_KEY` would be cargo-cult — it would block
deploys without closing a hole. The actual hazard was targeting the wrong
database, which is what this fixes.

**Tests**

Six tests in `tests/test_migrations.py`, five of which fail against the
previous `env.py`. They import `env.py` directly with a stubbed
`alembic.context` installed *before* the import, since the module reads
`context.is_offline_mode()` at module scope.

- `test_alembic_env_honours_explicit_url_override`
- `test_alembic_env_prefers_ini_url_over_settings`
- `test_alembic_env_falls_back_to_resolved_settings`
- `test_alembic_env_refuses_placeholder_target`
- `test_alembic_env_accepts_a_real_target` — guards against over-blocking
- `test_alembic_env_redacts_password_when_logging`

### P0-8 — Vite dev server bound to every interface

**Status:** resolved
**Severity:** High (information disclosure on the LAN)

**Files**

- `frontend/vite.config.ts`
- `frontend/package.json`

**Issue**

`"dev": "vite --host"` bound the dev server to `0.0.0.0`. The dev server
serves unminified sources, the repo's `.env` values through `envDir: '..'`,
and a proxy to the API — all reachable by anything that can route to the
host, with no authentication.

**Change**

`host: '127.0.0.1'` on both `server` and `preview`, and the `--host` flag
removed from the `dev` script. Passing `--host` on the command line still
overrides it for deliberate device testing.

`npm test` (53 tests) and `npm run build` both pass. The build initially
failed on `src/landing/*` with `Cannot find module 'zustand'`; that was a
stale `node_modules` from unrelated concurrent work (`zustand` was already
in `package.json`), resolved with `npm install`.

### P0-9 — Graph hydration read another tenant's `EmailRecord`; wildcard `LIKE`

**Status:** resolved
**Severity:** Critical (tenant isolation) + High (availability, correctness)

**Files**

- `backend/app/modules/graph/store.py`
- `backend/app/routers/api.py`, `app/services/campaigns.py`, `app/modules/graph/attribution.py`
- `backend/app/modules/search/elastic_sync.py`, new `backend/app/sql_utils.py`
- `backend/tests/test_graph_neo.py`, `test_step3_privacy.py`

**Issue 1 — unscoped hydration read (`store.py:361,363`)**

`related_entities()`'s fallback branch reads `EmailRecord` directly, with no
`organization_id` filter on either lookup. Both paths leak:

- `email_id`: any caller could pass another tenant's email id. The row's
  sender, recipient and phishing classification were fed to
  `upsert_email_graph()` and the traversal was **rooted** on it, so the
  response carried that email's IP / domain / campaign neighbourhood. The
  router's `_filter_graph_emails()` strips foreign *email* nodes, but the
  infra nodes and the edges leading to them survive — and those are the
  tenant-attributable part. The pre-fix regression test reproduces it:
  org-A asking for org-B's email id gets back
  `domain:othercorp.test` and `campaign:phishing-Low-Suspicious`.
- substring fallback: `sender_address ILIKE '%value%'` then `.first()` picked
  an arbitrary row from *any* organization.

**Issue 2 — unescaped `LIKE` (same line)**

The pattern was built with `f"%{clean_val}%"` and no `escape=`, so `%` and `_`
in the caller's value acted as wildcards. `GET /graph/related?value=%25`
matched every sender in the table and hydrated from whichever row `.first()`
returned.

**Issue 3 — `NodeNotFound` 500 (found by the new tests)**

When no node matched and the value had no `@` (`value=a`, `value=%`,
`value=zz`), `key` stayed `None` and `nx.ego_graph(G, None, ...)` raised
`NodeNotFound`, which nothing caught — `GET /graph/related?value=a` was an
unauthenticated-input **500 for every logged-in caller**, trivially
triggerable and repeatable.

**Change**

- `related_entities()` takes `organization_id`, defaulting to a new public
  `ALL_TENANTS` sentinel so internal callers must state their intent rather
  than inherit a default. `_org_clause()` maps it to `AND TRUE`,
  `organization_id = :org`, or `AND FALSE` for a user with no org — an
  org-less user matches nothing rather than everything.
- The router passes `ALL_TENANTS` for Admin and `user.organization_id`
  otherwise, matching the `_org_filter` idiom used elsewhere in the file.
- Both DB lookups are wrapped in that clause and the `ILIKE` pattern now goes
  through a shared `escape_like()` with `escape=LIKE_ESCAPE`.
- `escape_like()` moved out of `elastic_sync` into `app/sql_utils.py`; the
  graph store and the `/emails` search filter now share one implementation
  instead of the audit's two divergent idioms.
- Unknown values with no synthesisable node return `{"nodes": [], "edges": []}`.

**Not changed (deliberately).** `ensure_graph_hydrated()` still loads every
organization into the shared graph. That is the documented design — the graph
is shared threat intel and the router strips foreign email nodes — so
re-scoping it is an architecture change, not a patch. The tests pre-seed the
graph so `ensure_graph_hydrated()` short-circuits, isolating the branch that
was actually unscoped.

**Tests** — `tests/test_graph_neo.py`, 6 new. All 6 fail on the pre-fix code
(4 on the missing `organization_id` parameter, 1 on the missing `_org_clause`,
1 on `NodeNotFound`); the endpoint test additionally demonstrates the
cross-tenant `domain:` / `campaign:` leak. Each tenancy test asserts the
`ALL_TENANTS` variant still resolves the row, so a pass proves scoping rather
than a broken lookup.

### P0-10 — Header-name casing bypassed the whole header-forensics layer

**Status:** resolved
**Severity:** High (detection bypass; attacker-controlled)

**Files**

- `backend/app/modules/forensics/header_parser.py`
- `backend/app/modules/ingestion/parser.py`
- `backend/app/modules/forensics/received_chain.py`, `auth_validator.py`
- `backend/app/modules/traceability/ip_extractor.py`
- `backend/tests/test_forensics.py`

**Issue**

RFC 5322 §2.2 makes header field names case-insensitive, but
`Message.raw_items()` preserves whatever the sender typed. `parse_eml()`
copied those keys into `raw_headers` verbatim, and every consumer looked
headers up by exact name. A sender could therefore pick the casing:

- `fROM: attacker@evil.test` → `from_addr = ''`, which silently disabled
  `display-name-spoof`, `reply-to-mismatch`, the punycode and lookalike
  domain checks, and the From/Return-Path comparison in
  `detect_routing_anomalies`. A spoofed From with a live Reply-To mismatch
  scored clean.
- `rECEIVED: …` → `split_received()` returned `[]`, so the hop chain
  vanished: `missing-received-chain` fired as an artifact, `origin_ip` could
  not be attributed from the chain, and the SPF/reputation checks that
  consume it never ran. The Received chain is entirely sender-controlled
  text, so this was the highest-value target of the three.
- `From:` and `fROM:` in one message became two dict entries, so the
  `multiple-from` spoofing signal never fired.
- `X-ORIGINATING-IP` / `Authentication-Results` casing defeats
  `ip_extractor`, which only tried `k` and `k.lower()`.

`auth_validator` already had its own case-insensitive lookup, so this was
four modules doing it four different ways — two of them not at all.

**Change**

- `header_parser` gains `canonical_header_name()` (a preferred spelling per
  known header, sender casing preserved for anything unrecognised) and
  `header_value()`, one case-insensitive accessor handling list values.
- `parse_eml()` canonicalises keys through a lowercase→keyed map, so
  duplicates differing only in case now merge. That fixes
  `multiple-from` and `Received`-chain joining at the source rather than at
  each call site.
- `parse_headers`, `received_chain`, and `ip_extractor` all read through
  `header_value()`; `auth_validator._get_header()` delegates to it and its
  private copy is deleted.
- `header_value()` scans case-insensitively as a fallback, so rows
  persisted *before* this normalisation still resolve.

The sender's original casing is no longer stored. That is deliberate: it is
not consumed anywhere, and keeping it would mean every future lookup has to
remember to be case-insensitive.

**Tests** — `tests/test_forensics.py`, 5 new; all 5 fail pre-fix (the `fROM`
case returns `from_addr=''`, `rECEIVED` returns zero hops, the duplicate
`From` produces no flag, `header_value` does not exist, and
`X-ORIGINATING-IP` yields no IPs).

## Still open

### From this audit

- **H21 — frontend token storage is real, but needs a decision.** `supabaseClient.ts`
  sets `persistSession: true`, so supabase-js writes the access *and* refresh
  token to `localStorage`; any XSS yields full account takeover. Moving to
  memory-only tokens plus an HttpOnly refresh cookie is the fix, but it needs
  Supabase SSR cookie plumbing and touches every authenticated call site.
  Not started — it is an architecture change, not a patch.
- **H22 / C1-residual — the SPA transmits `client_secret`.** `pages.tsx:301,334,386,2157,2175`
  post it and `AuthorizeIn`/`SyncNowIn` accept it. C1's headline claim
  (secret in the `?state=` URL) was **stale** — the state is an opaque
  `secrets.token_urlsafe(32)` token and the secret is vault-encrypted
  server-side. What remains is that the browser sends a secret the backend
  already stores. Removing the field breaks self-hosted users who enter their
  own OAuth client secret in the UI unless a separate credential-store
  endpoint is added first. **Needs a product decision, so not started.**
- `masking.py:19,17` — the E164 pattern spans newlines and the card pattern
  backtracks. Real; not yet fixed.
- MISP residuals in `feeds.py`: unbounded `_MISP_CACHE` growth (`:162`) and a
  silent 30-value truncation (`MISP_VALUE_CAP`) against inputs of up to 60,
  which contradicts the "coverage identical" comment.
- `k8s/backend.yaml`: readiness probe polls `/health/detailed` every 15s, which
  runs unauthenticated model inference and returns `live_lookups`; `replicas:
  2` with no shared state; image pinned to a tag rather than a digest.
- The remaining Medium and Low findings (upload size, dashboard full scans,
  rate limits, log redaction, compose/k8s hardening, dependency pinning) are
  untouched. Several are already narrower than the audit describes — H8 is
  fixed via `redacted_db_url()`, H23 via the `/ws/ticket` exchange, and the
  `Exception`-handler and `localStorage` claims were re-verified as accurate
  only where noted above.

### From the earlier audit, still open

- Secret enforcement does not cover the Celery worker
  (`app/services/tasks.py:15-28`), though no worker is deployed in any
  compose/k8s/Dockerfile target today. (The Alembic entrypoint was
  deliberately **not** gated on `require_secrets()` — see P0-7.)
- `require_secrets()` validates only `SECRET_KEY` and `ELASTICSEARCH_URL`. The
  vault key and the custody key are checked later, or lazily at use time.
- No gitleaks pre-commit hook and no CI guard against tracked `.env` files.
  (No `.env` is currently tracked and `.gitignore:4-6` covers the pattern, so
  this is preventative.)
- Two migration revisions still to write: `timestamp` → `timestamptz` on 14
  columns, and `uq_email_hash_org` → partial unique index.
- `Tracker.md:4` still claims `seed.py` exists and is gated behind
  `ALLOW_SEED=1`. The file and its test were removed.

### Needs operator action (cannot be done from here)

- Production is stamped `b7c2d1a9e4f5` and will run `c9e8f7a6b3d2` then
  `e5a1c93d7b28` on the next deploy. `c9e8f7a6b3d2` has never been applied in
  production and failed there previously. `database.py:121` logs only
  `alembic upgrade failed: <ExcType>`, so run `alembic upgrade head` by hand
  to see the real error.
- Live third-party keys (Supabase, Google/Microsoft OAuth, MISP, VirusTotal)
  must be rotated by the operator; the agent has no access to those consoles.
