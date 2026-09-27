# System Rules & Policies

## 1. Threat Detection & Action Rules

### Risk Scoring Thresholds (code: `modules/correlation/scoring.py:91-100` + `modules/alerting/dispatcher.py:evaluate_policy`)
- **Critical Risk (90 - 100):**
  - *Action:* Hard block / Auto-quarantine.
  - *Alert:* Instant high-priority alert to SOC dashboard (WebSocket score ≥75 stream) and via PagerDuty + Slack (`pagerduty+slack+dashboard` channel; 15-min per-(email, severity) dedup, Slack 10/min, PagerDuty 5/min, 3-attempt backoff).
- **High Risk (75 - 89):**
  - *Action:* Send to user's Junk/Spam folder or hold for admin approval (`JunkOrHold`).
  - *Alert:* Logged in dashboard as actionable case (`dashboard+slack` channel) + WebSocket push.
- **Medium Risk (50 - 74):**
  - *Action:* Deliver to Inbox with a highly visible cautionary banner (`DeliverWithBanner`, dashboard-only channel).
- **Low Risk (0 - 49):**
  - *Action:* Deliver normally (`Deliver`, no alert channel; scoring label is `Low-Suspicious`).

### Ensemble Weights (as implemented in `modules/correlation/scoring.py`, sum to 1.0)
- **nlp 0.30** (ML score + linguistic cues) · **auth 0.25** (SPF/DKIM/DMARC) · **intel 0.20** (feeds/blocklists) · **routing 0.15** (chain anomalies, domain age, payment language) · **attachment 0.10** (malware heuristics).
- Every stored `score_breakdown` signal carries weight/value/contribution and sums exactly to the fraud score (asserted by `scripts/live_demo_check.py`).

### Behavioral Rules (code: `modules/correlation/scoring.py:61-88`)
- If an email originates from a newly registered domain (under 30 days, negative/future ages ignored as clock garbage) AND contains payment instructions, add +30 to Fraud Score (`new-domain+payment:+30` breakdown signal).
- If SPF/DKIM fail BUT the sender claims to be a C-Level Executive (ceo/cfo/chief/president in impersonation cues), auto-escalate to High Risk (floor to 75.0 via `exec-spoof-auth-fail:force-high`).
- Ingest is idempotent per tenant: duplicate bytes on `(raw_eml_hash, organization_id)` (partial unique index `uq_email_hash_org`) return the stored verdict instead of re-scoring.

### Access & Rate Rules (code: `routers/deps.py`, `routers/api.py`, `modules/auth/rate_limit.py`)
- Roles: **ReadOnly** reads; **Analyst** ingests + edits cases + syncs mailboxes; **Admin** deletes cases + runs retention + sees all tenants. New Supabase signups default to **Analyst** with a personal org (`supabase_handle_new_user.sql`); cross-tenant reads return 404 (indistinguishable from missing), never 403.
- Rate limits (slowapi, kill-switch `RATE_LIMIT_ENABLED`): 60/min ingest, 30/min OAuth authorize/callback, 10/min sync-now; login throttling is owned by Supabase server-side. `CaseUpdate` rejects unknown fields, blank titles, bad assignees and non-enum statuses (422/400).

## 2. Privacy & Compliance Safeguards (GDPR/CCPA)

### PII Masking
- All email fields (`subject/sender/recipient/body` via `modules/privacy/masking.py:50-59` + `reporting/generator.py:12-15`) are masked (card Luhn, SSN, phone, `***@domain`) before rendering or indexing; masking is **unconditional** — no `Unmask_Privileges` bypass exists in the request path (Step 3). The legacy `Unmask_Privileges` role in earlier drafts does not exist; only `Admin/Analyst/ReadOnly` (see `Shema.md:10`).

### Data Retention (code: `modules/privacy/retention.py`, `services/scheduler.py` daily 03:00 `RETENTION_HOUR`)
- **Clean Traffic (score <50):** raw bodies are never stored in the first place (only `body_text_masked`); retention body-blanks any legacy rows at 7 days (`RETENTION_CLEAN_DAYS`), keeping metadata. Audit lines go to `backend/retention_audit.log`.
- **Suspicious/Malicious Traffic:** Retained for 90 days (`RETENTION_MALICIOUS_DAYS`) for forensic investigation, after which rows are fully deleted in batches (email + analysis + trace + ES doc + graph node, per-batch rollback), leaving only aggregated threat intel indicators in the Graph DB. Manual run: `POST /api/v1/admin/retention` (Admin-only).

### Chain of Custody (code: `modules/privacy/chain_of_custody.py`, `modules/reporting/generator.py`)
- When an analyst exports a forensic report, the system must generate a SHA-256 hash of the original `.eml` file and append a digital signature to the PDF report to ensure evidentiary integrity for law enforcement. Manifest v1 binds purpose + version + timestamp into the HMAC payload; `CUSTODY_KEY` signs, `CUSTODY_KEY_PREVIOUS` is accepted during rotation windows only; `APP_ENV=development` alone keeps an ephemeral per-process dev key (never persisted, never verifies across restarts).
