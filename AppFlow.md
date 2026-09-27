# Application Flow

## 1. Data Ingestion Phase
1. **Email Arrival:** Email is ingested via `POST /api/v1/emails/ingest` (`{"raw": "<rfc822>"}`), `POST /api/v1/emails/upload` (`.eml/.txt/.mime`, 5 MB max), the inline SMTP relay (`SMTP_ENABLED=1` → `modules/ingestion/smtp_server.py`, default `127.0.0.1:1025`, AUTH/TLS/DATA-limit options), personal Gmail OAuth2 sync (`routers/gmail.py`), or org Google/Microsoft connectors (`routers/oauth.py` + `services/mailbox_poll.py`; `MAIL_POLL_MINUTES=0` = manual Sync now only). Ingest is idempotent per tenant on `(raw_eml_hash, organization_id)` — duplicate bytes return the stored verdict.
2. **Metadata Extraction:** `modules/ingestion/parser.py` separates raw headers, body (HTML/Text), and attachment metadata (8-byte magic); `bleach` sanitizes with size/count caps; `MAX_RAW_BYTES` = 5 MB enforced at the API and SMTP layers.
3. **Queueing:** The bounded in-memory queue (`modules/ingestion/queue.py`, `SMTP_QUEUE_MAX` count + `SMTP_QUEUE_MAX_BYTES` byte budget, overflow → 452, `ack_email()` consumer discipline) is the **primary** pipeline path. Kafka (`KAFKA_BOOTSTRAP`) is an opt-in **mirror** for external consumers only (never the pipeline path; mirror failures only log). Celery (`CELERY_BROKER_URL`, `services/tasks.py:analyze_email_task`) is the opt-in async path: `POST ...?async_mode=true` → 202 `{task_id}` → `GET /api/v1/tasks/{id}` (ownership-checked per tenant); unset keeps the synchronous pipeline.

## 2. Processing & ML Pipeline (`backend/app/services/pipeline.py` — one enrichment failing never fails the whole ingestion)
1. **Header Validation Pipeline:**
   - Verify SPF/DKIM/DMARC/ARC status (`modules/forensics/auth_validator.py`; offline → `unverifiable`, scores near-zero).
   - Extract the entire `Received` header chain (`modules/forensics/received_chain.py` + `header_parser.py`) to reconstruct the SMTP relay path and flag anomalies (brand spoof, multi-From, homoglyph/lookalike domains via `threat_intel/lookalikes.py`).
2. **Traceability Pipeline:**
   - Isolate the originating IP (`traceability/ip_extractor.py`, trust boundary `TRUSTED_RELAY_HOSTS/IPS` → last-external-hop).
   - Query GeoLocation (MaxMind + ip-api fallback + offline stub), WHOIS/DNS (`whois_dns.py`), and proxy/VPN/Tor detection (`vpn_tor.py`) — all gated by `ENABLE_LIVE_LOOKUPS` (default `0` = fast offline).
3. **NLP Pipeline:**
   - TF-IDF + LogisticRegression (`ml_models/phishing_clf.joblib`) + linguistic cues (`modules/nlp/engine.py`); lexical URL classifier (`threat_intel/url_ml.py`); optional dev-only transformer rerank (pinned revision, production falls back to sklearn).
   - Analyze subject and body for urgency cues, sentiment, and semantic BEC patterns. Raw bodies are used in-memory only and **never persisted** — only `body_text_masked` is stored (`modules/privacy/masking.py`).
4. **Threat Feed Pipeline:**
   - Check domains, URLs, IPs and attachment hashes against VirusTotal (skipped without `VIRUSTOTAL_API_KEY`), URLhaus, MISP, DNSBL/Spamhaus DROP, operator `backend/data/local_blocklist.txt`, and `KNOWN_LEGIT_DOMAINS`-augmented lookalike detection (dev-only demo fixtures when offline).

## 3. Correlation & Risk Scoring
1. **Data Aggregation:** `services/pipeline.py` fuses all pipelines in `modules/correlation/scoring.py`: nlp 0.30 / auth 0.25 / intel 0.20 / routing 0.15 / attachment 0.10; behavioral rules (new-domain <30d + payment +30; SPF/DKIM-fail + exec-impersonation forces ≥75); every `score_breakdown` signal sums exactly to the 0–100 fraud score.
2. **Graph Lookups:** `modules/graph/store.py:upsert_email_graph` writes entities; `find_campaigns` / `related_entities` read Neo4j when `NEO4J_URI` is set, else networkx. `services/campaigns.py` builds cards/detail; `/graph/campaigns` exposes infra clusters only, `/graph/related` is tenant-filtered.
3. **Fraud Score Calculation:** Bands per `Rules.md` + `scoring.py:91-100` / `alerting/dispatcher.py:evaluate_policy`: Critical ≥90 Quarantine, High ≥75 JunkOrHold, Medium ≥50 DeliverWithBanner, Low Deliver. Elastic mirror (`search/elastic_sync.py`) + dashboard-cache invalidation (`dash:` prefix) happen on write.

## 4. Alerting & Action
1. **Policy Evaluation:** `modules/alerting/dispatcher.py:evaluate_policy` maps the score to bands (Critical 90-100 Quarantine via pagerduty+slack+dashboard, High 75-89 JunkOrHold via dashboard+slack, Medium 50-74 DeliverWithBanner, Low Deliver; per `Rules.md` + `scoring.py:91-100`). Per-(email, severity) 15-min dedup, per-channel rate limits (Slack 10/min, PagerDuty 5/min), 3-attempt backoff; `sent` lists only channels actually attempted.
2. **User/Admin Alert:** Score ≥75 is broadcast over WebSocket (`POST /api/v1/ws/ticket` → `WS /api/v1/ws/alerts?ticket=`, same-org + Admin, nav bell live stream) and persisted as dashboard cases; Slack/PagerDuty fire only when `SLACK_WEBHOOK_URL` / `PAGERDUTY_ROUTING_KEY` are set.

## 5. Analyst Review & Forensic Reporting
1. **Dashboard Interaction:** Analyst opens the specific alert case (`GET /api/v1/emails/{id}` → email + analysis + trace; tenant-scoped, 404-no-leak; `GET /dashboard`, `GET /search?q=`, `GET /campaigns[/{id}]`, cases CRUD with `CaseUpdate` validation).
2. **Visualization:** EmailView's 5 tabs (`frontend/src/pages.tsx:TABS` — Summary / Why this score? / Header Forensics / GeoLocation / Graph View) show the fraud score, weighted-breakdown bar chart, parsed received chain + SPF/DKIM/DMARC, OSM-embed origin map, and custom `GraphSvg` related-entity diagram.
3. **Report Generation:** Analyst exports a chain-of-custody compliant forensic report (`GET /api/v1/reports/{id}.json` / `.pdf`, filename-guarded) — SHA-256 of the `.eml` + HMAC manifest v1 (`CUSTODY_KEY`, rotation via `CUSTODY_KEY_PREVIOUS`), PII-masked subjects/senders/recipients (`reporting/generator.py`).
4. **Retention:** `services/scheduler.py` runs `apply_retention()` daily at 03:00 (`RETENTION_HOUR`): clean mail body-blanked at 7d, malicious fully deleted (email + analysis + trace + ES doc + graph node, batched with per-batch rollback) at 90d; manual `POST /api/v1/admin/retention` (Admin); audit lines in `backend/retention_audit.log`.

## Present-Stage Notes (September 2026)
- Default runs are offline-first: live network enrichment (WHOIS/DNS/URLhaus/DNSBL/ip-api) is skipped unless `ENABLE_LIVE_LOOKUPS=1`, so ingestion stays fast without internet. Offline auth checks report `unverifiable` (distinct from real failures) and score near-zero.
- Gmail OAuth in the Dashboard auto-captures `?code=` + opaque `state` from Google's redirect tab (PKCE S256, server-side single-use state, allowlisted `redirect_uri`) — analysts never handle codes manually; Finish connection is only a retry. Org Google/Microsoft connectors live under Mailboxes (`routers/oauth.py`).
- Queue reality: in-memory queue is primary (bounded count + bytes, survives nothing across restarts); Kafka is an opt-in external-consumer mirror; Celery `?async_mode` is the opt-in background path (`GET /tasks/{id}` ownership-checked).
- Known limitation: large real-world messages take tens of seconds each through the pipeline (auth DNS + model inference), so multi-mail syncs are slow but complete; per-stage timeouts and background sync jobs are roadmap. `uvicorn --reload` restarts also cause transient 500s (~10s, retry).
