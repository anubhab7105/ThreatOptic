# Product Requirements Document (PRD)

## Product Name
AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

## Background
Email continues to be one of the most widely used communication channels in government, education, banking, and enterprise ecosystems. However, it also remains one of the most exploited attack vectors for phishing, impersonation, business email compromise, financial fraud, credential theft, and malware delivery. Traditional security controls are often insufficient to detect sophisticated fraudulent emails that use AI-generated language, domain lookalikes, display-name spoofing, hidden redirection links, and relay chains.

## Problem Statement
Current email security ecosystems primarily focus on filtering or blocking suspicious content but provide limited intelligence for deep forensic tracing of fraudulent email origins. There is a need for an AI-powered platform capable of detecting phishing, spoofed, impersonated, and fraudulent emails in real time, analyzing the complete technical structure, tracing its transmission path, estimating its origin, and generating forensic intelligence.

## Proposed Solution
Develop an AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform that combines Natural Language Processing (NLP), Machine Learning (ML), email header forensics, IP intelligence, domain analysis, and graph-based correlation to identify suspicious emails, detect advanced email threats, and investigate their probable origin.

## Key Components

### 1. Fraudulent Email Detection Engine
- NLP-based analysis of email subject lines, body text, urgency cues, impersonation language.
- Detection of phishing indicators (spoofed sender addresses, deceptive domains, malicious links).
- AI/ML models to classify emails.
- Identification of business email compromise (BEC) patterns.

### 2. Email Header and Protocol Analysis Module
- Deep analysis of email headers (Return-Path, Received, Message-ID, DKIM, SPF, DMARC).
- Detection of anomalies in mail routing, forged sender fields, relay manipulation.
- Validation of authorized infrastructure.

### 3. Origin Traceability and Location Analysis
- Extraction of originating IP addresses from header chains.
- IP geolocation mapping.
- Correlation with VPN, TOR, open relay, botnet, or cloud-hosted infrastructure.
- Domain intelligence analysis (WHOIS, DNS, MX).

### 4. Identity Correlation and Attribution Support
- Correlation with known threat intelligence and blacklists.
- Graph-based relationship analysis.
- Confidence-based investigative assessment for attribution.
- Support for flagging compromised accounts vs. direct malicious actors.

### 5. Alerting, Dashboard, and Forensic Reporting
- Real-time alerts for high-risk emails.
- Analyst dashboard showing fraud score, trace path, geolocation map, and attribution.
- Generation of structured forensic reports.
- Searchable case management view for fraud campaigns.

### 6. Privacy, Legal, and Compliance Safeguards
- Controlled handling of personal data and metadata.
- Logging, evidence preservation, and chain-of-custody support.
- Configurable retention and masking mechanisms.

## Expected Outcomes
- Early and accurate detection of fraudulent and phishing attacks.
- Improved ability to trace suspicious email origin paths.
- Enhanced fraud investigation capability through geolocation and domain intelligence.
- Reduced financial loss, reputational damage, and unauthorized data disclosure.
- Better institutional readiness for cyber incident response.

## Present-Stage Scope Note (September 2026)
All six components above are implemented and demoable. Honest scoping for the "AI" label: the running ML is a scikit-learn TF-IDF + LogisticRegression text classifier (phishing / bec / clean) contributing 30% of the fraud score (`modules/correlation/scoring.py:WEIGHTS`), backed by hand-written linguistic cue families (`modules/nlp/`), plus a lexical URL classifier (`modules/threat_intel/url_ml.py` → `ml_models/url_phishing_model.pkl`); transformer/LLM reranking exists only as a dormant `TRANSFORMERS_MODEL` + `TRANSFORMERS_REVISION` hook in `modules/nlp/engine.py` (libraries not installed, production refuses unpinned models and falls back to sklearn). Detection strength in v1 therefore comes from ML fused with deterministic forensics (headers, auth, geo, feeds, graph), all of it explainable per-signal in the UI (`score_breakdown` sums to the fraud score).

## Implementation Status (maps each component to the code)
- §1 Detection engine → `backend/app/modules/nlp/engine.py` (TF-IDF/LogReg + cues), `backend/app/modules/threat_intel/url_analyzer.py` + `url_ml.py`, `backend/app/modules/threat_intel/attachment_analyzer.py`, `backend/app/modules/correlation/scoring.py` (nlp 0.30 / auth 0.25 / intel 0.20 / routing 0.15 / attachment 0.10). Committed model: `backend/ml_models/phishing_clf.joblib` (+ `.sha256`, optional `MODEL_VERIFY_KEY` Ed25519); metrics at `GET /api/v1/model/metrics` / Model Info page.
- §2 Header/protocol analysis → `backend/app/modules/forensics/header_parser.py`, `received_chain.py`, `auth_validator.py` (SPF/DKIM/DMARC + ARC/alignment, `unverifiable` when `ENABLE_LIVE_LOOKUPS=0`).
- §3 Origin traceability → `backend/app/modules/traceability/ip_extractor.py` (`TRUSTED_RELAY_HOSTS/IPS` boundary), `geoip.py` (MaxMind GeoLite2 + ip-api fallback, offline stub), `whois_dns.py`, `vpn_tor.py`. Offline-first: live WHOIS/DNS/URLhaus/DNSBL/ip-api run only with `ENABLE_LIVE_LOOKUPS=1`.
- §4 Identity correlation → `backend/app/modules/graph/store.py` (networkx local, Neo4j when `NEO4J_URI` set), `backend/app/modules/graph/attribution.py`, `backend/app/services/campaigns.py`; infra-only `GET /graph/campaigns`, tenant-filtered `GET /graph/related`.
- §5 Alerting/dashboard/reporting → `backend/app/modules/alerting/dispatcher.py` (Slack/PagerDuty/dedup 15 min/rate limits/backoff; policy in `Rules.md`), `POST /ws/ticket` → `WS /ws/alerts` (score ≥75, same-org + Admin), React SPA (`frontend/src/pages.tsx`: Dashboard, EmailView 5 tabs, Campaigns, Cases, Mailboxes, Model Info), chain-of-custody PDF/JSON (`modules/reporting/generator.py` + `privacy/chain_of_custody.py` HMAC manifest).
- §6 Privacy/compliance → `backend/app/modules/privacy/masking.py` (cards-Luhn/SSN/phones/email-localparts; names/addresses/IPs not masked; no unmask bypass), `retention.py` (clean 7d body-blank, malicious 90d full delete, `POST /api/v1/admin/retention`), raw bodies never persisted (`Rules.md` §2, `SECURITY.md` rotation runbook).
- Auth/RBAC (cross-cutting) → Supabase owns login/register/sessions; backend verifies JWT (`routers/deps.py`, JWKS + HS256 dev fallback) and reads role/org from `public.users` (trigger `backend/supabase_handle_new_user.sql`, default `Analyst` + personal org). Only `GET /auth/me` exists; `ReadOnly` reads, `Analyst` ingests/edits, `Admin` deletes/retention. All `/api/v1/*` tenant-scoped (Admin bypass, 404-no-leak).
