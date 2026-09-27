# Implementation Plan

> Status September 2026: Phases 1–6 complete and demoable; Phase 7 (Supabase auth, explainability, campaigns, Gmail + org mailbox OAuth, model transparency) complete per Tracker, including audit fixes F1–F12 and remediation revisions (`REMEDIATION_LOG.md`). Auth is Supabase-owned (no local register/login/refresh routes — only `GET /auth/me`); remaining roadmap: larger BEC corpora (committed BEC support is 2 rows — `metrics.json` macro F1 0.6593), per-stage pipeline timeouts + background sync jobs, transformer rerank (dormant `TRANSFORMERS_MODEL` hook), SIEM/ticketing integrations (roadmap-only in `Techspec.md`).

## Phase 1: Foundation & Data Ingestion (Weeks 1-3)
- **Architecture Setup:** ~~Provision AWS/GCP resources, Kubernetes clusters~~ → as built: Supabase (Postgres + Auth), `docker-compose.yml` (backend + frontend + neo4j + elasticsearch + kafka; no local postgres), `k8s/backend.yaml`, Railway (backend) + Vercel (frontend) per `DEPLOY.md`.
- **Ingestion Pipeline:** Develop API connectors (Microsoft Graph, Google Workspace) and SMTP relay endpoints. → as built: `routers/gmail.py` (personal Gmail vault) + `routers/oauth.py` (org Google/Microsoft, state + PKCE + allowlist) + `services/mailbox_poll.py` + inline SMTP (`modules/ingestion/smtp_server.py`, `SMTP_ENABLED=1`) + REST ingest/upload (`routers/api.py`).
- **Parsing Core:** Build the robust MIME parser and header extraction utility. → `modules/ingestion/parser.py` (headers/body/attachment magic, bleach caps, 5 MB limit, idempotent `(raw_eml_hash, org)` ingest).
- **Milestone:** System can ingest, parse, and store raw emails securely. → met, except raw bodies are never stored (only masked) per privacy model.

## Phase 2: Traceability & Forensics Engine (Weeks 4-6)
- **Header Analysis:** Implement logic to parse `Received` chains and identify the true originating IP.
- **GeoLocation Integration:** Connect to MaxMind / IP2Location APIs.
- **Protocol Validation:** Implement SPF, DKIM, and DMARC validation scripts.
- **Milestone:** Platform accurately maps the origin and path of an ingested email.

## Phase 3: AI/ML & Threat Detection Engine (Weeks 7-10)
- **NLP Model Training:** ~~Fine-tune open-source LLMs / Transformers on phishing and BEC datasets~~ → as built: TF-IDF + LogisticRegression (`scripts/train_nlp.py` ← `fetch_datasets.py` SpamAssassin + curated BEC → `ml_models/dataset.csv`, gitignored; artifacts `phishing_clf.joblib` + `.sha256` committed; metrics → `metrics.json`, served by `GET /model/metrics`); transformer rerank is a dormant pinned-revision hook only.
- **Threat Intel Feeds:** Integrate with MISP, VirusTotal, and URLhaus. → as built, plus DNSBL/Spamhaus DROP, operator `backend/data/local_blocklist.txt`, attachment VT (`threat_intel/`); OTX AlienVault is roadmap-only.
- **Scoring Engine:** Develop the weighted scoring algorithm that outputs the overall Fraud Score. → `modules/correlation/scoring.py` (nlp .30 / auth .25 / intel .20 / routing .15 / attachment .10; `score_breakdown` sums to score; bands in `Rules.md`).
- **Milestone:** System accurately classifies emails as legitimate, suspicious, or malicious. → met for phishing/clean (F1 0.98/0.998); BEC recall is 0.0 on the committed corpus (support=2) — needs the larger-BEC-corpus roadmap item.

## Phase 4: Graph Correlation & Attribution (Weeks 11-13)
- **Graph Modeling:** Implement data pipelines to push entities (IPs, Domains) into Neo4j.
- **Clustering:** Write Cypher queries to detect domain clustering and repeat attacker infrastructure.
- **Attribution Logic:** Develop the confidence-based assessment logic for campaign attribution.
- **Milestone:** System links seemingly isolated phishing emails to larger campaigns.

## Phase 5: Dashboard, UI & Reporting (Weeks 14-16)
- **Frontend Development:** Build the React.js SOC dashboard. → as built: Vite 6 + React 18 + TS + Router 7 + Supabase-js (`frontend/`); routes in `main.tsx`, views in `pages.tsx` (Landing/Login/Dashboard/EmailView/Cases/Campaigns/Mailboxes/ModelInfo/Privacy/Terms).
- **Data Visualization:** ~~Integrate D3.js for trace maps and Cytoscape for graph node visualization.~~ → as built: OSM iframe embed for geo, custom `GraphSvg` for related entities, `ThreatGauge`/distribution bars; no D3/Cytoscape dependency.
- **Forensic Reporting:** Implement the PDF/JSON export feature with chain-of-custody compliance and PII masking. → `modules/reporting/generator.py` + `privacy/chain_of_custody.py` (HMAC manifest v1, rotation), `GET /reports/{id}.pdf/.json`.
- **Milestone:** Analysts can view, interact with, and export intelligence. → met.

## Phase 6: QA, Compliance & Deployment (Weeks 17-18)
- **Security Audits:** Pen-testing and data privacy reviews.
- **UAT:** Beta testing with sample organizational traffic.
- **Go-Live:** Production deployment and documentation handover.
