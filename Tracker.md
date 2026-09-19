# Project Task Tracker

## Phase 1: Foundation & Ingestion
- [ ] Provision cloud infrastructure (VPCs, DB clusters).
- [ ] Initialize code repositories and CI/CD pipelines.
- [ ] Implement database schemas (Postgres, Elastic/Mongo).
- [ ] Build SMTP ingestion service.
- [ ] Build O365 / Google Workspace API connectors.
- [ ] Implement email parser for headers, body, and attachments.

## Phase 2: Traceability & Forensics
- [ ] Develop `Received` header traversal logic.
- [ ] Integrate IP to GeoLocation API.
- [ ] Integrate WHOIS and DNS lookup services.
- [ ] Implement SPF, DKIM, DMARC validation.
- [ ] Identify and flag proxy, TOR, and VPN IPs.

## Phase 3: AI/ML & Threat Detection
- [ ] Curate and sanitize training datasets (Phishing, BEC, Clean).
- [ ] Train/Deploy NLP models for urgency and impersonation cues.
- [ ] Implement URL extraction and sandbox/defang logic.
- [ ] Connect external Threat Intelligence APIs.
- [ ] Build risk scoring and aggregation algorithm.

## Phase 4: Graph Correlation & Attribution
- [ ] Deploy Neo4j graph database.
- [ ] Write entity extraction and graph population workers.
- [ ] Develop queries for domain clustering.
- [ ] Build campaign attribution logic.

## Phase 5: Dashboard & UI
- [ ] Setup React project with UI component library.
- [ ] Build real-time alert feed interface.
- [ ] Develop detailed Forensic Analysis View.
- [ ] Implement interactive GeoLocation Map.
- [ ] Implement interactive Node-Graph Visualization.
- [ ] Build PDF forensic report generator.

## Phase 6: QA & Launch
- [ ] Perform PII masking and compliance checks.
- [ ] End-to-end integration testing.
- [ ] Security penetration testing.
- [ ] Deploy to production environment.
- [ ] User training and documentation release.
