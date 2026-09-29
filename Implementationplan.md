# Implementation Plan

> Status September 2026: Phases 1\u20136 complete and demoable; Phase 7 (auth, explainability, campaigns, Gmail demo, model transparency) complete per Tracker, including audit fixes F1\u2013F12. Remaining roadmap: larger BEC corpora, per-stage pipeline timeouts + background sync jobs, transformer rerank, SIEM/ticketing integrations.

## Phase 1: Foundation & Data Ingestion (Weeks 1-3)
- **Architecture Setup:** Provision AWS/GCP resources, Kubernetes clusters, and Databases (Postgres, Mongo/Elastic, Neo4j).
- **Ingestion Pipeline:** Develop API connectors (Microsoft Graph, Google Workspace) and SMTP relay endpoints.
- **Parsing Core:** Build the robust MIME parser and header extraction utility.
- **Milestone:** System can ingest, parse, and store raw emails securely.

## Phase 2: Traceability & Forensics Engine (Weeks 4-6)
- **Header Analysis:** Implement logic to parse `Received` chains and identify the true originating IP.
- **GeoLocation Integration:** Connect to MaxMind / IP2Location APIs.
- **Protocol Validation:** Implement SPF, DKIM, and DMARC validation scripts.
- **Milestone:** Platform accurately maps the origin and path of an ingested email.

## Phase 3: AI/ML & Threat Detection Engine (Weeks 7-10)
- **NLP Model Training:** Fine-tune open-source LLMs / Transformers on phishing and BEC datasets for sentiment, urgency, and impersonation detection.
- **Threat Intel Feeds:** Integrate with MISP, VirusTotal, and URLhaus.
- **Scoring Engine:** Develop the weighted scoring algorithm that outputs the overall Fraud Score.
- **Milestone:** System accurately classifies emails as legitimate, suspicious, or malicious.

## Phase 4: Graph Correlation & Attribution (Weeks 11-13)
- **Graph Modeling:** Implement data pipelines to push entities (IPs, Domains) into Neo4j.
- **Clustering:** Write Cypher queries to detect domain clustering and repeat attacker infrastructure.
- **Attribution Logic:** Develop the confidence-based assessment logic for campaign attribution.
- **Milestone:** System links seemingly isolated phishing emails to larger campaigns.

## Phase 5: Dashboard, UI & Reporting (Weeks 14-16)
- **Frontend Development:** Build the React.js SOC dashboard.
- **Data Visualization:** Integrate D3.js for trace maps and Cytoscape for graph node visualization.
- **Forensic Reporting:** Implement the PDF/JSON export feature with chain-of-custody compliance and PII masking.
- **Milestone:** Analysts can view, interact with, and export intelligence.

## Phase 6: QA, Compliance & Deployment (Weeks 17-18)
- **Security Audits:** Pen-testing and data privacy reviews.
- **UAT:** Beta testing with sample organizational traffic.
- **Go-Live:** Production deployment and documentation handover.
