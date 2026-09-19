# Technical Specification

## Overview
The AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform leverages advanced AI/ML models, deep header parsing, and graph-based correlation to provide real-time email threat detection and extensive forensic capabilities.

## Tech Stack
- **Backend Services:** Python (FastAPI or Django) for core logic and ML serving, Node.js for async event processing.
- **AI/ML Engine:** PyTorch, HuggingFace Transformers (for NLP classification and urgency detection), scikit-learn.
- **Databases:**
  - **Relational:** PostgreSQL (User data, Case management, Configuration).
  - **Document/Search:** Elasticsearch or MongoDB (Raw email logs, fast text search).
  - **Graph:** Neo4j (Identity correlation, domain clustering, relationship analysis).
- **Frontend:** React.js, TypeScript, D3.js / Cytoscape.js (for visual trace maps and dashboards).
- **Infrastructure:** Docker, Kubernetes for orchestration, AWS/GCP, Kafka/RabbitMQ for event streaming.

## Core Modules

### 1. Ingestion & Preprocessing
- **APIs & Protocols:** IMAP, SMTP interfaces, Microsoft Graph API (O365), Google Workspace API.
- **Parsing Engine:** Robust parsing of MIME structures, extraction of raw headers, body text, and attachments.

### 2. Header Forensics & Traceability
- **Header Analysis:** Parsers for `Received` chains, `Message-ID`, `X-Mailer`, etc.
- **Authentication Validation:** Built-in validation tools for SPF, DKIM, and DMARC alignments.
- **IP & Geo Engine:** Integrations with MaxMind, IP2Location, and WHOIS databases to map IP to geographical and ISP data.

### 3. ML & NLP Engine
- **Text Analysis:** Transformer-based models for detecting impersonation, urgency, and social engineering.
- **Link/Attachment Analysis:** Defanging URLs, checking against threat feeds (e.g., VirusTotal, URLhaus), and sandboxing attachments.

### 4. Correlation & Attribution
- **Graph Construction:** Mapping `Sender IP` -> `Domain` -> `Email Alias` -> `Known Threat Actor`.
- **Scoring System:** Weighted ensemble model combining NLP score, Header integrity score, and Threat Intel score.

## Integrations
- Threat Intelligence Feeds (MISP, OTX AlienVault).
- SIEM/SOAR platforms (Splunk, IBM QRadar, Cortex XSOAR).
- Ticketing systems (Jira, ServiceNow).
