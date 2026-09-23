# System Design

## System Architecture

```mermaid
graph TD;
    A[Email Ingestion / API] --> B[Message Queue]
    B --> C[Header Forensic Parser]
    B --> D[NLP & Content Analyzer]
    B --> E[Threat Intel Fetcher]
    
    C --> F[Origin Trace & GeoLocation]
    C --> G[SPF/DKIM/DMARC Validator]
    
    D --> H[Risk Scoring Engine]
    E --> H
    F --> H
    G --> H
    
    H --> I[(Graph Database - Neo4j)]
    H --> J[(Document DB - ElasticSearch)]
    
    H --> K[Alerting Service]
    K --> L[SOC Analyst Dashboard]
    L --> M[Forensic Report Generator]
```

## UI/UX Guidelines

### Theme & Aesthetics
- **Color Palette:** Dark mode optimized for long hours of SOC monitoring. High contrast colors for alerts (Red for Critical, Orange for High, Yellow for Medium).
- **Typography:** Monospaced fonts for raw headers and IP addresses; clean sans-serif for dashboard metrics.

### Key Screens
1. **Global Threat Dashboard:** High-level metrics (Emails processed, blocked threats, active campaigns).
2. **Email Analysis View (Detailed — 5 tabs as implemented `frontend/src/pages.tsx:641`):** 
   - Tab 1: Executive Summary (Fraud Score, Classification).
   - Tab 2: Why this score? (Explainable weighted breakdown).
   - Tab 3: Header Forensics (Parsed received chain + SPF/DKIM/DMARC).
   - Tab 4: GeoLocation Map (Interactive world map showing IP origin).
   - Tab 5: Graph View (Node-link diagram of related domains/IPs).
3. **Case Management:** Kanban or list view of ongoing investigations.
4. **Mailboxes (present stage):** Organization-level Google/Microsoft OAuth connectors with background polling and manual Sync now.
5. **Model Info (present stage):** Live classifier metrics, per-class precision/recall/F1, and confusion matrix.
6. **Gmail live import (present stage):** No visible auth-code field \u2014 the app auto-captures `?code=` from Google's redirect tab and finishes the connection itself.

## Component Design

### 1. NLP Microservice
- Stateless API taking text and returning probability vectors for different threat classes. Can be horizontally scaled with GPU nodes.

### 2. Graph Correlation Worker
- Listens to the database, asynchronously updating the Neo4j graph as new entities are discovered to keep real-time ingestion fast.

### 3. Report Generator
- Assembles data securely, applying PII masking rules before rendering PDF/JSON evidence files.
