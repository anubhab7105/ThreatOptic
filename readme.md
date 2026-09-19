# AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

## Overview
This repository contains the architecture, documentation, and source code for the AI-Powered Email Threat Detection, GeoLocation, and Forensic Intelligence Platform. 

The platform is designed to move beyond static, signature-based email filtering by utilizing Natural Language Processing (NLP), Graph-based identity correlation, and deep header forensics. It aims to accurately detect sophisticated phishing, impersonation, and BEC (Business Email Compromise) attacks, trace their true geographical origins, and provide actionable forensic intelligence for SOC analysts and law enforcement.

## Documentation Index
Please refer to the following markdown files in this repository to understand the system comprehensively:

1. [Product Requirements Document (PRD)](PRD.md) - Problem statement, proposed solutions, and key components.
2. [Technical Specification (Techspec)](Techspec.md) - Tech stack and core module breakdown.
3. [Application Flow (AppFlow)](AppFlow.md) - Step-by-step data lifecycle from ingestion to alerting.
4. [System Design (Design)](Design.md) - Architectural diagrams and UI/UX approach.
5. [Database Schema (Shema)](Shema.md) - Data models across relational, document, and graph databases.
6. [Implementation Plan](Implementationplan.md) - Phased roadmap for development and rollout.
7. [Project Tracker (Tracker)](Tracker.md) - Actionable checklist of tasks.
8. [System Rules (Rules)](Rules.md) - Detection thresholds, privacy safeguards, and compliance policies.

## Getting Started (Developer Setup)

### Option A — local (SQLite, no infra)
```bash
python3 backend/scripts/train_nlp.py
PYTHONPATH=backend uvicorn app.main:app --reload --port 8000
# in another shell:
cd frontend && npm install && npm run dev
# API: http://localhost:8000/docs  UI: http://localhost:5173
```

### Option B — full stack (Postgres, Neo4j, Elastic, Kafka)
```bash
docker compose up --build
# backend http://localhost:8000/docs  frontend http://localhost:5173
```

### Key API
- POST /api/v1/emails/ingest {"raw": "<rfc822>"} | POST /api/v1/emails/upload (.eml)
- GET /api/v1/emails/{id} | GET /api/v1/dashboard
- GET /api/v1/reports/{id}.pdf / .json | GET /api/v1/graph/related?value=...
- POST /api/v1/cases | PATCH /api/v1/cases/{id}

Default SQLite file: `email_forensics.db`. Copy `backend/.env.example` to `backend/.env` to enable VirusTotal/MISP/Slack/Neo4j/Kafka.

## Contributing
Please adhere to the coding standards defined in the repository wiki. Ensure all commits referencing feature additions are tied to tasks in `Tracker.md`.

## License
Proprietary / Confidential. All rights reserved.
