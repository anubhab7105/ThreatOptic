# Application Flow

## 1. Data Ingestion Phase
1. **Email Arrival:** Email is ingested into the platform either directly via an SMTP relay (inline mode) or via API polling (O365/G-Suite).
2. **Metadata Extraction:** System separates raw headers, email body (HTML/Text), and attachments.
3. **Queueing:** Extracted data is placed onto a message broker (e.g., Kafka) for parallel processing.

## 2. Processing & ML Pipeline
1. **Header Validation Pipeline:**
   - Verify SPF/DKIM/DMARC status.
   - Extract the entire `Received` header chain to reconstruct the SMTP relay path.
2. **Traceability Pipeline:**
   - Isolate the originating IP.
   - Query GeoLocation, WHOIS, and proxy/VPN detection services.
3. **NLP Pipeline:**
   - Analyze subject and body for urgency cues, sentiment, and semantic BEC patterns.
4. **Threat Feed Pipeline:**
   - Check domains, URLs, and IPs against global blocklists.

## 3. Correlation & Risk Scoring
1. **Data Aggregation:** Results from all pipelines are sent to the Correlation Engine.
2. **Graph Lookups:** Query Neo4j to see if any extracted entities (domains, IPs) connect to previously identified fraud campaigns.
3. **Fraud Score Calculation:** The engine calculates a final Confidence Score (0-100) based on weighted findings.

## 4. Alerting & Action
1. **Policy Evaluation:** The score is evaluated against organizational rules (Critical 90-100 Quarantine, High 75-89 Junk/Hold, Medium 50-74 Banner, per `Rules.md` + `scoring.py:91-100` / `components.tsx:3-8`; legacy >85 text was superseded).
2. **User/Admin Alert:** High-risk notifications are dispatched to SOC analysts or end-users via UI, Email, or Slack/Teams.

## 5. Analyst Review & Forensic Reporting
1. **Dashboard Interaction:** Analyst opens the specific alert case.
2. **Visualization:** Platform displays a geographical map of origin and a trace node graph.
3. **Report Generation:** Analyst exports a chain-of-custody compliant forensic report (PDF/JSON) for escalation or legal review.

## Present-Stage Notes (September 2026)
- Default runs are offline-first: live network enrichment (WHOIS/DNS/URLhaus/DNSBL/ip-api) is skipped unless `ENABLE_LIVE_LOOKUPS=1`, so ingestion stays fast without internet.
- Gmail OAuth in the Dashboard auto-captures `?code=` from Google's redirect tab \u2014 analysts never handle codes manually.
- Known limitation: large real-world messages take tens of seconds each through the pipeline (auth DNS + model inference), so multi-mail syncs are slow but complete; per-stage timeouts and background sync jobs are roadmap.
