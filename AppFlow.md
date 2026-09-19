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
1. **Policy Evaluation:** The score is evaluated against organizational rules (e.g., Score > 85 triggers Quarantine).
2. **User/Admin Alert:** High-risk notifications are dispatched to SOC analysts or end-users via UI, Email, or Slack/Teams.

## 5. Analyst Review & Forensic Reporting
1. **Dashboard Interaction:** Analyst opens the specific alert case.
2. **Visualization:** Platform displays a geographical map of origin and a trace node graph.
3. **Report Generation:** Analyst exports a chain-of-custody compliant forensic report (PDF/JSON) for escalation or legal review.
