# Database Schema Design

This document outlines the high-level schema for the primary data stores.

## Relational Database (PostgreSQL)

### `User`
- `id`: UUID (Primary Key)
- `username`: String
- `role`: Enum (Admin, Analyst, ReadOnly)
- `organization_id`: UUID
- `created_at`: Timestamp

### `Organization`
- `id`: UUID (Primary Key)
- `name`: String
- `compliance_policy`: JSON (Settings for data retention and PII masking)

### `InvestigationCase`
- `id`: UUID (Primary Key)
- `title`: String
- `status`: Enum (Open, InProgress, Closed)
- `assignee_id`: UUID (Foreign Key -> User)
- `created_at`: Timestamp

---

## Document Database (Elasticsearch / MongoDB)
*Used for fast text search and storing raw blobs.*

### `EmailRecord`
- `_id`: UUID
- `message_id`: String (from email headers)
- `sender_address`: String
- `recipient_address`: String
- `subject`: String
- `raw_headers`: Object
- `body_text_masked`: String
- `attachments_metadata`: Array
- `timestamp`: DateTime

### `AnalysisResult`
- `_id`: UUID
- `email_id`: UUID
- `fraud_score`: Float (0-100)
- `threat_classification`: String (e.g., "BEC", "Phishing")
- `nlp_cues_detected`: Array of Strings
- `authentication_results`: Object (SPF, DKIM, DMARC status)

### `TraceabilityData`
- `_id`: UUID
- `email_id`: UUID
- `origin_ip`: String
- `geolocation`: Object (`lat`, `lon`, `country`, `city`)
- `isp_asn`: String
- `is_vpn_tor`: Boolean

---

## Graph Database (Neo4j)
*Nodes and edges for correlation.*

### Nodes
- `IP_Address` {ip, country, is_malicious}
- `Domain` {name, registrar, creation_date}
- `Email_Address` {address, is_compromised}
- `Threat_Campaign` {name, signature_type}

### Edges
- `(Email_Address)-[:SENT_FROM]->(IP_Address)`
- `(IP_Address)-[:HOSTS]->(Domain)`
- `(Domain)-[:PART_OF]->(Threat_Campaign)`
