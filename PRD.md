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
All six components above are implemented and demoable. Honest scoping for the "AI" label: the running ML is a scikit-learn TF-IDF + LogisticRegression text classifier (phishing / bec / clean) contributing 30% of the fraud score, backed by ~35 hand-written linguistic cue families; transformer/LLM reranking exists only as a dormant `TRANSFORMERS_MODEL` hook (libraries not installed). Detection strength in v1 therefore comes from ML fused with deterministic forensics (headers, auth, geo, feeds, graph), all of it explainable per-signal in the UI.
