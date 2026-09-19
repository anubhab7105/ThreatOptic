# System Rules & Policies

## 1. Threat Detection & Action Rules

### Risk Scoring Thresholds
- **Critical Risk (90 - 100):**
  - *Action:* Hard block / Auto-quarantine.
  - *Alert:* Instant high-priority alert to SOC dashboard and via PagerDuty/Slack.
- **High Risk (75 - 89):**
  - *Action:* Send to user's Junk/Spam folder or hold for admin approval.
  - *Alert:* Logged in dashboard as actionable case.
- **Medium Risk (50 - 74):**
  - *Action:* Deliver to Inbox with a highly visible cautionary banner.
- **Low Risk (0 - 49):**
  - *Action:* Deliver normally.

### Behavioral Rules
- If an email originates from a newly registered domain (under 30 days) AND contains payment instructions, add +30 to Fraud Score.
- If SPF/DKIM fail BUT the sender claims to be a C-Level Executive, auto-escalate to High Risk.

## 2. Privacy & Compliance Safeguards (GDPR/CCPA)

### PII Masking
- All raw email body content must pass through a sanitization filter that masks credit cards, SSNs, and identifiable personal names before being rendered on the analyst dashboard, unless the analyst has specific `Unmask_Privileges`.

### Data Retention
- **Clean Traffic:** Metadata retained for 7 days; body content dropped immediately.
- **Suspicious/Malicious Traffic:** Retained for 90 days for forensic investigation, after which body content is purged, leaving only aggregated threat intel indicators in the Graph DB.

### Chain of Custody
- When an analyst exports a forensic report, the system must generate a SHA-256 hash of the original `.eml` file and append a digital signature to the PDF report to ensure evidentiary integrity for law enforcement.
