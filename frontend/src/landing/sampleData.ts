/* Landing sample data — all fictional, clearly labeled Sample. Never calls backend. */

export const SAMPLE_SCORE = 87;
export const SAMPLE_SEVERITY = 'Critical' as const;

export const SAMPLE_FACTORS = [
  { name: 'Authentication failure (SPF fail, DKIM fail, DMARC fail)', weight: 34, detail: 'Return-Path domain does not authorize the sending IP.' },
  { name: 'Lookalike sender domain (paypa1-secure.example vs expected)', weight: 27, detail: 'Display name impersonates an executive; domain uses .invalid test space.' },
  { name: 'Urgent wire-transfer language + link to credential page', weight: 26, detail: 'Pressure phrasing with a link outside the organization domain.' },
] as const;

export const SAMPLE_HOPS = [
  { hop: 1, from: 'internal.invalid [10.0.0.5]', by: 'evil-relay.example', ip: '203.0.113.88', result: 'no auth' },
  { hop: 2, from: 'evil-relay.example [203.0.113.88]', by: 'mx.company.example', ip: '198.51.100.23', result: 'SPF fail · DKIM fail' },
] as const;

export const SAMPLE_EMAIL_TEXT = `From: "Chief Executive" <ceo@paypa1-secure.example>
To: finance@example.com
Subject: Urgent: confidential wire transfer needed ASAP
Date: Mon, 22 Sep 2026 09:14:00 +0000
Message-ID: <sample-001@paypa1-secure.example>

Hi, kindly wire $48,000 to the new vendor bank details
immediately. Do not disclose. Verify the account now at
http://credential-harvest.example/login

— Sent from a fictional sample. Nothing leaves your browser.`;

export const EXPLAIN_FACTORS = [
  { name: 'Authentication (SPF/DKIM/DMARC)', weight: 25, text: 'Hard fail on all three checks' },
  { name: 'Language model (urgency + impersonation)', weight: 30, text: 'Executive display-name spoof, pressure phrasing' },
  { name: 'Threat intel (URL + attachment reputation)', weight: 20, text: 'Linked host on a sample blocklist entry' },
  { name: 'Routing anomalies (relay + geo mismatch)', weight: 15, text: 'Unexpected relay country vs sender claim' },
  { name: 'Attachment signals', weight: 10, text: 'No attachment in sample; weight held at baseline' },
] as const;

export const HEADER_SAMPLE_ROWS = [
  { field: 'From', value: '"Chief Executive" <ceo@paypa1-secure.example>', note: 'Display-name impersonation' },
  { field: 'Return-Path', value: '<bounce@evil-relay.example>', note: 'Does not match From' },
  { field: 'SPF', value: 'fail — 203.0.113.88 not authorized', note: 'Hard fail' },
  { field: 'DKIM', value: 'fail — bad signature (d=paypa1-secure.example)', note: 'Hard fail' },
  { field: 'DMARC', value: 'fail — p=reject, From unaligned', note: 'Hard fail' },
  { field: 'Received #1', value: 'from internal.invalid by evil-relay.example', note: 'First external hop' },
  { field: 'Received #2', value: 'from evil-relay.example by mx.company.example', note: 'Delivering hop' },
] as const;

export const GEO_SAMPLE = {
  originIp: '203.0.113.88 (sample, TEST-NET-3)',
  country: 'Sample country — withheld',
  asn: 'AS64512 (sample)',
  hops: 2,
  note: 'Origin marker and hop arc are illustrative positions, not real geolocation.',
} as const;

export const GRAPH_SAMPLE_NODES = [
  { id: 'email-1', label: 'Sample email', kind: 'email' },
  { id: 'domain-1', label: 'paypa1-secure.example', kind: 'domain' },
  { id: 'ip-1', label: '203.0.113.88', kind: 'ip' },
  { id: 'url-1', label: 'credential-harvest.example/login', kind: 'url' },
  { id: 'case-1', label: 'Sample case #1042', kind: 'case' },
] as const;

export const GRAPH_SAMPLE_EDGES = [
  { from: 'email-1', to: 'domain-1', label: 'sent as' },
  { from: 'email-1', to: 'ip-1', label: 'relayed by' },
  { from: 'email-1', to: 'url-1', label: 'links to' },
  { from: 'email-1', to: 'case-1', label: 'opened as' },
] as const;
