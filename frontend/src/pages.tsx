import React, { useEffect, useMemo, useState } from 'react';
import { ApiError, downloadReport, jdel, jget, jpatch, jpost, uploadEmFile } from './api';
import { useAuth } from './auth';
import { AuthPill, Empty, ScoreBadge, SkeletonList, StatCard, Toast, severityColor } from './components';

/* ---------------- Login ---------------- */

export function LoginPage() {
  const { login, register } = useAuth();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!username.trim() || !password) return;
    setBusy(true);
    setErr('');
    try {
      if (mode === 'login') await login(username.trim(), password);
      else await register(username.trim(), password);
    } catch (e) {
      setErr(e instanceof ApiError ? `Authentication failed (${e.status}): ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page" style={{ maxWidth: 440 }}>
      <h1>SOC Sign in</h1>
      <p className="sub">JWT-secured access to the forensic intelligence platform.</p>
      <div className="card">
        <div className="tabs">
          {(['login', 'register'] as const).map((m) => (
            <button key={m} className={mode === m ? 'active' : ''} onClick={() => { setMode(m); setErr(''); }}>
              {m === 'login' ? 'Sign in' : 'Register'}
            </button>
          ))}
        </div>
        <Toast msg={err} />
        <div className="grid" style={{ gap: 10 }}>
          <input type="text" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') submit(); }} autoComplete="username" />
          <input type="password" placeholder={mode === 'register' ? 'Password (min 8 chars)' : 'Password'} value={password}
            onChange={(e) => setPassword(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') submit(); }} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} />
          <button onClick={submit} disabled={busy || !username.trim() || !password}>
            {busy ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create analyst account'}
          </button>
        </div>
        <p className="sub" style={{ marginTop: 12, marginBottom: 0 }}>
          {mode === 'register'
            ? 'New accounts join as Analyst (first-ever account becomes Admin).'
            : 'Demo seed: admin / admin123, analyst / analyst123.'}
        </p>
      </div>
    </div>
  );
}

const PHISH_SAMPLE = `From: "CEO" <ceo@xn--paypa1-secure.top>
To: finance@company.com
Subject: Urgent: Confidential wire transfer needed ASAP
Message-ID: <abc123@xn--paypa1-secure.top>
Return-Path: <bounce@evil-relay.test>
Received: from evil-relay.test (evil-relay.test [45.148.10.88]) by mx.company.com with ESMTPS id x1
Received: from internal ([10.0.0.5]) by evil-relay.test with SMTP id y2
Content-Type: text/plain

Hi, kindly wire $48,000 to new vendor bank details immediately. Do not disclose. Verify account now at http://malicious-example.com/login`;

const CLEAN_SAMPLE = `From: Alice <alice@company.com>
To: bob@company.com
Subject: Lunch tomorrow?
Message-ID: <lunch1@company.com>
Return-Path: <alice@company.com>
Received: from mail.company.com (mail.company.com [93.184.216.34]) by mx.company.com with ESMTPS id z9
Content-Type: text/plain

Hi Bob, lunch tomorrow at noon? Let me know if cafeteria works.`;

/* ---------------- Dashboard ---------------- */

type EmailRow = {
  id: string;
  subject: string;
  sender_address: string;
  recipient_address?: string;
  timestamp: string;
};

export function Dashboard() {
  const [stats, setStats] = useState<any>(null);
  const [emails, setEmails] = useState<EmailRow[]>([]);
  const [scores, setScores] = useState<Record<string, { score: number; cls: string }>>({});
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');
  const [raw, setRaw] = useState('');
  const [busy, setBusy] = useState(false);
  const [q, setQ] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [notice, setNotice] = useState('');

  const load = async (query = q) => {
    setLoading(true);
    setErr('');
    try {
      const [s, list] = await Promise.all([jget('/dashboard'), jget(`/emails?limit=100${query ? `&q=${encodeURIComponent(query)}` : ''}`)]);
      setStats(s);
      setEmails(list);
      // fetch scores for the visible rows (detail endpoint carries analysis)
      const entries = await Promise.all(
        list.slice(0, 30).map(async (e: EmailRow) => {
          try {
            const d = await jget(`/emails/${e.id}`);
            return [e.id, { score: d.analysis?.fraud_score ?? 0, cls: d.analysis?.threat_classification ?? '—' }] as const;
          } catch {
            return [e.id, { score: 0, cls: '—' }] as const;
          }
        }),
      );
      setScores(Object.fromEntries(entries));
    } catch (e) {
      setErr(e instanceof ApiError ? `Backend error (${e.status}): ${e.message}` : String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load('');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submit = async () => {
    if (!raw.trim()) return;
    setBusy(true);
    setErr('');
    setNotice('');
    try {
      const r = await jpost('/emails/ingest', { raw });
      setNotice(`Analyzed — score ${r.fraud_score} (${r.classification}), action: ${r.action}`);
      setRaw('');
      await load();
    } catch (e) {
      setErr(e instanceof ApiError ? `Ingest failed (${e.status}): ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  const onFile = async (f: File | undefined) => {
    if (!f) return;
    setBusy(true);
    setErr('');
    try {
      const r = await uploadEmFile(f);
      setNotice(`Uploaded ${f.name} — score ${r.fraud_score} (${r.classification})`);
      await load();
    } catch (e) {
      setErr(e instanceof ApiError ? `Upload failed (${e.status}): ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  const filtered = useMemo(() => {
    if (sevFilter === 'all') return emails;
    return emails.filter((e) => {
      const s = scores[e.id]?.score ?? -1;
      if (sevFilter === 'critical') return s >= 90;
      if (sevFilter === 'high') return s >= 75 && s < 90;
      if (sevFilter === 'medium') return s >= 50 && s < 75;
      return s >= 0 && s < 50;
    });
  }, [emails, scores, sevFilter]);

  const dist = stats?.score_distribution ?? { critical: 0, high: 0, medium: 0, low: 0 };
  const distTotal = Math.max(1, dist.critical + dist.high + dist.medium + dist.low);

  return (
    <div className="page">
      <h1>Global Threat Dashboard</h1>
      <p className="sub">Real-time phishing, BEC and spoofing detection across ingested mail.</p>
      <Toast msg={err} />
      {notice && <Toast msg={notice} kind="info" />}

      {loading && !stats ? (
        <SkeletonList rows={4} />
      ) : (
        stats && (
          <>
            <div className="grid stats">
              <StatCard label="Emails processed" value={stats.total_emails} />
              <StatCard label="Blocked threats (≥75)" value={stats.blocked_threats} />
              <StatCard label="Active campaigns" value={stats.active_campaigns} caption="shared infrastructure clusters" />
              <StatCard label="Classifications" value={Object.keys(stats.by_classification || {}).length} caption={Object.entries(stats.by_classification || {}).slice(0, 3).map(([k, v]) => `${k}:${v}`).join(' · ') || '—'} />
            </div>
            <div className="card" style={{ marginBottom: 18 }}>
              <h3>Score distribution</h3>
              <div className="distbar">
                <div style={{ width: `${(100 * dist.critical) / distTotal}%`, background: '#ef4444' }} />
                <div style={{ width: `${(100 * dist.high) / distTotal}%`, background: '#f97316' }} />
                <div style={{ width: `${(100 * dist.medium) / distTotal}%`, background: '#eab308' }} />
                <div style={{ width: `${(100 * dist.low) / distTotal}%`, background: '#22c55e' }} />
              </div>
              <div className="legend">
                <span><span className="sev" style={{ background: '#ef4444' }} />Critical {dist.critical}</span>
                <span><span className="sev" style={{ background: '#f97316' }} />High {dist.high}</span>
                <span><span className="sev" style={{ background: '#eab308' }} />Medium {dist.medium}</span>
                <span><span className="sev" style={{ background: '#22c55e' }} />Low {dist.low}</span>
              </div>
            </div>
          </>
        )
      )}

      <div className="card" style={{ marginBottom: 18 }}>
        <h3>Ingest email for analysis</h3>
        <textarea rows={6} value={raw} onChange={(e) => setRaw(e.target.value)} placeholder="Paste raw RFC822 / .eml content here…" />
        <div className="row" style={{ marginTop: 10 }}>
          <button onClick={submit} disabled={busy || !raw.trim()}>{busy ? 'Analyzing…' : 'Analyze email'}</button>
          <button className="ghost" onClick={() => setRaw(PHISH_SAMPLE)}>Load phishing sample</button>
          <button className="ghost" onClick={() => setRaw(CLEAN_SAMPLE)}>Load clean sample</button>
          <label className="row" style={{ gap: 6 }}>
            <span style={{ color: 'var(--muted)', fontSize: 12 }}>or upload .eml</span>
            <input type="file" accept=".eml,.txt,.mime" onChange={(e) => onFile(e.target.files?.[0])} />
          </label>
        </div>
      </div>

      <div className="toolbar">
        <input type="search" placeholder="Search subject / sender / body…" value={q} onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') load(); }} />
        <button className="ghost" onClick={() => load()}>Search</button>
        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
          <option value="all">All severities</option>
          <option value="critical">Critical (90+)</option>
          <option value="high">High (75–89)</option>
          <option value="medium">Medium (50–74)</option>
          <option value="low">Low (&lt;50)</option>
        </select>
        <button className="ghost" onClick={() => load()}>Refresh</button>
      </div>

      {loading ? <SkeletonList /> : filtered.length === 0 ? <Empty msg="No emails match. Ingest one above to get started." /> : (
        <table className="tbl">
          <thead><tr><th>Score</th><th>Subject</th><th>Sender</th><th>Classification</th><th>Received</th><th>Reports</th></tr></thead>
          <tbody>
            {filtered.map((e) => {
              const s = scores[e.id];
              return (
                <tr key={e.id}>
                  <td>{s ? <ScoreBadge v={s.score} /> : <span style={{ color: 'var(--muted)' }}>…</span>}</td>
                  <td><a href={`#/email/${e.id}`}>{e.subject || '(no subject)'}</a></td>
                  <td><span className="mono">{e.sender_address}</span></td>
                  <td>{s?.cls ?? '—'}</td>
                  <td style={{ color: 'var(--muted)', fontSize: 12 }}>{e.timestamp ? new Date(e.timestamp).toLocaleString() : '—'}</td>
                  <td>
                    <button className="ghost small" onClick={() => downloadReport(e.id, 'pdf')}>PDF</button>{' '}
                    <button className="ghost small" onClick={() => downloadReport(e.id, 'json')}>JSON</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

/* ---------------- Graph SVG ---------------- */

function GraphSvg({ graph }: { graph: any }) {
  const nodes: any[] = graph?.nodes ?? [];
  const edges: any[] = graph?.edges ?? [];
  if (!nodes.length) return <Empty msg="No related entities yet — graph grows as more mail shares IPs/domains." />;
  const w = 640, h = 300;
  const pos = nodes.map((_, i) => ({
    x: 70 + (i * (w - 140)) / Math.max(1, nodes.length - 1),
    y: h / 2 + (i % 2 === 0 ? -62 : 62),
  }));
  const idx = new Map(nodes.map((n, i) => [n.id, i]));
  const color = (k: string) => (k === 'Domain' ? '#f97316' : k === 'IP_Address' ? '#ef4444' : k === 'Threat_Campaign' ? '#a78bfa' : '#22c55e');
  return (
    <svg width="100%" viewBox={`0 0 ${w} ${h}`} style={{ background: '#0a0f1f', borderRadius: 8, border: '1px solid var(--border)' }}>
      {edges.map((e, i) => {
        const a = pos[idx.get(e.source) ?? -1], b = pos[idx.get(e.target) ?? -1];
        return a && b ? (
          <g key={i}>
            <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#60a5fa" strokeWidth={1.5} />
            {e.rel && <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 4} fill="#93a1bd" fontSize={9} textAnchor="middle">{e.rel}</text>}
          </g>
        ) : null;
      })}
      {nodes.map((n, i) => (
        <g key={n.id}>
          <circle cx={pos[i].x} cy={pos[i].y} r={17} fill={color(n.kind)} />
          <text x={pos[i].x} y={pos[i].y + 4} fill="#060a14" fontSize={9} fontWeight={800} textAnchor="middle">{(n.kind || '?')[0]}</text>
          <text x={pos[i].x} y={pos[i].y + 32} fill="#e5e7eb" fontSize={10} textAnchor="middle">{String(n.id).slice(0, 26)}</text>
        </g>
      ))}
    </svg>
  );
}

/* ---------------- Email detail ---------------- */

const TABS = ['Summary', 'Why this score?', 'Header Forensics', 'GeoLocation', 'Graph View'] as const;

function ScoreWhy({ breakdown, score }: { breakdown: any[]; score: number }) {
  const rows = [...(breakdown || [])].sort(
    (x, y) => (y.contribution_to_score ?? 0) - (x.contribution_to_score ?? 0),
  );
  if (!rows.length) return <Empty msg="No score breakdown stored for this email (analyzed before explainability was added)." />;
  const maxAbs = Math.max(1, ...rows.map((r) => Math.abs(r.contribution_to_score ?? 0)));
  return (
    <div>
      <p className="sub">
        Each bar is a signal's point contribution to the final fraud score of <b>{score}</b> (weights × values ± rules).
      </p>
      {rows.map((s) => {
        const c = s.contribution_to_score ?? 0;
        const w = (100 * Math.abs(c)) / maxAbs;
        const bar = c > 0 ? '#ef4444' : c < 0 ? '#22c55e' : '#3b4a6b';
        return (
          <div key={s.signal_name} style={{ marginBottom: 12 }}>
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <span><code>{s.signal_name}</code> <span style={{ color: 'var(--muted)', fontSize: 12 }}>×{s.weight} · value {String(s.value)}</span></span>
              <b style={{ color: bar }}>{c > 0 ? `+${c}` : c}</b>
            </div>
            <div className="distbar" style={{ marginTop: 4 }}>
              <div style={{ width: `${w}%`, background: bar }} />
            </div>
            {s.detail && <div style={{ color: 'var(--muted)', fontSize: 12, marginTop: 2 }}>{s.detail}</div>}
          </div>
        );
      })}
    </div>
  );
}

export function EmailView({ id }: { id: string }) {
  const [d, setD] = useState<any>(null);
  const [tab, setTab] = useState(0);
  const [graph, setGraph] = useState<any>(null);
  const [err, setErr] = useState('');

  useEffect(() => {
    setErr('');
    setD(null);
    jget(`/emails/${id}`).then(setD).catch((e) => setErr(e instanceof ApiError ? `Could not load email (${e.status}): ${e.message}` : String(e)));
  }, [id]);

  useEffect(() => {
    if (d?.email?.sender_address) {
      jget(`/graph/related?value=${encodeURIComponent(d.email.sender_address)}`).then(setGraph).catch(() => {});
    }
  }, [d]);

  if (err) return <div className="page"><a href="#/">← back</a><Toast msg={err} /></div>;
  if (!d) return <div className="page"><a href="#/">← back</a><SkeletonList /></div>;
  const a = d.analysis || {};
  const t = d.trace || {};
  const auth = a.authentication_results || {};
  const relay: any[] = Array.isArray(t.relay_chain) ? t.relay_chain : [];

  return (
    <div className="page">
      <a href="#/">← back to dashboard</a>
      <h1 style={{ marginTop: 8 }}>{d.email.subject || '(no subject)'} <ScoreBadge v={a.fraud_score ?? 0} /></h1>
      <p className="sub">
        {a.threat_classification || 'Unclassified'} · action: <b>{a.action_taken || '—'}</b> ·{' '}
        <button className="ghost small" onClick={() => downloadReport(id, 'pdf')}>forensic PDF</button>{' '}
        <button className="ghost small" onClick={() => downloadReport(id, 'json')}>JSON</button>
      </p>

      <div className="tabs">
        {TABS.map((name, i) => (
          <button key={name} className={tab === i ? 'active' : ''} onClick={() => setTab(i)}>{name}</button>
        ))}
      </div>

      {tab === 0 && (
        <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' }}>
          <div className="card">
            <h3>Verdict</h3>
            <dl className="kv">
              <dt>Fraud score</dt><dd><ScoreBadge v={a.fraud_score ?? 0} /> {a.threat_classification}</dd>
              <dt>Action</dt><dd>{a.action_taken}</dd>
              <dt>Breakdown</dt><dd><span className="mono">{JSON.stringify(a.trace_summary ?? {})}</span></dd>
            </dl>
            <h3>Cues detected</h3>
            {(a.nlp_cues_detected || []).length === 0 ? <p className="sub">None</p> : (
              <div>{(a.nlp_cues_detected || []).map((c: string) => <span key={c} className="auth-pill auth-none">{c}</span>)}</div>
            )}
          </div>
          <div className="card">
            <h3>Authentication</h3>
            <div>
              <AuthPill name="SPF" status={auth.spf?.status} />
              <AuthPill name="DKIM" status={auth.dkim?.status} />
              <AuthPill name="DMARC" status={auth.dmarc?.status} />
            </div>
            <h3 style={{ marginTop: 12 }}>Threat intel hits ({(a.threat_intel_hits || []).length})</h3>
            {(a.threat_intel_hits || []).length === 0 ? <p className="sub">No hits</p> : (
              <table className="tbl">
                <thead><tr><th>Type</th><th>Value</th><th>Reason</th></tr></thead>
                <tbody>
                  {(a.threat_intel_hits || []).slice(0, 20).map((h: any, i: number) => (
                    <tr key={i}>
                      <td>{h.type}</td>
                      <td><span className="mono">{String(h.value ?? h.url ?? '').slice(0, 80)}</span></td>
                      <td style={{ fontSize: 12 }}>{(h.reasons || []).join(', ') || (h.blocklisted ? 'blocklisted' : 'hit')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
          <div className="card" style={{ gridColumn: '1 / -1' }}>
            <h3>Body (PII masked)</h3>
            <pre className="dump" style={{ whiteSpace: 'pre-wrap' }}>{d.email.body_text_masked || '(empty)'}</pre>
          </div>
        </div>
      )}

      {tab === 1 && (
        <div className="card">
          <h3>Why this score?</h3>
          <ScoreWhy breakdown={a.score_breakdown} score={a.fraud_score ?? 0} />
        </div>
      )}

      {tab === 2 && (
        <div className="card">
          <h3>Chain of custody</h3>
          <dl className="kv">
            <dt>SHA-256 (.eml)</dt><dd><span className="mono">{d.email.raw_eml_hash}</span></dd>
            <dt>Message-ID</dt><dd><span className="mono">{d.email.message_id || '—'}</span></dd>
            <dt>Relay hops</dt><dd>{relay.length}</dd>
          </dl>
          <h3>Relay path (origin first)</h3>
          {relay.length === 0 ? <Empty msg="No Received headers — sender path unverifiable." /> : (
            <ol className="timeline">
              {relay.map((h: any, i: number) => (
                <li key={i}>
                  <div><b>Hop {i + 1}</b> — from <span className="mono">{h.from_host || '?'}</span> by <span className="mono">{h.by_host || '?'}</span></div>
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>IPs: {(h.ips || []).map((ip: string) => <span key={ip} className="mono" style={{ marginRight: 4 }}>{ip}</span>)}
                    {(h.ips || []).length === 0 && 'none parsed'}</div>
                </li>
              ))}
            </ol>
          )}
          <h3>Raw chain</h3>
          <pre className="dump">{JSON.stringify(relay, null, 2)}</pre>
        </div>
      )}

      {tab === 3 && (
        <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' }}>
          <div className="card">
            <h3>Origin</h3>
            <dl className="kv">
              <dt>Origin IP</dt><dd><span className="mono">{t.origin_ip || '—'}</span></dd>
              <dt>VPN / TOR</dt><dd>{String(t.is_vpn_tor)}</dd>
              <dt>ISP / ASN</dt><dd>{t.isp_asn || '—'}</dd>
              <dt>Country / City</dt><dd>{t.geolocation ? `${t.geolocation.country || '?'} / ${t.geolocation.city || '?'}` : '—'} <span style={{ color: 'var(--muted)', fontSize: 12 }}>({t.geolocation?.source})</span></dd>
            </dl>
            <h3>WHOIS</h3>
            <pre className="dump">{JSON.stringify(t.whois, null, 2)}</pre>
            <h3>DNS</h3>
            <pre className="dump">{JSON.stringify(t.dns, null, 2)}</pre>
          </div>
          <div className="card">
            <h3>Map</h3>
            {t.geolocation?.lat ? (
              <>
                <iframe
                  title="geo"
                  width="100%"
                  height="380"
                  style={{ border: 0, borderRadius: 8 }}
                  src={`https://www.openstreetmap.org/export/embed.html?bbox=${t.geolocation.lon - 10}%2C${t.geolocation.lat - 10}%2C${t.geolocation.lon + 10}%2C${t.geolocation.lat + 10}&layer=mapnik&marker=${t.geolocation.lat}%2C${t.geolocation.lon}`}
                />
                <p><a target="_blank" rel="noreferrer" href={`https://www.openstreetmap.org/?mlat=${t.geolocation.lat}&mlon=${t.geolocation.lon}#map=5/${t.geolocation.lat}/${t.geolocation.lon}`}>Open full map</a></p>
              </>
            ) : <Empty msg="No coordinates — private, missing or unresolvable origin IP." />}
          </div>
        </div>
      )}

      {tab === 4 && (
        <div className="card">
          <h3>Identity correlation</h3>
          <GraphSvg graph={graph} />
          <h3 style={{ marginTop: 12 }}>Raw graph</h3>
          <pre className="dump">{JSON.stringify(graph, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}

/* ---------------- Cases ---------------- */

type CaseRow = { id: string; title: string; status: string; email_ids: string[]; notes?: string; created_at: string };

const COLS = [
  { key: 'Open', color: '#60a5fa' },
  { key: 'InProgress', color: '#eab308' },
  { key: 'Closed', color: '#22c55e' },
];

export function Cases() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'Admin';
  const [cases, setCases] = useState<CaseRow[]>([]);
  const [title, setTitle] = useState('');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    setErr('');
    try {
      setCases(await jget('/cases'));
    } catch (e) {
      setErr(e instanceof ApiError ? `Could not load cases (${e.status}): ${e.message}` : String(e));
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { load(); }, []);

  const create = async () => {
    if (!title.trim()) return;
    setErr('');
    try {
      await jpost('/cases', { title: title.trim() });
      setTitle('');
      await load();
    } catch (e) {
      setErr(e instanceof ApiError ? `Create failed (${e.status}): ${e.message}` : String(e));
    }
  };

  const move = async (id: string, status: string) => {
    try {
      await jpatch(`/cases/${id}`, { status });
      await load();
    } catch (e) {
      setErr(e instanceof ApiError ? `Update failed (${e.status}): ${e.message}` : String(e));
    }
  };

  const remove = async (id: string) => {
    if (!confirm('Delete this case?')) return;
    try {
      await jdel(`/cases/${id}`);
      await load();
    } catch (e) {
      setErr(e instanceof ApiError ? `Delete failed (${e.status}): ${e.message}` : String(e));
    }
  };

  return (
    <div className="page">
      <h1>Case Management</h1>
      <p className="sub">Track investigations from triage to closure.</p>
      <Toast msg={err} />
      <div className="row" style={{ marginBottom: 16 }}>
        <input type="text" style={{ maxWidth: 360 }} value={title} onChange={(e) => setTitle(e.target.value)}
          placeholder="New case title…" onKeyDown={(e) => { if (e.key === 'Enter') create(); }} />
        <button onClick={create}>Create case</button>
      </div>
      {loading ? <SkeletonList /> : (
        <div className="kanban">
          {COLS.map((c) => (
            <div key={c.key} className="kcol">
              <h3><span className="sev" style={{ background: severityColor(c.key === 'Open' ? 'high' : c.key === 'Closed' ? 'low' : 'medium') }} />{c.key} ({cases.filter((k) => k.status === c.key).length})</h3>
              {cases.filter((k) => k.status === c.key).map((k) => (
                <div key={k.id} className="kcard">
                  <b>{k.title}</b>
                  <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                    <span className="mono">{k.id.slice(0, 8)}</span> · {k.email_ids?.length ?? 0} email(s)
                  </div>
                  <div className="row" style={{ marginTop: 8 }}>
                    {COLS.filter((x) => x.key !== c.key).map((x) => (
                      <button key={x.key} className="ghost small" onClick={() => move(k.id, x.key)}>{x.key}</button>
                    ))}
                    {isAdmin && <button className="danger small" onClick={() => remove(k.id)}>Delete</button>}
                  </div>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
