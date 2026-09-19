import React, { useEffect, useState } from 'react';
import { jget, jpost } from './api';

function ScoreBadge({ v }: { v: number }) {
  const c = v >= 90 ? '#ef4444' : v >= 75 ? '#f97316' : v >= 50 ? '#eab308' : '#22c55e';
  return <span style={{ background: c, padding: '2px 10px', borderRadius: 12, color: '#000', fontWeight: 700 }}>{v}</span>;
}

export function Dashboard() {
  const [stats, setStats] = useState<any>(null);
  const [emails, setEmails] = useState<any[]>([]);
  const load = async () => {
    setStats(await jget('/dashboard'));
    setEmails(await jget('/emails?limit=50'));
  };
  useEffect(() => { load(); }, []);
  const [raw, setRaw] = useState('');
  const submit = async () => {
    await jpost('/emails/ingest', { raw });
    setRaw('');
    load();
  };
  return (
    <div style={{ padding: 20 }}>
      <h1>SOC Global Threat Dashboard</h1>
      {stats && (
        <div style={{ display: 'flex', gap: 16 }}>
          <div>Processed: <b>{stats.total_emails}</b></div>
          <div>Blocked (≥75): <b>{stats.blocked_threats}</b></div>
          <div>Campaigns: <b>{stats.active_campaigns}</b></div>
          <div>By class: <code>{JSON.stringify(stats.by_classification)}</code></div>
        </div>
      )}
      <h2>Ingest raw .eml / RFC822</h2>
      <textarea rows={6} cols={100} value={raw} onChange={e => setRaw(e.target.value)} placeholder="Paste raw email here" />
      <br /><button onClick={submit}>Analyze</button>
      <Upload onDone={load} />
      <h2>Recent emails</h2>
      <table border={1} cellPadding={6}>
        <thead><tr><th>ID</th><th>Subject</th><th>Sender</th><th>Open</th></tr></thead>
        <tbody>
          {emails.map(e => (
            <tr key={e.id}>
              <td><code>{e.id.slice(0, 8)}</code></td>
              <td>{e.subject}</td>
              <td><code>{e.sender_address}</code></td>
              <td><a href={`#/email/${e.id}`}>Forensics</a> | <a href={`/api/v1/reports/${e.id}.pdf`}>PDF</a> | <a href={`/api/v1/reports/${e.id}.json`}>JSON</a></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Upload({ onDone }: { onDone: () => void }) {
  const up = async (f: File | undefined) => {
    if (!f) return;
    await jpost('/emails/upload', null, f);
    onDone();
  };
  return <div style={{ marginTop: 8 }}><input type="file" onChange={e => up(e.target.files?.[0])} /> upload .eml</div>;
}

export function EmailView({ id }: { id: string }) {
  const [d, setD] = useState<any>(null);
  const [tab, setTab] = useState(0);
  const [graph, setGraph] = useState<any>(null);
  useEffect(() => { jget(`/emails/${id}`).then(setD); }, [id]);
  useEffect(() => {
    if (d?.email?.sender_address) {
      const v = encodeURIComponent(d.email.sender_address);
      jget(`/graph/related?value=${v}`).then(setGraph).catch(() => {});
    }
  }, [d]);
  if (!d) return <div style={{ padding: 20 }}>loading…</div>;
  const a = d.analysis || {};
  return (
    <div style={{ padding: 20 }}>
      <a href="#/">← back</a>
      <h2>{d.email.subject} <ScoreBadge v={a.fraud_score ?? 0} /> {a.threat_classification}</h2>
      <div>
        {['Summary', 'Header Forensics', 'GeoLocation', 'Graph View'].map((t, i) => (
          <button key={t} onClick={() => setTab(i)} style={{ marginRight: 8, fontWeight: tab === i ? 800 : 400 }}>{t}</button>
        ))}
      </div>
      {tab === 0 && (
        <div>
          <p>Action: <b>{a.action_taken}</b></p>
          <p>Cues: <code>{JSON.stringify(a.nlp_cues_detected)}</code></p>
          <p>Auth: <code>{JSON.stringify(a.authentication_results)}</code></p>
          <p>Intel hits: <code>{JSON.stringify(a.threat_intel_hits)}</code></p>
          <p>Body (masked):</p><pre style={{ whiteSpace: 'pre-wrap', background: '#111827', padding: 12 }}>{d.email.body_text_masked}</pre>
        </div>
      )}
      {tab === 1 && (
        <div>
          <p>Hash: <code style={{ fontFamily: 'monospace' }}>{d.email.raw_eml_hash}</code></p>
          <p>Hops: {d.trace?.relay_chain?.length ?? 0}</p>
          <pre style={{ background: '#111827', padding: 12 }}>{JSON.stringify(d.trace?.relay_chain, null, 2)}</pre>
        </div>
      )}
      {tab === 2 && (
        <div>
          <p>Origin IP: <code style={{ fontFamily: 'monospace' }}>{d.trace?.origin_ip}</code> VPN/TOR: {String(d.trace?.is_vpn_tor)}</p>
          <p>Geo: <code>{JSON.stringify(d.trace?.geolocation)}</code></p>
          <p>WHOIS: <code>{JSON.stringify(d.trace?.whois)}</code></p>
          <p>DNS: <code>{JSON.stringify(d.trace?.dns)}</code></p>
          {d.trace?.geolocation?.lat ? (
            <a target="_blank" href={`https://www.openstreetmap.org/?mlat=${d.trace.geolocation.lat}&mlon=${d.trace.geolocation.lon}#map=5/${d.trace.geolocation.lat}/${d.trace.geolocation.lon}`}>Open map (OSM)</a>
          ) : null}
        </div>
      )}
      {tab === 3 && <pre style={{ background: '#111827', padding: 12 }}>{JSON.stringify(graph, null, 2)}</pre>}
    </div>
  );
}

export function Cases() {
  const [cases, setCases] = useState<any[]>([]);
  const [title, setTitle] = useState('');
  const load = async () => setCases(await jget('/cases'));
  useEffect(() => { load(); }, []);
  const create = async () => {
    const r = await fetch('/api/v1/cases', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title }) });
    if (r.ok) { setTitle(''); load(); }
  };
  const setStatus = async (id: string, status: string) => {
    await fetch(`/api/v1/cases/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status }) });
    load();
  };
  const cols = ['Open', 'InProgress', 'Closed'];
  return (
    <div style={{ padding: 20 }}>
      <h1>Case Management</h1>
      <input value={title} onChange={e => setTitle(e.target.value)} placeholder="New case title" />
      <button onClick={create}>Create</button>
      <div style={{ display: 'flex', gap: 16 }}>
        {cols.map(c => (
          <div key={c} style={{ flex: 1, background: '#111827', padding: 12, borderRadius: 8 }}>
            <h3>{c}</h3>
            {cases.filter(k => k.status === c).map(k => (
              <div key={k.id} style={{ background: '#1f2937', margin: 6, padding: 8, borderRadius: 6 }}>
                <b>{k.title}</b><br /><code>{k.id.slice(0, 8)}</code> emails:{k.email_ids?.length ?? 0}
                <div>{cols.filter(x => x !== c).map(x => <button key={x} onClick={() => setStatus(k.id, x)}>{x}</button>)}</div>
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
