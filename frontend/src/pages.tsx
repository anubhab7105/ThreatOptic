import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { ApiError, downloadReport, jdel, jget, jpatch, jpost, pollTask, uploadEmFile } from './api';
import { useAuth } from './auth';
import { AuthPill, Empty, ScoreBadge, SkeletonList, StatCard, Toast, severityColor } from './components';

export function formatDateTime(ts: string | null | undefined): string {
  if (!ts) return '—';
  const iso = ts.endsWith('Z') || /[+-]\d{2}(:\d{2})?$/.test(ts) ? ts : ts + 'Z';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
}

/* ---------- SEO helpers (custom domain: socforensics.io) ---------- */
const CANONICAL_BASE = 'https://socforensics.io';
/** Serialize for <script> injection: escape `</` so a crafted subject can
 * never break out of the script tag (C14 stored-XSS). `<\/` is valid JSON
 * and parses to the identical string. */
function safeJsonLd(obj: unknown): string {
  return JSON.stringify(obj).replace(/<\//g, '<\\/');
}
function setCanonical(path: string) {
  // History-API routes are real URLs: the canonical is the clean path itself.
  const clean = path.split(/[?#]/)[0] || '/';
  const href = `${CANONICAL_BASE}${clean.startsWith('/') ? clean : `/${clean}`}`;
  let el = document.querySelector<HTMLLinkElement>('link[rel="canonical"]');
  if (!el) { el = document.createElement('link'); el.rel = 'canonical'; document.head.appendChild(el); }
  el.href = href;
}
function setMeta(name: string, content: string) {
  let el = document.querySelector<HTMLMetaElement>(`meta[name="${name}"]`);
  if (!el) { el = document.createElement('meta'); el.name = name; document.head.appendChild(el); }
  el.content = content;
}
function setOG(prop: string, content: string) {
  let el = document.querySelector<HTMLMetaElement>(`meta[property="${prop}"]`);
  if (!el) { el = document.createElement('meta'); el.setAttribute('property', prop); document.head.appendChild(el); }
  el.content = content;
}
function usePageMeta(opts: { title: string; description: string; canonical: string; image?: string }) {
  useEffect(() => {
    document.title = opts.title;
    setMeta('description', opts.description);
    setCanonical(opts.canonical);
    setOG('og:title', opts.title);
    setOG('og:description', opts.description);
    setOG('og:url', `${CANONICAL_BASE}${opts.canonical}`);
    if (opts.image) setOG('og:image', opts.image);
    // twitter
    setMeta('twitter:title', opts.title);
    setMeta('twitter:description', opts.description);
  }, [opts.title, opts.description, opts.canonical, opts.image]);
}

function Breadcrumb({ items }: { items: { label: string; href?: string }[] }) {
  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: items.map((it, i) => ({
      '@type': 'ListItem',
      position: i + 1,
      name: it.label,
      item: it.href ? `${CANONICAL_BASE}/${it.href.replace(/^\//, '')}` : undefined,
    })),
  };
  return (
    <>
      <nav aria-label="Breadcrumb" className="breadcrumb">
        <ol>
          {items.map((it, i) => (
            <li key={i}>
              {it.href ? <Link to={it.href}>{it.label}</Link> : <span aria-current="page">{it.label}</span>}
              {i < items.length - 1 ? <span className="sep" aria-hidden="true"> › </span> : null}
            </li>
          ))}
        </ol>
      </nav>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd(jsonLd) }} />
    </>
  );
}

function InternalLinks({ current }: { current: string }) {
  const links = [
    { href: '/', label: 'Dashboard', desc: 'Threat overview' },
    { href: '/campaigns', label: 'Campaigns', desc: 'Infrastructure clusters' },
    { href: '/cases', label: 'Cases', desc: 'Kanban investigation' },
    { href: '/mailboxes', label: 'Mailboxes', desc: 'OAuth connectors' },
    { href: '/model', label: 'Model Info', desc: 'Transparency & metrics' },
  ].filter(l => l.href !== current);
  return (
    <div className="card" style={{ marginTop: 18 }}>
      <h3>Explore the platform</h3>
      <div className="row" style={{ gap: 12, flexWrap: 'wrap' }}>
        {links.slice(0, 4).map(l => (
          <Link key={l.href} to={l.href} className="ghost" style={{ padding: '8px 12px', border: '1px solid var(--border)', borderRadius: 8, background: 'var(--panel-2)', textDecoration: 'none' }}>
            <b>{l.label}</b> <span style={{ color: 'var(--muted)', fontWeight: 400 }}>- {l.desc}</span>
          </Link>
        ))}
      </div>
      <div style={{ marginTop: 10, fontSize: 12, color: 'var(--muted)' }}>
        Also: <a href="/sitemap.xml">Sitemap</a> · <a href="/robots.txt">Robots</a> · <a href="/llms.txt">LLMs</a> · <a href="https://socforensics.io/">socforensics.io</a>
      </div>
    </div>
  );
}

/* ---------------- Login ---------------- */

export function LoginPage() {
  usePageMeta({
    title: 'Sign In - SOC Forensics Lab | Secure Analyst Access',
    description: 'JWT-secured sign in for SOC analysts. Access the email threat dashboard with forensic intelligence, geolocation and chain-of-custody reporting.',
    canonical: '/login',
    image: 'https://socforensics.io/og-image.svg',
  });
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
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Sign In' }]} />
      <h1>SOC Sign in</h1>
      <p className="sub">JWT-secured access to the forensic intelligence platform.</p>
      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 14 }}>
        <img src="/favicon.svg" alt="SOC Forensics Lab shield logo - secure access" width={72} height={72} loading="eager" />
      </div>
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
            ? 'New accounts join as ReadOnly; an Analyst seat can be requested after signup.'
            : import.meta.env.DEV
              ? 'Demo seed: admin / admin123, analyst / analyst123.'
              : 'Use your provisioned analyst credentials.'}
        </p>
      </div>
      <InternalLinks current="/" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Sign In - SOC Forensics Lab',
        description: 'Secure analyst sign-in for the forensic intelligence platform',
        url: `${CANONICAL_BASE}/login`, isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
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

/* ---------------- Gmail live import ---------------- */

function GmailPanel({ onSynced }: { onSynced: () => void }) {
  const [status, setStatus] = useState<any>(null);
  const [clientId, setClientId] = useState(() => localStorage.getItem('gmail_client_id') || '');
  const [redirectUri, setRedirectUri] = useState(
    typeof window !== 'undefined' ? `${window.location.origin}/` : 'https://socforensics.io/',
  );
  const [code, setCode] = useState('');
  const [secret, setSecret] = useState(() => localStorage.getItem('gmail_client_secret') || '');
  const [query, setQuery] = useState('is:unread');
  const [maxN, setMaxN] = useState('10');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [notice, setNotice] = useState('');
  const [showCreds, setShowCreds] = useState(false);

  // Persist credentials in localStorage so they survive page refreshes
  const updateClientId = (v: string) => { setClientId(v); localStorage.setItem('gmail_client_id', v); };
  const updateSecret = (v: string) => { setSecret(v); localStorage.setItem('gmail_client_secret', v); };

  const refresh = async () => {
    try {
      setStatus(await jget('/gmail/status'));
    } catch (e) {
      setErr(e instanceof ApiError ? `Gmail status failed (${e.status}): ${e.message}` : String(e));
    }
  };
  useEffect(() => { void refresh(); }, []);

  const fail = (e: unknown, what: string) =>
    setErr(e instanceof ApiError ? `${what} failed (${e.status}): ${e.message}` : String(e));

  const getUrl = async () => {
    setBusy(true); setErr(''); setNotice('');
    try {
      let url = `/gmail/auth-url?redirect_uri=${encodeURIComponent(redirectUri)}`;
      if (clientId.trim()) url += `&client_id=${encodeURIComponent(clientId.trim())}`;
      if (secret.trim()) url += `&client_secret=${encodeURIComponent(secret.trim())}`;
      const r = await jget(url);
      window.location.href = r.auth_url;
      setNotice('Redirecting to Google consent page…');
    } catch (e) { fail(e, 'Consent URL'); } finally { setBusy(false); }
  };

  const finish = async (manualCode?: string) => {
    const c = (manualCode ?? code).trim();
    if (!c) return;
    setBusy(true); setErr(''); setNotice('');
    try {
      // Client secret is server-side only (C5) — never sent from the browser.
      const r = await jpost('/gmail/callback', { code: c, redirect_uri: redirectUri, client_id: clientId || undefined });
      setStatus(r);
      setCode('');
      setNotice(`Connected as ${r.gmail_address}. Credentials saved securely on the server.`);
    } catch (e) { fail(e, 'Connection'); } finally { setBusy(false); }
  };

  const autoTried = useRef(false);
  useEffect(() => {
    if (autoTried.current) return;
    autoTried.current = true;
    const q = new URLSearchParams(window.location.search).get('code');
    if (q) {
      setCode(q);
      window.history.replaceState({}, '', window.location.pathname);
      void finish(q);
    }
    const hashParams = new URLSearchParams(window.location.hash.includes('?') ? window.location.hash.split('?')[1] : '');
    const conn = hashParams.get('connected') || new URLSearchParams(window.location.search).get('connected');
    if (conn && conn.startsWith('google:')) {
      const addr = conn.replace('google:', '');
      setNotice(`Successfully connected as ${addr}!`);
      void refresh();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const sync = async () => {
    setBusy(true); setErr(''); setNotice('Syncing emails & running ML threat detection pipeline…');
    try {
      const num = Math.max(1, parseInt(maxN, 10) || 10);
      const r = await jpost('/gmail/sync', { max_results: num, query, client_id: clientId || undefined, client_secret: secret || undefined });
      setNotice(`Synced ${r.synced} email(s) through the pipeline${r.errors?.length ? `, ${r.errors.length} error(s)` : ''}.`);
      await refresh();
      await onSynced();
      window.dispatchEvent(new CustomEvent('soc:emails-updated'));
    } catch (e) { fail(e, 'Sync'); } finally { setBusy(false); }
  };

  const disconnect = async () => {
    if (!confirm('Disconnect this Gmail mailbox?')) return;
    try {
      await jdel('/gmail/disconnect');
      await refresh();
      await onSynced();
      window.dispatchEvent(new CustomEvent('soc:emails-updated'));
    } catch (e) { fail(e, 'Disconnect'); }
  };

  return (
    <div className="card" style={{ marginBottom: 18 }}>
      <h3>Gmail live import (OAuth2, read-only)</h3>
      <Toast msg={err} />
      {notice && <Toast msg={notice} kind="info" />}
      {status?.connected ? (
        <div>
          <p>Connected as <b>{status.gmail_address}</b>
            {status.last_sync_at ? <span style={{ color: 'var(--muted)' }}> · last sync {formatDateTime(status.last_sync_at)}</span> : null}
          </p>
          <div className="row">
            <input type="text" style={{ maxWidth: 200 }} value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Gmail query" title="Gmail search query" />
            <input type="number" min="1" style={{ maxWidth: 110 }} value={maxN} onChange={(e) => setMaxN(e.target.value)} placeholder="Count" title="Max emails to sync (any number)" />
            <button onClick={sync} disabled={busy}>{busy ? 'Syncing…' : 'Sync now'}</button>
            <button className="ghost" onClick={disconnect}>Disconnect</button>
            <button className="ghost small" onClick={() => setShowCreds(!showCreds)} title="Show/hide OAuth credentials">{showCreds ? '▲ Hide credentials' : '▼ Change credentials'}</button>
          </div>
          {showCreds && (
            <div className="grid" style={{ gap: 8, maxWidth: 560, marginTop: 10 }}>
              <input type="text" value={clientId} onChange={(e) => updateClientId(e.target.value)} placeholder="Google OAuth client ID" />
              <input type="password" value={secret} onChange={(e) => updateSecret(e.target.value)} placeholder="Client secret" autoComplete="off" />
              <p className="sub" style={{ marginBottom: 0, fontSize: 12 }}>Credentials are stored encrypted on the server per connection. Update here to use different credentials for the next sync.</p>
            </div>
          )}
        </div>
      ) : (
        <div>
          <p className="sub" style={{ marginTop: 0 }}>
            1. Create a Google Cloud OAuth client (Web, redirect URI below) with the Gmail API enabled. 2. Enter your Client ID and Secret below.
            3. Open the consent URL and approve. Google redirects back here and the connection finishes automatically. Credentials are encrypted and stored on the server.
          </p>
          <div className="grid" style={{ gap: 8, maxWidth: 560 }}>
            <input type="text" value={clientId} onChange={(e) => updateClientId(e.target.value)} placeholder="Google OAuth client ID (*.apps.googleusercontent.com)" />
            <input type="password" value={secret} onChange={(e) => updateSecret(e.target.value)} placeholder="Client secret (from Google Cloud Console)" autoComplete="off" />
            <input type="text" value={redirectUri} onChange={(e) => setRedirectUri(e.target.value)} placeholder="Redirect URI (must match Google console)" />
            <div className="row">
              <button className="ghost" onClick={getUrl} disabled={busy || !clientId.trim() || !redirectUri.trim()}>Connect Gmail</button>
            </div>
            <div className="row">
              <button onClick={() => finish()} disabled={busy || !code.trim()}>Finish connection</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ---------------- Dashboard ---------------- */

type EmailRow = {
  id: string;
  subject: string;
  sender_address: string;
  recipient_address?: string;
  timestamp: string;
  fraud_score?: number | null;
  threat_classification?: string | null;
};

export function Dashboard() {
  usePageMeta({
    title: 'Global Threat Dashboard - SOC Forensics Lab | Real-Time Email Threats',
    description: 'Real-time phishing, BEC and spoofing detection across ingested mail. Analyze emails, view fraud scores, track campaigns and export chain-of-custody reports.',
    canonical: '/',
    image: 'https://socforensics.io/og-image.svg',
  });
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
  const [asyncMode, setAsyncMode] = useState(false);

  const triggerDownload = async (id: string, kind: 'pdf' | 'json') => {
    try {
      await downloadReport(id, kind);
    } catch (e) {
      setErr(`Failed to download ${kind.toUpperCase()} report: ${e instanceof ApiError ? e.message : String(e)}`);
    }
  };

  const load = async (query = q, silent = false) => {
    if (!silent) setLoading(true);
    setErr('');
    try {
      const [s, list] = await Promise.all([
        jget('/dashboard'),
        jget(`/emails?limit=100${query ? `&q=${encodeURIComponent(query)}` : ''}`),
      ]);
      setStats(s);
      setEmails(list);
      // Scores and classification are included directly from the batch endpoint
      const scoreMap: Record<string, { score: number; cls: string }> = {};
      for (const e of list) {
        scoreMap[e.id] = {
          score: e.fraud_score ?? 0,
          cls: e.threat_classification ?? '—',
        };
      }
      setScores(scoreMap);
    } catch (e) {
      if (!silent) setErr(e instanceof ApiError ? `Backend error (${e.status}): ${e.message}` : String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load('', false);
    const onUpdate = () => { void load(q, true); };
    window.addEventListener('soc:emails-updated', onUpdate);
    const timer = setInterval(() => { void load(q, true); }, 6000);
    return () => {
      window.removeEventListener('soc:emails-updated', onUpdate);
      clearInterval(timer);
    };
  }, [q]);

  const submit = async () => {
    if (!raw.trim()) return;
    setBusy(true);
    setErr('');
    setNotice('');
    try {
      if (asyncMode) {
        // Celery path (Phase 3 item 10): queue, then poll the task id.
        const q = await jpost(`/emails/ingest?async_mode=true`, { raw });
        setNotice(`Queued background task ${q.task_id} — polling for the verdict…`);
        const r = await pollTask(q.task_id);
        setNotice(`Analyzed (background) - score ${r.fraud_score} (${r.classification}), action: ${r.action}`);
      } else {
        const r = await jpost('/emails/ingest', { raw });
        setNotice(`Analyzed - score ${r.fraud_score} (${r.classification}), action: ${r.action}`);
      }
      setRaw('');
      await load(q, false);
      window.dispatchEvent(new CustomEvent('soc:emails-updated'));
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
      setNotice(`Uploaded ${f.name} - score ${r.fraud_score} (${r.classification})`);
      await load(q, false);
      window.dispatchEvent(new CustomEvent('soc:emails-updated'));
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
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Threat Dashboard' }]} />
      <h1>Global Threat Dashboard</h1>
      <p className="sub">Real-time phishing, BEC and spoofing detection across ingested mail.</p>

      <div className="card" style={{ marginBottom: 16, display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
        <img src="/og-image.svg" alt="SOC Forensics Lab dashboard hero - email threat detection map and shield emblem" width={320} height={168} style={{ borderRadius: 8, border: '1px solid var(--border)', maxWidth: '100%', height: 'auto' }} loading="lazy" />
        <div style={{ flex: 1, minWidth: 240 }}>
          <h3 style={{ marginTop: 0 }}>Headers, scores, and locations in one view</h3>
          <p className="sub" style={{ marginBottom: 8 }}>Paste RFC822, upload .eml, or sync Gmail. Each message gets a 0-100 fraud score, SPF/DKIM/DMARC checks, VirusTotal and blocklist lookups, and an origin map with SHA-256 custody hash.</p>
          <div className="row">
            <Link to="/campaigns">View Campaigns →</Link>
            <span style={{ color: 'var(--muted)' }}>·</span>
            <Link to="/cases">Open Cases →</Link>
            <span style={{ color: 'var(--muted)' }}>·</span>
            <Link to="/model">Model Transparency →</Link>
          </div>
        </div>
      </div>

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
              <StatCard label="Classifications" value={Object.keys(stats.by_classification || {}).length} caption={Object.entries(stats.by_classification || {}).slice(0, 3).map(([k, v]) => `${k}:${v}`).join(' · ') || '-'} />
            </div>
            <div className="card" style={{ marginBottom: 18 }}>
              <h3>Score distribution</h3>
              <div className="distbar" role="img" aria-label={`Score distribution: Critical ${dist.critical}, High ${dist.high}, Medium ${dist.medium}, Low ${dist.low}`}>
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
          <label className="row" style={{ gap: 6, fontSize: 12, color: 'var(--muted)' }} title="Queue via Celery worker instead of inline analysis">
            <input type="checkbox" checked={asyncMode} onChange={(e) => setAsyncMode(e.target.checked)} /> background queue
          </label>
          <button className="ghost" onClick={() => setRaw(PHISH_SAMPLE)}>Load phishing sample</button>
          <button className="ghost" onClick={() => setRaw(CLEAN_SAMPLE)}>Load clean sample</button>
          <label className="row" style={{ gap: 6 }}>
            <span style={{ color: 'var(--muted)', fontSize: 12 }}>or upload .eml</span>
            <input type="file" accept=".eml,.txt,.mime" onChange={(e) => onFile(e.target.files?.[0])} />
          </label>
        </div>
      </div>

      <GmailPanel onSynced={() => load()} />

      <div className="toolbar">
        <input type="search" placeholder="Search subject / sender / body…" value={q} onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') void load(); }} />
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
                  <td><Link to={`/email/${e.id}`}>{e.subject || '(no subject)'}</Link></td>
                  <td><span className="mono">{e.sender_address}</span></td>
                  <td>{s?.cls ?? '—'}</td>
                  <td style={{ color: 'var(--muted)', fontSize: 12 }}>{formatDateTime(e.timestamp)}</td>
                  <td>
                    <button className="ghost small" onClick={() => triggerDownload(e.id, 'pdf')}>PDF</button>{' '}
                    <button className="ghost small" onClick={() => triggerDownload(e.id, 'json')}>JSON</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      <InternalLinks current="/" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Global Threat Dashboard - SOC Forensics Lab',
        description: 'Real-time phishing and BEC detection dashboard', url: `${CANONICAL_BASE}/`,
        isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
    </div>
  );
}

/* ---------------- Graph SVG ---------------- */

export function GraphSvg({ graph }: { graph: any }) {
  const nodes: any[] = graph?.nodes ?? [];
  const edges: any[] = graph?.edges ?? [];
  if (!nodes.length) return <Empty msg="No related entities yet - graph grows as more mail shares IPs/domains." />;
  const w = 700, h = 340;
  const cx = w / 2, cy = h / 2;

  // Degree calculation to find focal / center node
  const degreeMap = new Map<string, number>();
  edges.forEach((e) => {
    degreeMap.set(e.source, (degreeMap.get(e.source) || 0) + 1);
    degreeMap.set(e.target, (degreeMap.get(e.target) || 0) + 1);
  });

  // Pick central node if one has high connectivity
  let centerId: string | null = null;
  if (nodes.length >= 3) {
    const sorted = [...nodes].sort((a, b) => (degreeMap.get(b.id) || 0) - (degreeMap.get(a.id) || 0));
    if ((degreeMap.get(sorted[0].id) || 0) >= 2) {
      centerId = sorted[0].id;
    }
  }

  const otherNodes = centerId ? nodes.filter((n) => n.id !== centerId) : nodes;
  const radius = Math.min(w, h) * 0.36;

  const posMap = new Map<string, { x: number; y: number }>();
  if (centerId) {
    posMap.set(centerId, { x: cx, y: cy });
    otherNodes.forEach((n, i) => {
      const angle = (i / otherNodes.length) * 2 * Math.PI - Math.PI / 2;
      posMap.set(n.id, {
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      });
    });
  } else if (nodes.length === 1) {
    posMap.set(nodes[0].id, { x: cx, y: cy });
  } else if (nodes.length === 2) {
    posMap.set(nodes[0].id, { x: cx - 130, y: cy });
    posMap.set(nodes[1].id, { x: cx + 130, y: cy });
  } else {
    nodes.forEach((n, i) => {
      const angle = (i / nodes.length) * 2 * Math.PI - Math.PI / 2;
      posMap.set(n.id, {
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      });
    });
  }

  const color = (k: string) => (k === 'Domain' ? '#f97316' : k === 'IP_Address' ? '#ef4444' : k === 'Threat_Campaign' ? '#38bdf8' : '#22c55e');
  const label = (id: string) => String(id).replace(/^(email|ip|domain|campaign):/, '');

  return (
    <svg width="100%" viewBox={`0 0 ${w} ${h}`} role="img" aria-label="Identity correlation graph showing sender infrastructure relationships" style={{ background: '#0a0f1f', borderRadius: 8, border: '1px solid var(--border)' }}>
      <title>Attribution graph</title>
      <desc>Nodes represent domains, IPs and campaigns linked by shared infrastructure</desc>
      <defs>
        <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
          <feDropShadow dx="0" dy="0" stdDeviation="3" floodColor="#38bdf8" floodOpacity="0.3" />
        </filter>
      </defs>
      {edges.map((e, i) => {
        const a = posMap.get(e.source), b = posMap.get(e.target);
        if (!a || !b) return null;
        const mx = (a.x + b.x) / 2;
        const my = (a.y + b.y) / 2;
        return (
          <g key={i}>
            <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#3b82f6" strokeWidth={2} strokeOpacity={0.7} />
            {e.rel && (
              <g transform={`translate(${mx}, ${my})`}>
                <rect x={-e.rel.length * 3.2 - 4} y={-8} width={e.rel.length * 6.4 + 8} height={14} rx={4} fill="#0d1528" stroke="var(--border)" strokeWidth={0.8} />
                <text x={0} y={2.5} fill="#93a1bd" fontSize={8} fontWeight={700} textAnchor="middle">{e.rel}</text>
              </g>
            )}
          </g>
        );
      })}
      {nodes.map((n) => {
        const p = posMap.get(n.id) || { x: cx, y: cy };
        const lbl = label(n.id);
        const isCenter = n.id === centerId;
        const r = isCenter ? 22 : 18;
        return (
          <g key={n.id} style={{ cursor: 'pointer' }}>
            <title>{`${n.kind || 'Entity'}: ${lbl}`}</title>
            <circle cx={p.x} cy={p.y} r={r} fill={color(n.kind)} stroke="#0f172a" strokeWidth={2.5} filter="url(#glow)" />
            <text x={p.x} y={p.y + 4} fill="#060a14" fontSize={isCenter ? 11 : 9} fontWeight={900} textAnchor="middle">
              {(n.kind || '?')[0]}
            </text>
            <text x={p.x} y={p.y + (isCenter ? 36 : 30)} fill="#e5e7eb" fontSize={11} fontWeight={600} textAnchor="middle" style={{ textShadow: '0 1px 4px rgba(0,0,0,0.8)' }}>
              {lbl.length > 24 ? lbl.slice(0, 22) + '…' : lbl}
            </text>
            <text x={p.x} y={p.y + (isCenter ? 48 : 42)} fill="#93a1bd" fontSize={9} textAnchor="middle">
              {n.kind || ''}
            </text>
          </g>
        );
      })}
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
  const [cases, setCases] = useState<any[]>([]);
  const [caseId, setCaseId] = useState('');
  const [caseNotice, setCaseNotice] = useState('');

  const triggerDownload = async (kind: 'pdf' | 'json') => {
    try {
      await downloadReport(id, kind);
    } catch (e) {
      setErr(`Failed to download ${kind.toUpperCase()} report: ${e instanceof ApiError ? e.message : String(e)}`);
    }
  };

  const subject = d?.email?.subject || '(no subject)';
  const fraudScore = d?.analysis?.fraud_score ?? 0;
  usePageMeta({
    title: d ? `${subject} - Score ${fraudScore} - SOC Forensics Lab` : `Email Forensics - SOC Forensics Lab`,
    description: d ? `Forensic analysis for "${subject}" - classification ${d.analysis?.threat_classification || 'unknown'}, action ${d.analysis?.action_taken || '-'}, authentication and geolocation trace.` : 'Email forensic detail with header chain, geolocation and identity graph.',
    canonical: `/email/${id}`,
    image: 'https://socforensics.io/og-image.svg',
  });

  useEffect(() => {
    setErr('');
    setD(null);
    let cancelled = false;
    jget(`/emails/${id}`).then((v) => { if (!cancelled) setD(v); }).catch((e) => { if (!cancelled) setErr(e instanceof ApiError ? `Could not load email (${e.status}): ${e.message}` : String(e)); });
    jget('/cases').then((v) => { if (!cancelled) setCases(v); }).catch(() => {});
    return () => { cancelled = true; };
  }, [id]);

  const linkToCase = async () => {
    if (!caseId) return;
    try {
      const targetCase = cases.find((c: any) => c.id === caseId);
      const existing = targetCase?.email_ids || [];
      if (!existing.includes(id)) {
        await jpatch(`/cases/${caseId}`, { email_ids: [...existing, id] });
      }
      setCaseNotice(`Linked to case: ${targetCase?.title || caseId}`);
      setTimeout(() => setCaseNotice(''), 4000);
    } catch (e) {
      setErr(`Failed to link case: ${e instanceof ApiError ? e.message : String(e)}`);
    }
  };

  useEffect(() => {
    if (d?.email) {
      const val = d.email.sender_address || d.email.id;
      jget(`/graph/related?value=${encodeURIComponent(val)}&email_id=${encodeURIComponent(d.email.id || id || '')}`)
        .then(setGraph)
        .catch(() => { /* non-fatal */ });
    }
  }, [d, id]);

  if (err) return <div className="page"><Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Email', href: '/' }, { label: 'Error' }]} /><Link to="/">← back</Link><Toast msg={err} /></div>;
  if (!d) return <div className="page"><Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Email' }]} /><Link to="/">← back</Link><SkeletonList /></div>;
  const a = d.analysis || {};
  const t = d.trace || {};
  const auth = a.authentication_results || {};
  const relay: any[] = Array.isArray(t.relay_chain) ? t.relay_chain : [];

  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Dashboard', href: '/' }, { label: subject.slice(0, 36) || 'Email Detail' }]} />
      <Link to="/">← back to dashboard</Link>
      <h1 style={{ marginTop: 8 }}>{d.email.subject || '(no subject)'} <ScoreBadge v={a.fraud_score ?? 0} /></h1>
      <p className="sub">
        {a.threat_classification || 'Unclassified'} · action: <b>{a.action_taken || '—'}</b> ·{' '}
        received: <b>{formatDateTime(d.email.timestamp)}</b> ·{' '}
        <button className="ghost small" onClick={() => triggerDownload('pdf')}>forensic PDF</button>{' '}
        <button className="ghost small" onClick={() => triggerDownload('json')}>JSON</button>
      </p>

      {cases.length > 0 && (
        <div className="row" style={{ marginTop: 8, marginBottom: 12, alignItems: 'center' }}>
          <span style={{ fontSize: 13, color: 'var(--muted)' }}>Investigate:</span>
          <select value={caseId} onChange={(e) => setCaseId(e.target.value)} style={{ maxWidth: 260, fontSize: 12 }}>
            <option value="">Select an investigation case…</option>
            {cases.map((c: any) => (
              <option key={c.id} value={c.id}>{c.title} ({c.status})</option>
            ))}
          </select>
          <button className="ghost small" onClick={linkToCase} disabled={!caseId}>Link to Case</button>
          {caseNotice && <span style={{ color: 'var(--green)', fontSize: 12 }}>✓ {caseNotice}</span>}
        </div>
      )}

      <div className="tabs">
        {TABS.map((name, i) => (
          <button key={name} role="tab" aria-selected={tab === i} className={tab === i ? 'active' : ''} onClick={() => setTab(i)}>{name}</button>
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
            <img src="/favicon.svg" alt="Forensic shield watermark - verdict authenticity indicator" width={48} height={48} style={{ marginTop: 12, opacity: 0.9 }} loading="lazy" />
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
            <dt>Message-ID</dt><dd><span className="mono">{d.email.message_id || '-'}</span></dd>
            <dt>Relay hops</dt><dd>{relay.length}</dd>
          </dl>
          <h3>Relay path (origin first)</h3>
          {relay.length === 0 ? <Empty msg="No Received headers - sender path unverifiable." /> : (
            <ol className="timeline">
              {relay.map((h: any, i: number) => (
                <li key={i}>
                  <div><b>Hop {i + 1}</b> - from <span className="mono">{h.from_host || '?'}</span> by <span className="mono">{h.by_host || '?'}</span></div>
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
            <h3>Origin & Infrastructure</h3>
            <dl className="kv">
              <dt>Origin IP</dt>
              <dd>
                <span className="mono">{t.origin_ip || '-'}</span>
                {t.geolocation?.is_private && (
                  <span className="badge" style={{ marginLeft: 6, fontSize: 11, background: 'var(--muted)', color: '#fff', padding: '2px 6px', borderRadius: 4 }}>
                    Private RFC1918
                  </span>
                )}
              </dd>
              <dt>Coordinates</dt>
              <dd className="mono">
                {t.geolocation?.lat != null && t.geolocation?.lon != null
                  ? `${Number(t.geolocation.lat).toFixed(4)}, ${Number(t.geolocation.lon).toFixed(4)}`
                  : '-'}
              </dd>
              <dt>VPN / TOR</dt><dd>{String(t.is_vpn_tor)}</dd>
              <dt>ISP / ASN</dt><dd>{t.isp_asn || t.geolocation?.isp || '-'}</dd>
              <dt>Country / City</dt>
              <dd>
                {t.geolocation ? `${t.geolocation.country || '?'} / ${t.geolocation.city || '?'}` : '-'}
                {t.geolocation?.source && (
                  <span style={{ color: 'var(--muted)', fontSize: 12, marginLeft: 6 }}>
                    ({t.geolocation.source})
                  </span>
                )}
              </dd>
            </dl>
            <h3>WHOIS</h3>
            <pre className="dump">{JSON.stringify(t.whois, null, 2)}</pre>
            <h3>DNS</h3>
            <pre className="dump">{JSON.stringify(t.dns, null, 2)}</pre>
          </div>
          <div className="card">
            <h3>Origin Geolocation Map</h3>
            {t.geolocation?.lat != null && t.geolocation?.lon != null && !isNaN(Number(t.geolocation.lat)) && !isNaN(Number(t.geolocation.lon)) ? (
              <>
                <div style={{ marginBottom: 8, fontSize: 13, color: 'var(--muted)' }}>
                  Target: <b>{t.geolocation.city || t.geolocation.country || 'Coordinates'}</b>
                  {t.geolocation.source && <span> ({t.geolocation.source})</span>}
                </div>
                <iframe
                  title="Geolocation map of email origin"
                  width="100%"
                  height="380"
                  style={{ border: 0, borderRadius: 8 }}
                  loading="lazy"
                  sandbox="allow-scripts allow-same-origin"
                  referrerPolicy="no-referrer"
                  src={`https://www.openstreetmap.org/export/embed.html?bbox=${Number(t.geolocation.lon) - 4}%2C${Number(t.geolocation.lat) - 4}%2C${Number(t.geolocation.lon) + 4}%2C${Number(t.geolocation.lat) + 4}&layer=mapnik&marker=${Number(t.geolocation.lat)}%2C${Number(t.geolocation.lon)}`}
                />
                <p style={{ marginTop: 8 }}>
                  <a
                    target="_blank"
                    rel="noreferrer"
                    href={`https://www.openstreetmap.org/?mlat=${t.geolocation.lat}&mlon=${t.geolocation.lon}#map=7/${t.geolocation.lat}/${t.geolocation.lon}`}
                  >
                    Open full map (OSM)
                  </a>
                </p>
              </>
            ) : (
              <Empty msg="No coordinates available - sender origin IP is unresolvable or network lookups are offline." />
            )}
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
      <InternalLinks current="/email" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'TechArticle', headline: subject,
        description: `Forensic analysis for email ${id}`, url: `${CANONICAL_BASE}/email/${id}`,
        author: { '@id': `${CANONICAL_BASE}/#organization` }
      })}} />
    </div>
  );
}

/* ---------------- Campaigns ---------------- */

export function Campaigns() {
  usePageMeta({
    title: 'Campaigns - Shared Infrastructure Clusters - SOC Forensics Lab',
    description: 'Graph-detected campaign clusters sharing sender infrastructure, domains and IPs. Analyze confidence, attribution and forensic timelines.',
    canonical: '/campaigns',
    image: 'https://socforensics.io/og-image.svg',
  });
  const [cards, setCards] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');
  useEffect(() => {
    let cancelled = false;
    jget('/campaigns')
      .then((v) => { if (!cancelled) setCards(v); })
      .catch((e) => { if (!cancelled) setErr(e instanceof ApiError ? `Could not load campaigns (${e.status}): ${e.message}` : String(e)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);
  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Campaigns' }]} />
      <h1>Campaigns</h1>
      <p className="sub">Graph-detected clusters: domains sharing sender infrastructure, joined with forensic records.</p>
      <img src="/og-image.svg" alt="Campaign clustering visualization - threat infrastructure graph preview" width={640} height={336} style={{ width: '100%', maxWidth: 640, height: 'auto', borderRadius: 8, border: '1px solid var(--border)', marginBottom: 14 }} loading="lazy" />
      <Toast msg={err} />
      {loading ? <SkeletonList /> : cards.length === 0 ? <Empty msg="No campaigns yet - ingest more mail sharing IPs/domains." /> : (
        <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))' }}>
          {cards.map((k) => (
            <div key={k.id} className="card">
              <h3><Link to={`/campaign/${k.id}`}>{k.name}</Link></h3>
              <div className="stat-num">{k.email_count} <span style={{ fontSize: 14, fontWeight: 400, color: 'var(--muted)' }}>emails</span></div>
              <dl className="kv" style={{ gridTemplateColumns: '110px 1fr' }}>
                <dt>Confidence</dt><dd><b>{Math.round(k.confidence * 100)}%</b></dd>
                <dt>Shared IP</dt><dd><span className="mono">{k.ip}</span></dd>
                <dt>ASN</dt><dd>{k.asn || '-'}</dd>
                <dt>Domains</dt><dd>{(k.domains || []).map((d: string) => <span key={d} className="mono" style={{ marginRight: 4 }}>{d}</span>)}</dd>
                <dt>First seen</dt><dd style={{ fontSize: 12 }}>{formatDateTime(k.first_seen)}</dd>
                <dt>Last seen</dt><dd style={{ fontSize: 12 }}>{formatDateTime(k.last_seen)}</dd>
              </dl>
              <Link to={`/campaign/${k.id}`}>Open campaign →</Link>
            </div>
          ))}
        </div>
      )}
      <InternalLinks current="/campaigns" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'CollectionPage', name: 'Campaigns - SOC Forensics Lab',
        description: 'Shared infrastructure campaign clusters', url: `${CANONICAL_BASE}/campaigns`,
        isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
    </div>
  );
}

export function CampaignDetail({ id }: { id: string }) {
  const [d, setD] = useState<any>(null);
  const [err, setErr] = useState('');
  const cardName = d?.card?.name || `Campaign ${id.slice(0, 8)}`;
  usePageMeta({
    title: `${cardName} - Campaign Detail - SOC Forensics Lab`,
    description: d ? `Campaign ${cardName} with ${d.card.email_count} emails, confidence ${Math.round(d.card.confidence * 100)}%, shared IP ${d.card.ip}. Attribution graph and email list.` : 'Campaign attribution detail with graph and forensic emails.',
    canonical: `/campaign/${id}`,
    image: 'https://socforensics.io/og-image.svg',
  });
  useEffect(() => {
    setD(null);
    setErr('');
    let cancelled = false;
    jget(`/campaigns/${id}`)
      .then((v) => { if (!cancelled) setD(v); })
      .catch((e) => { if (!cancelled) setErr(e instanceof ApiError ? `Could not load campaign (${e.status}): ${e.message}` : String(e)); });
    return () => { cancelled = true; };
  }, [id]);
  if (err) return <div className="page"><Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Campaigns', href: '/campaigns' }, { label: 'Error' }]} /><Link to="/campaigns">← campaigns</Link><Toast msg={err} /></div>;
  if (!d) return <div className="page"><Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Campaigns', href: '/campaigns' }, { label: 'Loading' }]} /><Link to="/campaigns">← campaigns</Link><SkeletonList /></div>;
  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Campaigns', href: '/campaigns' }, { label: cardName }]} />
      <Link to="/campaigns">← campaigns</Link>
      <h1 style={{ marginTop: 8 }}>{d.card.name}</h1>
      <p className="sub">
        {d.card.email_count} emails · confidence {Math.round(d.card.confidence * 100)}% · IP <span className="mono">{d.card.ip}</span>
        {d.card.asn ? <> · ASN {d.card.asn}</> : null}
        {' · '}<Link to="/">Dashboard</Link> · <Link to="/cases">Cases</Link>
      </p>
      <div className="card" style={{ marginBottom: 14 }}>
        <h3>Attribution graph (campaign nodes)</h3>
        <GraphSvg graph={d.graph} />
      </div>
      <div className="card">
        <h3>Emails in this campaign</h3>
        {d.emails.length === 0 ? <Empty msg="No stored emails match this cluster." /> : (
          <table className="tbl">
            <thead><tr><th>Score</th><th>Subject</th><th>Sender</th><th>Classification</th><th>Received</th></tr></thead>
            <tbody>
              {d.emails.map((e: any) => (
                <tr key={e.id}>
                  <td><ScoreBadge v={e.fraud_score ?? 0} /></td>
                  <td><Link to={`/email/${e.id}`}>{e.subject || '(no subject)'}</Link></td>
                  <td><span className="mono">{e.sender}</span></td>
                  <td>{e.classification}</td>
                  <td style={{ color: 'var(--muted)', fontSize: 12 }}>{formatDateTime(e.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <InternalLinks current="/campaigns" />
    </div>
  );
}

/* ---------------- Model transparency ---------------- */

export function ModelInfo() {
  usePageMeta({
    title: 'Model Transparency & Metrics - SOC Forensics Lab',
    description: 'Phishing/BEC/clean classifier transparency: accuracy, macro F1, per-class precision/recall and confusion matrix from held-out evaluation.',
    canonical: '/model',
    image: 'https://socforensics.io/og-image.svg',
  });
  const [m, setM] = useState<any>(null);
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let cancelled = false;
    jget('/model/metrics')
      .then((v) => { if (!cancelled) setM(v); })
      .catch((e) => { if (!cancelled) setErr(e instanceof ApiError ? `Could not load model metrics (${e.status}): ${e.message}` : String(e)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);
  if (loading) return <div className="page"><Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Model Info' }]} /><h1>Model Transparency</h1><SkeletonList /></div>;
  if (err) return <div className="page"><Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Model Info' }]} /><h1>Model Transparency</h1><Toast msg={err} /></div>;
  const labels: string[] = m.confusion_labels || [];
  const per = m.per_class || {};
  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Model Transparency' }]} />
      <h1>Model Transparency</h1>
      <p className="sub">
        Phishing/BEC/clean text classifier (TF-IDF + LogisticRegression), evaluated on a held-out split
        ({m.n_test} test / {m.n_train} train, seed {m.random_state}). Metrics cached by <code>scripts/train_nlp.py</code>.
      </p>
      <img src="/og-image.svg" alt="Model metrics preview - accuracy and F1 visualization for SOC Forensics classifier" width={640} height={200} style={{ width: '100%', maxWidth: 640, height: 'auto', borderRadius: 8, border: '1px solid var(--border)', marginBottom: 14 }} loading="lazy" />
      <div className="grid stats">
        <StatCard label="Accuracy" value={`${Math.round((m.accuracy ?? 0) * 100)}%`} />
        <StatCard label="Macro F1" value={(m.macro_f1 ?? 0).toFixed(3)} />
        <StatCard label="Macro precision" value={(m.macro_precision ?? 0).toFixed(3)} />
        <StatCard label="Macro recall" value={(m.macro_recall ?? 0).toFixed(3)} />
      </div>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}>
        <div className="card">
          <h3>Per-class precision / recall / F1</h3>
          <table className="tbl">
            <thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th>Support</th></tr></thead>
            <tbody>
              {labels.map((l) => (
                <tr key={l}>
                  <td><b>{l}</b></td>
                  <td>{(per[l]?.precision ?? 0).toFixed(3)}</td>
                  <td>{(per[l]?.recall ?? 0).toFixed(3)}</td>
                  <td>{(per[l]?.f1 ?? 0).toFixed(3)}</td>
                  <td>{per[l]?.support ?? 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card">
          <h3>Confusion matrix (rows = actual, cols = predicted)</h3>
          <table className="tbl">
            <thead><tr><th></th>{labels.map((l) => <th key={l}>{l}</th>)}</tr></thead>
            <tbody>
              {(m.confusion_matrix || []).map((row: number[], i: number) => {
                const total = Math.max(1, row.reduce((x, y) => x + y, 0));
                return (
                  <tr key={labels[i]}>
                    <th style={{ textAlign: 'left' }}>{labels[i]}</th>
                    {row.map((v, j) => (
                      <td key={j} style={{ background: i === j ? 'rgba(34,197,94,0.15)' : v ? 'rgba(239,68,68,0.15)' : undefined }}>
                        <b>{v}</b> <span style={{ color: 'var(--muted)', fontSize: 11 }}>{Math.round((100 * v) / total)}%</span>
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
          <p className="sub" style={{ marginBottom: 0 }}>Diagonal cells are correct predictions; off-diagonal cells are confusions.</p>
        </div>
      </div>
      <InternalLinks current="/model" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'TechArticle', headline: 'Model Transparency - SOC Forensics Lab',
        description: 'Classifier evaluation metrics and confusion matrix', url: `${CANONICAL_BASE}/model`,
        author: { '@id': `${CANONICAL_BASE}/#organization` }
      })}} />
    </div>
  );
}

/* ---------------- Mailboxes (OAuth org connectors) ---------------- */

export function Mailboxes() {
  usePageMeta({
    title: 'Mailboxes - OAuth Connectors - SOC Forensics Lab',
    description: 'Organization-level OAuth connectors for Google and Microsoft mailboxes with encrypted refresh tokens, polling and manual sync.',
    canonical: '/mailboxes',
    image: 'https://socforensics.io/og-image.svg',
  });
  const [conns, setConns] = useState<any[]>([]);
  const [err, setErr] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [clientId, setClientId] = useState(() => localStorage.getItem('oauth_client_id') || '');
  const [clientSecret, setClientSecret] = useState(() => localStorage.getItem('oauth_client_secret') || '');
  const [redirectUri, setRedirectUri] = useState(
    typeof window !== 'undefined' ? `${window.location.origin}/` : 'https://socforensics.io/',
  );

  const updateClientId = (v: string) => { setClientId(v); localStorage.setItem('oauth_client_id', v); };
  const updateClientSecret = (v: string) => { setClientSecret(v); localStorage.setItem('oauth_client_secret', v); };

  const fail = (e: unknown, what: string) =>
    setErr(e instanceof ApiError ? `${what} failed (${e.status}): ${e.message}` : String(e));

  const load = async () => {
    try {
      setConns(await jget('/oauth/status'));
    } catch (e) { fail(e, 'Status'); }
  };
  useEffect(() => { void load(); }, []);

  const connect = async (provider: 'google' | 'microsoft') => {
    setErr(''); setNotice('');
    setBusy(true);
    try {
      let url = `/oauth/${provider}/authorize?redirect_uri=${encodeURIComponent(redirectUri)}`;
      if (clientId.trim()) url += `&client_id=${encodeURIComponent(clientId.trim())}`;
      if (clientSecret.trim()) url += `&client_secret=${encodeURIComponent(clientSecret.trim())}`;
      const r = await jget(url);
      window.location.href = r.auth_url;
    } catch (e) { fail(e, 'Connect'); } finally { setBusy(false); }
  };

  const [maxN, setMaxN] = useState('25');
  const syncNow = async () => {
    setBusy(true); setErr(''); setNotice('Syncing emails & running ML threat detection pipeline…');
    try {
      const num = Math.max(1, parseInt(maxN, 10) || 10);
      const r = await jpost('/oauth/sync-now', { max_results: num, client_id: clientId || undefined, client_secret: clientSecret || undefined });
      setNotice(`Synced ${r.synced} email(s)${r.errors?.length ? `, ${r.errors.length} error(s)` : ''}.`);
      await load();
      window.dispatchEvent(new CustomEvent('soc:emails-updated'));
    } catch (e) { fail(e, 'Sync'); } finally { setBusy(false); }
  };

  const disconnect = async (provider: string) => {
    if (!confirm(`Disconnect ${provider} mailbox?`)) return;
    try {
      await jdel(`/oauth/${provider}`);
      await load();
      window.dispatchEvent(new CustomEvent('soc:emails-updated'));
    } catch (e) { fail(e, 'Disconnect'); }
  };

  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Mailboxes' }]} />
      <h1>Mailboxes</h1>
      <p className="sub">Organization-level OAuth connectors (Google + Microsoft) with background polling. All credentials and refresh tokens are encrypted server-side.</p>
      <img src="/favicon.svg" alt="Mailbox connectors - secure OAuth integration for Gmail and Microsoft" width={64} height={64} style={{ marginBottom: 12 }} loading="lazy" />
      <Toast msg={err} />
      {notice && <Toast msg={notice} kind="info" />}
      <div className="card" style={{ marginBottom: 14 }}>
        <h3>Connected</h3>
        {conns.length === 0 ? <Empty msg="No mailbox connected yet." /> : (
          <table className="tbl">
            <thead><tr><th>Provider</th><th>Account</th><th>Last poll</th><th></th></tr></thead>
            <tbody>
              {conns.map((m) => (
                <tr key={m.provider + m.account_email}>
                  <td><b>{m.provider}</b></td>
                  <td><span className="mono">{m.account_email}</span></td>
                  <td style={{ fontSize: 12 }}>{formatDateTime(m.last_poll_at)}</td>
                  <td><button className="ghost small" onClick={() => disconnect(m.provider)}>Disconnect</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div className="row" style={{ marginTop: 10 }}>
          <input
            type="number"
            min="1"
            style={{ maxWidth: 110 }}
            value={maxN}
            onChange={(e) => setMaxN(e.target.value)}
            placeholder="Count"
            title="Max emails to sync (any number)"
          />
          <button onClick={syncNow} disabled={busy || conns.length === 0}>{busy ? 'Syncing…' : 'Sync now'}</button>
          <Link to="/">Back to Dashboard</Link>
        </div>
      </div>
      <div className="card">
        <h3>Connect Mailbox</h3>
        <div className="grid" style={{ gap: 8, maxWidth: 560 }}>
          <input type="text" value={clientId} onChange={(e) => updateClientId(e.target.value)} placeholder="OAuth client ID (from Google / Microsoft console)" />
          <input type="password" value={clientSecret} onChange={(e) => updateClientSecret(e.target.value)} placeholder="OAuth client secret" autoComplete="off" />
          <input type="text" value={redirectUri} onChange={(e) => setRedirectUri(e.target.value)} placeholder="Redirect URI (must match provider console)" />
          <div className="row">
            <button className="ghost" onClick={() => connect('google')} disabled={busy || !clientId.trim() || !clientSecret.trim()}>Connect Google</button>
            <button className="ghost" onClick={() => connect('microsoft')} disabled={busy || !clientId.trim() || !clientSecret.trim()}>Connect Microsoft</button>
          </div>
          <p className="sub" style={{ marginBottom: 0 }}>Enter your OAuth credentials above — they are encrypted and stored on the server per connection. No .env configuration needed. After consent you return here automatically.</p>
        </div>
      </div>
      <InternalLinks current="/mailboxes" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Mailboxes - SOC Forensics Lab',
        description: 'OAuth mailbox connectors', url: `${CANONICAL_BASE}/mailboxes`,
        isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
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
  usePageMeta({
    title: 'Case Management - Kanban Board - SOC Forensics Lab',
    description: 'Track forensic investigations from triage to closure. Kanban board for Open, In Progress and Closed cases with email linkage.',
    canonical: '/cases',
    image: 'https://socforensics.io/og-image.svg',
  });
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
  useEffect(() => { void load(); }, []);

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
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Case Management' }]} />
      <h1>Case Management</h1>
      <p className="sub">Track investigations from triage to closure.</p>
      <img src="/favicon.svg" alt="Case management kanban board - investigation workflow illustration" width={64} height={64} style={{ marginBottom: 12 }} loading="lazy" />
      <Toast msg={err} />
      <div className="row" style={{ marginBottom: 16 }}>
        <input type="text" style={{ maxWidth: 360 }} value={title} onChange={(e) => setTitle(e.target.value)}
          placeholder="New case title…" onKeyDown={(e) => { if (e.key === 'Enter') void create(); }} />
        <button onClick={create}>Create case</button>
        <Link to="/campaigns" className="ghost" style={{ padding: '8px 12px', border: '1px solid var(--border)', borderRadius: 8, background: 'var(--panel-2)', textDecoration: 'none' }}>View Campaigns →</Link>
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
      <InternalLinks current="/cases" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Case Management - SOC Forensics Lab',
        description: 'Kanban case management for forensic investigations', url: `${CANONICAL_BASE}/cases`,
        isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
    </div>
  );
}

/* ---------------- Privacy Policy ---------------- */

export function PrivacyPolicy() {
  usePageMeta({
    title: 'Privacy Policy - SOC Forensics Lab',
    description: 'How SOC Forensics Lab handles email data, cookies, and analyst accounts. Retention, masking, and your rights.',
    canonical: '/privacy',
    image: 'https://socforensics.io/og-image.svg',
  });
  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Privacy Policy' }]} />
      <h1>Privacy Policy</h1>
      <p className="sub">Effective 20 Sep 2026 - SOC Forensics Lab, 301 Congress Ave, Austin, TX 78701. Contact hello@socforensics.io</p>
      <div className="card">
        <h3>What we collect</h3>
        <p>Analyst credentials (username, hashed password, role), ingested email RFC822 content for forensic scoring, mailbox OAuth tokens stored encrypted server-side, and browser local storage for theme and cookie consent. We do not sell data.</p>
        <h3>How we use email content</h3>
        <p>Uploaded mail is parsed, scored 0-100, checked for SPF/DKIM/DMARC and threat intel, then stored with PII masked previews and a SHA-256 hash for chain-of-custody. Raw content is retained per your retention setting and purged by the daily scheduler. See retention_audit.log.</p>
        <h3>Cookies</h3>
        <p>Essential cookies keep you signed in (in-memory JWT, not localStorage) and remember theme and consent choice. No advertising cookies. Analytics is off by default. Use the banner to accept or decline essential storage.</p>
        <h3>Your rights</h3>
        <p>Request access or deletion of your analyst account and ingested data via hello@socforensics.io. OAuth refresh tokens can be revoked via Mailboxes disconnect.</p>
        <h3>Data location</h3>
        <p>Self-hosted SQLite by default or your Postgres/Elastic/Neo4j cluster per docker-compose. Geolocation uses offline GeoIP fallback unless live lookups are enabled.</p>
      </div>
      <InternalLinks current="/privacy" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Privacy Policy - SOC Forensics Lab',
        description: 'Privacy policy for SOC Forensics Lab', url: `${CANONICAL_BASE}/privacy`,
        isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
    </div>
  );
}

/* ---------------- Terms and Conditions ---------------- */

export function TermsConditions() {
  usePageMeta({
    title: 'Terms and Conditions - SOC Forensics Lab',
    description: 'Terms for using the SOC Forensics email threat platform. Acceptable use, liability, and reporting.',
    canonical: '/terms',
    image: 'https://socforensics.io/og-image.svg',
  });
  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Terms and Conditions' }]} />
      <h1>Terms and Conditions</h1>
      <p className="sub">Effective 20 Sep 2026 - Use of socforensics.io is governed by these terms.</p>
      <div className="card">
        <h3>Acceptable use</h3>
        <p>Upload only mail you are authorized to analyze. Do not ingest illegal content or attempt to bypass authentication, retrain the classifier without approval, or scrape threat intel feeds.</p>
        <h3>Forensic reports</h3>
        <p>Scores and classifications are investigative aids, not legal guarantees. Verify with SPF, DKIM, headers, and intel hits before action.</p>
        <h3>Availability</h3>
        <p>Service is provided as-is. The team may update scoring weights, retention, and polling intervals. Check Model Transparency for current metrics.</p>
        <h3>Liability</h3>
        <p>To the full extent permitted by law, SOC Forensics Lab is not liable for indirect damages from missed or flagged mail.</p>
        <h3>Contact</h3>
        <p>Questions: hello@socforensics.io. Postal: 301 Congress Ave, Suite 400, Austin, TX 78701.</p>
      </div>
      <InternalLinks current="/terms" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Terms and Conditions - SOC Forensics Lab',
        description: 'Terms and conditions for SOC Forensics Lab', url: `${CANONICAL_BASE}/terms`,
        isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
    </div>
  );
}
