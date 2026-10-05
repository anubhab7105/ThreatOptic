import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ApiError, assertIdpUrl, downloadReport, jdel, jget, jpatch, jpost, pollTask, uploadEmFile } from './api';
import { useAuth } from './auth';
import { AuthPill, CopyButton, PasswordToggle } from './components';
import { Alert, Badge, Button, Card, Drawer, EmptyState, ErrorState, Input, Modal, SegmentedControl, Select, SeverityBadge, SeverityIcon, Skeleton, SortTh, Spinner, StatusIndicator, Table, Tabs, Textarea, Toggle, Tooltip, Well } from './primitives';
import { useChartTheme } from './useChartTheme';

const CANONICAL_BASE = 'https://email-scanner-chi.vercel.app';

function safeJsonLd(obj: unknown): string {
  return JSON.stringify(obj).replace(/<\//g, '<\\/');
}

function setCanonical(path: string) {
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
    setMeta('twitter:title', opts.title);
    setMeta('twitter:description', opts.description);
  }, [opts.title, opts.description, opts.canonical, opts.image]);
}

export function formatDateTime(ts: string | null | undefined): string {
  if (!ts) return '—';
  const iso = ts.endsWith('Z') || /[+-]\d{2}(:\d{2})?$/.test(ts) ? ts : ts + 'Z';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
}

/* ---------------- Landing Page (Public) ---------------- */
// Inspection-Chamber landing lives in its own feature folder (Landing_Design.md §9).
// Route behavior unchanged: public "/" for logged-out visitors (see main.tsx Shell).
export { LandingPage } from './landing/LandingPage';

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
        Also: <a href="/sitemap.xml">Sitemap</a> · <a href="/robots.txt">Robots</a> · <a href="/llms.txt">LLMs</a> · <a href="https://email-scanner-chi.vercel.app/">ThreatOptic live demo</a>
      </div>
    </div>
  );
}

/* ---------------- Login ---------------- */

export function LoginPage() {
  usePageMeta({
    title: 'Sign In - ThreatOptic | Secure Analyst Access',
    description: 'JWT-secured sign in for SOC analysts. Access the email threat dashboard with forensic intelligence, geolocation and chain-of-custody reporting.',
    canonical: '/login',
    image: 'https://email-scanner-chi.vercel.app/og-image.svg',
  });
  const { login, register, user } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  // If auth state resolves to signed-in while on /login (e.g. session
  // restore), leave /login — the authed Shell has no /login route.
  useEffect(() => {
    if (user) navigate('/dashboard', { replace: true });
  }, [user, navigate]);

  const submit = async () => {
    if (!email.trim() || !password) return;
    setBusy(true);
    setErr('');
    setNotice('');
    try {
      if (mode === 'login') {
        await login(email.trim(), password);
        navigate('/dashboard', { replace: true });
      } else {
        const res = await register(email.trim(), password);
        if (res.needsConfirmation) setNotice('Account created — check your email to confirm, then sign in.');
      }
    } catch (e) {
      setErr(e instanceof ApiError ? `Authentication failed (${e.status}): ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-page-wrapper">
      <div className="login-card">
        <div className="login-form-pane">
          <div className="login-breadcrumb">
            <Link to="/">Home</Link>
            <span className="sep">›</span>
            <span>{mode === 'login' ? 'Sign in' : 'Register'}</span>
          </div>

          <h2 className="login-form-title">{mode === 'login' ? 'Sign in' : 'Register'}</h2>
          <p className="login-form-sub">Sign in to access the email threat dashboard.</p>

          <SegmentedControl
            label="Sign in or register"
            value={mode}
            onChange={(v) => { setMode(v); setErr(''); }}
            options={[{ value: 'login', label: 'Sign in' }, { value: 'register', label: 'Register' }]}
          />

          <div aria-live="polite" style={{ marginTop: 12 }}>
            {err ? <Alert tone="error">{err}</Alert> : null}
            {notice && !err ? <Alert tone="success">{notice}</Alert> : null}
          </div>

          <div style={{ marginTop: 12 }}>
            <Input
              id="login-email"
              label="Email"
              type="email"
              placeholder="e.g. analyst@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') submit(); }}
              autoComplete="email"
            />
          </div>

          <div className="login-field-group" style={{ marginTop: 12 }}>
            <PasswordToggle
              id="login-password"
              label="Password"
              value={password}
              onChange={setPassword}
              maxLength={128}
              placeholder={mode === 'register' ? 'Password (min 8 chars)' : '••••••••'}
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              className="login-input"
              onKeyDown={(e) => { if (e.key === 'Enter') submit(); }}
            />
          </div>

          <Button
            variant="primary"
            onClick={submit}
            loading={busy}
            disabled={!email.trim() || !password}
            style={{ width: '100%', marginTop: 12, marginBottom: 16 }}
          >
            {mode === 'login' ? 'Sign in' : 'Create account'}
          </Button>
        </div>
      </div>

      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Sign In - ThreatOptic',
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
Authentication-Results: mx.company.com;
  spf=fail (evil-relay.test: domain of bounce@evil-relay.test does not designate 45.148.10.88 as permitted sender) smtp.mailfrom=bounce@evil-relay.test;
  dkim=fail (bad signature) header.i=@xn--paypa1-secure.top;
  dmarc=fail (p=REJECT) header.from=xn--paypa1-secure.top
Received-SPF: fail (evil-relay.test: domain of bounce@evil-relay.test does not designate 45.148.10.88 as permitted sender) client-ip=45.148.10.88;
Received: from evil-relay.test (evil-relay.test [45.148.10.88]) by mx.company.com with ESMTPS id x1
Received: from internal ([10.0.0.5]) by evil-relay.test with SMTP id y2
Content-Type: text/plain

Hi, kindly wire $48,000 to new vendor bank details immediately. Do not disclose. Verify account now at http://malicious-example.com/login`;

const CLEAN_SAMPLE = `From: Alice <alice@company.com>
To: bob@company.com
Subject: Lunch tomorrow?
Message-ID: <lunch1@company.com>
Return-Path: <alice@company.com>
Authentication-Results: mx.company.com;
  spf=pass (mail.company.com: domain of alice@company.com designates 93.184.216.34 as permitted sender) smtp.mailfrom=alice@company.com;
  dkim=pass (signature verified) header.i=@company.com header.s=s1;
  dmarc=pass (p=REJECT) header.from=company.com
Received-SPF: pass (company.com: domain of alice@company.com designates 93.184.216.34 as permitted sender) client-ip=93.184.216.34;
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=company.com; s=s1; bh=abc; b=xyz
Received: from mail.company.com (mail.company.com [93.184.216.34]) by mx.company.com with ESMTPS id z9
Content-Type: text/plain

Hi Bob, lunch tomorrow at noon? Let me know if cafeteria works.`;

/* ---------------- Gmail live import ---------------- */

function GmailPanel({ onSynced, bare = false }: { onSynced: () => void; bare?: boolean }) {
  const [status, setStatus] = useState<any>(null);
  // OAuth credentials are never prepopulated in state or DOM — kept blank for privacy
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [showSecret, setShowSecret] = useState(false);
  const [redirectUri, setRedirectUri] = useState(
    typeof window !== 'undefined' ? `${window.location.origin}/` : 'http://localhost:5173/',
  );
  const [code, setCode] = useState('');
  const [oauthState, setOauthState] = useState('');
  const [query, setQuery] = useState('is:unread');
  const [maxN, setMaxN] = useState('10');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [notice, setNotice] = useState('');
  const [authUrl, setAuthUrl] = useState('');
  const [showCreds, setShowCreds] = useState(false);

  const updateClientId = (v: string) => {
    setClientId(v);
  };

  const updateClientSecret = (v: string) => {
    setClientSecret(v);
  };

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
    setBusy(true); setErr(''); setNotice(''); setAuthUrl('');
    try {
      const r = await jpost('/gmail/auth-url', {
        redirect_uri: redirectUri,
        client_id: clientId.trim() || undefined,
        client_secret: clientSecret.trim() || undefined,
      });
      // P1: never hand the browser to an unverified host — an analyst
      // connecting a mailbox is exactly the moment a phishing hop lands.
      const safeUrl = assertIdpUrl(r.auth_url, 'google');
      setAuthUrl(safeUrl);
      setNotice('Redirecting to Google consent page… If not redirected, click the link below.');
      try {
        window.location.assign(safeUrl);
      } catch {
        window.location.href = safeUrl;
      }
    } catch (e) { fail(e, 'Consent URL'); } finally { setBusy(false); }
  };

  const finish = async (manualCode?: string, manualState?: string) => {
    const c = (manualCode ?? code).trim();
    const s = (manualState ?? oauthState).trim();
    if (!c || !s) {
      setErr('Both authorization code and state are required — restart the connect flow.');
      return;
    }
    setBusy(true); setErr(''); setNotice('');
    try {
      // P0: client_id from state only, client_secret never from browser storage
      const effectiveCid = clientId.trim() || undefined;
      const effectiveSec = clientSecret.trim() || undefined;

      const r = await jpost('/gmail/callback', {
        code: c,
        state: s,
        redirect_uri: redirectUri,
        client_id: effectiveCid,
        client_secret: effectiveSec,
      });
      setStatus(r);
      setCode('');
      setOauthState('');
      setClientId('');
      setClientSecret('');
      setNotice(`Connected as ${r.gmail_address}. Credentials saved securely on the server.`);
      await refresh();
      await onSynced();
      window.dispatchEvent(new CustomEvent('soc:emails-updated'));
    } catch (e) { fail(e, 'Connection'); } finally { setBusy(false); }
  };

  const autoTried = useRef(false);
  useEffect(() => {
    if (autoTried.current) return;
    autoTried.current = true;
    const params = new URLSearchParams(window.location.search);
    const q = params.get('code');
    const st = params.get('state');
    if (q && st) {
      setCode(q);
      setOauthState(st);
      window.history.replaceState({}, '', window.location.pathname);
      void finish(q, st);
    } else if (q) {
      window.history.replaceState({}, '', window.location.pathname);
      setErr('OAuth state missing — restart the connect flow (possible CSRF).');
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
      const num = Math.max(1, Math.min(50, parseInt(maxN, 10) || 10));
      // Only send credentials if the user explicitly opened credentials and changed them
      const effectiveCid = showCreds && clientId.trim() ? clientId.trim() : undefined;
      const effectiveSec = showCreds && clientSecret.trim() ? clientSecret.trim() : undefined;

      const r = await jpost('/gmail/sync', {
        max_results: num,
        query,
        client_id: effectiveCid,
        client_secret: effectiveSec,
      });
      setErr('');
      setNotice(`Synced ${r.synced} email(s) through the pipeline${r.errors?.length ? `, ${r.errors.length} error(s)` : ''}.`);
      setClientId('');
      setClientSecret('');
      await refresh();
      await onSynced();
      window.dispatchEvent(new CustomEvent('soc:emails-updated'));
    } catch (e) {
      setNotice('');
      fail(e, 'Sync');
    } finally {
      setBusy(false);
    }
  };

  const disconnect = async () => {
    if (!confirm('Disconnect this Gmail mailbox?')) return;
    try {
      await jdel('/gmail/disconnect');
      setErr('');
      setNotice('Mailbox disconnected.');
      setClientId('');
      setClientSecret('');
      setShowCreds(false);
      await refresh();
      await onSynced();
      window.dispatchEvent(new CustomEvent('soc:emails-updated'));
    } catch (e) { fail(e, 'Disconnect'); }
  };

  // Stepper phase (Design.md §7.6): Waiting > Connecting > Connected / Error.
  // OAuth code/state are still auto-captured (see effect above); the visible
  // code fields below remain only as a collapsed manual retry.
  const phase = status?.connected ? 'connected' : err ? 'error' : busy || code ? 'connecting' : 'waiting';
  const steps = ['waiting', 'connecting', 'connected'] as const;
  const stepLabel: Record<string, string> = { waiting: 'Waiting', connecting: 'Connecting', connected: 'Connected' };
  const stepIcon = (s: string) => {
    if (phase === 'error' && s === 'connecting') return <span aria-hidden="true">⬢</span>;
    if (s === 'connected' && phase === 'connected') return <span aria-hidden="true">✓</span>;
    if (s === 'connecting' && phase === 'connecting') return <Spinner label="Connecting" />;
    if (steps.indexOf(s as typeof steps[number]) < steps.indexOf(phase as typeof steps[number])) return <span aria-hidden="true">✓</span>;
    return <span aria-hidden="true">○</span>;
  };

  const toggleCreds = () => {
    const next = !showCreds;
    setShowCreds(next);
    if (next) {
      setClientId('');
      setClientSecret('');
    }
  };

  const body = (
    <>
      <ol className="stepper" aria-label="Gmail connection progress">
        {steps.map((s, i) => (
          <li key={s} className={phase === 'error' && s === 'connecting' ? 'is-error' : s === phase ? 'is-current' : steps.indexOf(phase as typeof steps[number]) > i ? 'is-done' : undefined} aria-current={s === phase ? 'step' : undefined}>
            {stepIcon(s)} {stepLabel[s]}{i < steps.length - 1 ? <span className="step-sep" aria-hidden="true">›</span> : null}
          </li>
        ))}
        {phase === 'error' ? <li className="is-error"><span aria-hidden="true">⬢</span> Error</li> : null}
      </ol>
      <div aria-live="polite">
        {err ? <Alert tone="error" title="Gmail connection issue">{err}</Alert> : null}
        {notice && !err ? <Alert tone={status?.connected ? 'success' : 'info'}>{notice}</Alert> : null}
      </div>
      {phase === 'error' ? (
        <div className="row" style={{ marginTop: 8 }}>
          <Button size="sm" variant="primary" onClick={() => { setErr(''); void refresh(); }}>Retry</Button>
        </div>
      ) : null}
      {status?.connected ? (
        <div>
          <p style={{ margin: '12px 0 8px' }}>
            <StatusIndicator color="var(--success)" label={`Connected as ${status.gmail_address}`} />
            {status.last_sync_at ? (
              <Tooltip label={formatDateTime(status.last_sync_at)}>
                <span style={{ color: 'var(--text-muted)', fontSize: 12 }}> · last sync {formatDateTime(status.last_sync_at)}</span>
              </Tooltip>
            ) : null}
          </p>
          <div className="grid-2" style={{ maxWidth: 560 }}>
            <Input label="Gmail search query" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="is:unread" />
            <Input label="Max emails to sync" type="number" min="1" max="50" value={maxN} onChange={(e) => setMaxN(e.target.value)} />
          </div>
          <div className="row" style={{ marginTop: 10 }}>
            <Button size="sm" variant="primary" onClick={sync} loading={busy}>Sync now</Button>
            <Button size="sm" variant="ghost" onClick={toggleCreds}>{showCreds ? 'Hide credentials' : 'Change credentials'}</Button>
            <Button size="sm" variant="danger" onClick={disconnect}>Disconnect</Button>
          </div>
          {showCreds && (
            <Well>
              <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 0 }}>
                Server has encrypted credentials saved. Leave fields blank to keep current credentials, or enter new ones to rotate.
              </p>
              <div className="grid-2">
                <Input label="Google OAuth Client ID" value={clientId} onChange={(e) => updateClientId(e.target.value)} placeholder="Google OAuth Client ID (kept blank for privacy)" autoComplete="off" spellCheck={false} />
                <div>
                  <Input label="Google OAuth Client Secret" type={showSecret ? 'text' : 'password'} value={clientSecret} onChange={(e) => updateClientSecret(e.target.value)} placeholder="Google OAuth Client Secret (kept blank for privacy)" autoComplete="new-password" spellCheck={false} />
                  <div className="row" style={{ marginTop: 6 }}>
                    <Button size="sm" variant="ghost" onClick={() => setShowSecret(!showSecret)}>{showSecret ? 'Hide' : 'Show'}</Button>
                  </div>
                </div>
              </div>
            </Well>
          )}
        </div>
      ) : (
        <div>
          <p className="sub" style={{ marginTop: 0 }}>
            Enter your Google OAuth Client ID &amp; Secret below, then click <b>Connect Gmail</b>.
          </p>
          <div style={{ maxWidth: 560 }}>
            <div className="grid-2">
              <Input label="Google OAuth Client ID" value={clientId} onChange={(e) => updateClientId(e.target.value)} placeholder="Google OAuth client ID" autoComplete="off" spellCheck={false} />
              <div>
                <Input label="Google OAuth Client Secret" type={showSecret ? 'text' : 'password'} value={clientSecret} onChange={(e) => updateClientSecret(e.target.value)} placeholder="Google OAuth client secret" autoComplete="new-password" spellCheck={false} />
                <div className="row" style={{ marginTop: 6 }}>
                  <Button size="sm" variant="ghost" onClick={() => setShowSecret(!showSecret)}>{showSecret ? 'Hide' : 'Show'}</Button>
                </div>
              </div>
            </div>
            <div style={{ marginTop: 8 }}>
              <Input label="Redirect URI" help="Must match the Google Console entry exactly." value={redirectUri} onChange={(e) => setRedirectUri(e.target.value)} placeholder="Redirect URI (must match Google console)" autoComplete="off" spellCheck={false} />
            </div>
            <div className="row" style={{ marginTop: 10 }}>
              <Button variant="primary" onClick={getUrl} loading={busy} disabled={!clientId.trim() || !clientSecret.trim() || !redirectUri.trim()}>Connect Gmail</Button>
            </div>
            {authUrl && (
              <Well>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 6 }}>
                  Click below if Google login did not open automatically:
                </div>
                <a className="neu-btn neu-btn--primary neu-btn--md" href={authUrl}>
                  Open Google Consent Screen →
                </a>
              </Well>
            )}
            <details className="collapsible" style={{ marginTop: 8 }}>
              <summary>Manual connection retry</summary>
              <div className="grid-2" style={{ marginTop: 8 }}>
                <Input label="Authorization code" help="Auto-filled on redirect; only needed for manual retry." value={code} onChange={(e) => setCode(e.target.value)} placeholder="Authorization code" />
                <Input label="OAuth state" value={oauthState} onChange={(e) => setOauthState(e.target.value)} placeholder="State" />
              </div>
              <div className="row" style={{ marginTop: 8 }}>
                <Button onClick={() => finish()} disabled={busy || !code.trim() || !oauthState.trim()}>Finish connection</Button>
              </div>
            </details>
          </div>
        </div>
      )}
    </>
  );

  if (bare) return <>{body}</>;
  return (
    <Card title="Gmail live import" description="OAuth2, read-only mailbox sync">
      {body}
    </Card>
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
    title: 'Global Threat Dashboard - ThreatOptic | Real-Time Email Threats',
    description: 'Real-time phishing, BEC and spoofing detection across ingested mail. Analyze emails, view fraud scores, track campaigns and export chain-of-custody reports.',
    canonical: '/',
    image: 'https://email-scanner-chi.vercel.app/og-image.svg',
  });
  const [stats, setStats] = useState<any>(null);
  const [emails, setEmails] = useState<EmailRow[]>([]);
  const [scores, setScores] = useState<Record<string, { score: number; cls: string }>>({});
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');
  const [raw, setRaw] = useState('');
  const [busy, setBusy] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [notice, setNotice] = useState('');
  const [asyncMode, setAsyncMode] = useState(false);

  useEffect(() => {
    const onTopSearch = (e: Event) => {
      const detail = (e as CustomEvent).detail as { q?: string } | undefined;
      if (detail && typeof detail.q === 'string') setSearchQuery(detail.q);
    };
    const onSevFilter = (e: Event) => {
      const detail = (e as CustomEvent).detail as { sev?: string } | undefined;
      if (detail && typeof detail.sev === 'string') setSevFilter(detail.sev);
    };
    window.addEventListener('soc:top-search', onTopSearch);
    window.addEventListener('soc:severity-filter', onSevFilter);
    return () => {
      window.removeEventListener('soc:top-search', onTopSearch);
      window.removeEventListener('soc:severity-filter', onSevFilter);
    };
  }, []);

  const triggerDownload = async (id: string, kind: 'pdf' | 'json') => {
    try {
      await downloadReport(id, kind);
    } catch (e) {
      setErr(`Failed to download ${kind.toUpperCase()} report: ${e instanceof ApiError ? e.message : String(e)}`);
    }
  };

  const load = async (query = searchQuery, silent = false) => {
    if (!silent) setLoading(true);
    setErr('');
    const effectiveQuery = typeof query === 'string' ? query.trim() : '';
    try {
      const [s, list] = await Promise.all([
        jget('/dashboard'),
        jget(`/emails?limit=100${effectiveQuery ? `&q=${encodeURIComponent(effectiveQuery)}` : ''}`),
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
    const onUpdate = () => { void load(searchQuery, true); };
    window.addEventListener('soc:emails-updated', onUpdate);
    const timer = setInterval(() => { void load(searchQuery, true); }, 6000);
    return () => {
      window.removeEventListener('soc:emails-updated', onUpdate);
      clearInterval(timer);
    };
  }, [searchQuery]);

  const submit = async () => {
    if (!raw.trim()) return;
    setBusy(true);
    setErr('');
    setNotice('');
    try {
      if (asyncMode) {
        // Celery path (Phase 3 item 10): queue, then poll the task id.
        const taskRes = await jpost(`/emails/ingest?async_mode=true`, { raw });
        setNotice(`Queued background task ${taskRes.task_id} — polling for the verdict…`);
        const r = await pollTask(taskRes.task_id);
        setNotice(`Analyzed (background) - score ${r.fraud_score} (${r.classification}), action: ${r.action}`);
      } else {
        const r = await jpost('/emails/ingest', { raw });
        setNotice(`Analyzed - score ${r.fraud_score} (${r.classification}), action: ${r.action}`);
      }
      setRaw('');
      await load(searchQuery, false);
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
      await load(searchQuery, false);
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

  // Ingest source + analytics range + table sort (all client-side, existing data only)
  const [source, setSource] = useState<'paste' | 'upload' | 'gmail'>('paste');
  const [range, setRange] = useState<'24h' | '7d' | '30d' | 'all'>('7d');
  const [sortKey, setSortKey] = useState<'received' | 'score'>('received');
  const [sortDir, setSortDir] = useState<'ascending' | 'descending'>('descending');
  const [activityOpen, setActivityOpen] = useState<boolean>(() =>
    typeof window === 'undefined' ? true : !window.matchMedia('(max-width: 1023px)').matches);

  const scrollTo = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const newAnalysis = () => {
    setSource('paste');
    scrollTo('ingest-panel');
    setTimeout(() => document.getElementById('ingest-raw')?.focus(), 300);
  };

  const sevCounts = useMemo(() => {
    const c = { all: emails.length, critical: 0, high: 0, medium: 0, low: 0 };
    for (const e of emails) {
      const s = scores[e.id]?.score ?? -1;
      if (s >= 90) c.critical += 1;
      else if (s >= 75) c.high += 1;
      else if (s >= 50) c.medium += 1;
      else if (s >= 0) c.low += 1;
    }
    return c;
  }, [emails, scores]);

  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a, b) => {
      if (sortKey === 'score') {
        const sa = scores[a.id]?.score ?? -1;
        const sb = scores[b.id]?.score ?? -1;
        return sortDir === 'ascending' ? sa - sb : sb - sa;
      }
      const ta = new Date(a.timestamp).getTime() || 0;
      const tb = new Date(b.timestamp).getTime() || 0;
      return sortDir === 'ascending' ? ta - tb : tb - ta;
    });
    return arr;
  }, [filtered, scores, sortKey, sortDir]);

  const flipSort = (key: 'received' | 'score') => {
    if (sortKey === key) setSortDir(sortDir === 'ascending' ? 'descending' : 'ascending');
    else { setSortKey(key); setSortDir('descending'); }
  };

  // Ingest trend buckets from already-loaded emails (honest client-side range filter,
  // anchored to the newest loaded email so render stays pure)
  const trend = useMemo(() => {
    const end = Math.max(0, ...emails.map((e) => new Date(e.timestamp).getTime() || 0));
    const span = range === '24h' ? 864e5 : range === '7d' ? 7 * 864e5 : range === '30d' ? 30 * 864e5 : 0;
    const inRange = emails.filter((e) => {
      const t = new Date(e.timestamp).getTime() || 0;
      return !span || end - t <= span;
    });
    const buckets = new Map<string, number>();
    for (const e of inRange) {
      const d = new Date(e.timestamp);
      const key = range === '24h'
        ? `${d.getFullYear()}-${d.getMonth()}-${d.getDate()} ${d.getHours()}:00`
        : d.toISOString().slice(0, 10);
      buckets.set(key, (buckets.get(key) ?? 0) + 1);
    }
    return [...buckets.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).slice(-15);
  }, [emails, range]);
  const trendMax = Math.max(1, ...trend.map(([, v]) => v));

  const topCats = useMemo(() => {
    const entries = Object.entries(stats?.by_classification || {}) as [string, number][];
    return entries.sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [stats]);
  const topCatMax = Math.max(1, ...topCats.map(([, v]) => v));
  const chartVars = ['var(--chart-1)', 'var(--chart-2)', 'var(--chart-3)', 'var(--chart-4)', 'var(--chart-5)'];
  const riskOf = (s: number) => (s >= 90 ? 'critical' : s >= 75 ? 'high' : s >= 50 ? 'medium' : 'low');

  const blockedShare = stats?.total_emails ? Math.round((100 * (stats.blocked_threats || 0)) / Math.max(1, stats.total_emails)) : 0;

  return (
    <div className="page page-stack">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Threat Dashboard' }]} />
      <div className="greet-row">
        <div>
          <h1 className="greet-title">Global Threat Dashboard</h1>
          <p className="greet-sub">Real-time phishing, BEC and spoofing detection across ingested mail.</p>
        </div>
        <div className="greet-actions">
          <Button variant="ghost" onClick={() => { setRaw(PHISH_SAMPLE); newAnalysis(); }} title="Load a sample template">Template</Button>
          <Button variant="primary" onClick={newAnalysis}>+ New Analysis</Button>
        </div>
      </div>

      <div aria-live="polite">
        {err ? <Alert tone="error" title="Something needs attention">{err}</Alert> : null}
        {notice && !err ? <Alert tone="success">{notice}</Alert> : null}
      </div>

      {loading && !stats ? (
        <Card title="Loading dashboard"><Skeleton height={44} /><div style={{ height: 8 }} /><Skeleton height={120} /></Card>
      ) : (
        stats && (
          <>
            <Card title="Key metrics" description="Fleet-wide totals from the dashboard endpoint">
              <div className="kpi-strip">
                <div className="kpi"><div className="kpi__value">{stats.total_emails}</div><div className="kpi__label">Emails processed</div></div>
                <div className="kpi"><div className="kpi__value">{stats.blocked_threats}</div><div className="kpi__label">Blocked threats (≥75)</div><div className="kpi__sub"><span aria-hidden="true">▸</span>{blockedShare}% of all mail</div></div>
                <div className="kpi"><div className="kpi__value">{stats.active_campaigns}</div><div className="kpi__label">Active campaigns</div><div className="kpi__sub">shared infrastructure</div></div>
                <div className="kpi"><div className="kpi__value">{dist.critical}</div><div className="kpi__label">Critical (90–100)</div><div className="kpi__sub"><span aria-hidden="true">⬢</span>needs immediate triage</div></div>
                <div className="kpi"><div className="kpi__value">{Object.keys(stats.by_classification || {}).length}</div><div className="kpi__label">Classifications</div><div className="kpi__sub">{Object.entries(stats.by_classification || {}).slice(0, 2).map(([k, v]) => `${k}: ${v}`).join(' · ') || '—'}</div></div>
              </div>
            </Card>

            <Card
              title="Ingest email for analysis"
              description="Primary action area — pick a source, then analyze."
              actions={<Badge tone="info">paste · upload · Gmail</Badge>}
            >
              <div id="ingest-panel">
                <SegmentedControl
                  label="Ingest source"
                  value={source}
                  onChange={setSource}
                  options={[
                    { value: 'paste', label: 'Paste raw email' },
                    { value: 'upload', label: 'Upload .eml' },
                    { value: 'gmail', label: 'Gmail live import' },
                  ]}
                />
                <div style={{ marginTop: 12 }}>
                  <Well>
                    {source === 'paste' ? (
                      <>
                        <Textarea id="ingest-raw" label="Raw RFC822 message" rows={6} value={raw} onChange={(e) => setRaw(e.target.value)} placeholder="Paste raw RFC822 / .eml content here…" help="Nothing is sent until you press Analyze." />
                        <div className="row" style={{ marginTop: 10 }}>
                          <Button variant="primary" size="lg" onClick={submit} loading={busy} disabled={!raw.trim()}>Analyze email</Button>
                          <Toggle label="Background queue (Celery)" checked={asyncMode} onChange={(e) => setAsyncMode(e.target.checked)} />
                          <Button variant="ghost" size="sm" onClick={() => setRaw(PHISH_SAMPLE)}>Load phishing sample</Button>
                          <Button variant="ghost" size="sm" onClick={() => setRaw(CLEAN_SAMPLE)}>Load clean sample</Button>
                        </div>
                      </>
                    ) : source === 'upload' ? (
                      <>
                        <label className="neu-label" htmlFor="ingest-file" style={{ display: 'block', fontWeight: 600, fontSize: 13, marginBottom: 6 }}>Email file (.eml, .txt, .mime — max 5 MB)</label>
                        <input id="ingest-file" className="neu-input" type="file" accept=".eml,.txt,.mime" disabled={busy} onChange={(e) => onFile(e.target.files?.[0])} aria-describedby="ingest-file-help" />
                        <div id="ingest-file-help" className="neu-help">Analysis starts automatically when a file is chosen.</div>
                        {busy ? <div className="row" style={{ marginTop: 8 }}><Spinner label="Uploading and analyzing" /><span style={{ fontSize: 13 }}>Uploading and analyzing…</span></div> : null}
                      </>
                    ) : (
                      <GmailPanel onSynced={() => load()} bare />
                    )}
                  </Well>
                </div>
              </div>
            </Card>

            <Card
              title="Threat analytics"
              description="Severity share, ingest trend and top classifications."
              actions={
                <SegmentedControl
                  label="Analytics time range"
                  value={range}
                  onChange={setRange}
                  options={[
                    { value: '24h', label: '24h' }, { value: '7d', label: '7d' },
                    { value: '30d', label: '30d' }, { value: 'all', label: 'All' },
                  ]}
                />
              }
            >
              <div className="chart-grid">
                <div className="chart-block">
                  <h4>Emails by risk band</h4>
                  <p className="chart-sub">Critical {dist.critical} · High {dist.high} · Medium {dist.medium} · Low {dist.low}</p>
                  <div className="distbar" role="img" aria-label={`Score distribution: Critical ${dist.critical}, High ${dist.high}, Medium ${dist.medium}, Low ${dist.low}`}>
                    <div style={{ width: `${(100 * dist.critical) / distTotal}%`, background: 'var(--risk-critical)' }} />
                    <div style={{ width: `${(100 * dist.high) / distTotal}%`, background: 'var(--risk-high)' }} />
                    <div style={{ width: `${(100 * dist.medium) / distTotal}%`, background: 'var(--risk-medium)' }} />
                    <div style={{ width: `${(100 * dist.low) / distTotal}%`, background: 'var(--risk-low)' }} />
                  </div>
                  <div className="legend">
                    {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
                      <span key={s}><SeverityIcon severity={s} /> {s.charAt(0).toUpperCase() + s.slice(1)} {dist[s]}</span>
                    ))}
                  </div>
                </div>
                <div className="chart-block">
                  <h4>Ingest trend</h4>
                  <p className="chart-sub">{range === 'all' ? 'All loaded mail, by day' : `Last ${range}, loaded mail`}</p>
                  {trend.length === 0 ? (
                    <p className="chart-sub">No mail in this range yet.</p>
                  ) : (
                    <div className="trend-wrap">
                      <div className="trend" role="img" aria-label={`Ingest trend: ${trend.map(([k, v]) => `${k}: ${v}`).join(', ')}`}>
                        {trend.map(([k, v]) => (
                          <div key={k} className="trend-bar" title={`${k}: ${v}`} style={{ height: `${Math.max(4, (100 * v) / trendMax)}%` }} />
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                <div className="chart-block">
                  <h4>Top classifications</h4>
                  <p className="chart-sub">All-time counts from the dashboard endpoint</p>
                  {topCats.length === 0 ? <p className="chart-sub">No classifications yet.</p> : topCats.map(([name, v], i) => (
                    <div className="hbar-row" key={name}>
                      <span className="hbar-name" title={name}>{name}</span>
                      <span className="hbar-track"><span className="hbar-fill" style={{ display: 'block', width: `${(100 * v) / topCatMax}%`, background: chartVars[i % chartVars.length] }} /></span>
                      <span className="hbar-val">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            </Card>
          </>
        )
      )}

      <Card
        title="Recent threats"
        description="Every row opens the Email Analysis view."
        actions={<Badge tone="neutral">{sorted.length} shown</Badge>}
      >
        <div className="neu-segmented" role="group" aria-label="Filter by severity" style={{ marginBottom: 12 }}>
          {(['all', 'critical', 'high', 'medium', 'low'] as const).map((k) => (
            <button
              key={k}
              type="button"
              aria-pressed={sevFilter === k}
              title={k === 'all' ? 'All severities' : `${k} band`}
              onClick={() => setSevFilter(k)}
            >
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                {k === 'all' ? <span aria-hidden="true">◈</span> : <SeverityIcon severity={k} />}
                {k === 'all' ? 'All' : k.charAt(0).toUpperCase() + k.slice(1)}
                <b>{sevCounts[k]}</b>
              </span>
            </button>
          ))}
        </div>
        <div className="row" style={{ marginBottom: 12 }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <Input
              id="dash-search"
              label="Search threats"
              type="search"
              placeholder="Subject, sender, body…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') void load(searchQuery); }}
            />
          </div>
          <div className="row" style={{ alignSelf: 'end' }}>
            <Button variant="primary" size="sm" onClick={() => load(searchQuery)}>Search</Button>
            <Button variant="ghost" size="sm" onClick={() => load(searchQuery)}>Refresh</Button>
          </div>
        </div>
        <div id="all-emails">
          {loading ? <><Skeleton height={44} /><div style={{ height: 8 }} /><Skeleton height={44} /></> : sorted.length === 0 ? (
            <EmptyState
              message="No emails match. Ingest one above to get started."
              action={<Button variant="primary" size="sm" onClick={newAnalysis}>New analysis</Button>}
            />
          ) : (
            <Table label="Recent threats">
              <thead><tr>
                <th scope="col">Subject</th><th scope="col">Sender</th>
                <SortTh label="Received" direction={sortKey === 'received' ? sortDir : 'none'} onSort={() => flipSort('received')}>Received</SortTh>
                <SortTh label="Fraud score" direction={sortKey === 'score' ? sortDir : 'none'} onSort={() => flipSort('score')}>Verdict</SortTh>
                <th scope="col">Reports</th>
              </tr></thead>
              <tbody>
                {sorted.map((e) => {
                  const s = scores[e.id];
                  return (
                    <tr key={e.id}>
                      <td><Link to={`/email/${e.id}`}>{e.subject || '(no subject)'}</Link></td>
                      <td><span className="mono">{e.sender_address}</span></td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{formatDateTime(e.timestamp)}</td>
                      <td>
                        {s ? <SeverityBadge score={s.score} label={`${s.cls} ${s.score}`} /> : <span style={{ color: 'var(--text-muted)' }}>…</span>}
                      </td>
                      <td>
                        <div className="row" style={{ gap: 4, flexWrap: 'nowrap' }}>
                          <Button variant="ghost" size="sm" onClick={() => triggerDownload(e.id, 'pdf')}>PDF</Button>
                          <Button variant="ghost" size="sm" onClick={() => triggerDownload(e.id, 'json')}>JSON</Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>
          )}
        </div>
      </Card>

      <Card
        title="Activity"
        description="Latest scoring events across loaded mail."
        actions={
          <Button variant="ghost" size="sm" onClick={() => setActivityOpen(!activityOpen)} aria-expanded={activityOpen}>
            {activityOpen ? 'Collapse' : 'Expand'}
          </Button>
        }
      >
        {activityOpen ? (
          loading ? <Skeleton height={44} /> : filtered.length === 0 ? (
            <EmptyState message="Activity will appear once mail is ingested." />
          ) : (
            <ul className="activity-feed">
              {filtered.slice(0, 5).map((e) => {
                const s = scores[e.id];
                const sev = riskOf(s?.score ?? -1);
                return (
                  <li key={e.id} className="activity-item">
                    <SeverityIcon severity={s ? sev : 'unknown'} />
                    <div>
                      <div>System scored sender as <b>{s?.cls ?? '—'} {s?.score ?? ''}</b></div>
                      <div className="activity-time"><Link to={`/email/${e.id}`}>{(e.subject || '(no subject)').slice(0, 40)}</Link> · {formatDateTime(e.timestamp)}</div>
                    </div>
                  </li>
                );
              })}
            </ul>
          )
        ) : <p className="sub" style={{ margin: 0 }}>Collapsed — expand to review recent scoring events.</p>}
      </Card>

      <InternalLinks current="/" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Global Threat Dashboard - ThreatOptic',
        description: 'Real-time phishing and BEC detection dashboard', url: `${CANONICAL_BASE}/`,
        isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
    </div>
  );
}

/* ---------------- Graph SVG (Identity & Threat Correlation) ---------------- */

export function GraphSvg({ graph }: { graph: any }) {
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filterKind, setFilterKind] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [zoom, setZoom] = useState(1);
  const ct = useChartTheme();

  const rawNodes: any[] = graph?.nodes ?? [];
  const edges: any[] = graph?.edges ?? [];

  if (!rawNodes.length) {
    return <EmptyState message="No related entities yet — graph correlation links shared sender IPs, domains, and campaigns as emails are ingested." />;
  }

  // Deduplicate and normalize nodes
  const nodeMap = new Map<string, any>();
  rawNodes.forEach((n) => {
    const id = String(n.id || n);
    let kind = n.kind;
    if (!kind || kind === 'Unknown') {
      if (id.startsWith('email:')) kind = 'Email_Address';
      else if (id.startsWith('ip:')) kind = 'IP_Address';
      else if (id.startsWith('domain:')) kind = 'Domain';
      else if (id.startsWith('campaign:')) kind = 'Threat_Campaign';
      else kind = 'Entity';
    }
    nodeMap.set(id, { ...n, id, kind });
  });
  const nodes = Array.from(nodeMap.values());

  const w = 760;
  const h = 400;
  const cx = w / 2;
  const cy = h / 2;

  // Build adjacency map and degree count
  const degreeMap = new Map<string, number>();
  const neighborsMap = new Map<string, Set<string>>();
  nodes.forEach((n) => neighborsMap.set(n.id, new Set()));

  edges.forEach((e) => {
    degreeMap.set(e.source, (degreeMap.get(e.source) || 0) + 1);
    degreeMap.set(e.target, (degreeMap.get(e.target) || 0) + 1);
    if (neighborsMap.has(e.source)) neighborsMap.get(e.source)!.add(e.target);
    if (neighborsMap.has(e.target)) neighborsMap.get(e.target)!.add(e.source);
  });

  // Identify central focal node (highest degree or primary email)
  const sortedByDegree = [...nodes].sort((a, b) => (degreeMap.get(b.id) || 0) - (degreeMap.get(a.id) || 0));
  const centerId = sortedByDegree.length > 0 && (degreeMap.get(sortedByDegree[0].id) || 0) >= 1 ? sortedByDegree[0].id : nodes[0]?.id;

  // Position calculation with multi-ring topology
  const posMap = new Map<string, { x: number; y: number }>();
  if (nodes.length === 1) {
    posMap.set(nodes[0].id, { x: cx, y: cy });
  } else if (nodes.length === 2) {
    posMap.set(nodes[0].id, { x: cx - 140, y: cy });
    posMap.set(nodes[1].id, { x: cx + 140, y: cy });
  } else {
    // Center focal entity at the center
    posMap.set(centerId, { x: cx, y: cy });
    const otherNodes = nodes.filter((n) => n.id !== centerId);

    // Group remaining nodes by kind for cohesive cluster distribution
    const domains = otherNodes.filter((n) => n.kind === 'Domain');
    const ips = otherNodes.filter((n) => n.kind === 'IP_Address');
    const emails = otherNodes.filter((n) => n.kind === 'Email_Address');
    const campaigns = otherNodes.filter((n) => n.kind === 'Threat_Campaign');
    const others = otherNodes.filter((n) => !['Domain', 'IP_Address', 'Email_Address', 'Threat_Campaign'].includes(n.kind));

    const orderedSatellites = [...domains, ...ips, ...campaigns, ...emails, ...others];
    const baseRadius = Math.min(w, h) * 0.38;

    orderedSatellites.forEach((n, idx) => {
      // Alternate radial distance slightly to prevent dense cluster label collisions
      const rOffset = (idx % 2 === 0 ? 0 : 25) + (n.kind === 'Threat_Campaign' ? 20 : 0);
      const rad = baseRadius + rOffset;
      const angle = (idx / orderedSatellites.length) * 2 * Math.PI - Math.PI / 2;
      posMap.set(n.id, {
        x: cx + rad * Math.cos(angle),
        y: cy + rad * Math.sin(angle),
      });
    });
  }

  // Active focus calculation
  const activeFocusId = hoveredId || selectedId;
  const connectedToActive = activeFocusId ? neighborsMap.get(activeFocusId) || new Set() : null;

  const getColor = (k: string) => {
    // Entity colors fixed by type (Design.md §7.2), resolved via useChartTheme
    // so the canvas re-renders with new-theme values instead of stale ones.
    return ct.entity[k] ?? ct.entity.Entity;
  };

  const getIcon = (k: string) => {
    switch (k) {
      case 'Domain': return 'D';
      case 'IP_Address': return 'IP';
      case 'Threat_Campaign': return '⚡';
      case 'Email_Address': return '@';
      default: return '◈';
    }
  };

  const getCleanLabel = (id: string) => String(id).replace(/^(email|ip|domain|campaign):/, '');

  // Filter kinds summary
  const availableKinds = Array.from(new Set(nodes.map((n) => n.kind)));

  const selectedNodeData = selectedId ? nodeMap.get(selectedId) : null;
  const selectedEdges = selectedId ? edges.filter((e) => e.source === selectedId || e.target === selectedId) : [];

  const handleCopy = (text: string) => {
    void navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {/* Top Controls & Legend Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8, padding: '4px 2px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--muted)', marginRight: 4 }}>
            {nodes.length} Nodes · {edges.length} Edges
          </span>
          {availableKinds.map((k) => (
            <button
              key={k}
              type="button"
              className="ghost small"
              onClick={() => setFilterKind(filterKind === k ? null : k)}
              style={{
                fontSize: 11,
                padding: '2px 8px',
                borderRadius: 12,
                border: `1px solid ${getColor(k)}`,
                color: filterKind === k ? ct.onBright : getColor(k),
                background: filterKind === k ? getColor(k) : 'transparent',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              ● {k.replace('_', ' ')}
            </button>
          ))}
          {filterKind && (
            <button type="button" className="ghost small" onClick={() => setFilterKind(null)} style={{ fontSize: 11 }}>
              Clear Filter
            </button>
          )}
        </div>

        {/* Zoom Controls */}
        <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
          <Tooltip label="Zoom out"><button type="button" className="ghost small" onClick={() => setZoom((z) => Math.max(0.7, z - 0.15))} aria-label="Zoom out" style={{ padding: '2px 8px' }}>−</button></Tooltip>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', minWidth: 38, textAlign: 'center' }} aria-live="polite">{Math.round(zoom * 100)}%</span>
          <Tooltip label="Zoom in"><button type="button" className="ghost small" onClick={() => setZoom((z) => Math.min(1.6, z + 0.15))} aria-label="Zoom in" style={{ padding: '2px 8px' }}>+</button></Tooltip>
          {zoom !== 1 && (
            <Tooltip label="Reset zoom to fit"><button type="button" className="ghost small" onClick={() => setZoom(1)} aria-label="Reset zoom to fit" style={{ fontSize: 11, padding: '2px 6px' }}>Reset</button></Tooltip>
          )}
        </div>
      </div>
      <div className="graph-legend" aria-label="Entity type legend">
        {availableKinds.map((k) => (
          <span key={k} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <span aria-hidden="true" style={{ width: 10, height: 10, borderRadius: '50%', background: getColor(k) }} />
            {k.replace('_', ' ')}
          </span>
        ))}
      </div>

      <div className="graph-layout">
      {/* SVG Visualization Canvas */}
      <div className="graph-canvas" style={{ position: 'relative', overflow: 'hidden', borderRadius: 16, border: '1px solid var(--border-subtle)', background: 'var(--surface-inset)' }}>
        <svg
          width="100%"
          viewBox={`0 0 ${w} ${h}`}
          role="img"
          aria-label="Identity and threat infrastructure correlation graph"
          style={{
            display: 'block',
            transform: `scale(${zoom})`,
            transformOrigin: 'center center',
            transition: 'transform 0.15s ease-out',
          }}
        >
          <title>Identity correlation & threat attribution graph</title>
          <desc>Interactive graph showing relationships between senders, domains, IPs and threat campaigns.</desc>
          <defs>
            <filter id="glow-strong" x="-30%" y="-30%" width="160%" height="160%">
              <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor={ct.accentInfo} floodOpacity="0.6" />
            </filter>
            <filter id="glow-node" x="-30%" y="-30%" width="160%" height="160%">
              <feDropShadow dx="0" dy="0" stdDeviation="3" floodColor={ct.textPrimary} floodOpacity="0.3" />
            </filter>
            <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill={ct.charts[0]} fillOpacity="0.8" />
            </marker>
            <marker id="arrow-highlight" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M 0 0.5 L 10 5 L 0 9.5 z" fill={ct.accentInfo} />
            </marker>
          </defs>

          {/* Grid background lines */}
          <g opacity={0.12}>
            {Array.from({ length: 11 }).map((_, i) => (
              <line key={`gx-${i}`} x1={i * 76} y1={0} x2={i * 76} y2={h} stroke={ct.textMuted} strokeWidth={1} strokeDasharray="3,3" />
            ))}
            {Array.from({ length: 6 }).map((_, i) => (
              <line key={`gy-${i}`} x1={0} y1={i * 80} x2={w} y2={i * 80} stroke={ct.textMuted} strokeWidth={1} strokeDasharray="3,3" />
            ))}
          </g>

          {/* Edges */}
          {edges.map((e, i) => {
            const a = posMap.get(e.source);
            const b = posMap.get(e.target);
            if (!a || !b) return null;

            const isHighlighted = activeFocusId ? (e.source === activeFocusId || e.target === activeFocusId) : true;
            const isDimmed = activeFocusId ? !isHighlighted : filterKind ? (nodeMap.get(e.source)?.kind !== filterKind && nodeMap.get(e.target)?.kind !== filterKind) : false;

            const mx = (a.x + b.x) / 2;
            const my = (a.y + b.y) / 2;

            return (
              <g key={`edge-${i}`} opacity={isDimmed ? 0.15 : 1} style={{ transition: 'opacity 0.2s' }}>
                <line
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke={isHighlighted && activeFocusId ? ct.accentInfo : ct.charts[0]}
                  strokeWidth={isHighlighted && activeFocusId ? 2.8 : 1.8}
                  strokeOpacity={isHighlighted && activeFocusId ? 1 : 0.65}
                  markerEnd={isHighlighted && activeFocusId ? 'url(#arrow-highlight)' : 'url(#arrow)'}
                />
                {e.rel && (
                  <g transform={`translate(${mx}, ${my})`}>
                    <rect
                      x={-e.rel.length * 3.4 - 5}
                      y={-9}
                      width={e.rel.length * 6.8 + 10}
                      height={16}
                      rx={4}
                      fill={ct.surfaceInset}
                      stroke={isHighlighted && activeFocusId ? ct.accentInfo : ct.border}
                      strokeWidth={0.9}
                    />
                    <text x={0} y={2.8} fill={isHighlighted && activeFocusId ? ct.textPrimary : ct.textMuted} fontSize={8} fontWeight={700} textAnchor="middle">
                      {e.rel}
                    </text>
                  </g>
                )}
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((n) => {
            const p = posMap.get(n.id) || { x: cx, y: cy };
            const lbl = getCleanLabel(n.id);
            const isCenter = n.id === centerId;
            const isSelected = n.id === selectedId;
            const isHovered = n.id === hoveredId;
            const isConnected = connectedToActive ? (n.id === activeFocusId || connectedToActive.has(n.id)) : true;
            const isKindFiltered = filterKind ? n.kind === filterKind : true;

            const isDimmed = (activeFocusId && !isConnected) || (!activeFocusId && !isKindFiltered);
            const baseR = isCenter ? 22 : 17;
            const r = (isSelected || isHovered) ? baseR + 3 : baseR;
            const nodeColor = getColor(n.kind);

            return (
              <g
                key={n.id}
                tabIndex={0}
                role="button"
                aria-label={`${n.kind.replace('_', ' ')}: ${lbl}`}
                transform={`translate(${p.x}, ${p.y})`}
                opacity={isDimmed ? 0.25 : 1}
                style={{ cursor: 'pointer', transition: 'opacity 0.2s, transform 0.15s' }}
                onMouseEnter={() => setHoveredId(n.id)}
                onMouseLeave={() => setHoveredId(null)}
                onClick={() => setSelectedId(selectedId === n.id ? null : n.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    setSelectedId(selectedId === n.id ? null : n.id);
                  }
                }}
              >
                <title>{`${n.kind.replace('_', ' ')}: ${lbl}\nClick to inspect details`}</title>

                {/* Selection or Center pulse ring */}
                {(isCenter || isSelected || isHovered) && (
                  <circle
                    r={r + 6}
                    fill="none"
                    stroke={nodeColor}
                    strokeWidth={isSelected ? 2.5 : 1.5}
                    strokeDasharray={isCenter ? '3,3' : undefined}
                    opacity={isSelected ? 0.9 : 0.5}
                  />
                )}

                {/* Main Node Circle */}
                <circle
                  r={r}
                  fill={nodeColor}
                  stroke={ct.surfaceInset}
                  strokeWidth={2.5}
                  filter={isSelected || isHovered ? 'url(#glow-strong)' : 'url(#glow-node)'}
                />

                {/* Node Icon / Letter */}
                <text y={4} fill={ct.onBright} fontSize={isCenter ? 12 : 10} fontWeight={900} textAnchor="middle">
                  {getIcon(n.kind)}
                </text>

                {/* Primary Entity Label */}
                <g transform={`translate(0, ${r + 14})`}>
                  <rect
                    x={-Math.min(lbl.length * 3.4, 60) - 4}
                    y={-7}
                    width={Math.min(lbl.length * 6.8, 120) + 8}
                    height={15}
                    rx={3}
                    fill={ct.surfaceInset}
                    stroke={ct.border}
                    strokeWidth={0.75}
                  />
                  <text
                    y={3.5}
                    fill={ct.textPrimary}
                    fontSize={10.5}
                    fontWeight={isSelected || isHovered ? 700 : 600}
                    textAnchor="middle"
                  >
                    {lbl.length > 20 ? lbl.slice(0, 18) + '…' : lbl}
                  </text>
                </g>

                {/* Node Kind Badge */}
                <text y={r + 28} fill={ct.textMuted} fontSize={8.5} fontWeight={500} textAnchor="middle">
                  {n.kind.replace('_', ' ')}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Selected Entity Details Card */}
      {selectedNodeData && (
        <div className="card" style={{ background: 'var(--surface-inset)', border: `1px solid ${getColor(selectedNodeData.kind)}`, padding: 12, marginTop: 4 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 8 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span
                  style={{
                    background: getColor(selectedNodeData.kind),
                    color: ct.onBright,
                    fontSize: 11,
                    fontWeight: 800,
                    padding: '2px 8px',
                    borderRadius: 4,
                  }}
                >
                  {selectedNodeData.kind.replace('_', ' ')}
                </span>
                <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                  {getCleanLabel(selectedNodeData.id)}
                </span>
              </div>
              <p style={{ margin: '2px 0 0 0', fontSize: 12, color: 'var(--muted)' }}>
                Degree: <b>{degreeMap.get(selectedNodeData.id) || 0}</b> connected entities
              </p>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <button
                type="button"
                className="ghost small"
                onClick={() => handleCopy(getCleanLabel(selectedNodeData.id))}
                style={{ fontSize: 11 }}
              >
                {copied ? '✓ Copied' : 'Copy Value'}
              </button>
              <button
                type="button"
                className="ghost small"
                onClick={() => setSelectedId(null)}
                style={{ fontSize: 11 }}
              >
                ✕ Close
              </button>
            </div>
          </div>

          {/* Connected Links Breakdown */}
          {selectedEdges.length > 0 && (
            <div style={{ marginTop: 10, paddingTop: 8, borderTop: '1px solid var(--border)' }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--muted)', display: 'block', marginBottom: 6 }}>
                Direct Relationships ({selectedEdges.length}):
              </span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {selectedEdges.map((e, idx) => {
                  const targetId = e.source === selectedNodeData.id ? e.target : e.source;
                  const isOutgoing = e.source === selectedNodeData.id;
                  const targetNode = nodeMap.get(targetId);
                  const targetKind = targetNode?.kind || 'Entity';
                  return (
                    <div
                      key={idx}
                      onClick={() => setSelectedId(targetId)}
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 6,
                        background: 'var(--surface-raised)',
                        border: '1px solid var(--border)',
                        padding: '3px 8px',
                        borderRadius: 6,
                        fontSize: 11,
                        cursor: 'pointer',
                      }}
                      title="Click to jump to this entity"
                    >
                      <span style={{ color: 'var(--accent-info)', fontWeight: 700 }}>
                        {isOutgoing ? `→ ${e.rel || 'LINKS'}` : `← ${e.rel || 'LINKS'}`}
                      </span>
                      <span style={{ color: getColor(targetKind), fontWeight: 600 }}>
                        {getCleanLabel(targetId)}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
      </div>
    </div>
  );
}


/* ---------------- Email detail ---------------- */

const TABS = ['Summary', 'Why this score?', 'Header Forensics', 'GeoLocation', 'Graph View'] as const;

function ScoreWhy({ breakdown, score }: { breakdown: any[]; score: number }) {
  const rows = [...(breakdown || [])].sort(
    (x, y) => (y.contribution_to_score ?? 0) - (x.contribution_to_score ?? 0),
  );
  if (!rows.length) return <EmptyState message="No score breakdown stored for this email (analyzed before explainability was added)." />;
  const maxAbs = Math.max(1, ...rows.map((r) => Math.abs(r.contribution_to_score ?? 0)));
  return (
    <div>
      <p className="sub">
        Each bar is a signal's point contribution to the final fraud score of <b>{score}</b> (weights × values ± rules).
        Violet raises risk, teal lowers it — values are always stated as text.
      </p>
      <ul className="contrib">
        {rows.map((s) => {
          const c = s.contribution_to_score ?? 0;
          const w = (100 * Math.abs(c)) / maxAbs;
          // Brand pair (violet/teal + neutral) — never the risk palette.
          const bar = c > 0 ? 'var(--accent-secondary)' : c < 0 ? 'var(--chart-4)' : 'var(--text-muted)';
          return (
            <li key={s.signal_name}>
              <span className="contrib-top"><code>{s.signal_name}</code> <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>×{s.weight} · value {String(s.value)}</span></span>
              <b style={{ fontVariantNumeric: 'tabular-nums' }}>{c > 0 ? `+${c}` : c}</b>
              <span className="contrib-bar" role="img" aria-label={`${s.signal_name} contributes ${c > 0 ? '+' : ''}${c} points`}>
                <span className="contrib-fill" style={{ display: 'block', width: `${w}%`, background: bar }} />
              </span>
              {s.detail ? <span style={{ gridColumn: '1 / -1', color: 'var(--text-muted)', fontSize: 12 }}>{s.detail}</span> : null}
            </li>
          );
        })}
      </ul>
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
    title: d ? `${subject} - Score ${fraudScore} - ThreatOptic` : `ThreatOptic`,
    description: d ? `Forensic analysis for "${subject}" - classification ${d.analysis?.threat_classification || 'unknown'}, action ${d.analysis?.action_taken || '-'}, authentication and geolocation trace.` : 'Email forensic detail with header chain, geolocation and identity graph.',
    canonical: `/email/${id}`,
    image: 'https://email-scanner-chi.vercel.app/og-image.svg',
  });

  useEffect(() => {
    setErr('');
    setD(null);
    let cancelled = false;
    jget(`/emails/${encodeURIComponent(id)}`).then((v) => { if (!cancelled) setD(v); }).catch((e) => { if (!cancelled) setErr(e instanceof ApiError ? `Could not load email (${e.status}): ${e.message}` : String(e)); });
    jget('/cases').then((v) => { if (!cancelled) setCases(v); }).catch(() => {});
    return () => { cancelled = true; };
  }, [id]);

  const linkToCase = async () => {
    if (!caseId) return;
    try {
      const targetCase = cases.find((c: any) => c.id === caseId);
      const existing = targetCase?.email_ids || [];
      if (!existing.includes(id)) {
        await jpatch(`/cases/${encodeURIComponent(caseId)}`, { email_ids: [...existing, id] });
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

  if (err) return <div className="page page-stack"><Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Email', href: '/' }, { label: 'Error' }]} /><Link to="/">← back</Link><ErrorState message={/\(404\)/.test(err) ? 'This email was not found. It may have been purged by retention, or belong to a different workspace.' : 'Could not load this email.'} detail={err} onRetry={() => window.location.reload()} /></div>;
  if (!d) return <div className="page page-stack"><Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Email' }]} /><Link to="/">← back</Link><Card title="Loading email"><Skeleton height={44} /><div style={{ height: 8 }} /><Skeleton height={160} /></Card></div>;
  const a = d.analysis || {};
  const t = d.trace || {};
  const auth = a.authentication_results || {};
  const relay: any[] = Array.isArray(t.relay_chain) ? t.relay_chain : [];
  const fraud = a.fraud_score ?? 0;
  const hasCoords = t.geolocation?.lat != null && t.geolocation?.lon != null && !isNaN(Number(t.geolocation.lat)) && !isNaN(Number(t.geolocation.lon));

  return (
    <div className="page page-stack">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Dashboard', href: '/' }, { label: subject.slice(0, 36) || 'Email Detail' }]} />
      <Card
        actions={
          <>
            {cases.length > 0 ? (
              <span className="row" id="email-case-row" style={{ gap: 8 }}>
                <span style={{ maxWidth: 240 }}>
                  <Select label="Investigation case" value={caseId} onChange={(e) => setCaseId(e.target.value)}>
                    <option value="">Select a case…</option>
                    {cases.map((c: any) => (
                      <option key={c.id} value={c.id}>{c.title} ({c.status})</option>
                    ))}
                  </Select>
                </span>
                <Button variant="primary" size="sm" onClick={linkToCase} disabled={!caseId}>Link to case</Button>
              </span>
            ) : null}
            <details className="collapsible">
              <summary className="neu-btn neu-btn--ghost neu-btn--sm" style={{ textDecoration: 'none' }}>Export ▾</summary>
              <div className="row" style={{ marginTop: 8 }}>
                <Button variant="ghost" size="sm" onClick={() => triggerDownload('pdf')}>Forensic PDF</Button>
                <Button variant="ghost" size="sm" onClick={() => triggerDownload('json')}>JSON</Button>
              </div>
            </details>
          </>
        }
      >
        <Link to="/">← back to dashboard</Link>
        <Tooltip label={d.email.subject || '(no subject)'}>
          <h1 className="case-head__subject" style={{ marginTop: 8 }}>{d.email.subject || '(no subject)'}</h1>
        </Tooltip>
        <div className="case-meta">
          <span>From <span className="mono">{d.email.sender_address || 'unknown sender'}</span></span>
          <span className="dot-sep" aria-hidden="true">·</span>
          <SeverityBadge score={fraud} label={`${a.threat_classification || 'Unclassified'} ${fraud}`} />
          <span className="dot-sep" aria-hidden="true">·</span>
          <span>action: <b>{a.action_taken || '—'}</b></span>
          <span className="dot-sep" aria-hidden="true">·</span>
          <span>received: <b>{formatDateTime(d.email.timestamp)}</b></span>
        </div>
        <div className="case-score" style={{ marginTop: 12 }}>
          <span className="case-score__num" aria-label={`Fraud score ${fraud} out of 100`}>{fraud}</span>
          <span className="hbar-track" role="img" aria-label={`Fraud score ${fraud} of 100`} style={{ display: 'block', maxWidth: 280, flex: 1, height: 10, borderRadius: 5, background: 'var(--surface-inset)', border: '1px solid var(--border-subtle)', overflow: 'hidden' }}>
            <span style={{ display: 'block', height: '100%', width: `${Math.max(0, Math.min(100, fraud))}%`, background: 'var(--risk-high)' }} />
          </span>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>/ 100</span>
        </div>
        <div aria-live="polite">
          {caseNotice ? <Alert tone="success">{caseNotice}</Alert> : null}
        </div>
      </Card>

      <Tabs tabs={[...TABS]} active={tab} onChange={setTab} label="Email analysis views" />

      <Well>
        <div role="tabpanel" id={`email-tabpanel-${tab}`} aria-label={TABS[tab]}>
          {tab === 0 && (
            <>
              <section aria-label="Verdict and key indicators">
                <h2 style={{ marginTop: 0, fontSize: 16 }}>Verdict</h2>
                <dl className="deflist">
                  <dt>Fraud score</dt><dd><SeverityBadge score={fraud} /> {a.threat_classification}</dd>
                  <dt>Action</dt><dd>{a.action_taken || '—'}</dd>
                  <dt>SPF / DKIM / DMARC</dt>
                  <dd>
                    <span style={{ display: 'inline-flex', gap: 6, flexWrap: 'wrap' }}>
                      <AuthPill name="SPF" status={auth.spf?.status} />
                      <AuthPill name="DKIM" status={auth.dkim?.status} />
                      <AuthPill name="DMARC" status={auth.dmarc?.status} />
                      <AuthPill name="Alignment" status={auth.aligned ? 'aligned' : 'unaligned'} />
                    </span>
                  </dd>
                  <dt>NLP cues</dt>
                  <dd>{(a.nlp_cues_detected || []).length === 0 ? 'None' : (a.nlp_cues_detected || []).join(', ')}</dd>
                </dl>
              </section>
              <hr className="section-divider" />
              <section aria-label="Supporting evidence">
                <h2 style={{ marginTop: 0, fontSize: 16 }}>Supporting evidence</h2>
                <div className="grid-2">
                  <div>
                    <h3 style={{ margin: '0 0 8px', fontSize: 14 }}>Authentication detail</h3>
                    {(auth.spf?.detail || auth.dkim?.detail || auth.dmarc?.detail) ? (
                      <dl className="deflist" style={{ gridTemplateColumns: '70px 1fr' }}>
                        {auth.spf?.detail ? <><dt>SPF</dt><dd>{auth.spf.detail}</dd></> : null}
                        {auth.dkim?.detail ? <><dt>DKIM</dt><dd>{auth.dkim.detail}</dd></> : null}
                        {auth.dmarc?.detail ? <><dt>DMARC</dt><dd>{auth.dmarc.detail}</dd></> : null}
                      </dl>
                    ) : <p className="sub">No authentication detail recorded.</p>}
                    <h3 style={{ margin: '16px 0 8px', fontSize: 14 }}>Body (PII masked)</h3>
                    <pre className="dump" style={{ whiteSpace: 'pre-wrap' }}>{d.email.body_text_masked || '(empty)'}</pre>
                  </div>
                  <div>
                    <h3 style={{ margin: '0 0 8px', fontSize: 14 }}>Threat intel hits ({(a.threat_intel_hits || []).length})</h3>
                    {(a.threat_intel_hits || []).length === 0 ? <p className="sub">No hits.</p> : (
                      <Table label="Threat intelligence hits">
                        <thead><tr><th scope="col">Type</th><th scope="col">Value</th><th scope="col">Reason</th></tr></thead>
                        <tbody>
                          {(a.threat_intel_hits || []).slice(0, 20).map((h: any, i: number) => (
                            <tr key={i}>
                              <td>{h.type}</td>
                              <td><span className="mono">{String(h.value ?? h.url ?? '').slice(0, 80)}</span></td>
                              <td style={{ fontSize: 12 }}>{(h.reasons || []).join(', ') || (h.blocklisted ? 'blocklisted' : 'hit')}</td>
                            </tr>
                          ))}
                        </tbody>
                      </Table>
                    )}
                  </div>
                </div>
              </section>
            </>
          )}

          {tab === 1 && (
            <section aria-label="Why this score">
              <h2 style={{ marginTop: 0, fontSize: 16 }}>Why this score?</h2>
              <ScoreWhy breakdown={a.score_breakdown} score={fraud} />
            </section>
          )}

          {tab === 2 && (
            <>
              <section aria-label="Chain of custody">
                <h2 style={{ marginTop: 0, fontSize: 16 }}>Chain of custody</h2>
                <dl className="deflist">
                  <dt>SHA-256 (.eml)</dt><dd><span className="mono">{d.email.raw_eml_hash}</span> <CopyButton text={String(d.email.raw_eml_hash || '')} label="Copy hash" /></dd>
                  <dt>Message-ID</dt><dd><span className="mono">{d.email.message_id || '-'}</span> {d.email.message_id ? <CopyButton text={String(d.email.message_id)} label="Copy ID" /> : null}</dd>
                  <dt>Relay hops</dt><dd>{relay.length}</dd>
                </dl>
              </section>
              <hr className="section-divider" />
              <div className="grid-2">
                <section aria-label="Parsed relay path">
                  <h2 style={{ marginTop: 0, fontSize: 16 }}>Relay path (origin first)</h2>
                  {relay.length === 0 ? <EmptyState message="No Received headers — sender path unverifiable." /> : (
                    <ol className="timeline">
                      {relay.map((h: any, i: number) => (
                        <li key={i}>
                          <div><b>Hop {i + 1}</b> — from <span className="mono">{h.from_host || '?'}</span> by <span className="mono">{h.by_host || '?'}</span></div>
                          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>IPs: {(h.ips || []).map((ip: string) => <span key={ip} className="mono" style={{ marginRight: 4 }}>{ip}</span>)}
                            {(h.ips || []).length === 0 && 'none parsed'}</div>
                        </li>
                      ))}
                    </ol>
                  )}
                </section>
                <section aria-label="Raw headers">
                  <h2 style={{ marginTop: 0, fontSize: 16 }}>Raw chain</h2>
                  <pre className="dump">{JSON.stringify(relay, null, 2)}</pre>
                  <div className="row" style={{ marginTop: 8 }}>
                    <CopyButton text={JSON.stringify(relay, null, 2)} label="Copy raw chain" />
                  </div>
                </section>
              </div>
            </>
          )}

          {tab === 3 && (
            <>
              <section aria-label="Origin and map">
                <h2 style={{ marginTop: 0, fontSize: 16 }}>Origin</h2>
                <dl className="deflist">
                  <dt>Origin IP</dt>
                  <dd>
                    <span className="mono">{t.origin_ip || '-'}</span>
                    {t.geolocation?.is_private ? <Badge tone="neutral">Private RFC1918</Badge> : null}
                  </dd>
                  <dt>Country / City</dt><dd>{t.geolocation ? `${t.geolocation.country || '?'} / ${t.geolocation.city || '?'}` : '-'} {t.geolocation?.source ? <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>({t.geolocation.source})</span> : null}</dd>
                  <dt>ISP / ASN</dt><dd>{t.isp_asn || t.geolocation?.isp || '-'}</dd>
                  <dt>VPN / TOR</dt><dd>{String(t.is_vpn_tor)}</dd>
                  <dt>Coordinates</dt>
                  <dd className="mono">{hasCoords ? `${Number(t.geolocation.lat).toFixed(4)}, ${Number(t.geolocation.lon).toFixed(4)}` : '-'}</dd>
                </dl>
                <div style={{ marginTop: 12 }}>
                  {hasCoords ? (
                    <>
                      <div className="map-frame">
                        <iframe
                          title="Geolocation map of email origin"
                          width="100%"
                          height="380"
                          style={{ border: 0 }}
                          loading="lazy"
                          sandbox="allow-scripts allow-same-origin allow-popups"
                          referrerPolicy="no-referrer-when-downgrade"
                          src={`https://www.openstreetmap.org/export/embed.html?bbox=${Number(t.geolocation.lon) - 4}%2C${Number(t.geolocation.lat) - 4}%2C${Number(t.geolocation.lon) + 4}%2C${Number(t.geolocation.lat) + 4}&layer=mapnik&marker=${Number(t.geolocation.lat)}%2C${Number(t.geolocation.lon)}`}
                        />
                      </div>
                      <p className="sub" style={{ marginTop: 8, marginBottom: 0 }}>
                        Origin IP <span className="mono">{t.origin_ip || '—'}</span>
                        {t.geolocation?.city || t.geolocation?.country ? ` — ${t.geolocation.city || ''}${t.geolocation.city && t.geolocation.country ? ', ' : ''}${t.geolocation.country || ''}` : ''}
                        {' · '}<a target="_blank" rel="noreferrer" href={`https://www.openstreetmap.org/?mlat=${t.geolocation.lat}&mlon=${t.geolocation.lon}#map=7/${t.geolocation.lat}/${t.geolocation.lon}`}>Open full map (OSM)</a>
                      </p>
                    </>
                  ) : (
                    <EmptyState message="No coordinates available — sender origin IP is unresolvable or network lookups are offline." />
                  )}
                </div>
              </section>
              <hr className="section-divider" />
              <details className="collapsible">
                <summary>Secondary evidence (WHOIS, DNS)</summary>
                <div className="grid-2" style={{ marginTop: 12 }}>
                  <section aria-label="WHOIS record">
                    <h3 style={{ margin: '0 0 8px', fontSize: 14 }}>WHOIS</h3>
                    <pre className="dump">{JSON.stringify(t.whois, null, 2)}</pre>
                  </section>
                  <section aria-label="DNS records">
                    <h3 style={{ margin: '0 0 8px', fontSize: 14 }}>DNS</h3>
                    <pre className="dump">{JSON.stringify(t.dns, null, 2)}</pre>
                  </section>
                </div>
              </details>
            </>
          )}

          {tab === 4 && (
            <section aria-label="Identity correlation graph">
              <h2 style={{ marginTop: 0, fontSize: 16 }}>Identity correlation</h2>
              <p className="sub" style={{ marginTop: 0 }}>Trace node graph — domain linked to related campaign entities.</p>
              <GraphSvg graph={graph} />
              <details className="collapsible" style={{ marginTop: 12 }}>
                <summary>Raw graph JSON</summary>
                <pre className="dump" style={{ marginTop: 8 }}>{JSON.stringify(graph, null, 2)}</pre>
              </details>
            </section>
          )}
        </div>
      </Well>

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
    title: 'Campaigns - Shared Infrastructure Clusters - ThreatOptic',
    description: 'Graph-detected campaign clusters sharing sender infrastructure, domains and IPs. Analyze confidence, attribution and forensic timelines.',
    canonical: '/campaigns',
    image: 'https://email-scanner-chi.vercel.app/og-image.svg',
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
    <div className="page page-stack">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Campaigns' }]} />
      <div className="greet-row">
        <div>
          <h1 className="greet-title">Campaigns</h1>
          <p className="greet-sub">Graph-detected clusters: domains sharing sender infrastructure, joined with forensic records.</p>
        </div>
        <div className="greet-actions">
          <Badge tone="neutral">{cards.length} clusters</Badge>
        </div>
      </div>
      {err ? <Alert tone="error" title="Campaigns unavailable">{err}</Alert> : null}
      {loading ? <Card title="Loading campaigns"><Skeleton height={44} /><div style={{ height: 8 }} /><Skeleton height={120} /></Card> : cards.length === 0 ? (
        <Card title="No campaigns">
          <EmptyState
            message="No campaigns yet — ingest more mail sharing IPs/domains."
            action={<Link to="/" className="neu-btn neu-btn--primary neu-btn--sm">Ingest email</Link>}
          />
        </Card>
      ) : (
        <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))' }}>
          {cards.map((k) => (
            <Card
              key={k.id}
              title={k.name}
              description={`${k.email_count} emails · IP ${k.ip}`}
              actions={<Badge tone="info">⚡ {Math.round((k.confidence ?? 0) * 100)}% confidence</Badge>}
            >
              <dl className="deflist" style={{ gridTemplateColumns: '110px 1fr' }}>
                <dt>ASN</dt><dd>{k.asn || '-'}</dd>
                <dt>Domains</dt><dd>{(k.domains || []).map((d: string) => <span key={d} className="mono" style={{ marginRight: 4 }}>{d}</span>)}</dd>
                <dt>First seen</dt><dd style={{ fontSize: 12 }}>{formatDateTime(k.first_seen)}</dd>
                <dt>Last seen</dt><dd style={{ fontSize: 12 }}>{formatDateTime(k.last_seen)}</dd>
              </dl>
              <div className="row" style={{ marginTop: 12 }}>
                <span style={{ flex: 1 }} />
                <Link to={`/campaign/${k.id}`} className="neu-btn neu-btn--primary neu-btn--sm">Open campaign →</Link>
              </div>
            </Card>
          ))}
        </div>
      )}
      <InternalLinks current="/campaigns" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'CollectionPage', name: 'Campaigns - ThreatOptic',
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
    title: `${cardName} - Campaign Detail - ThreatOptic`,
    description: d ? `Campaign ${cardName} with ${d.card.email_count} emails, confidence ${Math.round(d.card.confidence * 100)}%, shared IP ${d.card.ip}. Attribution graph and email list.` : 'Campaign attribution detail with graph and forensic emails.',
    canonical: `/campaign/${id}`,
    image: 'https://email-scanner-chi.vercel.app/og-image.svg',
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
  if (err) return <div className="page page-stack"><Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Campaigns', href: '/campaigns' }, { label: 'Error' }]} /><Link to="/campaigns">← campaigns</Link><ErrorState message={/\(404\)/.test(err) ? 'This campaign was not found. It may have been deleted, or belong to a different workspace.' : 'Could not load this campaign.'} detail={err} onRetry={() => window.location.reload()} /></div>;
  if (!d) return <div className="page page-stack"><Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Campaigns', href: '/campaigns' }, { label: 'Loading' }]} /><Link to="/campaigns">← campaigns</Link><Card title="Loading campaign"><Skeleton height={44} /><div style={{ height: 8 }} /><Skeleton height={160} /></Card></div>;
  return (
    <div className="page page-stack">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Campaigns', href: '/campaigns' }, { label: cardName }]} />
      <Card
        actions={<Badge tone="info">⚡ {Math.round((d.card.confidence ?? 0) * 100)}% confidence</Badge>}
      >
        <Link to="/campaigns">← campaigns</Link>
        <h1 className="case-head__subject" style={{ marginTop: 8 }}>{d.card.name}</h1>
        <div className="case-meta">
          <span>{d.card.email_count} emails</span>
          <span className="dot-sep" aria-hidden="true">·</span>
          <span>IP <span className="mono">{d.card.ip}</span></span>
          {d.card.asn ? <><span className="dot-sep" aria-hidden="true">·</span><span>ASN {d.card.asn}</span></> : null}
        </div>
        <p className="sub" style={{ marginBottom: 0 }}>
          Shared-infrastructure cluster — {d.card.email_count} emails sharing <span className="mono">{d.card.ip}</span>.
          {' '}<Link to="/">Dashboard</Link> · <Link to="/cases">Cases</Link>
        </p>
      </Card>
      <Card title="Attribution graph" description="Campaign nodes and shared infrastructure.">
        <GraphSvg graph={d.graph} />
      </Card>
      <Card title="Emails in this campaign" description={`${(d.emails || []).length} stored emails match this cluster.`}>
        {d.emails.length === 0 ? <EmptyState message="No stored emails match this cluster." /> : (
          <Table label="Emails in this campaign">
            <thead><tr><th scope="col">Verdict</th><th scope="col">Subject</th><th scope="col">Sender</th><th scope="col">Classification</th><th scope="col">Received</th></tr></thead>
            <tbody>
              {d.emails.map((e: any) => (
                <tr key={e.id}>
                  <td><SeverityBadge score={e.fraud_score ?? 0} label={`${e.classification || 'Unclassified'} ${e.fraud_score ?? 0}`} /></td>
                  <td><Link to={`/email/${e.id}`}>{e.subject || '(no subject)'}</Link></td>
                  <td><span className="mono">{e.sender}</span></td>
                  <td>{e.classification}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{formatDateTime(e.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <InternalLinks current="/campaigns" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'TechArticle', headline: cardName,
        description: `Campaign ${cardName} with ${d?.card?.email_count || 0} emails, confidence ${d?.card?.confidence ? Math.round(d.card.confidence * 100) : 0}%`,
        url: `${CANONICAL_BASE}/campaign/${id}`,
        author: { '@id': `${CANONICAL_BASE}/#organization` }
      })}} />
    </div>
  );
}

/* ---------------- Model transparency ---------------- */

export function ModelInfo() {
  usePageMeta({
    title: 'Model Transparency & Metrics - ThreatOptic',
    description: 'Phishing/BEC/clean classifier transparency: accuracy, macro F1, per-class precision/recall and confusion matrix from held-out evaluation.',
    canonical: '/model',
    image: 'https://email-scanner-chi.vercel.app/og-image.svg',
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
  if (loading) return <div className="page page-stack"><Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Model Info' }]} /><h1 className="greet-title">Model Transparency</h1><Card title="Loading metrics"><Skeleton height={44} /><div style={{ height: 8 }} /><Skeleton height={120} /></Card></div>;
  if (err) return <div className="page page-stack"><Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Model Info' }]} /><h1 className="greet-title">Model Transparency</h1><ErrorState message={/metrics not computed yet/.test(err) ? 'No trained model found on the server. Run python backend/scripts/train_nlp.py to compute metrics.' : 'Could not load model metrics.'} detail={err} onRetry={() => window.location.reload()} /></div>;
  const labels: string[] = m.confusion_labels || [];
  const per = m.per_class || {};
  const macroP = m.macro_precision ?? (labels.length ? labels.reduce((x, l) => x + (per[l]?.precision ?? 0), 0) / labels.length : 0);
  const macroR = m.macro_recall ?? (labels.length ? labels.reduce((x, l) => x + (per[l]?.recall ?? 0), 0) / labels.length : 0);
  const macroF = m.macro_f1 ?? (labels.length ? labels.reduce((x, l) => x + (per[l]?.f1 ?? 0), 0) / labels.length : 0);
  const cmMax = Math.max(1, ...(m.confusion_matrix || []).flat());
  const heatClass = (v: number) => {
    const f = v / cmMax;
    if (f >= 0.8) return 'heat-4';
    if (f >= 0.55) return 'heat-3';
    if (f >= 0.3) return 'heat-2';
    if (f > 0) return 'heat-1';
    return 'heat-0';
  };
  const summaryMetrics: [string, string][] = [
    ['Accuracy', (m.accuracy ?? 0).toFixed(3)],
    ['Precision (macro)', Number(macroP).toFixed(3)],
    ['Recall (macro)', Number(macroR).toFixed(3)],
    ['F1 (macro)', Number(macroF).toFixed(3)],
    ...(m.auc != null ? [['AUC', Number(m.auc).toFixed(3)] as [string, string]] : []),
  ];
  return (
    <div className="page page-stack">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Model Transparency' }]} />
      <div className="greet-row">
        <div>
          <h1 className="greet-title">Classifier transparency</h1>
          <p className="greet-sub">
            Phishing/BEC/clean text classifier (TF-IDF + LogisticRegression), evaluated on a held-out split.
            Contributes 30% of the fraud score (nlp signal).
          </p>
        </div>
      </div>
      <Card title="Summary metrics" description="Held-out evaluation — one sequential scale, values always stated.">
        <div className="kpi-strip">
          {summaryMetrics.map(([label, value]) => (
            <div className="kpi" key={label}><div className="kpi__value">{value}</div><div className="kpi__label">{label}</div></div>
          ))}
        </div>
      </Card>
      <Card title="Per-class metrics" description="Precision, recall, F1 and support per class, with inline F1 bars.">
        <Table label="Per-class precision, recall, F1 and support">
          <thead><tr><th scope="col">Class</th><th scope="col">Precision</th><th scope="col">Recall</th><th scope="col">F1</th><th scope="col">Support</th></tr></thead>
          <tbody>
            {labels.map((l) => (
              <tr key={l}>
                <td><b>{l}</b></td>
                <td>{(per[l]?.precision ?? 0).toFixed(3)}</td>
                <td>{(per[l]?.recall ?? 0).toFixed(3)}</td>
                <td>
                  <span className="hbar-row" style={{ margin: 0 }}>
                    <span className="hbar-track" style={{ minWidth: 80 }}><span className="hbar-fill" style={{ display: 'block', width: `${Math.round(100 * (per[l]?.f1 ?? 0))}%`, background: 'var(--chart-4)' }} /></span>
                    <span className="hbar-val">{(per[l]?.f1 ?? 0).toFixed(3)}</span>
                  </span>
                </td>
                <td>{per[l]?.support ?? 0}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
      <Card title="Confusion matrix" description="Rows = actual, columns = predicted. Diagonal cells are correct predictions.">
        <Table label="Confusion matrix with counts and row percentages">
          <thead><tr><th scope="col"><span className="sr-only">Actual \ Predicted</span></th>{labels.map((l) => <th key={l} scope="col">{l}</th>)}</tr></thead>
          <tbody>
            {(m.confusion_matrix || []).map((row: number[], i: number) => {
              const total = Math.max(1, row.reduce((x, y) => x + y, 0));
              return (
                <tr key={labels[i]}>
                  <th scope="row" style={{ textAlign: 'left' }}>{labels[i]}</th>
                  {row.map((v, j) => (
                    <td key={j} className={heatClass(v)}>
                      <b>{v}</b> <span style={{ opacity: 0.75, fontSize: 11 }}>{Math.round((100 * v) / total)}%</span>
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </Table>
      </Card>
      <Card title="Dataset & training info" description="Support counts, split, version and training date.">
        <dl className="deflist">
          <dt>Train / test split</dt><dd>{m.n_train ?? '—'} train / {m.n_test ?? '—'} test{m.random_state != null ? ` · seed ${m.random_state}` : ''}</dd>
          {m.version || m.model_version ? <><dt>Model version</dt><dd><span className="mono">{m.version || m.model_version}</span></dd></> : null}
          {m.trained_at || m.training_date ? <><dt>Trained</dt><dd>{formatDateTime(m.trained_at || m.training_date)}</dd></> : null}
          <dt>Per-class support</dt><dd>{labels.length ? labels.map((l) => `${l}: ${per[l]?.support ?? 0}`).join(' · ') : '—'}</dd>
        </dl>
      </Card>
      <InternalLinks current="/model" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'TechArticle', headline: 'Model Transparency - ThreatOptic',
        description: 'Classifier evaluation metrics and confusion matrix', url: `${CANONICAL_BASE}/model`,
        author: { '@id': `${CANONICAL_BASE}/#organization` }
      })}} />
    </div>
  );
}

/* ---------------- Mailboxes (OAuth org connectors) ---------------- */

export function Mailboxes() {
  usePageMeta({
    title: 'Mailboxes - OAuth Connectors - ThreatOptic',
    description: 'Organization-level OAuth connectors for Google and Microsoft mailboxes with encrypted refresh tokens, polling and manual sync.',
    canonical: '/mailboxes',
    image: 'https://email-scanner-chi.vercel.app/og-image.svg',
  });
  const [conns, setConns] = useState<any[]>([]);
  const [err, setErr] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  // P0: OAuth client secrets are NEVER held in the browser — not in state,
  // not in storage. Client ID is not persisted (user enters each session). Kept blank for privacy.
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [showSecret, setShowSecret] = useState(false);
  const [redirectUri, setRedirectUri] = useState(
    typeof window !== 'undefined' ? `${window.location.origin}/` : 'http://localhost:5173/',
  );

  const updateClientId = (v: string) => {
    setClientId(v);
  };
  const updateClientSecret = (v: string) => {
    setClientSecret(v);
  };

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
      const r = await jpost(`/oauth/${provider}/authorize`, {
        redirect_uri: redirectUri,
        client_id: clientId.trim() || undefined,
        client_secret: clientSecret.trim() || undefined,
      });
      // P1: see getUrl() — the consent hop is verified against the IdP
      // allowlist before the browser leaves the dashboard.
      setClientId('');
      setClientSecret('');
      window.location.assign(assertIdpUrl(r.auth_url, provider));
    } catch (e) { fail(e, 'Connect'); } finally { setBusy(false); }
  };

  const [maxN, setMaxN] = useState('25');
  const syncNow = async () => {
    setBusy(true); setErr(''); setNotice('Syncing emails & running ML threat detection pipeline…');
    try {
      const num = Math.max(1, Math.min(50, parseInt(maxN, 10) || 10));
      const r = await jpost('/oauth/sync-now', {
        max_results: num,
        client_id: clientId.trim() || undefined,
        client_secret: clientSecret.trim() || undefined,
      });
      setNotice(`Synced ${r.synced} email(s)${r.errors?.length ? `, ${r.errors.length} error(s)` : ''}.`);
      setClientId('');
      setClientSecret('');
      await load();
      window.dispatchEvent(new CustomEvent('soc:emails-updated'));
    } catch (e) { fail(e, 'Sync'); } finally { setBusy(false); }
  };

  const disconnect = async (provider: string) => {
    if (!confirm(`Disconnect ${provider} mailbox?`)) return;
    try {
      await jdel(`/oauth/${provider}`);
      setClientId('');
      setClientSecret('');
      await load();
      window.dispatchEvent(new CustomEvent('soc:emails-updated'));
    } catch (e) { fail(e, 'Disconnect'); }
  };

  const [confirmDisc, setConfirmDisc] = useState<string | null>(null);

  const relTime = (ts: string | null | undefined) => {
    if (!ts) return 'never';
    const t = new Date(ts).getTime();
    if (isNaN(t)) return 'never';
    // eslint-disable-next-line react-hooks/purity -- relative "x ago" labels are inherently time-dependent; absolute time stays in the tooltip
    const mins = Math.max(0, Math.round((Date.now() - t) / 60000));
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.round(mins / 60);
    if (hrs < 48) return `${hrs}h ago`;
    return `${Math.round(hrs / 24)}d ago`;
  };

  const providerCard = (
    provider: 'google' | 'microsoft',
    name: string,
    glyph: string,
    conn: any,
  ) => {
    const status = busy ? { color: 'var(--warning)', label: 'Syncing' }
      : conn ? { color: 'var(--success)', label: 'Connected' }
      : err ? { color: 'var(--danger)', label: 'Error' }
      : { color: 'var(--text-muted)', label: 'Disconnected' };
    // Polling fields are optional in /oauth/status — fall back to manual sync.
    const pollOn = conn?.poll_enabled === true || (typeof conn?.poll_interval_minutes === 'number' && conn.poll_interval_minutes > 0);
    const canConnect = !busy && redirectUri.trim() && clientId.trim() && clientSecret.trim();
    return (
      <Card
        title={name}
        description={conn ? `Connected · ${conn.account_email}` : 'Not connected'}
        actions={<span className="provider-icon" aria-hidden="true" style={{ width: 40, height: 40, fontSize: 18 }}>{glyph}</span>}
      >
        <div className="provider-row">
          <StatusIndicator color={status.color} label={status.label} />
        </div>
        <div className="provider-meta">
          <span>
            Last sync:{' '}
            {conn?.last_poll_at || conn?.last_sync_at ? (
              <Tooltip label={formatDateTime(conn.last_poll_at || conn.last_sync_at)}>
                <span>{relTime(conn.last_poll_at || conn.last_sync_at)}</span>
              </Tooltip>
            ) : 'never'}
          </span>
          <span>Polling: {pollOn ? `On${conn.poll_interval_minutes ? ` (every ${conn.poll_interval_minutes}m)` : ''}` : 'Off — manual sync only'}</span>
        </div>
        {conn?.account_email ? (
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 6 }}>
            Account <span className="mono">{conn.account_email}</span> · encrypted refresh token stored, secret never shown
          </div>
        ) : null}
        {conn ? (
          <div className="row" style={{ marginTop: 10 }}>
            <span style={{ maxWidth: 130 }}>
              <Input label="Max emails" type="number" min="1" max="50" value={maxN} onChange={(e) => setMaxN(e.target.value)} placeholder="25" />
            </span>
            <Button size="sm" variant="primary" onClick={syncNow} loading={busy} disabled={conns.length === 0}>Sync now</Button>
            <Button size="sm" variant="ghost" onClick={() => document.getElementById('mailbox-settings')?.scrollIntoView({ behavior: 'smooth', block: 'start' })}>Configure</Button>
            <Button size="sm" variant="danger" onClick={() => setConfirmDisc(provider)}>Disconnect</Button>
          </div>
        ) : (
          <div className="row" style={{ marginTop: 10 }}>
            <Button variant="primary" size="sm" onClick={() => connect(provider)} loading={busy} disabled={!canConnect}>
              Connect {provider === 'google' ? 'Google' : 'Microsoft'}
            </Button>
          </div>
        )}
      </Card>
    );
  };

  const googleConn = conns.find((m) => m.provider === 'google');
  const msConn = conns.find((m) => m.provider === 'microsoft');

  return (
    <div className="page page-stack">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Mailboxes' }]} />
      <div className="greet-row">
        <div>
          <h1 className="greet-title">Mailbox connectors</h1>
          <p className="greet-sub">Organization-level OAuth connectors (Google + Microsoft). Credentials and refresh tokens are encrypted server-side.</p>
        </div>
      </div>
      <div aria-live="polite">
        {err ? <Alert tone="error" title="Mailbox sync issue">{err}<div className="row" style={{ marginTop: 8 }}><Button size="sm" variant="primary" onClick={() => { setErr(''); void load(); }}>Retry</Button></div></Alert> : null}
        {notice && !err ? <Alert tone="success">{notice}</Alert> : null}
      </div>
      {conns.length === 0 && !err ? (
        <Card title="Add a connection" description="Connect your first organization mailbox to enable polling and manual sync.">
          <EmptyState
            message="No mailbox connected yet — Google Workspace or Microsoft 365."
            action={<Button variant="primary" size="sm" onClick={() => document.getElementById('mailbox-settings')?.scrollIntoView({ behavior: 'smooth', block: 'start' })}>Connection settings</Button>}
          />
        </Card>
      ) : null}
      <div className="grid-2">
        {providerCard('google', 'Google Workspace', 'G', googleConn)}
        {providerCard('microsoft', 'Microsoft 365', 'M', msConn)}
      </div>
      <Card
        title="Connection settings"
        description="Shared OAuth parameters for both providers. Secrets stay in form state and are never persisted."
      >
        <div id="mailbox-settings" style={{ maxWidth: 560 }}>
          {conns.length > 0 ? (
            <p style={{ fontSize: 13, marginTop: 0 }}>
              Connected: {conns.map((m) => <span key={m.provider + m.account_email} className="mono" style={{ marginRight: 6 }}>{m.provider}:{m.account_email}</span>)}
            </p>
          ) : null}
          <Input label="Redirect URI" help="Must match the provider console entry exactly." value={redirectUri} onChange={(e) => setRedirectUri(e.target.value)} placeholder="Redirect URI (must match provider console)" autoComplete="off" spellCheck={false} />
          <details className="collapsible" style={{ marginTop: 8 }}>
            <summary>{showSecret ? '▲ Hide custom credentials' : '⚙ Custom credentials (optional)'}</summary>
            <div style={{ marginTop: 8 }}>
              <Well>
                <div className="grid-2">
                  <Input label="OAuth Client ID" help="Leave blank to use the server .env value." value={clientId} onChange={(e) => updateClientId(e.target.value)} placeholder="OAuth client ID (kept blank for privacy)" autoComplete="off" spellCheck={false} />
                  <div>
                    <Input label="OAuth Client Secret" help="Leave blank to use the server .env value." type={showSecret ? 'text' : 'password'} value={clientSecret} onChange={(e) => updateClientSecret(e.target.value)} placeholder="OAuth client secret (kept blank for privacy)" autoComplete="new-password" spellCheck={false} />
                    <div className="row" style={{ marginTop: 6 }}>
                      <Button size="sm" variant="ghost" onClick={() => setShowSecret(!showSecret)}>{showSecret ? 'Hide' : 'Show'}</Button>
                    </div>
                  </div>
                </div>
              </Well>
            </div>
          </details>
        </div>
      </Card>
      {confirmDisc ? (
        <Modal title={`Disconnect ${confirmDisc} mailbox?`} onClose={() => setConfirmDisc(null)}>
          <p>Polling and manual sync stop for this provider. Stored emails and cases are kept.</p>
          <div className="row" style={{ marginTop: 12 }}>
            <Button variant="danger" onClick={() => { const p = confirmDisc; setConfirmDisc(null); void disconnect(p); }}>Disconnect</Button>
            <Button variant="ghost" onClick={() => setConfirmDisc(null)}>Cancel</Button>
          </div>
        </Modal>
      ) : null}
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Mailboxes - ThreatOptic',
        description: 'OAuth mailbox connectors', url: `${CANONICAL_BASE}/mailboxes`,
        isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
    </div>
  );
}

/* ---------------- Cases ---------------- */

type CaseRow = { id: string; title: string; status: string; email_ids: string[]; notes?: string; created_at: string };

const CASE_STATUSES = [
  { key: 'Open', label: 'Open', tone: 'info' },
  { key: 'InProgress', label: 'In Progress', tone: 'medium' },
  { key: 'Closed', label: 'Closed', tone: 'low' },
] as const;

function statusLabel(s: string) {
  return CASE_STATUSES.find((x) => x.key === s)?.label ?? s;
}

/** Desktop ≥1024 / tablet 768–1023 / mobile <768 (Design.md §6). */
function useLayoutMode(): 'desktop' | 'tablet' | 'mobile' {
  const current = () => {
    if (typeof window === 'undefined' || !window.matchMedia) return 'desktop';
    if (window.matchMedia('(max-width: 767px)').matches) return 'mobile';
    if (window.matchMedia('(max-width: 1023px)').matches) return 'tablet';
    return 'desktop';
  };
  const [mode, setMode] = useState<'desktop' | 'tablet' | 'mobile'>(current);
  useEffect(() => {
    const onChange = () => setMode(current());
    window.addEventListener('resize', onChange);
    return () => window.removeEventListener('resize', onChange);
  }, []);
  return mode;
}

export function Cases() {
  usePageMeta({
    title: 'Case Management - Kanban Board - ThreatOptic',
    description: 'Track forensic investigations from triage to closure. Kanban board for Open, In Progress and Closed cases with email linkage.',
    canonical: '/cases',
    image: 'https://email-scanner-chi.vercel.app/og-image.svg',
  });
  const { user } = useAuth();
  const isAdmin = user?.role === 'Admin';
  const [cases, setCases] = useState<CaseRow[]>([]);
  const [title, setTitle] = useState('');
  const [err, setErr] = useState('');
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | string>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const mode = useLayoutMode();
  const ct = useChartTheme();

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
      setNotice('Case created.');
      await load();
    } catch (e) {
      setErr(e instanceof ApiError ? `Create failed (${e.status}): ${e.message}` : String(e));
    }
  };

  const move = async (id: string, status: string) => {
    try {
      await jpatch(`/cases/${encodeURIComponent(id)}`, { status });
      setNotice(`Case moved to ${statusLabel(status)}.`);
      await load();
    } catch (e) {
      setErr(e instanceof ApiError ? `Update failed (${e.status}): ${e.message}` : String(e));
    }
  };

  const remove = async (id: string) => {
    try {
      await jdel(`/cases/${encodeURIComponent(id)}`);
      setConfirmDeleteId(null);
      if (selectedId === id) setSelectedId(null);
      setNotice('Case deleted.');
      await load();
    } catch (e) {
      setErr(e instanceof ApiError ? `Delete failed (${e.status}): ${e.message}` : String(e));
    }
  };

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return cases.filter((k) => {
      if (statusFilter !== 'all' && k.status !== statusFilter) return false;
      if (q && !`${k.title} ${k.id}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [cases, search, statusFilter]);

  const selected = filtered.find((k) => k.id === selectedId) ?? cases.find((k) => k.id === selectedId) ?? null;
  const showList = mode === 'mobile' ? selectedId === null : true;

  const statusTone = (s: string) => (CASE_STATUSES.find((x) => x.key === s)?.tone ?? 'neutral') as 'info' | 'medium' | 'low' | 'neutral';
  const statusDot = (s: string) => s === 'Open' ? ct.risk.high : s === 'Closed' ? ct.risk.low : ct.risk.medium;

  const listPane = (
    <Card
      title="Investigations"
      description={`${filtered.length} of ${cases.length} in scope`}
      actions={<Badge tone="neutral">{cases.length} total</Badge>}
    >
      <div className="row" style={{ marginBottom: 8 }}>
        <div style={{ flex: 1, minWidth: 160 }}>
          <Input id="case-search" label="Search cases" type="search" placeholder="Title or case ID…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
      </div>
      <SegmentedControl
        label="Filter by status"
        value={statusFilter}
        onChange={setStatusFilter}
        options={[
          { value: 'all', label: `All (${cases.length})` },
          ...CASE_STATUSES.map((s) => ({ value: s.key as string, label: `${s.label} (${cases.filter((k) => k.status === s.key).length})` })),
        ]}
      />
      <div style={{ marginTop: 8 }}>
        <Input
          id="case-new-title"
          label="New case title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="New case title…"
          onKeyDown={(e) => { if (e.key === 'Enter') void create(); }}
        />
        <div className="row" style={{ marginTop: 8 }}>
          <Button variant="primary" size="sm" onClick={create} disabled={!title.trim()}>Create case</Button>
          <Link to="/campaigns" className="neu-btn neu-btn--ghost neu-btn--sm">View Campaigns →</Link>
        </div>
      </div>
      <ul className="invest-list">
        {filtered.map((k) => (
          <li key={k.id}>
            <button
              type="button"
              className="invest-list__item"
              aria-current={selected?.id === k.id}
              onClick={() => setSelectedId(k.id)}
            >
              <span style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <Badge tone={statusTone(k.status)}>{statusLabel(k.status)}</Badge>
                <b>{k.title}</b>
              </span>
              <span style={{ display: 'block', fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
                <span className="mono">{k.id.slice(0, 8)}</span> · {k.email_ids?.length ?? 0} email(s) · {formatDateTime(k.created_at)}
              </span>
            </button>
          </li>
        ))}
      </ul>
      {filtered.length === 0 ? (
        <div style={{ marginTop: 8 }}>
          <EmptyState message={cases.length === 0 ? 'No cases yet — create one above to start triaging.' : 'No cases match these filters.'} />
        </div>
      ) : null}
    </Card>
  );

  const detailPane = selected ? (
    <Card
      title={selected.title}
      description={`${statusLabel(selected.status)} · opened ${formatDateTime(selected.created_at)}`}
      actions={
        <span className="row" style={{ gap: 6 }}>
          {mode === 'mobile' ? <Button variant="ghost" size="sm" onClick={() => setSelectedId(null)}>← Back</Button> : null}
          <StatusIndicator color={statusDot(selected.status)} label={statusLabel(selected.status)} />
        </span>
      }
    >
      <dl className="deflist">
        <dt>Case ID</dt><dd><span className="mono">{selected.id}</span></dd>
        <dt>Status</dt>
        <dd>
          <span className="row" style={{ gap: 6 }}>
            {CASE_STATUSES.filter((s) => s.key !== selected.status).map((s) => (
              <Button key={s.key} variant="ghost" size="sm" onClick={() => move(selected.id, s.key)}>Move to {s.label}</Button>
            ))}
          </span>
        </dd>
        <dt>Linked emails</dt>
        <dd>{(selected.email_ids || []).length === 0 ? 'None linked yet.' : (
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {(selected.email_ids || []).map((eid: string) => (
              <li key={eid}><Link to={`/email/${eid}`} className="mono">{eid}</Link></li>
            ))}
          </ul>
        )}</dd>
        {selected.notes ? <><dt>Notes</dt><dd>{selected.notes}</dd></> : null}
      </dl>
      {isAdmin ? (
        <div className="danger-zone">
          <h4><span aria-hidden="true">⬢</span> Danger zone</h4>
          <p className="sub" style={{ margin: '0 0 8px' }}>Deleting a case is permanent and admin-only. Linked emails are kept.</p>
          <Button variant="danger" size="sm" onClick={() => setConfirmDeleteId(selected.id)}>Delete this case</Button>
        </div>
      ) : null}
    </Card>
  ) : (
    <Card title="No case selected" description="Pick an investigation from the list.">
      <EmptyState message="Select a case to review its timeline, linked emails and actions." />
    </Card>
  );

  return (
    <div className="page page-stack">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Case Management' }]} />
      <div className="greet-row">
        <div>
          <h1 className="greet-title">Case management</h1>
          <p className="greet-sub">Track investigations from triage to closure. {cases.length} case{cases.length === 1 ? '' : 's'} in scope.</p>
        </div>
      </div>
      <div aria-live="polite">
        {err ? <Alert tone="error" title="Cases unavailable">{err}</Alert> : null}
        {notice && !err ? <Alert tone="success">{notice}</Alert> : null}
      </div>
      {loading ? <Card title="Loading cases"><Skeleton height={44} /><div style={{ height: 8 }} /><Skeleton height={120} /></Card> : (
        <>
          {mode === 'desktop' ? (
            <div className="master-detail">
              {listPane}
              {detailPane}
            </div>
          ) : null}
          {mode === 'tablet' ? (
            <>
              {listPane}
              {selectedId !== null && selected ? (
                <Drawer title={selected.title} onClose={() => setSelectedId(null)}>
                  {detailPane}
                </Drawer>
              ) : null}
            </>
          ) : null}
          {mode === 'mobile' ? (showList ? listPane : detailPane) : null}
        </>
      )}
      {confirmDeleteId ? (
        <Modal title="Delete this case?" onClose={() => setConfirmDeleteId(null)}>
          <p>Permanent, admin-only. Linked emails are kept; the case record is removed.</p>
          <div className="row" style={{ marginTop: 12 }}>
            <Button variant="danger" onClick={() => remove(confirmDeleteId)}>Delete permanently</Button>
            <Button variant="ghost" onClick={() => setConfirmDeleteId(null)}>Cancel</Button>
          </div>
        </Modal>
      ) : null}
      <InternalLinks current="/cases" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Case Management - ThreatOptic',
        description: 'Kanban case management for forensic investigations', url: `${CANONICAL_BASE}/cases`,
        isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
    </div>
  );
}

/* ---------------- Privacy Policy ---------------- */

export function PrivacyPolicy() {
  usePageMeta({
    title: 'Privacy Policy - ThreatOptic',
    description: 'How ThreatOptic handles email data, cookies, and analyst accounts. Retention, masking, and your rights.',
    canonical: '/privacy',
    image: 'https://email-scanner-chi.vercel.app/og-image.svg',
  });
  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Privacy Policy' }]} />
      <h1>Privacy Policy</h1>
      <p className="sub">Effective 20 Sep 2026 - ThreatOptic. Contact anubhab7105@gmail.com</p>
      <div className="card">
        <h3>What we collect</h3>
        <p>Analyst credentials (email, role via Supabase Auth), ingested email RFC822 content for forensic scoring, mailbox OAuth tokens stored encrypted server-side, and browser local storage for theme and cookie consent. We do not sell data.</p>
        <h3>How we use email content</h3>
        <p>Uploaded mail is parsed, scored 0-100, checked for SPF/DKIM/DMARC and threat intel, then stored with PII masked previews and a SHA-256 hash for chain-of-custody. Raw content is retained per your retention setting and purged by the daily scheduler. See retention_audit.log.</p>
        <h3>Cookies</h3>
        <p>Essential cookies keep you signed in (in-memory JWT, not localStorage) and remember theme and consent choice. No advertising cookies. Analytics is off by default. Use the banner to accept or decline essential storage.</p>
        <h3>Your rights</h3>
        <p>Request access or deletion of your analyst account and ingested data via anubhab7105@gmail.com. OAuth refresh tokens can be revoked via Mailboxes disconnect.</p>
        <h3>Data location</h3>
        <p>Self-hosted SQLite by default or your Postgres/Elastic/Neo4j cluster per docker-compose. Geolocation uses offline GeoIP fallback unless live lookups are enabled.</p>
      </div>
      <InternalLinks current="/privacy" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Privacy Policy - ThreatOptic',
        description: 'Privacy policy for ThreatOptic', url: `${CANONICAL_BASE}/privacy`,
        isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
    </div>
  );
}

/* ---------------- Terms and Conditions ---------------- */

export function TermsConditions() {
  usePageMeta({
    title: 'Terms and Conditions - ThreatOptic',
    description: 'Terms for using the ThreatOptic email threat platform. Acceptable use, liability, and reporting.',
    canonical: '/terms',
    image: 'https://email-scanner-chi.vercel.app/og-image.svg',
  });
  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Terms and Conditions' }]} />
      <h1>Terms and Conditions</h1>
      <p className="sub">Effective 20 Sep 2026 - Use of ThreatOptic is governed by these terms.</p>
      <div className="card">
        <h3>Acceptable use</h3>
        <p>Upload only mail you are authorized to analyze. Do not ingest illegal content or attempt to bypass authentication, retrain the classifier without approval, or scrape threat intel feeds.</p>
        <h3>Forensic reports</h3>
        <p>Scores and classifications are investigative aids, not legal guarantees. Verify with SPF, DKIM, headers, and intel hits before action.</p>
        <h3>Availability</h3>
        <p>Service is provided as-is. The team may update scoring weights, retention, and polling intervals. Check Model Transparency for current metrics.</p>
        <h3>Liability</h3>
        <p>To the full extent permitted by law, ThreatOptic is not liable for indirect damages from missed or flagged mail.</p>
        <h3>Contact</h3>
        <p>Questions: anubhab7105@gmail.com.</p>
      </div>
      <InternalLinks current="/terms" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Terms and Conditions - ThreatOptic',
        description: 'Terms and conditions for ThreatOptic', url: `${CANONICAL_BASE}/terms`,
        isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
    </div>
  );
}
