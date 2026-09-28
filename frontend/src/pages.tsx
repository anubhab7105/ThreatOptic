import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { ApiError, assertIdpUrl, downloadReport, jdel, jget, jpatch, jpost, pollTask, uploadEmFile } from './api';
import { useAuth } from './auth';
import { AuthPill, AvatarStack, CopyButton, Empty, ScoreBadge, SkeletonList, ThreatGauge, Toast, VerdictPill, greetingFor, severityColor, PasswordToggle } from './components';
import { Alert, Badge, Button, Card, EmptyState, ErrorState, Input, SegmentedControl, Select, SeverityBadge, SeverityIcon, Skeleton, SortTh, Spinner, StatusIndicator, Table, Tabs, Textarea, Toggle, Tooltip, Well } from './primitives';
import { useChartTheme } from './useChartTheme';
import { ThemeToggle } from './main';

const CANONICAL_BASE = 'https://socforensics.io';

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

export function LandingPage() {
  usePageMeta({
    title: 'ThreatOptic | Email Threat Detection & Forensic Intelligence',
    description: 'Real-time phishing, BEC, and spoofing detection for SOC analysts. Header forensics, geolocation, identity correlation, and chain-of-custody reporting.',
    canonical: '/',
    image: 'https://email-scanner-chi.vercel.app/og-image.svg',
  });

  return (
    <div className="landing-page">
      <header className="landing-header">
        <nav className="landing-nav" aria-label="Primary">
          <Link to="/" className="brand" aria-label="ThreatOptic home"><span aria-hidden="true">◈</span> ThreatOptic</Link>
          <div className="landing-nav-links">
            <Link to="/model" className="nav-link">Model</Link>
            <Link to="/login" className="nav-link">Sign In</Link>
            <Link to="/login" className="nav-link btn-primary">Get Started</Link>
          </div>
          <ThemeToggle />
        </nav>
      </header>

      <main id="main-content">
        <section className="hero" aria-labelledby="hero-title">
          <svg className="hero-trace-bg" viewBox="0 0 1200 500" preserveAspectRatio="none" aria-hidden="true">
            <g stroke="var(--teal)" strokeWidth="1.2" opacity="0.55">
              <line x1="60" y1="500" x2="340" y2="120" />
              <line x1="60" y1="500" x2="480" y2="60" />
              <line x1="60" y1="500" x2="860" y2="90" />
              <line x1="60" y1="500" x2="760" y2="170" />
            </g>
            <g stroke="var(--correlation)" strokeWidth="1.2" opacity="0.55">
              <line x1="60" y1="500" x2="280" y2="230" />
            </g>
            <g fill="var(--teal)">
              <circle cx="340" cy="120" r="4" />
              <circle cx="860" cy="90" r="4" />
              <circle cx="760" cy="170" r="4" />
            </g>
            <g fill="var(--correlation)">
              <circle cx="480" cy="60" r="4" />
              <circle cx="280" cy="230" r="4" />
            </g>
          </svg>
          <div className="hero-content">
            <span className="hero-eyebrow">AI-powered email threat detection · GeoLocation · Forensic intelligence</span>
            <h1 id="hero-title">See where every email really comes from.</h1>
            <p className="hero-subtitle">Live-traced origin, scored 0–100 in real time — SPF/DKIM/DMARC, URL and attachment intelligence, geolocation, and identity graphs. Export chain-of-custody PDF/JSON reports.</p>
            <div className="hero-actions">
              <Link to="/login" className="btn-primary">Start analyzing</Link>
              <Link to="/model" className="btn-secondary">View Model Transparency</Link>
            </div>
            <p className="hero-trust">Self-hosted. No vendor lock-in. Dark-first SOC-grade interface.</p>
          </div>
          <div className="hero-visual">
            <div className="score-panel" aria-label="Sample score breakdown">
              <h4>Why this score — sample</h4>
              <div className="why-score">82</div>
              <div className="why-label">High · Junk/Hold</div>
              <div className="signal-row"><span className="sig-name">nlp 30%</span><span className="sig-bar"><span className="sig-fill" style={{ display: 'block', width: '82%', background: 'var(--correlation)' }} /></span></div>
              <div className="signal-row"><span className="sig-name">auth 25%</span><span className="sig-bar"><span className="sig-fill" style={{ display: 'block', width: '64%', background: 'var(--teal)' }} /></span></div>
              <div className="signal-row"><span className="sig-name">intel 20%</span><span className="sig-bar"><span className="sig-fill" style={{ display: 'block', width: '48%', background: 'var(--correlation)' }} /></span></div>
              <div className="signal-row"><span className="sig-name">routing 15%</span><span className="sig-bar"><span className="sig-fill" style={{ display: 'block', width: '30%', background: 'var(--muted)' }} /></span></div>
              <div style={{ marginTop: 8, fontSize: 12, fontFamily: 'var(--mono)' }}>
                <span style={{ color: 'var(--teal)' }}>SPF: pass</span>{' · '}
                <span style={{ color: 'var(--critical)' }}>DKIM: fail</span>{' · '}
                <span style={{ color: 'var(--muted)' }}>DMARC: unverifiable</span>
              </div>
            </div>
          </div>
        </section>

        <div className="pipeline-strip" aria-label="Pipeline: Ingest, Parse, Score, Correlate, Report">
          <div className="pipeline-inner">
            {['Ingest', 'Parse', 'Score', 'Correlate', 'Report'].map((s, i, arr) => (
              <span key={s} style={{ display: 'inline-flex', alignItems: 'center', gap: 12 }}>
                <span className="pipeline-node"><span className="p-dot" aria-hidden="true" />{s}</span>
                {i < arr.length - 1 ? <span className="pipeline-link" aria-hidden="true" /> : null}
              </span>
            ))}
          </div>
        </div>

        <section className="features" aria-labelledby="features-title">
          <h2 id="features-title" className="section-title">Built for forensic analysis</h2>
          <p className="section-sub">The same five pipeline phases, from ingest to chain-of-custody report.</p>
          <div className="features-grid">
            <article className="feature-card">
              <div className="feature-icon" aria-hidden="true">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2" /><line x1="12" y1="22" x2="12" y2="15.5" /><line x1="22" y1="8.5" x2="12" y2="15.5" /><line x1="2" y1="8.5" x2="12" y2="15.5" /></svg>
              </div>
              <h3>Header Forensics</h3>
              <p>Full RFC822 parsing with SPF, DKIM, DMARC, ARC, and alignment checks. Relay chain reconstruction with IP geolocation.</p>
            </article>
            <article className="feature-card">
              <div className="feature-icon" aria-hidden="true">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><line x1="12" y1="6" x2="12" y2="18" /><line x1="6" y1="12" x2="18" y2="12" /></svg>
              </div>
              <h3>Identity Correlation</h3>
              <p>Graph-based clustering links shared infrastructure across campaigns. IP, domain, email and campaign nodes share one color each.</p>
            </article>
            <article className="feature-card">
              <div className="feature-icon" aria-hidden="true">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" /></svg>
              </div>
              <h3>Chain-of-Custody Reports</h3>
              <p>SHA-256 hashed originals. PDF and JSON exports with timestamps, scores, and evidence references.</p>
            </article>
            <article className="feature-card">
              <div className="feature-icon" aria-hidden="true">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" /></svg>
              </div>
              <h3>Model Transparency</h3>
              <p>Open precision, recall and F1 with a per-class confusion matrix — the score is explainable, not a black box.</p>
            </article>
            <article className="feature-card">
              <div className="feature-icon" aria-hidden="true">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><path d="M12 6v6l4 2" /></svg>
              </div>
              <h3>Real-Time Ingestion</h3>
              <p>Paste RFC822, upload .eml, or connect Google Workspace / Microsoft 365 mailboxes via OAuth.</p>
            </article>
            <article className="feature-card">
              <div className="feature-icon" aria-hidden="true">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
              </div>
              <h3>Self-Hosted First</h3>
              <p>Deploy on your infrastructure. SQLite, Postgres, Elastic, or Neo4j backends. Air-gapped friendly with offline GeoIP.</p>
            </article>
          </div>
        </section>

        <section aria-label="Model transparency">
          <div className="model-strip">
            <div className="model-stat"><div className="m-num">0.91</div><div className="m-label">Precision</div></div>
            <div className="model-stat"><div className="m-num">0.88</div><div className="m-label">Recall</div></div>
            <div className="model-stat"><div className="m-num">0.89</div><div className="m-label">F1</div></div>
            <div className="model-stat"><div className="m-num" style={{ fontSize: 18, paddingTop: 8 }}><Link to="/model">Details →</Link></div><div className="m-label">Held-out evaluation</div></div>
          </div>
        </section>

        <section className="cta" aria-labelledby="cta-title">
          <h2 id="cta-title">Ready to analyze your first email?</h2>
          <p>Sign in to open the Global Threat Dashboard.</p>
          <Link to="/login" className="btn-primary btn-large">Sign in</Link>
        </section>
      </main>

      <footer className="landing-footer">
        <div className="footer-grid">
          <div className="footer-brand">
            <Link to="/" className="brand" aria-label="ThreatOptic home"><span aria-hidden="true">◈</span> ThreatOptic</Link>
            <p>Email threat detection, geolocation, and forensic intelligence for security operations teams.</p>
          </div>
          <nav className="footer-links" aria-label="Product">
            <h4>Product</h4>
            <ul>
              <li><Link to="/model">Model Transparency</Link></li>
              <li><Link to="/login">Sign In</Link></li>
            </ul>
          </nav>
          <nav className="footer-links" aria-label="Company">
            <h4>Company</h4>
            <ul>
              <li><Link to="/privacy">Privacy Policy</Link></li>
              <li><Link to="/terms">Terms of Service</Link></li>
              <li><a href="mailto:hello@socforensics.io">Contact</a></li>
            </ul>
          </nav>
          <nav className="footer-links" aria-label="Resources">
            <h4>Resources</h4>
            <ul>
              <li><a href="/sitemap.xml">Sitemap</a></li>
              <li><a href="/robots.txt">Robots</a></li>
              <li><a href="/llms.txt">LLMs.txt</a></li>
            </ul>
          </nav>
        </div>
        <div className="footer-bottom">
          <p>&copy; 2026 ThreatOptic. 301 Congress Ave, Austin, TX 78701.</p>
        </div>
      </footer>

      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'ThreatOptic | Email Threat Detection',
        description: 'Real-time phishing, BEC, and spoofing detection with header forensics, geolocation, and chain-of-custody reporting.',
        url: `${CANONICAL_BASE}/`, isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
    </div>
  );
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

/* ---------------- Login ---------------- */

export function LoginPage() {
  usePageMeta({
    title: 'Sign In - ThreatOptic | Secure Analyst Access',
    description: 'JWT-secured sign in for SOC analysts. Access the email threat dashboard with forensic intelligence, geolocation and chain-of-custody reporting.',
    canonical: '/login',
    image: 'https://socforensics.io/og-image.svg',
  });
  const { login, register } = useAuth();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!email.trim() || !password) return;
    setBusy(true);
    setErr('');
    setNotice('');
    try {
      if (mode === 'login') await login(email.trim(), password);
      else {
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
        <div className="login-hero-pane">
          <div style={{ fontWeight: 800, fontSize: 20 }}>◈ ThreatOptic</div>
          <h2>See where every email really comes from.</h2>
          <p className="tag">AI-powered email threat detection, geolocation &amp; forensic intelligence.</p>
          <div className="login-check"><span aria-hidden="true">✓</span> Header forensics &amp; SPF/DKIM/DMARC</div>
          <div className="login-check"><span aria-hidden="true">✓</span> IP geolocation &amp; origin tracing</div>
          <div className="login-check"><span aria-hidden="true">✓</span> Graph-correlated fraud campaigns</div>
        </div>
        <div className="login-form-pane">
          <div className="login-breadcrumb">
            <Link to="/">Home</Link>
            <span className="sep">›</span>
            <span>{mode === 'login' ? 'Sign in' : 'Register'}</span>
          </div>

          <h2 className="login-form-title">Sign in</h2>
          <p className="login-form-sub">Sign in to access the Global Threat Dashboard.</p>

          <div className="login-tabs" role="tablist" aria-label="Sign in or register">
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'login'}
              className={`login-tab-btn ${mode === 'login' ? 'active' : ''}`}
              onClick={() => { setMode('login'); setErr(''); }}
            >
              Sign in
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'register'}
              className={`login-tab-btn ${mode === 'register' ? 'active' : ''}`}
              onClick={() => { setMode('register'); setErr(''); }}
            >
              Register
            </button>
          </div>

          <Toast msg={err} />
          {notice ? <div className="login-notice" role="status">{notice}</div> : null}

          <div className="login-field-group">
            <label htmlFor="login-email" className="login-field-label">Email</label>
            <input
              id="login-email"
              type="email"
              placeholder="e.g. analyst@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') submit(); }}
              autoComplete="email"
              className="login-input"
            />
          </div>

          <div className="login-field-group">
            <PasswordToggle
              id="login-password"
              label="Password"
              value={password}
              onChange={setPassword}
              placeholder={mode === 'register' ? 'Password (min 8 chars)' : '••••••••'}
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
              className="login-input"
              onKeyDown={(e) => { if (e.key === 'Enter') submit(); }}
            />
          </div>

          <button
            type="button"
            className="login-submit-btn"
            onClick={submit}
            disabled={busy || !email.trim() || !password}
          >
            {busy ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}
          </button>
          <div className="login-seed">
            <div>Demo accounts (local dev): admin / admin123 · analyst / analyst123</div>
            <div style={{ marginTop: 8, display: 'flex', gap: 8, justifyContent: 'center' }}>
              <button type="button" className="ghost small" style={{ fontSize: 12, padding: '4px 10px' }} onClick={() => { setEmail('admin'); setPassword('admin123'); login('admin', 'admin123'); }}>Quick Login: Admin</button>
              <button type="button" className="ghost small" style={{ fontSize: 12, padding: '4px 10px' }} onClick={() => { setEmail('analyst'); setPassword('analyst123'); login('analyst', 'analyst123'); }}>Quick Login: Analyst</button>
            </div>
          </div>
          <p className="sub" style={{ marginTop: 8, fontSize: 12 }}>Public self-registration → ReadOnly by default. Admin creation requires the out-of-band SETUP_TOKEN.</p>
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

const DEFAULT_GOOGLE_CLIENT_ID = '';
const DEFAULT_GOOGLE_CLIENT_SECRET = '';

function GmailPanel({ onSynced, bare = false }: { onSynced: () => void; bare?: boolean }) {
  const [status, setStatus] = useState<any>(null);
  const [clientId, setClientId] = useState(DEFAULT_GOOGLE_CLIENT_ID);
  const [clientSecret, setClientSecret] = useState(DEFAULT_GOOGLE_CLIENT_SECRET);
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
      if (typeof sessionStorage !== 'undefined') sessionStorage.setItem('soc_oauth_provider', 'google');
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
      const num = Math.max(1, parseInt(maxN, 10) || 10);
      // P0: client_id from state only, client_secret never from browser storage
      const effectiveCid = clientId.trim() || undefined;
      const effectiveSec = clientSecret.trim() || undefined;

      const r = await jpost('/gmail/sync', {
        max_results: num,
        query,
        client_id: effectiveCid,
        client_secret: effectiveSec,
      });
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

  // Stepper phase (Design.md §7.6): Waiting > Connecting > Connected / Error.
  // OAuth code/state are still auto-captured (see effect above); no visible auth-code field.
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
            <Input label="Max emails to sync" type="number" min="1" value={maxN} onChange={(e) => setMaxN(e.target.value)} />
          </div>
          <div className="row" style={{ marginTop: 10 }}>
            <Button size="sm" variant="primary" onClick={sync} loading={busy}>Sync now</Button>
            <Button size="sm" variant="ghost" onClick={() => setShowCreds(!showCreds)}>{showCreds ? 'Hide credentials' : 'Change credentials'}</Button>
            <Button size="sm" variant="danger" onClick={disconnect}>Disconnect</Button>
          </div>
          {showCreds && (
            <Well>
              <div className="grid-2">
                <Input label="Google OAuth Client ID" value={clientId} onChange={(e) => updateClientId(e.target.value)} placeholder="Google OAuth client ID" />
                <div>
                  <Input label="Google OAuth Client Secret" type={showSecret ? 'text' : 'password'} value={clientSecret} onChange={(e) => updateClientSecret(e.target.value)} placeholder="Google OAuth client secret" />
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
            Connect your Gmail mailbox via Google OAuth (read-only) to import and analyze emails.
          </p>
          <div style={{ maxWidth: 560 }}>
            <Input label="Redirect URI" help="Must match the Google Console entry exactly." value={redirectUri} onChange={(e) => setRedirectUri(e.target.value)} placeholder="Redirect URI (must match Google console)" />
            <details className="collapsible" style={{ marginTop: 8 }}>
              <summary>{showCreds ? '▲ Hide custom credentials' : '⚙ Custom credentials (optional)'}</summary>
              <div style={{ marginTop: 8 }}>
                <Well>
                  <div className="grid-2">
                    <Input label="Google OAuth Client ID" help="Leave blank to use the server .env value." value={clientId} onChange={(e) => updateClientId(e.target.value)} placeholder="Leave blank to use server .env" />
                    <div>
                      <Input label="Google OAuth Client Secret" help="Leave blank to use the server .env value." type={showSecret ? 'text' : 'password'} value={clientSecret} onChange={(e) => updateClientSecret(e.target.value)} placeholder="Leave blank to use server .env" />
                      <div className="row" style={{ marginTop: 6 }}>
                        <Button size="sm" variant="ghost" onClick={() => { setShowCreds(true); setShowSecret(!showSecret); }}>{showSecret ? 'Hide' : 'Show'}</Button>
                      </div>
                    </div>
                  </div>
                </Well>
              </div>
            </details>
            <div className="row" style={{ marginTop: 10 }}>
              <Button variant="primary" onClick={getUrl} loading={busy} disabled={!redirectUri.trim()}>Connect Gmail</Button>
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
    canonical: '/dashboard',
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
  const { user } = useAuth();
  const displayName = user?.email ? user.email.split('@')[0].replace(/^[a-z]/, (c) => c.toUpperCase()) : 'Analyst';

  useEffect(() => {
    const onTopSearch = (e: Event) => {
      const detail = (e as CustomEvent).detail as { q?: string } | undefined;
      if (detail && typeof detail.q === 'string') setQ(detail.q);
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

  const scrollTo = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

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

  // Ingest source + analytics range + table sort (all client-side, existing data only)
  const [source, setSource] = useState<'paste' | 'upload' | 'gmail'>('paste');
  const [range, setRange] = useState<'24h' | '7d' | '30d' | 'all'>('7d');
  const [sortKey, setSortKey] = useState<'received' | 'score'>('received');
  const [sortDir, setSortDir] = useState<'ascending' | 'descending'>('descending');
  const [activityOpen, setActivityOpen] = useState<boolean>(() =>
    typeof window === 'undefined' ? true : !window.matchMedia('(max-width: 1023px)').matches);

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

  const newAnalysis = () => {
    setSource('paste');
    scrollTo('ingest-panel');
    setTimeout(() => document.getElementById('ingest-raw')?.focus(), 300);
  };

  return (
    <div className="page page-stack">
      <Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Threat Dashboard' }]} />
      <div className="greet-row">
        <div>
          <h1 className="greet-title">{greetingFor()}, {displayName}!</h1>
          <p className="greet-sub">Real-time phishing, BEC and spoofing detection across ingested mail.</p>
        </div>
        <div className="greet-actions">
          <Button variant="ghost" onClick={() => { setRaw(PHISH_SAMPLE); scrollTo('ingest-panel'); }} title="Load a sample template">Template</Button>
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
              <hr className="section-divider" />
              <ThreatGauge dist={dist} />
            </Card>
          </>
        )
      )}

      <div className="card" id="ingest-panel" style={{ marginBottom: 18 }}>
        <h3>Ingest email for analysis</h3>
        <textarea id="ingest-raw" rows={6} value={raw} onChange={(e) => setRaw(e.target.value)} placeholder="Paste raw RFC822 / .eml content here…" />
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
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') void load(); }}
            />
          </div>
          <div className="row" style={{ alignSelf: 'end' }}>
            <Button variant="primary" size="sm" onClick={() => load()}>Search</Button>
            <Button variant="ghost" size="sm" onClick={() => load()}>Refresh</Button>
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

      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Global Threat Dashboard - ThreatOptic',
        description: 'Real-time phishing and BEC detection dashboard', url: `${CANONICAL_BASE}/dashboard`,
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
    return <Empty msg="No related entities yet — graph correlation links shared sender IPs, domains, and campaigns as emails are ingested." />;
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
      <div className="graph-canvas" style={{ position: 'relative', overflow: 'hidden', borderRadius: 16, border: '1px solid var(--border-subtle)' }}>
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
                transform={`translate(${p.x}, ${p.y})`}
                opacity={isDimmed ? 0.25 : 1}
                style={{ cursor: 'pointer', transition: 'opacity 0.2s, transform 0.15s' }}
                onMouseEnter={() => setHoveredId(n.id)}
                onMouseLeave={() => setHoveredId(null)}
                onClick={() => setSelectedId(selectedId === n.id ? null : n.id)}
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
    title: d ? `${subject} - Score ${fraudScore} - ThreatOptic` : `Email Forensics - ThreatOptic`,
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

  if (err) return <div className="page page-stack"><Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Email', href: '/dashboard' }, { label: 'Error' }]} /><Link to="/dashboard">← back</Link><ErrorState message="Could not load this email." detail={err} onRetry={() => window.location.reload()} /></div>;
  if (!d) return <div className="page page-stack"><Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Email' }]} /><Link to="/dashboard">← back</Link><Card title="Loading email"><Skeleton height={44} /><div style={{ height: 8 }} /><Skeleton height={160} /></Card></div>;
  const a = d.analysis || {};
  const t = d.trace || {};
  const auth = a.authentication_results || {};
  const relay: any[] = Array.isArray(t.relay_chain) ? t.relay_chain : [];
  const fraud = a.fraud_score ?? 0;
  const hasCoords = t.geolocation?.lat != null && t.geolocation?.lon != null && !isNaN(Number(t.geolocation.lat)) && !isNaN(Number(t.geolocation.lon));

  return (
    <div className="page page-stack">
      <Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Investigations', href: '/dashboard' }, { label: subject.slice(0, 36) || 'Email Detail' }]} />

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
        <Tooltip label={d.email.subject || '(no subject)'}>
          <h1 className="case-head__subject">{d.email.subject || '(no subject)'}</h1>
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
                <h3 style={{ marginTop: 0 }}>Verdict</h3>
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
                <h3 style={{ marginTop: 0 }}>Supporting evidence</h3>
                <div className="grid-2">
                  <div>
                    <h4 style={{ margin: '0 0 8px', fontSize: 13 }}>Authentication detail</h4>
                    {(auth.spf?.detail || auth.dkim?.detail || auth.dmarc?.detail) ? (
                      <dl className="deflist" style={{ gridTemplateColumns: '70px 1fr' }}>
                        {auth.spf?.detail ? <><dt>SPF</dt><dd>{auth.spf.detail}</dd></> : null}
                        {auth.dkim?.detail ? <><dt>DKIM</dt><dd>{auth.dkim.detail}</dd></> : null}
                        {auth.dmarc?.detail ? <><dt>DMARC</dt><dd>{auth.dmarc.detail}</dd></> : null}
                      </dl>
                    ) : <p className="sub">No authentication detail recorded.</p>}
                    <h4 style={{ margin: '16px 0 8px', fontSize: 13 }}>Body (PII masked)</h4>
                    <pre className="dump" style={{ whiteSpace: 'pre-wrap' }}>{d.email.body_text_masked || '(empty)'}</pre>
                  </div>
                  <div>
                    <h4 style={{ margin: '0 0 8px', fontSize: 13 }}>Threat intel hits ({(a.threat_intel_hits || []).length})</h4>
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
              <h3 style={{ marginTop: 0 }}>Why this score?</h3>
              <ScoreWhy breakdown={a.score_breakdown} score={fraud} />
            </section>
          )}

          {tab === 2 && (
            <>
              <section aria-label="Chain of custody">
                <h3 style={{ marginTop: 0 }}>Chain of custody</h3>
                <dl className="deflist">
                  <dt>SHA-256 (.eml)</dt><dd><span className="mono">{d.email.raw_eml_hash}</span> <CopyButton text={String(d.email.raw_eml_hash || '')} label="Copy hash" /></dd>
                  <dt>Message-ID</dt><dd><span className="mono">{d.email.message_id || '-'}</span> {d.email.message_id ? <CopyButton text={String(d.email.message_id)} label="Copy ID" /> : null}</dd>
                  <dt>Relay hops</dt><dd>{relay.length}</dd>
                </dl>
              </section>
              <hr className="section-divider" />
              <div className="grid-2">
                <section aria-label="Parsed relay path">
                  <h3 style={{ marginTop: 0 }}>Relay path (origin first)</h3>
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
                  <h3 style={{ marginTop: 0 }}>Raw chain</h3>
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
                <h3 style={{ marginTop: 0 }}>Origin</h3>
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
                    <h4 style={{ margin: '0 0 8px', fontSize: 13 }}>WHOIS</h4>
                    <pre className="dump">{JSON.stringify(t.whois, null, 2)}</pre>
                  </section>
                  <section aria-label="DNS records">
                    <h4 style={{ margin: '0 0 8px', fontSize: 13 }}>DNS</h4>
                    <pre className="dump">{JSON.stringify(t.dns, null, 2)}</pre>
                  </section>
                </div>
              </details>
            </>
          )}

          {tab === 4 && (
            <section aria-label="Identity correlation graph">
              <h3 style={{ marginTop: 0 }}>Identity correlation</h3>
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
      <Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Campaigns' }]} />
      <div className="greet-row">
        <div>
          <h1 className="greet-title">Campaigns</h1>
          <p className="greet-sub">Graph-detected clusters: domains sharing sender infrastructure, joined with forensic records.</p>
        </div>
      </div>
      <Toast msg={err} />
      {loading ? <SkeletonList /> : cards.length === 0 ? <Empty msg="No campaigns yet - ingest more mail sharing IPs/domains." /> : (
        <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))' }}>
          {cards.map((k) => (
            <div key={k.id} className="card hoverable">
              <div className="invest-card-top">
                <span className="badge info">{Math.round((k.confidence ?? 0) * 100)}% confidence</span>
                <AvatarStack names={[(k.domains || [])[0] || k.name, 'analyst']} max={2} />
              </div>
              <h3 style={{ fontSize: 16 }}><Link to={`/campaign/${k.id}`} style={{ color: 'inherit' }}>{k.name}</Link></h3>
              <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 8 }}>{k.email_count} emails · IP <span className="mono">{k.ip}</span></div>
              <dl className="kv" style={{ gridTemplateColumns: '110px 1fr' }}>
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
  if (err) return <div className="page"><Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Campaigns', href: '/campaigns' }, { label: 'Error' }]} /><Link to="/campaigns">← campaigns</Link><Toast msg={err} /></div>;
  if (!d) return <div className="page"><Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Campaigns', href: '/campaigns' }, { label: 'Loading' }]} /><Link to="/campaigns">← campaigns</Link><SkeletonList /></div>;
  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Campaigns', href: '/campaigns' }, { label: cardName }]} />
      <div className="doc-title-row">
        <h1 className="doc-title">{d.card.name}</h1>
        <span className="badge info">{Math.round((d.card.confidence ?? 0) * 100)}% confidence</span>
        <div className="doc-tools">
          <AvatarStack names={[d.card.ip || 'campaign', 'analyst']} max={2} />
        </div>
      </div>
      <p className="sub">
        {d.card.email_count} emails · confidence {Math.round((d.card.confidence ?? 0) * 100)}% · IP <span className="mono">{d.card.ip}</span>
        {d.card.asn ? <> · ASN {d.card.asn}</> : null}
        {' · '}<Link to="/dashboard">Dashboard</Link> · <Link to="/cases">Cases</Link>
      </p>
      <div className="doc-section">
        <div className="doc-rail" aria-hidden="true" />
        <div>
          <h3>Introduction</h3>
          <p>
            Campaign detail reuses the doc-view — Introduction, Key Signals, Headers, Geo and Graph —
            filtered to this campaign&apos;s entities ({d.card.email_count} emails sharing <span className="mono">{d.card.ip}</span>).
          </p>
        </div>
      </div>
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
  const macroP = labels.length ? labels.reduce((a, l) => a + (per[l]?.precision ?? 0), 0) / labels.length : 0;
  const macroR = labels.length ? labels.reduce((a, l) => a + (per[l]?.recall ?? 0), 0) / labels.length : 0;
  const macroF = labels.length ? labels.reduce((a, l) => a + (per[l]?.f1 ?? 0), 0) / labels.length : 0;
  const cmMax = Math.max(1, ...(m.confusion_matrix || []).flat());
  const heatClass = (v: number) => {
    const f = v / cmMax;
    if (f >= 0.8) return 'heat-4';
    if (f >= 0.55) return 'heat-3';
    if (f >= 0.3) return 'heat-2';
    if (f > 0) return 'heat-1';
    return 'heat-0';
  };
  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Model Transparency' }]} />
      <div className="greet-row">
        <div>
          <h1 className="greet-title">Classifier transparency</h1>
          <p className="greet-sub">
            Phishing/BEC/clean text classifier (TF-IDF + LogisticRegression), evaluated on a held-out split
            ({m.n_test} test / {m.n_train} train, seed {m.random_state}). One teal ramp does the whole heat map.
          </p>
        </div>
      </div>
      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', marginBottom: 18 }}>
        <div className="card" style={{ textAlign: 'center' }}>
          <div style={{ fontFamily: 'var(--serif)', fontSize: 36, fontWeight: 800, color: 'var(--teal)' }}>{macroP.toFixed(2)}</div>
          <h3 style={{ textAlign: 'center' }}>Precision</h3>
        </div>
        <div className="card" style={{ textAlign: 'center' }}>
          <div style={{ fontFamily: 'var(--serif)', fontSize: 36, fontWeight: 800, color: 'var(--teal)' }}>{macroR.toFixed(2)}</div>
          <h3 style={{ textAlign: 'center' }}>Recall</h3>
        </div>
        <div className="card" style={{ textAlign: 'center' }}>
          <div style={{ fontFamily: 'var(--serif)', fontSize: 36, fontWeight: 800, color: 'var(--teal)' }}>{macroF.toFixed(2)}</div>
          <h3 style={{ textAlign: 'center' }}>F1</h3>
        </div>
      </div>
      <p className="sub">Accuracy {(m.accuracy ?? 0).toFixed(3)} · macro F1 {(m.macro_f1 ?? 0).toFixed(3)} · contributes 30% of the fraud score (nlp signal).</p>
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
                      <td key={j} className={heatClass(v)}>
                        <b>{v}</b> <span style={{ opacity: 0.75, fontSize: 11 }}>{Math.round((100 * v) / total)}%</span>
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
    image: 'https://socforensics.io/og-image.svg',
  });
  const [conns, setConns] = useState<any[]>([]);
  const [err, setErr] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  // OAuth secrets are held in form state only and are never persisted.
  const [clientId, setClientId] = useState(DEFAULT_GOOGLE_CLIENT_ID);
  const [clientSecret, setClientSecret] = useState(DEFAULT_GOOGLE_CLIENT_SECRET);
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
  useEffect(() => {
    void load();
    const params = new URLSearchParams(window.location.search);
    const conn = params.get('connected');
    if (conn) {
      const [prov, ...rest] = conn.split(':');
      const addr = decodeURIComponent(rest.join(':'));
      setNotice(`Successfully connected ${prov} mailbox (${addr})!`);
      window.history.replaceState({}, '', window.location.pathname);
      window.dispatchEvent(new CustomEvent('soc:emails-updated'));
    }
    const oErr = params.get('error');
    if (oErr) {
      const desc = params.get('error_description') || oErr;
      setErr(`OAuth error: ${desc}`);
      window.history.replaceState({}, '', window.location.pathname);
    }
  }, []);

  const connect = async (provider: 'google' | 'microsoft') => {
    setErr(''); setNotice('');
    setBusy(true);
    if (typeof sessionStorage !== 'undefined') sessionStorage.setItem('soc_oauth_provider', provider);
    try {
      const r = await jpost(`/oauth/${provider}/authorize`, {
        redirect_uri: redirectUri,
        client_id: clientId.trim() || undefined,
        client_secret: clientSecret.trim() || undefined,
      });
      // P1: see getUrl() — the consent hop is verified against the IdP
      // allowlist before the browser leaves the dashboard.
      window.location.href = assertIdpUrl(r.auth_url, provider);
    } catch (e) { fail(e, 'Connect'); } finally { setBusy(false); }
  };

  const [maxN, setMaxN] = useState('25');
  const syncNow = async () => {
    setBusy(true); setErr(''); setNotice('Syncing emails & running ML threat detection pipeline…');
    try {
      const num = Math.max(1, parseInt(maxN, 10) || 10);
      const r = await jpost('/oauth/sync-now', {
        max_results: num,
        client_id: clientId.trim() || undefined,
        client_secret: clientSecret.trim() || undefined,
      });
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

  const googleConn = conns.find((m) => m.provider === 'google');
  const msConn = conns.find((m) => m.provider === 'microsoft');

  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Mailboxes' }]} />
      <div className="greet-row">
        <div>
          <h1 className="greet-title">Mailbox connectors</h1>
          <p className="greet-sub">Organization-level OAuth connectors (Google + Microsoft). Credentials and refresh tokens are encrypted server-side.</p>
        </div>
      </div>
      <Toast msg={err} />
      {notice && <Toast msg={notice} kind="info" />}
      <div className="provider-grid" style={{ marginBottom: 14 }}>
        <div className="card provider-card">
          <div className="provider-top">
            <span className={`health-dot ${googleConn ? 'health-connected' : 'health-error'}`} aria-hidden="true" />
            <div>
              <p className="provider-name">Google Workspace</p>
              <p className="provider-sub">{googleConn ? <>Connected · <span className="mono">{googleConn.account_email}</span></> : 'Not connected'}</p>
            </div>
          </div>
          {googleConn ? (
            <>
              <div className="row">
                <input
                  type="number"
                  min="1"
                  style={{ maxWidth: 110 }}
                  value={maxN}
                  onChange={(e) => setMaxN(e.target.value)}
                  placeholder="Count"
                  title="Max emails to sync (any number)"
                />
                <button className="btn-new" onClick={syncNow} disabled={busy}>{busy ? 'Syncing…' : 'Sync now'}</button>
                <button className="ghost small" onClick={() => disconnect('google')}>Disconnect</button>
              </div>
              {googleConn.last_poll_at ? <p className="provider-sub">Last poll {formatDateTime(googleConn.last_poll_at)}</p> : null}
              <p className="provider-sub" style={{ fontStyle: 'italic' }}>Encrypted refresh token stored · secret never shown</p>
            </>
          ) : (
            <div className="row">
              <button className="ghost" onClick={() => connect('google')} disabled={busy || !redirectUri.trim()}>Connect Google</button>
            </div>
          )}
        </div>
        <div className="card provider-card">
          <div className="provider-top">
            <span className={`health-dot ${msConn ? 'health-connected' : 'health-error'}`} aria-hidden="true" />
            <div>
              <p className="provider-name">Microsoft 365</p>
              <p className="provider-sub">{msConn ? <>Connected · <span className="mono">{msConn.account_email}</span></> : 'Not connected'}</p>
            </div>
          </div>
          {msConn ? (
            <>
              <div className="row">
                <button className="btn-new" onClick={syncNow} disabled={busy}>{busy ? 'Syncing…' : 'Sync now'}</button>
                <button className="ghost small" onClick={() => disconnect('microsoft')}>Disconnect</button>
              </div>
              {msConn.last_poll_at ? <p className="provider-sub">Last poll {formatDateTime(msConn.last_poll_at)}</p> : null}
              <p className="provider-sub" style={{ fontStyle: 'italic' }}>Encrypted refresh token stored · secret never shown</p>
            </>
          ) : (
            <div className="row">
              <button className="ghost" onClick={() => connect('microsoft')} disabled={busy || !redirectUri.trim()}>Connect Microsoft</button>
            </div>
          )}
        </div>
      </div>
      <p className="sub" style={{ fontStyle: 'italic' }}>Sync speed note: real emails take tens of seconds through the forensic pipeline, so multi-mail syncs finish but run slowly (background job queued for a future phase).</p>
      <div className="card" style={{ marginBottom: 14 }}>
        <h3>Connection settings</h3>
        <div className="grid" style={{ gap: 8, maxWidth: 560 }}>
          {conns.length > 0 ? (
            <div style={{ fontSize: 13 }}>
              Connected: {conns.map((m) => <span key={m.provider + m.account_email} className="mono" style={{ marginRight: 6 }}>{m.provider}:{m.account_email}</span>)}
            </div>
          ) : <Empty msg="No mailbox connected yet." />}
          <div>
            <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 4 }}>Redirect URI (must match provider console)</label>
            <input type="text" value={redirectUri} onChange={(e) => setRedirectUri(e.target.value)} placeholder="Redirect URI (must match provider console)" style={{ width: '100%' }} />
          </div>
          <div>
            <button
              type="button"
              className="ghost small"
              onClick={() => setShowSecret(!showSecret)}
              style={{ fontSize: 11, cursor: 'pointer', padding: '3px 8px', marginTop: 2 }}
            >
              {showSecret ? '▲ Hide custom credentials' : '⚙ Custom credentials (optional)'}
            </button>
          </div>
          {showSecret && (
            <div className="grid" style={{ gap: 8, marginTop: 4, padding: 10, border: '1px solid var(--border)', borderRadius: 6 }}>
              <div>
                <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 4 }}>OAuth Client ID</label>
                <input type="text" value={clientId} onChange={(e) => updateClientId(e.target.value)} placeholder="Leave blank to use server .env" style={{ width: '100%' }} />
              </div>
              <div>
                <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 4 }}>OAuth Client Secret</label>
                <input type="password" value={clientSecret} onChange={(e) => updateClientSecret(e.target.value)} placeholder="Leave blank to use server .env" style={{ width: '100%' }} />
              </div>
            </div>
          )}
        </div>
      </div>
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

const COLS = [
  { key: 'Open', color: 'var(--correlation)', cls: 'k-open' },
  { key: 'InProgress', color: 'var(--high)', cls: 'k-progress' },
  { key: 'Closed', color: 'var(--low)', cls: 'k-closed' },
];

export function Cases() {
  usePageMeta({
    title: 'Case Management - Kanban Board - ThreatOptic',
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
  const [menuOpen, setMenuOpen] = useState<string | null>(null);

  const statusPill = (key: string) => (key === 'Open' ? 'verdict-draft' : key === 'Closed' ? 'verdict-low' : 'verdict-progress');

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
      <Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Case Management' }]} />
      <div className="greet-row">
        <div>
          <h1 className="greet-title">Case management</h1>
          <p className="greet-sub">Track investigations from triage to closure. {cases.length} case{cases.length === 1 ? '' : 's'} in scope.</p>
        </div>
      </div>
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
              <div className={`kcol-head ${c.cls}`}>{c.key === 'InProgress' ? 'In Progress' : c.key} · {cases.filter((k) => k.status === c.key).length}</div>
              {cases.filter((k) => k.status === c.key).map((k) => (
                <div key={k.id} className="kcard">
                  <div className="invest-card-top">
                    <span className={`verdict-pill ${statusPill(k.status)}`}>
                      <span className="ws-dot" style={{ background: severityColor(k.status === 'Open' ? 'high' : k.status === 'Closed' ? 'low' : 'medium') }} aria-hidden="true" />
                      {k.status === 'InProgress' ? 'In Progress' : k.status}
                    </span>
                    <button type="button" className="doc-tool-btn" style={{ width: 30, height: 30 }} aria-label={`Actions for ${k.title}`} title="Actions" aria-expanded={menuOpen === k.id} onClick={() => setMenuOpen(menuOpen === k.id ? null : k.id)}>⋯</button>
                  </div>
                  <b>{k.title}</b>
                  <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
                    <span className="mono">{k.id.slice(0, 8)}</span> · {k.email_ids?.length ?? 0} email(s)
                  </div>
                  <div style={{ marginTop: 8 }}>
                    <AvatarStack names={[k.title, 'analyst']} max={2} />
                  </div>
                  {menuOpen === k.id && (
                    <div className="row" style={{ marginTop: 8 }}>
                      {COLS.filter((x) => x.key !== c.key).map((x) => (
                        <button key={x.key} className="ghost small" onClick={() => { setMenuOpen(null); void move(k.id, x.key); }}>{x.key === 'InProgress' ? 'In Progress' : x.key}</button>
                      ))}
                      {isAdmin && <button className="danger small" onClick={() => remove(k.id)}>Delete</button>}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ))}
        </div>
      )}
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
    image: 'https://socforensics.io/og-image.svg',
  });
  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Privacy Policy' }]} />
      <div className="utility-canvas">
        <div className="utility-card">
          <div style={{ fontSize: 12, color: 'var(--muted)' }}>Home &gt; Privacy Policy</div>
          <h1 style={{ margin: '8px 0 4px' }}>Privacy Policy</h1>
          <p className="sub">Effective 20 Sep 2026 - ThreatOptic, 301 Congress Ave, Austin, TX 78701. Contact hello@socforensics.io</p>
        <h3>What we collect</h3>
        <p>Analyst credentials (email, role via Supabase Auth), ingested email RFC822 content for forensic scoring, mailbox OAuth tokens stored encrypted server-side, and browser local storage for theme and cookie consent. We do not sell data.</p>
        <h3>How we use email content</h3>
        <p>Uploaded mail is parsed, scored 0-100, checked for SPF/DKIM/DMARC and threat intel, then stored with PII masked previews and a SHA-256 hash for chain-of-custody. Raw content is retained per your retention setting and purged by the daily scheduler. See retention_audit.log.</p>
        <h3>Cookies</h3>
        <p>Essential cookies keep you signed in (in-memory JWT, not localStorage) and remember theme and consent choice. No advertising cookies. Analytics is off by default. Use the banner to accept or decline essential storage.</p>
        <h3>Your rights</h3>
        <p>Request access or deletion of your analyst account and ingested data via hello@socforensics.io. OAuth refresh tokens can be revoked via Mailboxes disconnect.</p>
        <h3>Data location</h3>
        <p>Self-hosted SQLite by default or your Postgres/Elastic/Neo4j cluster per docker-compose. Geolocation uses offline GeoIP fallback unless live lookups are enabled.</p>
        <p style={{ marginTop: 16 }}><a href="mailto:hello@socforensics.io" style={{ color: 'var(--teal)' }}>Contact our Data Protection Officer →</a></p>
        </div>
      </div>
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
    image: 'https://socforensics.io/og-image.svg',
  });
  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Terms and Conditions' }]} />
      <div className="utility-canvas">
        <div className="utility-card">
          <div style={{ fontSize: 12, color: 'var(--muted)' }}>Home &gt; Terms and Conditions</div>
          <h1 style={{ margin: '8px 0 4px' }}>Terms and Conditions</h1>
          <p className="sub">Effective 20 Sep 2026 - Use of socforensics.io is governed by these terms.</p>
          <h3>Acceptable use</h3>
          <p>Upload only mail you are authorized to analyze. Do not ingest illegal content or attempt to bypass authentication, retrain the classifier without approval, or scrape threat intel feeds.</p>
          <h3>Forensic reports</h3>
          <p>Scores and classifications are investigative aids, not legal guarantees. Verify with SPF, DKIM, headers, and intel hits before action.</p>
          <h3>Availability</h3>
          <p>Service is provided as-is. The team may update scoring weights, retention, and polling intervals. Check Model Transparency for current metrics.</p>
          <h3>Liability</h3>
          <p>To the full extent permitted by law, ThreatOptic is not liable for indirect damages from missed or flagged mail.</p>
          <h3>Contact</h3>
          <p>Questions: hello@socforensics.io. Postal: 301 Congress Ave, Suite 400, Austin, TX 78701.</p>
        </div>
      </div>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Terms and Conditions - ThreatOptic',
        description: 'Terms and conditions for ThreatOptic', url: `${CANONICAL_BASE}/terms`,
        isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
    </div>
  );
}
