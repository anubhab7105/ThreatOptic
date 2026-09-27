import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { ApiError, assertIdpUrl, downloadReport, jdel, jget, jpatch, jpost, pollTask, uploadEmFile } from './api';
import { useAuth } from './auth';
import { AISparkle, AuthPill, AvatarStack, Empty, MetricRing, ScoreBadge, SkeletonList, StatCard, ThreatGauge, Toast, VerdictPill, greetingFor, severityColor, PasswordToggle } from './components';
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
    title: 'SOC Forensics Lab | Email Threat Detection & Forensic Intelligence',
    description: 'Real-time phishing, BEC, and spoofing detection for SOC analysts. Header forensics, geolocation, identity correlation, and chain-of-custody reporting.',
    canonical: '/',
    image: 'https://socforensics.io/og-image.svg',
  });

  return (
    <div className="landing-page">
      <header className="landing-header">
        <nav className="landing-nav" aria-label="Primary">
          <Link to="/" className="brand" aria-label="SOC Forensics Lab home"><span aria-hidden="true">◈</span> SOC Forensics Lab</Link>
          <div className="landing-nav-links">
            <Link to="/login" className="nav-link">Sign In</Link>
            <Link to="/login" className="nav-link btn-primary">Get Started</Link>
          </div>
          <ThemeToggle />
        </nav>
      </header>

      <main id="main-content">
        <section className="hero" aria-labelledby="hero-title">
          <div className="hero-content">
            <h1 id="hero-title">Email threat detection that explains itself.</h1>
            <p className="hero-subtitle">Score every message 0&ndash;100 with SPF/DKIM/DMARC, URL and attachment intelligence, geolocation, and identity graphs. Export chain-of-custody PDF/JSON reports.</p>
            <div className="hero-actions">
              <Link to="/login" className="btn-primary">Start Free Trial</Link>
              <Link to="/model" className="btn-secondary">View Model Transparency</Link>
            </div>
            <p className="hero-trust">Self-hosted. No vendor lock-in. Used by incident response teams worldwide.</p>
          </div>
          <div className="hero-visual" aria-hidden="true">
            <svg viewBox="0 0 600 400" className="hero-illustration" role="img" aria-label="Email threat analysis dashboard showing fraud score, authentication results, and geolocation">
              <defs>
                <linearGradient id="gridGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#0b1220" stopOpacity="0" />
                  <stop offset="100%" stopColor="#16233f" stopOpacity="0.3" />
                </linearGradient>
              </defs>
              <rect x="20" y="20" width="560" height="360" rx="12" fill="url(#gridGradient)" stroke="#24365c" strokeWidth="1.5" />
              <rect x="40" y="40" width="200" height="120" rx="8" fill="#111c33" stroke="#24365c" strokeWidth="1" />
              <text x="50" y="65" fill="#60a5fa" fontSize="12" fontWeight="600" fontFamily="system-ui">FRAUD SCORE</text>
              <text x="50" y="95" fill="#ef4444" fontSize="48" fontWeight="800" fontFamily="ui-monospace">94</text>
              <text x="50" y="125" fill="#93a1bd" fontSize="11" fontFamily="system-ui">Critical &mdash; BEC Detected</text>
              <rect x="40" y="180" width="200" height="120" rx="8" fill="#111c33" stroke="#24365c" strokeWidth="1" />
              <text x="50" y="205" fill="#60a5fa" fontSize="12" fontWeight="600" fontFamily="system-ui">AUTHENTICATION</text>
              <g fontSize="11" fontFamily="system-ui">
                <text x="50" y="230" fill="#ef4444">SPF: Fail</text>
                <text x="50" y="250" fill="#ef4444">DKIM: Fail</text>
                <text x="50" y="270" fill="#ef4444">DMARC: Fail</text>
              </g>
              <rect x="260" y="40" width="300" height="260" rx="8" fill="#111c33" stroke="#24365c" strokeWidth="1" />
              <text x="280" y="65" fill="#60a5fa" fontSize="12" fontWeight="600" fontFamily="system-ui">GEOLOCATION & IDENTITY GRAPH</text>
              <circle cx="410" cy="180" r="80" fill="none" stroke="#24365c" strokeWidth="1.5" />
              <circle cx="410" cy="180" r="45" fill="#ef4444" fillOpacity="0.15" />
              <circle cx="410" cy="180" r="45" fill="none" stroke="#ef4444" strokeWidth="2" strokeDasharray="4,4" />
              <circle cx="410" cy="180" r="8" fill="#ef4444" />
              <text x="410" y="280" fill="#93a1bd" fontSize="11" fontFamily="system-ui" textAnchor="middle">Origin: 45.148.10.88 (VPN)</text>
              <g fontSize="10" fill="#38bdf8" fontFamily="system-ui">
                <circle cx="320" cy="140" r="6" fill="#38bdf8" />
                <text x="330" y="144" fill="#e5e7eb">sender@domain</text>
                <circle cx="480" cy="120" r="6" fill="#f59e0b" />
                <text x="490" y="124" fill="#e5e7eb">malicious.example</text>
                <circle cx="480" cy="240" r="6" fill="#a855f7" />
                <text x="490" y="244" fill="#e5e7eb">Campaign #C-2026-0892</text>
              </g>
            </svg>
          </div>
        </section>

        <section className="features" aria-labelledby="features-title">
          <h2 id="features-title" className="section-title">Built for forensic analysis</h2>
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
              <p>Graph-based clustering links shared infrastructure across campaigns. Detect coordinated attacks by IP, domain, and sender overlap.</p>
            </article>
            <article className="feature-card">
              <div className="feature-icon" aria-hidden="true">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" /></svg>
              </div>
              <h3>Chain-of-Custody Reports</h3>
              <p>SHA-256 hashed originals. PDF and JSON exports with timestamps, scores, and evidence references for legal proceedings.</p>
            </article>
            <article className="feature-card">
              <div className="feature-icon" aria-hidden="true">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" /></svg>
              </div>
              <h3>Model Transparency</h3>
              <p>Open metrics: accuracy, macro F1, per-class precision/recall, confusion matrix. Retrained on your data with audit logs.</p>
            </article>
            <article className="feature-card">
              <div className="feature-icon" aria-hidden="true">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><path d="M12 6v6l4 2" /></svg>
              </div>
              <h3>Real-Time Ingestion</h3>
              <p>Paste RFC822, upload .eml, or connect Gmail/Microsoft mailboxes via OAuth. Background Celery queue for high-volume pipelines.</p>
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

        <section className="cta" aria-labelledby="cta-title">
          <h2 id="cta-title">Ready to analyze your first email?</h2>
          <p>Create an account in seconds. No credit card required.</p>
          <Link to="/login" className="btn-primary btn-large">Create Free Account</Link>
        </section>
      </main>

      <footer className="landing-footer">
        <div className="footer-grid">
          <div className="footer-brand">
            <Link to="/" className="brand" aria-label="SOC Forensics Lab home"><span aria-hidden="true">◈</span> SOC Forensics Lab</Link>
            <p>Email threat detection, geolocation, and forensic intelligence for security operations teams.</p>
          </div>
          <nav className="footer-links" aria-label="Product">
            <h4>Product</h4>
            <ul>
              <li><Link to="/model">Model Transparency</Link></li>
              <li><Link to="/login">Dashboard Demo</Link></li>
              <li><a href="https://github.com" target="_blank" rel="noopener">GitHub</a></li>
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
          <p>&copy; 2026 SOC Forensics Lab. 301 Congress Ave, Austin, TX 78701.</p>
        </div>
      </footer>

      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'SOC Forensics Lab | Email Threat Detection',
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

function InternalLinks({ current }: { current: string }) {
  // Public visitors can only reach public routes — linking them to
  // auth-gated pages (/dashboard, /campaigns, ...) would 404.
  const { user } = useAuth();
  const authLinks = [
    { href: '/dashboard', label: 'Dashboard', desc: 'Threat overview' },
    { href: '/campaigns', label: 'Campaigns', desc: 'Infrastructure clusters' },
    { href: '/cases', label: 'Cases', desc: 'Kanban investigation' },
    { href: '/mailboxes', label: 'Mailboxes', desc: 'OAuth connectors' },
    { href: '/model', label: 'Model Info', desc: 'Transparency & metrics' },
  ];
  const publicLinks = [
    { href: '/', label: 'Home', desc: 'Product overview' },
    { href: '/login', label: 'Sign In', desc: 'Analyst access' },
    { href: '/model', label: 'Model Info', desc: 'Transparency & metrics' },
    { href: '/privacy', label: 'Privacy', desc: 'Data handling' },
    { href: '/terms', label: 'Terms', desc: 'Acceptable use' },
  ];
  const links = (user ? authLinks : publicLinks).filter(l => l.href !== current);
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
          <div style={{ fontWeight: 800, fontSize: 20 }}>◈ Netraksha</div>
          <h2>Trace every email back to its source.</h2>
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

          <h2 className="login-form-title">Netraksha</h2>
          <p className="login-form-sub">Sign in to access the email threat dashboard.</p>

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
            <label htmlFor="login-email" className="login-field-label">Username</label>
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
            <div>admin / admin123 · analyst / analyst123 (seeded demo accounts)</div>
            <div style={{ marginTop: 8, display: 'flex', gap: 8, justifyContent: 'center' }}>
              <button type="button" className="ghost small" style={{ fontSize: 12, padding: '4px 10px' }} onClick={() => { setEmail('admin'); setPassword('admin123'); login('admin', 'admin123'); }}>⚡ Quick Login: Admin</button>
              <button type="button" className="ghost small" style={{ fontSize: 12, padding: '4px 10px' }} onClick={() => { setEmail('analyst'); setPassword('analyst123'); login('analyst', 'analyst123'); }}>⚡ Quick Login: Analyst</button>
            </div>
          </div>
          <p className="sub" style={{ marginTop: 8, fontSize: 12 }}>Public self-registration → ReadOnly by default. Admin creation requires the out-of-band SETUP_TOKEN.</p>
        </div>
      </div>

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

function GmailPanel({ onSynced }: { onSynced: () => void }) {
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
              <label style={{ fontSize: 12, fontWeight: 600 }}>Google OAuth Client ID</label>
              <input type="text" value={clientId} onChange={(e) => updateClientId(e.target.value)} placeholder="Google OAuth client ID" />
              <label style={{ fontSize: 12, fontWeight: 600 }}>Google OAuth Client Secret</label>
              <div className="row" style={{ gap: 6 }}>
                <input type={showSecret ? "text" : "password"} style={{ flex: 1 }} value={clientSecret} onChange={(e) => updateClientSecret(e.target.value)} placeholder="Google OAuth client secret" />
                <button type="button" className="ghost small" onClick={() => setShowSecret(!showSecret)}>{showSecret ? 'Hide' : 'Show'}</button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div>
          <p className="sub" style={{ marginTop: 0 }}>
            Connect your Gmail mailbox via Google OAuth (read-only) to import and analyze emails.
          </p>
          <div className="grid" style={{ gap: 8, maxWidth: 560 }}>
            <div>
              <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 4 }}>Redirect URI (must match Google Console)</label>
              <input type="text" value={redirectUri} onChange={(e) => setRedirectUri(e.target.value)} placeholder="Redirect URI (must match Google console)" style={{ width: '100%' }} />
            </div>
            <div>
              <button
                type="button"
                className="ghost small"
                onClick={() => setShowCreds(!showCreds)}
                style={{ fontSize: 11, cursor: 'pointer', padding: '3px 8px', marginTop: 2 }}
              >
                {showCreds ? '▲ Hide custom credentials' : '⚙ Custom credentials (optional)'}
              </button>
            </div>
            {showCreds && (
              <div className="grid" style={{ gap: 8, marginTop: 4, padding: 10, background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--border)', borderRadius: 6 }}>
                <div>
                  <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 4 }}>Google OAuth Client ID</label>
                  <input type="text" value={clientId} onChange={(e) => updateClientId(e.target.value)} placeholder="Leave blank to use server .env" style={{ width: '100%' }} />
                </div>
                <div>
                  <label style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 4 }}>Google OAuth Client Secret</label>
                  <div className="row" style={{ gap: 6 }}>
                    <input type={showSecret ? "text" : "password"} style={{ flex: 1 }} value={clientSecret} onChange={(e) => updateClientSecret(e.target.value)} placeholder="Leave blank to use server .env" />
                    <button type="button" className="ghost small" onClick={() => setShowSecret(!showSecret)}>{showSecret ? 'Hide' : 'Show'}</button>
                  </div>
                </div>
              </div>
            )}
            <div className="row" style={{ marginTop: 4 }}>
              <button className="ghost" onClick={getUrl} disabled={busy || !redirectUri.trim()}>Connect Gmail</button>
            </div>
            {authUrl && (
              <div style={{ marginTop: 8, padding: 12, background: 'rgba(59, 130, 246, 0.12)', border: '1px solid #3b82f6', borderRadius: 8 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#93c5fd', marginBottom: 6 }}>
                  👉 Click below if Google login did not open automatically:
                </div>
                <a
                  href={authUrl}
                  style={{
                    display: 'inline-block',
                    background: '#2563eb',
                    color: '#ffffff',
                    fontWeight: 700,
                    fontSize: 13,
                    padding: '8px 16px',
                    borderRadius: 6,
                    textDecoration: 'none',
                    boxShadow: '0 2px 4px rgba(0,0,0,0.2)',
                  }}
                >
                  Open Google Consent Screen →
                </a>
              </div>
            )}
            <div className="row" style={{ marginTop: 6 }}>
              <input type="text" value={code} onChange={(e) => setCode(e.target.value)} placeholder="Authorization code (auto-filled on redirect)" style={{ flex: 1 }} />
              <input type="text" value={oauthState} onChange={(e) => setOauthState(e.target.value)} placeholder="State (auto-filled on redirect)" style={{ flex: 1 }} />
              <button onClick={() => finish()} disabled={busy || !code.trim() || !oauthState.trim()}>Finish connection</button>
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
    window.addEventListener('soc:top-search', onTopSearch);
    return () => window.removeEventListener('soc:top-search', onTopSearch);
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

  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Threat Dashboard' }]} />
      <div className="greet-row">
        <div>
          <h1 className="greet-title">{greetingFor()}, {displayName}!</h1>
          <p className="greet-sub">Real-time phishing, BEC and spoofing detection across ingested mail.</p>
        </div>
        <div className="greet-actions">
          <button type="button" className="pill-filter" onClick={() => { setSevFilter('all'); scrollTo('all-emails'); }} title="Show this week's emails">This Week ▾</button>
          <button type="button" className="btn-note" onClick={() => { scrollTo('ingest-panel'); setTimeout(() => document.getElementById('ingest-raw')?.focus(), 300); }} title="Write an analysis note">Note</button>
          <button type="button" className="btn-tpl" onClick={() => { setRaw(PHISH_SAMPLE); scrollTo('ingest-panel'); }} title="Load a sample template">Template</button>
          <AISparkle onClick={() => scrollTo('recent-investigations')} />
          <button type="button" className="btn-new" onClick={() => { scrollTo('ingest-panel'); setTimeout(() => document.getElementById('ingest-raw')?.focus(), 300); }}>+ New Analysis</button>
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
            <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', marginBottom: 18 }}>
              <div className="card">
                <h3>Score distribution</h3>
                <div className="distbar" role="img" aria-label={`Score distribution: Critical ${dist.critical}, High ${dist.high}, Medium ${dist.medium}, Low ${dist.low}`}>
                  <div style={{ width: `${(100 * dist.critical) / distTotal}%`, background: '#DC2626' }} />
                  <div style={{ width: `${(100 * dist.high) / distTotal}%`, background: '#EA580C' }} />
                  <div style={{ width: `${(100 * dist.medium) / distTotal}%`, background: '#F59E0B' }} />
                  <div style={{ width: `${(100 * dist.low) / distTotal}%`, background: '#22C55E' }} />
                </div>
                <div className="legend">
                  <span><span className="sev" style={{ background: '#DC2626' }} />Critical {dist.critical}</span>
                  <span><span className="sev" style={{ background: '#EA580C' }} />High {dist.high}</span>
                  <span><span className="sev" style={{ background: '#F59E0B' }} />Medium {dist.medium}</span>
                  <span><span className="sev" style={{ background: '#22C55E' }} />Low {dist.low}</span>
                </div>
              </div>
              <div className="card">
                <h3>Threat Overview</h3>
                <ThreatGauge dist={dist} />
              </div>
            </div>
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

      <div className="toolbar">
        <input id="dash-search" type="search" placeholder="Search subject / sender / body…" value={q} onChange={(e) => setQ(e.target.value)}
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

      <div id="recent-investigations" className="card" style={{ marginBottom: 18 }}>
        <h3>Recent Investigations</h3>
        {loading ? <SkeletonList rows={2} /> : filtered.length === 0 ? <Empty msg="No investigations yet. Ingest one above to get started." /> : (
          <div className="invest-grid" style={{ marginBottom: 0 }}>
            {filtered.slice(0, 3).map((e) => {
              const s = scores[e.id];
              return (
                <Link key={e.id} to={`/email/${e.id}`} className="card invest-card hoverable" style={{ textDecoration: 'none', color: 'inherit', margin: 0 }}>
                  <div className="invest-card-top">
                    {s ? <ScoreBadge v={s.score} /> : <span style={{ color: 'var(--muted)' }}>…</span>}
                    <AvatarStack names={[e.sender_address, displayName]} max={2} />
                  </div>
                  <div className="invest-subject">{e.subject || '(no subject)'}</div>
                  <div className="invest-meta">{e.sender_address} · {formatDateTime(e.timestamp)}</div>
                </Link>
              );
            })}
          </div>
        )}
      </div>

      <div className="two-col" style={{ marginBottom: 18 }}>
        <div className="card" id="all-emails" style={{ margin: 0 }}>
          <h3>All Emails</h3>
          {loading ? <SkeletonList /> : filtered.length === 0 ? <Empty msg="No emails match. Ingest one above to get started." /> : (
            <table className="tbl">
              <thead><tr><th>Subject</th><th>Sender</th><th>Received</th><th>Verdict</th><th>Reports</th></tr></thead>
              <tbody>
                {filtered.map((e) => {
                  const s = scores[e.id];
                  return (
                    <tr key={e.id}>
                      <td><Link to={`/email/${e.id}`}>{e.subject || '(no subject)'}</Link></td>
                      <td><span className="mono">{e.sender_address}</span></td>
                      <td style={{ color: 'var(--muted)', fontSize: 12 }}>{formatDateTime(e.timestamp)}</td>
                      <td>
                        {s ? <ScoreBadge v={s.score} /> : <span style={{ color: 'var(--muted)' }}>…</span>}
                        <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>{s?.cls ?? '—'}</div>
                      </td>
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
        </div>
        <div className="card" style={{ margin: 0 }}>
          <h3>Activity Feed</h3>
          {loading ? <SkeletonList rows={3} /> : filtered.length === 0 ? <Empty msg="Activity will appear once mail is ingested." /> : (
            <ul className="activity-feed">
              {filtered.slice(0, 5).map((e) => {
                const s = scores[e.id];
                return (
                  <li key={e.id} className="activity-item">
                    <span className="activity-dot" aria-hidden="true" />
                    <div>
                      <div>System scored sender as <b>{s?.cls ?? '—'} {s?.score ?? ''}</b></div>
                      <div className="activity-time"><Link to={`/email/${e.id}`}>{(e.subject || '(no subject)').slice(0, 40)}</Link> · {formatDateTime(e.timestamp)}</div>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>

      <InternalLinks current="/dashboard" />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: 'Global Threat Dashboard - SOC Forensics Lab',
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
    switch (k) {
      case 'Domain': return '#f59e0b'; // Amber
      case 'IP_Address': return '#ef4444'; // Crimson
      case 'Threat_Campaign': return '#a855f7'; // Purple
      case 'Email_Address': return '#10b981'; // Emerald
      default: return '#38bdf8'; // Sky
    }
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
                color: filterKind === k ? '#060a14' : getColor(k),
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
          <button type="button" className="ghost small" onClick={() => setZoom((z) => Math.max(0.7, z - 0.15))} title="Zoom Out" style={{ padding: '2px 8px' }}>−</button>
          <span style={{ fontSize: 11, color: 'var(--muted)', minWidth: 38, textAlign: 'center' }}>{Math.round(zoom * 100)}%</span>
          <button type="button" className="ghost small" onClick={() => setZoom((z) => Math.min(1.6, z + 0.15))} title="Zoom In" style={{ padding: '2px 8px' }}>+</button>
          {zoom !== 1 && (
            <button type="button" className="ghost small" onClick={() => setZoom(1)} style={{ fontSize: 11, padding: '2px 6px' }}>Reset</button>
          )}
        </div>
      </div>

      {/* SVG Visualization Canvas */}
      <div className="graph-canvas" style={{ position: 'relative', overflow: 'hidden', borderRadius: 16, border: '1px solid var(--border)' }}>
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
              <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#38bdf8" floodOpacity="0.6" />
            </filter>
            <filter id="glow-node" x="-30%" y="-30%" width="160%" height="160%">
              <feDropShadow dx="0" dy="0" stdDeviation="3" floodColor="#ffffff" floodOpacity="0.3" />
            </filter>
            <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#3b82f6" fillOpacity="0.8" />
            </marker>
            <marker id="arrow-highlight" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M 0 0.5 L 10 5 L 0 9.5 z" fill="#38bdf8" />
            </marker>
          </defs>

          {/* Grid background lines */}
          <g opacity={0.12}>
            {Array.from({ length: 11 }).map((_, i) => (
              <line key={`gx-${i}`} x1={i * 76} y1={0} x2={i * 76} y2={h} stroke="#475569" strokeWidth={1} strokeDasharray="3,3" />
            ))}
            {Array.from({ length: 6 }).map((_, i) => (
              <line key={`gy-${i}`} x1={0} y1={i * 80} x2={w} y2={i * 80} stroke="#475569" strokeWidth={1} strokeDasharray="3,3" />
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
                  stroke={isHighlighted && activeFocusId ? '#38bdf8' : '#3b82f6'}
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
                      fill="#0b1329"
                      stroke={isHighlighted && activeFocusId ? '#38bdf8' : 'var(--border)'}
                      strokeWidth={0.9}
                    />
                    <text x={0} y={2.8} fill={isHighlighted && activeFocusId ? '#e0f2fe' : '#94a3b8'} fontSize={8} fontWeight={700} textAnchor="middle">
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
                  stroke="#070d1d"
                  strokeWidth={2.5}
                  filter={isSelected || isHovered ? 'url(#glow-strong)' : 'url(#glow-node)'}
                />

                {/* Node Icon / Letter */}
                <text y={4} fill="#060a14" fontSize={isCenter ? 12 : 10} fontWeight={900} textAnchor="middle">
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
                    fill="rgba(8, 12, 24, 0.85)"
                  />
                  <text
                    y={3.5}
                    fill={isSelected || isHovered ? '#ffffff' : '#e2e8f0'}
                    fontSize={10.5}
                    fontWeight={isSelected || isHovered ? 700 : 600}
                    textAnchor="middle"
                  >
                    {lbl.length > 20 ? lbl.slice(0, 18) + '…' : lbl}
                  </text>
                </g>

                {/* Node Kind Badge */}
                <text y={r + 28} fill="#94a3b8" fontSize={8.5} fontWeight={500} textAnchor="middle">
                  {n.kind.replace('_', ' ')}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Selected Entity Details Card */}
      {selectedNodeData && (
        <div className="card" style={{ background: '#0b1329', border: `1px solid ${getColor(selectedNodeData.kind)}`, padding: 12, marginTop: 4 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 8 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span
                  style={{
                    background: getColor(selectedNodeData.kind),
                    color: '#060a14',
                    fontSize: 11,
                    fontWeight: 800,
                    padding: '2px 8px',
                    borderRadius: 4,
                  }}
                >
                  {selectedNodeData.kind.replace('_', ' ')}
                </span>
                <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: '#f8fafc' }}>
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
                        background: '#131e3d',
                        border: '1px solid var(--border)',
                        padding: '3px 8px',
                        borderRadius: 6,
                        fontSize: 11,
                        cursor: 'pointer',
                      }}
                      title="Click to jump to this entity"
                    >
                      <span style={{ color: '#38bdf8', fontWeight: 700 }}>
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
        const bar = c > 0 ? '#FB923C' : c < 0 ? '#22C55E' : '#8A90A8';
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

  if (err) return <div className="page"><Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Email', href: '/dashboard' }, { label: 'Error' }]} /><Link to="/dashboard">← back</Link><Toast msg={err} /></div>;
  if (!d) return <div className="page"><Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Email' }]} /><Link to="/dashboard">← back</Link><SkeletonList /></div>;
  const a = d.analysis || {};
  const t = d.trace || {};
  const auth = a.authentication_results || {};
  const relay: any[] = Array.isArray(t.relay_chain) ? t.relay_chain : [];

  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Investigations', href: '/dashboard' }, { label: subject.slice(0, 36) || 'Email Detail' }]} />
      <div className="doc-title-row">
        <h1 className="doc-title">{d.email.subject || '(no subject)'}</h1>
        <VerdictPill score={a.fraud_score ?? 0} classification={a.threat_classification} />
        <div className="doc-tools">
          <AISparkle onClick={() => setTab(1)} title="Explain this score" />
          <button type="button" className="doc-tool-btn" title="More actions" aria-label="More actions">⋯</button>
        </div>
      </div>
      <p className="sub">
        {a.threat_classification || 'Unclassified'} · action: <b>{a.action_taken || '—'}</b> ·{' '}
        received: <b>{formatDateTime(d.email.timestamp)}</b> ·{' '}
        <button className="ghost small" onClick={() => triggerDownload('pdf')}>forensic PDF</button>{' '}
        <button className="ghost small" onClick={() => triggerDownload('json')}>JSON</button>
      </p>
      <div className="doc-section">
        <div className="doc-rail" aria-hidden="true" />
        <div>
          <h3>Introduction</h3>
          <p>
            Summary: message from <span className="mono">{d.email.sender_address || 'unknown sender'}</span> scored{' '}
            <b>{a.fraud_score ?? 0}</b> ({a.threat_classification || 'Unclassified'}) with action <b>{a.action_taken || '—'}</b>.
            SPF/DKIM/DMARC: {(auth.spf?.status || '—').toUpperCase()} / {(auth.dkim?.status || '—').toUpperCase()} / {(auth.dmarc?.status || '—').toUpperCase()}.
            {(a.nlp_cues_detected || []).length > 0 ? ` Key signals: ${(a.nlp_cues_detected || []).join(', ')}.` : ''}
          </p>
          <div style={{ marginTop: 8 }}>
            <AvatarStack names={[d.email.sender_address || 'sender', 'analyst']} max={3} />
          </div>
        </div>
      </div>

      {cases.length > 0 && (
        <div className="row" id="email-case-row" style={{ marginTop: 8, marginBottom: 12, alignItems: 'center' }}>
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
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
              <AuthPill name="SPF" status={auth.spf?.status} />
              <AuthPill name="DKIM" status={auth.dkim?.status} />
              <AuthPill name="DMARC" status={auth.dmarc?.status} />
              <AuthPill name="Alignment" status={auth.aligned ? 'aligned' : 'unaligned'} />
            </div>
            {(auth.spf?.detail || auth.dkim?.detail || auth.dmarc?.detail) && (
              <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 8, lineHeight: 1.45 }}>
                {auth.spf?.detail && <div><b>SPF:</b> {auth.spf.detail}</div>}
                {auth.dkim?.detail && <div><b>DKIM:</b> {auth.dkim.detail}</div>}
                {auth.dmarc?.detail && <div><b>DMARC:</b> {auth.dmarc.detail}</div>}
              </div>
            )}
            <h3 style={{ marginTop: 14 }}>Threat intel hits ({(a.threat_intel_hits || []).length})</h3>
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
          <h3>Key Signals</h3>
          <p className="sub" style={{ marginBottom: 10 }}>Weighted contribution of each signal to the final score — peach bars raise risk, green bars lower it.</p>
          <ScoreWhy breakdown={a.score_breakdown} score={a.fraud_score ?? 0} />
          <div style={{ marginTop: 10 }}>
            <AvatarStack names={['analyst', 'soc.ir']} max={2} />
          </div>
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
                <div className="rounded-map">
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
                </p>
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
          <p className="sub" style={{ marginBottom: 10 }}>Trace node graph — domain linked to related campaign entities.</p>
          <GraphSvg graph={graph} />
          <h3 style={{ marginTop: 12 }}>Raw graph</h3>
          <pre className="dump">{JSON.stringify(graph, null, 2)}</pre>
        </div>
      )}
      <div className="doc-footer">
        <AvatarStack names={['analyst', 'soc.ir']} max={2} />
        <span>Last analyzed {formatDateTime(d.email.timestamp)}</span>
        <span style={{ flex: 1 }} />
        <button className="ghost small" onClick={() => document.getElementById('email-case-row')?.scrollIntoView({ behavior: 'smooth' })}>Add to case</button>
        <button className="ghost small" onClick={() => triggerDownload('pdf')}>Export PDF</button>
        <button className="ghost small" onClick={() => triggerDownload('json')}>JSON</button>
      </div>
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
      <Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Campaigns' }]} />
      <div className="greet-row">
        <div>
          <h1 className="greet-title">{greetingFor()}, Analyst!</h1>
          <p className="greet-sub">Graph-detected clusters: domains sharing sender infrastructure, joined with forensic records.</p>
        </div>
        <div className="greet-actions">
          <AISparkle onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })} title="Summarize campaigns" />
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
      <Breadcrumb items={[{ label: 'Home', href: '/dashboard' }, { label: 'Model Transparency' }]} />
      <div className="greet-row">
        <div>
          <h1 className="greet-title">{greetingFor()}, Analyst!</h1>
          <p className="greet-sub">
            Phishing/BEC/clean text classifier (TF-IDF + LogisticRegression), evaluated on a held-out split
            ({m.n_test} test / {m.n_train} train, seed {m.random_state}). Metrics cached by <code>scripts/train_nlp.py</code>.
          </p>
        </div>
      </div>
      <div className="metric-grid" style={{ marginBottom: 18 }}>
        <div className="card metric-card">
          <MetricRing pct={(m.accuracy ?? 0) * 100} />
          <div className="metric-label">Accuracy</div>
        </div>
        <div className="card metric-card">
          <MetricRing pct={(m.macro_f1 ?? 0) * 100} />
          <div className="metric-label">Macro F1</div>
        </div>
        <div className="card metric-card">
          <MetricRing pct={(m.macro_precision ?? 0) * 100} />
          <div className="metric-label">Macro precision</div>
        </div>
        <div className="card metric-card">
          <MetricRing pct={(m.macro_recall ?? 0) * 100} />
          <div className="metric-label">Macro recall</div>
        </div>
      </div>
      <p className="sub">Honest scope note: TF-IDF + LogisticRegression contributes 30% of the fraud score — see the present-stage note in the PRD.</p>
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
          <h1 className="greet-title">{greetingFor()}, Analyst!</h1>
          <p className="greet-sub">Organization-level OAuth connectors (Google + Microsoft) with background polling. All credentials and refresh tokens are encrypted server-side.</p>
        </div>
      </div>
      <Toast msg={err} />
      {notice && <Toast msg={notice} kind="info" />}
      <div className="provider-grid" style={{ marginBottom: 14 }}>
        <div className="card provider-card">
          <div className="provider-top">
            <span className={`provider-icon${googleConn ? '' : ' idle'}`} aria-hidden="true">G</span>
            <div>
              <p className="provider-name">Google Workspace</p>
              <p className="provider-sub">{googleConn ? <span className="mono">{googleConn.account_email}</span> : 'Not connected'}</p>
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
            <span className={`provider-icon${msConn ? '' : ' idle'}`} aria-hidden="true">M</span>
            <div>
              <p className="provider-name">Microsoft 365</p>
              <p className="provider-sub">{msConn ? <span className="mono">{msConn.account_email}</span> : 'Not connected'}</p>
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
          <div className="row" style={{ marginTop: 4 }}>
            <Link to="/dashboard">Back to Dashboard</Link>
          </div>
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
  const [menuOpen, setMenuOpen] = useState<string | null>(null);

  const headColor = (key: string) => (key === 'Open' ? '#9AA1B5' : key === 'Closed' ? '#22C55E' : '#5B6CFF');
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
          <h1 className="greet-title">{greetingFor()}, Analyst!</h1>
          <p className="greet-sub">Track investigations from triage to closure.</p>
        </div>
        <div className="greet-actions">
          <span className="pill-filter" title="Cases in scope">This Week · {cases.length} cases</span>
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
              <div className="kcol-head" style={{ background: headColor(c.key) }}>{c.key === 'InProgress' ? 'In Progress' : c.key} {cases.filter((k) => k.status === c.key).length}</div>
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
      <div className="utility-canvas">
        <div className="utility-card">
          <div style={{ fontSize: 12, color: 'var(--muted)' }}>Home &gt; Privacy Policy</div>
          <h1 style={{ margin: '8px 0 4px' }}>Privacy Policy</h1>
          <p className="sub">Effective 20 Sep 2026 - SOC Forensics Lab, 301 Congress Ave, Austin, TX 78701. Contact hello@socforensics.io</p>
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
        </div>
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
          <p>To the full extent permitted by law, SOC Forensics Lab is not liable for indirect damages from missed or flagged mail.</p>
          <h3>Contact</h3>
          <p>Questions: hello@socforensics.io. Postal: 301 Congress Ave, Suite 400, Austin, TX 78701.</p>
        </div>
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
