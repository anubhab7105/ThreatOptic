import React, { Suspense, lazy, useEffect, useState } from 'react';
import { AvatarStack, KeyboardShortcuts, useKeyboardShortcuts } from './components';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom';
import './theme.css';
import { AuthProvider, useAuth } from './auth';
import { BASE, jpost } from './api';
import { BackToTop, ScrollProgress, SkipToContent } from './components';

// Code-split pages to reduce initial bundle
const Dashboard = lazy(() => import('./pages').then(m => ({ default: m.Dashboard })));
const EmailView = lazy(() => import('./pages').then(m => ({ default: m.EmailView })));
const Cases = lazy(() => import('./pages').then(m => ({ default: m.Cases })));
const Campaigns = lazy(() => import('./pages').then(m => ({ default: m.Campaigns })));
const CampaignDetail = lazy(() => import('./pages').then(m => ({ default: m.CampaignDetail })));
const LoginPage = lazy(() => import('./pages').then(m => ({ default: m.LoginPage })));
const LandingPage = lazy(() => import('./pages').then(m => ({ default: m.LandingPage })));
const ModelInfo = lazy(() => import('./pages').then(m => ({ default: m.ModelInfo })));
const Mailboxes = lazy(() => import('./pages').then(m => ({ default: m.Mailboxes })));
const PrivacyPolicy = lazy(() => import('./pages').then(m => ({ default: m.PrivacyPolicy })));
const TermsConditions = lazy(() => import('./pages').then(m => ({ default: m.TermsConditions })));

// Canonical domain - custom domain configured via CNAME / Cloudflare (see frontend/public/CNAME)
const CANONICAL_BASE = 'https://socforensics.io';

/** Serialize for <script> injection: escape `</` so crafted strings can
 * never break out of the script tag (C14 stored-XSS). */
function safeJsonLd(obj: unknown): string {
  return JSON.stringify(obj).replace(/<\//g, '<\\/');
}

function setCanonical(path: string) {
  const href = `${CANONICAL_BASE}${path}`;
  let el = document.querySelector<HTMLLinkElement>('link[rel="canonical"]');
  if (!el) {
    el = document.createElement('link');
    el.rel = 'canonical';
    document.head.appendChild(el);
  }
  el.href = href;
}

function setMeta(name: string, content: string) {
  let el = document.querySelector<HTMLMetaElement>(`meta[name="${name}"]`);
  if (!el) {
    el = document.createElement('meta');
    el.name = name;
    document.head.appendChild(el);
  }
  el.content = content;
}

export function Breadcrumb({ items }: { items: { label: string; href?: string }[] }) {
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

export function ThemeToggle() {
  const [theme, setTheme] = useState<string>(() => {
    try {
      const s = localStorage.getItem('soc-theme');
      if (s === 'light' || s === 'dark') return s;
      return document.documentElement.getAttribute('data-theme') || 'light';
    } catch { return 'light'; }
  });
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('soc-theme', theme); } catch { /* storage unavailable */ }
  }, [theme]);
  return (
    <button className="theme-toggle" onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')} aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`} title={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode (Inkwise light is default; dark SOC kept)`}>
      <span aria-hidden="true">{theme === 'light' ? '☀' : '☾'}</span> {theme === 'light' ? 'Dark' : 'Light'}
    </button>
  );
}

function CookieConsent() {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    try {
      const v = localStorage.getItem('soc-cookie-consent');
      if (!v) setVisible(true);
    } catch { setVisible(true); /* storage unavailable */ }
  }, []);
  const accept = () => {
    try { localStorage.setItem('soc-cookie-consent', 'accepted'); } catch { /* storage unavailable */ }
    setVisible(false);
  };
  const decline = () => {
    try { localStorage.setItem('soc-cookie-consent', 'declined'); } catch { /* storage unavailable */ }
    setVisible(false);
  };
  if (!visible) return null;
  return (
    <div className="cookie-banner" role="dialog" aria-label="Cookie consent">
      <p>
        We use essential cookies to keep you signed in and to remember your theme and privacy choice. Analytics cookies are off by default. See our <Link to="/privacy">Privacy Policy</Link> and <Link to="/terms">Terms</Link>.
      </p>
      <div className="cookie-actions">
        <button onClick={accept}>Accept essential</button>
        <button className="ghost" onClick={decline}>Decline</button>
        <Link to="/privacy" className="ghost" style={{ padding: '8px 14px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--panel-2)', textDecoration: 'none', color: 'var(--text)', fontWeight: 700, fontSize: 13 }}>Learn more</Link>
      </div>
    </div>
  );
}

function OAuthCallbackHandler() {
  const { provider } = useParams<{ provider?: string }>();
  const location = useLocation();

  useEffect(() => {
    const apiBase = (BASE || '').replace(/\/+$/, '');
    const prov = provider || (typeof sessionStorage !== 'undefined' && sessionStorage.getItem('soc_oauth_provider')) || 'google';
    if (typeof sessionStorage !== 'undefined') sessionStorage.removeItem('soc_oauth_provider');
    const target = `${apiBase}/api/v1/oauth/${prov}/callback${location.search}`;
    window.location.href = target;
  }, [provider, location]);

  return (
    <div className="page" style={{ textAlign: 'center', paddingTop: 60 }}>
      <h2>Connecting your account...</h2>
      <p className="sub">Please wait while we complete the authorization flow.</p>
    </div>
  );
}

function NotFoundPage() {
  const { user } = useAuth();
  useEffect(() => {
    document.title = 'Page Not Found - SOC Forensics Lab';
    setMeta('description', 'The requested forensic resource was not found. Return to the threat dashboard, campaigns, or case board.');
    setCanonical('/404');
    const ogTitle = document.querySelector('meta[property="og:title"]');
    if (ogTitle) ogTitle.setAttribute('content', 'Page Not Found - SOC Forensics Lab');
  }, []);
  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: 'Page not found' }]} />
      <div className="utility-canvas">
        <div className="utility-card">
          <div style={{ fontSize: 12, color: 'var(--muted)' }}>Home &gt; Page not found</div>
          <div className="utility-404">404</div>
          <p style={{ fontSize: 15, margin: '0 0 8px' }}>This investigation doesn&apos;t exist, or you don&apos;t have access to it.</p>
          <p className="sub">This is a routing miss, not a threat — nothing has been logged.</p>
          <div style={{ margin: '16px 0' }}>
            <Link to={user ? '/dashboard' : '/'} className="btn-new">{user ? 'Back to Dashboard' : 'Back to Home'}</Link>
          </div>
          {user ? (
          <ul style={{ margin: '8px 0', paddingLeft: 18, fontSize: 13 }}>
            <li><Link to="/dashboard">Global Threat Dashboard</Link> - ingest and score emails</li>
            <li><Link to="/campaigns">Campaigns</Link> - shared infrastructure clusters</li>
            <li><Link to="/cases">Case Management</Link> - triage to closure</li>
            <li><Link to="/mailboxes">Mailboxes</Link> - OAuth connectors</li>
            <li><Link to="/model">Model Info</Link> - transparency, metrics, confusion matrix</li>
          </ul>
          ) : (
          <ul style={{ margin: '8px 0', paddingLeft: 18, fontSize: 13 }}>
            <li><Link to="/">Home</Link> - product overview</li>
            <li><Link to="/login">Sign In</Link> - analyst access</li>
            <li><Link to="/model">Model Info</Link> - transparency, metrics, confusion matrix</li>
            <li><Link to="/privacy">Privacy Policy</Link> - data handling</li>
            <li><Link to="/terms">Terms</Link> - acceptable use</li>
          </ul>
          )}
        </div>
      </div>
      <div className="card" style={{ marginTop: 16 }}>
        <h3>Helpful Links</h3>
        <div className="row">
          <a href="/sitemap.xml">Sitemap</a>
          <span style={{ color: 'var(--muted)' }}>-</span>
          <a href="/robots.txt">Robots</a>
          <span style={{ color: 'var(--muted)' }}>-</span>
          <a href="/llms.txt">LLMs</a>
          <span style={{ color: 'var(--muted)' }}>-</span>
          <a href="https://socforensics.io/" rel="canonical">socforensics.io</a>
        </div>
      </div>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd({
        '@context': 'https://schema.org', '@type': 'WebPage', name: '404 Not Found - SOC Forensics Lab',
        description: 'Requested forensic resource not found', url: `${CANONICAL_BASE}/404`,
        isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
    </div>
  );
}

function AlertBell() {
  const [alerts, setAlerts] = React.useState<any[]>([]);
  const [open, setOpen] = React.useState(false);
  const [live, setLive] = React.useState(false);
  React.useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;
    (async () => {
      try {
        // P0: never put the long-lived access token in the WS URL (leaks
        // to proxy/access logs). Exchange it via POST for a 60s ticket.
        const t = await jpost('/ws/ticket', {});
        if (closed || !t?.ticket) return;
        const base = BASE;
        const wsBase = base
          ? base.replace(/^http/, 'ws')
          : `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`;
        ws = new WebSocket(`${wsBase}/api/v1/ws/alerts?ticket=${encodeURIComponent(t.ticket)}`);
        ws.onopen = () => { if (!closed) setLive(true); };
        ws.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data);
            if (msg.event === 'high-risk-alert') setAlerts((a) => [msg, ...a].slice(0, 20));
          } catch { /* ignore malformed frames */ }
        };
        ws.onclose = () => { if (!closed) setLive(false); };
      } catch { /* WS unavailable: bell stays dormant */ }
    })();
    return () => { closed = true; try { ws?.close(); } catch { /* noop */ } };
  }, []);
  return (
    <span style={{ position: 'relative' }} title={live ? 'Live alert stream connected' : 'Live alert stream'}>
      <button className="bell-btn" onClick={() => setOpen((o) => !o)} aria-label={`Alerts, ${alerts.length} unread${live ? ', live' : ''}`} title="High-risk alerts">
        <span aria-hidden="true">🔔</span>
        {(alerts.length > 0 || !live) && <span className="bell-dot" aria-hidden="true" style={!live && alerts.length === 0 ? { background: '#8A90A8' } : undefined} />}
      </button>
      {open && (
        <div className="card" style={{ position: 'absolute', right: 0, top: '110%', width: 320, zIndex: 50 }} role="alert">
          <h3>High-risk alerts {live ? '(live)' : '(offline)'}</h3>
          {alerts.length === 0 ? <p className="sub">No alerts this session.</p> : (
            <ul style={{ paddingLeft: 18, margin: 0 }}>
              {alerts.map((a, i) => (
                <li key={i}><Link to={`/email/${a.email_id}`}>{a.subject || a.email_id}</Link> <b>{a.fraud_score}</b></li>
              ))}
            </ul>
          )}
          <div className="row" style={{ marginTop: 8 }}>
            <button className="ghost small" onClick={() => { setAlerts([]); setOpen(false); }}>Clear</button>
          </div>
        </div>
      )}
    </span>
  );
}

class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { hasError: boolean; msg: string }>
{
  constructor(props: any) { super(props); this.state = { hasError: false, msg: '' }; }
  static getDerivedStateFromError(err: any) { return { hasError: true, msg: err?.message || String(err) }; }
  componentDidCatch() { /* handled */ }
  render() {
    if (this.state.hasError) {
      return (
        <div className="page">
          <h1>Something went wrong</h1>
          <p className="sub">An unexpected error occurred in the forensic UI. Reload or return to the dashboard.</p>
          <div className="toast">{this.state.msg.slice(0, 400)}</div>
          <Link to="/dashboard">Back to Dashboard</Link>
        </div>
      );
    }
    return this.props.children;
  }
}

function EmailRoute() {
  const { id } = useParams();
  return <EmailView id={id!} />;
}

function CampaignRoute() {
  const { id } = useParams();
  return <CampaignDetail id={id!} />;
}

function Shell() {
  const { user, loading, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [health, setHealth] = useState<'ok' | 'down' | 'unknown'>('unknown');

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const code = params.get('code');
    const state = params.get('state');
    if (code) {
      const originPath = window.location.origin + window.location.pathname;
      // P0: never read OAuth secrets from browser storage and never forward
      // them as query params (proxy/access-log leak). Forward only the opaque
      // code + state; server resolves credentials/redirect from its own store.
      const prov = (typeof sessionStorage !== 'undefined' && sessionStorage.getItem('soc_oauth_provider')) || 'google';
      if (typeof sessionStorage !== 'undefined') sessionStorage.removeItem('soc_oauth_provider');
      const apiBase = (BASE || '').replace(/\/+$/, '');
      let target = `${apiBase}/api/v1/oauth/${prov}/callback?code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(originPath)}`;
      if (state) target += `&state=${encodeURIComponent(state)}`;

      window.history.replaceState({}, '', window.location.pathname);
      window.location.href = target;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const ac = new AbortController();
    fetch(`${BASE}/health`, { signal: ac.signal })
      .then((r) => { if (!ac.signal.aborted) setHealth(r.ok ? 'ok' : 'down'); })
      .catch(() => { if (!ac.signal.aborted) setHealth('down'); });
    return () => ac.abort();
  }, []);

useEffect(() => {
    setCanonical(location.pathname);
  }, [location.pathname]);

  const on = (path: string) => (location.pathname === path ? ' active' : '');
  const onCampaigns = location.pathname.startsWith('/campaign') ? ' active' : '';
  const onDashboard = location.pathname === '/dashboard' ? ' active' : '';
  const [wsOpen, setWsOpen] = useState(false);
  const [topQ, setTopQ] = useState('');

  const submitTopSearch = () => {
    window.dispatchEvent(new CustomEvent('soc:top-search', { detail: { q: topQ } }));
    if (location.pathname !== '/dashboard') navigate('/dashboard');
    else {
      // already on dashboard — focus the in-page search as well
      setTimeout(() => document.getElementById('dash-search')?.focus(), 50);
    }
    setWsOpen(false);
  };

  // Global keyboard shortcuts
  useKeyboardShortcuts({
    'ctrl+k': () => { (document.getElementById('topbar-search') || document.getElementById('dash-search') || document.getElementById('search-input'))?.focus(); },
    'ctrl+shift+d': () => { navigate('/dashboard'); },
    'ctrl+shift+c': () => { navigate('/campaigns'); },
    'ctrl+shift+i': () => { navigate('/cases'); },
    'ctrl+shift+m': () => { navigate('/mailboxes'); },
    'ctrl+shift+t': () => { navigate('/model'); },
    'ctrl+shift+l': async () => { await logout(); navigate('/'); },
    'ctrl+/': () => { (document.getElementById('shortcuts-dialog') as HTMLDialogElement)?.showModal(); },
    'escape': () => { setWsOpen(false); (document.getElementById('shortcuts-dialog') as HTMLDialogElement)?.close(); },
  });

  if (loading) {
    return (
      <div>
        <SkipToContent />
        <ScrollProgress />
        <nav className="nav" aria-label="Primary">
          <Link to="/" className="brand" aria-label="SOC Forensics Lab home"><span aria-hidden="true">◈</span> Email Forensics SOC</Link>
        </nav>
        <div className="page"><div className="skel" style={{ height: 120 }} aria-hidden="true" /></div>
      </div>
    );
  }

  if (!user) {
    // Public pages: landing, login, privacy, terms
    return (
      <div>
        <SkipToContent />
        <ScrollProgress />
        <nav className="nav" aria-label="Primary" style={{ justifyContent: 'space-between' }}>
          <Link to="/" className="brand" aria-label="SOC Forensics Lab home"><span aria-hidden="true">◈</span> SOC Forensics Lab</Link>
          <ThemeToggle />
        </nav>
        <ErrorBoundary>
          <Suspense fallback={<div className="page"><div className="skel" style={{ height: 120 }} /></div>}>
            <Routes>
              <Route path="/api/v1/oauth/:provider/callback" element={<OAuthCallbackHandler />} />
              <Route path="/oauth/:provider/callback" element={<OAuthCallbackHandler />} />
              <Route path="/" element={<LandingPage />} />
              <Route path="/login" element={<LoginPage />} />
              <Route path="/model" element={<ModelInfo />} />
              <Route path="/privacy" element={<PrivacyPolicy />} />
              <Route path="/terms" element={<TermsConditions />} />
              <Route path="*" element={<NotFoundPage />} />
            </Routes>
          </Suspense>
        </ErrorBoundary>
        <CookieConsent />
      </div>
    );
  }

  return (
    <div className="app-shell">
      <SkipToContent />
      <ScrollProgress />
      <BackToTop />
      <aside className="icon-rail" aria-label="Primary">
        <Link to="/dashboard" className="rail-logo" aria-label="Netraksha home" title="Netraksha — Global Threat Dashboard"><span aria-hidden="true">◈</span></Link>
        <Link to="/dashboard" className={`rail-btn${onDashboard}`} aria-label="Home dashboard" title="Home / Dashboard" aria-current={onDashboard ? 'page' : undefined}><span aria-hidden="true">⌂</span></Link>
        <Link to="/campaigns" className={`rail-btn${onCampaigns}`} aria-label="Campaigns" title="Campaigns" aria-current={onCampaigns ? 'page' : undefined}><span aria-hidden="true">◉</span></Link>
        <Link to="/cases" className={`rail-btn${on('/cases')}`} aria-label="Cases" title="Cases" aria-current={on('/cases') ? 'page' : undefined}><span aria-hidden="true">▤</span></Link>
        <Link to="/mailboxes" className={`rail-btn${on('/mailboxes')}`} aria-label="Mailboxes" title="Mailboxes" aria-current={on('/mailboxes') ? 'page' : undefined}><span aria-hidden="true">✉</span></Link>
        <Link to="/model" className={`rail-btn${on('/model')}`} aria-label="Model info" title="Model info" aria-current={on('/model') ? 'page' : undefined}><span aria-hidden="true">◐</span></Link>
        <span className="rail-spacer" />
        <Link to="/campaigns" className="rail-btn" aria-label="History" title="History"><span aria-hidden="true">◷</span></Link>
        <Link to="/model" className="rail-btn" aria-label="Reports and charts" title="Reports"><span aria-hidden="true">◫</span></Link>
        <span className="rail-btn" role="img" aria-label="AI assistant — Explain and summarize" title="AI — Explain / summarize"><span aria-hidden="true">✦</span></span>
      </aside>
      <aside className={`workspace-col${wsOpen ? ' open' : ''}`} aria-label="Workspace">
        <div className="ws-label">Workspace</div>
        <div className="ws-org" title={`${user.email} — ${user.role}`}>
          <span className="avatar" style={{ background: '#5B6CFF' }} aria-hidden="true">{(user.email || 'A').trim().charAt(0).toUpperCase()}</span>
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{user.role === 'Admin' ? 'Organization' : 'Personal workspace'}</span>
        </div>
        <nav aria-label="Threat folders" style={{ marginTop: 8 }}>
          <Link to="/dashboard" className="ws-folder" onClick={() => setWsOpen(false)}><span className="ws-dot" style={{ background: '#DC2626' }} aria-hidden="true" />Critical</Link>
          <Link to="/dashboard" className="ws-folder" onClick={() => setWsOpen(false)}><span className="ws-dot" style={{ background: '#EA580C' }} aria-hidden="true" />Phishing</Link>
          <Link to="/dashboard" className="ws-folder" onClick={() => setWsOpen(false)}><span className="ws-dot" style={{ background: '#F59E0B' }} aria-hidden="true" />BEC</Link>
          <Link to="/dashboard" className="ws-folder" onClick={() => setWsOpen(false)}><span className="ws-dot" style={{ background: '#22C55E' }} aria-hidden="true" />Spoofing / Clean</Link>
        </nav>
        <div className="ws-label" style={{ marginTop: 16 }}>Active Analysts</div>
        <div className="ws-analysts">
          <AvatarStack names={[user.email, 'arka.analyst', 'soc.ir', 'threat.hunt', 'case.lead', 'forensics.ai']} />
        </div>
        <button type="button" className="ws-invite" onClick={() => { setWsOpen(false); navigate('/dashboard'); }}>+ Invite analyst</button>
        <div className="health" title="backend reachability" style={{ marginTop: 14 }}>
          <span className="dot" style={{ background: health === 'ok' ? '#22c55e' : health === 'down' ? '#ef4444' : '#eab308' }} aria-hidden="true" />
          {health === 'ok' ? 'API online' : health === 'down' ? 'API unreachable' : 'checking API...'}
        </div>
      </aside>
      <div className="shell-main">
        <div className="topbar">
          <button className="mobile-menu-btn ws-toggle" onClick={() => setWsOpen((o) => !o)} aria-label="Toggle workspace panel" aria-expanded={wsOpen}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <line x1="3" y1="12" x2="21" y2="12" />
              <line x1="3" y1="6" x2="21" y2="6" />
              <line x1="3" y1="18" x2="21" y2="18" />
            </svg>
          </button>
          <label className="search-pill" htmlFor="topbar-search">
            <span aria-hidden="true">⌕</span>
            <input id="topbar-search" type="search" placeholder="Search subject, sender, body..." value={topQ} onChange={(e) => setTopQ(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') submitTopSearch(); }} aria-label="Search subject, sender, body" />
            <kbd aria-hidden="true">⌘F</kbd>
          </label>
          <div className="topbar-actions">
            <AlertBell />
            <ThemeToggle />
            <span className="presence-wrap" title={`${user.email} — ${user.role}`}>
              <span className="avatar" style={{ background: '#5B6CFF' }} aria-hidden="true">{(user.email || 'A').trim().charAt(0).toUpperCase()}</span>
              <span className="presence-dot" aria-hidden="true" />
            </span>
            <Link to="/" onClick={async (e) => { e.preventDefault(); await logout(); navigate('/'); }} style={{ fontSize: 12, fontWeight: 600 }}>Sign out</Link>
          </div>
        </div>
        <div className="content-well">

      <ErrorBoundary>
        <Suspense fallback={<div className="sheet"><div className="skel" style={{ height: 120 }} /></div>}>
          <div id="main-content" className="sheet">
            <Routes>
            <Route path="/api/v1/oauth/:provider/callback" element={<OAuthCallbackHandler />} />
            <Route path="/oauth/:provider/callback" element={<OAuthCallbackHandler />} />
            <Route path="/email/:id" element={<EmailRoute />} />
            <Route path="/campaign/:id" element={<CampaignRoute />} />
            <Route path="/campaigns" element={<Campaigns />} />
            <Route path="/model" element={<ModelInfo />} />
            <Route path="/mailboxes" element={<Mailboxes />} />
            <Route path="/cases" element={<Cases />} />
            <Route path="/privacy" element={<PrivacyPolicy />} />
            <Route path="/terms" element={<TermsConditions />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/login" element={<Navigate to="/dashboard" replace />} />
            <Route path="*" element={<NotFoundPage />} />
            </Routes>
          </div>
        </Suspense>
      </ErrorBoundary>

      <footer className="footer">
        <div>Email Threat Detection - GeoLocation - Forensic Intelligence - chain-of-custody reports via PDF/JSON</div>
        <div style={{ marginTop: 6 }}>
          <Link to="/dashboard">Dashboard</Link> - <Link to="/campaigns">Campaigns</Link> - <Link to="/cases">Cases</Link> - <Link to="/mailboxes">Mailboxes</Link> - <Link to="/model">Model</Link>
          {' - '}<Link to="/privacy">Privacy Policy</Link> - <Link to="/terms">Terms</Link>
          {' - '}<a href="/sitemap.xml">Sitemap</a> - <a href="/robots.txt">Robots</a> - <a href="/llms.txt">LLMs</a>
          {' - '}<span>SOC Forensics Lab - 301 Congress Ave, Austin, TX 78701</span>
        </div>
        <div style={{ marginTop: 6, color: '#5a6b8a' }}>© 2026 SOC Forensics Lab - socforensics.io</div>
      </footer>
        </div>
      </div>
      <CookieConsent />
      <KeyboardShortcuts shortcuts={[
        { key: 'Ctrl+K', description: 'Focus search' },
        { key: 'Ctrl+Shift+D', description: 'Go to Dashboard' },
        { key: 'Ctrl+Shift+C', description: 'Go to Campaigns' },
        { key: 'Ctrl+Shift+I', description: 'Go to Cases' },
        { key: 'Ctrl+Shift+M', description: 'Go to Mailboxes' },
        { key: 'Ctrl+Shift+T', description: 'Go to Model Info' },
        { key: 'Ctrl+Shift+L', description: 'Sign out' },
        { key: 'Ctrl+/', description: 'Show shortcuts' },
        { key: 'Esc', description: 'Close dialogs / mobile menu' },
      ]} />
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <BrowserRouter>
    <AuthProvider>
      <Shell />
    </AuthProvider>
  </BrowserRouter>,
);
