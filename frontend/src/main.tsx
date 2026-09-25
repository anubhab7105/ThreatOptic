import React, { Suspense, lazy, useEffect, useState } from 'react';
import { KeyboardShortcuts, useKeyboardShortcuts } from './components';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Link, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom';
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
      item: it.href ? `${CANONICAL_BASE}${it.href.replace(/^\//, '')}` : undefined,
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
      return document.documentElement.getAttribute('data-theme') || 'dark';
    } catch { return 'dark'; }
  });
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('soc-theme', theme); } catch { /* storage unavailable */ }
  }, [theme]);
  return (
    <button className="theme-toggle" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`} title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}>
      <span aria-hidden="true">{theme === 'dark' ? '☾' : '☀'}</span> {theme === 'dark' ? 'Light' : 'Dark'}
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

function NotFoundPage() {
  useEffect(() => {
    document.title = 'Page Not Found - SOC Forensics Lab';
    setMeta('description', 'The requested forensic resource was not found. Return to the threat dashboard, campaigns, or case board.');
    setCanonical('/404');
    const ogTitle = document.querySelector('meta[property="og:title"]');
    if (ogTitle) ogTitle.setAttribute('content', 'Page Not Found - SOC Forensics Lab');
  }, []);
  return (
    <div className="page">
      <Breadcrumb items={[{ label: 'Home', href: '/' }, { label: '404 Not Found' }]} />
      <h1>404 - Page Not Found</h1>
      <p className="sub">The forensic resource you requested does not exist or has been moved. This incident has not been logged - it is a routing miss, not a threat.</p>
      <div className="card" style={{ display: 'flex', gap: 18, alignItems: 'center', flexWrap: 'wrap' }}>
        <img src="/favicon.svg" alt="SOC Forensics shield logo - link back to dashboard" width={84} height={84} style={{ flexShrink: 0 }} loading="lazy" />
        <div>
          <p style={{ marginTop: 0 }}>Try one of these instead:</p>
          <ul style={{ margin: '8px 0', paddingLeft: 18 }}>
            <li><Link to="/">Global Threat Dashboard</Link> - ingest and score emails</li>
            <li><Link to="/campaigns">Campaigns</Link> - shared infrastructure clusters</li>
            <li><Link to="/cases">Case Management</Link> - triage to closure</li>
            <li><Link to="/mailboxes">Mailboxes</Link> - OAuth connectors</li>
            <li><Link to="/model">Model Info</Link> - transparency, metrics, confusion matrix</li>
          </ul>
          <p className="sub" style={{ marginBottom: 0 }}>If you followed an internal link, please report the broken path to hello@socforensics.io - Austin, TX SOC.</p>
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
      <button className="ghost" onClick={() => setOpen((o) => !o)} aria-label={`Alerts (${alerts.length} unread)`} title="High-risk alerts">
        🔔{alerts.length > 0 && <b style={{ color: '#ef4444' }}> {alerts.length}</b>}
        <span className="dot" style={{ background: live ? '#22c55e' : '#6b7280', marginLeft: 6 }} aria-hidden="true" />
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
            <button className="ghost" onClick={() => { setAlerts([]); setOpen(false); }}>Clear</button>
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
          <Link to="/">Back to Dashboard</Link>
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
      let target = `/api/v1/oauth/google/callback?code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(originPath)}`;
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
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Global keyboard shortcuts
  useKeyboardShortcuts({
    'ctrl+k': () => { document.getElementById('search-input')?.focus(); },
    'ctrl+shift+d': () => { navigate('/dashboard'); },
    'ctrl+shift+c': () => { navigate('/campaigns'); },
    'ctrl+shift+i': () => { navigate('/cases'); },
    'ctrl+shift+m': () => { navigate('/mailboxes'); },
    'ctrl+shift+t': () => { navigate('/model'); },
    'ctrl+shift+l': () => { logout(); navigate('/'); },
    'ctrl+/': () => { (document.getElementById('shortcuts-dialog') as HTMLDialogElement)?.showModal(); },
    'escape': () => { setMobileMenuOpen(false); (document.getElementById('shortcuts-dialog') as HTMLDialogElement)?.close(); },
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
              <Route path="/" element={<LandingPage />} />
              <Route path="/login" element={<LoginPage />} />
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
    <div>
      <SkipToContent />
      <ScrollProgress />
      <BackToTop />
      <nav className="nav" aria-label="Primary">
        <Link to="/dashboard" className="brand" aria-label="SOC Forensics Lab home"><span aria-hidden="true">◈</span> Email Forensics SOC</Link>
        <Link to="/dashboard" className={`nl${onDashboard}`} aria-current={onDashboard ? 'page' : undefined}>Dashboard</Link>
        <Link to="/campaigns" className={`nl${onCampaigns}`}>Campaigns</Link>
        <Link to="/cases" className={`nl${on('/cases')}`}>Cases</Link>
        <Link to="/mailboxes" className={`nl${on('/mailboxes')}`}>Mailboxes</Link>
        <Link to="/model" className={`nl${on('/model')}`}>Model Info</Link>
        <span className="spacer" />
        <AlertBell />
        <ThemeToggle />
        <span className="health" title={`${user.email} - ${user.role}`}>
          {user.email} ({user.role})
        </span>
        <Link to="/" className="nl" onClick={(e) => { e.preventDefault(); logout(); navigate('/'); }}>Sign out</Link>
        <span className="health" title="backend reachability">
          <span className="dot" style={{ background: health === 'ok' ? '#22c55e' : health === 'down' ? '#ef4444' : '#eab308' }} aria-hidden="true" />
          {health === 'ok' ? 'API online' : health === 'down' ? 'API unreachable' : 'checking API...'}
        </span>
        <button className="mobile-menu-btn" onClick={() => setMobileMenuOpen(true)} aria-label="Open menu" aria-expanded={mobileMenuOpen}>
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <line x1="3" y1="12" x2="21" y2="12" />
            <line x1="3" y1="6" x2="21" y2="6" />
            <line x1="3" y1="18" x2="21" y2="18" />
          </svg>
        </button>
      </nav>

      <div className={`mobile-menu${mobileMenuOpen ? ' open' : ''}`} role="dialog" aria-modal="true" aria-label="Navigation menu">
        <div className="mobile-menu-panel">
          <div className="mobile-menu-header">
            <Link to="/dashboard" className="brand" aria-label="SOC Forensics Lab home"><span aria-hidden="true">◈</span> SOC Forensics Lab</Link>
            <button className="mobile-menu-close" onClick={() => setMobileMenuOpen(false)} aria-label="Close menu">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
          </div>
          <nav className="mobile-menu-nav" aria-label="Main navigation">
            <Link to="/dashboard" className="mobile-menu-link" onClick={() => setMobileMenuOpen(false)}>Dashboard</Link>
            <Link to="/campaigns" className="mobile-menu-link" onClick={() => setMobileMenuOpen(false)}>Campaigns</Link>
            <Link to="/cases" className="mobile-menu-link" onClick={() => setMobileMenuOpen(false)}>Cases</Link>
            <Link to="/mailboxes" className="mobile-menu-link" onClick={() => setMobileMenuOpen(false)}>Mailboxes</Link>
            <Link to="/model" className="mobile-menu-link" onClick={() => setMobileMenuOpen(false)}>Model Info</Link>
          </nav>
          <div className="mobile-menu-footer">
            <Link to="/privacy" className="mobile-menu-link" onClick={() => setMobileMenuOpen(false)}>Privacy Policy</Link>
            <Link to="/terms" className="mobile-menu-link" onClick={() => setMobileMenuOpen(false)}>Terms of Service</Link>
            <Link to="/" className="nl" onClick={(e) => { e.preventDefault(); logout(); navigate('/'); setMobileMenuOpen(false); }}>Sign out</Link>
          </div>
        </div>
      </div>

      <ErrorBoundary>
        <Suspense fallback={<div className="page"><div className="skel" style={{ height: 120 }} /></div>}>
          <div id="main-content">
            <Routes>
              <Route path="/email/:id" element={<EmailRoute />} />
              <Route path="/campaign/:id" element={<CampaignRoute />} />
              <Route path="/campaigns" element={<Campaigns />} />
              <Route path="/model" element={<ModelInfo />} />
              <Route path="/mailboxes" element={<Mailboxes />} />
              <Route path="/cases" element={<Cases />} />
              <Route path="/privacy" element={<PrivacyPolicy />} />
              <Route path="/terms" element={<TermsConditions />} />
              <Route path="/dashboard" element={<Dashboard />} />
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
