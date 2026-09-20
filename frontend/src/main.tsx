import React, { Suspense, lazy, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './theme.css';
import { AuthProvider, useAuth } from './auth';
import { BASE } from './api';

// Code-split pages to reduce initial bundle
const Dashboard = lazy(() => import('./pages').then(m => ({ default: m.Dashboard })));
const EmailView = lazy(() => import('./pages').then(m => ({ default: m.EmailView })));
const Cases = lazy(() => import('./pages').then(m => ({ default: m.Cases })));
const Campaigns = lazy(() => import('./pages').then(m => ({ default: m.Campaigns })));
const CampaignDetail = lazy(() => import('./pages').then(m => ({ default: m.CampaignDetail })));
const LoginPage = lazy(() => import('./pages').then(m => ({ default: m.LoginPage })));
const ModelInfo = lazy(() => import('./pages').then(m => ({ default: m.ModelInfo })));
const Mailboxes = lazy(() => import('./pages').then(m => ({ default: m.Mailboxes })));
const PrivacyPolicy = lazy(() => import('./pages').then(m => ({ default: m.PrivacyPolicy })));
const TermsConditions = lazy(() => import('./pages').then(m => ({ default: m.TermsConditions })));

// Canonical domain - custom domain configured via CNAME / Cloudflare (see frontend/public/CNAME)
const CANONICAL_BASE = 'https://socforensics.io';

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
      item: it.href ? `${CANONICAL_BASE}${it.href.replace(/^#/, '')}` : undefined,
    })),
  };
  return (
    <>
      <nav aria-label="Breadcrumb" className="breadcrumb">
        <ol>
          {items.map((it, i) => (
            <li key={i}>
              {it.href ? <a href={it.href}>{it.label}</a> : <span aria-current="page">{it.label}</span>}
              {i < items.length - 1 ? <span className="sep" aria-hidden="true"> › </span> : null}
            </li>
          ))}
        </ol>
      </nav>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
    </>
  );
}

function ThemeToggle() {
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
        We use essential cookies to keep you signed in and to remember your theme and privacy choice. Analytics cookies are off by default. See our <a href="#/privacy">Privacy Policy</a> and <a href="#/terms">Terms</a>.
      </p>
      <div className="cookie-actions">
        <button onClick={accept}>Accept essential</button>
        <button className="ghost" onClick={decline}>Decline</button>
        <a href="#/privacy" className="ghost" style={{ padding: '8px 14px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--panel-2)', textDecoration: 'none', color: 'var(--text)', fontWeight: 700, fontSize: 13 }}>Learn more</a>
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
      <Breadcrumb items={[{ label: 'Home', href: '#/' }, { label: '404 Not Found' }]} />
      <h1>404 - Page Not Found</h1>
      <p className="sub">The forensic resource you requested does not exist or has been moved. This incident has not been logged - it is a routing miss, not a threat.</p>
      <div className="card" style={{ display: 'flex', gap: 18, alignItems: 'center', flexWrap: 'wrap' }}>
        <img src="/favicon.svg" alt="SOC Forensics shield logo - link back to dashboard" width={84} height={84} style={{ flexShrink: 0 }} loading="lazy" />
        <div>
          <p style={{ marginTop: 0 }}>Try one of these instead:</p>
          <ul style={{ margin: '8px 0', paddingLeft: 18 }}>
            <li><a href="#/">Global Threat Dashboard</a> - ingest and score emails</li>
            <li><a href="#/campaigns">Campaigns</a> - shared infrastructure clusters</li>
            <li><a href="#/cases">Case Management</a> - triage to closure</li>
            <li><a href="#/mailboxes">Mailboxes</a> - OAuth connectors</li>
            <li><a href="#/model">Model Info</a> - transparency, metrics, confusion matrix</li>
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
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify({
        '@context': 'https://schema.org', '@type': 'WebPage', name: '404 Not Found - SOC Forensics Lab',
        description: 'Requested forensic resource not found', url: `${CANONICAL_BASE}/404`,
        isPartOf: { '@id': `${CANONICAL_BASE}/#website` }
      })}} />
    </div>
  );
}

class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { hasError: boolean; msg: string }> {
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
          <a href="#/">Back to Dashboard</a>
        </div>
      );
    }
    return this.props.children;
  }
}

function Shell() {
  const { user, loading, logout } = useAuth();
  const [hash, setHash] = useState(window.location.hash || '#/');
  const [health, setHealth] = useState<'ok' | 'down' | 'unknown'>('unknown');

  useEffect(() => {
    const f = () => setHash(window.location.hash || '#/');
    window.addEventListener('hashchange', f);
    return () => window.removeEventListener('hashchange', f);
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    if (code) {
      const originPath = window.location.origin + window.location.pathname;
      window.location.href = `/api/v1/oauth/google/callback?code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(originPath)}${state ? `&state=${encodeURIComponent(state)}` : ''}`;
    }
  }, []);
  useEffect(() => {
    const ac = new AbortController();
    fetch(`${BASE}/health`, { signal: ac.signal })
      .then((r) => { if (!ac.signal.aborted) setHealth(r.ok ? 'ok' : 'down'); })
      .catch(() => { if (!ac.signal.aborted) setHealth('down'); });
    return () => ac.abort();
  }, [hash]);

  useEffect(() => {
    if (!hash || hash === '#/') setCanonical('/');
  }, [hash]);

  const getRoute = (): { name: string; id?: string } => {
    if (hash.startsWith('#/email/')) return { name: 'email', id: hash.replace('#/email/', '') };
    if (hash.startsWith('#/campaign/') && !hash.startsWith('#/campaigns')) return { name: 'campaign', id: hash.replace('#/campaign/', '') };
    if (hash === '#/campaigns' || hash.startsWith('#/campaigns?')) return { name: 'campaigns' };
    if (hash.startsWith('#/model')) return { name: 'model' };
    if (hash.startsWith('#/mailboxes')) return { name: 'mailboxes' };
    if (hash.startsWith('#/cases')) return { name: 'cases' };
    if (hash.startsWith('#/privacy')) return { name: 'privacy' };
    if (hash.startsWith('#/terms')) return { name: 'terms' };
    if (hash === '#/' || hash === '' || hash === '#/dashboard') return { name: 'dash' };
    return { name: 'notfound' };
  };
  const route = getRoute();

  if (loading) {
    return (
      <div>
        <nav className="nav" aria-label="Primary">
          <a href="#/" className="brand" aria-label="SOC Forensics Lab home"><span aria-hidden="true">◈</span> Email Forensics SOC</a>
        </nav>
        <div className="page"><div className="skel" style={{ height: 120 }} aria-hidden="true" /></div>
      </div>
    );
  }

  if (!user) {
    // Public pages like privacy/terms should be accessible without login
    if (route.name === 'privacy' || route.name === 'terms') {
      return (
        <div>
          <nav className="nav" aria-label="Primary">
            <a href="#/" className="brand" aria-label="SOC Forensics Lab home"><span aria-hidden="true">◈</span> Email Forensics SOC</a>
            <a className="nl" href="#/">Dashboard</a>
            <span className="spacer" />
            <ThemeToggle />
          </nav>
          <ErrorBoundary>
            <Suspense fallback={<div className="page"><div className="skel" style={{ height: 120 }} /></div>}>
              {route.name === 'privacy' ? <PrivacyPolicy /> : <TermsConditions />}
            </Suspense>
          </ErrorBoundary>
          <CookieConsent />
        </div>
      );
    }
    return (
      <div>
        <nav className="nav" aria-label="Primary" style={{ justifyContent: 'space-between' }}>
          <a href="#/" className="brand" aria-label="SOC Forensics Lab home"><span aria-hidden="true">◈</span> Email Forensics SOC</a>
          <ThemeToggle />
        </nav>
        <ErrorBoundary>
          <Suspense fallback={<div className="page"><div className="skel" style={{ height: 120 }} /></div>}>
            <LoginPage />
          </Suspense>
        </ErrorBoundary>
        <CookieConsent />
      </div>
    );
  }

  return (
    <div>
      <nav className="nav" aria-label="Primary">
        <a href="#/" className="brand" aria-label="SOC Forensics Lab home"><span aria-hidden="true">◈</span> Email Forensics SOC</a>
        <a className={`nl${route.name === 'dash' ? ' active' : ''}`} href="#/" aria-current={route.name === 'dash' ? 'page' : undefined}>Dashboard</a>
        <a className={`nl${route.name === 'campaigns' || route.name === 'campaign' ? ' active' : ''}`} href="#/campaigns">Campaigns</a>
        <a className={`nl${route.name === 'cases' ? ' active' : ''}`} href="#/cases">Cases</a>
        <a className={`nl${route.name === 'mailboxes' ? ' active' : ''}`} href="#/mailboxes">Mailboxes</a>
        <a className={`nl${route.name === 'model' ? ' active' : ''}`} href="#/model">Model Info</a>
        <span className="spacer" />
        <ThemeToggle />
        <span className="health" title={`${user.username} - ${user.role}`}>
          {user.username} ({user.role})
        </span>
        <a className="nl" href="#/" onClick={(e) => { e.preventDefault(); logout(); window.location.hash = '#/'; }}>Sign out</a>
        <span className="health" title="backend reachability">
          <span className="dot" style={{ background: health === 'ok' ? '#22c55e' : health === 'down' ? '#ef4444' : '#eab308' }} aria-hidden="true" />
          {health === 'ok' ? 'API online' : health === 'down' ? 'API unreachable' : 'checking API...'}
        </span>
      </nav>

      <ErrorBoundary>
        <Suspense fallback={<div className="page"><div className="skel" style={{ height: 120 }} /></div>}>
          {route.name === 'email' ? (
            <EmailView id={route.id!} />
          ) : route.name === 'campaign' ? (
            <CampaignDetail id={route.id!} />
          ) : route.name === 'campaigns' ? (
            <Campaigns />
          ) : route.name === 'model' ? (
            <ModelInfo />
          ) : route.name === 'mailboxes' ? (
            <Mailboxes />
          ) : route.name === 'cases' ? (
            <Cases />
          ) : route.name === 'privacy' ? (
            <PrivacyPolicy />
          ) : route.name === 'terms' ? (
            <TermsConditions />
          ) : route.name === 'dash' ? (
            <Dashboard />
          ) : (
            <NotFoundPage />
          )}
        </Suspense>
      </ErrorBoundary>

      <footer className="footer">
        <div>Email Threat Detection - GeoLocation - Forensic Intelligence - chain-of-custody reports via PDF/JSON</div>
        <div style={{ marginTop: 6 }}>
          <a href="#/">Dashboard</a> - <a href="#/campaigns">Campaigns</a> - <a href="#/cases">Cases</a> - <a href="#/mailboxes">Mailboxes</a> - <a href="#/model">Model</a>
          {' - '}<a href="#/privacy">Privacy Policy</a> - <a href="#/terms">Terms</a>
          {' - '}<a href="/sitemap.xml">Sitemap</a> - <a href="/robots.txt">Robots</a> - <a href="/llms.txt">LLMs</a>
          {' - '}<span>SOC Forensics Lab - 301 Congress Ave, Austin, TX 78701</span>
        </div>
        <div style={{ marginTop: 6, color: '#5a6b8a' }}>© 2026 SOC Forensics Lab - socforensics.io</div>
      </footer>
      <CookieConsent />
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <AuthProvider>
    <Shell />
  </AuthProvider>,
);
