import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './theme.css';
import { AuthProvider, useAuth } from './auth';
import { Dashboard, EmailView, Cases, Campaigns, CampaignDetail, LoginPage, ModelInfo } from './pages';

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
    fetch('/health')
      .then((r) => setHealth(r.ok ? 'ok' : 'down'))
      .catch(() => setHealth('down'));
  }, [hash]);

  const route = hash.startsWith('#/email/')
    ? 'email'
    : hash.startsWith('#/campaign/')
      ? 'campaign'
      : hash.startsWith('#/campaigns')
        ? 'campaigns'
        : hash.startsWith('#/model')
          ? 'model'
          : hash.startsWith('#/cases')
            ? 'cases'
            : 'dash';

  if (loading) {
    return (
      <div>
        <nav className="nav">
          <span className="brand"><span>◈</span> Email Forensics SOC</span>
        </nav>
        <div className="page"><div className="skel" style={{ height: 120 }} /></div>
      </div>
    );
  }

  if (!user) return <LoginPage />;

  return (
    <div>
      <nav className="nav">
        <span className="brand">
          <span>◈</span> Email Forensics SOC
        </span>
        <a className={`nl${route === 'dash' ? ' active' : ''}`} href="#/">Dashboard</a>
        <a className={`nl${route === 'campaigns' || route === 'campaign' ? ' active' : ''}`} href="#/campaigns">Campaigns</a>
        <a className={`nl${route === 'cases' ? ' active' : ''}`} href="#/cases">Cases</a>
        <a className={`nl${route === 'model' ? ' active' : ''}`} href="#/model">Model Info</a>
        <span className="spacer" />
        <span className="health" title={`${user.username} · ${user.role}`}>
          {user.username} ({user.role})
        </span>
        <a className="nl" href="#/" onClick={(e) => { e.preventDefault(); logout(); window.location.hash = '#/'; }}>Sign out</a>
        <span className="health" title="backend reachability">
          <span
            className="dot"
            style={{ background: health === 'ok' ? '#22c55e' : health === 'down' ? '#ef4444' : '#eab308' }}
          />
          {health === 'ok' ? 'API online' : health === 'down' ? 'API unreachable' : 'checking API…'}
        </span>
      </nav>
      {route === 'email' ? (
        <EmailView id={hash.replace('#/email/', '')} />
      ) : route === 'campaign' ? (
        <CampaignDetail id={hash.replace('#/campaign/', '')} />
      ) : route === 'campaigns' ? (
        <Campaigns />
      ) : route === 'model' ? (
        <ModelInfo />
      ) : route === 'cases' ? (
        <Cases />
      ) : (
        <Dashboard />
      )}
      <div className="footer">AI Email Threat Detection · GeoLocation · Forensic Intelligence — chain-of-custody reports via PDF/JSON</div>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <AuthProvider>
    <Shell />
  </AuthProvider>,
);
