import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './theme.css';
import { jget } from './api';
import { Dashboard, EmailView, Cases } from './pages';

function Router() {
  const [hash, setHash] = useState(window.location.hash || '#/');
  const [health, setHealth] = useState<'ok' | 'down' | 'unknown'>('unknown');
  useEffect(() => {
    const f = () => setHash(window.location.hash || '#/');
    window.addEventListener('hashchange', f);
    return () => window.removeEventListener('hashchange', f);
  }, []);
  useEffect(() => {
    fetch('/api/v1/dashboard')
      .then((r) => setHealth(r.ok ? 'ok' : 'down'))
      .catch(() => setHealth('down'));
  }, [hash]);

  const route = hash.startsWith('#/email/')
    ? 'email'
    : hash.startsWith('#/cases')
      ? 'cases'
      : 'dash';

  return (
    <div>
      <nav className="nav">
        <span className="brand">
          <span>◈</span> Email Forensics SOC
        </span>
        <a className={`nl${route === 'dash' ? ' active' : ''}`} href="#/">Dashboard</a>
        <a className={`nl${route === 'cases' ? ' active' : ''}`} href="#/cases">Cases</a>
        <span className="spacer" />
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
      ) : route === 'cases' ? (
        <Cases />
      ) : (
        <Dashboard />
      )}
      <div className="footer">AI Email Threat Detection · GeoLocation · Forensic Intelligence — chain-of-custody reports via PDF/JSON</div>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<Router />);
