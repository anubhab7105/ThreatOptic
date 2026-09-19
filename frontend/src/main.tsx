import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Dashboard, EmailView, Cases } from './pages';

function Router() {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    const f = () => setHash(window.location.hash);
    window.addEventListener('hashchange', f);
    return () => window.removeEventListener('hashchange', f);
  }, []);
  return (
    <div>
      <nav style={{ padding: 12, background: '#111827' }}>
        <a href="#/" style={{ marginRight: 16 }}>Dashboard</a>
        <a href="#/cases" style={{ marginRight: 16 }}>Cases</a>
        <span style={{ opacity: 0.7 }}>AI Email Threat & Forensics</span>
      </nav>
      {hash.startsWith('#/email/') ? <EmailView id={hash.replace('#/email/', '')} />
        : hash.startsWith('#/cases') ? <Cases />
        : <Dashboard />}
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<Router />);
