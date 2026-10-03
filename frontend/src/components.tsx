import React, { useEffect, useRef, useState } from 'react';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export function severityOf(score: number): Severity {
  if (typeof score !== 'number' || Number.isNaN(score) || !isFinite(score)) return 'unknown';
  if (score >= 90) return 'critical';
  if (score >= 75) return 'high';
  if (score >= 50) return 'medium';
  if (score >= 0) return 'low';
  return 'unknown';
}

export function severityColor(s: string): string {
  if (s === 'critical' || s === 'Critical') return '#ef4444';
  if (s === 'high' || s === 'High') return '#f97316';
  if (s === 'medium' || s === 'Medium') return '#eab308';
  if (s === 'low' || s === 'Low' || s === 'clean' || s === 'Clean') return '#22c55e';
  return '#6b7280';
}

export function ScoreBadge({ v }: { v: number | null | undefined }) {
  if (v === null || v === undefined) {
    return <span className="badge unknown" title="no score">—</span>;
  }
  const sev = severityOf(v);
  return (
    <span className={`badge ${sev}`} title={`fraud score ${v}`}>
      {v}
    </span>
  );
}

export function StatCard({ label, value, caption }: { label: string; value: React.ReactNode; caption?: string }) {
  return (
    <div className="card">
      <h3>{label}</h3>
      <div className="stat-num">{value}</div>
      {caption && <div className="stat-cap">{caption}</div>}
    </div>
  );
}

export function Toast({ msg, kind, onClose }: { msg: string; kind?: 'error' | 'info'; onClose?: () => void }) {
  if (!msg) return null;
  const role = kind === 'info' ? 'status' : 'alert';
  return (
    <div
      role={role}
      className={`toast${kind === 'info' ? ' info' : ''}`}
      style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}
    >
      <span style={{ wordBreak: 'break-word', flex: 1 }}>{msg}</span>
      {onClose && (
        <button
          onClick={onClose}
          type="button"
          style={{
            background: 'transparent',
            border: 'none',
            color: 'inherit',
            cursor: 'pointer',
            fontSize: '1.25rem',
            lineHeight: 1,
            padding: '0 4px',
            opacity: 0.8,
          }}
          title="Dismiss"
          aria-label="Dismiss alert"
        >
          ×
        </button>
      )}
    </div>
  );
}

export function Empty({ msg }: { msg: string }) {
  return <div className="empty">{msg}</div>;
}

export function SkeletonList({ rows = 4 }: { rows?: number }) {
  return (
    <div className="grid">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="skel" style={{ height: 44 }} />
      ))}
    </div>
  );
}

export function AuthPill({ name, status }: { name: string; status: string }) {
  const s = (status || '').toLowerCase().trim();
  let cls: string;
  const label = (status || 'NONE').toUpperCase();

  if (s === 'pass' || s === 'found' || s === 'aligned') {
    cls = 'auth-pass';
  } else if (s === 'fail' || s === 'reject' || s === 'unaligned') {
    cls = 'auth-fail';
  } else if (s === 'softfail' || s === 'neutral' || s === 'temperror' || s === 'permerror') {
    cls = 'auth-warn';
  } else {
    cls = 'auth-none';
  }

  return (
    <span className={`auth-pill ${cls}`} title={status}>
      {name}: {label}
    </span>
  );
}

export function BackToTop() {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const onScroll = () => setVisible(window.scrollY > 200);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);
  if (!visible) return null;
  return (
    <button
      className="back-to-top"
      onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
      aria-label="Back to top"
      title="Back to top"
    >
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <line x1="18" y1="15" x2="12" y2="9" />
        <line x1="6" y1="9" x2="12" y2="15" />
      </svg>
    </button>
  );
}

export function ScrollProgress() {
  const [progress, setProgress] = useState(0);
  useEffect(() => {
    const onScroll = () => {
      const scrollTop = window.scrollY;
      const docHeight = document.documentElement.scrollHeight - window.innerHeight;
      setProgress(docHeight > 0 ? (scrollTop / docHeight) * 100 : 0);
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);
  return (
    <div className="scroll-progress" role="progressbar" aria-valuenow={Math.round(progress)} aria-valuemin={0} aria-valuemax={100} aria-label="Page scroll progress">
      <div className="scroll-progress-bar" style={{ width: `${progress}%` }} />
    </div>
  );
}

export function SkipToContent() {
  return (
    <a href="#main-content" className="skip-link">
      Skip to main content
    </a>
  );
}

export function CopyButton({ text, label = 'Copy', successLabel = 'Copied!' }: { text: string; label?: string; successLabel?: string }) {
  const [copied, setCopied] = useState(false);
  const handleClick = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };
  return (
    <button type="button" className="copy-btn" onClick={handleClick} aria-label={label}>
      {copied ? (
        <>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12" /></svg>
          {successLabel}
        </>
      ) : (
        <>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
          {label}
        </>
      )}
    </button>
  );
}

export function FAQ({ items }: { items: { question: string; answer: React.ReactNode }[] }) {
  const [openIndex, setOpenIndex] = useState<number | null>(null);
  return (
    <div className="faq">
      {items.map((item, i) => (
        <details key={i} className="faq-item" open={openIndex === i} onToggle={() => setOpenIndex(openIndex === i ? null : i)}>
          <summary className="faq-question">
            {item.question}
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="faq-chevron">
              <polyline points="6 9 12 15 18 9" />
            </svg>
          </summary>
          <div className="faq-answer">{item.answer}</div>
        </details>
      ))}
    </div>
  );
}

export function PasswordToggle({ value, onChange, label = 'Password', ...props }: { value: string; onChange: (v: string) => void; label?: string } & Omit<React.InputHTMLAttributes<HTMLInputElement>, 'onChange' | 'value'>) {
  const [show, setShow] = useState(false);
  return (
    <div className="password-wrapper">
      <label htmlFor={props.id} className="login-field-label">{label}</label>
      <div className="password-input-wrap">
        <input
          type={show ? 'text' : 'password'}
          id={props.id}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          {...props}
        />
        <button
          type="button"
          className="password-toggle"
          onClick={() => setShow(!show)}
          aria-label={show ? 'Hide password' : 'Show password'}
          aria-pressed={show}
        >
          {show ? (
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" /><line x1="1" y1="1" x2="23" y2="23" /></svg>
          ) : (
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></svg>
          )}
        </button>
      </div>
    </div>
  );
}

export function KeyboardShortcuts({ shortcuts }: { shortcuts: { key: string; description: string }[] }) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  return (
    <dialog ref={dialogRef} className="shortcuts-dialog" id="shortcuts-dialog">
      <div className="shortcuts-content">
        <header>
          <h3>Keyboard Shortcuts</h3>
          <button className="ghost small" onClick={() => dialogRef.current?.close()}>Close</button>
        </header>
        <dl>
          {shortcuts.map((s, i) => (
            <div key={i} className="shortcut-row">
              <kbd>{s.key}</kbd>
              <dd>{s.description}</dd>
            </div>
          ))}
        </dl>
      </div>
    </dialog>
  );
}

export function useKeyboardShortcuts(shortcuts: Record<string, () => void>) {
  const callbackRef = useRef(shortcuts);
  const dialogRef = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    callbackRef.current = shortcuts;
  }, [shortcuts]);
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLSelectElement) return;
      const key = (e.ctrlKey || e.metaKey ? 'Ctrl+' : '') + (e.shiftKey ? 'Shift+' : '') + (e.altKey ? 'Alt+' : '') + e.key.toLowerCase();
      if (callbackRef.current[key]) {
        e.preventDefault();
        callbackRef.current[key]();
      }
      if (e.key === '?' && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        dialogRef.current?.showModal();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);
  return dialogRef;
}
