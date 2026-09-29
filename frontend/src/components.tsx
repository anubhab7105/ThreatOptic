import React, { useEffect, useRef, useState } from 'react';
import { useChartTheme } from './useChartTheme';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export function severityOf(score: number): Severity {
  if (typeof score !== 'number' || Number.isNaN(score)) return 'unknown';
  if (score >= 90) return 'critical';
  if (score >= 75) return 'high';
  if (score >= 50) return 'medium';
  if (score >= 0) return 'low';
  return 'unknown';
}

export function severityColor(s: string): string {
  if (s === 'critical' || s === 'Critical') return 'var(--critical)';
  if (s === 'high' || s === 'High') return 'var(--high)';
  if (s === 'medium' || s === 'Medium') return 'var(--medium)';
  if (s === 'low' || s === 'Low' || s === 'clean' || s === 'Clean') return 'var(--low)';
  return 'var(--muted)';
}

const AVATAR_COLORS = ['var(--teal)', 'var(--correlation)', 'var(--muted)'];

export function AvatarStack({ names, max = 4 }: { names: string[]; max?: number }) {
  const shown = names.slice(0, max);
  const extra = names.length - shown.length;
  return (
    <span className="avatar-stack" aria-label={`${names.length} analysts`}>
      {shown.map((n, i) => (
        <span key={i} className={i === 0 ? 'presence-wrap' : undefined} style={{ display: 'inline-flex' }}>
          <span className="avatar" title={n} style={{ background: AVATAR_COLORS[i % AVATAR_COLORS.length] }}>
            {n.trim().charAt(0).toUpperCase() || 'A'}
          </span>
          {i === 0 ? <span className="presence-dot" aria-hidden="true" /> : null}
        </span>
      ))}
      {extra > 0 ? <span className="avatar-more">+{extra}</span> : null}
    </span>
  );
}

export function greetingFor(date = new Date()): string {
  const h = date.getHours();
  if (h < 12) return 'Good morning';
  if (h < 17) return 'Good afternoon';
  return 'Good evening';
}

export function ThreatGauge({ dist }: { dist: { critical: number; high: number; medium: number; low: number } }) {
  const c = dist.critical || 0;
  const h = dist.high || 0;
  const m = dist.medium || 0;
  const l = dist.low || 0;
  const total = Math.max(1, c + h + m + l);
  const highRisk = c + h;
  const pct = Math.round((100 * highRisk) / total);


  const ct = useChartTheme();
  const segs = [
    { v: c, color: ct.risk.critical },
    { v: h, color: ct.risk.high },
    { v: m, color: ct.risk.medium },
    { v: l, color: ct.risk.low },
  ];
  const R = 54;
  const CIRC = 2 * Math.PI * R;
  let acc = 0;
  const label = `Threat overview: ${pct}% high-risk, ${highRisk} of ${total} emails. Critical ${c}, High ${h}, Medium ${m}, Low ${l}.`;
  return (
    <div className="gauge-card">
      <svg className="gauge-svg" width="132" height="132" viewBox="0 0 132 132" role="img" aria-label={label}>
        <title>Threat overview gauge</title>
        <circle cx="66" cy="66" r={R} fill="none" stroke={ct.surfaceRaised} strokeWidth="16" />
        {segs.map((s, i) => {
          if (!s.v) return null;
          const frac = s.v / total;
          const dash = frac * CIRC;
          const gap = CIRC - dash;
          const rot = (acc / total) * 360;
          acc += s.v;
          return (
            <circle
              key={i}
              cx="66" cy="66" r={R} fill="none"
              stroke={s.color} strokeWidth="16"
              strokeDasharray={`${dash} ${gap}`}
              transform={`rotate(${rot - 90} 66 66)`}
              strokeLinecap="butt"
            />
          );
        })}
        <text x="66" y="64" textAnchor="middle" fontSize="22" fontWeight="800" fill={ct.textPrimary}>{pct}%</text>
        <text x="66" y="82" textAnchor="middle" fontSize="10" fill={ct.textMuted}>high-risk</text>
      </svg>
      <div>
        <div style={{ fontSize: 12, color: 'var(--muted)' }}>{highRisk} / {total} emails</div>
        <div className="gauge-legend" style={{ marginTop: 8 }}>
          <span><span className="sev" style={{ background: ct.risk.critical }} />Critical <b>{c}</b></span>
          <span><span className="sev" style={{ background: ct.risk.high }} />High <b>{h}</b></span>
          <span><span className="sev" style={{ background: ct.risk.medium }} />Medium <b>{m}</b></span>
          <span><span className="sev" style={{ background: ct.risk.low }} />Low <b>{l}</b></span>
        </div>
        <span style={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)' }}>{label}</span>
      </div>
    </div>
  );
}

export function Empty({ msg }: { msg: string }) {
  return <div className="empty">{msg}</div>;
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
