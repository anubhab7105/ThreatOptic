import React, { useEffect, useId, useRef, useState } from 'react';
import { severityOf } from './components';




export function Spinner({ label = 'Loading' }: { label?: string }) {
  return <span className="neu-spinner" role="status" aria-label={label} />;
}

export function Skeleton({ height = 18, width }: { height?: number; width?: string | number }) {
  return <div className="neu-skeleton" style={{ height, width }} aria-hidden="true" />;
}

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
};

export function Button({ variant = 'secondary', size = 'md', loading = false, disabled, children, ...rest }: ButtonProps) {
  const cls = `neu-btn neu-btn--${variant} neu-btn--${size}`;
  return (
    <button className={cls} disabled={disabled || loading} aria-busy={loading || undefined} aria-disabled={disabled || loading || undefined} {...rest}>
      {loading ? <Spinner label="Loading" /> : null}
      {children}
    </button>
  );
}

export function IconButton({ label, tooltip, children, ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement> & { label: string; tooltip?: string }) {
  return (
    <span className="neu-tooltip">
      <button type="button" className="neu-icon-btn" aria-label={label} title={tooltip ?? label} {...rest}>
        <span aria-hidden="true">{children}</span>
      </button>
      {tooltip ? <span className="neu-tooltip__bubble" role="tooltip">{tooltip}</span> : null}
    </span>
  );
}

type FieldProps = {
  label: string;
  help?: string;
  error?: string;
  id?: string;
};

export function Input({ label, help, error, id, ...rest }: FieldProps & React.InputHTMLAttributes<HTMLInputElement>) {
  const auto = useId();
  const fid = id ?? auto;
  const errId = `${fid}-err`;
  return (
    <div className="neu-field">
      <label className="neu-label" htmlFor={fid}>{label}</label>
      <input id={fid} className={`neu-input${error ? ' neu-input--error' : ''}`} aria-invalid={!!error} aria-describedby={error ? errId : undefined} {...rest} />
      {error ? <div id={errId} className="neu-error" role="alert"><span aria-hidden="true">⚠</span>{error}</div>
        : help ? <div className="neu-help">{help}</div> : null}
    </div>
  );
}

export function Select({ label, help, error, id, children, ...rest }: FieldProps & React.SelectHTMLAttributes<HTMLSelectElement>) {
  const auto = useId();
  const fid = id ?? auto;
  const errId = `${fid}-err`;
  return (
    <div className="neu-field">
      <label className="neu-label" htmlFor={fid}>{label}</label>
      <select id={fid} className={`neu-select${error ? ' neu-select--error' : ''}`} aria-invalid={!!error} aria-describedby={error ? errId : undefined} {...rest}>
        {children}
      </select>
      {error ? <div id={errId} className="neu-error" role="alert"><span aria-hidden="true">⚠</span>{error}</div>
        : help ? <div className="neu-help">{help}</div> : null}
    </div>
  );
}

export function Textarea({ label, help, error, id, ...rest }: FieldProps & React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const auto = useId();
  const fid = id ?? auto;
  const errId = `${fid}-err`;
  return (
    <div className="neu-field">
      <label className="neu-label" htmlFor={fid}>{label}</label>
      <textarea id={fid} className={`neu-textarea${error ? ' neu-textarea--error' : ''}`} aria-invalid={!!error} aria-describedby={error ? errId : undefined} {...rest} />
      {error ? <div id={errId} className="neu-error" role="alert"><span aria-hidden="true">⚠</span>{error}</div>
        : help ? <div className="neu-help">{help}</div> : null}
    </div>
  );
}

export function Checkbox({ label, ...rest }: { label: React.ReactNode } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="neu-check">
      <input type="checkbox" {...rest} /> {label}
    </label>
  );
}

export function Radio({ label, ...rest }: { label: React.ReactNode } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="neu-check">
      <input type="radio" {...rest} /> {label}
    </label>
  );
}

export function Toggle({ label, ...rest }: { label: React.ReactNode } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="neu-switch">
      <input type="checkbox" role="switch" {...rest} />
      <span className="neu-track" aria-hidden="true" />
      {label}
    </label>
  );
}

export function SegmentedControl<T extends string>({ options, value, onChange, label }: {
  options: { value: T; label: React.ReactNode; title?: string }[];
  value: T;
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div className="neu-segmented" role="group" aria-label={label}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={value === o.value}
          title={o.title ?? (typeof o.label === 'string' ? o.label : undefined)}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Card({ title, description, actions, children }: {
  title?: string; description?: string; actions?: React.ReactNode; children: React.ReactNode;
}) {
  return (
    <section className="neu-card">
      {(title || actions) ? (
        <div className="neu-card__header">
          <div>
            {title ? <h2 className="neu-card__title">{title}</h2> : null}
            {description ? <p className="neu-card__desc">{description}</p> : null}
          </div>
          {actions ? <div className="neu-card__actions">{actions}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  );
}

export const Panel = Card;

export function Well({ children }: { children: React.ReactNode }) {
  return <div className="neu-well">{children}</div>;
}

export function Table({ children, label }: { children: React.ReactNode; label: string }) {
  return (
    <div className="neu-table-wrap">
      <table className="neu-table" aria-label={label}>{children}</table>
    </div>
  );
}

export function SortTh({ label, direction, onSort, children }: {
  label: string; direction: 'ascending' | 'descending' | 'none'; onSort: () => void; children: React.ReactNode;
}) {
  const icon = direction === 'ascending' ? '▲' : direction === 'descending' ? '▼' : '△';
  return (
    <th aria-sort={direction} scope="col">
      <button type="button" onClick={onSort} aria-label={`${label}, sort ${direction === 'ascending' ? 'descending' : 'ascending'}`}>
        {children} <span aria-hidden="true">{icon}</span>
      </button>
    </th>
  );
}

export function Tabs({ tabs, active, onChange, label }: {
  tabs: string[]; active: number; onChange: (i: number) => void; label: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKey = (e: React.KeyboardEvent, i: number) => {
    let next: number | null = null;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (i + 1) % tabs.length;
    if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = (i - 1 + tabs.length) % tabs.length;
    if (e.key === 'Home') next = 0;
    if (e.key === 'End') next = tabs.length - 1;
    if (next !== null) {
      e.preventDefault();
      onChange(next);
      refs.current[next]?.focus();
    }
  };
  return (
    <div className="neu-tabs" role="tablist" aria-label={label}>
      {tabs.map((t, i) => (
        <button
          key={t}
          ref={(el) => { refs.current[i] = el; }}
          type="button"
          role="tab"
          aria-selected={active === i}
          tabIndex={active === i ? 0 : -1}
          onClick={() => onChange(i)}
          onKeyDown={(e) => onKey(e, i)}
        >
          {t}
        </button>
      ))}
    </div>
  );
}

function useDismiss(onClose: () => void) {
  const prevFocus = useRef<Element | null>(null);
  useEffect(() => {
    prevFocus.current = document.activeElement;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      if (prevFocus.current instanceof HTMLElement) prevFocus.current.focus();
    };
  }, [onClose]);
}

export function Modal({ title, onClose, children, label }: {
  title: string; onClose: () => void; children: React.ReactNode; label?: string;
}) {
  useDismiss(onClose);
  const trap = (e: React.KeyboardEvent) => {
    if (e.key !== 'Tab') return;
    const root = (e.currentTarget as HTMLElement);
    const items = Array.from(root.querySelectorAll<HTMLElement>('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'))
      .filter((el) => !el.hasAttribute('disabled'));
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  return (
    <div className="neu-modal-backdrop" onClick={onClose}>
      <div className="neu-modal" role="dialog" aria-modal="true" aria-label={label ?? title} onClick={(e) => e.stopPropagation()} onKeyDown={trap}>
        <div className="neu-card__header">
          <h2 className="neu-card__title">{title}</h2>
          <div className="neu-card__actions">
            <button type="button" className="neu-icon-btn" onClick={onClose} aria-label="Close dialog">✕</button>
          </div>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Drawer({ title, onClose, children }: {
  title: string; onClose: () => void; children: React.ReactNode;
}) {
  useDismiss(onClose);
  return (
    <>
      <div className="neu-drawer-backdrop" onClick={onClose} aria-hidden="true" />
      <div className="neu-drawer" role="dialog" aria-modal="true" aria-label={title}>
        <div className="neu-card__header">
          <h2 className="neu-card__title">{title}</h2>
          <div className="neu-card__actions">
            <button type="button" className="neu-icon-btn" onClick={onClose} aria-label="Close panel">✕</button>
          </div>
        </div>
        {children}
      </div>
    </>
  );
}


export function SeverityIcon({ severity }: { severity: string }) {
  const s = severity.toLowerCase();
  const common = { width: 14, height: 14, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 2.4, strokeLinecap: 'round', strokeLinejoin: 'round' } as const;
  if (s === 'critical') return (<svg {...common} aria-hidden="true"><polygon points="7.9 2 16.1 2 22 7.9 22 16.1 16.1 22 7.9 22 2 16.1 2 7.9 7.9 2" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>);
  if (s === 'high') return (<svg {...common} aria-hidden="true"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>);
  if (s === 'medium') return (<svg {...common} aria-hidden="true"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>);
  return (<svg {...common} aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><polyline points="9 12 11 14 15 10" /></svg>);
}

export function Badge({ tone = 'neutral', icon, children }: {
  tone?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'neutral';
  icon?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <span className={`neu-badge neu-badge--${tone}`}>
      {icon ? <span aria-hidden="true">{icon}</span> : null}
      {children}
    </span>
  );
}

export function SeverityBadge({ score, label }: { score: number; label?: string }) {
  const sev = severityOf(score);
  const text = label ?? (sev === 'unknown' ? 'Draft' : `${sev.charAt(0).toUpperCase() + sev.slice(1)} ${score}`);
  const tone = sev === 'unknown' ? 'neutral' : (sev as 'critical' | 'high' | 'medium' | 'low');
  return (
    <Badge tone={tone} icon={<SeverityIcon severity={sev} />}>
      {text}
    </Badge>
  );
}

export function StatusIndicator({ color, label }: { color: string; label: string }) {
  return (
    <span className="neu-status">
      <span className="neu-dot" style={{ background: color }} aria-hidden="true" />
      {label}
    </span>
  );
}

export function Alert({ tone = 'info', title, children, dismissible = false }: {
  tone?: 'info' | 'success' | 'warning' | 'error';
  title?: string;
  children: React.ReactNode;
  dismissible?: boolean;
}) {
  const [open, setOpen] = useState(true);
  if (!open) return null;
  const icon = tone === 'error' ? '⬢' : tone === 'warning' ? '▲' : tone === 'success' ? '✓' : 'ℹ';
  return (
    <div className={`neu-alert neu-alert--${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      <span aria-hidden="true">{icon}</span>
      <div style={{ flex: 1 }}>
        {title ? <b style={{ display: 'block', marginBottom: 2 }}>{title}</b> : null}
        {children}
      </div>
      {dismissible ? (
        <button type="button" className="neu-icon-btn" style={{ width: 32, height: 32 }} onClick={() => setOpen(false)} aria-label="Dismiss notification">✕</button>
      ) : null}
    </div>
  );
}

export function EmptyState({ icon = '◈', message, action }: {
  icon?: React.ReactNode; message: string; action?: React.ReactNode;
}) {
  return (
    <div className="neu-empty">
      <div className="neu-empty__icon" aria-hidden="true">{icon}</div>
      <p>{message}</p>
      {action}
    </div>
  );
}

export function ErrorState({ message, detail, onRetry }: {
  message: string; detail?: string; onRetry?: () => void;
}) {
  return (
    <div className="neu-error-state" role="alert">
      <div className="neu-empty__icon" aria-hidden="true">⬢</div>
      <p>{message}</p>
      {detail ? (
        <details>
          <summary>Technical detail</summary>
          <pre style={{ whiteSpace: 'pre-wrap' }}>{detail.slice(0, 500)}</pre>
        </details>
      ) : null}
      {onRetry ? <Button variant="primary" onClick={onRetry}>Retry</Button> : null}
    </div>
  );
}

let tooltipSeq = 0;
export function Tooltip({ label, children }: { label: string; children: React.ReactElement }) {
  const [id] = useState(() => `neu-tip-${++tooltipSeq}`);
  const child = children as React.ReactElement<{ 'aria-describedby'?: string }>;
  return (
    <span className="neu-tooltip">
      {React.cloneElement(child, { 'aria-describedby': id })}
      <span className="neu-tooltip__bubble" role="tooltip" id={id}>{label}</span>
    </span>
  );
}
