import React from 'react';

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
  if (s === 'critical' || s === 'Critical') return '#ef4444';
  if (s === 'high' || s === 'High') return '#f97316';
  if (s === 'medium' || s === 'Medium') return '#eab308';
  if (s === 'low' || s === 'Low' || s === 'clean' || s === 'Clean') return '#22c55e';
  return '#6b7280';
}

export function ScoreBadge({ v }: { v: number }) {
  const sev = severityOf(v ?? 0);
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

export function Toast({ msg, kind }: { msg: string; kind?: 'error' | 'info' }) {
  if (!msg) return null;
  return <div role="alert" className={`toast${kind === 'info' ? ' info' : ''}`}>{msg}</div>;
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
