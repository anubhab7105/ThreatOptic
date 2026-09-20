import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
export function severityOf(score) {
    if (score >= 90)
        return 'critical';
    if (score >= 75)
        return 'high';
    if (score >= 50)
        return 'medium';
    return 'low';
}
export function severityColor(s) {
    if (s === 'critical' || s === 'Critical')
        return '#ef4444';
    if (s === 'high' || s === 'High')
        return '#f97316';
    if (s === 'medium' || s === 'Medium')
        return '#eab308';
    return '#22c55e';
}
export function ScoreBadge({ v }) {
    const sev = severityOf(v ?? 0);
    return (_jsx("span", { className: `badge ${sev}`, title: `fraud score ${v}`, children: v }));
}
export function StatCard({ label, value, caption }) {
    return (_jsxs("div", { className: "card", children: [_jsx("h3", { children: label }), _jsx("div", { className: "stat-num", children: value }), caption && _jsx("div", { className: "stat-cap", children: caption })] }));
}
export function Toast({ msg, kind }) {
    if (!msg)
        return null;
    return _jsx("div", { className: `toast${kind === 'info' ? ' info' : ''}`, children: msg });
}
export function Empty({ msg }) {
    return _jsx("div", { className: "empty", children: msg });
}
export function SkeletonList({ rows = 4 }) {
    return (_jsx("div", { className: "grid", children: Array.from({ length: rows }).map((_, i) => (_jsx("div", { className: "skel", style: { height: 44 } }, i))) }));
}
export function AuthPill({ name, status }) {
    const s = (status || '').toLowerCase();
    const cls = s === 'pass' || s === 'found' ? 'auth-pass' : s === 'fail' || s === 'softfail' ? 'auth-fail' : 'auth-none';
    return (_jsxs("span", { className: `auth-pill ${cls}`, title: status, children: [name, ": ", status || 'n/a'] }));
}
