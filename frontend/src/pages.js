import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useEffect, useMemo, useState } from 'react';
import { ApiError, downloadReport, jdel, jget, jpatch, jpost, uploadEmFile } from './api';
import { useAuth } from './auth';
import { AuthPill, Empty, ScoreBadge, SkeletonList, StatCard, Toast, severityColor } from './components';
/* ---------------- Login ---------------- */
export function LoginPage() {
    const { login, register } = useAuth();
    const [mode, setMode] = useState('login');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [err, setErr] = useState('');
    const [busy, setBusy] = useState(false);
    const submit = async () => {
        if (!username.trim() || !password)
            return;
        setBusy(true);
        setErr('');
        try {
            if (mode === 'login')
                await login(username.trim(), password);
            else
                await register(username.trim(), password);
        }
        catch (e) {
            setErr(e instanceof ApiError ? `Authentication failed (${e.status}): ${e.message}` : String(e));
        }
        finally {
            setBusy(false);
        }
    };
    return (_jsxs("div", { className: "page", style: { maxWidth: 440 }, children: [_jsx("h1", { children: "SOC Sign in" }), _jsx("p", { className: "sub", children: "JWT-secured access to the forensic intelligence platform." }), _jsxs("div", { className: "card", children: [_jsx("div", { className: "tabs", children: ['login', 'register'].map((m) => (_jsx("button", { className: mode === m ? 'active' : '', onClick: () => { setMode(m); setErr(''); }, children: m === 'login' ? 'Sign in' : 'Register' }, m))) }), _jsx(Toast, { msg: err }), _jsxs("div", { className: "grid", style: { gap: 10 }, children: [_jsx("input", { type: "text", placeholder: "Username", value: username, onChange: (e) => setUsername(e.target.value), onKeyDown: (e) => { if (e.key === 'Enter')
                                    submit(); }, autoComplete: "username" }), _jsx("input", { type: "password", placeholder: mode === 'register' ? 'Password (min 8 chars)' : 'Password', value: password, onChange: (e) => setPassword(e.target.value), onKeyDown: (e) => { if (e.key === 'Enter')
                                    submit(); }, autoComplete: mode === 'login' ? 'current-password' : 'new-password' }), _jsx("button", { onClick: submit, disabled: busy || !username.trim() || !password, children: busy ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create analyst account' })] }), _jsx("p", { className: "sub", style: { marginTop: 12, marginBottom: 0 }, children: mode === 'register'
                            ? 'New accounts join as Analyst (first-ever account becomes Admin).'
                            : 'Demo seed: admin / admin123, analyst / analyst123.' })] })] }));
}
const PHISH_SAMPLE = `From: "CEO" <ceo@xn--paypa1-secure.top>
To: finance@company.com
Subject: Urgent: Confidential wire transfer needed ASAP
Message-ID: <abc123@xn--paypa1-secure.top>
Return-Path: <bounce@evil-relay.test>
Received: from evil-relay.test (evil-relay.test [45.148.10.88]) by mx.company.com with ESMTPS id x1
Received: from internal ([10.0.0.5]) by evil-relay.test with SMTP id y2
Content-Type: text/plain

Hi, kindly wire $48,000 to new vendor bank details immediately. Do not disclose. Verify account now at http://malicious-example.com/login`;
const CLEAN_SAMPLE = `From: Alice <alice@company.com>
To: bob@company.com
Subject: Lunch tomorrow?
Message-ID: <lunch1@company.com>
Return-Path: <alice@company.com>
Received: from mail.company.com (mail.company.com [93.184.216.34]) by mx.company.com with ESMTPS id z9
Content-Type: text/plain

Hi Bob, lunch tomorrow at noon? Let me know if cafeteria works.`;
export function Dashboard() {
    const [stats, setStats] = useState(null);
    const [emails, setEmails] = useState([]);
    const [scores, setScores] = useState({});
    const [loading, setLoading] = useState(true);
    const [err, setErr] = useState('');
    const [raw, setRaw] = useState('');
    const [busy, setBusy] = useState(false);
    const [q, setQ] = useState('');
    const [sevFilter, setSevFilter] = useState('all');
    const [notice, setNotice] = useState('');
    const load = async (query = q) => {
        setLoading(true);
        setErr('');
        try {
            const [s, list] = await Promise.all([jget('/dashboard'), jget(`/emails?limit=100${query ? `&q=${encodeURIComponent(query)}` : ''}`)]);
            setStats(s);
            setEmails(list);
            // fetch scores for the visible rows (detail endpoint carries analysis)
            const entries = await Promise.all(list.slice(0, 30).map(async (e) => {
                try {
                    const d = await jget(`/emails/${e.id}`);
                    return [e.id, { score: d.analysis?.fraud_score ?? 0, cls: d.analysis?.threat_classification ?? '—' }];
                }
                catch {
                    return [e.id, { score: 0, cls: '—' }];
                }
            }));
            setScores(Object.fromEntries(entries));
        }
        catch (e) {
            setErr(e instanceof ApiError ? `Backend error (${e.status}): ${e.message}` : String(e));
        }
        finally {
            setLoading(false);
        }
    };
    useEffect(() => {
        load('');
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);
    const submit = async () => {
        if (!raw.trim())
            return;
        setBusy(true);
        setErr('');
        setNotice('');
        try {
            const r = await jpost('/emails/ingest', { raw });
            setNotice(`Analyzed — score ${r.fraud_score} (${r.classification}), action: ${r.action}`);
            setRaw('');
            await load();
        }
        catch (e) {
            setErr(e instanceof ApiError ? `Ingest failed (${e.status}): ${e.message}` : String(e));
        }
        finally {
            setBusy(false);
        }
    };
    const onFile = async (f) => {
        if (!f)
            return;
        setBusy(true);
        setErr('');
        try {
            const r = await uploadEmFile(f);
            setNotice(`Uploaded ${f.name} — score ${r.fraud_score} (${r.classification})`);
            await load();
        }
        catch (e) {
            setErr(e instanceof ApiError ? `Upload failed (${e.status}): ${e.message}` : String(e));
        }
        finally {
            setBusy(false);
        }
    };
    const filtered = useMemo(() => {
        if (sevFilter === 'all')
            return emails;
        return emails.filter((e) => {
            const s = scores[e.id]?.score ?? -1;
            if (sevFilter === 'critical')
                return s >= 90;
            if (sevFilter === 'high')
                return s >= 75 && s < 90;
            if (sevFilter === 'medium')
                return s >= 50 && s < 75;
            return s >= 0 && s < 50;
        });
    }, [emails, scores, sevFilter]);
    const dist = stats?.score_distribution ?? { critical: 0, high: 0, medium: 0, low: 0 };
    const distTotal = Math.max(1, dist.critical + dist.high + dist.medium + dist.low);
    return (_jsxs("div", { className: "page", children: [_jsx("h1", { children: "Global Threat Dashboard" }), _jsx("p", { className: "sub", children: "Real-time phishing, BEC and spoofing detection across ingested mail." }), _jsx(Toast, { msg: err }), notice && _jsx(Toast, { msg: notice, kind: "info" }), loading && !stats ? (_jsx(SkeletonList, { rows: 4 })) : (stats && (_jsxs(_Fragment, { children: [_jsxs("div", { className: "grid stats", children: [_jsx(StatCard, { label: "Emails processed", value: stats.total_emails }), _jsx(StatCard, { label: "Blocked threats (\u226575)", value: stats.blocked_threats }), _jsx(StatCard, { label: "Active campaigns", value: stats.active_campaigns, caption: "shared infrastructure clusters" }), _jsx(StatCard, { label: "Classifications", value: Object.keys(stats.by_classification || {}).length, caption: Object.entries(stats.by_classification || {}).slice(0, 3).map(([k, v]) => `${k}:${v}`).join(' · ') || '—' })] }), _jsxs("div", { className: "card", style: { marginBottom: 18 }, children: [_jsx("h3", { children: "Score distribution" }), _jsxs("div", { className: "distbar", children: [_jsx("div", { style: { width: `${(100 * dist.critical) / distTotal}%`, background: '#ef4444' } }), _jsx("div", { style: { width: `${(100 * dist.high) / distTotal}%`, background: '#f97316' } }), _jsx("div", { style: { width: `${(100 * dist.medium) / distTotal}%`, background: '#eab308' } }), _jsx("div", { style: { width: `${(100 * dist.low) / distTotal}%`, background: '#22c55e' } })] }), _jsxs("div", { className: "legend", children: [_jsxs("span", { children: [_jsx("span", { className: "sev", style: { background: '#ef4444' } }), "Critical ", dist.critical] }), _jsxs("span", { children: [_jsx("span", { className: "sev", style: { background: '#f97316' } }), "High ", dist.high] }), _jsxs("span", { children: [_jsx("span", { className: "sev", style: { background: '#eab308' } }), "Medium ", dist.medium] }), _jsxs("span", { children: [_jsx("span", { className: "sev", style: { background: '#22c55e' } }), "Low ", dist.low] })] })] })] }))), _jsxs("div", { className: "card", style: { marginBottom: 18 }, children: [_jsx("h3", { children: "Ingest email for analysis" }), _jsx("textarea", { rows: 6, value: raw, onChange: (e) => setRaw(e.target.value), placeholder: "Paste raw RFC822 / .eml content here\u2026" }), _jsxs("div", { className: "row", style: { marginTop: 10 }, children: [_jsx("button", { onClick: submit, disabled: busy || !raw.trim(), children: busy ? 'Analyzing…' : 'Analyze email' }), _jsx("button", { className: "ghost", onClick: () => setRaw(PHISH_SAMPLE), children: "Load phishing sample" }), _jsx("button", { className: "ghost", onClick: () => setRaw(CLEAN_SAMPLE), children: "Load clean sample" }), _jsxs("label", { className: "row", style: { gap: 6 }, children: [_jsx("span", { style: { color: 'var(--muted)', fontSize: 12 }, children: "or upload .eml" }), _jsx("input", { type: "file", accept: ".eml,.txt,.mime", onChange: (e) => onFile(e.target.files?.[0]) })] })] })] }), _jsxs("div", { className: "toolbar", children: [_jsx("input", { type: "search", placeholder: "Search subject / sender / body\u2026", value: q, onChange: (e) => setQ(e.target.value), onKeyDown: (e) => { if (e.key === 'Enter')
                            load(); } }), _jsx("button", { className: "ghost", onClick: () => load(), children: "Search" }), _jsxs("select", { value: sevFilter, onChange: (e) => setSevFilter(e.target.value), children: [_jsx("option", { value: "all", children: "All severities" }), _jsx("option", { value: "critical", children: "Critical (90+)" }), _jsx("option", { value: "high", children: "High (75\u201389)" }), _jsx("option", { value: "medium", children: "Medium (50\u201374)" }), _jsx("option", { value: "low", children: "Low (<50)" })] }), _jsx("button", { className: "ghost", onClick: () => load(), children: "Refresh" })] }), loading ? _jsx(SkeletonList, {}) : filtered.length === 0 ? _jsx(Empty, { msg: "No emails match. Ingest one above to get started." }) : (_jsxs("table", { className: "tbl", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: "Score" }), _jsx("th", { children: "Subject" }), _jsx("th", { children: "Sender" }), _jsx("th", { children: "Classification" }), _jsx("th", { children: "Received" }), _jsx("th", { children: "Reports" })] }) }), _jsx("tbody", { children: filtered.map((e) => {
                            const s = scores[e.id];
                            return (_jsxs("tr", { children: [_jsx("td", { children: s ? _jsx(ScoreBadge, { v: s.score }) : _jsx("span", { style: { color: 'var(--muted)' }, children: "\u2026" }) }), _jsx("td", { children: _jsx("a", { href: `#/email/${e.id}`, children: e.subject || '(no subject)' }) }), _jsx("td", { children: _jsx("span", { className: "mono", children: e.sender_address }) }), _jsx("td", { children: s?.cls ?? '—' }), _jsx("td", { style: { color: 'var(--muted)', fontSize: 12 }, children: e.timestamp ? new Date(e.timestamp).toLocaleString() : '—' }), _jsxs("td", { children: [_jsx("button", { className: "ghost small", onClick: () => downloadReport(e.id, 'pdf'), children: "PDF" }), ' ', _jsx("button", { className: "ghost small", onClick: () => downloadReport(e.id, 'json'), children: "JSON" })] })] }, e.id));
                        }) })] }))] }));
}
/* ---------------- Graph SVG ---------------- */
function GraphSvg({ graph }) {
    const nodes = graph?.nodes ?? [];
    const edges = graph?.edges ?? [];
    if (!nodes.length)
        return _jsx(Empty, { msg: "No related entities yet \u2014 graph grows as more mail shares IPs/domains." });
    const w = 640, h = 300;
    const pos = nodes.map((_, i) => ({
        x: 70 + (i * (w - 140)) / Math.max(1, nodes.length - 1),
        y: h / 2 + (i % 2 === 0 ? -62 : 62),
    }));
    const idx = new Map(nodes.map((n, i) => [n.id, i]));
    const color = (k) => (k === 'Domain' ? '#f97316' : k === 'IP_Address' ? '#ef4444' : k === 'Threat_Campaign' ? '#a78bfa' : '#22c55e');
    return (_jsxs("svg", { width: "100%", viewBox: `0 0 ${w} ${h}`, style: { background: '#0a0f1f', borderRadius: 8, border: '1px solid var(--border)' }, children: [edges.map((e, i) => {
                const a = pos[idx.get(e.source) ?? -1], b = pos[idx.get(e.target) ?? -1];
                return a && b ? (_jsxs("g", { children: [_jsx("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, stroke: "#60a5fa", strokeWidth: 1.5 }), e.rel && _jsx("text", { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 - 4, fill: "#93a1bd", fontSize: 9, textAnchor: "middle", children: e.rel })] }, i)) : null;
            }), nodes.map((n, i) => (_jsxs("g", { children: [_jsx("circle", { cx: pos[i].x, cy: pos[i].y, r: 17, fill: color(n.kind) }), _jsx("text", { x: pos[i].x, y: pos[i].y + 4, fill: "#060a14", fontSize: 9, fontWeight: 800, textAnchor: "middle", children: (n.kind || '?')[0] }), _jsx("text", { x: pos[i].x, y: pos[i].y + 32, fill: "#e5e7eb", fontSize: 10, textAnchor: "middle", children: String(n.id).slice(0, 26) })] }, n.id)))] }));
}
/* ---------------- Email detail ---------------- */
const TABS = ['Summary', 'Header Forensics', 'GeoLocation', 'Graph View'];
export function EmailView({ id }) {
    const [d, setD] = useState(null);
    const [tab, setTab] = useState(0);
    const [graph, setGraph] = useState(null);
    const [err, setErr] = useState('');
    useEffect(() => {
        setErr('');
        setD(null);
        jget(`/emails/${id}`).then(setD).catch((e) => setErr(e instanceof ApiError ? `Could not load email (${e.status}): ${e.message}` : String(e)));
    }, [id]);
    useEffect(() => {
        if (d?.email?.sender_address) {
            jget(`/graph/related?value=${encodeURIComponent(d.email.sender_address)}`).then(setGraph).catch(() => { });
        }
    }, [d]);
    if (err)
        return _jsxs("div", { className: "page", children: [_jsx("a", { href: "#/", children: "\u2190 back" }), _jsx(Toast, { msg: err })] });
    if (!d)
        return _jsxs("div", { className: "page", children: [_jsx("a", { href: "#/", children: "\u2190 back" }), _jsx(SkeletonList, {})] });
    const a = d.analysis || {};
    const t = d.trace || {};
    const auth = a.authentication_results || {};
    const relay = Array.isArray(t.relay_chain) ? t.relay_chain : [];
    return (_jsxs("div", { className: "page", children: [_jsx("a", { href: "#/", children: "\u2190 back to dashboard" }), _jsxs("h1", { style: { marginTop: 8 }, children: [d.email.subject || '(no subject)', " ", _jsx(ScoreBadge, { v: a.fraud_score ?? 0 })] }), _jsxs("p", { className: "sub", children: [a.threat_classification || 'Unclassified', " \u00B7 action: ", _jsx("b", { children: a.action_taken || '—' }), " \u00B7", ' ', _jsx("button", { className: "ghost small", onClick: () => downloadReport(id, 'pdf'), children: "forensic PDF" }), ' ', _jsx("button", { className: "ghost small", onClick: () => downloadReport(id, 'json'), children: "JSON" })] }), _jsx("div", { className: "tabs", children: TABS.map((name, i) => (_jsx("button", { className: tab === i ? 'active' : '', onClick: () => setTab(i), children: name }, name))) }), tab === 0 && (_jsxs("div", { className: "grid", style: { gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' }, children: [_jsxs("div", { className: "card", children: [_jsx("h3", { children: "Verdict" }), _jsxs("dl", { className: "kv", children: [_jsx("dt", { children: "Fraud score" }), _jsxs("dd", { children: [_jsx(ScoreBadge, { v: a.fraud_score ?? 0 }), " ", a.threat_classification] }), _jsx("dt", { children: "Action" }), _jsx("dd", { children: a.action_taken }), _jsx("dt", { children: "Breakdown" }), _jsx("dd", { children: _jsx("span", { className: "mono", children: JSON.stringify(a.trace_summary ?? {}) }) })] }), _jsx("h3", { children: "Cues detected" }), (a.nlp_cues_detected || []).length === 0 ? _jsx("p", { className: "sub", children: "None" }) : (_jsx("div", { children: (a.nlp_cues_detected || []).map((c) => _jsx("span", { className: "auth-pill auth-none", children: c }, c)) }))] }), _jsxs("div", { className: "card", children: [_jsx("h3", { children: "Authentication" }), _jsxs("div", { children: [_jsx(AuthPill, { name: "SPF", status: auth.spf?.status }), _jsx(AuthPill, { name: "DKIM", status: auth.dkim?.status }), _jsx(AuthPill, { name: "DMARC", status: auth.dmarc?.status })] }), _jsxs("h3", { style: { marginTop: 12 }, children: ["Threat intel hits (", (a.threat_intel_hits || []).length, ")"] }), (a.threat_intel_hits || []).length === 0 ? _jsx("p", { className: "sub", children: "No hits" }) : (_jsxs("table", { className: "tbl", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: "Type" }), _jsx("th", { children: "Value" }), _jsx("th", { children: "Reason" })] }) }), _jsx("tbody", { children: (a.threat_intel_hits || []).slice(0, 20).map((h, i) => (_jsxs("tr", { children: [_jsx("td", { children: h.type }), _jsx("td", { children: _jsx("span", { className: "mono", children: String(h.value ?? h.url ?? '').slice(0, 80) }) }), _jsx("td", { style: { fontSize: 12 }, children: (h.reasons || []).join(', ') || (h.blocklisted ? 'blocklisted' : 'hit') })] }, i))) })] }))] }), _jsxs("div", { className: "card", style: { gridColumn: '1 / -1' }, children: [_jsx("h3", { children: "Body (PII masked)" }), _jsx("pre", { className: "dump", style: { whiteSpace: 'pre-wrap' }, children: d.email.body_text_masked || '(empty)' })] })] })), tab === 1 && (_jsxs("div", { className: "card", children: [_jsx("h3", { children: "Chain of custody" }), _jsxs("dl", { className: "kv", children: [_jsx("dt", { children: "SHA-256 (.eml)" }), _jsx("dd", { children: _jsx("span", { className: "mono", children: d.email.raw_eml_hash }) }), _jsx("dt", { children: "Message-ID" }), _jsx("dd", { children: _jsx("span", { className: "mono", children: d.email.message_id || '—' }) }), _jsx("dt", { children: "Relay hops" }), _jsx("dd", { children: relay.length })] }), _jsx("h3", { children: "Relay path (origin first)" }), relay.length === 0 ? _jsx(Empty, { msg: "No Received headers \u2014 sender path unverifiable." }) : (_jsx("ol", { className: "timeline", children: relay.map((h, i) => (_jsxs("li", { children: [_jsxs("div", { children: [_jsxs("b", { children: ["Hop ", i + 1] }), " \u2014 from ", _jsx("span", { className: "mono", children: h.from_host || '?' }), " by ", _jsx("span", { className: "mono", children: h.by_host || '?' })] }), _jsxs("div", { style: { fontSize: 12, color: 'var(--muted)' }, children: ["IPs: ", (h.ips || []).map((ip) => _jsx("span", { className: "mono", style: { marginRight: 4 }, children: ip }, ip)), (h.ips || []).length === 0 && 'none parsed'] })] }, i))) })), _jsx("h3", { children: "Raw chain" }), _jsx("pre", { className: "dump", children: JSON.stringify(relay, null, 2) })] })), tab === 2 && (_jsxs("div", { className: "grid", style: { gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' }, children: [_jsxs("div", { className: "card", children: [_jsx("h3", { children: "Origin" }), _jsxs("dl", { className: "kv", children: [_jsx("dt", { children: "Origin IP" }), _jsx("dd", { children: _jsx("span", { className: "mono", children: t.origin_ip || '—' }) }), _jsx("dt", { children: "VPN / TOR" }), _jsx("dd", { children: String(t.is_vpn_tor) }), _jsx("dt", { children: "ISP / ASN" }), _jsx("dd", { children: t.isp_asn || '—' }), _jsx("dt", { children: "Country / City" }), _jsxs("dd", { children: [t.geolocation ? `${t.geolocation.country || '?'} / ${t.geolocation.city || '?'}` : '—', " ", _jsxs("span", { style: { color: 'var(--muted)', fontSize: 12 }, children: ["(", t.geolocation?.source, ")"] })] })] }), _jsx("h3", { children: "WHOIS" }), _jsx("pre", { className: "dump", children: JSON.stringify(t.whois, null, 2) }), _jsx("h3", { children: "DNS" }), _jsx("pre", { className: "dump", children: JSON.stringify(t.dns, null, 2) })] }), _jsxs("div", { className: "card", children: [_jsx("h3", { children: "Map" }), t.geolocation?.lat ? (_jsxs(_Fragment, { children: [_jsx("iframe", { title: "geo", width: "100%", height: "380", style: { border: 0, borderRadius: 8 }, src: `https://www.openstreetmap.org/export/embed.html?bbox=${t.geolocation.lon - 10}%2C${t.geolocation.lat - 10}%2C${t.geolocation.lon + 10}%2C${t.geolocation.lat + 10}&layer=mapnik&marker=${t.geolocation.lat}%2C${t.geolocation.lon}` }), _jsx("p", { children: _jsx("a", { target: "_blank", rel: "noreferrer", href: `https://www.openstreetmap.org/?mlat=${t.geolocation.lat}&mlon=${t.geolocation.lon}#map=5/${t.geolocation.lat}/${t.geolocation.lon}`, children: "Open full map" }) })] })) : _jsx(Empty, { msg: "No coordinates \u2014 private, missing or unresolvable origin IP." })] })] })), tab === 3 && (_jsxs("div", { className: "card", children: [_jsx("h3", { children: "Identity correlation" }), _jsx(GraphSvg, { graph: graph }), _jsx("h3", { style: { marginTop: 12 }, children: "Raw graph" }), _jsx("pre", { className: "dump", children: JSON.stringify(graph, null, 2) })] }))] }));
}
const COLS = [
    { key: 'Open', color: '#60a5fa' },
    { key: 'InProgress', color: '#eab308' },
    { key: 'Closed', color: '#22c55e' },
];
export function Cases() {
    const { user } = useAuth();
    const isAdmin = user?.role === 'Admin';
    const [cases, setCases] = useState([]);
    const [title, setTitle] = useState('');
    const [err, setErr] = useState('');
    const [loading, setLoading] = useState(true);
    const load = async () => {
        setLoading(true);
        setErr('');
        try {
            setCases(await jget('/cases'));
        }
        catch (e) {
            setErr(e instanceof ApiError ? `Could not load cases (${e.status}): ${e.message}` : String(e));
        }
        finally {
            setLoading(false);
        }
    };
    useEffect(() => { load(); }, []);
    const create = async () => {
        if (!title.trim())
            return;
        setErr('');
        try {
            await jpost('/cases', { title: title.trim() });
            setTitle('');
            await load();
        }
        catch (e) {
            setErr(e instanceof ApiError ? `Create failed (${e.status}): ${e.message}` : String(e));
        }
    };
    const move = async (id, status) => {
        try {
            await jpatch(`/cases/${id}`, { status });
            await load();
        }
        catch (e) {
            setErr(e instanceof ApiError ? `Update failed (${e.status}): ${e.message}` : String(e));
        }
    };
    const remove = async (id) => {
        if (!confirm('Delete this case?'))
            return;
        try {
            await jdel(`/cases/${id}`);
            await load();
        }
        catch (e) {
            setErr(e instanceof ApiError ? `Delete failed (${e.status}): ${e.message}` : String(e));
        }
    };
    return (_jsxs("div", { className: "page", children: [_jsx("h1", { children: "Case Management" }), _jsx("p", { className: "sub", children: "Track investigations from triage to closure." }), _jsx(Toast, { msg: err }), _jsxs("div", { className: "row", style: { marginBottom: 16 }, children: [_jsx("input", { type: "text", style: { maxWidth: 360 }, value: title, onChange: (e) => setTitle(e.target.value), placeholder: "New case title\u2026", onKeyDown: (e) => { if (e.key === 'Enter')
                            create(); } }), _jsx("button", { onClick: create, children: "Create case" })] }), loading ? _jsx(SkeletonList, {}) : (_jsx("div", { className: "kanban", children: COLS.map((c) => (_jsxs("div", { className: "kcol", children: [_jsxs("h3", { children: [_jsx("span", { className: "sev", style: { background: severityColor(c.key === 'Open' ? 'high' : c.key === 'Closed' ? 'low' : 'medium') } }), c.key, " (", cases.filter((k) => k.status === c.key).length, ")"] }), cases.filter((k) => k.status === c.key).map((k) => (_jsxs("div", { className: "kcard", children: [_jsx("b", { children: k.title }), _jsxs("div", { style: { fontSize: 12, color: 'var(--muted)' }, children: [_jsx("span", { className: "mono", children: k.id.slice(0, 8) }), " \u00B7 ", k.email_ids?.length ?? 0, " email(s)"] }), _jsxs("div", { className: "row", style: { marginTop: 8 }, children: [COLS.filter((x) => x.key !== c.key).map((x) => (_jsx("button", { className: "ghost small", onClick: () => move(k.id, x.key), children: x.key }, x.key))), isAdmin && _jsx("button", { className: "danger small", onClick: () => remove(k.id), children: "Delete" })] })] }, k.id)))] }, c.key))) }))] }));
}
