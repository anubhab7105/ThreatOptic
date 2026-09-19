import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useEffect, useState } from 'react';
import { jget, jpost } from './api';
function ScoreBadge({ v }) {
    const c = v >= 90 ? '#ef4444' : v >= 75 ? '#f97316' : v >= 50 ? '#eab308' : '#22c55e';
    return _jsx("span", { style: { background: c, padding: '2px 10px', borderRadius: 12, color: '#000', fontWeight: 700 }, children: v });
}
export function Dashboard() {
    const [stats, setStats] = useState(null);
    const [emails, setEmails] = useState([]);
    const load = async () => {
        setStats(await jget('/dashboard'));
        setEmails(await jget('/emails?limit=50'));
    };
    useEffect(() => { load(); }, []);
    const [raw, setRaw] = useState('');
    const submit = async () => {
        await jpost('/emails/ingest', { raw });
        setRaw('');
        load();
    };
    return (_jsxs("div", { style: { padding: 20 }, children: [_jsx("h1", { children: "SOC Global Threat Dashboard" }), stats && (_jsxs("div", { style: { display: 'flex', gap: 16 }, children: [_jsxs("div", { children: ["Processed: ", _jsx("b", { children: stats.total_emails })] }), _jsxs("div", { children: ["Blocked (\u226575): ", _jsx("b", { children: stats.blocked_threats })] }), _jsxs("div", { children: ["Campaigns: ", _jsx("b", { children: stats.active_campaigns })] }), _jsxs("div", { children: ["By class: ", _jsx("code", { children: JSON.stringify(stats.by_classification) })] })] })), _jsx("h2", { children: "Ingest raw .eml / RFC822" }), _jsx("textarea", { rows: 6, cols: 100, value: raw, onChange: e => setRaw(e.target.value), placeholder: "Paste raw email here" }), _jsx("br", {}), _jsx("button", { onClick: submit, children: "Analyze" }), _jsx(Upload, { onDone: load }), _jsx("h2", { children: "Recent emails" }), _jsxs("table", { border: 1, cellPadding: 6, children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: "ID" }), _jsx("th", { children: "Subject" }), _jsx("th", { children: "Sender" }), _jsx("th", { children: "Open" })] }) }), _jsx("tbody", { children: emails.map(e => (_jsxs("tr", { children: [_jsx("td", { children: _jsx("code", { children: e.id.slice(0, 8) }) }), _jsx("td", { children: e.subject }), _jsx("td", { children: _jsx("code", { children: e.sender_address }) }), _jsxs("td", { children: [_jsx("a", { href: `#/email/${e.id}`, children: "Forensics" }), " | ", _jsx("a", { href: `/api/v1/reports/${e.id}.pdf`, children: "PDF" }), " | ", _jsx("a", { href: `/api/v1/reports/${e.id}.json`, children: "JSON" })] })] }, e.id))) })] })] }));
}
function Upload({ onDone }) {
    const up = async (f) => {
        if (!f)
            return;
        await jpost('/emails/upload', null, f);
        onDone();
    };
    return _jsxs("div", { style: { marginTop: 8 }, children: [_jsx("input", { type: "file", onChange: e => up(e.target.files?.[0]) }), " upload .eml"] });
}
function GraphSvg({ graph }) {
    const nodes = graph?.nodes ?? [];
    const edges = graph?.edges ?? [];
    if (!nodes.length)
        return _jsx("p", { children: "No related entities yet." });
    const w = 600, h = 300;
    const pos = nodes.map((_, i) => ({
        x: 60 + (i * (w - 120)) / Math.max(1, nodes.length - 1),
        y: h / 2 + (i % 2 === 0 ? -60 : 60),
    }));
    const idx = new Map(nodes.map((n, i) => [n.id, i]));
    return (_jsxs("svg", { width: w, height: h, style: { background: '#111827', borderRadius: 8 }, children: [edges.map((e, i) => {
                const a = pos[idx.get(e.source) ?? 0], b = pos[idx.get(e.target) ?? 0];
                return a && b ? _jsx("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, stroke: "#60a5fa" }, i) : null;
            }), nodes.map((n, i) => (_jsxs("g", { children: [_jsx("circle", { cx: pos[i].x, cy: pos[i].y, r: 18, fill: n.kind === 'Domain' ? '#f97316' : n.kind === 'IP_Address' ? '#ef4444' : '#22c55e' }), _jsx("text", { x: pos[i].x, y: pos[i].y + 32, fill: "#e5e7eb", fontSize: 10, textAnchor: "middle", children: String(n.id).slice(0, 24) })] }, n.id)))] }));
}
export function EmailView({ id }) {
    const [d, setD] = useState(null);
    const [tab, setTab] = useState(0);
    const [graph, setGraph] = useState(null);
    useEffect(() => { jget(`/emails/${id}`).then(setD); }, [id]);
    useEffect(() => {
        if (d?.email?.sender_address) {
            const v = encodeURIComponent(d.email.sender_address);
            jget(`/graph/related?value=${v}`).then(setGraph).catch(() => { });
        }
    }, [d]);
    if (!d)
        return _jsx("div", { style: { padding: 20 }, children: "loading\u2026" });
    const a = d.analysis || {};
    return (_jsxs("div", { style: { padding: 20 }, children: [_jsx("a", { href: "#/", children: "\u2190 back" }), _jsxs("h2", { children: [d.email.subject, " ", _jsx(ScoreBadge, { v: a.fraud_score ?? 0 }), " ", a.threat_classification] }), _jsx("div", { children: ['Summary', 'Header Forensics', 'GeoLocation', 'Graph View'].map((t, i) => (_jsx("button", { onClick: () => setTab(i), style: { marginRight: 8, fontWeight: tab === i ? 800 : 400 }, children: t }, t))) }), tab === 0 && (_jsxs("div", { children: [_jsxs("p", { children: ["Action: ", _jsx("b", { children: a.action_taken })] }), _jsxs("p", { children: ["Cues: ", _jsx("code", { children: JSON.stringify(a.nlp_cues_detected) })] }), _jsxs("p", { children: ["Auth: ", _jsx("code", { children: JSON.stringify(a.authentication_results) })] }), _jsxs("p", { children: ["Intel hits: ", _jsx("code", { children: JSON.stringify(a.threat_intel_hits) })] }), _jsx("p", { children: "Body (masked):" }), _jsx("pre", { style: { whiteSpace: 'pre-wrap', background: '#111827', padding: 12 }, children: d.email.body_text_masked })] })), tab === 1 && (_jsxs("div", { children: [_jsxs("p", { children: ["Hash: ", _jsx("code", { style: { fontFamily: 'monospace' }, children: d.email.raw_eml_hash })] }), _jsxs("p", { children: ["Hops: ", d.trace?.relay_chain?.length ?? 0] }), _jsx("pre", { style: { background: '#111827', padding: 12 }, children: JSON.stringify(d.trace?.relay_chain, null, 2) })] })), tab === 2 && (_jsxs("div", { children: [_jsxs("p", { children: ["Origin IP: ", _jsx("code", { style: { fontFamily: 'monospace' }, children: d.trace?.origin_ip }), " VPN/TOR: ", String(d.trace?.is_vpn_tor)] }), _jsxs("p", { children: ["Geo: ", _jsx("code", { children: JSON.stringify(d.trace?.geolocation) })] }), _jsxs("p", { children: ["WHOIS: ", _jsx("code", { children: JSON.stringify(d.trace?.whois) })] }), _jsxs("p", { children: ["DNS: ", _jsx("code", { children: JSON.stringify(d.trace?.dns) })] }), d.trace?.geolocation?.lat ? (_jsxs(_Fragment, { children: [_jsx("a", { target: "_blank", href: `https://www.openstreetmap.org/?mlat=${d.trace.geolocation.lat}&mlon=${d.trace.geolocation.lon}#map=5/${d.trace.geolocation.lat}/${d.trace.geolocation.lon}`, children: "Open map (OSM)" }), _jsx("br", {}), _jsx("iframe", { title: "geo", width: "100%", height: "350", src: `https://www.openstreetmap.org/export/embed.html?bbox=${d.trace.geolocation.lon - 10}%2C${d.trace.geolocation.lat - 10}%2C${d.trace.geolocation.lon + 10}%2C${d.trace.geolocation.lat + 10}&layer=mapnik&marker=${d.trace.geolocation.lat}%2C${d.trace.geolocation.lon}` })] })) : _jsx("p", { children: "No coordinates (private/unknown IP)." })] })), tab === 3 && (_jsxs("div", { children: [_jsx(GraphSvg, { graph: graph }), _jsx("pre", { style: { background: '#111827', padding: 12 }, children: JSON.stringify(graph, null, 2) })] }))] }));
}
export function Cases() {
    const [cases, setCases] = useState([]);
    const [title, setTitle] = useState('');
    const load = async () => setCases(await jget('/cases'));
    useEffect(() => { load(); }, []);
    const create = async () => {
        const r = await fetch('/api/v1/cases', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title }) });
        if (r.ok) {
            setTitle('');
            load();
        }
    };
    const setStatus = async (id, status) => {
        await fetch(`/api/v1/cases/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status }) });
        load();
    };
    const cols = ['Open', 'InProgress', 'Closed'];
    return (_jsxs("div", { style: { padding: 20 }, children: [_jsx("h1", { children: "Case Management" }), _jsx("input", { value: title, onChange: e => setTitle(e.target.value), placeholder: "New case title" }), _jsx("button", { onClick: create, children: "Create" }), _jsx("div", { style: { display: 'flex', gap: 16 }, children: cols.map(c => (_jsxs("div", { style: { flex: 1, background: '#111827', padding: 12, borderRadius: 8 }, children: [_jsx("h3", { children: c }), cases.filter(k => k.status === c).map(k => (_jsxs("div", { style: { background: '#1f2937', margin: 6, padding: 8, borderRadius: 6 }, children: [_jsx("b", { children: k.title }), _jsx("br", {}), _jsx("code", { children: k.id.slice(0, 8) }), " emails:", k.email_ids?.length ?? 0, _jsx("div", { children: cols.filter(x => x !== c).map(x => _jsx("button", { onClick: () => setStatus(k.id, x), children: x }, x)) })] }, k.id)))] }, c))) })] }));
}
