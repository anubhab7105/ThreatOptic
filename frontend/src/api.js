/** API client — base URL configurable via VITE_API_URL (dev proxy falls back to ''). */
const BASE = import.meta.env?.VITE_API_URL ?? '';
export const API = `${BASE}/api/v1`;
const TOKEN_KEY = 'soc.auth.v1';
export function getTokens() {
    try {
        const raw = localStorage.getItem(TOKEN_KEY);
        return raw ? JSON.parse(raw) : null;
    }
    catch {
        return null;
    }
}
export function setTokens(pair) {
    localStorage.setItem(TOKEN_KEY, JSON.stringify(pair));
}
export function clearTokens() {
    localStorage.removeItem(TOKEN_KEY);
}
function authHeaders(extra = {}) {
    const t = getTokens();
    return t?.access_token ? { ...extra, Authorization: `Bearer ${t.access_token}` } : { ...extra };
}
export class ApiError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}
async function handle(r) {
    if (r.status === 401) {
        // Let the auth context drop the session; callers still get the error.
        window.dispatchEvent(new Event('soc:unauthorized'));
    }
    if (!r.ok) {
        const text = await r.text().catch(() => r.statusText);
        throw new ApiError(r.status, text.slice(0, 500) || `HTTP ${r.status}`);
    }
    const ct = r.headers.get('content-type') || '';
    if (ct.includes('application/pdf'))
        return r.blob();
    return r.json();
}
export async function jget(path) {
    return handle(await fetch(API + path, { headers: authHeaders() }));
}
export async function jpost(path, body, opts = {}) {
    const headers = { 'Content-Type': 'application/json' };
    return handle(await fetch(API + path, {
        method: 'POST',
        headers: opts.auth === false ? headers : authHeaders(headers),
        body: JSON.stringify(body),
    }));
}
export async function jpatch(path, body) {
    return handle(await fetch(API + path, {
        method: 'PATCH',
        headers: authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(body),
    }));
}
export async function jdel(path) {
    return handle(await fetch(API + path, { method: 'DELETE', headers: authHeaders() }));
}
export async function uploadEmFile(file) {
    const fd = new FormData();
    fd.append('f', file);
    return handle(await fetch(API + '/emails/upload', { method: 'POST', headers: authHeaders(), body: fd }));
}
/** Authenticated download (report links can't carry a bearer token as plain anchors). */
export async function downloadReport(id, kind) {
    const blob = (await handle(await fetch(`${API}/reports/${id}.${kind}`, { headers: authHeaders() })));
    const url = URL.createObjectURL(blob instanceof Blob ? blob : new Blob([JSON.stringify(blob, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic-${id}.${kind}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
}
