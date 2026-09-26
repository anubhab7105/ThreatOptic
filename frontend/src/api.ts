/** API client — base URL configurable via VITE_API_URL (dev proxy falls back to ''). */
export const BASE: string =
  (import.meta as any).env?.VITE_API_URL ?? '';

export const API = `${BASE}/api/v1`;

export type TokenPair = { access_token: string; refresh_token: string; token_type: string };

// P0: tokens are memory-first. The ONLY browser persistence is
// sessionStorage (cleared on tab close) — never localStorage, where a
// persistent XSS foothold could exfiltrate long-lived refresh tokens.
// (Full httpOnly-cookie storage needs backend set-cookie support;
// session-only storage is the documented minimum.) Logout clears both.
const LEGACY_KEY = 'soc_tokens';

function readStored(): TokenPair | null {
  try {
    const s = sessionStorage.getItem(LEGACY_KEY);
    return s ? JSON.parse(s) : null;
  } catch {
    return null;
  }
}

let _tokens: TokenPair | null = (() => {
  try {
    // One-time migration: drop any legacy persistent copy.
    localStorage.removeItem(LEGACY_KEY);
  } catch { /* storage unavailable */ }
  return readStored();
})();

export function getTokens(): TokenPair | null {
  if (!_tokens) _tokens = readStored();
  return _tokens;
}

export function setTokens(pair: TokenPair) {
  _tokens = pair;
  try {
    sessionStorage.setItem(LEGACY_KEY, JSON.stringify(pair));
  } catch { /* storage unavailable */ }
}

export function clearTokens() {
  _tokens = null;
  try {
    sessionStorage.removeItem(LEGACY_KEY);
    localStorage.removeItem(LEGACY_KEY);
    sessionStorage.removeItem('soc_gmail_client_id');
    sessionStorage.removeItem('soc_gmail_client_secret');
  } catch { /* storage unavailable */ }
}

function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const t = getTokens();
  return t?.access_token ? { ...extra, Authorization: `Bearer ${t.access_token}` } : { ...extra };
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// Single in-flight refresh shared by concurrent 401s (no stampede).
let _refreshing: Promise<TokenPair | null> | null = null;

async function tryRefresh(): Promise<boolean> {
  const t = getTokens();
  if (!t?.refresh_token) return false;
  if (!_refreshing) {
    _refreshing = (async () => {
      try {
        const rr = await fetch(API + '/auth/refresh', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: getTokens()?.refresh_token }),
        });
        if (!rr.ok) return null;
        const pair = (await rr.json()) as TokenPair;
        setTokens(pair);
        return pair;
      } catch {
        return null;
      } finally {
        _refreshing = null;
      }
    })();
  }
  return (await _refreshing) !== null;
}

async function handle(r: Response) {
  if (!r.ok) {
    const text = await r.text().catch(() => r.statusText);
    throw new ApiError(r.status, text.slice(0, 500) || `HTTP ${r.status}`);
  }
  const ct = r.headers.get('content-type') || '';
  if (ct.includes('application/pdf')) return r.blob();
  if (!ct.includes('application/json')) {
    // Non-JSON 2xx (plain text, empty): return text, never throw SyntaxError.
    return r.text().catch(() => '');
  }
  try {
    return await r.json();
  } catch {
    return null;
  }
}

/** Core request: on 401, attempt ONE refresh and retry the ORIGINAL request
 * (method + body preserved); only a failed refresh drops the session (Step 6).
 * Auth endpoints themselves never retry (that would loop). */
async function request(path: string, init: RequestInit, opts: { auth?: boolean; _retried?: boolean } = {}): Promise<any> {
  const headers = { ...(init.headers as Record<string, string> || {}) };
  const r = await fetch(API + path, {
    ...init,
    headers: opts.auth === false ? headers : authHeaders(headers),
  });
  if (r.status === 401 && opts.auth !== false && !opts._retried && !path.startsWith('/auth/')) {
    if (await tryRefresh()) {
      return request(path, init, { ...opts, _retried: true });
    }
    window.dispatchEvent(new Event('soc:unauthorized'));
  } else if (r.status === 401 && (opts.auth === false || path.startsWith('/auth/') || opts._retried)) {
    // Genuine auth failure (bad credentials, dead refresh): drop the session.
    if (!path.startsWith('/auth/login') || opts._retried) window.dispatchEvent(new Event('soc:unauthorized'));
  }
  return handle(r);
}

export async function jget(path: string) {
  return request(path, { method: 'GET' });
}

export async function jpost(path: string, body: unknown, opts: { auth?: boolean } = {}) {
  return request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, opts);
}

export async function jpatch(path: string, body: unknown) {
  return request(path, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export async function jdel(path: string) {
  return request(path, { method: 'DELETE' });
}

export const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
const ALLOWED_UPLOAD_EXTS = ['.eml', '.txt', '.mime'];

export async function uploadEmFile(file: File) {
  if (file.size > MAX_UPLOAD_BYTES) {
    throw new ApiError(413, `file too large (${(file.size / 1048576).toFixed(1)} MB; max 5 MB)`);
  }
  const lower = file.name.toLowerCase();
  if (!ALLOWED_UPLOAD_EXTS.some((ext) => lower.endsWith(ext))) {
    throw new ApiError(400, `unsupported file type "${file.name}" (expected .eml, .txt or .mime)`);
  }
  const fd = new FormData();
  fd.append('f', file);
  return request('/emails/upload', { method: 'POST', body: fd });
}

/** Poll a Celery ingestion task until terminal state (Phase 3 item 10). */
export async function pollTask(taskId: string, tries = 30, delayMs = 2000): Promise<any> {
  for (let i = 0; i < tries; i++) {
    const st = await jget(`/tasks/${taskId}`);
    if (st.state === 'SUCCESS') return st.result;
    if (st.state === 'FAILURE') throw new ApiError(500, `background task failed: ${st.error || taskId}`);
    await new Promise((r) => setTimeout(r, delayMs));
  }
  throw new ApiError(504, `background task ${taskId} still running`);
}

/** Authenticated download (report links can't carry a bearer token as plain anchors). */
export async function downloadReport(id: string, kind: 'pdf' | 'json') {
  const blob = (await request(`/reports/${id}.${kind}`, { method: 'GET' })) as Blob;
  const url = URL.createObjectURL(blob instanceof Blob ? blob : new Blob([JSON.stringify(blob, null, 2)], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `forensic-${id}.${kind}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
