/** API client — base URL configurable via VITE_API_URL (dev proxy falls back to ''). */
export const BASE: string =
  (import.meta as any).env?.VITE_API_URL ?? '';

export const API = `${BASE}/api/v1`;

export type TokenPair = { access_token: string; refresh_token: string; token_type: string };

// In-memory only (deliberately NOT localStorage): a stored XSS payload must
// not be able to exfiltrate a long-lived token from disk. The tradeoff is
// that a full page reload drops the session and returns to the login page.
let _tokens: TokenPair | null = null;

export function getTokens(): TokenPair | null {
  return _tokens;
}

export function setTokens(pair: TokenPair) {
  _tokens = pair;
}

export function clearTokens() {
  _tokens = null;
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

async function handle(r: Response) {
  if (r.status === 401) {
    // Let the auth context drop the session; callers still get the error.
    window.dispatchEvent(new Event('soc:unauthorized'));
  }
  if (!r.ok) {
    const text = await r.text().catch(() => r.statusText);
    throw new ApiError(r.status, text.slice(0, 500) || `HTTP ${r.status}`);
  }
  const ct = r.headers.get('content-type') || '';
  if (ct.includes('application/pdf')) return r.blob();
  return r.json();
}

export async function jget(path: string) {
  return handle(await fetch(API + path, { headers: authHeaders() }));
}

export async function jpost(path: string, body: unknown, opts: { auth?: boolean } = {}) {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  return handle(
    await fetch(API + path, {
      method: 'POST',
      headers: opts.auth === false ? headers : authHeaders(headers),
      body: JSON.stringify(body),
    }),
  );
}

export async function jpatch(path: string, body: unknown) {
  return handle(
    await fetch(API + path, {
      method: 'PATCH',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(body),
    }),
  );
}

export async function jdel(path: string) {
  return handle(await fetch(API + path, { method: 'DELETE', headers: authHeaders() }));
}

export async function uploadEmFile(file: File) {
  const fd = new FormData();
  fd.append('f', file);
  return handle(await fetch(API + '/emails/upload', { method: 'POST', headers: authHeaders(), body: fd }));
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
  const blob = (await handle(
    await fetch(`${API}/reports/${id}.${kind}`, { headers: authHeaders() }),
  )) as Blob;
  const url = URL.createObjectURL(blob instanceof Blob ? blob : new Blob([JSON.stringify(blob, null, 2)], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `forensic-${id}.${kind}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
