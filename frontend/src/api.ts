/** API client — base URL configurable via VITE_API_URL (dev proxy falls back to ''). */
import { supabase } from './supabaseClient';

export const BASE: string =
  (import.meta as any).env?.VITE_API_URL ||
  (typeof window !== 'undefined' && window.location?.hostname?.endsWith('vercel.app')
    ? 'https://emailscanner-production-e5ad.up.railway.app'
    : '');

export const API = `${BASE}/api/v1`;

async function authHeaders(extra: Record<string, string> = {}): Promise<Record<string, string>> {
  let token: string | undefined;
  try {
    const { data: { session } } = await supabase.auth.getSession();
    token = session?.access_token;
  } catch {
    /* ignore */
  }
  if (!token) {
    try {
      token = localStorage.getItem('soc-dev-token') || undefined;
    } catch {
      /* ignore */
    }
  }
  return token
    ? { ...extra, Authorization: `Bearer ${token}` }
    : { ...extra };
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/**
 * Hosts the browser is ever allowed to be handed off to for OAuth consent.
 * Mirrors the fixed endpoints in backend/app/modules/ingestion/connectors.py
 * (GOOGLE_AUTH_URL / MS_AUTH_URL) — no wildcards, https only.
 */
const IDP_ORIGINS: Record<string, readonly string[]> = {
  google: ['https://accounts.google.com'],
  microsoft: ['https://login.microsoftonline.com'],
};

/**
 * Validate a server-supplied `auth_url` before navigating to it (P1).
 *
 * The API builds this URL from fixed constants, so a host that is not the
 * real IdP means something upstream is wrong or compromised. Refusing here
 * keeps a "log in to connect your mailbox" flow from becoming a phishing
 * hop off a domain analysts are trained to trust. Fails closed: the caller
 * must handle the throw and must not navigate anyway.
 */
export function assertIdpUrl(url: unknown, provider: string): string {
  const raw = typeof url === 'string' ? url.trim() : '';
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new ApiError(0, `Refusing to redirect: the API returned an unusable ${provider} authorization URL.`);
  }
  const allowed = IDP_ORIGINS[provider] ?? [];
  if (parsed.protocol !== 'https:' || !allowed.includes(parsed.origin)) {
    throw new ApiError(
      0,
      `Refusing to redirect to ${parsed.origin} for ${provider} sign-in. ` +
        `Expected ${allowed.join(' or ') || 'a known identity provider'}.`
    );
  }
  return parsed.toString();
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

/**
 * Build the message shown when fetch() itself is rejected.
 *
 * The browser reports "Failed to fetch" for every one of these, and — this
 * is the trap — it never reveals a cross-origin response body. So the two
 * commonest causes are indistinguishable from inside the page:
 *
 *   a) VITE_API_URL points at a host that does not exist. A one-character
 *      typo in a deploy-time-baked URL lands on a *different* app that
 *      answers 404 with no CORS headers, which the browser surfaces as the
 *      exact same "no Access-Control-Allow-Origin header" message as (b).
 *      Hosts like Railway return `{"message":"Application not found"}`.
 *   b) The host is fine but its CORS allowlist omits this page's origin.
 *
 * They are separated by a single curl the user can run themselves, so hand
 * them the exact command and say which side of it to look at. When VITE_API_URL
 * is unset the calls are same-origin and CORS cannot be involved at all, so
 * that branch drops the allowlist theory entirely.
 */
export function networkFailureMessage(
  path: string,
  base: string = BASE,
  pageOrigin: string = typeof window !== 'undefined' ? window.location.origin : 'this page'
): string {
  const apiPath = `${base}/api/v1`;
  const target = apiPath || '(this page, same origin)';
  const head =
    `Cannot reach the API at ${target} (${path}). ` +
    `The browser rejected the request before any response was readable.`;

  if (!base) {
    return (
      `${head} VITE_API_URL is unset, so these calls are same-origin and CORS ` +
      `is not involved: the API is either not deployed at ${pageOrigin} or your ` +
      `Vercel rewrite/proxy for /api is not forwarding to it.`
    );
  }

  return (
    `${head} Either VITE_API_URL is wrong, or the API's CORS allowlist omits ${pageOrigin}. ` +
    `VITE_API_URL is baked in at build time, so changing it needs a Vercel rebuild. ` +
    `Tell the two apart with:\n` +
    `  curl -s ${base}/health\n` +
    `A JSON body with "cors_origins" means the host is right and the allowlist is ` +
    `the problem (it will not list ${pageOrigin}). ` +
    `An "Application not found" / 404 / DNS error means the host is wrong — check ` +
    `VITE_API_URL for a typo.`
  );
}

/** Core request: Supabase SDK owns session refresh — on 401 we surface
 * `soc:unauthorized` so AuthProvider can drop to signed-out state. */
async function request(path: string, init: RequestInit, opts: { auth?: boolean } = {}): Promise<any> {
  const headers = { ...(init.headers as Record<string, string> || {}) };
  let r: Response;
  try {
    r = await fetch(API + path, {
      ...init,
      headers: opts.auth === false ? headers : await authHeaders(headers),
    });
  } catch (e) {
    // A rejected fetch() means the browser never got a response at all. The
    // console says only "Failed to fetch", which conflates two causes the
    // user must distinguish, so name the branch they are actually in.
    if (e instanceof TypeError) {
      throw new ApiError(0, networkFailureMessage(path));
    }
    throw e;
  }
  if (r.status === 401 && opts.auth !== false && !path.startsWith('/auth/')) {
    window.dispatchEvent(new Event('soc:unauthorized'));
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
