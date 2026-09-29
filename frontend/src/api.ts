
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

  }
  if (!token) {
    try {
      token = localStorage.getItem('soc-dev-token') || undefined;
    } catch {

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






const IDP_ORIGINS: Record<string, readonly string[]> = {
  google: ['https://accounts.google.com'],
  microsoft: ['https://login.microsoftonline.com'],
};










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

    return r.text().catch(() => '');
  }
  try {
    return await r.json();
  } catch {
    return null;
  }
}




















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



async function request(path: string, init: RequestInit, opts: { auth?: boolean } = {}): Promise<any> {
  const headers = { ...(init.headers as Record<string, string> || {}) };
  let r: Response;
  try {
    r = await fetch(API + path, {
      ...init,
      headers: opts.auth === false ? headers : await authHeaders(headers),
    });
  } catch (e) {



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


export async function pollTask(taskId: string, tries = 30, delayMs = 2000): Promise<any> {
  for (let i = 0; i < tries; i++) {
    const st = await jget(`/tasks/${taskId}`);
    if (st.state === 'SUCCESS') return st.result;
    if (st.state === 'FAILURE') throw new ApiError(500, `background task failed: ${st.error || taskId}`);
    await new Promise((r) => setTimeout(r, delayMs));
  }
  throw new ApiError(504, `background task ${taskId} still running`);
}


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
