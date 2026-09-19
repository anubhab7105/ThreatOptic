/** API client — base URL configurable via VITE_API_URL (dev proxy falls back to ''). */
const BASE: string =
  (import.meta as any).env?.VITE_API_URL ?? '';

export const API = `${BASE}/api/v1`;

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function handle(r: Response) {
  if (!r.ok) {
    const text = await r.text().catch(() => r.statusText);
    throw new ApiError(r.status, text.slice(0, 500) || `HTTP ${r.status}`);
  }
  const ct = r.headers.get('content-type') || '';
  if (ct.includes('application/pdf')) return r.blob();
  return r.json();
}

export async function jget(path: string) {
  return handle(await fetch(API + path));
}

export async function jpost(path: string, body: unknown) {
  return handle(
    await fetch(API + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
}

export async function jpatch(path: string, body: unknown) {
  return handle(
    await fetch(API + path, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
}

export async function jdel(path: string) {
  return handle(await fetch(API + path, { method: 'DELETE' }));
}

export async function uploadEmFile(file: File) {
  const fd = new FormData();
  fd.append('f', file);
  return handle(await fetch(API + '/emails/upload', { method: 'POST', body: fd }));
}

export const reportPdfUrl = (id: string) => `${API}/reports/${id}.pdf`;
export const reportJsonUrl = (id: string) => `${API}/reports/${id}.json`;
