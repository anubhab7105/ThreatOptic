export const API = '/api/v1';
export async function jget(path: string) {
  const r = await fetch(API + path);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
export async function jpost(path: string, body: any, file?: File) {
  if (file) {
    const fd = new FormData();
    fd.append('f', file);
    const r = await fetch(API + path, { method: 'POST', body: fd });
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  }
  const r = await fetch(API + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
