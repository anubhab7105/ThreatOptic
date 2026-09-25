import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

// The API client is where "blocked by CORS" surfaces in the UI, and the
// browser's own message is only "TypeError: Failed to fetch". These tests
// pin that the app explains the real cause instead of showing that.
vi.mock('./supabaseClient', () => ({
  supabase: { auth: { getSession: async () => ({ data: { session: null } }) } },
}));

const { jget, jpost, ApiError, BASE, API } = await import('./api');

describe('api network-failure diagnostics', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const rejects = () => Promise.reject(new TypeError('Failed to fetch'));

  it('names the API base, the origin and /health when the browser blocks the request', async () => {
    vi.mocked(fetch).mockImplementation(rejects);
    const err = await jget('/emails').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(0);
    // The console-only symptom is replaced with the three things to check.
    expect(err.message).toContain(API);
    expect(err.message).toContain('VITE_API_URL');
    expect(err.message).toContain('CORS_ORIGINS');
    expect(err.message).toMatch(/includes (this page|http)/);
    expect(err.message).toContain('/health');
  });

  it('applies the same diagnostics to POST bodies, not just GETs', async () => {
    vi.mocked(fetch).mockImplementation(rejects);
    const err = await jpost('/emails/ingest', { raw: 'x' }).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(0);
    expect(err.message).toContain('/emails/ingest');
  });

  it('does not mask non-network errors', async () => {
    vi.mocked(fetch).mockImplementation(() => Promise.reject(new RangeError('boom')));
    const err = await jget('/emails').catch((e) => e);
    expect(err).toBeInstanceOf(RangeError);
  });

  it('still reports real HTTP errors verbatim', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response('nope', { status: 403, headers: { 'content-type': 'text/plain' } })
    );
    const err = await jget('/cases').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(403);
    expect(err.message).toBe('nope');
  });

  it('never puts credentials into the diagnostic message', async () => {
    vi.mocked(fetch).mockImplementation(rejects);
    const err = await jget('/emails').catch((e) => e);
    expect(err.message).not.toMatch(/Bearer /i);
    expect(err.message).not.toMatch(/eyJ/); // JWT prefix
  });
});

describe('api base URL', () => {
  it('derives the API path from VITE_API_URL', () => {
    expect(API).toBe(`${BASE}/api/v1`);
  });
});
