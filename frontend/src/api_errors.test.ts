import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

// The API client is where "blocked by CORS" surfaces in the UI, and the
// browser's own message is only "TypeError: Failed to fetch". These tests
// pin that the app explains the real cause instead of showing that.
vi.mock('./supabaseClient', () => ({
  supabase: { auth: { getSession: async () => ({ data: { session: null } }) } },
}));

const { jget, jpost, ApiError, BASE, API, networkFailureMessage } = await import('./api');

describe('api network-failure diagnostics', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
    vi.stubGlobal('window', { location: { origin: 'https://app.vercel.app' } });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const rejects = () => Promise.reject(new TypeError('Failed to fetch'));

  it('names the API base and the path that failed', async () => {
    vi.mocked(fetch).mockImplementation(rejects);
    const err = await jget('/emails').catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(0);
    // The console-only symptom is replaced with the real target.
    expect(err.message).toContain(API);
    expect(err.message).toContain('/emails');
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

// A rejected fetch() is the browser's only signal for *both* a wrong host and
// a wrong allowlist, and it never exposes the cross-origin response body — so
// the message has to branch on which of the two the deployment is actually in.
describe('networkFailureMessage separates a VITE_API_URL typo from a CORS misconfiguration', () => {
  const PAGE = 'https://email-scanner-chi.vercel.app';
  const API_HOST = 'https://api.example.test';

  it('cross-origin: names both candidate causes and the command that separates them', () => {
    const text = networkFailureMessage('/api/v1/gmail/status', API_HOST, PAGE);

    expect(text).toContain(PAGE);
    expect(text).toContain(API_HOST);
    expect(text).toMatch(/VITE_API_URL is wrong/);
    expect(text).toMatch(/CORS allowlist omits/);
    // The actionable bit: one command, and how to read each outcome.
    expect(text).toContain(`curl -s ${API_HOST}/health`);
    expect(text).toMatch(/cors_origins/);
    expect(text).toMatch(/Application not found/);
  });

  it('cross-origin: warns that VITE_API_URL is baked at build time', () => {
    // Editing the Vercel variable without rebuilding changes nothing, which
    // is the other half of most "I changed it and it did not help" reports.
    expect(networkFailureMessage('/x', API_HOST, PAGE)).toMatch(/baked in at build time/i);
  });

  it('same-origin: drops the CORS theory entirely, since it cannot apply', () => {
    const text = networkFailureMessage('/api/v1/gmail/status', '', PAGE);

    expect(text).toMatch(/same-origin/);
    expect(text).toMatch(/CORS is not involved/);
    // No point sending the user to an allowlist that was never consulted.
    expect(text).not.toMatch(/CORS_ORIGINS|CORS allowlist omits/);
    expect(text).toMatch(/rewrite|proxy/);
  });

  it('defaults to the live page origin and the configured base', () => {
    vi.stubGlobal('window', { location: { origin: PAGE } });
    const text = networkFailureMessage('/x', API_HOST);
    expect(text).toContain(PAGE);
    expect(text).toContain(API_HOST);
    vi.unstubAllGlobals();
  });

  it('survives a non-DOM environment without throwing', () => {
    expect(() => networkFailureMessage('/x', API_HOST)).not.toThrow();
    expect(networkFailureMessage('/x', API_HOST)).toMatch(/this page/);
  });
});

describe('api base URL', () => {
  it('derives the API path from VITE_API_URL', () => {
    expect(API).toBe(`${BASE}/api/v1`);
  });
});
