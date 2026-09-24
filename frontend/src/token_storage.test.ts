import { describe, expect, it } from 'vitest';
import apiSrc from './api.ts?raw';

// P0: auth tokens must never persist in localStorage (survives tab close,
// exfiltratable by persistent XSS). Memory-first, sessionStorage minimum,
// cleared on logout. Theme/consent prefs in localStorage are fine.
describe('auth token storage hygiene (P0)', () => {
  const api: string = apiSrc as unknown as string;

  it('never writes tokens to localStorage', () => {
    expect(api).not.toMatch(/localStorage\.setItem\(['"]soc_tokens['"]/);
  });

  it('never reads tokens back from localStorage', () => {
    expect(api).not.toMatch(/localStorage\.getItem\(['"]soc_tokens['"]/);
  });

  it('persists session-only and clears on logout', () => {
    expect(api).toMatch(/sessionStorage\.setItem/);
    expect(api).toMatch(/sessionStorage\.removeItem/);
  });
});
