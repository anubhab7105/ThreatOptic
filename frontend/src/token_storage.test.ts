import { describe, expect, it } from 'vitest';
import apiSrc from './api.ts?raw';



describe('auth token storage hygiene (Supabase)', () => {
  const api: string = apiSrc as unknown as string;

  it('does not manage tokens manually', () => {
    expect(api).not.toMatch(/soc_tokens/);
    expect(api).not.toMatch(/sessionStorage\.setItem/);
    expect(api).not.toMatch(/getTokens|setTokens|clearTokens/);
  });

  it('does not implement its own refresh flow', () => {
    expect(api).not.toMatch(/\/auth\/refresh/);
    expect(api).not.toMatch(/tryRefresh/);
  });

  it('derives the bearer token from the Supabase session', () => {
    expect(api).toMatch(/supabase\.auth\.getSession/);
    expect(api).toMatch(/Authorization/);
  });
});
