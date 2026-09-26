import { describe, expect, it, vi } from 'vitest';
import manifest from '../package.json';

// assertIdpUrl is pure, but api.ts constructs the Supabase client on import.
vi.mock('./supabaseClient', () => ({
  supabase: { auth: { getSession: async () => ({ data: { session: null } }) } },
}));

const { ApiError, assertIdpUrl } = await import('./api');

import mainSrc from './main.tsx?raw';
import pagesSrc from './pages.tsx?raw';

// Open redirect via <Link to> / useNavigate (GHSA-wrjc-x8rr-h8h6,
// CVE-2025-68470): a target that is protocol-relative ("//evil.test") or
// backslash-escaped ("/\evil.test") is resolved by the browser as a
// different origin, so a crafted value turns this dashboard — a SOC tool
// users are trained to trust — into a launchpad for phishing.
describe('no open redirect via router targets (P1)', () => {
  const files: Array<[string, string]> = [
    ['main.tsx', mainSrc as unknown as string],
    ['pages.tsx', pagesSrc as unknown as string],
  ];

  it('pins a react-router range whose floor is past the open-redirect fix', () => {
    // The advisory (GHSA-wrjc-x8rr-h8h6) covers react-router < 7.18.4. A
    // caret range on 7.x can only ever resolve to >= its floor, so pinning
    // the floor is a sound guarantee that `npm ci` cannot install a
    // vulnerable build. Read the declared range rather than the installed
    // tree so a stale node_modules cannot mask a downgrade.
    const range = manifest.dependencies['react-router-dom'];
    expect(range, 'react-router-dom must stay a declared dependency').toBeTruthy();
    const floor = /^([~^]|\s)*(\d+)\.(\d+)\.(\d+)/.exec(range!);
    expect(floor, `cannot parse a pinned floor out of "${range}"`).not.toBeNull();
    const [major, minor, patch] = [floor![2], floor![3], floor![4]].map(Number);
    const atLeastFixed = major > 7 || (major === 7 && (minor > 17 || (minor === 17 && patch >= 4)));
    expect(
      atLeastFixed,
      `react-router-dom ${range} can resolve to a build with the open-redirect advisory; need a floor >= 7.18.4`
    ).toBe(true);
  });

  it.each(files)('%s: every static <Link to> target is a single-slash path', (_name, text) => {
    const targets = [...text.matchAll(/<Link\b[^>]*?\bto=["']([^"']+)["']/g)].map((m) => m[1]);
    expect(targets.length).toBeGreaterThan(0);
    for (const to of targets) {
      expect(to.startsWith('/'), `"${to}" is not an absolute path`).toBe(true);
      expect(to.startsWith('//'), `"${to}" is protocol-relative (open redirect)`).toBe(false);
      expect(/^\/\\/.test(to) || to.startsWith('/\\'), `"${to}" uses a backslash (open redirect)`).toBe(false);
      expect(to).not.toMatch(/^[a-z][a-z0-9+.-]*:/i); // no scheme
    }
  });

  it.each(files)('%s: every dynamic <Link to> template starts with a single slash', (_name, text) => {
    const targets = [...text.matchAll(/<Link\b[^>]*?\bto=\{`([^`]*)`\}/g)].map((m) => m[1]);
    for (const to of targets) {
      expect(to.startsWith('/'), `\`${to}\` is not an absolute path`).toBe(true);
      expect(to.startsWith('//'), `\`${to}\` is protocol-relative (open redirect)`).toBe(false);
      expect(to.startsWith('/\\'), `\`${to}\` uses a backslash (open redirect)`).toBe(false);
    }
  });

  it.each(files)('%s: every navigate() argument is a single-slash literal', (_name, text) => {
    const targets = [...text.matchAll(/navigate\(\s*['"]([^'"]+)['"]\s*\)/g)].map((m) => m[1]);
    for (const to of targets) {
      expect(to.startsWith('/'), `navigate("${to}") is not an absolute path`).toBe(true);
      expect(to.startsWith('//'), `navigate("${to}") is protocol-relative (open redirect)`).toBe(false);
      expect(to.startsWith('/\\'), `navigate("${to}") uses a backslash (open redirect)`).toBe(false);
    }
  });

  it.each(files)('%s: does not assign window.location from a location-derived value', (_name, text) => {
    // Every full-page navigation must be one of exactly three shapes:
    //   - the OAuth return hop, to a same-origin /api path we build
    //   - the IdP consent hop, through assertIdpUrl()
    //   - a named local holding one of the above
    const assignments = [...text.matchAll(/window\.location\.(?:href|assign|replace)\s*=\s*([^;\n]+)/g)]
      .map((m) => m[1].trim());
    for (const expr of assignments) {
      const allowed =
        expr.includes('/api/v1/oauth/') ||                    // return hop, inline
        expr.startsWith('assertIdpUrl(') ||                   // consent hop, guarded
        /^[A-Za-z_$][\w$]*$/.test(expr) ||                    // a named local
        /^window\.location\.\w+\s*=\s*\w+$/.test(expr);       // the assign() fallback
      expect(allowed, `window.location assigned from unexpected expression: ${expr}`).toBe(true);
    }
  });

  it.each(files)('%s: a raw server auth_url is never navigated to unchecked', (_name, text) => {
    expect(text).not.toMatch(/window\.location\.[a-z]+\s*=\s*r\.auth_url/);
    expect(text).not.toMatch(/window\.location\.[a-z]+\s*=\s*res\.auth_url/);
    expect(text).not.toMatch(/window\.location\.[a-z]+\s*=\s*r\?\.auth_url/);
  });

  it('both OAuth consent hops in pages.tsx are gated by assertIdpUrl', () => {
    const pages: string = pagesSrc as unknown as string;
    // /gmail/auth-url and /oauth/{provider}/authorize each need one guard.
    const guards = pages.match(/assertIdpUrl\(/g) ?? [];
    expect(guards.length, 'both consent flows must verify the IdP origin').toBe(2);
    expect(pages).toMatch(/jpost\('\/gmail\/auth-url'[\s\S]{0,400}assertIdpUrl\(/);
    expect(pages).toMatch(/jpost\(`\/oauth\/\$\{provider\}\/authorize`[\s\S]{0,400}assertIdpUrl\(/);
  });
});

describe('OAuth consent hop is restricted to real IdP origins (P1)', () => {
  const realGoogle = 'https://accounts.google.com/o/oauth2/v2/auth?client_id=x&state=s';
  const realMicrosoft = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x';

  it('accepts the endpoints the backend actually builds', () => {
    expect(assertIdpUrl(realGoogle, 'google')).toBe(realGoogle);
    expect(assertIdpUrl(realMicrosoft, 'microsoft')).toBe(realMicrosoft);
  });

  it.each([
    ['lookalike host', 'https://accounts.google.com.evil.test/o/oauth2/v2/auth', 'google'],
    ['subdomain of the IdP', 'https://evil.accounts.google.com.attacker.test/x', 'google'],
    ['userinfo trick', 'https://accounts.google.com@evil.test/o/oauth2/v2/auth', 'google'],
    ['plaintext downgrade', 'http://accounts.google.com/o/oauth2/v2/auth', 'google'],
    ['google url for microsoft', realGoogle, 'microsoft'],
    ['unknown provider', realGoogle, 'yahoo'],
  ])('refuses %s', (_label, url, provider) => {
    expect(() => assertIdpUrl(url, provider)).toThrow(ApiError);
  });

  it.each([
    ['empty', ''],
    ['not a url', 'javascript:alert(1)'],
    ['null', null],
    ['undefined', undefined],
    ['object', { href: 'https://accounts.google.com' }],
  ])('refuses a non-string / malformed value (%s)', (_label, value) => {
    expect(() => assertIdpUrl(value, 'google')).toThrow(ApiError);
  });
});
