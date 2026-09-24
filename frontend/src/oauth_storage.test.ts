import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

function src(name: string): string {
  return fs.readFileSync(path.join(__dirname, name), 'utf8');
}

// P0: OAuth client secrets / PKCE verifiers must never touch browser storage.
// Browser holds at most opaque code/state identifiers; secrets stay server-side.
describe('oauth browser-storage hygiene (P0)', () => {
  const pages = src('pages.tsx');
  const main = src('main.tsx');
  const api = src('api.ts');

  it('never persists OAuth client secrets in localStorage/sessionStorage', () => {
    for (const [label, text] of [['pages.tsx', pages], ['main.tsx', main], ['api.ts', api]] as const) {
      expect(text, `${label} must not read gmail_client_secret from storage`).not.toMatch(/localStorage\.getItem\(['"]gmail_client_secret['"]/);
      expect(text, `${label} must not read oauth_client_secret from storage`).not.toMatch(/localStorage\.getItem\(['"]oauth_client_secret['"]/);
      expect(text, `${label} must not write gmail_client_secret to storage`).not.toMatch(/localStorage\.setItem\(['"]gmail_client_secret['"]/);
      expect(text, `${label} must not write oauth_client_secret to storage`).not.toMatch(/localStorage\.setItem\(['"]oauth_client_secret['"]/);
      expect(text, `${label} must not use sessionStorage for client secrets`).not.toMatch(/sessionStorage\.(get|set)Item\(['"][^'"]*(client_secret|oauth_client|gmail_client)[^'"]*['"]/);
    }
  });

  it('never forwards client_secret as a query parameter from the OAuth return handler', () => {
    // main.tsx Shell handler builds the provider callback target URL.
    expect(main).not.toMatch(/client_secret=\$\{/);
    expect(main).not.toMatch(/[`'"]&client_secret=/);
  });
});
