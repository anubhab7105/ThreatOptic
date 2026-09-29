import { describe, expect, it } from 'vitest';
import pagesSrc from './pages.tsx?raw';
import mainSrc from './main.tsx?raw';
import apiSrc from './api.ts?raw';



describe('oauth browser-storage hygiene (P0)', () => {
  const pages: string = pagesSrc as unknown as string;
  const main: string = mainSrc as unknown as string;
  const api: string = apiSrc as unknown as string;

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

    expect(main).not.toMatch(/client_secret=\$\{/);
    expect(main).not.toMatch(/[`'"]&client_secret=/);
  });

  it('never builds auth-url/authorize URLs with secret query params', () => {


    expect(pages).not.toMatch(/\/gmail\/auth-url\?.*client_secret/);
    expect(pages).not.toMatch(/\/authorize\?.*client_secret/);
    expect(pages).not.toMatch(/jget\(`\/gmail\/auth-url/);
    expect(pages).not.toMatch(/jget\(`\/oauth\//);
  });

  it('never opens WebSockets with the long-lived access token in the URL', () => {

    expect(main).not.toMatch(/ws\/alerts\?token=/);
    expect(main).toMatch(/ws\/alerts\?ticket=/);
  });
});
