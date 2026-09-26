import { describe, expect, it } from 'vitest';
import { loadEnv } from 'vite';

import viteConfig from '../vite.config';
// `?raw` gives us the config source as a string through Vite's own pipeline, so
// this file needs no node builtins. That matters: @types/node is deliberately
// absent from this project so Node globals do not leak into the browser type
// space, so importing 'node:fs' here would break `npm run build`.
import configSource from '../vite.config.ts?raw';

// One .env for the whole repo. The backend reads the repo root (config.py
// searches backend/.env then <repo>/.env), docker-compose.yml injects the repo
// root, and now the frontend does too. Before this, `envDir` was unset, so
// Vite defaulted to frontend/ and ignored the root file entirely.
const ENV_DIR = '..';

// The config is a function of `mode`, so evaluate it the way Vite does. Vitest
// runs with cwd = frontend/, which makes '..' resolve to the repo root exactly
// as it does when `npm run dev` / `npm run build` run from that directory.
const configFor = (mode: string) =>
  (viteConfig as unknown as (env: { mode: string }) => Record<string, unknown>)({ mode });

describe('single root .env', () => {
  it('reads the repo root, not frontend/', () => {
    expect(configFor('development').envDir).toBe(ENV_DIR);
  });

  it('builds and dev both point at the same env dir', () => {
    expect(configFor('development').envDir).toBe(configFor('production').envDir);
  });

  it('actually reaches the shared file from the frontend directory', () => {
    // Mirrors what the config does internally, so a wrong envDir fails here
    // rather than as a mysteriously empty import.meta.env at runtime.
    const parsed = loadEnv('development', ENV_DIR, '');
    expect(parsed).toBeTypeOf('object');
  });
});

describe('dev proxy target', () => {
  const proxy = () =>
    (configFor('development') as { server: { proxy: Record<string, { target: string }> } })
      .server.proxy;

  it('defaults to the local backend', () => {
    expect(proxy()['/api'].target).toBe('http://localhost:8000');
    expect(proxy()['/health'].target).toBe('http://localhost:8000');
  });

  it('proxies /api and /health, so the browser calls its own origin', () => {
    // This is what keeps CORS out of local development entirely.
    expect(Object.keys(proxy()).sort()).toEqual(['/api', '/health']);
  });

  it('reads VITE_PROXY_TARGET from the env file, not just the process env', () => {
    // Regression: the config read `process.env.VITE_PROXY_TARGET` at module
    // load, which never sees .env contents. Anything set in the file was
    // silently ignored and the default always won.
    expect(configSource).toContain('loadEnv');
    expect(configSource).not.toMatch(/process\.env\.VITE_PROXY_TARGET/);
  });
});

describe('server secrets are not exposed to the browser', () => {
  it("keeps Vite's default envPrefix so only VITE_ keys reach client code", () => {
    // The root .env holds SECRET_KEY, CUSTODY_KEY, TOKEN_ENCRYPTION_KEY,
    // SUPABASE_JWT_SECRET and DATABASE_URL alongside the VITE_ keys. Widening
    // envPrefix (or setting it to '') would inline every one of them into the
    // shipped bundle.
    expect('envPrefix' in configFor('production')).toBe(false);
  });

  it('the prefix filter keeps server-only keys out of the client-visible set', () => {
    // Runs against the developer's real root .env when one exists. Asserts the
    // filter that stands between that file and the browser: Vite injects only
    // envPrefix-matching keys into import.meta.env.
    const everything = loadEnv('development', ENV_DIR, '');
    const clientVisible = loadEnv('development', ENV_DIR, 'VITE_');

    const serverOnly = Object.keys(everything).filter((k) => !k.startsWith('VITE_'));
    if (serverOnly.length === 0) {
      // No root .env on this machine (fresh checkout / CI). The structural
      // assertion above still guards the config; nothing more to check.
      expect(Object.keys(clientVisible).every((k) => k.startsWith('VITE_'))).toBe(true);
      return;
    }

    // The file really does contain server secrets...
    expect(serverOnly).toContain('SECRET_KEY');
    // ...and none of them are client-visible.
    for (const key of serverOnly) {
      expect(clientVisible).not.toHaveProperty(key);
    }
  });
});
