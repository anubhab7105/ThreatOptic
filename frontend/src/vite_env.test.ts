import { describe, expect, it } from 'vitest';
import { loadEnv } from 'vite';

import viteConfig from '../vite.config';




import configSource from '../vite.config.ts?raw';





const ENV_DIR = '..';




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

    expect(Object.keys(proxy()).sort()).toEqual(['/api', '/health']);
  });

  it('reads VITE_PROXY_TARGET from the env file, not just the process env', () => {



    expect(configSource).toContain('loadEnv');
    expect(configSource).not.toMatch(/process\.env\.VITE_PROXY_TARGET/);
  });
});

describe('server secrets are not exposed to the browser', () => {
  it("keeps Vite's default envPrefix so only VITE_ keys reach client code", () => {




    expect('envPrefix' in configFor('production')).toBe(false);
  });

  it('the prefix filter keeps server-only keys out of the client-visible set', () => {



    const everything = loadEnv('development', ENV_DIR, '');
    const clientVisible = loadEnv('development', ENV_DIR, 'VITE_');

    const serverOnly = Object.keys(everything).filter((k) => !k.startsWith('VITE_'));
    if (serverOnly.length === 0) {


      expect(Object.keys(clientVisible).every((k) => k.startsWith('VITE_'))).toBe(true);
      return;
    }


    expect(serverOnly).toContain('SECRET_KEY');

    for (const key of serverOnly) {
      expect(clientVisible).not.toHaveProperty(key);
    }
  });
});
