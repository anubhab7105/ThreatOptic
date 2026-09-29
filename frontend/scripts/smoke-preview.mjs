



import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { chromium } from '@playwright/test';

const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : fallback;
};
const flag = (name) => args.includes(name);
const port = Number(opt('--port', '4173'));
const routes = opt('--routes', '/,/login,/model,/privacy,/terms').split(',');
const width = Number(opt('--width', '1440'));
const theme = opt('--theme', null);
const reducedMotion = flag('--reduced-motion');
const blockWebgl = flag('--block-webgl');
const base = `http://localhost:${port}`;

async function waitForServer(url, tries = 60) {
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {  }
    await sleep(500);
  }
  throw new Error(`preview server did not start at ${url}`);
}

const server = spawn(process.execPath, ['node_modules/vite/bin/vite.js', 'preview', '--port', String(port)], {
  stdio: ['ignore', 'pipe', 'pipe'],
});
let failed = false;
try {
  await waitForServer(`${base}/`);
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext({
      viewport: { width, height: 900 },
      colorScheme: theme ?? 'light',
      reducedMotion: reducedMotion ? 'reduce' : 'no-preference',
    });
    if (theme) {
      await context.addInitScript((t) => {
        try { localStorage.setItem('theme', t); } catch {  }
      }, theme);
    }
    if (blockWebgl) {
      await context.addInitScript(() => {
        const proto = HTMLCanvasElement.prototype.getContext;
        HTMLCanvasElement.prototype.getContext = function (type, ...rest) {
          if (type === 'webgl' || type === 'webgl2' || type === 'experimental-webgl') return null;
          return proto.call(this, type, ...rest);
        };
      });
    }
    for (const route of routes) {
      const page = await context.newPage();
      const errors = [];


      const benign = /Failed to load resource|CORS policy|ERR_|Failed to fetch|NetworkError|fetch at /;
      page.on('console', (msg) => {
        if (msg.type() === 'error' && !benign.test(msg.text())) errors.push(`console.error: ${msg.text().slice(0, 300)}`);
      });
      page.on('pageerror', (err) => errors.push(`pageerror: ${String(err).slice(0, 300)}`));
      await page.goto(`${base}${route}`, { waitUntil: 'networkidle', timeout: 30000 });
      await sleep(2500);
      const probe = await page.evaluate(() => ({
        rootLen: document.getElementById('root')?.innerHTML.length ?? -1,
        theme: document.documentElement.getAttribute('data-theme'),
        poster: !!document.getElementById('hero-poster'),
        heroCanvas: document.querySelectorAll('#hero-viewport-well canvas').length,
        hScroll: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      }));
      const ok = errors.length === 0 && probe.rootLen > 0;
      if (!ok) failed = true;
      console.log(`${ok ? 'PASS' : 'FAIL'} ${route} root=${probe.rootLen} theme=${probe.theme} poster=${probe.poster} heroCanvas=${probe.heroCanvas} hScroll=${probe.hScroll} errors=${errors.length}`);
      for (const e of errors.slice(0, 5)) console.log(`      ${e}`);
      await page.close();
    }
    await context.close();
  } finally {
    await browser.close();
  }
} finally {
  server.kill();
}
process.exit(failed ? 1 : 0);
