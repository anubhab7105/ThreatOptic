// One-off probe: hero canvas mounts on desktop; theme toggle recolors without remount.
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { chromium } from '@playwright/test';

const port = 44219;
const server = spawn(process.execPath, ['node_modules/vite/bin/vite.js', 'preview', '--port', String(port)], { stdio: 'ignore' });
const waitUp = async () => {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`http://localhost:${port}/`);
      if (r.ok) return;
    } catch {}
    await sleep(500);
  }
};
try {
  await waitUp();
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', (e) => errs.push(String(e).slice(0, 150)));
  await page.goto(`http://localhost:${port}/`, { waitUntil: 'networkidle' });
  await sleep(4000); // idle-gated 3D mount
  const before = await page.evaluate(() => ({
    theme: document.documentElement.getAttribute('data-theme'),
    canvas: document.querySelectorAll('#hero-viewport-well canvas').length,
  }));
  // Mark the canvas node, then toggle theme twice via the header toggle.
  await page.evaluate(() => document.querySelector('#hero-viewport-well canvas')?.setAttribute('data-probe', 'orig'));
  const toggles = await page.$$('.landing-new__nav-actions .theme-toggle');
  if (toggles.length === 0) throw new Error('theme toggle not found');
  await toggles[0].click();
  await sleep(1200);
  const mid = await page.evaluate(() => ({
    theme: document.documentElement.getAttribute('data-theme'),
    origCanvasAlive: !!document.querySelector('#hero-viewport-well canvas[data-probe="orig"]'),
    canvas: document.querySelectorAll('#hero-viewport-well canvas').length,
    stored: (() => { try { return localStorage.getItem('theme'); } catch { return null; } })(),
  }));
  await toggles[0].click();
  await sleep(1200);
  const after = await page.evaluate(() => ({
    theme: document.documentElement.getAttribute('data-theme'),
    origCanvasAlive: !!document.querySelector('#hero-viewport-well canvas[data-probe="orig"]'),
    canvas: document.querySelectorAll('#hero-viewport-well canvas').length,
  }));
  console.log(JSON.stringify({ before, mid, after, pageerrors: errs }, null, 2));
  await browser.close();
} finally {
  server.kill();
}
