// One-off Lighthouse run against the production preview.
// Launches Playwright's Chromium with a remote-debugging port for Lighthouse.
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import lighthouse from 'lighthouse';

const port = Number(process.argv[2] || '44220');
const formFactor = process.argv[3] || 'desktop';
const dbgPort = Number(process.argv[4] || '19222');

const pwRoot = join(process.env.USERPROFILE || process.env.HOME, 'AppData', 'Local', 'ms-playwright');
const chromeDir = readdirSync(pwRoot).find((d) => d.startsWith('chromium-') && !d.includes('headless'));
const chromeExe = join(pwRoot, chromeDir, 'chrome-win64', 'chrome.exe');
if (!existsSync(chromeExe)) throw new Error(`chrome not found at ${chromeExe}`);

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
let chrome = null;
try {
  await waitUp();
  chrome = spawn(chromeExe, [
    '--headless=new', '--no-first-run', '--no-default-browser-check',
    `--remote-debugging-port=${dbgPort}`, '--disable-background-networking',
    'about:blank',
  ], { stdio: 'ignore' });
  await sleep(3000);
  const result = await lighthouse(`http://localhost:${port}/`, {
    port: dbgPort,
    output: 'json',
    logLevel: 'error',
    onlyCategories: ['performance', 'accessibility', 'seo'],
    formFactor,
    screenEmulation: formFactor === 'mobile'
      ? { mobile: true, width: 390, height: 844, deviceScaleFactor: 2, disabled: false }
      : { mobile: false, width: 1440, height: 900, deviceScaleFactor: 1, disabled: false },
  }, undefined);
  const cats = result.lhr.categories;
  const audits = result.lhr.audits;
  const top = (id) => {
    const a = audits[id];
    if (!a) return null;
    return { score: a.score, ms: Math.round(a.numericValue ?? -1), details: (a.details?.items || []).slice(0, 4).map((i) => i.url ? `${i.url.split('/').pop()} wastedMs=${Math.round(i.wastedMs ?? i.wastedBytes ?? 0)}` : JSON.stringify(i).slice(0, 120)) };
  };
  console.log(JSON.stringify({
    formFactor,
    performance: cats.performance.score,
    accessibility: cats.accessibility.score,
    seo: cats.seo.score,
    LCP_ms: Math.round(audits['largest-contentful-paint']?.numericValue ?? -1),
    CLS: audits['cumulative-layout-shift']?.numericValue ?? -1,
    TBT_ms: Math.round(audits['total-blocking-time']?.numericValue ?? -1),
    unusedJS: top('unused-javascript'),
    renderBlocking: top('render-blocking-resources'),
    bootup: top('bootup-time'),
    networkRequests: audits['network-requests']?.details?.items?.length ?? -1,
  }, null, 2));
} finally {
  try { chrome?.kill(); } catch {}
  server.kill();
}
