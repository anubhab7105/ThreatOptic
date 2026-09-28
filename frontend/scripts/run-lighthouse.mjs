// One-off Lighthouse run against the production preview using Playwright's Chromium.
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import lighthouse from 'lighthouse';
import { chromium } from '@playwright/test';

const port = Number(process.argv[2] || '44220');
const formFactor = process.argv[3] || 'desktop';
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
  const browser = await chromium.launch(argsSafe());
  function argsSafe() { return []; }
  const wsEndpoint = browser.wsEndpoint();
  const chromePort = Number(new URL(wsEndpoint).port);
  const result = await lighthouse(`http://localhost:${port}/`, {
    port: chromePort,
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
  console.log(JSON.stringify({
    formFactor,
    performance: cats.performance.score,
    accessibility: cats.accessibility.score,
    seo: cats.seo.score,
    LCP_ms: audits['largest-contentful-paint']?.numericValue,
    CLS: audits['cumulative-layout-shift']?.numericValue,
  }, null, 2));
  await browser.close();
} finally {
  server.kill();
}
