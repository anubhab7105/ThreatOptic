// One-off probe: list elements wider than the viewport at 390px.
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { chromium } from '@playwright/test';

const port = 44214;
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
  const page = await (await browser.newContext({ viewport: { width: 390, height: 844 } })).newPage();
  await page.goto(`http://localhost:${port}/`, { waitUntil: 'networkidle' });
  await sleep(2000);
  const bad = await page.evaluate(() => {
    const vw = document.documentElement.clientWidth;
    const out = [];
    document.querySelectorAll('*').forEach((el) => {
      const r = el.getBoundingClientRect();
      if (r.right > vw + 1 || r.left < -1) {
        let cls = '';
        try { cls = typeof el.className === 'string' ? el.className.split(' ').slice(0, 3).join('.') : (el.getAttribute('class') || '').split(' ').slice(0, 3).join('.'); } catch { /* svg */ }
        out.push(`${el.tagName}${cls ? '.' + cls : ''} l=${Math.round(r.left)} r=${Math.round(r.right)} w=${Math.round(r.width)}`);
      }
    });
    return { vw, bodyScrollW: document.body.scrollWidth, docEl: document.documentElement.scrollWidth, offenders: out.slice(0, 20) };
  });
  console.log(JSON.stringify(bad, null, 2));
  await browser.close();
} finally {
  server.kill();
}
