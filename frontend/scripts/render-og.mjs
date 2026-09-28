// One-off/dev-time OG image renderer: SVG -> public/og-image.png (1200x630).
// Usage: node scripts/render-og.mjs. Requires devDependency @resvg/resvg-js.
import { writeFileSync } from 'node:fs';
import { Resvg } from '@resvg/resvg-js';

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <rect width="1200" height="630" fill="#131824"/>
  <g stroke="#E6EAF3" stroke-opacity="0.08" stroke-width="1.5">
    <circle cx="880" cy="315" r="260" fill="none"/>
    <circle cx="880" cy="315" r="190" fill="none" stroke-dasharray="5 8"/>
    <circle cx="880" cy="315" r="125" fill="none" stroke-dasharray="4 8"/>
  </g>
  <ellipse cx="880" cy="500" rx="170" ry="22" fill="#1A2032"/>
  <rect x="740" y="240" width="280" height="180" rx="18" fill="#2A3247" stroke="#E6EAF3" stroke-opacity="0.3" stroke-width="2"/>
  <polygon points="740,258 880,356 1020,258 1020,240 740,240" fill="#1A2032" stroke="#E6EAF3" stroke-opacity="0.3" stroke-width="2"/>
  <rect x="740" y="316" width="280" height="12" fill="#818CF8" fill-opacity="0.6"/>
  <ellipse cx="880" cy="330" rx="200" ry="58" fill="none" stroke="#818CF8" stroke-width="3" stroke-opacity="0.8"/>
  <g fill="#818CF8">
    <circle cx="660" cy="180" r="9"/>
    <circle cx="1060" cy="170" r="7"/>
    <circle cx="1090" cy="430" r="10"/>
    <circle cx="630" cy="440" r="7"/>
  </g>
  <rect x="80" y="200" width="8" height="8" rx="4" fill="#818CF8"/>
  <text x="80" y="260" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="64" font-weight="800" fill="#E6EAF3">ThreatOptic</text>
  <text x="80" y="330" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="40" font-weight="600" fill="#A5B4FC">See the attack behind</text>
  <text x="80" y="380" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="40" font-weight="600" fill="#A5B4FC">every email.</text>
  <text x="80" y="440" font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif" font-size="24" fill="#A9B3C7">Explainable email threat investigation</text>
  <rect x="80" y="480" width="220" height="48" rx="10" fill="#818CF8"/>
  <text x="190" y="511" text-anchor="middle" font-family="system-ui, sans-serif" font-size="22" font-weight="700" fill="#0F1220">Open workspace</text>
</svg>`;

const resvg = new Resvg(svg, { fitTo: { mode: 'width', value: 1200 } });
const png = resvg.render().asPng();
writeFileSync(new URL('../public/og-image.png', import.meta.url), png);
console.log(`og-image.png written (${png.length} bytes)`);
