import { useEffect, useRef } from 'react';
import createGlobe from 'cobe';

/** M4 globe visual. Mounts a `cobe` canvas only when visible; SVG fallback stays behind in the DOM. */
export function GeoGlobe() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    try {
      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
      const nav = navigator as Navigator & { connection?: { saveData?: boolean } };
      if (nav.connection?.saveData) return;
    } catch {
      return;
    }

    let globe: { destroy: () => void; update: (s: Record<string, unknown>) => void } | null = null;
    let visible = true;
    let raf = 0;
    let phi = 0;

    const start = () => {
      try {
        const cs = getComputedStyle(document.documentElement);
        const accent = cs.getPropertyValue('--scene-accent').trim() || '#4F46E5';
        const bg = cs.getPropertyValue('--scene-bg').trim() || '#DDE3ED';
        const toRgb = (hex: string): [number, number, number] => {
          const h = hex.replace('#', '');
          if (h.length !== 6) return [0.3, 0.3, 0.9];
          return [parseInt(h.slice(0, 2), 16) / 255, parseInt(h.slice(2, 4), 16) / 255, parseInt(h.slice(4, 6), 16) / 255];
        };
        globe = createGlobe(canvas, {
          devicePixelRatio: Math.min(1.5, window.devicePixelRatio || 1),
          width: 320,
          height: 200,
          phi,
          theta: 0.35,
          dark: document.documentElement.getAttribute('data-theme') === 'dark' ? 1 : 0,
          diffuse: 1.1,
          mapSamples: 8000,
          mapBrightness: 5,
          baseColor: toRgb(bg.startsWith('#') ? bg : '#DDE3ED'),
          markerColor: toRgb(accent.startsWith('#') ? accent : '#4F46E5'),
          glowColor: [0.7, 0.7, 0.8],
          markers: [{ location: [37.09, -95.71], size: 0.08 }],
        });
        const tick = () => {
          if (globe && visible && !document.hidden) {
            phi += 0.004;
            try {
              globe.update({ phi });
            } catch {
              /* noop */
            }
          }
          raf = window.requestAnimationFrame(tick);
        };
        raf = window.requestAnimationFrame(tick);
      } catch {
        globe = null;
      }
    };

    const onVis = () => {
      visible = !document.hidden;
    };
    const io =
      'IntersectionObserver' in window
        ? new IntersectionObserver(
            (entries) => {
              const inView = entries.some((e) => e.isIntersecting);
              // Never run alongside the main WebGL canvas: only render when the
              // hero well is off-screen.
              const hero = document.getElementById('hero-viewport-well');
              const heroVisible = hero ? hero.getBoundingClientRect().top < window.innerHeight && hero.getBoundingClientRect().bottom > 0 : false;
              visible = inView && !document.hidden && !heroVisible;
            },
            { threshold: 0.2 },
          )
        : null;
    if (io) io.observe(canvas);
    document.addEventListener('visibilitychange', onVis);
    // Defer creation until near viewport to avoid a second context upfront.
    const t = window.setTimeout(start, 400);

    const onTheme = () => {
      try {
        globe?.destroy();
      } catch {
        /* noop */
      }
      globe = null;
      start();
    };
    const mo = new MutationObserver(onTheme);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    return () => {
      window.clearTimeout(t);
      cancelAnimationFrame(raf);
      document.removeEventListener('visibilitychange', onVis);
      io?.disconnect();
      mo.disconnect();
      try {
        globe?.destroy();
      } catch {
        /* noop */
      }
    };
  }, []);

  return <canvas ref={canvasRef} style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }} aria-hidden="true" />;
}
