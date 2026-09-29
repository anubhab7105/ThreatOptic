import React, { Suspense, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { ThemeToggle } from '../main';
import { Badge, Button, Card, SeverityBadge, Tabs, Tooltip, Well } from '../primitives';
import { HeroPoster } from './Poster';
import { SceneBoundary } from './SceneBoundary';
import { useSceneStore } from './sceneStore';
import {
  EXPLAIN_FACTORS,
  GEO_SAMPLE,
  GRAPH_SAMPLE_EDGES,
  GRAPH_SAMPLE_NODES,
  HEADER_SAMPLE_ROWS,
  SAMPLE_EMAIL_TEXT,
  SAMPLE_FACTORS,
  SAMPLE_HOPS,
  SAMPLE_SCORE,
} from './sampleData';
import './landing.css';

const CANONICAL_BASE = 'https://socforensics.io';

function safeJsonLd(obj: unknown): string {
  return JSON.stringify(obj).replace(/<\//g, '<\\/');
}


const HeroScene = React.lazy(() => import('./HeroScene').then((m) => ({ default: m.HeroScene })));
const PipelineScene = React.lazy(() => import('./PipelineScene').then((m) => ({ default: m.PipelineScene })));
const GeoGlobe = React.lazy(() => import('./GeoGlobe').then((m) => ({ default: m.GeoGlobe })));

function usePageMeta(opts: { title: string; description: string; canonical: string; image?: string }) {
  useEffect(() => {
    document.title = opts.title;
    const setMeta = (name: string, content: string) => {
      let el = document.querySelector<HTMLMetaElement>(`meta[name="${name}"]`);
      if (!el) {
        el = document.createElement('meta');
        el.name = name;
        document.head.appendChild(el);
      }
      el.content = content;
    };
    const setProp = (prop: string, content: string) => {
      let el = document.querySelector<HTMLMetaElement>(`meta[property="${prop}"]`);
      if (!el) {
        el = document.createElement('meta');
        el.setAttribute('property', prop);
        document.head.appendChild(el);
      }
      el.content = content;
    };
    setMeta('description', opts.description);
    setProp('og:title', opts.title);
    setProp('og:description', opts.description);
    setProp('og:url', `${CANONICAL_BASE}${opts.canonical}`);
    if (opts.image) setProp('og:image', opts.image);
    setMeta('twitter:title', opts.title);
    setMeta('twitter:description', opts.description);
    let link = document.querySelector<HTMLLinkElement>('link[rel="canonical"]');
    if (!link) {
      link = document.createElement('link');
      link.rel = 'canonical';
      document.head.appendChild(link);
    }
    link.href = `${CANONICAL_BASE}${opts.canonical}`;
  }, [opts.title, opts.description, opts.canonical, opts.image]);
}

function useReveal() {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const root = ref.current;
    if (!root) return;
    const items = root.querySelectorAll('.landing-reveal');
    if (!('IntersectionObserver' in window)) {
      items.forEach((el) => el.classList.add('is-visible'));
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            e.target.classList.add('is-visible');
            io.unobserve(e.target);
          }
        }
      },
      { threshold: 0.12 },
    );
    items.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);
  return ref;
}

function Icon({ d }: { d: string }) {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={d} />
    </svg>
  );
}

const PIPELINE_STEPS = [
  {
    n: 'Step 1 · Ingest',
    title: 'Ingest',
    body: 'Upload a .eml file, paste raw RFC822, or connect a mailbox. Gmail live import connects over OAuth and syncs selected mail into the workspace.',
    scene: 'Small envelopes slide into a funnel toward the chamber.',
  },
  {
    n: 'Step 2 · Analyze',
    title: 'Analyze',
    body: 'Headers, body, links and attachments are separated and inspected: SPF, DKIM, DMARC and ARC checks, relay-chain reconstruction, URL and attachment intelligence.',
    scene: 'The envelope opens; four labeled layers fan out.',
  },
  {
    n: 'Step 3 · Score',
    title: 'Score',
    body: 'A fraud score from 0–100 with the reasons behind it — ranked factors with text weights, never a black box. Weights: language 30, authentication 25, intel 20, routing 15, attachment 10.',
    scene: 'Layers converge; a gauge ring fills to the sample score.',
  },
  {
    n: 'Step 4 · Investigate',
    title: 'Investigate',
    body: 'Trace origin with GeoLocation, map relationships in Graph View, open a case, and export a chain-of-custody PDF or JSON report.',
    scene: 'Nodes emerge into a graph; a hop path arcs to a small globe marker.',
  },
] as const;

const SHOWCASE_TABS = ['Summary', 'Why this score?', 'Header Forensics', 'GeoLocation', 'Graph View'] as const;

function ShowcaseVisual({ active }: { active: number }) {
  if (active === 0) {
    return (
      <Well>
        <p style={{ margin: '0 0 10px', fontSize: 13, color: 'var(--text-secondary)' }}>
          <Badge tone="neutral">Sample data</Badge>
        </p>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', marginBottom: 12 }}>
          <SeverityBadge score={SAMPLE_SCORE} />
          <span className="landing-new__mono">score {SAMPLE_SCORE} / 100 · Critical · action: hold</span>
        </div>
        <dl className="landing-new__kv">
          <dt>Subject</dt>
          <dd>Urgent: confidential wire transfer needed ASAP</dd>
          <dt>Sender</dt>
          <dd>ceo@paypa1-secure.example (fictional)</dd>
          <dt>Verdict</dt>
          <dd>Impersonation + auth failure — open a case</dd>
        </dl>
      </Well>
    );
  }
  if (active === 1) {
    return (
      <Well>
        <p style={{ margin: '0 0 6px', fontSize: 13, color: 'var(--text-secondary)' }}>
          <Badge tone="neutral">Sample data</Badge> Ranked factors, weights sum to the score.
        </p>
        {SAMPLE_FACTORS.map((f) => (
          <div className="landing-new__factor" key={f.name}>
            <span>{f.name}</span>
            <b>+{f.weight}</b>
            <span className="landing-new__factor-bar" aria-hidden="true">
              <span className="landing-new__factor-fill" style={{ width: `${Math.min(100, f.weight * 2.4)}%` }} />
            </span>
            <span style={{ gridColumn: '1 / -1', color: 'var(--text-muted)', fontSize: 12 }}>{f.detail}</span>
          </div>
        ))}
      </Well>
    );
  }
  if (active === 2) {
    return (
      <Well>
        <p style={{ margin: '0 0 10px', fontSize: 13, color: 'var(--text-secondary)' }}>
          <Badge tone="neutral">Sample data</Badge> Monospace hop timeline, same shape as the app.
        </p>
        <div style={{ overflowX: 'auto' }}>
          <table className="neu-table" aria-label="Sample header forensics">
            <thead>
              <tr>
                <th scope="col">Field</th>
                <th scope="col">Value</th>
                <th scope="col">Reading</th>
              </tr>
            </thead>
            <tbody>
              {HEADER_SAMPLE_ROWS.map((r) => (
                <tr key={r.field}>
                  <td className="landing-new__mono">{r.field}</td>
                  <td className="landing-new__mono">{r.value}</td>
                  <td>{r.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Well>
    );
  }
  if (active === 3) {
    return (
      <Well>
        <p style={{ margin: '0 0 10px', fontSize: 13, color: 'var(--text-secondary)' }}>
          <Badge tone="neutral">Sample data</Badge> Origin marker and hop arc are illustrative, not real geolocation.
        </p>
        <div className="landing-new__geo-grid">
          <div>
            <dl className="landing-new__kv">
              <dt>Origin IP</dt>
              <dd>{GEO_SAMPLE.originIp}</dd>
              <dt>Country</dt>
              <dd>{GEO_SAMPLE.country}</dd>
              <dt>ASN</dt>
              <dd>{GEO_SAMPLE.asn}</dd>
              <dt>Hops</dt>
              <dd>{GEO_SAMPLE.hops} relays traced</dd>
            </dl>
            <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>{GEO_SAMPLE.note}</p>
          </div>
          <div className="landing-new__well" style={{ aspectRatio: '16 / 10', minHeight: 180 }} aria-hidden="true">
            <Suspense fallback={null}>
              <SceneBoundary>
                <GeoGlobe />
              </SceneBoundary>
            </Suspense>
            <svg viewBox="0 0 320 200" role="presentation" style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }}>
              <ellipse cx="160" cy="100" rx="120" ry="70" fill="none" stroke="var(--scene-line)" strokeWidth="1.5" strokeDasharray="4 5" />
              <path d="M60 140 Q160 40 260 90" fill="none" stroke="var(--scene-accent)" strokeWidth="2" />
              <circle cx="60" cy="140" r="6" fill="var(--scene-accent)" />
              <circle cx="260" cy="90" r="7" fill="var(--scene-risk)" />
            </svg>
          </div>
        </div>
      </Well>
    );
  }
  return (
    <Well>
      <p style={{ margin: '0 0 10px', fontSize: 13, color: 'var(--text-secondary)' }}>
        <Badge tone="neutral">Sample data</Badge> Lightweight SVG graph — never a second WebGL context.
      </p>
      <svg className="landing-new__graph-svg" viewBox="0 0 560 220" role="img" aria-label="Sample relationship graph: one email connected to a domain, an IP, a URL and a case.">
        <g stroke="var(--border-strong)" strokeWidth="1.2">
          <line x1="280" y1="110" x2="120" y2="60" />
          <line x1="280" y1="110" x2="120" y2="165" />
          <line x1="280" y1="110" x2="440" y2="60" />
          <line x1="280" y1="110" x2="440" y2="165" />
        </g>
        {[
          { x: 280, y: 110, label: GRAPH_SAMPLE_NODES[0].label },
          { x: 120, y: 60, label: GRAPH_SAMPLE_NODES[1].label },
          { x: 120, y: 165, label: GRAPH_SAMPLE_NODES[2].label },
          { x: 440, y: 60, label: GRAPH_SAMPLE_NODES[3].label },
          { x: 440, y: 165, label: GRAPH_SAMPLE_NODES[4].label },
        ].map((n) => (
          <g key={n.label}>
            <rect x={n.x - 78} y={n.y - 16} width="156" height="32" rx="10" fill="var(--surface)" stroke="var(--border-subtle)" />
            <circle cx={n.x - 62} cy={n.y} r="6" fill="var(--accent-primary)" />
            <text x={n.x - 50} y={n.y + 4} fontSize="10" fill="var(--text-primary)">{n.label.slice(0, 24)}</text>
          </g>
        ))}
      </svg>
      <ul className="landing-new__mono" style={{ margin: '10px 0 0', paddingLeft: 18, color: 'var(--text-secondary)' }}>
        {GRAPH_SAMPLE_EDGES.map((e) => (
          <li key={`${e.from}-${e.to}`}>{e.from} —{e.label}→ {e.to}</li>
        ))}
      </ul>
    </Well>
  );
}

function SampleDemo() {
  const [ran, setRan] = useState(false);
  const [playing, setPlaying] = useState(false);
  const reduceMotion = useRef(false);
  useEffect(() => {
    try {
      reduceMotion.current = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    } catch {
      reduceMotion.current = false;
    }
  }, []);
  const run = () => {
    if (reduceMotion.current) {
      setRan(true);
      return;
    }
    setPlaying(true);
    window.setTimeout(() => {
      setRan(true);
      setPlaying(false);
    }, 650);
  };
  return (
    <div>
      <Well>
        <label className="neu-label" htmlFor="landing-sample-mail" style={{ display: 'block', fontWeight: 700, fontSize: 13, marginBottom: 8 }}>
          Fictional phishing sample (nothing leaves your browser)
        </label>
        <pre id="landing-sample-mail" className="landing-new__demo-mail" tabIndex={0} aria-label="Sample email text">{SAMPLE_EMAIL_TEXT}</pre>
        <div className="row" style={{ marginTop: 12 }}>
          <Button variant="primary" onClick={run} loading={playing} disabled={playing}>
            Run sample analysis
          </Button>
          {ran ? <Badge tone="neutral">Sample only. Nothing leaves your browser.</Badge> : null}
        </div>
      </Well>
      <div aria-live="polite" style={{ marginTop: 12 }}>
        {ran ? (
          <Card title="Sample result" description="Canned client-side output — labeled Sample">
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
              <SeverityBadge score={SAMPLE_SCORE} />
              <span className="landing-new__mono">score {SAMPLE_SCORE} / 100</span>
              <Badge tone="neutral">Sample</Badge>
            </div>
            <ul style={{ margin: '0 0 10px', paddingLeft: 20, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
              {SAMPLE_FACTORS.map((f) => (
                <li key={f.name}>{f.name} (+{f.weight})</li>
              ))}
            </ul>
            <ol className="landing-new__hop-list">
              {SAMPLE_HOPS.map((h) => (
                <li key={h.hop}>
                  Hop {h.hop}: {h.from} → {h.by} · <span className="landing-new__mono">{h.ip} · {h.result}</span>
                </li>
              ))}
            </ol>
            <div className="row" style={{ marginTop: 14 }}>
              <Link className="neu-btn neu-btn--primary neu-btn--md" to="/login">
                Analyze your own emails
              </Link>
            </div>
          </Card>
        ) : null}
      </div>
    </div>
  );
}

export function LandingPage() {
  usePageMeta({
    title: 'ThreatOptic | See the attack behind every email',
    description: 'Score suspicious emails, dissect their headers, trace their origin and map who they connect to — in one explainable workspace.',
    canonical: '/',
    image: 'https://socforensics.io/og-image.png',
  });
  const rootRef = useReveal();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [compact, setCompact] = useState(false);
  const [showScene, setShowScene] = useState(false);
  const [showPipelineScene, setShowPipelineScene] = useState(false);
  const [tab, setTab] = useState(0);

  useEffect(() => {
    const onScroll = () => setCompact(window.scrollY > 40);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);


  useEffect(() => {
    let cancelled = false;
    const enable = () => {
      if (!cancelled) setShowScene(true);
    };
    try {
      const saveData = (navigator as Navigator & { connection?: { saveData?: boolean } }).connection?.saveData;
      const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      const small = window.matchMedia('(max-width: 767px)').matches;
      if (saveData || reduced || small) return;
      const w = window as unknown as {
        requestIdleCallback?: (cb: () => void, o?: { timeout: number }) => number;
        cancelIdleCallback?: (id: number) => void;
      };
      if (typeof w.requestIdleCallback === 'function') {
        const id = w.requestIdleCallback(enable, { timeout: 2500 });
        return () => {
          cancelled = true;
          w.cancelIdleCallback?.(id);
        };
      }
      const t = window.setTimeout(enable, 1200);
      return () => {
        cancelled = true;
        window.clearTimeout(t);
      };
    } catch {

    }
    return () => {
      cancelled = true;
    };
  }, []);


  useEffect(() => {
    let raf = 0;
    const update = () => {
      raf = 0;
      try {
        const section = document.getElementById('how-it-works');
        if (!section) return;
        if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
          useSceneStore.getState().setProgress(0);
          return;
        }
        const r = section.getBoundingClientRect();
        const total = r.height - window.innerHeight * 0.6;
        const done = -r.top + window.innerHeight * 0.25;
        useSceneStore.getState().setProgress(total > 0 ? done / total : 0);
      } catch {

      }
    };
    const onScroll = () => {
      if (!raf) raf = window.requestAnimationFrame(update);
    };
    update();
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll);
    return () => {
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('resize', onScroll);
      if (raf) window.cancelAnimationFrame(raf);
    };
  }, []);

  useEffect(() => {
    const el = document.getElementById('pipeline-scene-host');
    if (!el || !('IntersectionObserver' in window)) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setShowPipelineScene(true);
          io.disconnect();
        }
      },
      { rootMargin: '400px' },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  return (
    <div className="landing-new" ref={rootRef}>
      <a href="#main-content" className="skip-link">
        Skip to content
      </a>
      <header className={`landing-new__header${compact ? ' landing-new__header--compact' : ''}`}>
        <nav className="landing-new__nav" aria-label="Primary">
          <Link to="/" className="landing-new__brand" aria-label="ThreatOptic home">
            <span className="landing-new__brand-mark" aria-hidden="true">◈</span> ThreatOptic
          </Link>
          <div className="landing-new__links">
            <a href="#how-it-works">How it works</a>
            <a href="#features">Features</a>
            <a href="#demo">Demo</a>
            <a href="#security">Security</a>
          </div>
          <div className="landing-new__nav-actions">
            <ThemeToggle />
            <Link className="neu-btn neu-btn--primary neu-btn--md" to="/login">
              Open workspace
            </Link>
            <button
              type="button"
              className="neu-icon-btn landing-new__drawer-btn"
              aria-label={drawerOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={drawerOpen}
              onClick={() => setDrawerOpen((o) => !o)}
            >
              <span aria-hidden="true">{drawerOpen ? '✕' : '☰'}</span>
            </button>
          </div>
        </nav>
        {drawerOpen ? (
          <nav className="landing-new__wrap landing-new__drawer" aria-label="Mobile">
            <a href="#how-it-works" onClick={() => setDrawerOpen(false)}>How it works</a>
            <a href="#features" onClick={() => setDrawerOpen(false)}>Features</a>
            <a href="#demo" onClick={() => setDrawerOpen(false)}>Demo</a>
            <a href="#security" onClick={() => setDrawerOpen(false)}>Security</a>
            <Link to="/login" onClick={() => setDrawerOpen(false)}>Open workspace</Link>
            <Link to="/model" onClick={() => setDrawerOpen(false)}>Model transparency</Link>
          </nav>
        ) : null}
      </header>

      <main id="main-content" className="landing-new__main">
        {}
        <section className="landing-new__hero" aria-labelledby="landing-h1">
          <div className="landing-new__hero-grid">
            <div className="landing-reveal">
              <span className="landing-new__eyebrow">
                <span className="landing-new__eyebrow-dot" aria-hidden="true" /> Email threat investigation
              </span>
              <h1 id="landing-h1" className="landing-new__title">See the attack behind every email.</h1>
              <p className="landing-new__lead">
                Score suspicious emails, dissect their headers, trace their origin and map who they connect to, all in one explainable workspace.
              </p>
              <div className="landing-new__cta-row">
                <Link className="neu-btn neu-btn--primary neu-btn--lg" to="/login">
                  Open workspace
                </Link>
                <a className="neu-btn neu-btn--lg" href="#how-it-works">
                  See how it works
                </a>
              </div>
              <ul className="landing-new__chips" aria-label="Capabilities">
                <li><Badge tone="info" icon={<span aria-hidden="true">◐</span>}>Explainable scoring</Badge></li>
                <li><Badge tone="info" icon={<span aria-hidden="true">⌘</span>}>Header forensics</Badge></li>
                <li><Badge tone="info" icon={<span aria-hidden="true">✉</span>}>Live Gmail import</Badge></li>
              </ul>
            </div>
            <div className="landing-new__viewport landing-reveal">
              <div className="landing-new__well" id="hero-viewport-well">
                <HeroPoster />
                {showScene ? (
                  <div className="landing-canvas-host" aria-hidden="true">
                    <Suspense fallback={null}>
                      <SceneBoundary>
                        <HeroScene />
                      </SceneBoundary>
                    </Suspense>
                  </div>
                ) : null}
                <span className="landing-new__scene-label">
                  <SeverityBadge score={SAMPLE_SCORE} /> <span>Sample</span>
                </span>
              </div>
              <p className="landing-new__well-caption">Static preview shown first; interactive 3D loads after first paint on capable desktops. Decorative — all content is in text.</p>
            </div>
          </div>
        </section>

        {}
        <section id="how-it-works" className="landing-new__section" aria-labelledby="how-title" style={{ paddingTop: 0 }}>
          <div className="landing-new__wrap">
            <h2 id="how-title" className="landing-new__section-title landing-reveal">From raw email to explainable case</h2>
            <p className="landing-new__section-sub landing-reveal">Four steps. The same canvas follows along on desktop; plain text below carries every step for screen readers and reduced motion.</p>
            <div className="landing-new__steps">
              {PIPELINE_STEPS.map((s, i) => (
                <Card key={s.title} title={`${i + 1}. ${s.title}`} description={s.n}>
                  <p>{s.body}</p>
                  <p className="landing-new__step-tag">3D note: {s.scene}</p>
                </Card>
              ))}
            </div>
            <div id="pipeline-scene-host" className="landing-new__pipeline-visual">
              {showPipelineScene ? (
                <Suspense fallback={null}>
                  <SceneBoundary>
                    <PipelineScene progress={0} reduced />
                  </SceneBoundary>
                </Suspense>
              ) : null}
            </div>
          </div>
        </section>

        {}
        <section id="features" className="landing-new__section" aria-labelledby="features-title" style={{ paddingTop: 0 }}>
          <div className="landing-new__wrap">
            <h2 id="features-title" className="landing-new__section-title landing-reveal">One workspace, five lenses</h2>
            <p className="landing-new__section-sub landing-reveal">The same five tabs as the investigation view, illustrated with UI primitives and sample data.</p>
            <div className="landing-new__showcase-panel landing-reveal">
              <Tabs tabs={[...SHOWCASE_TABS]} active={tab} onChange={setTab} label="Feature showcase" />
              <div role="tabpanel" aria-label={SHOWCASE_TABS[tab]}>
                <p className="landing-new__tab-desc">
                  {tab === 0 ? 'Verdict and key indicators first, then supporting evidence — the triage starting point.' : null}
                  {tab === 1 ? 'Every score ships with ranked reasons and text weights, so the verdict can be challenged.' : null}
                  {tab === 2 ? 'Parsed fields beside raw headers, with a hop timeline, copy support and weight-plus-icon emphasis.' : null}
                  {tab === 3 ? 'Origin, country, ASN and hop path first; reputation and related indicators below.' : null}
                  {tab === 4 ? 'A lightweight node graph of shared infrastructure — SVG on the landing page, full canvas in the app.' : null}
                </p>
                <ul className="landing-new__tab-bullets">
                  {tab === 0 ? (<><li>Fraud score 0–100 with severity badge (icon + text + tint)</li><li>Key indicators before supporting evidence</li><li>Direct path to case creation and report export</li></>) : null}
                  {tab === 1 ? (<><li>Ranked contributing factors with contribution bars</li><li>Text weights beside every bar</li><li>Link to Model Info transparency metrics</li></>) : null}
                  {tab === 2 ? (<><li>SPF, DKIM, DMARC and ARC with pass/fail pills</li><li>Relay chain as a vertical timeline</li><li>Raw headers with copy buttons</li></>) : null}
                  {tab === 3 ? (<><li>Origin IP, country, ASN and hop path</li><li>Illustrative globe or SVG map with origin marker</li><li>Themed in both light and dark</li></>) : null}
                  {tab === 4 ? (<><li>Shared IPs, domains and addresses as linked nodes</li><li>Compact toolbar with zoom, fit, filter and legend in-app</li><li>Node detail panel without invented data</li></>) : null}
                </ul>
                <ShowcaseVisual active={tab} />
              </div>
            </div>
          </div>
        </section>

        {}
        <section className="landing-new__section" aria-labelledby="explain-title" style={{ paddingTop: 0 }}>
          <div className="landing-new__wrap">
            <h2 id="explain-title" className="landing-new__section-title landing-reveal">Every score comes with its reasons</h2>
            <p className="landing-new__section-sub landing-reveal">Sample factor weights below. Real model metrics live on the transparency page.</p>
            <div className="landing-new__explain">
              <Card title="Sample factor breakdown" description="Weights sum to the score — sample data">
                {EXPLAIN_FACTORS.map((f) => (
                  <div className="landing-new__factor" key={f.name}>
                    <span>{f.name}</span>
                    <b>{f.weight}%</b>
                    <span className="landing-new__factor-bar" aria-hidden="true">
                      <span className="landing-new__factor-fill" style={{ width: `${f.weight * 2.6}%` }} />
                    </span>
                    <span style={{ gridColumn: '1 / -1', color: 'var(--text-muted)', fontSize: 12 }}>{f.text}</span>
                  </div>
                ))}
              </Card>
              <Card title="Model transparency" description="Held-out evaluation, per-class metrics, confusion matrix">
                <p style={{ margin: '0 0 12px', color: 'var(--text-secondary)', fontSize: 14, lineHeight: 1.6 }}>
                  Open precision, recall and F1 with a per-class confusion matrix. The score is explainable, not a black box.
                </p>
                <div className="row">
                  <Link className="neu-btn neu-btn--primary neu-btn--md" to="/model">View Model Info</Link>
                  <Tooltip label="Accuracy, precision, recall, F1 and confusion matrix">
                    <Link className="neu-btn neu-btn--md" to="/model">What is measured?</Link>
                  </Tooltip>
                </div>
              </Card>
            </div>
          </div>
        </section>

        {}
        <section id="demo" className="landing-new__section" aria-labelledby="demo-title" style={{ paddingTop: 0 }}>
          <div className="landing-new__wrap">
            <h2 id="demo-title" className="landing-new__section-title landing-reveal">Try a sample analysis</h2>
            <p className="landing-new__section-sub landing-reveal">Client-side only. Fictional domains, no real brands. Nothing leaves your browser.</p>
            <div className="landing-reveal"><SampleDemo /></div>
          </div>
        </section>

        {}
        <section className="landing-new__section" aria-labelledby="integrations-title" style={{ paddingTop: 0 }}>
          <div className="landing-new__wrap">
            <h2 id="integrations-title" className="landing-new__section-title landing-reveal">Connect a mailbox, work the case, export the proof</h2>
            <p className="landing-new__section-sub landing-reveal">The same stepper shape as the in-app Gmail import.</p>
            <div className="landing-new__split">
              <Card title="Mailbox connection" description="OAuth, read-only — Waiting › Connecting › Connected">
                <div className="landing-new__flow" aria-label="Connection flow: waiting, connecting, connected">
                  <span className="landing-new__flow-step landing-new__flow-step--done"><span aria-hidden="true">✓</span> Waiting</span>
                  <span className="landing-new__flow-sep" aria-hidden="true">›</span>
                  <span className="landing-new__flow-step landing-new__flow-step--current"><span aria-hidden="true">○</span> Connecting</span>
                  <span className="landing-new__flow-sep" aria-hidden="true">›</span>
                  <span className="landing-new__flow-step"><span aria-hidden="true">○</span> Connected</span>
                </div>
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>Gmail live import connects automatically once authorized. Manage polling, sync state and disconnect from the Mailboxes workspace.</p>
                <div className="row"><Link className="neu-btn neu-btn--md" to="/login">Open Mailboxes</Link></div>
              </Card>
              <div style={{ display: 'grid', gap: 16 }}>
                <Card title="Case management" description="Triage to closure with timeline and notes">
                  <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>Group related mail, track status and assignee, keep the investigation trail beside the evidence.</p>
                  <div className="row" style={{ marginTop: 10 }}><Link className="neu-btn neu-btn--md" to="/login">Open Cases</Link></div>
                </Card>
                <Card title="Reports" description="Chain-of-custody PDF and JSON">
                  <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>SHA-256 hashed originals with timestamps, scores and evidence references — downloadable from the workspace.</p>
                </Card>
              </div>
            </div>
          </div>
        </section>

        {}
        <section id="security" className="landing-new__section" aria-labelledby="security-title" style={{ paddingTop: 0 }}>
          <div className="landing-new__wrap">
            <h2 id="security-title" className="landing-new__section-title landing-reveal">Access control you can describe honestly</h2>
            <p className="landing-new__section-sub landing-reveal">Only what the product does. No compliance badges, no invented claims.</p>
            <Card title="Security and access" description="Factual platform behavior">
              <ul className="landing-new__icon-rows">
                <li>
                  <span className="landing-new__icon" aria-hidden="true"><Icon d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></span>
                  <div><b>Role-based access</b><p>Read-only, analyst and admin roles gate ingestion, case edits and destructive actions.</p></div>
                </li>
                <li>
                  <span className="landing-new__icon" aria-hidden="true"><Icon d="M12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2" /></span>
                  <div><b>Tenant isolation</b><p>Every email, case and dashboard query is scoped to the signed-in organization.</p></div>
                </li>
                <li>
                  <span className="landing-new__icon" aria-hidden="true"><Icon d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /></span>
                  <div><b>Authenticated mailbox OAuth</b><p>Mailbox connectors authorize through the provider consent flow; secrets stay server-side.</p></div>
                </li>
                <li>
                  <span className="landing-new__icon" aria-hidden="true"><Icon d="M16 13H8M16 17H8M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /></span>
                  <div><b>Exportable reports</b><p>Evidence exports as PDF or JSON with hashes and timestamps for handoff.</p></div>
                </li>
              </ul>
            </Card>
          </div>
        </section>

        {}
        <section className="landing-new__section" aria-labelledby="cta-title" style={{ paddingTop: 0 }}>
          <div className="landing-new__wrap">
            <Card title="Start investigating in minutes">
              <div className="landing-new__cta-panel">
                <h2 id="cta-title" className="landing-new__section-title">Start investigating in minutes</h2>
                <p>Sign in to open the workspace — dashboard, cases, mailboxes and model transparency.</p>
                <div className="landing-new__cta-row" style={{ justifyContent: 'center' }}>
                  <Link className="neu-btn neu-btn--primary neu-btn--lg" to="/login">Open workspace</Link>
                  <Link className="neu-btn neu-btn--lg" to="/model">View Model Info</Link>
                </div>
              </div>
            </Card>
          </div>
        </section>
      </main>

      <footer className="landing-new__footer">
        <div className="landing-new__footer-grid">
          <div className="landing-new__footer-brand">
            <Link to="/" className="landing-new__brand" aria-label="ThreatOptic home"><span className="landing-new__brand-mark" aria-hidden="true">◈</span> ThreatOptic</Link>
            <p>Email threat detection, geolocation, and forensic intelligence for security operations teams.</p>
          </div>
          <nav aria-label="Product">
            <h2>Product</h2>
            <ul>
              <li><Link to="/login">Open workspace</Link></li>
              <li><Link to="/model">Model transparency</Link></li>
            </ul>
          </nav>
          <nav aria-label="Company">
            <h2>Company</h2>
            <ul>
              <li><Link to="/privacy">Privacy Policy</Link></li>
              <li><Link to="/terms">Terms of Service</Link></li>
            </ul>
          </nav>
          <nav aria-label="Resources">
            <h2>Resources</h2>
            <ul>
              <li><a href="/sitemap.xml">Sitemap</a></li>
              <li><a href="/robots.txt">Robots</a></li>
              <li><a href="/llms.txt">LLMs.txt</a></li>
            </ul>
          </nav>
        </div>
        <div className="landing-new__footer-bottom">
          <p>© 2026 ThreatOptic · Sample visuals labeled where illustrative.</p>
        </div>
      </footer>

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: safeJsonLd({
            '@context': 'https://schema.org',
            '@type': 'SoftwareApplication',
            name: 'ThreatOptic',
            applicationCategory: 'SecurityApplication',
            operatingSystem: 'Web',
            url: `${CANONICAL_BASE}/`,
            description: 'Score suspicious emails, dissect headers, trace origin and map relationships in an explainable workspace.',
            offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
          }),
        }}
      />
    </div>
  );
}
