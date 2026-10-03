# Landing_Design.md: Public Landing Page (3D Neumorphic SOC)

> Companion to `Design.md`. The landing page uses the same tokens, themes and accessibility rules, but is allowed to be more expressive: real 3D, scroll storytelling and larger surfaces. Where this file and `Design.md` conflict **for the landing page only**, this file wins. Backend, API contracts, auth, roles, tenancy and every in-app route are out of scope and must not change.

---

## 1. Concept: "The Inspection Chamber"

The product turns a suspicious email into an explainable investigation: **score it, dissect its headers, trace where it came from, map who it connects to.** The landing page tells that story as one continuous 3D scene.

- A soft-matte, clay-like 3D **envelope** floats inside a calm slate chamber. It is the same material language as the neumorphic UI: matte, rounded, softly lit, no glow.
- As the visitor scrolls, the envelope is **scanned, opened, dissected into layers** (headers, body, links, attachments), **scored**, and finally **connected into a graph**. Each step maps to a real product tab.
- The scene sits in an **inset viewport well** on the page, so 3D and 2D feel like one system.

**Personality:** confident, precise, quiet. Think forensic instrument, not sci-fi movie.

**Never:** neon glow, bloom, glassmorphism, lens flares, matrix rain, skulls/hooded hackers, padlock clip-art, fake dashboards with invented numbers, stock photos.

---

## 2. Truthfulness rules (non-negotiable)

- **No invented proof.** No fake customer logos, testimonials, user counts, uptime numbers, compliance badges (SOC 2, ISO, etc.) or "trusted by" claims.
- Any number shown must come from the real Model Info data if available, or be clearly labeled **"Sample data"**.
- The interactive demo (section 5.6) is client-side only, labeled as a sample, and never calls the backend.
- Describe only features that exist in the product: email ingestion and analysis, explainable fraud score, header forensics, threat intelligence, GeoLocation, relationship graph, case management, mailbox OAuth, Gmail live import, model metrics, PDF/JSON reports, role-based access, tenant isolation.

---

## 3. Design system inheritance and landing extensions

Use all tokens from `Design.md` section 2 (light and dark) and the same theme system, toggle and persistence. Add these **scene tokens** (CSS variables, themed):

| Token | Light | Dark |
|---|---|---|
| `--scene-bg` | `#DDE3ED` | `#131824` |
| `--scene-clay` | `#E9EEF6` | `#2A3247` |
| `--scene-clay-shade` | `#BFC9DA` | `#1A2032` |
| `--scene-accent` | `#4F46E5` | `#818CF8` |
| `--scene-line` | `rgba(27,35,51,0.35)` | `rgba(230,234,243,0.35)` |
| `--scene-risk` | `#B91C1C` | `#F87171` |

Landing-specific allowances:

- Hero and showcase panels may use `--shadow-raised-lg`. Everything else follows `Design.md` (max two shadow layers, max nesting depth two).
- Larger type scale: display 56/64/72, section title 36/40, lead 20.
- Section rhythm: 96px vertical padding desktop, 64px tablet, 48px mobile.
- Content max width 1200px, hero up to 1360px.
- Section dividers are spacing plus a hairline; no heavy separators.
- Every interactive control keeps the 1px border and focus ring from `Design.md` section 4.

---

## 4. Tech and open-source stack

Detect the existing framework first (Vite/React, Next.js, etc.) and match it. Verify version compatibility before installing (React Three Fiber v8 pairs with React 18, v9 with React 19).

| Purpose | Package | License |
|---|---|---|
| 3D engine | `three` | MIT |
| React renderer for three | `@react-three/fiber` | MIT |
| Helpers (Html, Float, PerformanceMonitor, AdaptiveDpr, Lightformer) | `@react-three/drei` | MIT |
| Damped motion / easing | `maath` | MIT |
| Scene state | `zustand` | MIT |
| UI motion, scroll progress | `motion` (Framer Motion) | MIT |
| Lightweight globe (geo section) | `cobe` | MIT |
| Icons | `lucide-react` | ISC |
| Accessible primitives | Radix UI / shadcn/ui (only what is needed) | MIT |
| Fonts (self-hosted) | `@fontsource-variable/inter`, `@fontsource/jetbrains-mono` | OFL |

Rules:

- **Do not** use `@react-three/postprocessing`/bloom, Spline, or anything proprietary or requiring an external service.
- **Do not** let drei fetch HDRI files from a CDN. Build the lighting with `<Environment>` + `<Lightformer>` (procedural), or self-host any asset. The site must work with no third-party requests except fonts self-hosted from the same origin.
- Prefer procedural geometry (RoundedBox, extruded shapes, tubes, instanced meshes). If a `.glb` is needed, keep it under 300 KB, compress with meshopt/draco, and self-host.
- Avoid smooth-scroll hijacking libraries. Use native scroll plus scroll-linked progress (`motion` `useScroll` or CSS scroll-driven animations with fallback).
- One WebGL context on the page at a time: the hero/pipeline canvas. The globe (`cobe`) mounts only when its section is near the viewport and the main canvas is not visible, or is replaced by an SVG map fallback.
- Lazy-load all 3D code (`React.lazy`/dynamic import with `ssr: false` in Next.js) so it never blocks first paint.

---

## 5. Page structure

### 5.1 Navigation (sticky, raised-md)

Logo/wordmark (read the real product name and logo from the repo; do not invent one), anchor links (How it works, Features, Demo, Security), theme toggle (same component as the app), primary CTA (**Open workspace**, linking to the existing login/app entry route), mobile drawer under 768px. Nav becomes visually compact after scrolling 40px.

### 5.2 Hero: pinned-canvas start

Layout: two columns on desktop (copy left, 3D right), stacked on tablet, poster on mobile.

**Copy (starting point, adjust wording to the product's voice):**

- Eyebrow: `Email threat investigation`
- H1: **See the attack behind every email.**
- Lead: *Score suspicious emails, dissect their headers, trace their origin and map who they connect to, all in one explainable workspace.*
- Primary CTA: **Open workspace**. Secondary CTA: **See how it works** (smooth-anchors to section 5.3).
- Under the CTAs, a small inset row of three real capability chips with icons: `Explainable scoring`, `Header forensics`, `Live Gmail import`.

**3D hero scene** (sits in an inset well with `--r-lg`, aspect 4:3 on desktop):

1. Central matte envelope (rounded-box body plus flap), slow idle float (amplitude under 0.15 units, period around 6s).
2. Three thin orbit rings (torus, low tube radius) representing analysis layers, rotating slowly at different speeds.
3. Every ~7s a **scan plane** (flat translucent slab, no glow) sweeps across the envelope, and a small HTML label anchored to it reads `Fraud score 87 · Critical` with the tag **Sample**.
4. A cluster of 12-20 small node spheres (instanced) connected by thin lines drifts around, hinting at the graph.
5. Pointer parallax: camera and envelope tilt max 6 degrees, damped with `maath`. Disabled for touch and reduced motion.
6. Lighting: soft key light top-left, faint rim, procedural environment via Lightformers, soft contact shadow under the envelope. Materials: `MeshStandardMaterial`, roughness 0.75-0.9, metalness 0, colors from scene tokens (read via CSS variables, update on theme change without remounting the canvas).

### 5.3 How it works: scroll-driven pipeline

Desktop: the same canvas stays **pinned** while four steps scroll on the left; scene state is driven by scroll progress (0 to 1). Tablet: not pinned, each step shows a smaller scene snapshot. Mobile: SVG illustrations per step.

| Step | Copy | Scene state |
|---|---|---|
| 1. Ingest | Upload, paste, or connect a mailbox. Gmail live import connects automatically. | Small envelopes slide into a funnel toward the chamber |
| 2. Analyze | Headers, body, links and attachments are separated and inspected. | Envelope opens; four labeled layers fan out |
| 3. Score | A fraud score with the reasons behind it, not a black box. | Layers converge; a gauge ring fills to the sample score |
| 4. Investigate | Trace origin, map relationships, open a case, export a report. | Nodes emerge into a graph around the envelope; a hop path arcs to a small globe marker |

Each step also has a keyboard-reachable "Skip 3D" text alternative for screen readers describing the same content in plain text (see section 8).

### 5.4 Feature showcase (five tabs, mirroring the app)

Tabs: **Summary, Why this score?, Header Forensics, GeoLocation, Graph View.**

- One large raised panel with an inset well containing the active tab's visual.
- Visuals are **built from the real UI primitives** (Badge, Table, Tabs, gauge), not screenshots, so they respect both themes and stay crisp. Use clearly marked sample data.
- Each tab has a 2-3 sentence description and 3 bullet capabilities (only real ones).
- Header Forensics visual: monospace hop timeline. GeoLocation visual: `cobe` globe or SVG map with an origin marker and hop arc. Graph View visual: a lightweight SVG/canvas node graph, not a second WebGL context.

### 5.5 Explainability strip

Compact section: "Every score comes with its reasons." Shows a ranked factor list with contribution bars and text weights (sample), plus a link to the Model Info transparency section. If real model metrics can be imported safely at build time from existing static data, show them; otherwise show sample-labeled values.

### 5.6 Interactive sample analysis (client-side)

- Prefilled fictional phishing email (fictional domains using `example.com`/`.invalid`, no real brands).
- Button: **Run sample analysis**. On click, animate a canned result: score, severity badge (icon + text), three contributing factors, a mini hop trail.
- Label: **"Sample only. Nothing leaves your browser."**
- Below the result: CTA **Analyze your own emails** to the workspace entry route.
- Must be keyboard operable, `aria-live="polite"` for the result, and functional with JavaScript animation disabled.

### 5.7 Integrations and workflow

Panel showing mailbox connection and Gmail live import as a compact **Waiting > Connecting > Connected** state flow (static illustration matching the in-app stepper), plus case management and report export (PDF/JSON) as two short inset callouts.

### 5.8 Security and access

Honest, factual only: role-based access, tenant isolation, authenticated mailbox OAuth, exportable reports. Icon rows on a single panel. No compliance claims unless the repo/docs prove them.

### 5.9 Final CTA

Large raised panel with a small looping-free static version of the envelope (poster), headline **Start investigating in minutes**, primary CTA, secondary link to docs if a docs route exists.

### 5.10 Footer

Flat. Product name, link groups only for routes/pages that actually exist, theme toggle repeat is optional, copyright.

---

## 6. Motion rules

- Purpose only: motion explains the pipeline or gives feedback. No decorative loops besides the hero idle float and scan.
- Durations 140-240ms for UI, 600-900ms for scene transitions. Easing: ease-out.
- Section reveals: opacity + 12px translate, once, via IntersectionObserver.
- `prefers-reduced-motion: reduce`: no idle float, no scan, no parallax, no scroll-driven scene changes. Show the **static poster** and the steps as plain content.
- Pause rendering when the tab is hidden, when the canvas is off-screen, and after 30s idle in the hero; resume on interaction or scroll.

---

## 7. Performance budget and fallbacks

**Targets (desktop, production build, mid-range laptop):** LCP under 2.5s, CLS 0, INP under 200ms, Lighthouse Performance 90+, Accessibility 95+, SEO 95+.

- 3D code is a separate lazy chunk, target under 250 KB gzipped, loaded only after first paint (`requestIdleCallback` or after hero copy is painted).
- Canvas: `dpr={[1, 1.5]}`, `frameloop="demand"` when static, `antialias` on, no shadow maps (use a baked/fake contact shadow), triangle count under 50k, instanced nodes, no per-frame allocations.
- Use `PerformanceMonitor` to lower DPR and node count on slow frames.
- **Fallback tiers:**
  1. Full scene: desktop >= 1024px, WebGL available, no reduced motion, no `saveData`.
  2. Reduced scene: 768-1023px, fewer nodes, no pinned scroll.
  3. Static poster (themed SVG/AVIF, pre-sized to avoid CLS): mobile < 768px, reduced motion, `saveData`, WebGL unavailable, or context lost.
- Handle `webglcontextlost`/error boundary: swap to the poster without breaking the page.
- Poster is also the initial paint placeholder for the hero (so LCP is the poster, not the canvas).
- Fonts self-hosted, `font-display: swap`, preload only the primary weight.

---

## 8. Accessibility

Inherit `Design.md` section 4 in full, plus:

- The 3D canvas is decorative: `aria-hidden="true"` and `role="presentation"`, with all real content available as normal text in the DOM.
- Scroll storytelling has a full plain-text equivalent; no information exists only inside the canvas.
- Page has one `h1`, logical heading order, landmarks (`header`, `nav`, `main`, `section` with `aria-labelledby`, `footer`), and a **Skip to content** link.
- All CTAs are real links/buttons with clear names; icon-only controls have labels and tooltips.
- Sample severity always uses icon + text + tint.
- Tab pattern for the feature showcase follows ARIA tablist with arrow keys.
- Contrast: verify every text pair on both themes and on top of the scene well; overlay labels in the scene use a solid `--surface-raised` chip with `--text-primary`, never text on the raw 3D render.

---

## 9. Routing and integration constraints

- Do not modify authentication, guards, roles, tenancy or API behavior.
- The landing page lives at `/` for logged-out visitors. Preserve whatever the current logged-in behavior at `/` is (do not add or remove redirects unless the existing behavior is already "logged-out shows something else"). If the current `/` behavior conflicts, add the landing page at `/welcome` (or `/landing`) and report the decision instead of changing routing logic.
- All CTAs link to **existing** routes only (login/app entry). Verify each link resolves.
- Landing code lives in its own feature folder (for example `landing/` or `features/landing/`) and reuses shared primitives and tokens from the app. No landing-only color values outside the scene tokens.

---

## 10. SEO and metadata

- Descriptive `<title>` and meta description based on the real product; Open Graph and Twitter tags with a static themed OG image (generate one; do not use stock imagery).
- Semantic HTML, meaningful link text, `lang` attribute, canonical URL if the framework supports it.
- Optional `SoftwareApplication` JSON-LD with only truthful fields.

---

## 11. Definition of done

- [ ] Landing page renders in light and dark, follows the global toggle and persistence, no flash
- [ ] Non-3D page is fully complete and usable on its own (progressive enhancement)
- [ ] 3D hero and pipeline work on desktop with no console errors; theme switch updates scene colors without remounting
- [ ] All three fallback tiers verified (full, reduced, poster) including reduced-motion, WebGL disabled and context loss
- [ ] Performance targets and 3D chunk budget met; no third-party network requests
- [ ] No invented claims, logos, numbers or testimonials; sample data labeled
- [ ] Sample analysis works client-side only and is keyboard accessible
- [ ] Contrast, focus, keyboard, screen reader and skip-link checks pass
- [ ] Responsive at 1440, 1280, 1024, 768, 390
- [ ] Every CTA and link resolves to an existing route; auth and app routes unchanged
- [ ] Build, lint, type-check and tests pass; no unused dependencies added
