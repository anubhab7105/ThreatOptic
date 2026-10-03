# Design.md: Neumorphic SOC Interface (Cool Slate + Indigo)

> Single source of truth for the frontend redesign. If this file and any other instruction conflict, this file wins for visual decisions. Backend, routes, API contracts, auth, roles, tenancy, WebSockets and business logic are **out of scope and must not change**.

---

## 1. Design intent

**Feel:** tactile, calm, structured, professional, security-focused, information-dense.
**Style decision:** full, consistent neumorphism on every surface, with the accessibility safeguards in section 4 to keep a dense SOC tool usable.

**Never use:** glassmorphism, neon glow, heavy gradients, large blur layers, decorative 3D, oversized floating cards, pill-shaped everything, decorative animation.

### Three surface treatments (the only ones allowed)

| Treatment | Meaning | Used for |
|---|---|---|
| **Raised** | Can be acted on or is a primary container | Buttons, cards/panels, sidebar, header, tabs (inactive), toggles |
| **Inset** | Holds input or content that is entered/scanned | Inputs, selects, textareas, filter bars, table wells, code/log blocks, graph canvas, selected tab track |
| **Flat** | Structure only | Rows inside tables, dividers, nested content, text blocks |

### Hard rules

1. **Max two shadow layers per element** (one dark, one light). Never stack extra shadows.
2. **Max nesting depth of 2:** raised surface > inset well > flat content. A raised element must never sit inside another raised element.
3. Do not put a card around every small data element. Group into larger analytical surfaces.
4. Shadows never carry meaning alone. State is always also shown by text, icon, shape, or border.
5. All colors come from tokens. No hex/rgb in components.

---

## 2. Design tokens

Implement as CSS custom properties on `:root[data-theme="light"]` and `:root[data-theme="dark"]`. Components reference only semantic tokens.

### 2.1 Color tokens

| Token | Light | Dark |
|---|---|---|
| `--bg` (page background) | `#E4E9F1` | `#171C28` |
| `--surface` (base of all neumorphic surfaces) | `#E4E9F1` | `#1B2130` |
| `--surface-raised` | `#E9EEF6` | `#202738` |
| `--surface-inset` | `#DDE3ED` | `#131824` |
| `--text-primary` | `#1B2333` | `#E6EAF3` |
| `--text-secondary` | `#46536B` | `#A9B3C7` |
| `--text-muted` | `#56637A` | `#8792A8` |
| `--text-on-accent` | `#FFFFFF` | `#0F1220` |
| `--border-subtle` | `rgba(27,35,51,0.14)` | `rgba(230,234,243,0.12)` |
| `--border-strong` | `rgba(27,35,51,0.50)` | `rgba(230,234,243,0.40)` |
| `--accent-primary` (indigo) | `#4F46E5` | `#818CF8` |
| `--accent-primary-hover` | `#4338CA` | `#A5B4FC` |
| `--accent-secondary` (violet) | `#6D28D9` | `#A78BFA` |
| `--accent-info` (sky) | `#0369A1` | `#38BDF8` |
| `--risk-critical` | `#B91C1C` | `#F87171` |
| `--risk-high` | `#C2410C` | `#FB923C` |
| `--risk-medium` | `#A16207` | `#FACC15` |
| `--risk-low` | `#15803D` | `#4ADE80` |
| `--success` | `#15803D` | `#4ADE80` |
| `--warning` | `#A16207` | `#FACC15` |
| `--danger` | `#B91C1C` | `#F87171` |
| `--focus-ring` | `#4F46E5` | `#A5B4FC` |

Tinted fills for badges/alerts: `color-mix(in srgb, var(--risk-x) 14%, var(--surface))`.

Chart palette (`--chart-1` to `--chart-6`): indigo, sky, violet, teal (`#0F766E` light / `#2DD4BF` dark), amber, rose. Charts must read these via CSS variables and re-render on theme change.

> Verify every text/background pair with a contrast checker. Target: body text 4.5:1 minimum, large text and UI boundaries 3:1 minimum. Adjust token values, not components, if any pair fails.

### 2.2 Shadow tokens

| Token | Light | Dark |
|---|---|---|
| `--sh-light` | `rgba(255,255,255,0.85)` | `rgba(70,82,110,0.28)` |
| `--sh-dark` | `rgba(160,172,194,0.60)` | `rgba(5,8,15,0.65)` |

```css
--shadow-raised-sm: 3px 3px 6px var(--sh-dark), -3px -3px 6px var(--sh-light);
--shadow-raised-md: 5px 5px 10px var(--sh-dark), -5px -5px 10px var(--sh-light);
--shadow-raised-lg: 8px 8px 16px var(--sh-dark), -8px -8px 16px var(--sh-light);
--shadow-inset-sm:  inset 2px 2px 4px var(--sh-dark), inset -2px -2px 4px var(--sh-light);
--shadow-inset-md:  inset 4px 4px 8px var(--sh-dark), inset -4px -4px 8px var(--sh-light);
```

Usage: `raised-sm` for buttons/toggles/tabs, `raised-md` for cards/panels/header, `raised-lg` for modals and drawers only, `inset-sm` for pressed states and small controls, `inset-md` for inputs, filter bars, table wells and canvases.

### 2.3 Shape, spacing, type, motion

- **Radius:** `--r-sm 8px`, `--r-md 12px`, `--r-lg 16px`. Buttons and inputs use `--r-md`. Full pills only for status dots.
- **Spacing:** 4px base (4, 8, 12, 16, 24, 32, 48). Dense tables use 8/12.
- **Type:** UI font Inter (system fallback). Monospace (JetBrains Mono, fallback ui-monospace) for headers, IPs, hashes, message IDs, raw logs. Scale: 12, 13, 14 (body), 16, 20, 24, 32. Tabular numbers on KPIs and tables.
- **Motion:** 140ms ease-out, only on `box-shadow`, `background-color`, `color`, `border-color`, `transform` (max 1px). No decorative or looping animation. Skeleton shimmer allowed, replaced by static placeholder under reduced motion.
- **Z-layers:** base 0, sticky header 10, drawer 30, modal 40, toast 50.

---

## 3. Theme system

- Apply `data-theme="light|dark"` on `<html>` and set `color-scheme` accordingly.
- Resolution order: stored preference (`localStorage`, key `theme`) then `prefers-color-scheme` then light.
- Inline pre-hydration script in the document head sets the attribute before first paint (no flash of wrong theme).
- Listen to `matchMedia` changes only while no stored preference exists.
- Toggle lives in the global header (visible on every route and mobile drawer), is a real `<button>` with `aria-pressed`, an icon plus visible or tooltip label, and does not reload the page.
- Theme provider exposes `theme` and `setTheme`. Components must not re-render for theme changes unless they read theme values in JS (charts, map, graph canvas only).
- Third-party surfaces (charts, map tiles, graph canvas, PDF preview, date pickers, scrollbars, `<select>` popups) must be themed via tokens or their theme APIs.

---

## 4. Accessibility safeguards for full neumorphism

Neumorphic boundaries are low-contrast by nature. These rules are mandatory:

1. **Every interactive control** (button, input, select, textarea, tab, toggle, checkbox) gets a `1px solid var(--border-subtle)` in addition to its shadow.
2. **Focus:** `outline: 2px solid var(--focus-ring); outline-offset: 2px` on `:focus-visible`, plus keep shadow. Never remove outlines.
3. **Table rows** are separated by hairline dividers (`--border-subtle`), not shadows. Row hover uses a background tint and a left accent marker.
4. **Severity and status** always combine an icon (distinct shape per level) + text label + tint. Never color alone. Badge text uses `--text-primary`, not the risk color.
5. `@media (prefers-contrast: more)`: raise borders to `--border-strong` and drop shadows to none.
6. `@media (forced-colors: active)`: rely on system colors and borders.
7. `@media (prefers-reduced-motion: reduce)`: disable transitions and shimmer.
8. Minimum hit target 40x40px (44px on touch). Icon-only controls require `aria-label` and a tooltip.
9. Semantic HTML: `header`, `nav`, `main`, `section`, `table`, `dialog`, correct heading order, `aria-live` for toasts and loading results, `role="tablist"` pattern for tabs with arrow-key navigation.

---

## 5. Component specifications

### 5.1 Interaction states (all interactive components)

| State | Treatment |
|---|---|
| Default | Raised-sm (or inset for inputs) + 1px border |
| Hover | Background shifts to `--surface-raised`, shadow may grow one step, cursor pointer |
| Pressed | `--shadow-inset-sm`, `transform: translateY(1px)` |
| Active / selected | Inset + accent-primary text/icon + 2px accent indicator (bar or underline) + `aria-current`/`aria-selected` |
| Focus | Focus ring (section 4) |
| Disabled | 50% opacity, no shadow, `not-allowed`, `aria-disabled`, still readable |
| Loading | Spinner (or skeleton) inside the control, keep width, `aria-busy="true"`, block repeat clicks |

### 5.2 Components

- **Button:** variants Primary (accent-primary fill, `--text-on-accent`, raised), Secondary (raised surface), Ghost (flat, border on hover), Destructive (danger text + icon, separated from routine actions, requires confirm dialog). Sizes sm 32, md 40, lg 48.
- **Inputs / select / textarea:** inset-md, `--r-md`, label always visible above (no placeholder-only), helper and error text below with icon, error uses `--danger` border + message.
- **Card / panel:** raised-md, optional header row with title, description and actions, inner content sits on inset wells or flat.
- **Table:** inset well container; sticky header row (flat, uppercase 12px muted); flat rows with hairlines; sortable headers with icon and `aria-sort`; horizontal scroll container on small screens; empty state inside the well.
- **Tabs:** inactive tabs raised-sm on an inset track; selected tab inset with accent indicator; keyboard arrows; on mobile become horizontally scrollable, not wrapped.
- **Modal / dialog:** raised-lg, backdrop is a flat 50% scrim (no blur), focus trapped, Esc closes, returns focus to trigger.
- **Drawer:** raised-lg, same rules as modal, used for sidebar under 768px.
- **Badge / status:** small radius (`--r-sm`), tinted fill + icon + label. Severity icons: Critical (octagon-alert), High (triangle-alert), Medium (circle-alert), Low (shield-check). Status dot only as a supplement.
- **Toast / alert:** raised-md, left accent bar + icon + text, `role="status"` (or `alert` for errors), auto-dismiss except errors.
- **Loading:** skeletons in inset wells matching final layout; global spinner component reused everywhere; no layout shift.
- **Empty state:** icon, one-line explanation, one primary action.
- **Error state:** icon, plain message, technical detail collapsible, Retry button.
- **Tooltip:** flat dark/light inverted surface, appears on hover and focus, `aria-describedby`.
- **Toggle / checkbox / radio / segmented control:** inset track, raised thumb, with text or icon state label.

---

## 6. Layout system

### Breakpoints

| Name | Width | Behavior |
|---|---|---|
| Desktop | >= 1280 | Full sidebar (248px), multi-column workspaces |
| Laptop | 1024-1279 | Collapsed icon rail (72px) with tooltips, 2-column max |
| Tablet | 768-1023 | Rail hidden behind drawer, single main column, collapsible secondary panels |
| Mobile | < 768 | Drawer nav, single column, master-detail becomes sequential, tables scroll horizontally or use stacked rows |

### App shell

- **Header** (sticky, raised-md): breadcrumb/page title, global search if it exists, tenant/user menu, theme toggle, notifications if they exist.
- **Sidebar** (raised-md): existing routes only, active item inset with accent indicator, icon + label, collapse control.
- **Content:** max-width 1440px, 24px padding desktop, 16px mobile, 24px vertical rhythm between sections.

---

## 7. Page specifications

### 7.1 `/dashboard`

Order top to bottom:

1. Global header.
2. **Compact KPI strip:** one raised panel containing 4-6 metrics separated by hairlines (value, label, delta with icon). No per-metric cards.
3. **Ingestion workspace (primary action area):** largest panel. Source choices (upload, paste, mailbox/Gmail live import) as a segmented control, the active method's form below in an inset well, clear primary "Analyze" action, progress and result feedback inline.
4. **Threat analytics:** one raised panel with 2-3 charts (severity distribution, trend, top categories) sharing one header and time-range control.
5. **Recent threats table:** inset well, severity filter as one inset segmented filter bar (All / Critical / High / Medium / Low with counts, icon + label), search, sortable columns, row opens Email Analysis.
6. **Activity / secondary:** collapsible panel on tablet and mobile.

### 7.2 Email Analysis (keep five tabs)

Tabs: Summary, Why this score?, Header Forensics, GeoLocation, Graph View.

- **Case header (raised panel):** subject (truncate with tooltip), sender, classification, fraud score (numeric + gauge with text), severity badge, timestamp, primary action (e.g. create/open case) plus overflow for export (PDF/JSON).
- **Tab workspace:** dominant area below the header. Content sits on one inset well per tab, using flat sections and dividers inside, not nested cards.
- **Summary:** verdict and key indicators first, then supporting evidence in a two-column definition layout.
- **Why this score?:** ranked contributing factors as a flat list with horizontal contribution bars and text weights.
- **Header Forensics:** monospace, two-pane (parsed fields / raw headers), hop chain as a vertical timeline, copy buttons, syntax emphasis by weight and icon, not just color.
- **GeoLocation:** map/origin first (origin, country, ASN, hop path), secondary evidence (reputation, related indicators) collapsed below. Map themed per theme.
- **Graph View:** canvas fills the workspace inside an inset well, compact toolbar (zoom, fit, filter, layout, legend) as icon buttons with tooltips, node detail in a side panel on desktop and bottom sheet on mobile.

### 7.3 `/cases`

- **Desktop/laptop:** master-detail. Left: grouped search + filters (status, severity, assignee) and investigation list (selected item inset with accent marker). Right: selected investigation detail with timeline/notes/linked emails.
- **Tablet:** list with detail as a slide-over panel.
- **Mobile:** list then detail as sequential navigation with a Back control.
- **Admin destructive actions** (delete, purge) live in a separate "Danger zone" section at the bottom of detail, visually distinct (danger icon + text + border), confirmation dialog required.

### 7.4 `/mailboxes`

Connection-management workspace. One row/panel per provider containing:

- Provider name and icon
- Connection status (Connected / Disconnected / Error / Syncing) with icon + text
- Last sync (relative time with absolute in tooltip)
- Polling state (On/Off with interval)
- Actions: Sync now (primary small), Configure, Disconnect (destructive, confirm)

Add-connection area is a clear panel at top or an empty state. Errors show inline with Retry.

### 7.5 Model Info

Sections in this order, each a single raised panel with inset content:

1. **Summary metrics** (accuracy, precision, recall, F1, AUC as a compact strip).
2. **Per-class metrics** (table with inline bars, text values).
3. **Confusion matrix** (heatmap with numeric values in each cell, tokenized sequential scale, axis labels, works in both themes, readable without color).
4. **Dataset / support information** (support counts, split, version, training date).

### 7.6 Gmail Live Import

- Preserve existing automatic OAuth-code handling. **Do not add a visible auth-code field.**
- Compact stepper: **Waiting > Connecting > Connected / Error**, each step with icon + label, `aria-live="polite"` announcements, current step highlighted with inset + accent.
- Uses the global spinner, alert and error components. Error offers Retry.

---

## 8. Data visualization rules

- All colors from `--chart-*` and risk tokens; no hardcoded series colors.
- Grid lines and axes use `--border-subtle` and `--text-muted`.
- Tooltips use the tooltip component style.
- Every chart has a text alternative (`aria-label` or an accessible data table toggle).
- Series distinguished by more than hue (marker shape, dash pattern, direct labels) where there are 3 or more series.
- Charts re-render on theme change and never keep old-theme colors.

---

## 9. Performance rules

- CSS variables only; theme switch changes one attribute.
- No `backdrop-filter`, no large blur layers, no animated shadows on lists, no looping decorative animation.
- Table rows and list items must not use shadows (avoids paint cost on long lists).
- Avoid theme-driven re-renders beyond charts, map and graph canvas.

---

## 10. Cleanup checklist

- Remove obsolete theme classes and old palette values once nothing references them.
- Remove duplicated styling and consolidate repeated components into shared primitives.
- Remove dead components only after confirming they are unused (search for imports and dynamic usage).
- Grep for leftover hardcoded hex/rgb/hsl values and inline color styles; every remaining one needs a reason.

---

## 11. Preservation contract (do not change)

Routes, API calls and contracts, authentication, role permissions, tenant isolation, WebSocket behavior, email ingestion, analysis, threat scoring, header forensics, threat intelligence, GeoLocation, graph functionality, case management, mailbox OAuth, Gmail live import, model metrics, PDF/JSON report generation, business logic.

---

## 12. Definition of done

- [ ] Both themes fully implemented, persist, follow system default, no reload, no flash
- [ ] Zero hardcoded colors in components; tokens only
- [ ] Every interactive component has all seven states
- [ ] Contrast targets met in both themes (section 2.1)
- [ ] Keyboard-only navigation works on every route; focus always visible
- [ ] Reduced-motion, high-contrast and forced-colors handled
- [ ] Layouts verified at 1440, 1280, 1024, 768, 390 widths
- [ ] Charts, map, graph, tables, modals, inputs themed in both modes
- [ ] Loading, empty, error, success states exist for every data view
- [ ] Build, lint and existing tests pass; no console errors
- [ ] Manual regression pass on every route shows no functional change
