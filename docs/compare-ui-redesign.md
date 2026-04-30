# Compare UI uplift — Phase 2 visual language design

**Status:** Phase 2 of the visual uplift workplan
**Date:** 2026-05-01
**Predecessor:** [docs/compare-ui-audit.md](compare-ui-audit.md)
**Architecture given:** [docs/adr/0008-compare-runs-architecture.md](adr/0008-compare-runs-architecture.md)
**Phase 1 defaults adopted:** Q1=B (single total-findings sparkline strip, lazy-loaded, hidden when cross-SBOM); Q2=three stacked big numbers (preserves PB-1, no scalar); Q3=defer Tabs 2+3; Q4=memory-only hover card (no fetch on hover); Q5=strict copy templates.

---

## TL;DR

Five themes, all presentational, no backend touch:

1. **Hero delta** — Region 2 becomes the page's headline. Adaptive headline + sub-line, three big stacked numbers, promoted distribution bar (28px), three smaller tiles below.
2. **Sparklines** — single 240×24 strip above the tiles, total_findings over the last 30 runs of the shared SBOM. Hidden when cross-SBOM or <2 historical runs.
3. **IdenticalRunsCard** — collapses Region 2 into a celebratory card when added+resolved+severity_changed === 0. Treats the most-common production case as the headline, not an edge case.
4. **Findings row v2** — severity gradient on the left edge, second-line attribution with version-arrow viz, KEV + EPSS chips, hover card on CVE id sourced from in-memory CVE cache only.
5. **Adaptive tabs + filter chips** — activity dots on tabs, dim-when-zero on chips, clear-all button, "showing X of Y" line.

Every change preserves URL state, keyboard shortcuts, and the IA from ADR-0008.

---

## 1. Theme 1 — Hero delta (Region 2 redesign)

### 1.1 Wireframe (1440px desktop)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  POSTURE DELTA                                                               │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                                                                        │  │
│  │  Net safer: -19 resolved vs +8 added.                                  │  │
│  │  Same SBOM, re-scanned 11 hours later — feed-only changes possible.    │  │
│  │                                                                        │  │
│  │  ┌──────────────┐  ┌────────────────────────────────────────────────┐  │  │
│  │  │              │  │ ████░░░░░░░░░░░░░░░░░░░░░░░░░████ ░░ ███████   │  │  │
│  │  │     8        │  │ +8                              -19   3 sev    │  │  │
│  │  │   ─────      │  │                                                │  │  │
│  │  │   added      │  │ Distribution: added │ severity-changed │       │  │  │
│  │  │              │  │ unchanged │ resolved                           │  │  │
│  │  │     19       │  └────────────────────────────────────────────────┘  │  │
│  │  │   ─────      │                                                       │  │
│  │  │   resolved   │                                                       │  │
│  │  │              │                                                       │  │
│  │  │     3        │                                                       │  │
│  │  │   ─────      │                                                       │  │
│  │  │   severity   │                                                       │  │
│  │  │              │                                                       │  │
│  │  └──────────────┘                                                       │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ─────────────────  total findings, last 30 runs ──────────────────  373    │  │
│       ▁▁▂▂▂▃▃▃▄▄▄▄▅▅▅▆▆▆▇▇▇▇█████ ●  (current)                              │  │
│                                                                              │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────────────┐            │
│  │ KEV exposure │  │ Fix-available    │  │ High+Critical        │            │
│  │  2 → 1  ▼-1  │  │  60% → 80%  ▲+20pp│  │  12 → 8  ▼-4         │            │
│  └──────────────┘  └──────────────────┘  └──────────────────────┘            │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Component layout grid (desktop ≥1024px)

```
┌──────── PostureHero ────────────────────────────────────────────────────────┐
│  HeroHeadline             — full width, single line, text-(--hero-headline) │
│  HeroSubline              — full width, italic, text-sm                     │
│                                                                             │
│  ┌── BigNumbersColumn ─┐  ┌── DistributionBarLarge ────────────────────┐    │
│  │ 30% width            │  │ 70% width                                 │    │
│  │ flex-col gap-3       │  │ h-(--distribution-bar-height)             │    │
│  │ [+8 added]           │  │                                           │    │
│  │ [-19 resolved]       │  │                                           │    │
│  │ [3 severity]         │  │                                           │    │
│  └─────────────────────┘  └───────────────────────────────────────────┘    │
│                                                                             │
│  Sparkline strip          — 1 row, full width, h-6                          │
│                                                                             │
│  ┌── PostureTiles (3 col grid) ──────────────────────────────────────┐      │
│  │ KEV │ Fix-available │ High+Critical                               │      │
│  └──────────────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.3 Mobile (≤640px) layout

```
┌── PostureHero (mobile) ──────────┐
│  HeroHeadline (text-xl, wraps)   │
│  HeroSubline (text-xs, italic)   │
│                                  │
│  ┌── BigNumbers (inline pills) ─┐│
│  │ +8 added · -19 resolved · 3   ││
│  │ severity                      ││
│  └──────────────────────────────┘│
│                                  │
│  DistributionBarLarge (h-7)      │
│                                  │
│  Sparkline (smaller, h-5)        │
│                                  │
│  PostureTile #1 (full width)     │
│  PostureTile #2 (full width)     │
│  PostureTile #3 (full width)     │
└──────────────────────────────────┘
```

Total mobile hero height target: **<320px** (per prompt success criteria). Achieved via collapse to inline pills + tile stacking.

### 1.4 Big numbers color & weight rules

Each of the three numbers (`added`, `resolved`, `severity_changed`) follows:

| State | Numeral size | Color | Label |
|---|---|---|---|
| Value > 0, "added" | `var(--hero-bignumber-size)` bold | `text-red-700` (light) / `text-red-300` (dark) | "added" beneath, `text-xs uppercase tracking-wider` |
| Value > 0, "resolved" | same | `text-emerald-700` / `text-emerald-300` | "resolved" beneath |
| Value > 0, "severity-changed" | same | `text-amber-700` / `text-amber-300` | "severity changed" beneath |
| Value = 0 | `text-3xl` muted (recede) | `text-hcl-muted` | label muted too |

The "value = 0 recedes" rule is the key adaptive behaviour — when nothing was added, the "0 / added" pair fades back to make the resolved or severity-changed numbers dominate visually.

### 1.5 Adaptive headline copy table (Q5 strict templates)

Driven by [components/compare/HeroHeadline/headlineRules.ts](../frontend/src/components/compare/HeroHeadline/headlineRules.ts) — pure function, exhaustive case match.

Inputs (from `PostureDelta`):
- `added = findings_added_count`
- `resolved = findings_resolved_count`
- `sev = findings_severity_changed_count`
- `unchanged = findings_unchanged_count`

| State (predicate) | Headline | Tone |
|---|---|---|
| `added === 0 && resolved === 0 && sev === 0 && unchanged === 0` | "No vulnerabilities in either run." | neutral (muted) |
| `added === 0 && resolved === 0 && sev === 0 && unchanged > 0` | (Theme 3 path — IdenticalRunsCard renders instead) | — |
| `added > 0 && resolved === 0 && sev === 0` | "+{added} new findings. Nothing resolved." | red |
| `added === 0 && resolved > 0 && sev === 0` | "−{resolved} findings resolved. No new exposure." | green |
| `added === 0 && resolved === 0 && sev > 0` | "{sev} finding{s?} reclassified. No additions or removals." | amber |
| `added > 0 && resolved > 0 && resolved > added` | "Net safer: −{resolved} resolved vs +{added} added." | green |
| `added > 0 && resolved > 0 && added > resolved` | "Net worse: +{added} new vs −{resolved} resolved." | red |
| `added > 0 && resolved > 0 && added === resolved` | "Mixed: +{added} new, −{resolved} resolved." | amber |
| any with `sev > 0` (combined with above) | (append) " Plus {sev} severity reclassification{s?}." | suffix |

Tone drives the headline's text color via the existing severity color palette:
- red: `text-red-700` (light) / `text-red-300` (dark)
- green: `text-emerald-700` / `text-emerald-300`
- amber: `text-amber-700` / `text-amber-300`
- neutral: `text-hcl-navy`

### 1.6 Sub-line copy (RelationshipDescriptor — promoted)

The existing `<RelationshipDescriptor />` text already does this work; in the hero it just renders italic, one line, beneath the headline:

| Relationship state | Sub-line copy |
|---|---|
| `same_sbom: true`, days_between < 1/24 | "Same SBOM, re-scanned <1h apart — feed-only changes possible." |
| `same_sbom: true`, days_between < 1 | "Same SBOM, re-scanned {hours}h later — feed-only changes possible." |
| `same_sbom: true`, days_between ≥ 1 | "Same SBOM, re-scanned {days} days later — feed-only changes possible." |
| `same_project: true`, `same_sbom: false` | "Different SBOMs of project {project_name}, {days_between} days apart." |
| `same_project: false` | "Cross-project compare: {project_a} → {project_b}." |
| `direction_warning != null` | "⚠ {direction_warning}" — clickable to swap |

The "feed-only changes possible" framing is the highest-information piece of copy on the page. It tells the user that since the SBOM is identical, the entire delta (or non-delta) is attributable to the vulnerability feed, not the codebase. This is now front-and-center, not a buried grey line.

### 1.7 Posture tiles — reduced visual weight

Tiles stay (PB-1: three independently-defensible deltas). Visual changes only:

| Property | Was | Now | Rationale |
|---|---|---|---|
| Outer padding | `p-4` (16px) | `p-3` (12px) | tighter |
| Title size | `text-[10px]` | `text-[10px]` | unchanged |
| Value size | `text-2xl` (24px) | `text-xl` (20px) | recede ~17% |
| Delta size | `text-sm` (14px) | `text-xs` (12px) | recede ~14% |
| Border | none | `border border-border-subtle` | gives them a frame so they read as "context" |
| Surface variant | `elevated` (shadow) | `solid` (border only) | flatter |

Net effect: the eye lands on the headline + big numbers + distribution bar first. The tiles are clearly *context*, not *headline*.

---

## 2. Theme 2 — Sparkline strip

### 2.1 Wireframe

```
─────────────────────  TOTAL FINDINGS, LAST 30 RUNS ─────────────────────  373
       ▁▁▂▂▂▃▃▃▄▄▄▄▅▅▅▆▆▆▇▇▇▇█████ ●
```

A single horizontal strip rendered between `BigNumbers + DistributionBar` and `PostureTiles`. **One sparkline per page, not per tile.** Per-tile sparklines were rejected in Phase 1 §6 because the data isn't available without backend changes (only `total_findings` is exposed historically; KEV / fix-available / high+critical histories are not).

### 2.2 Component spec

`<Sparkline />`:
- 240px wide × 24px tall (desktop), 200×20 (mobile)
- Raw SVG `<path>`, `stroke-width: 1.5`, `stroke-linecap: round`, `fill: none`
- Stroke color: `var(--color-hcl-blue)` at 80% opacity for past, full opacity for the current run point
- Current-run marker: 3px filled circle at the rightmost data point, tinted by hero tone (red if net-worse, green if net-safer, neutral if no change)

### 2.3 Data source

[components/compare/Sparkline/Sparkline.tsx](../frontend/src/components/compare/Sparkline/Sparkline.tsx) accepts:

```ts
interface Props {
  sbomId: number | null;       // when null, returns null (no render)
  currentRunId: number;
  fallbackTotal?: number;      // shown as the right-side number while loading
}
```

Internal: `useQuery({ queryKey: ['compare', 'sparkline', sbomId], queryFn: () => fetch(\`/api/runs?sbom_id=${sbomId}&page_size=30\`) })`.

Uses the existing list endpoint (already present in [app/routers/runs.py:65](../app/routers/runs.py#L65)). **No new backend.**

The list response is `AnalysisRunOut[]`, which carries `total_findings`. The component:

1. Sorts ascending by `id`.
2. Filters to `run_status ∈ {OK, FINDINGS, PARTIAL}` (skip ERROR / RUNNING).
3. If <2 points remain, renders nothing. Returns `null`.
4. Otherwise generates an SVG path normalising `total_findings` into the y-domain.

### 2.4 Hide rules

| Condition | Render |
|---|---|
| `relationship.same_sbom === false` | nothing — different SBOM histories don't share a meaningful series |
| <2 historical runs of the SBOM | nothing |
| Network failure on the secondary fetch | nothing — fail silently, don't block the hero |

The strip is **not on the critical path of the hero**. `<PostureHero />` renders first and the sparkline lazy-loads via `next/dynamic` so it doesn't add to LCP.

---

## 3. Theme 3 — IdenticalRunsCard

### 3.1 Trigger

```ts
function isIdenticalRuns(p: PostureDelta): boolean {
  return (
    p.findings_added_count === 0 &&
    p.findings_resolved_count === 0 &&
    p.findings_severity_changed_count === 0
  );
}
```

When true, `<CompareView />` renders `<IdenticalRunsCard />` in place of `<PostureHero />`. The Findings / Components / Posture-detail tabs remain accessible and functional below it (the user can still drill into the unchanged set), but the hero region is replaced entirely.

### 3.2 Wireframe — has unchanged findings

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│      ✓                                                                   │
│      No changes detected.                                                │
│                                                                          │
│      Both runs share 373 findings; none added, resolved, or              │
│      reclassified.                                                       │
│                                                                          │
│      Same SBOM re-scanned 11 hours apart — confirms vulnerability        │
│      feed was stable in this window.                                     │
│                                                                          │
│      [View shared findings (373) →]                                      │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Wireframe — both runs are clean (zero findings on each side)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│      ✓                                                                   │
│      No vulnerabilities in either run.                                   │
│                                                                          │
│      Both Run #{a} and Run #{b} produced clean scans.                    │
│                                                                          │
│      Same SBOM re-scanned 11 hours apart — confirms posture is stable.   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3.4 Wireframe — cross-SBOM identical-zero (rare)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│      ✓                                                                   │
│      Different SBOMs, no overlapping vulnerabilities.                    │
│                                                                          │
│      Run A and Run B do not share any findings.                          │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3.5 Component spec

```tsx
interface Props {
  result: CompareResult;
  onViewSharedFindings: () => void;   // sets ?tab=findings&show_unchanged=true
}
```

Uses existing primitives: `Surface variant="gradient"`, `Button variant="secondary"`, `<Check />` icon from `lucide-react`.

The check icon is at `text-4xl` (40px), `text-emerald-600` — high-saturation green earns this much real estate because the celebratory state is so common in production.

### 3.6 CTA wiring

`onViewSharedFindings()` calls `urlState.setTab('findings')` AND `urlState.setShowUnchanged(true)`. The compose-two-mutations pattern uses a small new helper:

```ts
// hooks/useCompareUrlState.ts — append
const showSharedFindings = useCallback(
  () => writeParams((p) => {
    p.delete('tab');               // tab=findings is the default → omit
    p.set('show_unchanged', 'true');
  }, 'push'),
  [writeParams],
);
```

History semantics: this is a navigation action so it pushes (consistent with `setTab`).

---

## 4. Theme 4 — Findings row v2 (Tab 1 only)

### 4.1 Wireframe

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ ▌+NEW│  CVE-2024-12345  HIGH  🔥KEV  EPSS 87%   pyyaml@6.0.1                │
│ ▌    │  ↳ introduced by upgrade pyyaml 5.4.0 → 6.0.1                        │
└──────────────────────────────────────────────────────────────────────────────┘
   ▲ severity gradient (3px solid + 60px linear-fade to transparent)
```

### 4.2 Per-row dimensions

| Element | Value |
|---|---|
| Row height | 72px (was 52px); `py-2.5` becomes effectively two-line |
| Severity gradient strip | 3px solid border-l in severity color + linear-gradient fade to transparent over 60px from the left edge |
| Change-kind chip | unchanged from v1 |
| CVE id | `font-mono text-xs` + hover-card affordance (Theme 4 §4.4) |
| Severity badge | unchanged; for severity_changed, `BadgeA → BadgeB` |
| KEV chip | unchanged from v1 |
| EPSS chip | NEW: shown when `epss_percentile_current ≥ 0.5` (50th percentile). `border-amber-300 bg-amber-50 text-amber-900 px-1.5 py-0.5` "EPSS {pct}%" |
| Component name | `text-sm text-hcl-navy` |
| Second line | `text-[11px] italic text-hcl-muted` with embedded version-arrow visualisation |

### 4.3 Severity gradient component

```tsx
// SeverityGradient.tsx
function SeverityGradient({ severity }: { severity: 'critical'|'high'|'medium'|'low'|'unknown' }) {
  const stop = `var(--severity-${severity}-fade)`;
  return (
    <div
      aria-hidden
      className="absolute inset-y-0 left-0 w-[60px] pointer-events-none"
      style={{
        background: `linear-gradient(to right, ${stop} 0%, transparent 100%)`,
      }}
    />
  );
}
```

The 3px solid border-l is unchanged — it stays as the change_kind indicator. The gradient is *additive* and uses severity (not change_kind), so a critical finding looks more aggressive than a low finding even when they're both `+ NEW`.

### 4.4 CVE hover card

Component: `<CveHoverCard />`, lazy-loaded via `next/dynamic`, 200ms delay before show, 150ms cross-fade.

**Data source — memory only.** The TanStack Query cache for `['cve-detail', cveId]` may already have data from a previous click in this session. The hover card reads `queryClient.getQueryData(['cve-detail', cveId])` and only renders if a hit:

```tsx
const cached = queryClient.getQueryData<CveDetail>(['cve-detail', cveId]);
if (!cached) {
  return <Tooltip>Click to view full advisory</Tooltip>;
}
return (
  <HoverCard>
    <strong>{cached.title}</strong>
    <p>{cached.summary.slice(0, 100)}{cached.summary.length > 100 ? '…' : ''}</p>
    <div className="text-[10px] text-hcl-muted">Click for full advisory →</div>
  </HoverCard>
);
```

**No fetch on hover.** This avoids the firehose of requests from a user scrolling the table. The first time a user clicks a row, the modal fetch populates the cache; the second time they hover the same id (or any id whose cache entry exists), the hover card lights up.

### 4.5 Attribution second line

Component: `<AttributionLine />`. Renders the `attribution` string from the row, with version arrow visualisation:

| Input | Output |
|---|---|
| `"via upgrade pyyaml 5.4.0 → 6.0.1"` | `↳ via upgrade pyyaml 5.4.0 → 6.0.1` (the arrow is rendered as `<span class="text-emerald-600">→</span>` if version goes up, `text-red-600` if down) |
| `"introduced by upgrade pkg 1.0 → 2.0"` | `↳ introduced by upgrade pkg 1.0 → 2.0` |
| `"via new dependency pkg@1.0"` | `↳ via new dependency pkg@1.0` (no arrow) |
| `"via removal of pkg"` | `↳ via removal of pkg` |
| (null / empty) | omitted entirely; row stays single-line |

Single-line rows (when `attribution` is null) keep the v1 52px height — only rows with attribution get the 72px treatment. Average row height in production is somewhere between (most added/resolved rows have attribution; severity_changed rows usually don't).

---

## 5. Theme 5 — Adaptive tabs + filter chips

### 5.1 Tabs

| State | Visual |
|---|---|
| Active tab | `bg-hcl-light text-hcl-navy font-semibold`, count visible |
| Inactive tab with content | `text-hcl-muted hover:bg-surface-muted`, count visible |
| Inactive tab with **zero** items | `text-hcl-muted/50`, count `(0)` greyed |
| Findings tab with **critical or high** added | red dot indicator after the count: `<span class="ml-1.5 inline-block h-1.5 w-1.5 rounded-full bg-red-600">` |
| Findings tab with **high** added (no critical) | amber dot |

Dot indicator priority: critical > high. Only one dot per tab.

### 5.2 Filter chips

| State | Visual |
|---|---|
| Active | unchanged from v1 (severity color fill) |
| Inactive | unchanged (border + muted text) |
| Inactive with **effective count = 0** | `opacity-50`, tooltip: "0 items match this filter in the current diff" |
| Active chip × button | small `<X />` (10px) inside the chip on the right; click removes just that chip, not all |

### 5.3 Clear-all + status line

```
[+ Added (8)]  [- Resolved (19)]  [↕ Severity (3)]  [Clear all]      Showing 27 of 30 findings
[Critical] [High] [Medium] [Low]                                      (filtered)
[🔥 KEV only] [🔧 Fix-available]  [Show unchanged]
```

- **Clear all** button appears when ≥ 1 filter is non-default. Resets all chips to default state. Single button, not per-row.
- **Status line** lives on the right of the chip row, `text-[11px] text-hcl-muted`. Format: `"Showing {visible} of {total} findings"` + optional `(filtered)` suffix when any filter is non-default.

---

## 6. Token spec — additions to globals.css

All new tokens go in [src/app/globals.css](../frontend/src/app/globals.css), at the bottom of the `:root` and `.dark` blocks. **No replacements**, only additions.

```css
:root {
  /* Hero typography (clamp() so we don't add fixed sizes) */
  --hero-headline-size: clamp(1.5rem, 2.5vw, 2.25rem);    /* 24–36px */
  --hero-bignumber-size: clamp(2.5rem, 5vw, 3.75rem);     /* 40–60px */
  --hero-headline-tracking: -0.025em;

  /* Distribution bar (promoted) */
  --distribution-bar-height: 28px;
  --distribution-bar-radius: 999px;

  /* Severity gradient stops — for the row left-border fade (Theme 4 §4.3) */
  --severity-critical-fade: rgba(192, 57, 43, 0.10);
  --severity-high-fade: rgba(212, 104, 10, 0.10);
  --severity-medium-fade: rgba(184, 134, 11, 0.08);
  --severity-low-fade: rgba(0, 103, 177, 0.06);
  --severity-unknown-fade: rgba(107, 122, 141, 0.05);
}

.dark {
  --severity-critical-fade: rgba(248, 113, 113, 0.12);
  --severity-high-fade: rgba(251, 146, 60, 0.10);
  --severity-medium-fade: rgba(251, 191, 36, 0.10);
  --severity-low-fade: rgba(96, 165, 250, 0.08);
  --severity-unknown-fade: rgba(148, 163, 184, 0.06);
}
```

**No new severity colors.** Only fade variants of the existing `severity.*` palette. **No new font-size scale entries** — the `clamp()` tokens are CSS-only and don't pollute the Tailwind type ramp.

---

## 7. Animation timing reference

All durations use existing CSS variables (`--duration-fast`, `--duration-base`, `--duration-slow`, `--duration-slower`).

| Animation | Duration | Easing | Trigger |
|---|---|---|---|
| Headline tone cross-fade | `--duration-base` (200ms) | `--ease-out` | tone change |
| Big-number count-up | `Math.min(value × 30, 800)` ms | `--ease-out` | first mount only |
| Distribution-bar segment width | `--duration-slower` (480ms) | `--ease-out` | data change |
| Sparkline draw-on (stroke-dashoffset) | 600ms (custom) | `--ease-out` | first mount only |
| Hover card reveal | `--duration-fast` (150ms) | `--ease-out` | 200ms delay after hover |
| IdenticalRunsCard mount | `--duration-base` (200ms) | `--ease-spring` | mount |

**Reduced motion** (`@media (prefers-reduced-motion: reduce)`):
- Count-up animations skip — number renders at final value from frame 1
- Cross-fades, draw-ons, segment-width transitions all become 0ms
- The hover card delay stays at 200ms (not motion, but feels nicer)
- The card mount becomes a hard cut

Implemented with the existing `motion-reduce:transition-none motion-reduce:animate-none` pattern.

---

## 8. Accessibility spec

| Concern | Spec |
|---|---|
| Adaptive headline tone change | `<div role="status" aria-live="polite">` wrapping the headline; tone change re-fires aria-live |
| Sparkline | `<title>` element inside the SVG — "Total findings, last 30 runs of {sbom_name}: trending {flat\|up\|down}, current value {n}" |
| Severity gradient | `aria-hidden="true"` — the chip text remains the source of truth |
| Hover card | focusable via Tab; `Enter` opens the full modal; `Esc` closes the card; `role="tooltip"` on the card; `aria-describedby` linking the row to the card |
| Count-up animations | skip on reduced motion; final value rendered immediately; aria-live on the number is silenced during count-up to avoid "8…7…6…5…4…3…2…1" announcements |
| Color is never sole carrier | every red/green delta has an explicit "added"/"resolved" word label; the dot indicator on tabs has an `aria-label` like "1 critical added" |
| Distribution bar | already has `role="img"` + `aria-label` in v1 — preserved; numeric labels are part of the rendered text, not just the aria-label |
| IdenticalRunsCard | `<h2>` for the headline so it sits in the page heading hierarchy |
| Mobile pill collapse | the inline pill version of big numbers uses `aria-label="8 added, 19 resolved, 3 severity-changed"` so screen readers see it as one announcement, not three |

---

## 9. Per-element classification

Every visual element on the page, mapped to its uplift outcome.

### 9.1 Region 1 (Selection bar)

| Element | Outcome |
|---|---|
| Run pickers | **Preserve** verbatim |
| Swap / Share / Export buttons | **Preserve** verbatim |
| RelationshipDescriptor | **Demote** — moves to hero sub-line; the original location keeps a compact 1-line version that's hidden when the hero shows it |

### 9.2 Region 2 (Posture)

| Element | Outcome |
|---|---|
| "POSTURE DELTA" eyebrow | **Replace** — becomes the adaptive `<HeroHeadline />` |
| Distribution bar | **Promote** — h-3 → h-7 (28px), labels inline, segment colors at full saturation |
| Three posture tiles | **Preserve + reduce weight** — smaller padding, smaller numbers, border instead of shadow |
| (new) Big numbers column | **Add** — `<BigNumbersColumn />` with three large semantic-colored numerals |
| (new) Sparkline strip | **Add** — single total-findings strip, lazy-loaded |

### 9.3 Region 3 (Tabs + body)

| Element | Outcome |
|---|---|
| Tab strip | **Adapt** — activity dot indicators, zero-state dimming |
| Filter chip row | **Adapt** — dim-when-zero, clear-all button, status line |
| Findings table | **Replace row component** — `<FindingRowAdvanced />` with severity gradient + 2nd line + hover card |
| Components tab | **Out of scope** (defer per Phase 1 Q3) |
| Posture detail tab | **Out of scope** (defer per Phase 1 Q3) |
| CveDetailDialog (drill-in) | **Preserve** verbatim |
| Empty/loading/error states | **Preserve** structure; copy only updates if existing copy refers to "Risk delta" (it doesn't — already says "Posture") |

### 9.4 Identical-runs case

| Element | Outcome |
|---|---|
| Region 2 (when added+resolved+sev = 0) | **Replace** with `<IdenticalRunsCard />` |
| Tabs + body | **Preserve** — accessible below the card |

---

## 10. Out-of-scope (deferred)

| # | Item | Reason |
|---|---|---|
| F-9 | Per-tile sparklines (KEV history, fix-available history, high+critical history) | Requires backend changes to surface severity counts on `RunSummary` and add a `/runs/{id}/posture-history` endpoint. Forbidden by Phase 1 constraint. |
| F-10 | AI-generated headlines | Out-of-scope per prompt §4.3 |
| F-11 | Tab 2 (Components) visual uplift | Deferred per prompt §4.3 |
| F-12 | Tab 3 (Posture detail) visual uplift | Deferred per prompt §4.3 |
| F-13 | Density toggle (compact / comfortable) | Deferred per prompt §4.3 |
| F-14 | History / trend page (the sparkline is a teaser only) | Deferred per prompt §4.3 |
| F-15 | Saved comparisons | Pre-existing F-4 |

---

## 11. Phase 3 deliverables (preview)

**New components** (paths from [docs/compare-ui-audit.md §A](compare-ui-audit.md)):

```
HeroHeadline/         HeroHeadline.tsx, headlineRules.ts, headlineRules.test.ts
PostureHero/          PostureHero.tsx, BigNumbersColumn.tsx, DistributionBarLarge.tsx,
                      PostureTiles.tsx, PostureTile.tsx
Sparkline/            Sparkline.tsx, Sparkline.test.tsx
IdenticalRunsCard/    IdenticalRunsCard.tsx
FindingRow/           FindingRowAdvanced.tsx, SeverityGradient.tsx,
                      AttributionLine.tsx, CveHoverCard.tsx
TabsAdaptive/         TabsAdaptive.tsx
FilterChipsAdaptive/  FilterChipsAdaptive.tsx
```

**Updated components:**
- `CompareView.tsx` — branch on `isIdenticalRuns(diff)`; replace `<PostureHeader />` with `<PostureHero />` or `<IdenticalRunsCard />`
- `SelectionBar/RelationshipDescriptor.tsx` — compact mode in selection bar, full mode in hero sub-line
- `FindingsTab/FindingsTab.tsx` — render `<FindingRowAdvanced />`
- `FindingsTab/FindingsTable.tsx` — small wrapper that owns the hover-card overlay portal
- `FindingsTab/FindingsFilterBar.tsx` — clear-all button + status line (the chips themselves move to `<FilterChipsAdaptive />`)
- `useCompareUrlState.ts` — append `showSharedFindings` helper for the IdenticalRunsCard CTA

**CSS additions:** ~25 lines in `globals.css` (Token spec §6).

**No backend touch. No new dependencies.**
