# Compare UI uplift — Phase 1 audit

**Status:** Phase 1 of the visual uplift workplan
**Date:** 2026-05-01
**Scope:** Read-only audit of the current `/analysis/compare` page; pixel measurements; design-token inventory; identification of what is earning its space and what isn't.
**Predecessor:** [docs/adr/0008-compare-runs-architecture.md](adr/0008-compare-runs-architecture.md) — establishes the three-region IA the uplift preserves.

---

## TL;DR

- The page works. The visual hierarchy is the problem: **every region carries equal weight, and the most decision-relevant element (the distribution bar) is 12px tall and grey.**
- Tokens are in place. HCLTech navy/blue/cyan + a `severity.*` palette already cover the colors we need. New tokens for the uplift are limited to: hero typography sizes, the bigger distribution bar, severity gradient stops.
- **Recharts is already in deps**; raw SVG is fine for sparklines.
- **Sparklines have a real data-availability problem.** The current `/api/runs/recent` returns 20 most-recent rows across all SBOMs and exposes only `total_findings` aggregate per row — not per-severity, not KEV-specific. For honest per-tile sparklines (KEV history, fix-available history, high+critical history) we'd need backend changes the prompt forbids. See §6 for the three options.

---

## 1. Pixel measurements (current page)

Computed from the Tailwind classes on the live components — every value is the literal pixel a `1440 × 900` viewport will produce. Numbers in parentheses are the Tailwind class that produced them.

### 1.1 Top-level layout

```
TopBar                    ~64px tall   (h-16 in app shell, set in [components/layout/TopBar])
gap                       16px         (.space-y-4 between regions in CompareView:121)
```

### 1.2 Region 1 — Selection bar

[components/compare/SelectionBar/SelectionBar.tsx](../frontend/src/components/compare/SelectionBar/SelectionBar.tsx)

| Element | Measurement | Source |
|---|---|---|
| Outer Surface (`elevation=2`, sticky) | full width | `Surface variant="elevated" sticky top-2 z-20` |
| SurfaceContent vertical padding | 20px top, 16px bottom | `py-4` (= py-16px), but the inner space-y-3 + py-4 round to ~16+20 |
| RunPicker label | 12px font, ~16px tall | `text-[10px] font-semibold` |
| RunPicker trigger button | 38px tall | `mt-1 ... px-3 py-2.5` (= 10px top + 14px text + 10px bottom) |
| Swap / Share buttons | 32px tall | `px-3 py-2 text-xs` |
| Vertical rhythm between rows | 12px | `space-y-3` |
| RelationshipDescriptor row | 16px tall | `text-xs` |
| **Total Region 1 height** | **~120px** | sum of above + outer padding |

### 1.3 Region 2 — Posture delta

[components/compare/PostureHeader/PostureHeader.tsx](../frontend/src/components/compare/PostureHeader/PostureHeader.tsx)

| Element | Measurement | Source |
|---|---|---|
| Outer Surface (`variant="gradient"`) | full width | `Surface variant="gradient" elevation={2}` |
| SurfaceContent padding | 20px top + 24px bottom | `space-y-4` between children |
| "POSTURE DELTA" eyebrow | 10px font, ~14px tall | `text-[10px] font-semibold uppercase` |
| **Distribution bar itself** | **12px tall** | **`h-3` — this is the problem** ([DistributionBar.tsx:33](../frontend/src/components/compare/PostureHeader/DistributionBar.tsx#L33)) |
| Distribution bar legend | ~16px tall | `text-xs` |
| Tile grid | 3 columns at lg, gap 12px | `grid-cols-3 gap-3` |
| Each tile (`PostureMetricTile`) | ~84px tall | `Surface elevation=1 p-4` + label 14px + values 32px (`text-2xl`) + delta 20px |
| **Total Region 2 height** | **~190px** | |

The "headline" of the page is **the eyebrow text "POSTURE DELTA"** — it's 10px tall, all-caps, in muted grey. That's the entire problem in one line.

### 1.4 Region 3 — Tabs + body

[components/compare/CompareView.tsx](../frontend/src/components/compare/CompareView.tsx) (lines 145–180)

| Element | Measurement | Source |
|---|---|---|
| Tab strip | 32px tall | `px-3 py-1.5 text-sm` |
| FilterBar — chip row | 32–40px tall (wraps) | `gap-1.5` + `px-2.5 py-1` |
| FilterBar — search input | 40px tall | `h-10` |
| Findings table — header row | 28px tall | `px-3 py-2 text-[10px]` |
| Findings table — body row | **52px tall** | `px-3 py-2.5` (10+10) + content ~32px |
| **Tab body region** | **~400px+ scrollable** | |

### 1.5 Above-the-fold (1440 × 900)

```
TopBar                    64px
gap                       16px
Region 1 (Selection)     120px
gap                       16px
Region 2 (Posture)       190px         ←  this is the headline area, 0 hierarchy
gap                       16px
Tab strip                 32px
gap                       16px (space-y inside Surface)
Filter chips              ~80px (chip row + search input)
Table header              28px
≈ 5 visible body rows    260px
                       ─────
                         838px        ←  fits exactly above-the-fold at 900px
```

**Chrome vs data ratio above-the-fold (1440×900):**

- TopBar + Selection bar + tab strip + filter chips + table header = **324px / 900px ≈ 36% chrome**
- Region 2 distribution bar (the most data-dense element) = **12px / 900px ≈ 1.3%**
- Posture tiles = **~84px / 900px ≈ 9%**
- Visible findings rows = **260px / 900px ≈ 29%**

The page gives **1.3% of vertical real estate to the distribution bar** and **36% to chrome**. That's the diagnosis.

---

## 2. Design-token inventory

### 2.1 Theme tokens (CSS custom properties)

[src/app/globals.css](../frontend/src/app/globals.css), lines 1–107.

**Color tokens** — all theme-aware via CSS vars:

| Token | Light | Dark |
|---|---|---|
| `--color-background` | `#eef3f9` | `#0a101c` |
| `--color-foreground` | `#0c1929` | `#eef4fb` |
| `--color-surface` | `#ffffff` | `#151f30` |
| `--color-surface-muted` | `#f4f8fc` | `#101827` |
| `--color-border` | `#b8cce0` | `#2d3f56` |
| `--color-border-subtle` | `#dce8f2` | `#243047` |
| `--color-hcl-navy` (text) | `#1a2b4a` | `#eef4fb` |
| `--color-hcl-muted` | `#5c6d7e` | `#8fa4bd` |
| `--color-hcl-blue` | `#0067b1` | `#3d9fda` |
| `--color-hcl-cyan` | `#00b2e2` | `#38d4ff` |
| `--color-hcl-light` | `#e3eef8` | `#1e2d42` |

**Tailwind extension** — [tailwind.config.ts](../frontend/tailwind.config.ts):

- `severity.critical` = `#C0392B`
- `severity.high` = `#D4680A`
- `severity.medium` = `#B8860B`
- `severity.low` = `#0067B1`
- `severity.unknown` = `#6B7A8D`

**Elevation** — `--elev-1..4`, used as `shadow-elev-1..4` in Tailwind.

**Glow** — `--glow-primary`, `--glow-cyan`, `--glow-critical`, `--glow-success` (used sparingly on KEV badges, primary CTAs).

**Easing curves**:
- `--ease-out` = `cubic-bezier(0.16, 1, 0.3, 1)` — standard
- `--ease-spring` = `cubic-bezier(0.34, 1.56, 0.64, 1)` — overshoot
- `--ease-emphasized` = `cubic-bezier(0.2, 0, 0, 1)` — Material 3 style

**Durations**:
- `--duration-fast` = 150ms
- `--duration-base` = 200ms
- `--duration-slow` = 300ms
- `--duration-slower` = 480ms

### 2.2 Type scale

| Class | Size | Line height | Letter spacing |
|---|---|---|---|
| `text-[10px]` | 10px | inherit | inherit |
| `text-xs` | 12px | 16px | 0 |
| `text-sm` | 14px | 20px | 0 |
| `text-base` | 16px | 24px | 0 |
| `text-display-sm` | 18px | 25.2 | -0.02em |
| `text-2xl` | 24px | 32px | 0 |
| `text-display` | 24px | 30px | -0.03em |
| `text-display-lg` | 30px | 36px | -0.035em |

The type scale **stops at 30px**. The hero composition's "big numbers" (planned `text-5xl` = 48px and the headline planned `text-2xl` to `text-3xl`) need fluid `clamp()` tokens — not new fixed sizes — since the existing `text-display-lg` is already the ceiling.

### 2.3 Spacing scale

Standard Tailwind. `space-y-3` (12px), `space-y-4` (16px), `space-y-6` (24px), `gap-3` (12px), `gap-4` (16px) dominate the codebase. Border-radii `rounded-lg` (8px) and `rounded-xl` (12px) are the convention.

### 2.4 Severity color usage today

[components/ui/Badge.tsx:29–55](../frontend/src/components/ui/Badge.tsx#L29-L55) maps severity to:

| Severity | Background | Text | Dot |
|---|---|---|---|
| CRITICAL | `bg-red-50` | `text-red-900` | `bg-red-600` |
| HIGH | `bg-orange-50` | `text-orange-900` | `bg-orange-500` |
| MEDIUM | `bg-amber-50` | `text-amber-900` | `bg-amber-500` |
| LOW | `bg-hcl-light` | `text-hcl-blue` | `bg-hcl-blue` |
| UNKNOWN | `bg-slate-100` | `text-slate-700` | `bg-slate-400` |

**The uplift will reuse these verbatim.** No new severity colors.

The findings table also uses left-border tones for change_kind:

- `border-l-red-500` (added)
- `border-l-emerald-500` (resolved)
- `border-l-amber-500` (severity_changed)
- `border-l-slate-300` (unchanged)

These will be promoted into the `SeverityGradient` component for the row-level enhancement.

### 2.5 Existing motion utilities

`@layer base` contains:

- `.shimmer` — skeleton shimmer animation
- `.dialog-scrim-in` / `.dialog-panel-in` — modal entry
- `.motion-rise` — subtle entry slide
- `.surface-gradient` — radial gradient bg for hero panels (already used by `Surface variant="gradient"`)

Reduced-motion is already wired: the `motion-reduce:transition-none` and `motion-reduce:animate-none` Tailwind utilities are used throughout the codebase. New uplift animations will follow the same pattern.

---

## 3. Chart libraries

| Library | In deps? | Use today | Use for uplift |
|---|---|---|---|
| `recharts` | ✓ (frontend/package.json:23) | `dashboard/*` widgets | Tab 3 stacked-severity-bar already uses raw flex (see PostureDetailTab); no new Recharts needed for the uplift |
| `lucide-react` | ✓ | iconography | continue |
| `d3` / `visx` / `chart.js` | ✗ | — | **do NOT add** |

**Sparklines: hand-roll in raw SVG.** A 30-point sparkline is ~150 LOC of pure SVG path-building; pulling in Recharts for it is overkill and bumps bundle weight. Same conclusion as the prompt's §3.4.

---

## 4. What is earning its space, and what isn't

### Earning its space (preserve)

| Element | Why it earns it |
|---|---|
| Selection bar | Picks the inputs. Job complete. |
| Three posture tiles | Each tile maps to a specific public source (KEV catalog, fix-available column, severity column). PB-1 stands. |
| Findings table left-border colour | Subtle but the eye picks up the change_kind in <16ms. Keep, extend with gradient. |
| Filter chip row | Multi-axis filter with URL state. Job complete; only needs adaptive dimming. |
| Tabs | Genuinely needed; only need activity indicators. |
| RelationshipDescriptor | High-information line. **Failure mode is positioning, not content.** |
| TopBar / breadcrumb / back / share | Standard nav chrome. |

### Not earning its space (rework)

| Element | What it costs | What to do |
|---|---|---|
| **"POSTURE DELTA" eyebrow** | 14px tall, dominant top-of-region position, no information value | Replace with a data-driven `<HeroHeadline />` |
| **Distribution bar at h-3 (12px)** | 12px / 900px = 1.3% of viewport for the densest element on the page | Promote to ≥28px tall, add inline numeric labels, segment colors at full saturation |
| **Posture tiles all the same weight as headers above them** | Visual flatness — eye doesn't know what to read | Reduce tile typography by ~25% so they feel like *context* below the hero, not headers |
| **All-zero state rendered identically to mixed states** | The most common production case (rerun-no-change) is shown as an empty grid of "0 → 0" | `<IdenticalRunsCard />` celebratory layout |
| **RelationshipDescriptor as a 12px grey line** | The most insightful piece of context (same SBOM, hours apart) is visually invisible | Promote to italic, second-line position under the hero headline |
| **Big-numbers absent** | No single visual anchor for "what changed" | Add `<BigNumbersColumn />` with `text-5xl font-bold` semantic-coloured numerals |

### Rework but keep present (Theme 4 — findings table density)

The current row is functional but answers ~3 questions. Industry-standard triage UIs answer 5–6 per row by:

- Adding a 2nd visual line (italic attribution with version-arrow visualisation)
- Hover preview (CVE summary in a hover card)
- EPSS chip when percentile > 50
- Severity gradient on the left edge instead of a flat 4px border

Row height grows from 52px to ~72px — a 38% bump that pays for ~67% more information per row.

### Not earning its space (cut entirely)

Nothing yet. The current page is sparse but doesn't have superfluous elements — the problem is *under-investment* in the headline, not over-investment elsewhere.

---

## 5. Identical-runs case (the screenshot)

The screenshot's data is:
- `findings_added_count: 0`
- `findings_resolved_count: 0`
- `findings_severity_changed_count: 0`
- `findings_unchanged_count: 373` (or similar)
- `kev_count_a == kev_count_b` (no change)
- `fix_available_pct_a == fix_available_pct_b` (no change)
- `high_critical_count_a == high_critical_count_b` (no change)
- `relationship.same_sbom: true`
- `relationship.days_between: ~0.46` (≈ 11 hours)

In this state, the entire Region 2 renders as a row of "0"s and "no change" tags. **It's the most common production case** (most reruns produce no-op diffs because the underlying SBOM hasn't changed and the vulnerability feed has already been seen by the prior scan).

Treating it as an edge case — flat zeros, no celebration, no contextual framing about what *would have* changed (i.e. "feed-only changes possible") — fails the user's most common interaction. The Theme 3 `<IdenticalRunsCard />` is therefore not a nice-to-have; it's the headline for the **most-common page state in the product**.

---

## 6. Sparkline data availability

The prompt specifies sparklines on each posture tile derived from "the last 30 completed runs of either run's SBOM". This needs scrutiny.

### Data the client has access to today

[`GET /api/runs/recent`](../app/routers/runs.py) returns up to 50 most-recent runs **across all SBOMs**, with `RunSummary` fields:

```ts
{ id, sbom_id, sbom_name, project_id, project_name,
  run_status, completed_on, started_on,
  total_findings, total_components }
```

`total_findings` is an aggregate count only. **Severity-by-severity counts (critical_count, high_count, medium_count, low_count) ARE stored on `analysis_run` but NOT exposed in `RunSummary`.** KEV count over time is not stored anywhere historically — it's a current-state lookup against `kev_entry`.

### The three sparkline-realistic options

| Option | What gets a sparkline | Backend cost | Honesty |
|---|---|---|---|
| **A — Skip sparklines for v1** | None | $0 | Honest. Simplest. Document as F-9 follow-up. |
| **B — `total_findings` series only** | A single sparkline above the eyebrow line, NOT per-tile | $0 — uses existing `recentRuns` | Honest if labelled "total findings over time"; misleading if rendered per-tile because none of the three tiles measure total findings |
| **C — Per-tile sparklines** | KEV history, fix-available history, high+critical history | Backend changes — need to surface severity counts on `RunSummary` and add a `/runs/{id}/posture-history` endpoint | **Forbidden by Phase 1 constraint "No backend changes"** |

**Recommendation: Option B.** A single `total_findings` sparkline rendered as a context strip *above* the three tiles, clearly labelled "total findings, last 30 runs of this SBOM", with the current run's data point visually distinguished. Honest and doable client-side. The three tiles stay sparkline-free in v1.

If the user prefers Option A (no sparklines at all in v1) that's also fine — design will downgrade gracefully. **Need user decision before Phase 2.**

---

## 7. Open questions blocking Phase 2

| # | Question | Default if no input |
|---|---|---|
| Q1 | **Sparklines** — Option A (none), B (single total-findings strip), or C (deferred to a future backend-changes follow-up)? | **B** — single sparkline above tiles, labelled, optional per-instance hide if the SBOM has <2 historical runs |
| Q2 | **Big numbers column** — three separate stacked numbers (added / resolved / severity_changed) or one giant number ("net delta") with three breakdown sub-rows underneath? | Three stacked numbers — preserves PB-1 (no scalar) by refusing to compute a "net" |
| Q3 | **Tabs 2 (Components) and 3 (Posture detail)** — leave alone in this uplift, or do them too? | Leave alone — the Phase 4 of this prompt explicitly says "if scope allows, do Tab 1 plus Region 2; defer Tabs 2 & 3" |
| Q4 | **Hover card** on CVE id — popover above the row, or replace tooltip with hover card sourced from CVE cache? | Hover card via `next/dynamic`; first 100 chars of `summary` from the `/api/v1/cves/{id}` cache hit (no fetch — data is already cached when the modal opened earlier in the session). If cache miss, fall back to a "Click for details" tooltip, no fetch on hover |
| Q5 | **Adaptive headline copy** — strict template per state (predictable for support docs) vs varied phrasings (more human)? | Strict templates — easier to test, fewer i18n landmines |

Will proceed with the **defaults** in Phase 2 unless you push back.

---

## Appendix A — Files I will touch in Phase 3+

**New components:**

```
frontend/src/components/compare/HeroHeadline/
  HeroHeadline.tsx
  headlineRules.ts
  headlineRules.test.ts
frontend/src/components/compare/PostureHero/
  PostureHero.tsx
  BigNumbersColumn.tsx
  DistributionBarLarge.tsx
  PostureTiles.tsx
  PostureTile.tsx
frontend/src/components/compare/Sparkline/
  Sparkline.tsx
  Sparkline.test.tsx
frontend/src/components/compare/IdenticalRunsCard/
  IdenticalRunsCard.tsx
frontend/src/components/compare/FindingRow/
  FindingRowAdvanced.tsx
  SeverityGradient.tsx
  AttributionLine.tsx
  CveHoverCard.tsx
frontend/src/components/compare/TabsAdaptive/
  TabsAdaptive.tsx
frontend/src/components/compare/FilterChipsAdaptive/
  FilterChipsAdaptive.tsx
```

**Updated components:**

- [components/compare/CompareView.tsx](../frontend/src/components/compare/CompareView.tsx) — switch on `isIdenticalRuns(diff)` to render `<IdenticalRunsCard />` vs `<PostureHero />`; replace `<PostureHeader />` invocation with `<PostureHero />`
- [components/compare/SelectionBar/RelationshipDescriptor.tsx](../frontend/src/components/compare/SelectionBar/RelationshipDescriptor.tsx) — wired into hero sub-line; the original location keeps a compact version for the empty-selection state
- [components/compare/FindingsTab/FindingsTab.tsx](../frontend/src/components/compare/FindingsTab/FindingsTab.tsx) — render `<FindingRowAdvanced />`; the existing inline row component is removed
- [components/compare/PostureHeader/PostureHeader.tsx](../frontend/src/components/compare/PostureHeader/PostureHeader.tsx) — **deleted**, replaced by `<PostureHero />`

**CSS additions:**

A small block of new tokens in [globals.css](../frontend/src/app/globals.css):

```css
:root {
  /* Hero typography */
  --hero-headline-size: clamp(1.5rem, 2.5vw, 2.25rem);
  --hero-bignumber-size: clamp(2.5rem, 5vw, 3.75rem);
  --hero-headline-tracking: -0.025em;

  /* Distribution bar (promoted) */
  --distribution-bar-height: 28px;
  --distribution-bar-radius: 999px; /* full pill */

  /* Severity gradient stops — for the row left-border fade */
  --severity-critical-fade: rgba(192, 57, 43, 0.10);
  --severity-high-fade: rgba(212, 104, 10, 0.10);
  --severity-medium-fade: rgba(184, 134, 11, 0.08);
  --severity-low-fade: rgba(0, 103, 177, 0.06);
}

.dark {
  --severity-critical-fade: rgba(248, 113, 113, 0.12);
  --severity-high-fade: rgba(251, 146, 60, 0.10);
  --severity-medium-fade: rgba(251, 191, 36, 0.10);
  --severity-low-fade: rgba(96, 165, 250, 0.08);
}
```

No new severity colors — only fade variants of the existing `severity.*` palette.

**No backend changes. No new dependencies. No new endpoints.**
