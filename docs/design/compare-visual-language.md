# Compare visual language reference

Single-page reference for the Compare page's visual system after the
Phase 4 UI uplift. Covers tokens, adaptive copy, animation timing, and
hero state matrix.

> **User-facing doc:** [docs/features/compare-runs.md](../features/compare-runs.md)
> **Architecture:** [docs/adr/0008-compare-runs-architecture.md](../adr/0008-compare-runs-architecture.md)
> **Audit + redesign brief:** [compare-ui-audit.md](../compare-ui-audit.md), [compare-ui-redesign.md](../compare-ui-redesign.md)

---

## 1. Token additions

All compare-specific tokens live in [frontend/src/app/globals.css](../../frontend/src/app/globals.css). **No replacements** — every value is additive on top of the existing HCLTech palette.

### 1.1 Hero typography

| Token | Light + dark | Notes |
|---|---|---|
| `--hero-headline-size` | `clamp(1.5rem, 2.5vw, 2.25rem)` | 24–36px fluid |
| `--hero-bignumber-size` | `clamp(2.5rem, 5vw, 3.75rem)` | 40–60px fluid |
| `--hero-headline-tracking` | `-0.025em` | Matches `--display-lg` letterSpacing |

`clamp()` chosen so we don't bloat the Tailwind type ramp. Used by `<HeroHeadline />`, `<BigNumbersColumn />`, and `<IdenticalRunsCard />`.

### 1.2 Distribution bar

| Token | Value |
|---|---|
| `--distribution-bar-height` | `28px` (was `12px`) |
| `--distribution-bar-radius` | `999px` (full pill) |

Used by `<DistributionBarLarge />`.

### 1.3 Severity gradient stops

Decorative fade variants of the existing `severity.*` palette. Reused for the row left-edge gradient (`<SeverityGradient />`).

| Token | Light | Dark |
|---|---|---|
| `--severity-critical-fade` | `rgba(192, 57, 43, 0.10)` | `rgba(248, 113, 113, 0.12)` |
| `--severity-high-fade` | `rgba(212, 104, 10, 0.10)` | `rgba(251, 146, 60, 0.10)` |
| `--severity-medium-fade` | `rgba(184, 134, 11, 0.08)` | `rgba(251, 191, 36, 0.10)` |
| `--severity-low-fade` | `rgba(0, 103, 177, 0.06)` | `rgba(96, 165, 250, 0.08)` |
| `--severity-unknown-fade` | `rgba(107, 122, 141, 0.05)` | `rgba(148, 163, 184, 0.06)` |

**No new severity colors** — these are alpha-blend variants of the existing `severity.critical`, `severity.high`, `severity.medium`, `severity.low`, `severity.unknown` Tailwind tokens.

### 1.4 Animation keyframes

`@keyframes compare-sparkline-draw` — drives the SVG path stroke-dashoffset draw-on animation in `<Sparkline />`. 600ms `--ease-out`. Reduced-motion users get the final state from frame 1 via the global `*` reduced-motion rule.

---

## 2. Adaptive headline rules

Pure function: [`computeHeadline()`](../../frontend/src/components/compare/HeroHeadline/headlineRules.ts). Tests: [`headlineRules.test.ts`](../../frontend/src/components/compare/HeroHeadline/headlineRules.test.ts) (13 tests, exhaustive).

### 2.1 Inputs

```ts
interface HeadlineInputs {
  added: number;
  resolved: number;
  severityChanged: number;
  unchanged: number;
}
```

### 2.2 State matrix

| State (predicate) | Headline | Tone |
|---|---|---|
| `a=0 r=0 s=0 u=0` | "No vulnerabilities in either run." | neutral |
| `a=0 r=0 s=0 u>0` | (IdenticalRunsCard renders instead) | — |
| `a>0 r=0 s=0` | "+{a} new finding{s?}. Nothing resolved." | red |
| `a=0 r>0 s=0` | "−{r} finding{s?} resolved. No new exposure." | green |
| `a=0 r=0 s>0` | "{s} finding{s?} reclassified. No additions or removals." | amber |
| `a>0 r>0 r>a` | "Net safer: −{r} resolved vs +{a} added." | green |
| `a>0 r>0 a>r` | "Net worse: +{a} new vs −{r} resolved." | red |
| `a>0 r>0 a=r` | "Mixed: +{a} new, −{r} resolved." | amber |
| `a>0 r=0 s>0` | "+{a} new finding{s?}." | red |
| `a=0 r>0 s>0` | "−{r} finding{s?} resolved." | green |
| any with `s>0` (combined) | (append) " Plus {s} severity reclassification{s?}." | suffix only |

### 2.3 Tone → CSS mapping

| Tone | Light | Dark |
|---|---|---|
| red | `text-red-700` | `text-red-300` |
| green | `text-emerald-700` | `text-emerald-300` |
| amber | `text-amber-700` | `text-amber-300` |
| neutral | `text-hcl-navy` | `text-hcl-navy` |

Returned by `toneTextClass(tone)`.

---

## 3. Sub-line (relationship) copy

Driven by `RunRelationship` in the diff payload. Rendered italic, second line of `<HeroHeadline />`.

| Relationship state | Sub-line |
|---|---|
| `same_sbom: true`, days_between < 1/24 | "Same SBOM, re-scanned <1h apart — feed-only changes possible." |
| `same_sbom: true`, days_between < 1 | "Same SBOM, re-scanned {hours}h later — feed-only changes possible." |
| `same_sbom: true`, days_between ≥ 1 | "Same SBOM, re-scanned {days} days later — feed-only changes possible." |
| `same_project: true`, `same_sbom: false`, days_between present | "Different SBOMs of the same project, {time fragment} apart." |
| `same_project: true`, `same_sbom: false`, no days_between | "Different SBOMs of the same project." |
| neither flag | "Cross-project compare." |
| `direction_warning != null` | "⚠ {direction_warning}" — clickable to swap |

---

## 4. Hero state matrix

What the user sees at the top of the page given the diff payload.

| Predicate | Region 2 component | Sub-states |
|---|---|---|
| `added + resolved + severity_changed === 0` | `<IdenticalRunsCard />` | shared (unchanged > 0) · both-clean (all totals = 0) · no-overlap (cross-SBOM, no shared findings) |
| any non-zero diff | `<PostureHero />` | tone of headline driven by §2.2 state matrix |

`<PostureHero />` composition (top → bottom):

1. `<HeroHeadline />` — adaptive headline + sub-line
2. Two-column grid: `<BigNumbersColumn />` (30%) + `<DistributionBarLarge />` (70%)
3. `<Sparkline />` strip (lazy-loaded; hidden when cross-SBOM or <2 historical runs)
4. Three-column grid of `<PostureTile />` — KEV exposure / Fix-available coverage / High+Critical exposure

Mobile (≤640px): everything stacks; big numbers reflow to inline pills; sparkline hidden if SBOM has insufficient history.

---

## 5. Animation timing reference

| Animation | Duration | Easing | Trigger | Reduced-motion behaviour |
|---|---|---|---|---|
| Headline tone (red ↔ green ↔ amber) | `--duration-base` (200ms) | `--ease-out` | Tone change | None — text colour already final |
| Distribution-bar segment width | `--duration-slower` (480ms) | `--ease-spring` | Data change | Final width from frame 1 |
| Sparkline draw-on (stroke-dashoffset) | 600ms | `--ease-out` | First mount | Final state from frame 1 |
| Hover card reveal | `--duration-fast` (150ms) | `--ease-out` | 200ms after hover/focus | Same delay, no fade |
| `<IdenticalRunsCard />` mount | inherited from `Surface` (~`--duration-base`) | `--ease-spring` | Mount | Hard cut |

All durations sourced from existing CSS variables (`--duration-fast`, `--duration-base`, `--duration-slow`, `--duration-slower`). Compliance with `prefers-reduced-motion` is achieved via the global `*` selector in [globals.css](../../frontend/src/app/globals.css):

```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
```

---

## 6. Accessibility contract

| Concern | Implementation |
|---|---|
| Adaptive headline tone change | `<h2 aria-live="polite" aria-atomic="true">`. NOT `role="status"` — that conflicts with the implicit heading role (axe `aria-allowed-role` rule). |
| Sparkline | `<svg role="img">` + `<title>` — "Total findings, last N runs of {sbom}: trending {flat|up|down}, current value {n}." |
| Severity gradient | `aria-hidden="true"` (decorative). The change_kind chip text is the source of truth. |
| Tab dot indicator | `aria-label` like "1 new critical finding" / "2 new high-severity findings". Color is not the sole carrier. |
| Big numbers | `aria-label="{n} {label}"` so screen readers don't re-read each visual block as separate noise. |
| Distribution bar | `role="img"` with `aria-label="Added {a}, severity-changed {s}, unchanged {u}, resolved {r}"`. |
| Mobile pill collapse | (BigNumbersColumn) inline pills carry the same `aria-label`s; layout reflow only. |
| `<IdenticalRunsCard />` | `<h2>` headline, `<button>` CTA with text content (no icon-only buttons). |
| Hover card | `role="tooltip"` + 200ms reveal delay. `pointer-events: none` so hovering the card itself doesn't trap it. Tab + Enter still opens the full modal. |
| Reduced-motion | All count-up / draw-on / cross-fade animations skip via the global `*` rule above. |

Pinned by [`CompareView.axe.test.tsx`](../../frontend/src/components/compare/__tests__/CompareView.axe.test.tsx) — zero violations across `EmptySelection`, `SameRunPicked`, `RunNotReady` error, `loaded happy path`, and `IdenticalRunsCard` states.

---

## 7. Component tree

```
<CompareView>
├── <TopBar />
├── <SelectionBar>
│   ├── <RunPicker> × 2
│   ├── Swap / Share / (Export when data) buttons
│   └── (compact <RelationshipDescriptor />, hidden when hero shows it)
│
├── isIdenticalRuns(data)
│     ? <IdenticalRunsCard onViewSharedFindings={…} />
│     : <PostureHero>
│         ├── <HeroHeadline>            ← adaptive headline + sub-line
│         ├── <BigNumbersColumn>        ← 3 stacked numerals
│         ├── <DistributionBarLarge>    ← 28px promoted bar
│         ├── <Sparkline />             ← lazy-loaded, hide-on-fail
│         └── <PostureTile> × 3         ← KEV / Fix-available / High+Critical
│
├── <TabsAdaptive>                       ← activity dot on Findings tab
│
├── tab === 'findings'   ? <FindingsTab>
│                              ├── <FilterChipsAdaptive>
│                              ├── search input
│                              └── <FindingsTable>
│                                    └── <FindingRowAdvanced> × N
│                                          ├── <SeverityGradient />
│                                          ├── KEV / EPSS / FIX chips
│                                          ├── <CveHoverCard />
│                                          └── <AttributionLine />
│
├── tab === 'components' ? <ComponentsTab />     ← unchanged in this uplift
└── tab === 'delta'      ? <PostureDetailTab />  ← unchanged in this uplift
```

---

## 8. Migration & rollout

### 8.1 Zero breaking changes

| Surface | Status |
|---|---|
| Backend (`app/`) | Untouched — `git diff app/` is empty for the uplift PR |
| `POST /api/v1/compare` payload shape | Unchanged |
| `POST /api/v1/compare/{cache_key}/export` | Unchanged |
| `GET /api/runs/recent`, `/api/runs/search` | Unchanged |
| `GET /api/analysis-runs/compare` (deprecated v1) | Unchanged |
| URL state schema | Unchanged — every existing share link still resolves to the same view |
| Keyboard shortcuts (`?`, `1`/`2`/`3`, `e`, `s`, `/`, `Esc`) | Unchanged |
| CVE detail modal | Unchanged — `<FindingRowAdvanced />` opens the same dialog |

### 8.2 Feature flag

**None.** This is a purely additive visual change. The new components replace the v1 hero / row / tab strip in place; the kill-switch from ADR-0008 §1.1 (`NEXT_PUBLIC_COMPARE_V1_FALLBACK`) still works to roll back to the v1 page if either set of changes regresses.

### 8.3 Bundle impact

Targeted: <30KB gzipped delta on the compare route. Achieved via:

- No new dependencies (Recharts, lucide-react, Tailwind, shadcn primitives only)
- `<Sparkline />` and `<CveHoverCard />` lazy-loaded via `next/dynamic`
- New tokens are CSS variables (zero JS weight)
- Headline rules: ~120 LOC pure function, no runtime imports beyond types

### 8.4 Six-step staging verification

Before flipping production:

1. Build + deploy the uplift PR to staging.
2. Open `https://staging.example/analysis/compare?run_a=<a>&run_b=<b>` with two identical runs (the most common production case). Expect `<IdenticalRunsCard />` with the green checkmark, "No changes detected" headline, and "View shared findings" CTA.
3. Click the CTA — URL should change to add `?show_unchanged=true&tab=findings` (default-tab omitted), and the Findings tab should populate with unchanged rows.
4. Open with two runs that have a real diff. Expect `<PostureHero />` with a tone-coloured headline ("Net safer", "Net worse", or "Mixed").
5. Tab to a finding row — expect focus ring; press Enter — expect CVE detail modal.
6. Open with `prefers-reduced-motion: reduce` set in browser settings. Expect:
   - Sparkline appears at final state (no draw-on)
   - Distribution bar segments at final width (no transition)
   - Hover cards still reveal (200ms is intentional reveal delay, not animation)

If all six pass, the uplift is safe to roll forward.

---

## 9. Out-of-scope (logged as follow-ups)

| # | Item | Reason |
|---|---|---|
| F-9 | Per-tile sparklines (KEV history, fix-available history, high+critical history) | Backend doesn't expose severity counts on `RunSummary`; no historical KEV/EPSS snapshots |
| F-11 | Tab 2 (Components) visual uplift | Phase 4 prompt §4.3 deferred |
| F-12 | Tab 3 (Posture detail) visual uplift | Phase 4 prompt §4.3 deferred |
| F-13 | Density toggle (compact / comfortable) | Phase 4 prompt §4.3 deferred |
| F-14 | History / trend page (sparkline is a teaser) | Phase 4 prompt §4.3 deferred |
| F-16 | AI-generated headline | Phase 4 prompt §4.3 — separate prompt |
