# Dashboard v2 — Information Architecture & Copy Design

**Phase 2 deliverable.** No code changes. Locks: layout, copy, visual spec, data contracts, element classification. Awaits owner approval before Phase 3.

**Companion doc:** [docs/dashboard-v2-audit.md](docs/dashboard-v2-audit.md) — Phase 1 audit.
**Brief reference:** the v2 brief titled *"Calm posture, real trend, value delivered."*

---

## 0. Design principle

> The dashboard is **boring most of the time and loud only when it should be.**

Every decision below ladders up to that. If a card decorates without informing, it's cut. If a label sounds urgent when nothing is, the label is rewritten. Copy is data-driven; tone is data-driven; the only thing that's static is the layout.

Four questions the dashboard answers in 5 seconds:

1. **What's the current state?** (hero headline + severity bar)
2. **What changed recently?** (Findings Trend chart)
3. **What's the one most important thing to look at?** (adaptive primary CTA)
4. **Has the tool been working for me?** ("Your Analyzer, So Far")

---

## 1. Wireframe (locked)

```
┌──────────────────────────────────────────────────────────────────────────┐
│ TopBar:  Dashboard · Real-time security posture across your SBOMs        │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  HERO POSTURE CARD  (Surface gradient · elev-3 · radius 16)              │
│  ─────────────────                                                       │
│  [Adaptive headline — display-lg, hcl-navy, tracking-display]            │
│  [Sub-line — sm, hcl-muted, max-w-2xl]                                   │
│  [Latest run · 2 days ago] (text-[10px] uppercase, hcl-muted) — only     │
│   shown when data exists                                                 │
│                                                                          │
│  ╔══════════════════════════════════════════════════════════════════╗    │
│  ║  Severity distribution bar — h-7 (28px) · radius full · gap-px   ║    │
│  ║  Critical · High · Medium · Low — color tokens, proportional      ║    │
│  ╚══════════════════════════════════════════════════════════════════╝    │
│  · Critical 0  · High 0  · Medium 1259  · Low 0   (·  N unknown — pill)  │
│                                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────────────────┐      │
│  │ KEV      │ │ Fix-     │ │ Net 7d   │ │ 30-DAY MINI TREND       │      │
│  │ exposed  │ │ available│ │ change   │ │ ▁▁▂▃▅▇█▇▅▃▂▁▁▂▃        │      │
│  │  0       │ │  0/513   │ │  +0/-0   │ │ Sparkline + label       │      │
│  └──────────┘ └──────────┘ └──────────┘ └─────────────────────────┘      │
│                                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│  QUICK ACTIONS                                                           │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────────────┐   │
│  │ Upload SBOM │ │ Analysis runs│ │ Compare runs │ │ Manage projects │   │
│  │ (PRIMARY)   │ │ (outline)    │ │ (outline)    │ │ (outline)       │   │
│  └─────────────┘ └──────────────┘ └──────────────┘ └─────────────────┘   │
│  Primary swaps based on headline_state (see §4)                          │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  FINDINGS TREND  (Surface elevated · radius 12 · h-80)                   │
│  ──────────────                                                          │
│  Stacked area chart, last 30 days, severity-coloured bands, dashed       │
│  reference line at 30-day average, click-through to filtered runs view   │
│  Annotation markers (▼) for sbom_uploaded · remediation events           │
│  Legend chips clickable to toggle severities                             │
│                                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│  YOUR ANALYZER, SO FAR                                                   │
│  ──────────────────                                                      │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐             │
│  │ SBOMs      │ │ Runs       │ │ Findings   │ │ Monitoring │             │
│  │ scanned    │ │ executed   │ │ surfaced   │ │ for        │             │
│  │ ─────────  │ │ ─────────  │ │ ─────────  │ │ ─────────  │             │
│  │  3         │ │  4         │ │  513       │ │  2 days    │             │
│  │ across 1   │ │ 3 this     │ │ 0 resolved │ │ since      │             │
│  │ project    │ │ week       │ │ to date    │ │ Apr 30     │             │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘             │
├──────────────────────────────────────────────────────────────────────────┤
│  TOP VULNERABLE SBOMs (kept)         RECENT ACTIVITY (kept)              │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
                                                                          
[Sidebar footer "Degraded · NVD mirror disabled" REMOVED from user pages]
```

---

## 2. Adaptive headline rules — locked copy

The hero headline is **deterministic** from the dashboard summary payload. Server computes `headline_state` once per request; frontend renders the matching `(headline, subline, tone)` triple via a pure lookup.

### 2.1 State precedence (top wins)

```
1. no_data           ← total_sboms == 0
2. kev_present       ← kev_count >= 1
3. criticals_no_kev  ← critical >= 1 AND kev_count == 0
4. high_only         ← critical == 0 AND high >= 1
5. low_volume        ← critical == 0 AND high == 0 AND total_findings > 0
6. clean             ← total_sboms > 0 AND total_findings == 0
```

Precedence is strict — the first matching rule wins. `no_data` and `clean` are mutually exclusive at the data level (one requires zero SBOMs, the other requires SBOMs with zero findings); precedence is just there to keep the rules unambiguous if both somehow held.

### 2.2 Copy table (locked)

`{N}` and `{M}` are placeholders the frontend interpolates from the data payload; pluralization is handled per the existing `pluralize()` helper at [`frontend/src/lib/pluralize.ts`](frontend/src/lib/pluralize.ts).

| State | Headline | Sub-line | Tone | Tone visual |
|---|---|---|---|---|
| `no_data` | **No SBOMs uploaded yet.** | Upload your first SBOM to see your security posture here. | `neutral` | hcl-muted text, slate ambient |
| `clean` | **All clear across {N} {SBOMs/SBOM}.** | No critical or high-severity findings in your portfolio right now. | `success` | emerald-700 / emerald-300 |
| `kev_present` | **{N} actively exploited {findings/finding} need{s} attention.** | These are listed in CISA's Known Exploited Vulnerabilities catalog. Prioritize remediation. | `danger` | red-700 / red-300, severity-critical-fade ambient |
| `criticals_no_kev` | **{N} critical {findings/finding} across {M} {SBOMs/SBOM}.** | None are in CISA KEV. Review and prioritize by exploitability. | `warning` | orange-700 / orange-300, severity-high-fade ambient |
| `high_only` | **{N} high-severity {findings/finding} to review.** | No criticals; manageable backlog. | `info` | sky-700 / sky-300, severity-low-fade ambient |
| `low_volume` | **{N} {findings/finding}, none critical or high.** | Stable posture — schedule routine remediation. | `neutral` | hcl-muted, slate ambient |

### 2.3 Pluralization examples (verified against `pluralize.ts`)

| State | Live DB values (today) | Resolved copy |
|---|---|---|
| `no_data` | sbom_count=0 | **No SBOMs uploaded yet.** / Upload your first SBOM… |
| `clean` (1 SBOM) | sbom_count=1, findings=0 | **All clear across 1 SBOM.** / No critical or high-severity… |
| `clean` (3 SBOMs) | sbom_count=3, findings=0 | **All clear across 3 SBOMs.** / No critical or high-severity… |
| `kev_present` (1 KEV) | kev_count=1 | **1 actively exploited finding needs attention.** / These are listed in CISA's Known Exploited… |
| `kev_present` (12 KEV) | kev_count=12 | **12 actively exploited findings need attention.** / These are listed in CISA's Known Exploited… |
| `criticals_no_kev` (1c, 1 SBOM) | crit=1, sbom_count=1 | **1 critical finding across 1 SBOM.** / None are in CISA KEV… |
| `criticals_no_kev` (12c, 4 SBOMs) | crit=12, sbom_count=4 | **12 critical findings across 4 SBOMs.** / None are in CISA KEV… |
| `high_only` | crit=0, high=7 | **7 high-severity findings to review.** / No criticals; manageable backlog. |
| `low_volume` (this DB) | crit=0, high=0, findings=1259 | **1,259 findings, none critical or high.** / Stable posture — schedule routine remediation. |

### 2.4 What we are explicitly NOT showing

- ❌ "Urgent attention required" (anywhere)
- ❌ "Critical risk" / "Posture critical" / any unspecific alarm
- ❌ Live red-dot indicator in the hero
- ❌ "Posture degraded" hero state — see §2.5 freshness handling
- ❌ "Posture unavailable" hero state — same reason

### 2.5 Data freshness — handled inline, not as a hero state

The current state machine has a `degraded` band that fires when `hours_since_latest_run > 24`. The v2 hero doesn't carry that band. Instead:

- The hero shows a small `Latest run · 2 days ago` line under the sub-line whenever `last_successful_run_at` is non-null.
- Color is `hcl-muted` regardless of staleness — calm by default.
- After 7 days the line bumps to `text-amber-600 dark:text-amber-300` (informational, not alarmist) and reads `Latest run · 8 days ago — consider re-scanning.`
- After 30 days the same line reads `Latest run · {N} days ago — data may be stale.`
- API health (the old `health.status !== 'ok'` gate) collapses into a single error toast at the page level, not a hero state.

This keeps the hero focused on **security posture** and treats freshness as a separate axis the user can scan if they want.

---

## 3. Hero metric row — locked

Below the severity distribution bar, four inline metric tiles. Same widths, same height, same typography — the row reads as a unit, not as four floating pills.

### 3.1 Tiles

| Tile | Label (uppercase, 10px) | Value | Sub-line / annotation | Tone rule |
|---|---|---|---|---|
| 1 | KEV EXPOSED | `{kev_count}` (font-metric, 24px, tabular-nums) | `On CISA KEV` (10px, hcl-muted) | `red` if `kev_count > 0`, else `neutral` |
| 2 | FIX AVAILABLE | `{fix_count} / {distinct}` | `Actionable now` | `sky` if `fix_count > 0`, else `neutral` |
| 3 | NET 7-DAY CHANGE | `+{added} / -{resolved}` | `vs prior 7 days` | green when net negative; red when net positive; neutral when zero |
| 4 | 30-DAY MINI TREND | inline 60×24 sparkline (--color-hcl-blue) | `30-day finding trend` (10px) | always `info` |

### 3.2 Net 7-day change semantics — locked

> **Decision (open question 1 from audit):** `added` and `resolved` count distinct **vuln_ids in scope**, not finding rows.

Rationale: users care how many *new things to triage* appeared this week and how many were *fixed*. A CVE that touches three components is one work item, not three. Vuln_id semantic matches that mental model and aligns with the existing "Distinct Vulnerabilities" KPI in the legacy dashboard.

Computation:
- `added`: distinct `vuln_id` present in the latest successful run per SBOM as of today, but absent from the latest successful run per SBOM as of 7 days ago.
- `resolved`: the inverse — present 7 days ago, absent today.
- Both use the same scoping subquery as `posture` (§1.4 of audit).

### 3.3 Tile dimensions

| Aspect | Spec |
|---|---|
| Min width | 7rem (112px) |
| Height | 4.5rem (72px) |
| Padding | px-3 py-2 |
| Border radius | rounded-lg (0.5rem) |
| Background | `bg-surface/60` w/ blur, severity tone overlay if active |
| Border | 1px solid `border-border` (1px solid `border-{tone}-200/700` when active) |
| Gap between tiles | gap-3 |
| Stack at <= 640px | column gap-2, full width |

### 3.4 Severity distribution bar

| Aspect | Spec | Why this differs from v1 |
|---|---|---|
| Height | 28px (was 10px) | Spec calls for ≥ 28px. Anchors the eye. |
| Radius | rounded-full | unchanged |
| Background (zero) | `bg-emerald-100 dark:bg-emerald-950/60` with centered "No findings" text | unchanged |
| Segment colors | severity-{critical,high,medium,low} from existing tokens | unchanged |
| Segment gap | 1px (gap-px) | unchanged |
| Unknown handling | separate pill below the bar (data-quality signal) | unchanged |
| Animation | 700ms `ease-spring` width transition on data change | unchanged |

The increased height is the only material change; the bar is otherwise reused.

---

## 4. Quick actions — adaptive primary

Four buttons, repositioned below the hero. The **primary** changes based on `headline_state`. All others are outline-style at all times.

| `headline_state` | `primary_action` | Primary label / icon | Other actions (always outline) |
|---|---|---|---|
| `no_data` | `upload` | **Upload SBOM** / `Upload` icon | Analysis runs · Compare runs · Manage projects |
| `kev_present` | `review_kev` | **Review KEV-listed findings** / `ShieldAlert` | Upload SBOM · Analysis runs · Compare runs |
| `criticals_no_kev` | `review_critical` | **Review critical findings** / `AlertTriangle` | Upload SBOM · Analysis runs · Compare runs |
| `high_only` | `view_top_sboms` | **View top vulnerable SBOMs** / `ListChecks` | Upload SBOM · Analysis runs · Compare runs |
| `low_volume` | `view_top_sboms` | **View top vulnerable SBOMs** / `ListChecks` | Upload SBOM · Analysis runs · Compare runs |
| `clean` | `upload` | **Upload another SBOM** / `Upload` | Analysis runs · Compare runs · Manage projects |

`primary_action` lives on the dashboard summary payload (server-computed). The frontend maps `primary_action → button config` from a single const table — no copy logic on the client.

### 4.1 Button styling (Tailwind)

| Style | Classes |
|---|---|
| Primary | `bg-primary text-white shadow-sm hover:bg-hcl-dark focus-visible:ring-2 focus-visible:ring-hcl-blue/50` |
| Outline | `border border-border bg-surface text-hcl-navy hover:bg-surface-muted` |
| Manage projects (tertiary) | `border border-dashed border-primary/40 text-primary hover:bg-primary/5` (kept from v1) |

---

## 5. Findings Trend chart — visual spec

### 5.1 Layout

| Aspect | Spec |
|---|---|
| Surface | `Surface elevated`, full width, `radius 12`, `shadow-card` |
| Header | h3 `text-base font-semibold text-hcl-navy` "Findings trend" + sub `text-xs text-hcl-muted` "Daily severity counts across all analysis runs." + clickable severity legend chips on the right |
| Chart height | 320px (was 260) |
| Margin | top 8 / right 16 / left -16 / bottom 0 |
| Empty state | `<EmptyTrendState>` shown when `points.length < 7` (or `earliest_run_date` is within last 7 days). Copy: "Trend will appear after a week of regular scanning. {N} runs so far." |

### 5.2 Stacked-area treatment

- Stack order from bottom up: **Critical, High, Medium, Low, Unknown**. Critical at the bottom carries the most visual weight.
- Severity colors from existing tokens (no new severity colors): `severity-critical #C0392B`, `severity-high #D4680A`, `severity-medium #B8860B`, `severity-low #0067B1`, `severity-unknown #6B7A8D`.
- Linear gradients (existing pattern in `TrendChart.tsx`): `0% → 32% opacity at top, 0% at bottom`.
- Stroke 2px in the same color as the fill base. `dot={false}`. Active dot 4px on hover.
- Animation: 650ms `ease-out` on data change.

### 5.3 Reference line — 30-day average

- Horizontal `<ReferenceLine y={avg_total}>` from Recharts.
- Stroke `var(--color-border)`, dasharray `4 4`, opacity 0.6.
- Label "30-day avg" right-anchored, `text-[10px] text-hcl-muted font-metric tabular-nums`.

### 5.4 Annotations

| Kind | Marker | Color | Hover label |
|---|---|---|---|
| `sbom_uploaded` | small triangle ▼ at the top of the chart on that day | `--color-hcl-blue` | "Apr 30: 2 SBOMs uploaded" (when count > 1) / "Apr 29: cyclonedx-multi-ecosystem uploaded" (when count == 1, label includes name) |
| `remediation` | small chevron downward | `severity-low` | "May 1: 14 findings resolved" |
| `kev_first_seen` | small shield outline | `severity-critical` | "May 2: CVE-2025-1234 added to KEV" |

Markers are rendered as `<ReferenceDot>` per annotation. Stack vertically when multiple events share a day (small offset, max 3 visible per day with a "+N more" tooltip).

### 5.5 Interaction

- **Click a date on the X-axis or click the area at a day** → navigate to `/analysis?tab=runs&date={date}` (existing route handles this).
- **Click a severity legend chip** → toggles that severity (Recharts `<Legend>` native behavior; current code already supports this at [`TrendChart.tsx:96-98`](frontend/src/components/dashboard/TrendChart.tsx#L96)).
- **Hover anywhere** → vertical line + custom tooltip showing severity breakdown table for that day.

### 5.6 Tooltip content (locked)

```
APR 30
─────────────────
● Critical    0
● High        0
● Medium  1,259
● Low         0
─────────────────
TOTAL     1,259
```

(Existing `CustomTooltip` at [`TrendChart.tsx:36-67`](frontend/src/components/dashboard/TrendChart.tsx#L36) is reused; only data shape changes.)

---

## 6. "Your Analyzer, So Far" — locked

Four-tile growth metrics row. **No deltas, no comparisons, no "vs last week."** These numbers only go up; the implicit story is "this tool keeps working for you."

### 6.1 Tile layout

```
┌────────────────┐
│ ▌SBOMs scanned │  ← uppercase 11px hcl-muted label
│                │
│      3         │  ← font-metric ~3rem (--hero-bignumber-size), tabular-nums
│                │
│ across 1       │  ← 12px hcl-muted sub-line
│ project        │
└────────────────┘
   ▌ = left accent border, w-1, brand color (hcl-blue, no severity tone)
```

| Tile | Big number | Sub-line | Source field |
|---|---|---|---|
| 1 | `sboms_scanned_total` | "across {N} {projects/project}" | `projects_total` |
| 2 | `runs_executed_total` | "{N} this week" | `runs_executed_this_week` |
| 3 | `findings_surfaced_total` | "{N} resolved to date" | `findings_resolved_total` |
| 4 | `days_monitoring` (with " day"/" days" suffix) | "since {date format(first_run_at, 'MMM d')}" | `first_run_at` |

### 6.2 Tile dimensions

| Aspect | Spec |
|---|---|
| Background | `bg-surface` (raised) |
| Border | left accent `border-l-4 border-l-hcl-blue`, rest `border border-border` |
| Border radius | rounded-xl (0.75rem) |
| Padding | `px-6 py-5` (matches existing StatsGrid card) |
| Big number | `font-metric text-[3rem] font-bold leading-none text-hcl-navy tabular-nums` |
| Label | `text-[11px] uppercase tracking-wider text-hcl-muted` |
| Sub-line | `text-xs text-hcl-muted mt-1` |
| Min height | 6rem (96px) |
| Hover | none — these aren't actionable; resist the urge |

### 6.3 Empty / first-day cases

| Condition | Tile 1 | Tile 2 | Tile 3 | Tile 4 |
|---|---|---|---|---|
| `runs_executed_total == 0` | `0` / "no SBOMs yet" | `0` / "no runs yet" | `—` / "no findings yet" | `—` / "ready when you are" |
| Day 1 (just onboarded) | `1` / "across 1 project" | `1` / "1 this week" | `513` / "0 resolved to date" | `0 days` / "since today" |

---

## 7. Removals — explicit

| Element | File | Reason |
|---|---|---|
| `Security posture · live` red dot | `HeroRiskPulse.tsx:264-275` | Decoration that desensitizes the eye |
| `Active Projects` / `Total SBOMs` / `Distinct Vulnerabilities` cards | `StatsGrid.tsx` | Inventory counts now in "Your Analyzer, So Far" reframed as growth |
| `Vulnerability severity` donut | `SeverityChart.tsx` | Categorical donut adds nothing beyond the labeled severity bar |
| `SBOM activity` donut (Active 30d / Stale) | `ActivityChart.tsx` | Same reasoning; lifetime tile + trend chart cover the use case |
| `Degraded · NVD mirror disabled` widget on user pages | `SidebarStatus.tsx` | Operator/admin concern leaking onto user surface |
| `degraded` posture band | `dashboardPosture.ts:139-141, 79-103` | Folded into a calm "Latest run · X ago" inline indicator (§2.5) |
| `derivePosture` 6-state machine (replaced) | `dashboardPosture.ts:73-137` | Replaced by server-side `headline_state` |

### 7.1 Sidebar widget — what replaces it

> **Decision (open question 2 from audit):** Hide on user-facing pages; retain a single neutral connectivity dot in the collapsed-sidebar mode (no copy, no error tone).

Implementation strategy for Phase 4:
- Strip the `nvd_mirror.enabled === false` and `nvd_mirror.stale` paths from the user-visible footer.
- The expanded sidebar shows only `API healthy` / `API unreachable` (no mirror state, no "Degraded").
- The collapsed sidebar shows one dot — green when `data.status === 'ok'`, slate when offline; never amber.
- Mirror status moves to a future `/admin/health` route (out of scope for this redesign — flagged as a follow-up per brief §3.6).

---

## 8. Preserved — explicit

| Element | File | What stays |
|---|---|---|
| Sidebar nav, brand bar, recent-runs widget | `Sidebar.tsx`, `SidebarContext.tsx` | unchanged |
| TopBar with breadcrumb + page title pattern | `TopBar.tsx` | unchanged |
| Hero card Surface gradient + ambient glow | `HeroRiskPulse.tsx` outer wrapper | retained, only inner content changes |
| Severity distribution bar (made larger) | `HeroRiskPulse.tsx:305-356` | retained, h-2.5 → h-7 |
| KEV / Fix-available tile primitives | `HeroRiskPulse.tsx:436-460` `PostureMetricTile` | retained, used by 4 new tiles |
| `Sparkline` primitive | `frontend/src/components/ui/Sparkline.tsx` | retained, used in mini-trend tile |
| `Numeric` / `tabular-nums` typography helpers | existing utility classes | unchanged |
| Top vulnerable SBOMs list | `TopVulnerableSboms.tsx` | unchanged |
| Recent activity timeline | `ActivityFeed.tsx` | unchanged |
| HCLTech parent badge | `Sidebar.tsx:106-112` | unchanged |
| Recharts `<AreaChart>` infrastructure | `TrendChart.tsx:111-240` | retained; only data feed replaced |
| Custom trend tooltip | `TrendChart.tsx:36-67` | retained |

---

## 9. Data contracts — Phase 3 inputs

This locks the API surface Phase 3 implements.

### 9.1 New: `GET /dashboard/lifetime`

```py
class LifetimeMetrics(BaseModel):
    sboms_scanned_total: int
    projects_total: int
    runs_executed_total: int
    runs_executed_this_week: int
    findings_surfaced_total: int       # distinct (vuln_id, component_name, component_version)
    findings_resolved_total: int       # cross-run join, cached
    first_run_at: datetime | None
    days_monitoring: int               # (now - first_run_at).days, 0 when no runs

    schema_version: Literal[1] = 1
```

### 9.2 Replaced: `GET /dashboard/trend?days=30`

```py
class TrendDataPoint(BaseModel):
    date: date
    critical: int
    high: int
    medium: int
    low: int
    unknown: int                       # NEW — was silently dropped in v1
    total: int                         # NEW — convenience for tooltip & ref line

class TrendAnnotation(BaseModel):
    date: date
    kind: Literal["sbom_uploaded", "remediation", "kev_first_seen"]
    label: str                         # human-readable: "+2 SBOMs uploaded"
    count: int = 1                     # for marker stacking when multiple

class FindingsTrendResponse(BaseModel):
    days: int                          # echo of query param
    points: list[TrendDataPoint]       # always exactly `days` items, zero-filled
    annotations: list[TrendAnnotation]
    avg_total: float                   # 30-day mean of point.total
    earliest_run_date: date | None     # so frontend can detect "<7 days of data"

    schema_version: Literal[1] = 1
```

`series` (the v1 field) becomes `points`. Frontend types are renamed in the same Phase 3 PR. The OpenAPI schema therefore changes — but the consumer is internal and within the same monorepo, so no compatibility shim is needed.

### 9.3 Extended: `GET /dashboard/posture`

```py
class DashboardPosture(BaseModel):
    severity: SeverityCounts
    kev_count: int
    fix_available_count: int
    last_successful_run_at: datetime | None
    total_sboms: int
    total_active_projects: int

    # New in v2:
    total_findings: int                # replaces a separate /stats round-trip
    distinct_vulnerabilities: int      # replaces a separate /stats round-trip
    net_7day_added: int                # new vuln_ids vs 7 days ago, in scope
    net_7day_resolved: int             # vuln_ids resolved vs 7 days ago, in scope
    headline_state: Literal[
      "no_data", "clean", "kev_present",
      "criticals_no_kev", "high_only", "low_volume"
    ]
    primary_action: Literal[
      "upload", "review_kev", "review_critical", "view_top_sboms"
    ]

    schema_version: Literal[1] = 1
```

### 9.4 Decommissioned: `GET /dashboard/stats` and `GET /dashboard/severity`

Their fields move into `/dashboard/posture`. The endpoints stay live for one release cycle returning the legacy shape unchanged (additive deprecation per ADR-0001 deprecation window pattern). The frontend stops calling them in Phase 4. Phase 5 deletes them in a follow-up.

> **Decision (open question 3 from audit):** caching = ETag-based 304s (already in `maybe_not_modified`) for v2. Lifetime endpoint adds an in-process `functools.lru_cache(maxsize=1)` keyed by `max(analysis_run.id)` with a 15-minute TTL so the expensive cross-run join runs at most once per quarter-hour. Defer Redis to multi-tenant rework.

> **Decision (open question 4 from audit):** `headline_state` and `primary_action` are computed **server-side** and shipped on `/dashboard/posture`. The frontend renders by lookup. Confirms brief §2.1 / §3.3.

---

## 10. Component tree (Phase 4 inputs)

```
components/dashboard/
  HeroPostureCard/
    HeroPostureCard.tsx               # replaces HeroRiskPulse.tsx
    AdaptiveHeadline.tsx              # pure (state, data) → JSX
    SeverityDistributionBar.tsx       # extracted, h-7
    HeroMetricRow.tsx
    HeroMetric.tsx                    # KEV / Fix / Net7d (numeric tile)
    HeroMiniTrend.tsx                 # 60×24 Sparkline tile
    LatestRunIndicator.tsx            # the "Latest run · 2 days ago" line
  QuickActions/
    QuickActions.tsx                  # replaces DashboardQuickActions.tsx
    QuickActionButton.tsx
    primaryActionConfig.ts            # const map: primary_action → button props
  FindingsTrendChart/
    FindingsTrendChart.tsx            # replaces TrendChart.tsx (chart logic kept)
    TrendChartTooltip.tsx             # extracted from current
    TrendAnnotationMarker.tsx
    EmptyTrendState.tsx
  LifetimeStats/
    LifetimeStats.tsx
    LifetimeStatTile.tsx
  TopVulnerableSboms/                 # existing, unchanged
  RecentActivity/                     # existing (ActivityFeed.tsx), unchanged
  hooks/
    useDashboardSummary.ts            # wraps /dashboard/posture (extended)
    useLifetimeStats.ts               # wraps /dashboard/lifetime
    useFindingsTrend.ts               # wraps /dashboard/trend (renamed)

lib/
  headlineCopy.ts                     # const map: headline_state → (data) => {headline, subline, tone}
  dashboardPosture.ts                 # _dashboard_v1.ts (kept under flag)
```

The headline rule logic moves out of `dashboardPosture.ts` (which was a state-machine) and into `headlineCopy.ts` (which is a pure rendering map). Server now owns the state; client owns the copy.

---

## 11. Light + dark parity matrix

Every new component renders correctly in both modes from day one. Spec uses CSS variables so dark-mode parity is automatic for colors that route through the existing token system. Hand-checked items that need explicit attention:

| Component | Light | Dark |
|---|---|---|
| Severity distribution bar | proportional segments on `bg-border-subtle` (#dce8f2) | same shape on `bg-border-subtle` dark (#243047) |
| Hero ambient glow | `*-300/30` opacity per tone | `*-400/30` opacity per tone |
| Headline tone classes | `text-emerald-700` | `text-emerald-300` (matches existing pattern) |
| Lifetime tile accent border | `border-l-hcl-blue` (#0067B1) | `border-l-hcl-blue` (#3D9FDA) (auto via token) |
| Trend reference line | `--color-border` (#b8cce0) at 0.6 opacity | `--color-border` (#2d3f56) at 0.6 opacity |
| Annotation markers | severity tokens (color-stable across modes) | severity tokens (color-stable across modes) |

No new tokens introduced; no hex literals in components. All colors route through Tailwind classes that are mapped in `tailwind.config.ts` to CSS vars.

---

## 12. Mobile (≤ 640px) layout

| Section | Desktop (≥ 1024px) | Mobile |
|---|---|---|
| Hero | row layout, metric tiles right-aligned | column layout, metric tiles 2×2 grid below severity bar |
| Severity bar | full-width, h-7 | full-width, h-7 (unchanged) |
| Hero metric row | 4 tiles in a row, gap-3 | 2×2 grid, gap-2 |
| Quick actions | inline row, 4 buttons | column stack, gap-2, primary first |
| Trend chart | h-80 | h-56, X-axis labels every 7 days |
| Lifetime tiles | 4 across | 2×2 grid |
| Top vulnerable + Activity | 2 columns | column stack |

---

## 13. Anti-patterns the design explicitly rejects

(For the implementer: if a temptation arises during Phase 4 that contradicts these, stop and revisit this doc.)

- ❌ Adding a "risk score" scalar
- ❌ Replacing a state-driven headline with a generic alarmist phrase
- ❌ Showing `0 → 0` deltas as if something happened
- ❌ Adding more donut charts to "look advanced"
- ❌ Showing growth deltas on lifetime tiles
- ❌ Trend chart with date gaps where days have no findings
- ❌ Annotations without backing DB events
- ❌ Letting Recharts default colors leak through
- ❌ Centering the dashboard around quick-action buttons
- ❌ Routing operator/admin warnings (mirror, disk, queue) onto user pages

---

## 14. What this doc explicitly does NOT cover

(So Phase 4 doesn't accidentally pull these in.)

- User-customizable widgets / drag-to-reorder layout
- Multi-tenant scoping (deferred per existing direction)
- AI-generated narrative ("This week, your security posture…")
- Email digests / scheduled exports
- Slack notifications on state changes
- Time-period comparisons (besides Net 7-day)
- Drill-down from every tile (only quick-actions and trend chart click-through, per brief)
- Historical KEV catalog tracking — `kev_first_seen` annotations omitted if signal isn't trivially derivable; the chart still renders the other annotation kinds
- Re-skin of "Top vulnerable SBOMs" or "Recent activity"
- Admin/operator health surface — separate work

---

## 15. Element classification (preserved / replaced / removed / added) — final

| Class | Element | Notes |
|---|---|---|
| **Preserved** | Sidebar nav, recent-runs sidebar widget | unchanged |
| **Preserved** | TopBar + breadcrumb | unchanged |
| **Preserved** | Hero card Surface gradient shell | content swaps |
| **Preserved** | Severity distribution bar | resized to h-7 |
| **Preserved** | KEV / Fix tile primitives (`PostureMetricTile`) | reused for 4 new tiles |
| **Preserved** | Sparkline primitive | reused in mini-trend |
| **Preserved** | Recharts `<AreaChart>` infrastructure | data feed swapped |
| **Preserved** | Custom trend tooltip | unchanged |
| **Preserved** | Top vulnerable SBOMs list | unchanged |
| **Preserved** | Recent activity timeline | unchanged |
| **Replaced** | Hero headline (was `Urgent attention required`) | 6 new state-specific copies |
| **Replaced** | Hero severity bar height (10px → 28px) | spec calls for ≥ 28px |
| **Replaced** | KEV/Fix/sparkline floating cluster | 4-tile inline metric row |
| **Replaced** | `derivePosture` state machine | server-side `headline_state` |
| **Replaced** | Trend chart data feed | zero-filled, with annotations |
| **Replaced** | Trend chart visual (line → stacked area) | already stacked area in v1; trade is data fix + ref line + annotations |
| **Replaced** | Quick actions primary button (always Upload) | adaptive primary by state |
| **Removed** | `Security posture · live` red dot | desensitizes the eye |
| **Removed** | `Active Projects` / `Total SBOMs` / `Distinct Vulnerabilities` cards | reincarnated in lifetime section |
| **Removed** | `Vulnerability severity` donut | redundant with severity bar |
| **Removed** | `SBOM activity` donut | covered by lifetime + trend |
| **Removed** | `Degraded · NVD mirror disabled` footer | operator concern off user surface |
| **Removed** | `degraded` and `urgent` headline states | calmer state set |
| **Added** | `<LatestRunIndicator>` inline freshness line | replaces `degraded` band, calmer |
| **Added** | 4-tile hero metric row with Net 7-day | new "what changed this week?" answer |
| **Added** | `<HeroMiniTrend>` 60×24 sparkline tile | always-on micro view |
| **Added** | "Your Analyzer, So Far" 4-tile lifetime section | answers "has the tool been working?" |
| **Added** | Trend chart annotations (sbom_uploaded · remediation · kev_first_seen) | story layer on top of the time-series |
| **Added** | Trend chart 30-day average reference line | context for any single day's value |
| **Added** | Trend chart `<EmptyTrendState>` | for first-7-days condition |
| **Added** | `GET /dashboard/lifetime` endpoint | new contract |
| **Added** | `headline_state` + `primary_action` on `/dashboard/posture` | server-side rules |
| **Added** | `unknown` + `total` fields on trend points | makes `unknown` first-class |
| **Added** | `annotations` + `avg_total` + `earliest_run_date` on trend response | new contract |
| **Added** | `Pydantic` response models for every dashboard endpoint | OpenAPI schema typed end-to-end |

---

## 16. Phase 2 gate — owner review checklist

Before approving Phase 3 to start, please confirm:

- [ ] **Headline copy table (§2.2)** reads correctly for each of the 6 states
- [ ] **State precedence (§2.1)** is correct — KEV always wins over critical-only; no_data wins over everything
- [ ] **Net 7-day uses vuln_id semantics (§3.2)**, not finding-row counts
- [ ] **Latest run line replaces the `degraded` band (§2.5)** — no separate hero state for stale data
- [ ] **Sidebar widget hides on user pages (§7.1)** — collapsed-mode dot remains as the only mirror-status hint
- [ ] **Primary action mapping (§4)** matches expectations — `kev_present → review_kev` etc.
- [ ] **Lifetime tile labels (§6.1)** — `SBOMs scanned`, `Runs executed`, `Findings surfaced`, `Monitoring for` (no deltas)
- [ ] **Trend annotation kinds (§5.4)** — `sbom_uploaded`, `remediation`, `kev_first_seen` (best-effort)
- [ ] **Empty-trend threshold = 7 days** of data, not some other cut-off
- [ ] **`/dashboard/stats` and `/dashboard/severity` keep working for one release cycle** (additive deprecation)

---

**End of Phase 2. Awaiting `continue` or revisions to copy / structure / open decisions.**
