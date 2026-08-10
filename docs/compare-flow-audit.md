# Compare SBOM flow — audit + remediation (PR 3 of 3)

**Status:** Phase 2 fixes shipped; Phase 3 code-level verification complete. **Awaiting owner live verification (browser screenshots, mobile + dark-mode parity at runtime) before merge.** See "Phase 3 verification log" at the bottom.
**Date:** 2026-05-07
**Predecessors in the sequenced refactor:**
- PR 1 — UX polish (slot-B same-SBOM-different-timestamp guard)
- PR 2 — soft delete (out of scope for this PR; do not bundle)
**This PR:** read existing compare flow critically and surface what's broken, confusing, or missing — without scope creep into the comparison engine, soft-delete awareness, or new features.

> **Methodology note (must read).** This is a **code-level** audit. The repo has no running dev server in the environment used for the audit, so the "walkthrough" reads the actual implementation files and traces what the user would experience step-for-step. Where the prompt asks for screenshots and runtime measurements (§1.8 performance, §1.9 axe, §1.10 mobile), the audit cites the existing automated coverage and the static markup; live screenshots and live-render numbers are **deferred to Phase 3 verification** when the fixes land. The owner should call out any finding here whose conclusion they don't trust without a screenshot — it'll be added to a "verify before fixing" pile.

---

## Section A — User journey walkthrough

### A.1 Discovery / entry point

Three entry paths exist:

1. **Sidebar** — [Sidebar.tsx:52](../frontend/src/components/layout/Sidebar.tsx#L52) — `Analysis ▸ Compare` (sub-item under the Analysis collapsible group).
2. **Command palette** — [CommandPalette.tsx:176](../frontend/src/components/layout/CommandPalette.tsx#L176) — "Compare runs" with `GitCompareArrows` icon.
3. **Keyboard shortcut** — [KeyboardCheatsheet.tsx:31](../frontend/src/components/layout/KeyboardCheatsheet.tsx#L31) — `g c` chord jumps to `/analysis/compare`.
4. **Analysis runs list** — [analysis/page.tsx:73-76](../frontend/src/app/analysis/page.tsx#L73-L76) — multi-select two runs, click "Compare". This is the most discoverable path; it pre-fills `?run_a=&run_b=` so the user lands on a populated page.

### A.2 Empty state (no params)

On `/analysis/compare` with no query params:

- TopBar renders title "Compare runs" + breadcrumbs.
- "Back" button (router.back()).
- Sticky `SelectionBar` with two `RunPicker` triggers (Run A · baseline / Run B · candidate), a Swap button (disabled), a Share button (disabled).
- `EmptySelectionState` card below the bar with copy: *"Pick two runs to compare. Choose a baseline run (Run A) and a candidate run (Run B) using the pickers above. We'll show what changed — added, resolved, or reclassified — between them."* ([CompareStates.tsx:55-67](../frontend/src/components/compare/states/CompareStates.tsx#L55-L67))

The empty state copy is good — it labels the slots semantically ("baseline" / "candidate") and previews the three change kinds the user will see. No onboarding tour, no example pair, no "compare your last two runs" shortcut.

### A.3 Picker behaviour

Implemented at [SelectionBar/RunPicker.tsx](../frontend/src/components/compare/SelectionBar/RunPicker.tsx).

- **Default open list:** 20 most-recent runs across all SBOMs (`GET /api/runs/recent?limit=20`). Server caps at 50.
- **Search:** 200 ms-debounced `GET /api/runs/search?q=`. Substring match on `sbom_name`, `project_name`, or numeric run id. Server caps at 50 results.
- **Same-project filter chip:** appears in the Run B picker when Run A is already selected. It's a *client-side* filter over the loaded baseOptions — narrowing a 20-row list, not asking the server for more matching rows.
- **Option label format:** `<sbom_name> #<id> · <project_name> · <date> · <STATUS>` (date, status uppercased).
- **Trigger label format (selected):** `<sbom_name> · Run #<id> · <date>`.
- **Status filter:** none — `RUNNING`, `PENDING`, `ERROR`, `NO_DATA` runs all appear in the dropdown. Picking one fires the compare API which then 409s with `RUN_NOT_READY` (or 404 / etc.).

### A.4 Loading state

When `runA != null && runB != null && runA !== runB`, TanStack Query fires `compareRunsV2()`. While in flight:

- Page renders `CompareSkeleton` ([CompareStates.tsx:12-53](../frontend/src/components/compare/states/CompareStates.tsx#L12-L53)) — three Surfaces with shimmer placeholders that match the final shape (selection / posture / body).
- No estimated time, no progress bar, no "this may take a moment for large diffs."

### A.5 Error states

Five distinct error states in [CompareStates.tsx](../frontend/src/components/compare/states/CompareStates.tsx):

| State | Trigger | Copy |
|---|---|---|
| `EmptySelectionState` | runA or runB null | "Pick two runs to compare." |
| `SameRunPickedState({runId})` | runA === runB OR backend `COMPARE_E003_SAME_RUN` | "That's the same run twice — Run #N is selected on both sides." |
| `RunNotReadyState({status?})` | backend `COMPARE_E002_RUN_NOT_READY` | "One of the runs isn't ready yet. Status: **unknown**. We'll auto-retry shortly." |
| `RunNotFoundState({runId?})` | backend `COMPARE_E001_RUN_NOT_FOUND` | "Run not found — Run #? no longer exists." |
| `PermissionDeniedState` | backend `COMPARE_E004_PERMISSION_DENIED` (reserved; not currently emitted) | "You don't have access to one of these runs." |
| `GenericCompareError` | any other thrown error | "Could not compare runs — \<message\>." |

Errors are derived in `CompareView.errorView` ([CompareView.tsx:91-109](../frontend/src/components/compare/CompareView.tsx#L91-L109)) which switches on `HttpError.code`.

### A.6 Loaded state — Region map

When the request resolves, the page composes:

1. **Selection bar** (sticky) — picker triggers + Swap + Share + RelationshipDescriptor row.
2. **Region 2** — either:
   - `IdenticalRunsCard` (when added + resolved + severity_changed === 0) — celebratory empty state with one of three sub-variants ("both clean", "no overlap", "shared"), or
   - `PostureHero` — `HeroHeadline` + `BigNumbersColumn` + `DistributionBarLarge` + lazy-loaded `Sparkline` (only when shared SBOM) + three `PostureTile`s (KEV exposure / Fix-available coverage / High+Critical exposure).
3. **TabsAdaptive** — three tabs: Findings (default), Components, Posture detail. Each tab shows a `(N)` count badge. Findings tab shows a coloured dot when added findings include critical/high.
4. **Tab body** — one of FindingsTab / ComponentsTab / PostureDetailTab.
5. **ExportDialog** (modal) — markdown / csv / json formats, server-side serialised from cached payload.
6. **KeyboardShortcutsOverlay** — keyboard help overlay.

### A.7 Findings tab body

[FindingsTab/FindingsTab.tsx](../frontend/src/components/compare/FindingsTab/FindingsTab.tsx) + [FilterChipsAdaptive](../frontend/src/components/compare/FilterChipsAdaptive/FilterChipsAdaptive.tsx) + [FindingsTable](../frontend/src/components/compare/FindingsTab/FindingsTable.tsx) + [FindingRowAdvanced](../frontend/src/components/compare/FindingRow/FindingRowAdvanced.tsx).

- Filter chip row: 3 change-kind chips (Added / Resolved / Severity), 4 severity chips (Critical / High / Medium / Low), 3 toggles (KEV / Fix-available / Show unchanged), Clear-all link, "Showing N of M" status.
- Free-text search input (filters by CVE id / component name / PURL).
- Table with columns: Change | CVE / Advisory | Severity | Component | Attribution.
- Each row is fully clickable (whole row opens `CveDetailDialog`).
- Severity gradient on the left edge + 4 px change-kind border colour.
- KEV / EPSS / FIX badges per row.
- Hover card on CVE id reads from query cache; never fetches.

### A.8 Components tab body

[ComponentsTab/ComponentsTab.tsx](../frontend/src/components/compare/ComponentsTab/ComponentsTab.tsx).

- Local-state search input (NOT URL-driven) and "Show unchanged" checkbox.
- Banner alert when any `hash_changed` row is present (supply-chain alarm) — but the engine cannot emit `hash_changed` today since `content_hash` isn't stored; the banner is dead code in v1.
- Table columns: Change | Component | Ecosystem | Version | Linked findings.
- Version transition arrow (up/down) when `version_bumped`. **Direction calculated by string comparison** of version_a vs version_b.

### A.9 Posture detail tab body

[PostureDetailTab/PostureDetailTab.tsx](../frontend/src/components/compare/PostureDetailTab/PostureDetailTab.tsx). C9 severity grid implementation per ADR-0008 PB-2.

- Two side-by-side stacked bars: severity composition for Run A and Run B (normalised to `max(totalA, totalB)` so widths are comparable).
- Two columns below: "Top risk reductions" (top 5 resolved findings by KEV/severity/fix-available rank) and "Top risk introductions" (same ranking; top 5 added).
- No row interaction — read-only analytical view.

---

## Section B — Issues found (severity-classified)

### 🔴 B-1 — RunPicker trigger label is "Choose a run…" when arriving via shareable URL

**Location:** [RunPicker.tsx:72-117](../frontend/src/components/compare/SelectionBar/RunPicker.tsx#L72-L117).

**Repro:** Open a shareable URL like `/analysis/compare?run_a=42&run_b=43` where neither run id is in the most-recent-20 list (e.g. you're sharing a months-old comparison with a teammate).

**Behaviour:** The compare API call succeeds and the page renders the full diff. But the picker trigger buttons in the SelectionBar still read **"Choose a run…"** because `RunPicker.selectedRun` is computed from `baseOptions` (the recent/search results), not from the resolved compare payload. The user has no way to tell which run is in slot A vs slot B from looking at the SelectionBar — only the page subtitle (`Run #42 vs Run #43`) tells them.

**Why this is a 🔴 not a 🟡:** the v2 contract per ADR-0008 §4 is "URL is the source of truth." A user landing via a shareable URL is the canonical use case — and the most visually prominent control on the page lies about state in that case.

**Why surgical to fix:** SelectionBar already receives `runASummary={data?.run_a ?? aPick}` and `runBSummary={data?.run_b ?? bPick}` — it just doesn't pass them down to RunPicker. Add a `selectedRunSummary?: RunSummary | null` prop to RunPicker and prefer it over `baseOptions.find()` when computing the trigger label.

---

### 🔴 B-2 — Components-tab version-bump arrow uses string comparison, not semver

**Location:** [ComponentsTab.tsx:121-127](../frontend/src/components/compare/ComponentsTab/ComponentsTab.tsx#L121-L127).

```ts
const direction =
  row.change_kind === 'version_bumped'
    ? (row.version_b ?? '') > (row.version_a ?? '')
      ? 'up'
      : 'down'
    : null;
```

**Repro:** A component bumps `1.9.0 → 1.10.0` (genuine forward upgrade). The string comparison `'1.10.0' > '1.9.0'` evaluates **false** (lexicographic), so the row renders a *down arrow* (amber) — visually signalling "downgrade" — for what's actually an upgrade.

**Why this is 🔴 not 🟡:** the component diff's primary visual signal in this column is *backwards* for any version pair where lexicographic order disagrees with semver order. This is the common case for any project on a 1.10+ release cycle (web, react, vite, etc.). The icon is also colour-coded (`text-emerald-600` for up, `text-amber-600` for down) so the colour is wrong too.

**Surgical fix:** Use a semver-aware comparator. The repo already imports `semver` (check `frontend/package.json`); if not present, hand-roll a string→tuple comparator (`compareSemver(a, b): -1 | 0 | 1`) that splits on `.` and compares numerically with non-numeric tail tokens losing. Limit scope: don't extend to PEP 440 / Maven semver — use a "best effort numeric segments" comparator and fall back to string compare on parse failure. ~30 LOC + one test file.

---

### 🔴 B-3 — KEV exposure undercounts when finding's primary id is non-CVE

**Location:** [compare_service.py:304-311](../app/services/compare_service.py#L304-L311) and [compare_service.py:642-651](../app/services/compare_service.py#L642-L651).

**Behaviour:** `_lookup_current_kev` queries `KevEntry` (CVE-only catalog) by the set of `f.vuln_id.upper()` values from the finding diff. For findings whose primary `vuln_id` is `GHSA-…` / `PYSEC-…` / `OSV-…` but whose CVE alias *is* in KEV, the join produces no match and the row is marked `kev_current = false`.

**Impact:** The KEV exposure tile, KEV chip, and "KEV first" ranking in the top-contributors list all undercount KEV exposure for ecosystems that produce GHSA-primary findings (npm, RubyGems, Composer, Go, NuGet, Pub, Maven, PyPI when sourced via OSV). For npm-heavy SBOMs this is a **substantial** undercount — most npm advisories surface as GHSA in OSV.

**Architectural / Phase 2 deferral:** the v2 prompt forbids architectural changes to the engine in this PR. **File a follow-up ticket: "F-10: lift CVE alias into KEV lookup."** The fix is a join through `analysis_finding.aliases` (existing JSON column, parsed by `_cve_aliases_for` at [runs.py:193-207](../app/routers/runs.py#L193-L207)) before the KEV `IN (...)` clause; in-engine work, not a schema change.

---

### 🟡 B-4 — RunNotReady banner claims "auto-retry" but never refetches

**Location:** [CompareStates.tsx:78-85](../frontend/src/components/compare/states/CompareStates.tsx#L78-L85) (copy) and [CompareView.tsx:48-58](../frontend/src/components/compare/CompareView.tsx#L48-L58) (no `refetchInterval`).

The copy reads *"Comparison will be available once the analysis finishes. We'll auto-retry shortly."* But the TanStack Query call has no `refetchInterval`, no `refetchOnWindowFocus` flag, no manual retry button. The user must reload the page or re-pick a run. The runbook §4 also describes this state as "auto-poll" but the frontend doesn't.

**Surgical fix options:**
- **Honest copy + manual retry button:** Drop the auto-retry sentence. Add a `<Button>Retry</Button>` that calls `queryClient.invalidateQueries({ queryKey: ['compare', 'v2', runA, runB] })`.
- **Make copy true:** Set `refetchInterval: 5000` and `retry: 5` *only* when the last error was `COMPARE_E002_RUN_NOT_READY`. Cap the polling — don't background-poll forever; stop after 60 s and show the manual retry button.

The first option is cheaper and avoids accidentally hammering the backend on a stuck run. Recommend that.

---

### 🟡 B-5 — RunNotReady state shows "Status: unknown" even though backend returned the actual status

**Location:** [CompareView.tsx:101-103](../frontend/src/components/compare/CompareView.tsx#L101-L103) and [CompareStates.tsx:78-85](../frontend/src/components/compare/states/CompareStates.tsx#L78-L85).

The backend's error envelope for `COMPARE_E002_RUN_NOT_READY` includes `status: <RUNNING|ERROR|NO_DATA|...>` and `run_id: <int>` ([routers/compare.py:65-68](../app/routers/compare.py#L65-L68)). The HttpError class on the frontend receives the `detail` object, but `CompareView.errorView` calls `<RunNotReadyState />` without unpacking it — so the user sees `Status: unknown` instead of `Status: RUNNING`.

**Same shape** for `RunNotFoundState` ([CompareView.tsx:99](../frontend/src/components/compare/CompareView.tsx#L99) — `<RunNotFoundState />` with no `runId`). The URL has both run ids; could trivially pass `runId={urlState.runA}` (or whichever side is missing).

**Surgical fix:** Pull `detail` off the HttpError (it's already structured) and pass `status` / `runId` props through. ~5 lines.

---

### 🟡 B-6 — Components tab uses local component state for filters, not URL state

**Location:** [ComponentsTab.tsx:54-59](../frontend/src/components/compare/ComponentsTab/ComponentsTab.tsx#L54-L59).

```ts
const [needle, setNeedle] = useState('');
const [showUnchanged, setShowUnchanged] = useState(false);
```

The Findings tab persists every filter into the URL (`?q=`, `?show_unchanged=`, `?severity=`, etc.) so a user can share a filtered view. The Components tab uses `useState` — refresh resets, share-link doesn't preserve, back button doesn't restore. **Inconsistent UX between sibling tabs.**

**Surgical fix:** Add `q_components` and `show_unchanged_components` to `useCompareUrlState` (or piggy-back on the existing `q` and `show_unchanged` if cross-tab parity is acceptable — the simpler and recommended approach since the user is comparing the same diff in both tabs).

---

### 🟡 B-7 — "Same run twice" / "Run not ready" / etc. are alerts, not full empty-state surfaces

**Location:** [CompareStates.tsx:69-101](../frontend/src/components/compare/states/CompareStates.tsx#L69-L101).

`SameRunPickedState`, `RunNotReadyState`, `PermissionDeniedState`, `RunNotFoundState`, `GenericCompareError` all render via `<Alert>` — a thin band, not a centred full empty state. The picker bar (sticky, prominent) plus a thin alert below it can read like "the page is loaded; here's a notification" rather than "comparison is blocked." Compare to `EmptySelectionState`'s presentational weight ([CompareStates.tsx:55-67](../frontend/src/components/compare/states/CompareStates.tsx#L55-L67)) which uses `<EmptyState>` with illustration + larger title.

**Surgical fix:** Promote the four blocking error states to use the same `EmptyState` primitive as `EmptySelectionState`. Two lines per state.

---

### 🟡 B-8 — Severity filter chips have no "Unknown" toggle

**Location:** [FilterChipsAdaptive.tsx:29-34](../frontend/src/components/compare/FilterChipsAdaptive/FilterChipsAdaptive.tsx#L29-L34).

The chip row has Critical / High / Medium / Low — but `unknown` is in the URL state's valid severities set ([useCompareUrlState.ts:40-46](../frontend/src/hooks/useCompareUrlState.ts#L40-L46)) and findings can carry it. If a user toggles all four visible severity chips off, the resulting set is `{unknown}` — only unknown rows show — but they have no way to *toggle* unknown without manually editing the URL.

The dim-when-zero behaviour helps in the common case (most prod diffs have no unknown findings), but if a CVE feed imports a finding with unspecified severity, the user has no way to focus on it.

**Surgical fix:** Add a fifth chip `Unknown` with `border-slate-300 bg-slate-100 text-slate-900` styling. The dim-when-zero behaviour from `sevCounts.get('unknown') ?? 0` already keeps it visually subdued in the common case.

---

### 🟡 B-9 — `direction_warning` produces awkward copy when delta is sub-day

**Location:** [compare_service.py:626-631](../app/services/compare_service.py#L626-L631).

```python
direction_warning = (
    f"Run B is older than Run A by {abs(days_between):.1f} days "
    f"— did you mean to swap?"
)
```

If days_between is `-0.04` (≈1 hour reversed), the formatted output is `"Run B is older than Run A by 0.0 days — did you mean to swap?"` — confusingly says "0.0 days." For minute/hour-scale reversals (the most common case for a same-SBOM rerun where a user fat-fingers slot A and B), this is actively confusing.

**Surgical fix:** Format like `RelationshipDescriptor` already does — `< 1h`, `Nh`, `N.N days`. Move the formatter into a shared helper (or inline). ~10 LOC.

---

### 🟡 B-10 — Picker shows ineligible runs (RUNNING / ERROR / NO_DATA) without visual hint

**Location:** [routers/runs.py:154-193](../app/routers/runs.py#L154-L193) (server returns all statuses) and [RunPicker.tsx:202-251](../frontend/src/components/compare/SelectionBar/RunPicker.tsx#L202-L251) (client renders status as text but doesn't dim or block).

A user can pick a `RUNNING` run, then hit a `RUN_NOT_READY` error after the request fires. The picker option does show `· RUNNING` in muted text, but it's not visually de-emphasised relative to selectable rows. Picking it costs a round-trip and a confusing banner.

**Surgical fix options:**
- **Dim ineligible runs** in the dropdown (50% opacity, with a tooltip explaining why). Still selectable so power users can force the call and see the not-ready banner.
- **Filter ineligible runs server-side.** Add a `?status_in=OK,FINDINGS,PARTIAL` flag to `/api/runs/recent` and `/api/runs/search`. Backend change. Cleaner but bigger blast radius.

Recommend the first option — purely client-side, two extra props on each `<li>`.

---

### 🟡 B-11 — No loading affordance when the compare API takes >1 second

**Location:** [CompareStates.tsx:12-53](../frontend/src/components/compare/states/CompareStates.tsx#L12-L53).

The skeleton shows immediately and stays as long as the request is in flight. There is no "this is taking longer than usual" hint, no progress indicator, no time-elapsed counter. For a typical compare on the bundled SQLite the runbook §7 says p95 < 1.2 s (cold) — fine. For 1000+ findings each side on a slow connection or a hot worker, anecdotally 3–5 s is plausible; the skeleton offers no reassurance.

**Surgical fix:** When the query has been pending > 2 seconds, show a sub-bar under the skeleton: *"Computing diff — large runs can take a few seconds."* TanStack Query's `isFetching` plus a `useEffect` setTimeout matches the pattern used for the AI batch progress banner (per the prompt's reference). ~15 LOC.

---

### 🟡 B-12 — Whole-row click on findings table fights the intent of copying a CVE id

**Location:** [FindingRowAdvanced.tsx:78-94](../frontend/src/components/compare/FindingRow/FindingRowAdvanced.tsx#L78-L94).

`<tr onClick={onOpen}>` makes the entire row a single click target — clicking the CVE id, the component name, the attribution text, anywhere in the row, opens the `CveDetailDialog`. Users who want to *copy* the CVE id by double-clicking it find that the dialog opens instead and select-on-focus inside the dialog grabs focus.

**Surgical fix:** Either:
- Add `onMouseDown={(e) => { if (e.detail > 1) e.preventDefault(); }}` to allow double-click to select text (works in WebKit/Blink), or
- Change the trigger from a row click to a dedicated "View details" button at the end of the row + keyboard `Enter` on the row, *or*
- Wrap the CVE id span with `onClick={(e) => e.stopPropagation()}` so clicks on it don't bubble to the row.

Recommend the third — minimal change, preserves whole-row click for the rest.

---

### 🟡 B-13 — Component tab "Supply-chain alert" banner is dead code in v1

**Location:** [ComponentsTab.tsx:61-75](../frontend/src/components/compare/ComponentsTab/ComponentsTab.tsx#L61-L75).

The banner only appears when at least one row has `change_kind === 'hash_changed'`. The engine never emits that kind today: `compare_license_hash_enabled` is `false` by default and `content_hash` isn't stored on `sbom_component`. Per the discovery doc §2 and the runbook, this is expected — but the dead UI code clutters the tab and confuses anyone code-spelunking. Either remove it (and reintroduce when content_hash lands) or annotate it as feature-flagged.

**Recommendation:** Leave the banner code but move the gate behind an explicit `if (process.env.NEXT_PUBLIC_COMPARE_HASH_ALERT_ENABLED === 'true')`-style toggle so tree-shaking removes it from bundles where the column isn't populated. Or just delete and resurrect via git history when the feature ships. **Defer to follow-up — not a Phase 2 fix.**

---

### 🟡 B-14 — Cross-ecosystem name collisions in finding identity

**Location:** [compare_service.py:386-411](../app/services/compare_service.py#L386-L411). Identity = `(vuln_id, component_name.lower(), component_version)`. **Ecosystem is not part of the key.**

A finding for `requests@2.20.0` (PyPI) in run A will collide with a finding for `requests@2.20.0` (npm — yes, [npm has a `requests` package too](https://www.npmjs.com/package/requests)) in run B. They'll be diffed as the same finding even though they're different packages. The component diff *does* key on ecosystem (line 352), so component-level identity is correct — but the finding diff doesn't.

**Architectural follow-up:** Add `ecosystem` to `_FindingKey` and `_attribute_findings`'s strict map. Per the discovery doc §3, finding identity was deliberately weakened from `(vuln_id, component_purl)` because findings often lack purl when CPE-matched. The fix is to use `_purl_ecosystem(component_purl)` when available and fall back to `(name, "unknown")` only when purl is null — matching the component-diff identity.

**File a follow-up ticket: "F-11: ecosystem-aware finding identity."** Not a Phase 2 fix; the mitigation rate (chance of a real collision) is low for typical SBOMs.

---

### 🔵 B-15 — No comparison history / saved comparisons

The compare cache is a *transparent* 24 h-TTL cache, not a "history" surface. Once a user compares two runs, there's no list of "comparisons I've recently viewed." Every visit is a fresh URL-pasting exercise.

The prompt explicitly puts saved comparisons OUT of scope (§4 "Out of scope"). Listing here only so the audit doesn't mis-imply that absent-history is a defect — it's an explicit non-feature.

---

### 🔵 B-16 — Sparkline silently hides when SBOM has < 2 historical runs

**Location:** [Sparkline.tsx:68-69](../frontend/src/components/compare/Sparkline/Sparkline.tsx#L68-L69).

```tsx
if (sbomId == null || isError) return null;
if (series.length < 2) return null;
```

When a user runs a compare for a brand-new SBOM (only 1 prior run, or first-ever run), the sparkline strip simply doesn't render. There's no "not enough history yet" hint. For a power user who knows the sparkline exists this is fine; for first-time users it can be a "where did the chart go between visits?" mystery.

**Recommendation:** Render a flat dotted line + "first run for this SBOM" caption when `series.length < 2`. Low priority — small quality-of-life polish.

---

### 🔵 B-17 — `findings_unchanged_count` counted but FindingsTable's "Show unchanged" is a separate axis

This isn't a bug, but it's worth recording. The user can:

1. Toggle "Show unchanged" chip in FilterChipsAdaptive — this only flips visibility, it doesn't *re-rank* unchanged rows alongside the changes. They appear at the bottom (KIND_RANK = 3) when shown.
2. Ranking heuristic `severity_changed → added → resolved → unchanged → severity-desc → vuln_id` works well for a triage view but might surprise users who expect "what changed first."

---

## Section C — Edge case results (deliberate)

These are reasoned from the code paths, not run live. Each notes which path the engine and frontend take.

| # | Edge case | Engine path | Frontend render | Verdict |
|---|---|---|---|---|
| 1 | Pick same run id in both slots | Frontend `urlState.runA === urlState.runB` short-circuits before query fires; engine never sees the request. Backup: backend raises `SameRunError` (400). | `<SameRunPickedState />` alert. | ✅ Guarded twice, both layers. |
| 2 | Both runs entirely empty (zero findings each) | All four count fields are 0; `isIdenticalRuns()` returns true; variant is `both-clean`. | `IdenticalRunsCard` "No vulnerabilities in either run." | ✅ Correct, celebratory. |
| 3 | Two SBOMs with no findings in common (cross-SBOM) | Engine diffs as ADDED (B side) + RESOLVED (A side). `unchanged === 0`. | `PostureHero` (NOT IdenticalRunsCard, since added > 0 ∨ resolved > 0). | ✅ Correct. |
| 4 | Two SBOMs from different ecosystems (npm vs maven) | Component diff treats every component as ADDED (B side) + REMOVED (A side) since `_ComponentKey` includes ecosystem. Finding diff CAN collide on `(vuln_id, name, version)` if any name happens to overlap. See B-14. | `PostureHero` with very large added/resolved counts. Banner / hint that "this looks more like two unrelated SBOMs"? **None.** | 🟡 No "you might have meant to compare runs of the same SBOM" hint. |
| 5 | Oldest available SBOM vs newest | `_compute_relationship` sets `same_sbom: false`, `same_project: ?`, `days_between: <large>`. No special copy. | `HeroHeadline` sub-line: "Cross-project compare." | ✅ Generic but works. |
| 6 | Refresh after running a comparison | URL is the source of truth. Page re-mounts, query re-fires, hits 24 h cache (compare_cache table). Result is identical to pre-refresh. | Same view, ~50–200 ms warm. | ✅ Stable. |
| 7 | Browser back after running a comparison | `setRuns` and `setTab` push history entries. Filters replace. Back navigates through run-pair changes and tab changes, but skips filter toggles. | Per ADR-0008 §8 — works as designed. | ✅. |
| 8 | Two tabs comparing different runs concurrently | Each tab has its own URL state; query keys are `['compare', 'v2', a, b]`. No shared state pollution. Picker open/close is local state, no leak. | Independent. | ✅ Isolated. |
| 9 | Run A older than Run B (forward direction) | `direction_warning` is null. | RelationshipDescriptor reads "Same SBOM, re-scanned · Nh apart". | ✅. |
| 10 | Run A newer than Run B (reverse direction) | `direction_warning` is set with awkward "0.0 days" copy when sub-day. See B-9. | RelationshipDescriptor renders amber pill with the warning + "Swap A and B" button. | 🟡 (B-9 awkward copy). |
| 11 | Picking a `RUNNING` run | Backend 409 with status="RUNNING". Frontend renders `RunNotReadyState` with "Status: unknown". See B-5, B-10. | 🟡 picker has no visual hint; banner copy lies about auto-retry. | 🟡 (B-4, B-5, B-10). |
| 12 | Picking a deleted run id (404) | Backend `RunNotFoundError`. Frontend renders `RunNotFoundState` with "Run #?" instead of run id. See B-5. | 🟡 unhelpful "Run #? no longer exists." | 🟡 (B-5). |
| 13 | Cache_corrupt path (stale schema_version) | Service deletes the row, recomputes, returns fresh result. Logs `compare cache_corrupt cache_key=…`. | Transparent to the user. | ✅ Logged; no UI bleed. |
| 14 | Identical-run pair where unchanged is 0 too (both clean SBOMs) | `findings_unchanged_count === 0` AND total_findings === 0 on both sides → variant `both-clean`. | "No vulnerabilities in either run." | ✅. |

---

## Section D — Performance numbers (reasoned, not measured)

The audit didn't run live perf tests. Numbers cited are from the test-suite measurements recorded in [docs/runbook-compare.md §7](runbook-compare.md):

| Metric | Source value | Comment |
|---|---|---|
| Cold compare, ≤ 10 findings each | < 50 ms | Trivial diff. |
| Cold compare, ~500 findings each | ~250 ms | One-pass diff dominated by 2× component fetch + 2× finding fetch. |
| Cold compare, ~1000 findings each (typical) | ~500–800 ms (extrapolated, NOT measured) | Linear in `findings + components`. |
| Warm cache hit | < 20 ms | Single PK lookup on `compare_cache`. |
| Markdown / CSV export | < 30 ms | Re-serialise cached payload. |
| JSON export | < 50 ms | As above. |

**What the audit cannot tell you without measurements:**

- Frontend render time for a 1000-row findings table. The table is not virtualised; React renders all rows on mount. At ~72 px per row this is 72,000 px of DOM — likely 100–300 ms layout cost on a mid-range machine. **Worth measuring before deciding whether to virtualise** (don't pre-optimise; do confirm).
- Whether the `useMemo` in `FindingsTab.applyFilters` is fast enough on every filter chip toggle. The function is O(N log N) per call (sort included). At N = 5000 should be < 50 ms — fine.
- Whether the `Sparkline` lazy-load actually defers render correctly under realistic LCP conditions.

**Phase 3 verification step:** spin up the dev server, paste a large fixture (5000+ findings each) through `tests/fixtures/spdx_2_3_realistic.json`, time:
- API call (DevTools network tab — confirm cold path stays under 1.5 s on the bundled SQLite).
- Time-to-interactive on the findings table (DevTools Performance tab).
- Filter toggle latency (chip click → re-render).

If TTI > 500 ms with 5000 rows, file a follow-up ticket for table virtualisation; do NOT bundle into this PR.

---

## Section E — Recommended scope for Phase 2

Phase 2 should fix the issues that are surgical, low-risk, and high-value. The feedback memory says strict scope discipline; sticking to that here.

### Strongly recommended (in scope for Phase 2)

| # | Issue | Why now | Effort |
|---|---|---|---|
| **B-1** | Picker trigger label lies on shareable URLs | Shareable URLs are *the* compare contract per ADR-0008 §4. Currently broken. | ~15 LOC + 1 test. |
| **B-2** | Components version-bump arrow uses string compare | Visual signal is backwards for any 1.10+ project. Common. | ~30 LOC + 1 test. |
| **B-4** | RunNotReady "auto-retry" copy lies | Trivial copy fix; user trust matters. | ~5 LOC. |
| **B-5** | Error states drop structured detail (run id, status) | Backend already returns it. | ~5 LOC. |
| **B-6** | Components tab filters not URL-driven | Inconsistency between Findings & Components tabs is confusing; trivially fixable by reusing `q` and `show_unchanged`. | ~10 LOC. |
| **B-9** | "0.0 days" awkward copy | Trivial format fix. | ~5 LOC. |

Total surface for these six: ~70 LOC, ~3 new tests, scoped to specific files. No engine changes. No schema changes. No new endpoints.

### Recommended but optional (owner choice)

| # | Issue | Trade-off |
|---|---|---|
| **B-7** | Promote alert-band errors to full empty states | Polishing; ~10 LOC. Could bundle. |
| **B-8** | Add "Unknown" severity chip | Real but rare. Skip if you want zero scope expansion. |
| **B-10** | Dim ineligible runs in picker | Useful but slightly larger (visual + copy). Could bundle as 1-line opacity change. |
| **B-11** | "Taking longer than usual" hint after 2s | Polishing; ~15 LOC. Bundle if doing B-4 anyway (same file). |
| **B-12** | Stop CVE-id click from opening dialog | Affects copy-paste flow. Worth fixing; ~5 LOC. |

### Defer to follow-ups (NOT for Phase 2)

- **B-3** (KEV alias undercount) — file as **F-10**; engine change.
- **B-13** (dead `hash_changed` banner) — file alongside future content_hash work.
- **B-14** (cross-ecosystem finding identity) — file as **F-11**; engine change.
- **B-15** (saved comparisons) — explicit out-of-scope per prompt §4.
- **B-16** (sparkline hide when 1 run) — minor polish; not worth bundling.
- **B-17** (unchanged ranking) — design decision; not a defect.

### Anti-fixes I deliberately did NOT propose

- **No findings table virtualisation.** No measured proof yet that it's needed.
- **No comparison-engine refactor.** Constraint §4 says don't.
- **No new metric types or comparison axes.** Constraint §4 says don't.
- **No URL format changes.** Constraint §4 says shareable URLs must remain compatible.
- **No soft-delete-aware comparison.** PR 2 hasn't shipped; this PR cannot be filter-aware until then.

---

## Phase 1 gate

Owner: please mark each Phase 2 fix as **APPROVED / DEFERRED / REJECT** for the six issues in "Strongly recommended" above, and indicate whether the five "Recommended but optional" items should bundle. After your approval I'll start Phase 2 — surgical fixes only on the approved list, with before/after screenshots captured at Phase 3 verification time.

---

## Appendix A — Files I expect to touch in Phase 2

For the strongly-recommended set:

**Frontend**
- [components/compare/SelectionBar/SelectionBar.tsx](../frontend/src/components/compare/SelectionBar/SelectionBar.tsx) — pass new props to RunPicker.
- [components/compare/SelectionBar/RunPicker.tsx](../frontend/src/components/compare/SelectionBar/RunPicker.tsx) — accept `selectedRunSummary` prop, prefer it for trigger label.
- [components/compare/CompareView.tsx](../frontend/src/components/compare/CompareView.tsx) — extract HttpError detail; pass to error-state components.
- [components/compare/states/CompareStates.tsx](../frontend/src/components/compare/states/CompareStates.tsx) — drop misleading auto-retry copy; accept run id in 404 state.
- [components/compare/ComponentsTab/ComponentsTab.tsx](../frontend/src/components/compare/ComponentsTab/ComponentsTab.tsx) — use URL state hooks for `q` and `show_unchanged`; replace string version compare with semver-aware helper.
- [lib/compareSemver.ts](../frontend/src/lib/compareSemver.ts) (new, ~30 LOC + tests).
- [components/compare/__tests__/](../frontend/src/components/compare/__tests__/) — three new tests (URL-only-share picker label, semver direction, error-state detail forwarding).

**Backend**
- [app/services/compare_service.py](../app/services/compare_service.py) — replace `direction_warning` formatter to match `RelationshipDescriptor` time-bucketing.
- [tests/test_compare_service.py](../tests/test_compare_service.py) — add `_format_direction_warning` test.

**Docs**
- [docs/compare-flow-audit.md](compare-flow-audit.md) — append Phase 2 / Phase 3 verification log under "Status."

No new endpoints, no migrations, no new dependencies (semver compare can be hand-rolled).

## Appendix B — What this audit deliberately did NOT inspect

- Live runtime performance under representative load.
- Live screenshots of every state at 1440 × 900, 360 × 640, light + dark mode.
- vitest-axe runs against the live tree (existing tests at [components/compare/__tests__/CompareView.axe.test.tsx](../frontend/src/components/compare/__tests__/CompareView.axe.test.tsx) cover empty / same-run / error / loaded / identical-runs states; gaps are the picker open state, the export dialog open state, and the keyboard-shortcuts overlay).
- Cross-browser parity (Safari / Firefox / Chrome).
- The v1 `_v1/page.tsx` fallback rendering (assumed working; out of scope unless owner flags it).
- Auth flow integration (Compare page assumes the parent layout has handled auth — same assumption every other page makes).

These belong in Phase 3 verification once fixes are in. The audit's job is to identify *what* to fix; live verification is *how we prove* it.

---

## Phase 3 verification log (2026-05-07)

Owner approval landed on **all six** strongly-recommended fixes. They shipped in the same session; this log is the proof-of-work.

### What was done

| Audit ref | Fix | Files touched | Test added |
|---|---|---|---|
| **B-1** | RunPicker prefers parent-supplied `selectedRunSummary` for the trigger label | [RunPicker.tsx](../frontend/src/components/compare/SelectionBar/RunPicker.tsx), [SelectionBar.tsx](../frontend/src/components/compare/SelectionBar/SelectionBar.tsx) | `RunPicker.test.tsx` — "uses the parent-supplied summary for the trigger label when the id is not in the recent list" |
| **B-2** | New `compareVersions()` helper; ComponentsTab uses it | [compareVersions.ts](../frontend/src/lib/compareVersions.ts) (new), [ComponentsTab.tsx](../frontend/src/components/compare/ComponentsTab/ComponentsTab.tsx) | `compareVersions.test.ts` — 5 cases incl. `1.10.0 > 1.9.0` |
| **B-4** | `RunNotReadyState` drops misleading "auto-retry" copy; renders manual `Retry` button calling `refetch()` | [CompareStates.tsx](../frontend/src/components/compare/states/CompareStates.tsx), [CompareView.tsx](../frontend/src/components/compare/CompareView.tsx) | `CompareView.integration.test.tsx` — "auto-retry" string absent; Retry button present |
| **B-5** | Error states accept `runId` + `status` props; `CompareView.errorView` lifts them off `HttpError.detail`. **Plus:** latent `api.ts` parser bug fixed — was reading `body.detail.code` when compare/cves emit `error_code`; now reads `error_code ?? code`. Without this, no compare error code ever matched in production. | [api.ts](../frontend/src/lib/api.ts), [CompareStates.tsx](../frontend/src/components/compare/states/CompareStates.tsx), [CompareView.tsx](../frontend/src/components/compare/CompareView.tsx) | Integration test verifies "Run #2 isn't ready yet" + "RUNNING" + "Run #99 no longer exists" |
| **B-6** | ComponentsTab uses `useCompareUrlState` for `q` and `showUnchanged` (shared with FindingsTab — same intent across tabs) | [ComponentsTab.tsx](../frontend/src/components/compare/ComponentsTab/ComponentsTab.tsx) | Existing tests still pass; URL state covered indirectly |
| **B-9** | New `_format_time_gap()` helper. `direction_warning` reads e.g. *"by 2 hours"* / *"by 1.5 days"* instead of *"by 0.0 days"* | [compare_service.py](../app/services/compare_service.py) | `test_compare_service.py::test_format_time_gap_buckets_match_relationship_descriptor` |

### Test results (code-level proof)

| Suite | Tests | Result |
|---|---|---|
| Frontend — full suite | 348 / 348 | ✅ pass (46 files) |
| Frontend — `compare/__tests__` | 103 / 103 | ✅ pass (11 files) |
| Frontend — `CompareView.axe` | 5 / 5 | ✅ zero axe violations across empty / same-run / error / loaded / identical-runs states |
| Frontend — `lib` + `hooks` | 107 / 107 | ✅ pass |
| Backend — compare suite (service + router + v1 deprecation) | 31 / 31 | ✅ pass |
| TypeScript `tsc --noEmit` | clean for compare files | ✅ (3 pre-existing errors in `dashboard/FindingsTrendChart`, unrelated) |

### Mobile + dark-mode parity (code review only — see "Outstanding")

The only **new visible markup** is the Retry button in `RunNotReadyState`:

- `<Button variant="secondary">` uses theme tokens (`bg-surface`, `text-hcl-navy`, `border-border`, `hover:bg-surface-muted`) — all defined for both `:root` and `.dark` in `globals.css`. Dark-mode safe.
- The button sits inside `<div className="flex flex-wrap items-center gap-3">` — wraps below the status text on 360 px viewports.
- Alert `variant="warning"` already has both light (`amber-50`) and dark (`amber-950/40`) classes.

All other fixes are **logic-only or copy-only** and don't introduce new markup:
- B-1: trigger button content is the same `<span>`; only its content changes.
- B-2: same `Arrow` icon, same colour palette; only `direction` flips for affected version pairs.
- B-5: same banner shape; copy now interpolates structured detail.
- B-6: same input + checkbox; only the state source changes.
- B-9: backend-only string change; affects the existing amber `direction_warning` chip's text length.

No light-only or dark-only classes introduced. No 360 px overflow risks identified in the diff.

### Latent bug surfaced + fixed during Phase 2

While wiring B-5 I discovered the `api.ts` JSON-error parser was reading `body.detail.code` while the compare and cves routers emit `body.detail.error_code`. Net effect: **every compare error in production was falling through to `GenericCompareError`** — the structured banners (RunNotReady, RunNotFound, SameRunPicked, PermissionDenied) never rendered for real backend errors. Existing integration tests passed because they construct `new HttpError(...)` directly, bypassing the parser.

The one-line fallback `code = body.detail.error_code ?? body.detail.code` restores the contract without breaking any caller still using `code`. This was strictly required to make B-5 land — surfacing structured `runId` / `status` is moot if the error code never matches. Recorded here so it doesn't read like undocumented scope drift.

### Outstanding — owner verification required

Phase 3 of the prompt asks for screenshots, browser-based 360 px checks, and live light + dark mode parity. **The audit environment has no live browser**, so these are deferred to the owner. Suggested smoke checklist:

- [ ] Open `/analysis/compare?run_a=<old-id>&run_b=<old-id+1>` where neither id appears in recent runs → **B-1:** picker triggers should show the SBOM names + run numbers, not "Choose a run…".
- [ ] Compare two runs of a project on the 1.10+ branch (e.g. anything with React 18 → 19, Next 15 → 16) → **B-2:** Components tab version-bump arrow points up + green for the upgrade.
- [ ] Trigger `RUN_NOT_READY` by picking a `RUNNING` run → **B-4 + B-5:** banner reads "Run #N isn't ready yet · Status: RUNNING" with a Retry button (no "auto-retry shortly").
- [ ] Trigger `RUN_NOT_FOUND` by hand-editing the URL with a deleted run id → **B-5:** banner reads "Run #N no longer exists" (specific id, not "Run #?").
- [ ] In Components tab, type a search and toggle "Show unchanged" → reload → **B-6:** state restored. Click into Findings tab — same `q` and `showUnchanged` apply.
- [ ] Pick run pair where B is ~2 hours older than A → **B-9:** amber direction-warning pill reads "Run B is older than Run A by 2 hours" (not "0.0 days").
- [ ] Toggle dark mode on each of the above; resize to 360 px width and confirm Retry button + warning pill don't overflow.

If any of those fail, comment the audit ref against the failure and I'll re-open Phase 2 surgically.

### Deferred follow-ups (file as separate tickets, NOT part of this PR)

| Ticket id | Source | Brief |
|---|---|---|
| **F-10** | B-3 | KEV alias-aware lookup. Lift CVE alias from `analysis_finding.aliases` before the `KevEntry IN (...)` clause. Engine change. |
| **F-11** | B-14 | Ecosystem-aware finding identity. Add `ecosystem` to `_FindingKey` so `requests@2.20.0 (npm)` and `requests@2.20.0 (PyPI)` don't collide. Engine change. |
| **F-12** (suggested) | B-7, B-8, B-10, B-11, B-12, B-16 | UX polish bundle — promote alert-band errors to `EmptyState`, add Unknown severity chip, dim ineligible runs in picker, "taking longer than usual" hint, stop CVE-id click from opening dialog, sparkline 1-run fallback caption. Frontend-only; ~100 LOC total. |

### Sign-off block (owner please tick)

- [ ] B-1 verified live
- [ ] B-2 verified live
- [ ] B-4 verified live
- [ ] B-5 verified live
- [ ] B-6 verified live
- [ ] B-9 verified live
- [ ] Mobile 360 px clean
- [ ] Light + dark mode parity clean
- [ ] Approve merge of PR 3 of 3
