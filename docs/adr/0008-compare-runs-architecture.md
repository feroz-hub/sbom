# ADR-0008 — Compare Runs v2 architecture (strangler on v1)

- **Status:** Accepted (2026-05-01) — implemented and tested in the same PR. See §13 for delivered artefacts.
- **Context:** [docs/compare-discovery.md](../compare-discovery.md)
- **Authors:** Feroze Basha (FBT) / Claude
- **Supersedes:** the v1 compare surface — preserved at [frontend/src/app/analysis/compare/_v1/page.tsx](../../frontend/src/app/analysis/compare/_v1/page.tsx) (un-routable; emergency kill-switch only) and [app/routers/analysis.py:22](../../app/routers/analysis.py#L22) (deprecated v1 endpoint, sunset 2026-12-31)
- **Related:** [docs/adr/0001-dashboard-posture-model.md](0001-dashboard-posture-model.md), [docs/risk-index.md](../risk-index.md), [docs/features/cve-detail-modal.md](../features/cve-detail-modal.md), [docs/features/compare-runs.md](../features/compare-runs.md), [docs/runbook-compare.md](../runbook-compare.md)

## Context

Phase 1 ([docs/compare-discovery.md](../compare-discovery.md), 2026-04-30) found that compare v1 ships with three correctness gaps and three security gaps:

**Correctness:**
- C-1. Diff identity is plain `vuln_id` set diff — collapses CVE-X-against-package-A and CVE-X-against-package-B into one entry, hiding both events.
- C-2. `severity_delta` is aggregate count subtraction (B − A), not per-finding severity transitions. Hides the case where one CVE was reclassified Medium → Critical.
- C-3. No relationship awareness — happily diffs across projects, across SBOMs, across direction (B older than A) without warning the user.

**Security:**
- S-1. v1 endpoint at `/api/analysis-runs/compare` has no auth dep; any unauthenticated client can read run findings.
- S-2. v1 endpoint has no run-status guard — diffs `RUNNING` or `ERROR` runs and returns nonsense.
- S-3. v1 endpoint loads `SELECT *` from `analysis_finding` for both runs into Python lists, with no streaming or row cap.

**Functional gaps surfaced in Phase 1:**
- No in-page run pickers (users bounce back to `/analysis` to swap runs).
- No component-level diff (only finding-level), so users can't answer "what upgrade fixed this CVE?"
- No risk delta region anchored to defensible signals.
- No keyboard nav, no export, no share button.
- No mobile adaptation.

## Decision

### 1. Strangler, not parallel build

V2 is a **strangler** on v1, not a coexisting alternative:

- The frontend [page.tsx](../../frontend/src/app/analysis/compare/page.tsx) is rewritten in place. No `?v=2` flag, no `compare_v2_enabled` rollout flag. A single emergency rollback kill-switch is documented in §1.1 below.
- The backend v1 endpoint at `GET /api/analysis-runs/compare` stays, marked deprecated (HTTP `Deprecation: true` and `Sunset` headers), to avoid breaking any external consumers (CI scripts, the existing CSV/SARIF tooling siblings). It is **also patched** to fix S-1 and S-2 (auth was already wired via `_protected`; the remaining patches are status-guard + structured error envelopes + telemetry counter + deprecation headers).
- The new canonical endpoint is `POST /api/v1/compare`, request body `{run_a_id: int, run_b_id: int}`. SSE-streaming variant for large diffs at `POST /api/v1/compare/stream` arrives in a follow-up once the FE progressive-render loop is built.
- Once telemetry shows v1 endpoint hit-rate at <1% of v2 for two consecutive weeks, the v1 endpoint is deleted in a follow-up minor release. Telemetry sources in §1.2 below.

#### 1.1 Emergency kill-switch contract

Two env vars, one for each tier. The frontend's value is the load-bearing one (it controls what the user sees). The backend's value is a verification echo so ops can confirm deployment from a single curl.

| Env var | Tier | Read location | Effect when `true` |
|---|---|---|---|
| `NEXT_PUBLIC_COMPARE_V1_FALLBACK` | Frontend (Next.js, baked at build time per Next convention) | [frontend/src/app/analysis/compare/page.tsx](../../frontend/src/app/analysis/compare/page.tsx) at module load — `process.env.NEXT_PUBLIC_COMPARE_V1_FALLBACK === 'true'` | Default export renders the preserved `frontend/src/app/analysis/compare/_v1/page.tsx` component. URL parsing is preserved verbatim (`?run_a` / `?run_b`); v2 query params are ignored. Banner at top: "Compare is temporarily running on v1 — full features will return shortly." No maintenance page; users keep working with reduced fidelity. |
| `COMPARE_V1_FALLBACK` | Backend ([app/settings.py](../../app/settings.py)) | `Settings.compare_v1_fallback`, exposed in `GET /health` payload as `compare_v1_fallback: true\|false` | No backend behaviour change — `POST /api/v1/compare` still serves correctly. The env value is exposed solely as a deployment verification signal so ops can confirm both tiers were flipped together. |

**Verification protocol in staging** (must run before flipping in prod):

1. Deploy with `NEXT_PUBLIC_COMPARE_V1_FALLBACK=true` and `COMPARE_V1_FALLBACK=true` set in the staging env.
2. `curl https://staging.example/health | jq .compare_v1_fallback` → expect `true`.
3. Open `https://staging.example/analysis/compare?run_a=1&run_b=2` in a browser → expect the v1 page to render with the fallback banner.
4. Tick: copy the cache-key URL from the v1 page (it has none) → verify v1 contract is preserved.
5. Unset both env vars → redeploy → repeat steps 2–3 → expect `false` and v2 rendering.

Both tiers must be flipped together. Flipping only one is unsupported — frontend without backend means the page renders v1 but the `/health` echo lies; backend without frontend means the `/health` echo says fallback is on but users see v2.

#### 1.2 v1 deprecation telemetry

Three signals available without adding Prometheus infra:

1. **Structured WARNING-level log** on every v1 call: `compare_v1_deprecated_call run_a=… run_b=… total_calls=… sunset=…`. Operators grep / sum / aggregate.
2. **In-process counter** at `app.routers.analysis.get_compare_v1_call_count()` — read-only accessor for tests and a future ops admin endpoint. Process-local; multi-worker totals require log aggregation.
3. **`Deprecation: true` and `Sunset` HTTP headers** on every response — caching proxies and SDKs will surface these to their users, narrowing the long tail.

Removal threshold: <1% relative traffic vs `POST /api/v1/compare` for two consecutive weeks. Measured by summing the WARNING log lines and comparing to the access-log count for the v2 endpoint over the same window.

### 2. Three regions stacked vertically

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Region 1 — Selection bar                                  sticky top    │
├──────────────────────────────────────────────────────────────────────────┤
│  Region 2 — Posture delta                                  sticky        │
├──────────────────────────────────────────────────────────────────────────┤
│  Region 3 — Tabbed body (Findings | Components | Delta)    scrollable    │
└──────────────────────────────────────────────────────────────────────────┘
```

(See §5 for wireframes.)

### 3. Posture delta, not "risk score"

**Renamed and rebuilt.** Per [docs/risk-index.md](../risk-index.md), an opaque severity-weighted scalar was already removed from this product two days ago. Reintroducing one as "risk score" reopens the same wound. Region 2 instead shows three independently-defensible deltas, each anchored to a public source:

- **KEV exposure** (count of findings whose CVE is currently in CISA KEV) — A vs B
- **Fix-available coverage** (% of findings with non-empty `fixed_versions`) — A vs B
- **High+Critical exposure** (count of findings at HIGH or CRITICAL severity) — A vs B

Plus the v1 distribution bar (promoted into Region 2) and the v1 severity grid (kept in Region 3 / Tab 3 — "Posture delta" — as a side-by-side bar). No portfolio-level scalar. No multiplicative formula.

See §6 for the precise definitions and §11 for the pushback rationale against the prompt's `risk_score` formula.

### 4. URL is the source of truth

```
/analysis/compare
  ?run_a=<int>
  &run_b=<int>
  &tab=findings|components|delta
  &change=added,resolved,severity_changed
  &severity=critical,high,medium,low
  &show_unchanged=true
  &kev_only=true
  &fix_available=true
  &q=<string>
```

Every filter, every tab switch, every chip toggle writes to the URL. Row-expansion state and search-input focus are intentionally not in the URL — they're per-session and don't survive refresh by design.

### 5. Cache and streaming

- `compare_cache` table keyed by `sha256(f"{min(a,b)}:{max(a,b)}")`. Payload is the full `CompareResult` JSON. TTL 24h, but invalidated immediately on either run's reanalysis (Celery hook).
- Streaming threshold: `findings_count_a + findings_count_b + components_count_a + components_count_b > 5000`. Below the threshold: single JSON. Above: SSE in order `relationship → posture → findings (chunks of 500) → components (chunks of 500) → done`.

---

## 4. Capability classification — preserve / replace / drop

For every v1 capability inventoried in Phase 1, an explicit decision with a one-line justification. **Bold rows** are pushbacks against the user's baseline classification — see §11 for the reasoning.

### Frontend — preserve verbatim or near-verbatim

| # | Capability | Decision | Justification |
|---|---|---|---|
| C1 | URL `?run_a&run_b` parsing + `parseRunId` guard | **Preserve** | Already correct, already URL-driven. Extend to multi-param URL schema (§decision 4). |
| C2 | Same-run guard (`runA !== runB`) | **Preserve** | Identity check is correct. Move enforcement into URL state hook for testability. |
| C13 | Back button (`router.back()`) | **Preserve** | Standard nav affordance, no reason to touch. |
| C14 | Breadcrumb (Analysis Runs › Compare) | **Preserve** | Same. |
| C15 | Suspense wrapper + skeleton fallback | **Preserve** | Required by Next 15 for `useSearchParams` — non-negotiable. |
| C4 | Skeleton matching rendered shape | **Preserve, extend** | Skeleton structure stays; add a row-shaped skeleton inside the tabbed body for the table region. |
| C5 | Generic error alert | **Preserve, extend** | Add specific error renderers for permission-denied / run-not-ready / not-found before falling through to the generic alert. |

### Frontend — preserve visual, replace data source

| # | Capability | Decision | Justification |
|---|---|---|---|
| C6 | Run A → Run B hero header | **Preserve + extend** | Visual is good; add a one-line `RelationshipDescriptor` underneath that reads from the new `RunRelationship` payload (same project? same SBOM? days between? direction warning?). |
| C7 | Distribution bar (new / common / resolved) | **Preserve + promote** | Better than the v2 prompt's bare text summary. Promote into Region 2 (Posture). Render at full width above the metric chip row. |
| C8 | Summary tiles (counts with tone glow) | **Preserve + extend** | Tile layout stays. Replace the three count tiles with the three posture deltas (KEV, fix-available, high+critical) per §3. The v1 finding-count summary continues to live next to the distribution bar as a legend, not as the tile content. |
| C9 | Severity delta grid (Crit/High/Med/Low arrows) | **Preserve + relocate** | Keep the visual. Relocate to Tab 3 (Posture delta detail) as the side-by-side severity distribution chart the v2 prompt §3 already specified. The grid answers "did the composition shift?" — a question the per-finding `severity_changed` chip in Tab 1 doesn't answer. |
| C10 | Free-text vuln-id filter | **Preserve + extend** | Keep the input. Extend filter scope to also match component name and PURL (not just vuln_id). Add chip filters (change_kind, severity, kev_only, fix_available) alongside. |
| C3 | Empty state | **Preserve shape, replace contents** | Empty-state shell stays. Replace the "go back to Analysis Runs" CTA with two in-page run pickers — the empty state is now also the picker entry point. |

### Frontend — replace

| # | Capability | Decision | Justification |
|---|---|---|---|
| C11 | Three-column lists (New / Resolved / Common) | **Replace** | Split-column structure makes "what changed for THIS component?" hard. Unified virtualized table with per-row `change_kind` chip, severity, KEV/EPSS, attribution. Single ordering rule (§7). |
| C12 | Auto-link CVE-* → NVD, GHSA-* → GitHub Advisories | **Replace, with fallback** | Use existing CVE detail modal (richer, in-app, already cached). External NVD/GHSA links move to the modal footer. **Fallback:** for non-CVE/GHSA identifiers (PYSEC, RUSTSEC, GO, OSV-generic) where the CVE modal can't render — confirmed in [app/integrations/cve/identifiers.py:29-50](../../app/integrations/cve/identifiers.py#L29-L50) — keep an inline external link as a degraded affordance. |

### Frontend — add (no v1 equivalent)

| Capability | Justification |
|---|---|
| In-page run pickers (`<RunPicker />` Combobox) | Eliminates the bounce to `/analysis`. Search by run #, sbom_name, project, completed-on date. |
| Components tab (component diff with change_kinds) | Lets the user answer "what upgrade did this?" — the attribution that v1 cannot produce. |
| Posture delta tab (the detail view of Region 2) | Side-by-side severity distribution + top-5 fixers / regressions. |
| Per-finding attribution to component changes | "Resolved via upgrade pkg 1.2.3 → 1.4.0" — the highest-value insight the diff can produce. |
| Keyboard navigation (`j`/`k`, `1`/`2`/`3`, `s`, `c`, `e`, `?`) | Triage UI demands fast nav; pattern matches Linear and GitHub PR Files. |
| Export (Markdown / CSV / JSON) | Slack handoff (md), spreadsheet (csv), automation (json). |
| Share link button | Copy current URL with all filter state. The URL already serializes everything. |
| Mobile bottom-sheet adaptation | Triage on-call from a phone — pickers stack, tables become cards. |

### Backend — replace (with v1 patches for security gaps)

| # | Capability | Decision | Justification |
|---|---|---|---|
| B1 | `GET /api/analysis-runs/compare?run_a=&run_b=` | **Preserve, deprecated** | Marked `Deprecation: true` + `Sunset: <date>` headers; emits a structured warning log on every call. Removed in a follow-up release once telemetry shows <1% traffic vs v2 for two consecutive weeks. |
| B3 | Diff identity = `vuln_id` only | **Replace** | Identity becomes `(vuln_id, component_name, component_version)` per Phase 1 §3. Correctness fix; not optional. |
| B4 | Aggregate severity counts diff | **Replace** | `RiskDelta` carries (a) per-finding `severity_changed` events, (b) aggregate severity distributions for A and B (kept for the Tab 3 side-by-side). Both, in different regions. |
| B6 | No auth on v1 endpoint | **Patch v1 + add to v2** | This is a pre-existing security bug. Patched in v1 immediately; required in v2. Single shared `require_auth` dep. |
| B7 | No status-readiness check on v1 endpoint | **Patch v1 + add to v2** | Same — patched in both. `run_status ∈ {OK, FINDINGS, PARTIAL}` required; otherwise `409 Conflict` with a `RunNotReady` error code. |
| **(new)** | `POST /api/v1/compare` with `CompareResult` payload | **Add** | Canonical endpoint for v2. JWT-required. Tenant scope is single-org for v1 (per Phase 1 Q1). |
| **(new)** | `GET /api/v1/runs/recent`, `GET /api/v1/runs/search` | **Add** | Powers the in-page picker. Recent = last 20 runs the user touched; search = autocomplete by run #, sbom_name, project name, status. |
| **(new)** | `POST /api/v1/compare/{cache_key}/export` | **Add** | Server-side export for large diffs (so the browser doesn't have to hold 60MB of JSON). Small diffs export client-side. |
| **(new)** | Celery hook: invalidate `compare_cache` rows on run reanalysis | **Add** | Required for cache correctness. Fires on `analysis_run` row updates that change `completed_on` or `total_findings`. |

---

## 5. Wireframes

### Region 1 — Selection bar (sticky, ~80px)

```
┌──────────────────────────────────────────────────────────────────────────┐
│  RUN A                                  →                  RUN B         │
│  [▼ Test Sbom · Run #1 · Apr 28]                [▼ Test Sbom · Run #3 · Apr 30] │
│                                                                          │
│  Same project · 2 days apart · scanner unchanged   [Swap ⇄] [Share 🔗]   │
└──────────────────────────────────────────────────────────────────────────┘
```

`<RunPicker />` is a shadcn Combobox:

- Default open: last 20 runs the user has touched, most recent first
- Type-ahead: 200ms debounced query against `/api/v1/runs/search?q=…&limit=20`
- Each option row: SBOM name (bold), run #, project name (if cross-project), `completed_on` relative date, status chip
- Filter affordance inside the dropdown: a single chip "Same project as Run A" (only when picking Run B)
- Selecting a run writes `?run_a=` or `?run_b=` to the URL via `router.push` (selection is history-worthy)

`<RelationshipDescriptor />` is a single line below the pickers, computed from the API response's `RunRelationship`:

| State | Copy |
|---|---|
| Same project, ≥1 day | "Same project · {N} days apart" |
| Same project, <1 day | "Same project · {N} hours apart" |
| Different projects | "Different projects ({proj_a} → {proj_b})" |
| Same SBOM hash | "Same SBOM, re-scanned" |
| Direction warning | "⚠ Run B is older than Run A — did you mean to swap?" — clickable to swap |
| Cross-project | (added prefix to whichever applies) |

### Region 2 — Posture delta (sticky, ~140px)

Distribution bar promoted from v1 (full width). Below it: legend (v1 retains text), then three posture-delta tiles. The aggregate severity grid does **not** live here — it's in Tab 3 to keep this region scannable.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  POSTURE DELTA                                                           │
│                                                                          │
│  ████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████████████████████  │
│   8 new           3 common                                  19 resolved  │
│                                                                          │
│  ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐  │
│  │  KEV exposure      │  │  Fix-available     │  │  High+Critical     │  │
│  │  2 → 1   ▼ -1      │  │  60% → 80%   ▲ +20 │  │  12 → 8    ▼ -4    │  │
│  └────────────────────┘  └────────────────────┘  └────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

Tile semantics:

- **KEV exposure**: count of findings whose CVE is currently in `kev_entry`, scoped to each run. Down arrow = green = fewer KEV-listed findings; up arrow = red = worse.
- **Fix-available coverage**: `findings with non-empty fixed_versions / total findings`, as a percentage. Up arrow = green = more findings have remediation paths in B than A; down arrow = red.
- **High+Critical exposure**: count of findings at severity HIGH or CRITICAL. Down = green, up = red.

Each tile has a tooltip with the exact definition + a link to the source (KEV → CISA, fix-available → analysis_finding.fixed_versions, severity → upstream feed).

### Region 3 — Tabs

```
┌──────────────────────────────────────────────────────────────────────────┐
│  [ Findings (30) ] [ Components (33) ] [ Posture detail ]  ← tab strip   │
├──────────────────────────────────────────────────────────────────────────┤
│  Filter chips: [+ Added (8)] [- Resolved (19)] [~ Severity (3)]          │
│                [Critical] [High] [Medium] [Low]                          │
│                [🔥 KEV only] [🔧 Fix available] [Show unchanged]         │
│                                                                          │
│  [🔍 Filter by CVE id, component name, PURL...]                          │
│                                                                          │
│  ▼ Virtualized table — each row 56px (88px when expanded) ▼              │
│                                                                          │
│  + NEW    CVE-2024-1234   HIGH   pyyaml@6.0.1                            │
│                           ↳ via upgrade pyyaml 5.4.0 → 6.0.1             │
│                                                                          │
│  ✓ RES    CVE-2021-44832  CRIT 🔥 log4j-core@2.16.0 → 2.17.1             │
│                           ↳ via upgrade log4j-core 2.16.0 → 2.17.1       │
│                                                                          │
│  ↑↓ SEV   CVE-2023-9999   MED→HIGH  requests@2.31.0                      │
│                           ↳ severity reclassified by NVD                 │
│                                                                          │
│  ...                                                                     │
└──────────────────────────────────────────────────────────────────────────┘
```

#### Tab 1 — Findings (default, deep-link `?tab=findings`)

Columns (left → right):

1. `change_kind` chip (color + label) — left border tinted to match
2. CVE/GHSA id (monospace) — clicking opens CVE detail modal
3. Severity chip (with arrow if severity_changed)
4. KEV badge (🔥) when current cache says so
5. Component name@version (transition arrow if version_bumped)
6. Attribution string (right-aligned, italic, secondary text)

Default sort: `change_kind` priority `(severity_changed up, added, resolved, severity_changed down)` → severity desc → CVE id asc. Sortable headers for severity, component, change_kind.

Row interactions:

- Click anywhere on row → opens CVE detail modal (existing component, see [docs/features/cve-detail-modal.md](../features/cve-detail-modal.md))
- Hover → row actions reveal: "Copy CVE id", "Mark as triaged" (deferred to triage feature), "Open in OSV" (only for non-CVE/GHSA where the modal can't render)
- Keyboard: see §9

#### Tab 2 — Components (deep-link `?tab=components`)

Same virtualized table, one row per component diff. Columns:

1. `change_kind` chip
2. Component name + ecosystem (derived from PURL via `purl_to_ecosystem`)
3. Version transition (e.g. `1.2.3 → 1.4.0`, arrow direction indicating upgrade/downgrade)
4. Linked findings cell — "→ resolves 3" or "→ introduces 2", clickable to filter Tab 1 to those rows
5. License (if available; today never available — placeholder column hidden behind a feature flag, see §10 OOS)
6. Hash (same — hidden today)

#### Tab 3 — Posture delta detail (deep-link `?tab=delta`)

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Severity distribution                                                   │
│  Run A:  ▓▓▓░░░░░░░░░░░ (Crit 5, High 12, Med 18, Low 7)                 │
│  Run B:  ▓▓░░░░░░░░░░░░ (Crit 3, High 5,  Med 19, Low 4)                 │
│                                                                          │
│  KEV count over time:    Run A → Run B                                   │
│                          ●────────●  2 → 1                               │
│                                                                          │
│  Top 5 risk reductions (by severity-weighted contribution)               │
│  1. ✓ CVE-2021-44832 (CRIT, KEV) — log4j-core 2.16.0 → 2.17.1            │
│  2. ✓ CVE-2021-45046 (CRIT, KEV) — log4j-core 2.16.0 → 2.17.1            │
│  ...                                                                     │
│                                                                          │
│  Top 5 risk introductions                                                │
│  1. + CVE-2024-12345 (HIGH) — pyyaml 5.4.0 → 6.0.1                       │
│  ...                                                                     │
└──────────────────────────────────────────────────────────────────────────┘
```

This tab is read-only — no row interactions. Pure analytical view.

The "top 5" lists use a *display-only* ranking that combines severity ordinal + KEV flag (not a multiplicative score). Specifically: `(KEV first, then severity ordinal CRIT > HIGH > MED > LOW > NONE > UNKNOWN, then fix-available first, then alphabetical)`. This avoids the scalar problem and produces a defensible ordering.

### Empty / loading / error / edge states

| State | Trigger | Render |
|---|---|---|
| `EmptySelection` | `run_a` or `run_b` missing from URL | Region 1 empty pickers shown prominently with copy "Pick a baseline run and a candidate run to compare." Regions 2 + 3 absent. |
| `SameRunPicked` | `run_a === run_b` | "These are the same run — nothing to compare." with CTA "Pick a different Run B" → focuses Run B picker. |
| `RunNotReady` | API returns 409 | "Run B is still in progress (estimated {N} min remaining). Comparison will be ready when it completes." Auto-poll every 30s. |
| `PermissionDenied` | API returns 403 | "You don't have access to one of these runs. Ask the project owner." (Phase 1: never fires today since no per-user scoping. Reserved for tenancy follow-up.) |
| `RunNotFound` | API returns 404 | "Run #{id} no longer exists. It may have been deleted." with picker focus to clear. |
| `Loading` | `useQuery` pending | Skeleton with shape matching the rendered regions. Never a spinner. |

### Mobile (≤ 640px)

- Pickers stack vertically. The "→" between A and B becomes a vertical arrow.
- Region 2 collapses to a single horizontal scroll-snap row of three metric tiles (each 80% viewport width).
- Tabs become a sticky segmented control at the top of Region 3.
- Findings and Components tables become **cards** — one card per diff row. Card header = `change_kind` chip + CVE id; card body = severity, component, attribution.
- Filter chips wrap; long chip rows scroll horizontally with shadow indicators on overflow.
- Keyboard shortcuts disabled (no physical keyboard); tap targets ≥ 44px.

---

## 6. Posture metric definitions

These are the three Region 2 deltas. Each is independently defensible and anchored to a public source.

### 6.1 KEV exposure

```sql
-- per run
SELECT count(*) FROM analysis_finding f
JOIN kev_entry k ON k.cve_id = ANY(/* canonical ids of f.vuln_id and f.aliases */)
WHERE f.analysis_run_id = :run_id;
```

- **Source:** `kev_entry` table, refreshed every 24h from CISA KEV catalog (per [docs/risk-index.md](../risk-index.md))
- **Why it matters:** KEV listing is the highest-signal exploitability indicator in public vulnerability data
- **Delta direction:** down = better (fewer findings observed exploited in the wild)

### 6.2 Fix-available coverage

```sql
-- percentage per run
SELECT
  count(*) FILTER (WHERE f.fixed_versions IS NOT NULL
                   AND f.fixed_versions <> ''
                   AND f.fixed_versions <> '[]') * 100.0
  / NULLIF(count(*), 0)
FROM analysis_finding f
WHERE f.analysis_run_id = :run_id;
```

- **Source:** `analysis_finding.fixed_versions` populated by the analyzer from upstream feeds at scan time
- **Why it matters:** This is the operationally actionable subset — tells the team how much of the inventory can be remediated by version bump today
- **Delta direction:** up = better (more findings have known fixes)

### 6.3 High+Critical exposure

```sql
SELECT count(*) FROM analysis_finding f
WHERE f.analysis_run_id = :run_id
  AND f.severity IN ('CRITICAL', 'HIGH');
```

- **Source:** `analysis_finding.severity`, denormalized at scan time from upstream CVSS
- **Why it matters:** Maps to the standard escalation tier most security teams already act on
- **Delta direction:** down = better

### 6.4 Distribution bar (promoted from v1)

```sql
SELECT
  count(distinct f_b.vuln_id) FILTER (WHERE f_a.vuln_id IS NULL) AS new_,
  count(distinct f_a.vuln_id) FILTER (WHERE f_b.vuln_id IS NULL) AS resolved,
  count(distinct f_b.vuln_id) FILTER (WHERE f_a.vuln_id IS NOT NULL) AS common
FROM ...
```

(Conceptual; the diff engine produces these as side-effects of the per-finding diff in §3.5 of the prompt.)

The bar is a literal proportional rendering of `new : common : resolved`. Distinct from the per-finding events table — this is a portfolio view.

### 6.5 No `risk_score` scalar

Explicit non-decision: there is **no** "risk score" number anywhere in the UI. Reasons in §11 / pushback PB-1.

---

## 7. Diff identity rules

### 7.1 Component identity

`(name, ecosystem)` where `ecosystem = purl_to_ecosystem(purl)`, fallback `(name, "unknown")` when purl is missing.

Documented limitation: cross-ecosystem name collisions (e.g. `requests` exists in both PyPI and npm) will produce a false `version_bumped` event when a project switches the package's ecosystem between scans. This is rare in practice and visible in the Components tab as "ecosystem changed" via the version cell — acceptable for v1.

### 7.2 Finding identity

`(vuln_id, component_name, component_version)`. Reasoning in [docs/compare-discovery.md §3](../compare-discovery.md#3-findings):

- `component_id` FK is nullable (orphaned findings) so it can't carry identity
- `cpe` is unreliable for non-OS packages
- `(component_name, component_version)` is universally available because findings always store these denormalized at scan time

### 7.3 Finding `change_kind` enumeration

| change_kind | rule | Notes |
|---|---|---|
| `added` | identity in B not in A | Renders red `+ NEW` chip |
| `resolved` | identity in A not in B | Renders green `✓ RESOLVED` chip; row shows attribution to the component change |
| `severity_changed` | identity in both, `severity_a ≠ severity_b` | Renders amber `↑↓ SEVERITY` chip with arrow direction |
| `unchanged` | identity in both, severity equal | Hidden by default; shown only with `?show_unchanged=true` |

**Removed from the v2 prompt:** `kev_added`. KEV state is not snapshotted at scan time (see [docs/compare-discovery.md §3](../compare-discovery.md#3-findings)) so a true at-scan-time delta is impossible. KEV is instead surfaced as:

- a `🔥 KEV` badge on any row whose CVE is currently KEV-listed
- a `🔥 KEV only` filter chip
- the KEV exposure tile in Region 2

This is more honest to the data. See pushback PB-3.

### 7.4 Component `change_kind` enumeration

| change_kind | rule |
|---|---|
| `added` | name+ecosystem in B not in A |
| `removed` | name+ecosystem in A not in B |
| `version_bumped` | both, different version (sub-flag: `direction = up\|down\|crossgrade`) |
| `license_changed` | both, same version, different license — **stub only** (license not stored, never fires today) |
| `hash_changed` | both, same version, different content hash — **stub only** (hash not stored, never fires today) |
| `unchanged` | hidden by default |

Stubs are scaffolded so a future migration that adds `license` and `content_hash` columns is a one-liner change. See §10 OOS.

### 7.5 Attribution

For each `added` and `resolved` finding, the diff engine joins to the component diff table by component identity and attaches a human-readable string:

| Finding kind | Component kind | Attribution string |
|---|---|---|
| `resolved` | `version_bumped` | "via upgrade `pkg` `1.2.3 → 1.4.0`" |
| `resolved` | `removed` | "via removal of `pkg`" |
| `resolved` | (no component change) | "via vulnerability re-classification" |
| `added` | `version_bumped` | "introduced by upgrade `pkg` `1.2.3 → 1.4.0`" |
| `added` | `added` | "via new dependency `pkg@1.4.0`" |
| `added` | (no component change) | "newly published advisory against existing `pkg@version`" |

---

## 8. URL schema

| Param | Type | Default | Push or replace? |
|---|---|---|---|
| `run_a`, `run_b` | int | none | `push` (history-worthy navigation) |
| `tab` | `findings\|components\|delta` | `findings` | `push` |
| `change` | comma list of change_kinds | `added,resolved,severity_changed` (excludes `unchanged`) | `replace` |
| `severity` | comma list, lowercase | all | `replace` |
| `kev_only` | boolean | `false` | `replace` |
| `fix_available` | boolean | `false` | `replace` |
| `show_unchanged` | boolean | `false` | `replace` |
| `q` | string | `""` | `replace` (debounced 200ms write) |

History semantics: only run selection and tab change push history entries. Filter toggles and search input replace, so the back button takes the user out of the compare page rather than through 30 filter states.

---

## 9. Keyboard shortcuts

Active when no input is focused. `?` reveals an overlay listing them all.

| Key | Action |
|---|---|
| `j` / `↓` | Next row |
| `k` / `↑` | Previous row |
| `Enter` | Open CVE detail modal (Tab 1) / expand row (Tab 2) |
| `1` / `2` / `3` | Switch tab |
| `s`, `/` | Focus filter input |
| `c` | Copy current row's primary id |
| `e` | Open export dialog |
| `?` | Show shortcuts overlay |
| `Esc` | Close overlay; clear filter input if focused |
| `g` then `a` | Focus Run A picker |
| `g` then `b` | Focus Run B picker |

Implementation note: focus-state-aware hook. We never hijack typing — when the user is in a `<input>` or `[contenteditable]`, only `Esc` is intercepted.

---

## 10. Out of scope (v1 of v2)

Carried forward from the user prompt and Phase 1:

- ❌ Three-way compare (A vs B vs C)
- ❌ Saved comparisons / "watch this diff"
- ❌ Slack / email digest of new diffs
- ❌ Suppression / triage workflow inside compare
- ❌ Cross-organization compare
- ❌ Comparing non-completed runs (returns `RunNotReady`)
- ❌ AI-generated narrative summary of the diff
- ❌ License columns on `sbom_component` (and the `license_changed` change_kind that depends on them)
- ❌ Content-hash columns on `sbom_component` (and the `hash_changed` change_kind / supply-chain alarm — this is a high-value follow-up feature on its own)
- ❌ Tenant scoping (single-org per Phase 1 Q1)
- ❌ KEV / EPSS at-scan-time snapshotting (would require schema additions on `analysis_finding`)
- ❌ Persistence of "last picked runs" per user (no user-prefs table)

---

## 11. Pushbacks against the user's classification baseline

Four explicit disagreements that need acknowledgement before Phase 3:

### PB-1 (highest) — Drop the "risk score" scalar entirely

**The user's prompt §2.4 specifies:**
> Risk score formula (documented in the ADR): severity-weighted sum across all findings, with KEV multiplier. Critical=10, High=5, Medium=2, Low=0.5; KEV-listed ×3; EPSS percentile > 90 ×1.5.

**Disagreement.** This is the same shape as the "Risk Index" the user removed yesterday in [docs/risk-index.md](../risk-index.md). That document is clear:

> The index conflated severity, exploitability, and asset criticality into one opaque scalar. Industry practice (FAIR, EPSS, CISA SSVC) splits these.

The proposed `risk_score` is exactly that — a scalar collapsing severity (already represented), KEV (already a separate signal), and EPSS (already a separate signal) into one opaque number with arbitrary weights. The "Risk score 42 → 31 (-26%) safer" line in Region 2 reintroduces the same "vs. what threshold?" problem the removed Risk Index had.

**Counter-design (this ADR):** No scalar. Region 2 shows three independently-defensible deltas (KEV exposure, fix-available coverage, high+critical exposure). Each maps to a public source. None is multiplied. None claims "safer/riskier" overall — instead each tile claims a directional change in a specific signal, leaving the interpretation to the engineer.

If the user disagrees, the alternative I'd accept is **rename and shrink scope**: call it "exposure points" (not "risk"), document the formula prominently with a click-through to the methodology, place it in Tab 3 (Posture detail) only — not in Region 2 where it competes with the defensible signals. But by-default I will not ship the scalar in Region 2.

### PB-2 — C9 severity grid is preserved-and-relocated, not replaced

**The user's classification said:**
> C9 (severity grid) → keep the visual; data source becomes per-finding severity_changed events, not aggregate counts

**Disagreement.** The aggregate severity grid and per-finding `severity_changed` events answer different questions:

| Question | Answer source |
|---|---|
| "Did Run B's overall severity composition shift?" | Aggregate severity grid (C9 visual) |
| "Did this specific CVE get reclassified?" | Per-finding `severity_changed` chip in Tab 1 |

Replacing one with the other loses the portfolio view. The original v1 grid is genuinely useful — "Run B has 2 fewer Criticals" is the first thing a release manager looks at. Per-finding events answer a different (also useful) question.

**Counter-design (this ADR):** Keep C9's visual entirely, relocate from Region 2 (where it competed with the new posture tiles) into Tab 3 (Posture detail) as the side-by-side stacked bar the v2 prompt §3 already specified. Per-finding `severity_changed` events drive Tab 1 row chips. Both ship.

### PB-3 — Drop `kev_added` as a `change_kind`

**The user's prompt §3 (FindingChangeKind table) lists:**
> `kev_added`: same finding in both, but B is now KEV-listed

**Disagreement.** KEV state is not stored on `analysis_finding`. It's a current-state lookup against `kev_entry`. Without a snapshot at scan time, "B is now KEV-listed but A wasn't" cannot be honestly determined — the KEV catalog state at the moment Run A finished is gone.

**Counter-design (this ADR):** Drop `kev_added` from `FindingChangeKind`. Surface KEV as:

1. A `🔥 KEV` badge on any finding row (any change_kind) where the current cache says the CVE is KEV-listed
2. A `🔥 KEV only` filter chip
3. The KEV exposure tile in Region 2 (which is honestly labelled as "current KEV-listed count per run" — same caveat applies, but at the aggregate level the aggregate-as-of-now claim is more defensible than a per-row at-scan-time claim)

This is more truthful to the data. The user's intent ("flag findings that are urgent") is preserved; only the false at-scan-time framing is dropped.

### PB-4 (smaller) — C12 needs a fallback

**The user's classification said:**
> C12 (external links to NVD/GHSA) → use the existing in-app CVE detail modal instead. External links move to the modal footer only.

**Mostly agree, with a caveat.** The CVE detail modal is built around `CveDetail` which only resolves for vuln_ids in `{CVE-…, GHSA-…, PYSEC-…, RUSTSEC-…, GO-…}` (per [app/integrations/cve/identifiers.py](../../app/integrations/cve/identifiers.py)). For OSV-generic and any future identifier classes, the modal will return `not_found`.

**Counter-design (this ADR):** External link affordance is hidden when the modal will resolve. For unresolvable identifiers, the row falls back to the v1 inline external link (OSV.dev URL). The CVE modal footer still carries NVD/GHSA links for the resolvable cases.

---

## 12. Open follow-ups (logged, not in scope)

| # | Item |
|---|---|
| F-1 | Tenant scoping (`tenant_id` columns + JWT tenant claim + RLS at Postgres). |
| F-2 | Add `license` and `content_hash` columns to `sbom_component`; activate the stubbed `license_changed` and `hash_changed` change_kinds. |
| F-3 | Snapshot KEV state on `analysis_finding` at scan time so `kev_added` can become a true at-scan-time event. |
| F-4 | Saved comparisons table (`compare_pinned`) so users can name + bookmark a diff. |
| F-5 | AI narrative summary of a diff (separate prompt, after this ships clean). |
| F-6 | Remove deprecated `GET /api/analysis-runs/compare` after telemetry threshold. |
| F-7 | "Last picked runs per user" persistence (requires a user-prefs surface that doesn't exist yet). |

---

## 13. Delivered artefacts

All four pushbacks (PB-1 / PB-2 / PB-3 / PB-4) accepted as written. Implementation landed in a single PR alongside the v1 security/correctness patches, per the user's Phase 3 clarification §1.

### Backend

| File | Purpose |
|---|---|
| [alembic/versions/007_compare_cache.py](../../alembic/versions/007_compare_cache.py) | `compare_cache` table migration; idempotent. |
| [app/models.py](../../app/models.py) (append) | `CompareCache` ORM model. |
| [app/schemas_compare.py](../../app/schemas_compare.py) | Wire schema. `FindingChangeKind` (no `kev_added` — PB-3). `PostureDelta` (no scalar — PB-1). |
| [app/services/compare_service.py](../../app/services/compare_service.py) | 10-step diff engine. Strict + lax attribution lookup. |
| [app/services/compare_export.py](../../app/services/compare_export.py) | Markdown / CSV / JSON formatters. |
| [app/routers/compare.py](../../app/routers/compare.py) | `POST /api/v1/compare`, `POST /api/v1/compare/{cache_key}/export`. |
| [app/routers/runs.py](../../app/routers/runs.py) (append) | `/api/runs/recent`, `/api/runs/search`. |
| [app/routers/analysis.py](../../app/routers/analysis.py) | v1 patches: status guard, structured envelopes, Deprecation/Sunset headers, telemetry counter. |
| [app/main.py](../../app/main.py) | Register compare router under `_protected`. |
| [app/settings.py](../../app/settings.py) (append) | `compare_v1_fallback`, `compare_license_hash_enabled`, `compare_streaming_threshold`, `compare_cache_ttl_seconds`. |

### Frontend

| File | Purpose |
|---|---|
| [frontend/src/types/compare.ts](../../frontend/src/types/compare.ts) | TS wire types. `FindingChangeKind` excludes `kev_added` (PB-3). |
| [frontend/src/lib/api.ts](../../frontend/src/lib/api.ts) (append) | `compareRunsV2`, `recentRuns`, `searchRuns`, `exportCompare`. |
| [frontend/src/hooks/useCompareUrlState.ts](../../frontend/src/hooks/useCompareUrlState.ts) | URL-driven state, push/replace history semantics. |
| [frontend/src/components/compare/CompareView.tsx](../../frontend/src/components/compare/CompareView.tsx) | Top-level orchestrator. |
| [frontend/src/components/compare/SelectionBar/](../../frontend/src/components/compare/SelectionBar/) | Picker, relationship descriptor, share button. |
| [frontend/src/components/compare/PostureHeader/](../../frontend/src/components/compare/PostureHeader/) | Three count-based tiles + promoted distribution bar. NO scalar (PB-1). |
| [frontend/src/components/compare/FindingsTab/](../../frontend/src/components/compare/FindingsTab/) | Filter chips + table; CVE modal drill-in. |
| [frontend/src/components/compare/ComponentsTab/ComponentsTab.tsx](../../frontend/src/components/compare/ComponentsTab/ComponentsTab.tsx) | Component diff + supply-chain hash alert banner. |
| [frontend/src/components/compare/PostureDetailTab/PostureDetailTab.tsx](../../frontend/src/components/compare/PostureDetailTab/PostureDetailTab.tsx) | Side-by-side severity bar + top-5 ordinal-ranked contributors (PB-1). |
| [frontend/src/components/compare/states/CompareStates.tsx](../../frontend/src/components/compare/states/CompareStates.tsx) | Empty / loading / same-run / not-ready / not-found / generic-error states. |
| [frontend/src/components/compare/ExportDialog.tsx](../../frontend/src/components/compare/ExportDialog.tsx) | Markdown / CSV / JSON download dialog. |
| [frontend/src/components/compare/KeyboardShortcutsOverlay.tsx](../../frontend/src/components/compare/KeyboardShortcutsOverlay.tsx) | `?` overlay + tab/search/export shortcut handler. |
| [frontend/src/app/analysis/compare/_v1/page.tsx](../../frontend/src/app/analysis/compare/_v1/page.tsx) | Verbatim v1 page, preserved (Next-private folder). |
| [frontend/src/app/analysis/compare/page.tsx](../../frontend/src/app/analysis/compare/page.tsx) | Kill-switch routing: `NEXT_PUBLIC_COMPARE_V1_FALLBACK=true` → v1 with banner; otherwise v2. |

### Tests

| File | Tests | Focus |
|---|---|---|
| [tests/test_compare_service.py](../../tests/test_compare_service.py) | 15 | 10-step engine, helpers, cache, status guard, KEV lookup, attribution, license/hash flag |
| [tests/test_compare_router.py](../../tests/test_compare_router.py) | 9 | HTTP envelope codes, export round-trip, picker endpoints |
| [tests/test_compare_v1_deprecation.py](../../tests/test_compare_v1_deprecation.py) | 4 | Deprecation headers, telemetry counter, status guard, legacy contract preserved |
| [frontend/src/hooks/__tests__/useCompareUrlState.test.tsx](../../frontend/src/hooks/__tests__/useCompareUrlState.test.tsx) | 12 | URL parse round-trip, push/replace history semantics |
| [frontend/src/components/compare/__tests__/FindingsTab.filter.test.tsx](../../frontend/src/components/compare/__tests__/FindingsTab.filter.test.tsx) | 8 | Filter chips, sort order, free-text, show-unchanged |
| [frontend/src/components/compare/__tests__/RunPicker.test.tsx](../../frontend/src/components/compare/__tests__/RunPicker.test.tsx) | 6 | Trigger label, recent runs, keyboard nav, Escape, debounced search, paired-project chip |
| [frontend/src/components/compare/__tests__/CompareView.integration.test.tsx](../../frontend/src/components/compare/__tests__/CompareView.integration.test.tsx) | 7 | Empty/same-run/loading/error states, loaded happy path, "no risk score" pin |
| [frontend/src/components/compare/__tests__/CompareView.axe.test.tsx](../../frontend/src/components/compare/__tests__/CompareView.axe.test.tsx) | 4 | Zero axe violations on every state |
| [frontend/src/components/compare/__tests__/PostureMetricTile.test.tsx](../../frontend/src/components/compare/__tests__/PostureMetricTile.test.tsx) | 7 | Direction logic (down-good vs up-good), formatting |
| **Total new tests** | **72** | (28 backend + 44 frontend) |

Suite totals: **536 backend tests pass, 141 frontend tests pass, no regressions.**

### Documentation

| File | Audience |
|---|---|
| [docs/compare-discovery.md](../compare-discovery.md) | Phase 1 audit (architecture context). |
| [docs/adr/0008-compare-runs-architecture.md](0008-compare-runs-architecture.md) | This ADR. |
| [docs/features/compare-runs.md](../features/compare-runs.md) | User-facing feature doc. |
| [docs/runbook-compare.md](../runbook-compare.md) | Operator runbook (cache health, deprecation telemetry, kill-switch). |
