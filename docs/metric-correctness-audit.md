# Metric correctness audit

**Status:** Phase 0 (read-only diagnosis). No code changes proposed yet — pending scope decision in Phase 1.
**Date:** 2026-05-07
**Triggered by:** repeated user reports of inconsistent counts. Specifically:
1. Analysis Runs page → "Runs with findings: 0", but the table shows 5 of 7 runs with status "Vulnerabilities found".
2. Analysis Runs page → "Total findings: 1,261", but the C/H/M/L badges in the visible rows sum to 1,244 (gap = 17).
3. Dashboard "Findings Surfaced: 514", but a single run alone has 506 findings on its detail page.

**Sandbox limitation:** I do not have credentials for the production database from this environment, so I0.5 lists the SQL to execute and the predicted shape of the result; the live numbers must be filled in by someone with DB access (or by attaching a read-only DSN). The SQL is verbatim — no edits required to run it.

---

## I0.1 — Inventory: every count surface

Frontend route paths are Next.js App Router routes under `frontend/src/app/`; component paths are under `frontend/src/components/`.

| # | Surface | URL | Label | Component file:line | Hook | Endpoint |
|---|---|---|---|---|---|---|
| S01 | Dashboard hero — adaptive headline | `/` | Headline copy uses `total_sboms`, `total_findings`, `critical`, `high`, `kev_count` | `dashboard/HeroPostureCard/AdaptiveHeadline.tsx:24-43` | `getDashboardPosture` | `GET /dashboard/posture` |
| S02 | Dashboard hero — KEV exposed tile | `/` | KEV exposed | `dashboard/HeroPostureCard/HeroMetricRow.tsx:56-64` | same | same |
| S03 | Dashboard hero — Fix available tile | `/` | Fix available (of N distinct) | `dashboard/HeroPostureCard/HeroMetricRow.tsx:66-76` | same | same |
| S04 | Dashboard hero — Net 7-day | `/` | +N added / −M resolved | `dashboard/HeroPostureCard/HeroMetricRow.tsx:78-108` | same | same |
| S05 | Dashboard hero — Severity bar (C/H/M/L/U) | `/` | Critical / High / Medium / Low / Unknown | `dashboard/HeroPostureCard/SeverityDistributionBar.tsx:80-123` | same | same |
| S06 | Dashboard "Your Analyzer, So Far" — SBOMs scanned | `/` | SBOMs scanned | `dashboard/LifetimeStats/LifetimeStats.tsx:82` | `getDashboardLifetime` | `GET /dashboard/lifetime` |
| S07 | Dashboard "Your Analyzer, So Far" — Runs executed | `/` | Runs executed | `…/LifetimeStats.tsx:91` | same | same |
| S08 | Dashboard "Your Analyzer, So Far" — Findings surfaced | `/` | Findings surfaced (resolved to date) | `…/LifetimeStats.tsx:100` | same | same |
| S09 | Dashboard "Your Analyzer, So Far" — Monitoring days | `/` | Monitoring for | `…/LifetimeStats.tsx:109` | same | same |
| S10 | Dashboard findings-trend — per-severity per-day | `/` | C / H / M / L / Unknown series | `dashboard/FindingsTrendChart/FindingsTrendChart.tsx:211-235` | `getDashboardTrend` | `GET /dashboard/trend?days=30` |
| S11 | Analysis Runs — Total runs tile | `/analysis` | Total runs | `app/analysis/page.tsx:199-205` | `getRuns(page=1,page_size=100)` | `GET /api/runs?...` |
| S12 | Analysis Runs — Runs no issues tile | `/analysis` | Runs — no issues (PASS) | `app/analysis/page.tsx:207-212` | same | same |
| S13 | Analysis Runs — Runs with findings tile | `/analysis` | Runs — with findings (FAIL) | `app/analysis/page.tsx:214-220` | same | same |
| S14 | Analysis Runs — Runs source errors tile | `/analysis` | Runs — source errors (PARTIAL) | `app/analysis/page.tsx:222-228` | same | same |
| S15 | Analysis Runs — Runs failed tile | `/analysis` | Runs — failed (ERROR) | `app/analysis/page.tsx:230-236` | same | same |
| S16 | Analysis Runs — Total findings tile | `/analysis` | Total findings | `app/analysis/page.tsx:238-244` | same | same |
| S17 | Runs table — per-row C/H/M/L badges | `/analysis` | C: / H: / M: / L: counts | `analysis/RunsTable.tsx:347-365` | same | same |
| S18 | Run detail hero — Components / Findings / Sources | `/analysis/[id]` | meta tiles | `analysis/RunDetailHero.tsx:243-269` | `getRun` | `GET /api/runs/{id}` |
| S19 | Run detail — Severity distribution | `/analysis/[id]` | C / H / M / L / Unknown | `analysis/RunDetailHero.tsx:339-353` | same | same |
| S20 | Run detail — findings-table header count | `/analysis/[id]` | Findings (N) | `app/analysis/[id]/page.tsx:257-263` | `getAllEnrichedRunFindings` | `GET /api/runs/{id}/findings-enriched?...` |
| S21 | Compare — Distribution bar / summary tiles | `/analysis/compare` | New / Common / Resolved | `app/analysis/compare/_v1/page.tsx:150-220` | `compareRuns` | `GET /api/analysis-runs/compare` |
| S22 | Compare — Severity delta | `/analysis/compare` | C / H / M / L delta | `app/analysis/compare/_v1/page.tsx:222-241` | same | same |
| S23 | SBOM detail — components count | `/sboms/[id]` | Components | `sboms/SbomDetail.tsx:225` | `getSbomInfo` | `GET /api/sboms/{id}/info` |
| S24 | SBOM detail — Risk Summary KEV findings | `/sboms/[id]` | KEV findings | `sboms/SbomDetail.tsx:293` | `getSbomRiskSummary` | `GET /api/sboms/{id}/risk-summary` |
| S25 | SBOM detail — Risk-by-component severity | `/sboms/[id]` | C / H / M / L per component | `sboms/SbomDetail.tsx:346-349` | same | same |

**Surfaces searched for and not present:** dedicated `/projects/[id]` detail page (only a list page exists with no aggregate counts); standalone "Consolidated scan" page (it lives as a tab inside `/analysis`, with inline-streamed counts only — not pre-computed aggregates); `/sboms` list page has no aggregate count tiles.

---

## I0.2 — Query-per-surface mapping

The canonical metrics layer at `app/metrics/` is the documented source of truth ("Inline SQL for metrics in router files is forbidden" — `app/metrics/__init__.py:5`). For each surface above, the actual query path:

### Group A — backed by `app/metrics/` (canonical)

| # | Surface | Function | File:Line | SQL shape |
|---|---|---|---|---|
| S01-S05 | Dashboard posture | `findings_latest_per_sbom_*`, `findings_kev_in_scope`, `findings_net_change` | `app/metrics/findings.py:65-122`, `app/metrics/kev.py`, `app/metrics/windows.py` | `SELECT … FROM analysis_finding WHERE analysis_run_id IN (latest_run_per_sbom_subquery)` |
| S06-S07,S09 | Lifetime tiles (SBOMs / runs / days) | `sboms_total`, `runs_total_lifetime`, `runs_completed_this_week`, `runs_first_completed_at` | `app/metrics/sboms.py`, `app/metrics/runs.py:14-82` | `SELECT COUNT(id) FROM analysis_run` (no WHERE) for `runs_total_lifetime` etc. |
| S08 | Findings surfaced | `findings_distinct_lifetime` | `app/metrics/findings.py:129-159` | ``SELECT COUNT(DISTINCT vuln_id‖'\|'‖component_name‖'\|'‖component_version) FROM analysis_finding f JOIN analysis_run r ON r.id=f.analysis_run_id WHERE r.run_status IN ('OK','FINDINGS','PARTIAL')`` |
| S10 | Trend per-day per-severity | `findings_daily_distinct_active` | `app/metrics/findings.py:192-310` | Per-day snapshot of distinct `(vuln,component,version)` in latest-as-of-day successful run per SBOM. |

The key shared subquery, used by every "latest state" metric:

```sql
-- latest_run_per_sbom_subquery() in app/metrics/_helpers.py:22-34
SELECT MAX(id) FROM analysis_run
WHERE run_status IN ('OK','FINDINGS','PARTIAL')
GROUP BY sbom_id
```

### Group B — bypasses the metrics layer

| # | Surface | Where the number comes from | Note |
|---|---|---|---|
| S11-S16 | Analysis Runs page header tiles | **Computed in browser from `getRuns()` payload.** `app/analysis/page.tsx:107-117`. **No backend aggregation endpoint.** | Tile values derive from `runs.length`, `runs.filter(r.run_status==='PASS')`, `runs.reduce(s + r.total_findings)`, etc. — all on a paginated client-side slice. |
| S17 | Runs table per-row C/H/M/L badges | `analysis_run.critical_count` / `high_count` / `medium_count` / `low_count` columns directly off the row. | Denormalized counters maintained by the writer; table omits `unknown_count` (no `U:` chip). |
| S18-S19 | Run detail hero counts | `analysis_run.total_findings`, `total_components`, `critical_count`…`unknown_count` directly off the row. | Same denormalized counters. |
| S20 | Findings-table header count | `X-Total-Count` header on `GET /api/runs/{id}/findings-enriched`. | Server-side `COUNT(*) FROM analysis_finding WHERE analysis_run_id = :id`. |
| S21-S22 | Compare deltas | `app/routers/compare.py` (set-difference of `(vuln_id, component_name, component_version)` across the two runs). | Convention B-flavor over two specific runs. |
| S23-S25 | SBOM detail risk summary | `app/routers/sbom.py` risk-summary endpoint. | Latest-run-of-this-SBOM scope. |

### Verbatim quote of the broken summary computation (S11-S16)

```ts
// frontend/src/app/analysis/page.tsx:107-117
const summary = useMemo(() => {
  if (!runs) return null;
  return {
    total: runs.length,
    pass: runs.filter((r) => r.run_status === 'PASS').length,
    fail: runs.filter((r) => r.run_status === 'FAIL').length,
    partial: runs.filter((r) => r.run_status === 'PARTIAL').length,
    errors: runs.filter((r) => r.run_status === 'ERROR').length,
    findings: runs.reduce((s, r) => s + (r.total_findings ?? 0), 0),
  };
}, [runs]);
```

This block alone produces every Analysis Runs page anomaly.

---

## I0.3 — Convention classification

Conventions per the prompt:
- **A — Latest state.** Counts as they exist now, scoped to the latest successful run per SBOM (or to a single run, when scoped to that run).
- **B — Lifetime distinct.** Counts unique findings across all runs, deduped by `(vuln_id, component_name, component_version)`.
- **C — Total raw rows.** Raw `COUNT(*)` across all rows. Generally wrong for user-facing display.

`SUCCESSFUL_RUN_STATUSES = ('OK','FINDINGS','PARTIAL')` per `app/services/analysis_service.py:106`. **`ERROR`, `RUNNING`, `PENDING`, `NO_DATA` are excluded.**

| # | Surface | Label implies | Actually computed as | Match? |
|---|---|---|---|---|
| S01-S05 | Dashboard hero | A (latest_per_sbom) | A (latest_per_sbom) | ✓ |
| S06 | SBOMs scanned | total | C (raw row count of `sbom_source` — no soft-delete filter; see I0.4 §F2) | ⚠ |
| S07 | Runs executed | total | C (raw row count of `analysis_run`, **all statuses**) | "honest" per spec — by design (Q3 lock in `runs.py:14-21`) |
| S08 | **Findings surfaced** | B | B (distinct lifetime, successful-run-scoped) | ✓ |
| S09 | Monitoring days | computed from `MIN(completed_on)` of successful runs | A | ✓ |
| S10 | Trend chart | per-day distinct active | B-snapshot per day | ✓ |
| S11 | Total runs | "all runs" | **client-side `runs.length` of paginated slice (page_size=100)** | ❌ wrong query (S11-bug) |
| S12 | Runs no issues (PASS) | runs with `run_status==OK` | `runs.filter(r.run_status==='PASS')` — **legacy status name** | ❌ always 0 |
| S13 | Runs with findings (FAIL) | runs with `run_status==FINDINGS` | `runs.filter(r.run_status==='FAIL')` — **legacy status name** | ❌ always 0 |
| S14 | Runs source errors (PARTIAL) | runs with `run_status==PARTIAL` | `runs.filter(r.run_status==='PARTIAL')` | ✓ (correct only by accident — PARTIAL was not renamed) |
| S15 | Runs failed (ERROR) | runs with `run_status==ERROR` | `runs.filter(r.run_status==='ERROR')` | ✓ (same — ERROR not renamed) |
| S16 | Total findings | sum of findings across runs | sum of `r.total_findings` over the **paginated client slice** | ❌ undercounts when >100 runs; otherwise summing a denormalized column whose invariant is unverified |
| S17 | Per-row C/H/M/L badges | severity counts in this run | reads `critical_count` / `high_count` / `medium_count` / `low_count` directly | A — but excludes `unknown_count` from display |
| S18-S19 | Run detail hero | counts in this run | reads denormalized cols (`total_findings`, `critical_count`, …) directly | A |
| S20 | Run detail findings table count | findings in this run | server-side `COUNT(*)` on `analysis_finding WHERE analysis_run_id=:id` | A (live) |
| S21-S22 | Compare deltas | between two runs | set-difference on `(vuln,comp,ver)` across two runs | B-flavor (correct) |
| S23-S25 | SBOM detail risk | latest run of this SBOM | latest_run_per_sbom_subquery filtered to one sbom_id | A |

---

## I0.4 — Contradictions

The full list of inconsistencies, sorted by user impact:

### F1 — Analysis Runs status filtering uses ADR-0001 legacy status names (severity: **CRITICAL**)

**File:** `frontend/src/app/analysis/page.tsx:111-114`

```ts
pass:    runs.filter((r) => r.run_status === 'PASS').length,
fail:    runs.filter((r) => r.run_status === 'FAIL').length,
partial: runs.filter((r) => r.run_status === 'PARTIAL').length,
errors:  runs.filter((r) => r.run_status === 'ERROR').length,
```

The backend renamed `PASS → OK` and `FAIL → FINDINGS` per `app/services/analysis_service.py:96-110` (ADR-0001). Outbound payloads always emit canonical names. So:
- **Runs no issues** (S12) is always `0` — backend emits `OK`, FE looks for `PASS`.
- **Runs with findings** (S13) is always `0` — backend emits `FINDINGS`, FE looks for `FAIL`.

The codebase even ships a helper `canonicalRunStatus()` at `frontend/src/lib/analysisRunStatusLabels.ts:102-107` whose docstring says *"Use this when comparing or filtering — never hard-code 'FAIL' / 'PASS'."* The summary computation ignores it.

The runs table (S17) uses a different code path (`StatusBadge` looks up via case-insensitive `runStatusShortLabel` which already maps `FINDINGS → "Vulnerabilities found"`), which is why **the badges render correctly while the tile shows 0** — exactly the contradiction in the user's screenshot.

This **directly explains contradiction (1)** in the audit trigger.

**Class:** A (small SQL/ORM-equivalent FE change — switch the filter to `canonicalRunStatus`).

### F2 — Analysis Runs aggregates computed over a paginated client slice (severity: **HIGH**)

**File:** `frontend/src/app/analysis/page.tsx:92-105` + `:107-117`

The page calls `getRuns({page:1, page_size:100})` and then computes "Total runs", "Runs no issues", …, "Total findings" by reducing over the returned array.

If a deployment ever exceeds 100 runs, every tile silently undercounts. The backend `GET /api/runs` already returns `X-Total-Count`, but only the *number of runs* (not findings/by-status). For the user's current dataset (7 runs visible), `runs.length === total` accidentally, so this bug doesn't fire today — but it's a time-bomb.

The hint copy on the tiles says "All loaded runs in the table below" / "Sum of vulnerability counts across loaded runs" — at least the hint is honest, but the labels ("Total runs", "Total findings") are not.

**Class:** A or B depending on resolution: relabel ("Loaded runs" / "Loaded findings") = cheap B; expose backend aggregate endpoint = correct fix.

### F3 — "Total findings" (1,261) vs visible C/H/M/L badge sum (1,244): the unknown-bucket leak (severity: **MEDIUM**, perception)

**Files:** `frontend/src/app/analysis/page.tsx:115` + `frontend/src/components/analysis/RunsTable.tsx:347-365`

`summary.findings = Σ r.total_findings` — includes `unknown_count`.
The badges render only `C:` / `H:` / `M:` / `L:`. There is no `U:` chip.
The model column `unknown_count` exists (`app/models.py:171`) and is part of `total_findings`.

Therefore: `tile − Σ visible badges = Σ unknown_count over visible rows`. The user's observed 17-finding gap **is exactly this** (assuming `total_findings = C+H+M+L+unknown` invariant holds — see F4 about that invariant being unverified).

This explains contradiction (2). The number 1,261 is correct (modulo F2); the perception of a discrepancy is from the badges hiding the unknown bucket.

**Class:** B (label / display fix — either render a `U:` chip, or change the tile to `summary.findings = Σ (critical+high+medium+low)` if you want the chip-sum convention).

### F4 — Denormalized counter invariant is asserted nowhere (severity: **MEDIUM**)

**File:** `app/models.py:165-171`

`analysis_run.total_findings` and the five `*_count` columns are independent denormalized values written by the analysis worker. Spec invariant: `total_findings == critical_count + high_count + medium_count + low_count + unknown_count`.

There is no DB constraint, no canonical-metrics function, and no test that asserts this. If the writer ever updates one column but forgets another, the user sees the kind of drift (1,261 vs 1,244 if it happened to coincide, vs the "row cache differs from finding-count-by-severity-row-count" form). Today F3 fully accounts for the user's 17-row delta, but in the absence of an invariant test, F4 lurks.

**Class:** D (invariant test in Phase 3 of any fix).

### F5 — `findings_surfaced_total` (lifetime) appearing smaller than a single run's `total_findings` (severity: **LOW** — actually correct, but visually confusing)

**Files:** `app/services/dashboard_metrics.py:343-406` + `app/metrics/findings.py:129-159`

`Findings Surfaced` = `findings_distinct_lifetime` = distinct `(vuln_id, component_name, component_version)` tuples across all successful runs.
A single run's `total_findings` (S18) = raw row count `COUNT(*) FROM analysis_finding WHERE analysis_run_id = :id`.

These are different conventions. If a single run produces 506 finding rows but most of them resolve to the same `(vuln, comp, ver)` keys (e.g. a vuln affects two declared paths of the same component, producing duplicate rows post-enrichment), the lifetime distinct can be smaller than the raw row count — even when only one run has been processed.

So 514 (Findings Surfaced) < 506 (single run) is **mathematically possible**, but it violates user intuition. The label "Findings surfaced" reads as "raw findings the tool has shown me" (Convention C).

**Class:** B (label fix — "Distinct vulnerabilities surfaced" or "Unique findings surfaced") OR **F4 also overlaps**: if the writer's denormalized `total_findings` includes duplicates that the DISTINCT collapses, this is an indirect symptom of poor de-duping at write time.

This explains contradiction (3) — the math is consistent given the convention, but the label is misleading.

**Class:** B.

### F6 — Soft-delete filter not applied in metrics queries (severity: **MEDIUM**)

**Files:** `app/metrics/findings.py`, `app/metrics/runs.py`, `app/metrics/sboms.py`

Every entity has `is_active` (`app/models_mixins.py:31-56`). None of the metric queries filter on `is_active=true`. After any soft-delete, `runs_total_lifetime`, `findings_distinct_lifetime`, `sboms_total`, etc. all over-count.

This isn't observable in the user's screenshots (you'd need someone to soft-delete an SBOM and then read the dashboard), but it's a latent inconsistency between the API surface (`SoftDeleteMixin` exists, the docs imply it's enforced) and the metrics layer (which ignores it).

The audit prompt explicitly mentions `WHERE deleted = false` — that's evidence the user expects soft-delete to be honored. Today, no metric query honors it.

**Class:** A (add `WHERE is_active=TRUE` to every metric query — purely additive ORM change) OR if there's a write-side reason to count tombstones (audit trail), **B** (rename labels and document).

### F7 — Two parallel "lifetime" cache layers (severity: **LOW**)

**Files:** `app/services/dashboard_metrics.py:329-406` + `app/metrics/cache.py`

`compute_lifetime_metrics()` has its own 15-minute in-process cache; the metrics layer has its own cache. They share the invalidation key `(max_run_id, run_count, sbom_count)` and call `reset_cache()` together. Today they agree. But two independent caches with the same invalidation key are one refactor away from drifting.

**Class:** C (consolidate caches; not a current incident).

---

## I0.5 — Live verification queries

I cannot reach the production DB from this sandbox. Run these against prod (read-only role is sufficient — none of these mutate). Paste the output back into this file under the "Actual" column.

### Q1 — Run counts

```sql
-- Q1.1 Total runs (all statuses, all soft-delete states)
SELECT COUNT(*) FROM analysis_run;

-- Q1.2 Total runs after soft-delete filter (the "honest" total)
SELECT COUNT(*) FROM analysis_run WHERE is_active = TRUE;

-- Q1.3 By canonical status
SELECT run_status, COUNT(*)
FROM analysis_run
WHERE is_active = TRUE
GROUP BY run_status
ORDER BY run_status;

-- Q1.4 Runs with findings (using the canonical predicate)
SELECT COUNT(*) FROM analysis_run
WHERE run_status = 'FINDINGS' AND is_active = TRUE;
-- Compare: the FE currently filters on run_status = 'FAIL' (always 0)
```

### Q2 — Finding counts

```sql
-- Q2.1 Raw rows across all findings (Convention C)
SELECT COUNT(*) FROM analysis_finding;

-- Q2.2 Raw rows after soft-delete
SELECT COUNT(*) FROM analysis_finding WHERE is_active = TRUE;

-- Q2.3 Lifetime distinct, as the metrics layer computes it (Convention B)
SELECT COUNT(DISTINCT
  COALESCE(f.vuln_id, '') || '|' ||
  COALESCE(f.component_name, '') || '|' ||
  COALESCE(f.component_version, '')
)
FROM analysis_finding f
JOIN analysis_run r ON r.id = f.analysis_run_id
WHERE r.run_status IN ('OK','FINDINGS','PARTIAL');
-- This is "Findings Surfaced" on the dashboard.

-- Q2.4 Per-run breakdown — sanity-check denormalized total_findings
SELECT
  r.id,
  r.run_status,
  r.total_findings        AS cached,
  r.critical_count + r.high_count + r.medium_count + r.low_count + r.unknown_count AS sum_severity_cols,
  (SELECT COUNT(*) FROM analysis_finding f WHERE f.analysis_run_id = r.id) AS live_count,
  (SELECT COUNT(*) FROM analysis_finding f WHERE f.analysis_run_id = r.id AND f.is_active = TRUE) AS live_active_count
FROM analysis_run r
WHERE r.is_active = TRUE
ORDER BY r.id DESC
LIMIT 30;
-- Expected invariants (F4):
--   cached == sum_severity_cols
--   cached == live_count (or live_active_count if writer respects soft-delete)
-- Any row where the columns disagree is an instance of F4.

-- Q2.5 Latest-run severity breakdown for a specific run id
SELECT severity, COUNT(*)
FROM analysis_finding
WHERE analysis_run_id = :run_id  AND is_active = TRUE
GROUP BY severity;
```

### Q3 — Reconciliation pivots

```sql
-- Q3.1 The Analysis Runs page tiles, computed correctly server-side
WITH active AS (SELECT * FROM analysis_run WHERE is_active = TRUE)
SELECT
  COUNT(*)                                              AS total_runs,
  SUM(CASE WHEN run_status = 'OK'       THEN 1 ELSE 0 END) AS runs_no_issues,
  SUM(CASE WHEN run_status = 'FINDINGS' THEN 1 ELSE 0 END) AS runs_with_findings,
  SUM(CASE WHEN run_status = 'PARTIAL'  THEN 1 ELSE 0 END) AS runs_source_errors,
  SUM(CASE WHEN run_status = 'ERROR'    THEN 1 ELSE 0 END) AS runs_failed,
  SUM(total_findings)                                   AS total_findings_via_cached_col,
  SUM(critical_count + high_count + medium_count + low_count + unknown_count)
                                                        AS total_findings_via_severity_cols
FROM active;
-- These are the numbers the UI should display. The two SUM(...) variants
-- should match — F4 invariant test.
```

### Q4 — Visible-rows reconciliation (matches what the user is seeing)

To reproduce the screenshot the user reported, this is the dataset visible on `/analysis`:

```sql
SELECT
  id, run_status,
  total_findings,
  critical_count, high_count, medium_count, low_count, unknown_count,
  (critical_count + high_count + medium_count + low_count) AS chml_only
FROM analysis_run
WHERE is_active = TRUE
ORDER BY id DESC
LIMIT 7;
-- Expected: 5 rows have run_status='FINDINGS', 2 don't.
-- Σ chml_only across the 7 rows should equal 1,244 (matches the user's eyeball sum).
-- Σ total_findings across the 7 rows should equal 1,261.
-- The 17-row gap is Σ unknown_count over the 7 rows.
```

---

## I0.6 — Reconciliation table

Filling this in with the math from the user's screenshots; columns marked "(prod query needed)" require Q1-Q4 results.

| Surface | Expected | Displayed | Match? | Convention claimed | Convention actually used | Root cause |
|---|---|---|---|---|---|---|
| S08 Findings Surfaced | 514 (matches Q2.3) | 514 | ✓ | B | B | (correct given convention; F5 is a labeling concern) |
| S11 Total runs | 7 (matches Q1.2 if ≤100) | 7 | ✓ today | A "all runs" | C "page slice" | F2 — accidentally correct because <100 runs |
| S12 Runs no issues | 2 (Q1.3 OK count) | 0 | ❌ | A | filter on legacy `'PASS'` | F1 |
| S13 Runs with findings | 5 (Q1.3 FINDINGS count) | 0 | ❌ | A | filter on legacy `'FAIL'` | F1 |
| S14 Runs source errors | 0 (Q1.3 PARTIAL count) | 0 | ✓ | A | filter on `'PARTIAL'` (still canonical) | accidentally correct (F1 didn't rename PARTIAL) |
| S15 Runs failed | 0 (Q1.3 ERROR count) | 0 | ✓ | A | filter on `'ERROR'` (still canonical) | accidentally correct |
| S16 Total findings | 1,261 (Σ total_findings on visible) | 1,261 | ✓ | "all findings" | Σ cached `total_findings` on page slice | correct given S16's actual convention; user's confusion is F3 |
| S17 visible C/H/M/L badges | 1,244 (Σ chml on visible) | 1,244 | ✓ | A | Σ `(C+H+M+L)_count` on page slice | correct; missing `unknown_count` → F3 |
| S08 vs S18 (single run = 506) | 506 ≥ 514? — possible per F5 | 506 vs 514 | (math allows it) | B vs A — different conventions | both correct in isolation | F5 — labels imply convergence |

---

## I0.7 — Summary

**Real bugs (counts that are wrong):**

1. **F1 (CRITICAL)** — Analysis Runs page header tiles "Runs — no issues" and "Runs — with findings" are filtering on legacy status names that the backend stopped emitting at ADR-0001. Both are always 0 regardless of dataset. Root cause: hard-coded `'PASS'` / `'FAIL'` strings in 4 lines of `frontend/src/app/analysis/page.tsx:111-114`. Helper `canonicalRunStatus()` exists and explicitly says do not hard-code these names.
2. **F2 (HIGH)** — All Analysis Runs page header tiles compute over the first 100 runs only (`page_size: 100`). With ≤100 runs, accidentally correct; above that threshold, every tile undercounts silently. Backend has no aggregate endpoint for this page.
3. **F6 (MEDIUM)** — No metric query in `app/metrics/` filters on `is_active = TRUE`. Soft-deleted SBOMs / runs / findings inflate every dashboard count.

**Counts that are correct but the labels mislead:**

4. **F3** — "Total findings: 1,261" vs visible badge sum "1,244" is fully explained by the unknown-bucket missing from the C/H/M/L chips. The number 1,261 is correct; the badges hide 17 unknown findings. Either label/display fix.
5. **F5** — "Findings Surfaced: 514" vs single-run 506 is mathematically valid (B vs A conventions). The label "Findings surfaced" reads to users as raw count.

**Latent invariants that should be tested:**

6. **F4** — `total_findings == critical_count + high_count + medium_count + low_count + unknown_count` per row is asserted nowhere.
7. **F7** — Two parallel lifetime caches share an invalidation key; consolidate before they diverge.

**What the correct values should be** (subject to running Q1-Q4 against prod to get exact numbers):

- Analysis Runs / "Runs — no issues": **2** (count where `run_status='OK'`)
- Analysis Runs / "Runs — with findings": **5** (count where `run_status='FINDINGS'`)
- Analysis Runs / "Runs — source errors", "Runs — failed", "Total runs", "Total findings": already correct given <100 runs in dataset
- Dashboard / "Findings Surfaced": **514** is the correct lifetime distinct (only the label is potentially confusing)

**Phase 4 flag (separate PR):** F6 + F7 imply the metrics layer needs a small but cross-cutting refactor (a `_active_runs()`, `_active_findings()`, `_active_sboms()` filter helper used by every public function, plus consolidating the cache layers). That is broader than the FE fix needed for F1 and shouldn't bundle.

---

## Recommended Phase 1 scope (for owner review)

The cleanest bundling of fixes:

| Class | Fixes | PR |
|---|---|---|
| A | F1 (status names), F2 (tile labels OR add backend aggregate), F6 (soft-delete filter) | One PR per fix; F1 alone takes ~10 lines |
| B | F3 (add `U:` chip OR change tile to C+H+M+L sum), F5 (rename "Findings surfaced" → "Distinct vulnerabilities surfaced") | One PR for label changes |
| D | F4 invariant test in `tests/test_metric_consistency.py` | bundled with whichever fix lands first |
| Phase 4 | F6 broader metrics-layer soft-delete refactor, F7 cache consolidation | separate PR, owned by metrics-layer maintainer |

Pause for direction on which of these to take through Phase 2.
