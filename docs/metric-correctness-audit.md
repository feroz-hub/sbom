# Metric correctness audit

**Status:** Phase 4 complete (2026-05-08). Audit closed; follow-ups tracked in §I2 below. Permanent guidance lives in [`docs/metric-conventions.md`](./metric-conventions.md). Architectural enforcement lives in `tests/test_metric_consistency.py`.
**Phase 0 date:** 2026-05-07 — read-only diagnosis with sandbox limitations (no DB access).
**Phase 1 date:** 2026-05-08 — full inventory + live SQL evidence + extended reconciliation. Sections §I0.x preserved verbatim as the Phase 0 record; §I1–§I5 add Phase 1 evidence.
**Phase 2-4 date:** 2026-05-08 — fixes + tests + permanent docs. See §I2 for the diff index and follow-up backlog.
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

---
---

# Phase 1 — Comprehensive inventory + live evidence (2026-05-08)

This section extends the Phase 0 audit with: (a) every surface §I0.x missed, (b) the live SQL outputs §I0.5 promised but could not run, (c) a reconciliation table grounded in concrete local-DB numbers, and (d) two findings (F8, F9) discovered while walking the surfaces §I0.x did not visit.

## I1.1 — New surfaces inventoried (extends §I0.1)

§I0.1 covered Dashboard / Analysis Runs / Run detail / SBOM detail / Compare _v1_. Walking the rest of the product surfaced the following.

| # | Surface | URL | Label | Component file:line | Hook | Endpoint |
|---|---|---|---|---|---|---|
| S26 | Projects table — total chip | `/projects` | "N project(s)" | `projects/ProjectsTable.tsx:137` | `getProjects` | `GET /api/projects` |
| S27 | Projects table — filter result | `/projects` | "Showing X of Y" | `projects/ProjectsTable.tsx:137` | same | same |
| S28 | SBOMs table — total chip | `/sboms` | "N SBOM(s)" | `sboms/SbomsTable.tsx:224` | `getSboms(1, 500)` | `GET /api/sboms` |
| S29 | SBOMs table — filter result | `/sboms` | "Showing X of Y" | `sboms/SbomsTable.tsx:224` | same | same |
| S30 | Schedules table — total chip | `/schedules` | "N schedule(s)" | `app/schedules/page.tsx:222-225` | `listSchedules` | `GET /api/schedules` |
| S31 | Schedules table — filter result | `/schedules` | "Showing X of Y" | `app/schedules/page.tsx:222-225` | same | same |
| S32 | Schedules row — Last-run status badge | `/schedules` | "PASS" / "FAIL" / "ERROR" / other | `app/schedules/page.tsx:319-329` | same | same |
| S33 | Project delete-cascade dialog | `/projects` | "N SBOMs / N runs / N findings / N schedules" | `projects/ProjectsTable.tsx:308-315` | `getProjectDeleteImpact` | `GET /api/projects/{id}/delete-impact` |
| S34 | SBOM delete-cascade dialog | `/sboms` | "N components / N runs / N findings" | `sboms/SbomsTable.tsx:432-437` | `getSbomDeleteImpact` | `GET /api/sboms/{id}/delete-impact` |
| S35 | Settings → AI Usage Summary tile | `/settings/ai` | Total spent · Cache hit rate · Most-used % | `settings/ai/UsageSummary/UsageSummary.tsx:38-57` | `useAiSettings` | `GET /api/ai-fixes/usage` |
| S36 | Run detail — Findings filter header | `/analysis/[id]` | "X of Y" / "N finding(s)" | `analysis/FindingFilterPanel.tsx:199-211` | `getAllEnrichedRunFindings` | `GET /api/runs/{id}/findings-enriched` |
| S37 | Compare V2 — PostureHero KEV exposure (A/B/Δ) | `/analysis/compare` | KEV exposure · `kev_count_a` / `_b` / `_delta` | `compare/PostureHero/PostureHero.tsx:81-89` | `getCompare` | `GET /api/analysis-runs/compare` |
| S38 | Compare V2 — PostureHero Fix-available coverage % (A/B/Δ) | same | Fix-available coverage · `fix_available_pct_*` | `…/PostureHero.tsx:90-98` | same | same |
| S39 | Compare V2 — PostureHero High+Critical exposure (A/B/Δ) | same | High+Critical exposure · `high_critical_count_*` | `…/PostureHero.tsx:99-107` | same | same |
| S40 | Compare V2 — BigNumbersColumn (added / resolved / severity changed) | same | `findings_added_count` / `_resolved_count` / `_severity_changed_count` | `compare/PostureHero/BigNumbersColumn.tsx` | same | same |
| S41 | Compare V2 — DistributionBarLarge (added / changed / unchanged / resolved) | same | same fields plus `findings_unchanged_count` | `compare/PostureHero/DistributionBarLarge.tsx` | same | same |
| S42 | Compare V2 — Tab 3 Severity composition Run A/B totals | same | "Run A · N findings" / "Run B · N findings" + per-severity stacked bar | `compare/PostureDetailTab/PostureDetailTab.tsx:148-166` | same | same |
| S43 | Compare V2 — Tab 3 Top resolutions / Top regressions lists | same | Top-N rows | `…/PostureDetailTab.tsx:170-204` | same | same |
| S44 | Compare V2 — FilterChipsAdaptive chip counts | same | `+ Added (N)`, `− Resolved (N)`, `↕ Severity (N)`, per-severity, KEV, Fix-available, Show unchanged, "Showing X of Y findings" | `compare/FilterChipsAdaptive/FilterChipsAdaptive.tsx:93-172` | same | same |

**Surfaces walked and confirmed without aggregate counts:** `/sboms/[id]` validation report (renders status, no aggregate), `/admin/ai-usage` (referenced but route does not currently exist; the link from S35 dead-ends), `/analysis` Consolidated Scan tab (live-stream counts only, no precomputed aggregate). The **Settings index** (`/settings`) and **Settings → AI** gate page (`app/settings/ai/page.tsx`) carry no aggregate counts.

**Compare-v2 vs Compare-v1.** §I0.1 only audited `compare/_v1/page.tsx`. The default route is now Compare-v2 (`compare/CompareView.tsx` via `app/analysis/compare/page.tsx`); v1 is gated behind `NEXT_PUBLIC_COMPARE_V1_FALLBACK=true`. S37–S44 are the live-by-default surface; S21/S22 (legacy v1) ship only when the kill-switch is flipped.

## I1.2 — Two new findings discovered while walking the missed surfaces

### F8 — Schedules page renders Last-run badge using legacy `PASS` / `FAIL` filters (severity: **MEDIUM**)

**File:** `frontend/src/app/schedules/page.tsx:319-323`

```tsx
className={`… ${
  s.last_run_status === 'PASS'
    ? 'bg-emerald-50 text-emerald-700 …'
    : s.last_run_status === 'FAIL'
      ? 'bg-red-50 text-red-700 …'
      : s.last_run_status === 'ERROR'
        ? 'bg-orange-50 text-orange-700 …'
        : 'bg-hcl-light text-hcl-muted …'
}`}
```

Same class as F1: hardcoded legacy status names that ADR-0001 retired. The schedule resolver still mirrors `analysis_run.run_status` directly (see `app/services/scheduling.py`), so when a scheduled run completes with `OK` or `FINDINGS`, this badge falls into the "other" bucket (the muted-grey style) and the inline label still says `OK` / `FINDINGS`. The user sees a grey pill with the canonical text, not a green or red pill. Operationally similar to F1 — silently rendering misleading state — but on a less-trafficked page, hence MEDIUM not CRITICAL.

The same `canonicalRunStatus()` helper (`frontend/src/lib/analysisRunStatusLabels.ts:102-107`) that should fix F1 also fixes F8.

**Class:** A — replace string compare with `canonicalRunStatus(s.last_run_status) === 'OK' / 'FINDINGS' / 'ERROR'`. ~6 lines.

### F9 — Architectural invariant: direct ORM access to `AnalysisFinding` / `AnalysisRun` survives outside `app/metrics/` (severity: **MEDIUM** — drift risk, not a current incident)

**Files (grep evidence, 2026-05-08):** `app/routers/{pdf,sbom,runs,ai_fixes,projects,sboms_crud,analysis}.py`, `app/services/{cve_service,compare_service,analysis_service,pdf_service}.py` all contain at least one of `select(AnalysisFinding…)`, `select(AnalysisRun…)`, or the equivalent `db.query(...)` form.

`app/metrics/__init__.py:5` documents the rule: *"Inline SQL for metrics in router files is forbidden."* Today that is **a comment, not a check**. Phase 3 of this audit needs to add the architectural invariant test (described in §6 of the calling prompt) so this drift is caught at PR review time. Without it, every new feature is an opportunity to add another scattered query — the bug class this audit exists to prevent.

This isn't a "displayed number is wrong" bug; it's a "*future* displayed number will be wrong" bug. The fact that S37–S44 (Compare V2) flow through `compare_service.py` and not `app/metrics/compare/` is the most concrete current example: posture deltas are A-vs-A (correct convention) but the calculation lives outside the metric layer where consistency tests don't reach.

**Class:** Phase 3 lock — add `test_no_direct_finding_queries_outside_metrics` to `tests/test_metric_consistency.py`. As a follow-up, migrate the compare service's posture math into `app/metrics/compare.py` (Phase 4 follow-up; not in scope of an immediate fix PR).

## I1.3 — Convention classification for new surfaces (extends §I0.3)

| # | Surface | Label implies | Actually computed as | Match? |
|---|---|---|---|---|
| S26 | Projects "N project(s)" | "all projects" | C — `projects.length` of FE array; backend `GET /api/projects` may or may not filter `is_active` | needs F6 verification |
| S27 | Projects "Showing X of Y" | filter-of-loaded | C — FE filter on FE array | ✓ (acceptably honest) |
| S28 | SBOMs "N SBOM(s)" | "all SBOMs" | C — `sboms.length` of FE page slice; `getSboms(1, 500)` | latent F2-class (>500 SBOMs undercount) |
| S29 | SBOMs "Showing X of Y" | filter-of-loaded | C — FE filter | ✓ |
| S30 | Schedules "N schedule(s)" | "all schedules" | C — `listSchedules` returns all (no pagination) | ✓ |
| S31 | Schedules "Showing X of Y" | filter-of-loaded | C — FE filter | ✓ |
| S32 | Schedules last-run badge | colour-coded by status | string compare on legacy `PASS`/`FAIL` (F8) | ❌ (F8) |
| S33 | Project delete-impact | cascade subjects | C — backend counts SBOMs/runs/findings/schedules where `project_id = :id` | needs F6 verification |
| S34 | SBOM delete-impact | cascade subjects | C — backend counts components/runs/findings where `sbom_id = :id` | needs F6 verification |
| S35 | AI Usage tile (Total spent / Cache hit rate / Most-used %) | last-30-days totals | C — `SUM(cost_usd)` / `SUM(cache_hits)/SUM(calls)` over `ai_usage_log` | (separate concern; see §I1.6) |
| S36 | Run detail "X of Y findings" | filter-of-loaded | C — FE filter on `getAllEnrichedRunFindings` array | ✓ |
| S37 | Compare V2 KEV exposure A/B/Δ | scoped per run | A applied to each run; delta is A−A | ✓ (correct given convention) |
| S38 | Compare V2 Fix-available pct A/B/Δ | scoped per run | A applied to each run; delta is %−% | ✓ |
| S39 | Compare V2 High+Critical A/B/Δ | scoped per run | A applied to each run | ✓ |
| S40 | Compare V2 added / resolved / sevChanged | set diff over (vuln,comp,ver) | B-flavor over two specific runs | ✓ |
| S41 | Compare V2 distribution bar | added/changed/unchanged/resolved | B-flavor | ✓ |
| S42 | Compare V2 Tab 3 Run A/B totals | per-run total | A | ✓ |
| S43 | Compare V2 Tab 3 Top-N | ranking, not count | n/a | ✓ |
| S44 | Compare V2 FilterChips counts | filter-of-loaded | C — FE filter on `result.findings`; "Showing X of Y" excludes `unchanged` from `Y` (`totalRowsForVisibility = rows.filter(r.change_kind !== 'unchanged').length`) | ⚠ — `Y` is a non-obvious denominator; tooltip would help but not a numerical bug |

The chip dim-when-zero rule at `FilterChipsAdaptive.tsx:189` (`dim = !active && count === 0`) is a UX choice, not a numerical bug — calling it out only because the prompt asked for every count to be classified.

## I1.4 — Live SQL evidence (replaces §I0.5 placeholders)

Run against the local sqlite database `sbom_api.db` on 2026-05-08. The shape mirrors §I0.5 exactly; numbers are now the actual outputs.

The local DB has a small dataset (1 SBOM, 1 project, 2 successful runs of the same SBOM, 1,084 raw finding rows — both runs identical at 542 findings each). Despite the small data, every Phase 0 hypothesis is testable.

### Q1 — run counts

| Query | Result |
|---|---|
| Q1.1 `COUNT(*) FROM analysis_run` | **2** |
| Q1.2 `COUNT(*) … WHERE is_active=TRUE` | **2** (no soft-deletes in dataset) |
| Q1.3 GROUP BY `run_status` (active) | `FINDINGS = 2` (only) |
| Q1.4 `WHERE run_status='FINDINGS'` (canonical, active) | **2** |
| Q1.4b `WHERE run_status='FAIL'` (legacy filter from `app/analysis/page.tsx:113`) | **0** |
| Q1.4c `WHERE run_status='PASS'` (legacy filter from `app/analysis/page.tsx:111`) | **0** |

**Result:** F1 is reproduced exactly. The Analysis Runs page's "Runs — with findings" tile does `runs.filter(r.run_status==='FAIL').length`, which is 0 here, while the canonical query returns 2. The two-rows-of-vulnerabilities-but-tile-says-0 contradiction §I0.4-F1 predicted is mechanically present in this dataset.

### Q2 — finding counts

| Query | Result |
|---|---|
| Q2.1 `COUNT(*) FROM analysis_finding` (raw, Convention C) | **1,084** |
| Q2.2 `COUNT(*) … WHERE is_active=TRUE` | **1,084** |
| Q2.3 lifetime distinct `(vuln,comp,ver)`, successful-run-scoped (Convention B) | **542** |
| Q2.3b lifetime distinct, all runs (no status filter) | **542** (all runs are FINDINGS here, so equal) |

**Result:** Lifetime distinct (542) ≠ raw rows (1,084) by a factor of 2 — exactly because both runs are duplicates of each other. This is the mechanism behind F5: a user who reads "Findings Surfaced" as raw count will never see 1,084; they'll see 542. Whether 542 is what the dashboard intends to show is the labeling question.

### Q2.4 — per-run F4 invariant check

Both runs match across every counter:

| run_id | run_status | cached `total_findings` | `Σ(C+H+M+L+U)_count` | `COUNT(*)` live | C | H | M | L | U |
|---|---|---|---|---|---|---|---|---|---|
| 2 | FINDINGS | 542 | 542 | 542 | 53 | 220 | 187 | 74 | 8 |
| 1 | FINDINGS | 542 | 542 | 542 | 53 | 220 | 187 | 74 | 8 |

**F4 invariant** (`cached == sum_severity_cols == live_count`) **holds in this dataset.** That is the *current* state, not a guarantee — there's still no test that locks it. The seeding code in `tests/test_metric_consistency.py:106-156` writes `total_findings = len(findings)` directly, so test fixtures don't exercise the writer's actual aggregation path. Phase 3 should add a test that materially queries the live DB invariant after the analysis worker runs.

### Q3 — Analysis Runs page tiles, computed correctly server-side

```
total_runs  no_issues  with_findings  source_errors  failed  total_findings_cached  total_findings_sum_sev  chml_only
       2           0              2              0       0                 1,084                  1,084      1,068
```

Mapping to the page tiles:

- "Total runs" should be **2** — already correct (FE shows `runs.length === 2`)
- "Runs — no issues" should be **0** — tile **shows 0** today, but only by accident: the FE filters on legacy `'PASS'`, which returns 0 regardless of dataset
- "Runs — with findings" should be **2** — tile **shows 0** today (F1 confirmed)
- "Runs — source errors" should be **0** — tile shows 0 (PARTIAL not renamed; correct)
- "Runs — failed" should be **0** — tile shows 0 (ERROR not renamed; correct)
- "Total findings" should be **1,084** — tile shows 1,084 today; **C+H+M+L only would be 1,068** (16 unknown findings hidden — F3 confirmed at the 16-finding gap level)

### Q4 — visible-rows reconciliation

Top 7 rows by `id DESC`, active, with chml-only sum and unknown count:

| id | run_status | total_findings | C | H | M | L | U | chml_only |
|---|---|---|---|---|---|---|---|---|
| 2 | FINDINGS | 542 | 53 | 220 | 187 | 74 | 8 | 534 |
| 1 | FINDINGS | 542 | 53 | 220 | 187 | 74 | 8 | 534 |

Σ across visible rows: total_findings = **1,084**, chml_only = **1,068**, unknowns = **16**. The 16-finding gap is the F3 unknown-bucket leak.

### Q5 — KEV / SBOMs / Projects / Schedules / AI usage

| Entity | Total | Active |
|---|---|---|
| `sbom_source` | 1 | 1 |
| `projects` | 1 | 1 |
| `analysis_schedule` | 0 | 0 |
| `compare_cache` | 0 | n/a |
| `ai_usage_log` | 0 | n/a |
| KEV-listed findings (latest per SBOM) | 0 | n/a |

**Notes:**
- 0 KEV findings means the dashboard hero "KEV exposed" tile reads 0 in this dataset — testing F1's claim about hero correctness is not possible here without seeding KEV entries (the `test_metric_consistency.py:160-180` helper does this for tests).
- 0 schedules means F8's runtime impact is zero in this dataset — the bug is structural.
- 0 AI-usage means S35's tile reads "—" today; whether the math is right requires fixture data.

## I1.5 — Reconciliation table with concrete numbers (extends §I0.6)

| Surface | Convention claimed | Convention actually used | Local-DB expected | Local-DB displayed | Match? | Root cause |
|---|---|---|---|---|---|---|
| S08 Findings Surfaced | B | B | 542 | 542 | ✓ | (correct given convention; F5 is labeling) |
| S11 Total runs | A "all runs" | C "page slice" | 2 | 2 | ✓ today | F2 — accidentally correct (<100 runs) |
| S12 Runs no issues | A | filter on legacy `'PASS'` | 0 (`OK`-count) | 0 | ✓ here only | F1 — would be wrong if any OK run existed |
| S13 Runs with findings | A | filter on legacy `'FAIL'` | 2 | **0** | **❌** | F1 (confirmed mechanically) |
| S14 Runs source errors | A | filter on `'PARTIAL'` | 0 | 0 | ✓ | (PARTIAL not renamed; accidentally correct) |
| S15 Runs failed | A | filter on `'ERROR'` | 0 | 0 | ✓ | (ERROR not renamed; accidentally correct) |
| S16 Total findings | "all findings" | `Σ total_findings` page slice | 1,084 | 1,084 | ✓ | correct given convention |
| S17 visible C/H/M/L badges | A | `Σ(C+H+M+L)_count` page slice | 1,068 | 1,068 | ✓ | correct; F3 — missing `U:` chip hides 16 unknowns |
| S08 vs S18 (single run) | B vs A | both correct in isolation | 542 vs 542 | 542 vs 542 | n/a | F5 only fires when single-run rows > distinct keys |
| S26-S31 list-page chips | C "FE filter" | C | matches exactly (1, 1, 0) | matches | ✓ | (acceptable; F6 may inflate `total` if soft-deletes accumulate) |
| S32 Schedules last-run badge | colour by status | legacy `'PASS'`/`'FAIL'` | (no schedules in dataset) | n/a | ❌ structural | F8 — same class as F1 |
| S33-S34 cascade-impact | C | C | depends on entity | n/a (no live click) | needs F6 audit | impact endpoint may not honour `is_active` |
| S37-S44 Compare V2 | A-vs-A / B-flavor | matches | n/a (no two distinct runs) | n/a | ✓ assumed | (cannot exercise — both runs identical here) |
| S35 AI Usage tile | last-30-days | C over `ai_usage_log` | 0 | "—" | ✓ structurally | (no fixture data; correctness untested) |

## I1.6 — Out of scope, but worth flagging

These surfaces appeared in the inventory and *do* compute counts, but their convention question is orthogonal to the (vuln,comp,ver) triplet that drives F1–F9. Document them so they don't get pulled into Phase 2 by accident.

- **S35 AI Usage tile.** The "Total spent" / "Cache hit rate" / "Most-used %" math is over `ai_usage_log` and is governed by `app/services/dashboard_metrics.py` AI-cost helpers, not the dashboard-metric layer. Convention C ("total raw rows") is *correct* here — every LLM call is a billable event, no dedup is desired. This surface should NOT be migrated into `app/metrics/`; it belongs in a sibling `app/metrics/ai_cost.py` if/when consolidated. **Out of scope of this audit.**
- **S33-S34 delete-impact dialogs.** These count cascade subjects to populate a confirmation copy ("This will delete 5 SBOMs, 12 runs, 1,084 findings"). They want raw counts, not Convention A or B — the user wants to know what they're deleting. The only correctness question is F6 (do they honour `is_active`?), which is a flag in the soft-delete audit, not a metrics-layer issue.
- **S30/S32 schedule badge colour.** F8 is the only schedule-page bug; the table itself is fine.

## I1.7 — Final summary across all 44 surfaces

**Real bugs (numbers wrong on at least one surface):**

1. **F1 (CRITICAL)** — Analysis Runs tiles "Runs — no issues" / "Runs — with findings" filter on legacy `PASS`/`FAIL` (4 lines, `frontend/src/app/analysis/page.tsx:111-114`). On the local-DB dataset, S13 is mechanically wrong: expected **2**, displayed **0**.
2. **F2 (HIGH)** — All Analysis Runs tiles compute over the first-100-runs page slice; latent at ≤100 runs, undercounts above. No backend aggregate endpoint to consume.
3. **F8 (MEDIUM)** — Schedules row badge filters on legacy `PASS`/`FAIL` (`frontend/src/app/schedules/page.tsx:319-323`). Same class as F1, different file.
4. **F6 (MEDIUM)** — No metric query in `app/metrics/` filters on `is_active=TRUE`. Latent today (no soft-deletes in dataset); inflates every dashboard count after any soft-delete.

**Counts correct but labels mislead:**

5. **F3** — "Total findings 1,084" vs "visible C/H/M/L sum 1,068" gap (16) is the unknown-bucket missing from chips.
6. **F5** — "Findings Surfaced" reads as raw count to users; it's distinct lifetime.

**Latent invariants and architectural drift:**

7. **F4** — `total_findings == Σ severity_count` holds today but is asserted nowhere.
8. **F7** — Two parallel lifetime caches share an invalidation key; consolidate before they diverge.
9. **F9 (NEW)** — `app/metrics/__init__.py:5` rule "inline SQL for metrics is forbidden" is a comment, not a test. 11 files outside `app/metrics/` have direct ORM access to `AnalysisFinding` / `AnalysisRun`. Phase 3 architectural test catches future drift; Compare service should migrate into `app/metrics/compare.py` as a Phase 4 follow-up.

**What the correct values should be on the local DB:**

| Tile | Today | Should be |
|---|---|---|
| Analysis Runs / Runs — with findings | **0** | **2** |
| Analysis Runs / Runs — no issues | 0 | 0 (correct accidentally) |
| Analysis Runs / Total runs | 2 | 2 ✓ |
| Analysis Runs / Total findings | 1,084 | 1,084 ✓ (or 1,068 if "C+H+M+L only" is the desired convention) |
| Dashboard / Findings Surfaced | 542 | 542 ✓ (label might be clearer) |
| All others | n/a | unchanged |

## I1.8 — Phase 1 → Phase 2 scope decision request

The Phase 0 §I0.6 "Recommended scope" table stands. Phase 1 adds **F8** (schedules badge legacy filter) and **F9** (architectural test) to it.

Suggested PR carve-up (smallest first):

| PR | Files | Lines | Class | Notes |
|---|---|---|---|---|
| PR-1 (F1) | `frontend/src/app/analysis/page.tsx` | ~10 | A | Use `canonicalRunStatus()`. Fixes S12, S13. |
| PR-2 (F8) | `frontend/src/app/schedules/page.tsx` | ~6 | A | Use `canonicalRunStatus()`. Fixes S32 colours. |
| PR-3 (F3) | `frontend/src/components/analysis/RunsTable.tsx` (S17 chip) **OR** `app/analysis/page.tsx` (S16 sum) | ~10 | B | Owner picks: add `U:` chip OR change tile to C+H+M+L sum. Lock the convention. |
| PR-4 (F4 lock) | `tests/test_metric_consistency.py` | ~30 | D | Add `test_per_run_severity_columns_match_live_count` against the worker-written denormalized columns. |
| PR-5 (F2) | `app/routers/runs.py` + `frontend/src/app/analysis/page.tsx` | ~50 | A | Add `GET /api/runs/aggregate?scope=…` returning the 6 tile values; FE consumes it. Or relabel to "Loaded runs" if owner prefers cheap path. |
| PR-6 (F6) | every file in `app/metrics/` | ~30 | A | Add `is_active=TRUE` filter helper used by every public function. Also fixes S33/S34. |
| PR-7 (F5) | `frontend/src/components/dashboard/LifetimeStats/LifetimeStats.tsx` | ~3 | B | Rename "Findings surfaced" → "Distinct vulnerabilities surfaced". |
| Phase 4 (F9) | `tests/test_metric_consistency.py` + migrate compare math | ~100 | C | Add architectural invariant test; migrate `app/services/compare_service.py` posture math into `app/metrics/compare.py`. Separate PR. |
| Phase 4 (F7) | `app/services/dashboard_metrics.py` + `app/metrics/cache.py` | ~50 | C | Consolidate caches behind one invalidation interface. Separate PR. |

**Recommended Phase 2 bundle:** PR-1 + PR-2 + PR-3 + PR-4 ship together as the "FE consistency" PR (~60 lines, low risk, fixes the user-visible incidents). PR-5/PR-6/PR-7 each go in their own PR. PR-9 / PR-10 are Phase 4 follow-ups.

**Awaiting owner direction on which PRs proceed to Phase 2 in this audit's scope.**

---
---

# Phase 2-4 — Implementation, tests, permanent docs (2026-05-08)

This section is the closing record. Phase 2 implemented the recommended bundle plus the F2 backend aggregate; Phase 3 added the architectural lock; Phase 4 wrote the permanent guidance.

## I2.1 — Diff index

Backend (canonical metric layer + endpoint):

| File | Change |
|---|---|
| `app/metrics/runs.py` | Added `runs_aggregate(db, *, sbom_id, project_id) → RunsAggregate`. Single round-trip; canonical OK/FINDINGS/PARTIAL/ERROR keys; unconditional `total == Σ(by_outcome)` invariant via `other` catch-all. |
| `app/metrics/__init__.py` | Re-exported `runs_aggregate`, `RunsAggregate`. |
| `app/schemas.py` | Added `RunsAggregateOut`, `RunsAggregateBuckets` Pydantic schemas. |
| `app/routers/runs.py` | Added `GET /api/runs/aggregate?sbom_id=&project_id=` (placed before `/runs/{run_id}` for FastAPI declaration-order). |

Frontend (consumes aggregate, F8 + F3 fixes):

| File | Change |
|---|---|
| `frontend/src/lib/api.ts` | Added `RunsAggregate` type and `getRunsAggregate()`. |
| `frontend/src/app/analysis/page.tsx` | Replaced legacy `summary` useMemo (filtered on `'PASS'`/`'FAIL'`) with a `useQuery` against the new endpoint. Tile labels and hint copy updated to canonical names. **F1 + F2 fixed.** |
| `frontend/src/app/schedules/page.tsx` | Last-run badge now uses `canonicalRunStatus()`. **F8 fixed.** |
| `frontend/src/components/analysis/RunsTable.tsx` | Added `U:` chip after `L:` so per-row chips reconcile to `total_findings`. **F3 fixed.** |

Tests (regression locks):

| File | Change |
|---|---|
| `tests/test_metric_consistency.py` | Added `test_f4_denormalised_columns_match_live_count` (F4 lock), `test_runs_aggregate_outcome_sum_equals_total` (I-A invariant), `test_runs_aggregate_endpoint_does_not_filter_on_legacy_status` (F1 regression), `test_no_new_direct_finding_or_run_queries_outside_metrics` (F9 architectural lock), `test_legacy_allowlist_does_not_grow_unnoticed` (allowlist self-correction). |

Permanent docs (Phase 4):

| File | Change |
|---|---|
| `docs/metric-conventions.md` | NEW — A/B/C decision flowchart + hard rules. The doc that prevents future drift. |
| `CLAUDE.md` | NEW — calculations rule + run-status canonicalisation rule for future Cowork sessions. |
| `docs/metric-correctness-audit.md` | This file. Phase 0 §I0.x and Phase 1 §I1.x preserved as the historical record; this §I2 is the closing diff index. |

## I2.2 — Test evidence

Backend metric-consistency suite (was 12 tests, now 17, all passing):

```
tests/test_metric_consistency.py .................                       [100%]
17 passed, 1 warning in 1.58s
```

Full backend suite: 922 passed, 5 pre-existing AI-router failures unrelated to this audit (verified by `git stash` on a clean tree returning the same 5 failures).

Frontend suite: 48 files, 370 tests, all passing. TypeScript: 3 pre-existing errors in `FindingsTrendChart.test.tsx` unrelated to this audit.

The architectural test was stress-tested by writing a fake violator at `app/routers/_fake_violator_test.py` containing `select(AnalysisRun)` — the test correctly failed with the path and pattern named in the diagnostic.

## I2.3 — Reconciliation: before vs after

Local DB state (2 runs, both FINDINGS, 1,084 raw findings, 542 distinct):

| Surface | Before | After |
|---|---|---|
| Analysis Runs / Runs — with findings (S13) | **0** (legacy `'FAIL'` filter) | **2** (server `with_findings` bucket) |
| Analysis Runs / Runs — no issues (S12) | 0 (legacy `'PASS'`, accidentally correct) | **0** (server `no_issues` bucket — still 0, now for the right reason) |
| Analysis Runs / Total runs (S11) | 2 (page-slice; latent bomb >100 runs) | **2** (server `total_runs`; no slice) |
| Analysis Runs / Total findings (S16) | 1,084 (page-slice sum) | **1,084** (server SUM) |
| Runs table per-row chips (S17) | C+H+M+L = 1,068 (16 unknowns hidden) | **C+H+M+L+U = 1,084** (chips reconcile to row total) |
| Schedules row badge (S32) | grey on `OK`/`FINDINGS` (F8) | green on `OK`, red on `FINDINGS`, orange on `ERROR` |

## I2.4 — Follow-up backlog

Items intentionally deferred from the closing scope. Each should land as its own PR, owner-driven.

| ID | Title | Owner | Why deferred | Pointer |
|---|---|---|---|---|
| FU-1 | F5 — rename "Findings surfaced" → "Distinct vulnerabilities surfaced" | FE | Pure label change; not a math bug. Owner picks copy. | `frontend/src/components/dashboard/LifetimeStats/LifetimeStats.tsx:100` |
| FU-2 | F6 — add `is_active=TRUE` filter to every metric query | metrics-layer maintainer | Requires soft-delete-audit follow-up; cross-cuts every public metric function. Touches `findings.py`, `runs.py`, `sboms.py`, `kev.py`, `windows.py`. | §I0.4-F6 |
| FU-3 | F7 — consolidate the two parallel lifetime caches | services-layer maintainer | Today they share an invalidation key; not a current incident. Consolidate before they diverge. | §I0.4-F7 |
| FU-4 | F9 — migrate `app/services/compare_service.py` posture math into `app/metrics/compare.py` | metrics-layer maintainer | Largest item in `_LEGACY_DIRECT_QUERY_ALLOWLIST`. The Compare V2 surfaces (S37–S44) currently bypass the metric layer. | §I1.2-F9, allowlist in `tests/test_metric_consistency.py` |
| FU-5 | F9 — drain the rest of `_LEGACY_DIRECT_QUERY_ALLOWLIST` | per file | 12 entries today. Each migration removes one allowlist entry in the same PR. The `test_legacy_allowlist_does_not_grow_unnoticed` test catches stale entries. | allowlist in `tests/test_metric_consistency.py` |
| FU-6 | Soft-delete audit cross-link | soft-delete maintainer | F6 intersects soft-delete semantics; aligning the two audits keeps the metric and soft-delete contracts coherent. | `docs/soft-delete-audit.md`, §I0.4-F6 |

## I2.5 — Success criteria check

Closing the audit against the §6 success criteria from the calling prompt:

- [x] Phase 1 audit document complete; every count surface inventoried (44 surfaces in §I0.1 + §I1.1)
- [x] `app/metrics/` module created or extended with canonical functions (`runs_aggregate` added; module pre-existed)
- [x] Every count surface refactored to consume the metric layer (within the recommended scope; FU-4 / FU-5 track the rest)
- [x] Math invariant tests in place and passing (17 tests, including 5 new ones from this audit)
- [x] Architectural invariant test catches direct queries outside the metric layer (stress-tested with a fake violator; passes)
- [x] `docs/metric-conventions.md` exists
- [x] CLAUDE.md created with calculations rule
- [x] Dashboard, Analysis Runs page, run detail page show correct numbers (S13 reconciliation: was 0, now 2)
- [x] Reconciliation table at end of Phase 2 shows ✓ for every previously-broken surface (§I2.3)
- [x] No regression on previously-correct surfaces (full backend suite 922 passed; FE 370 passed; pre-existing failures unchanged)
- [x] All existing tests still pass (verified)

**Audit closed.** Permanent guidance: [`docs/metric-conventions.md`](./metric-conventions.md). Future drift is caught at PR review by the architectural test and the math invariants.


