# Dashboard metrics — consistency audit

**Status:** Phase 1 / 6 — diagnosis only, no code changes.
**Date:** 2026-05-02
**Scope:** every numeric field rendered on the dashboard, run-detail, and lifetime surfaces.
**Severity:** P0 — public-facing numbers contradict each other; one screen says **6 KEV**, another says **0 KEV exposed**, both reading the same database.

This document is the diagnosis. Definitions and fixes land in the Phase 2 spec
([dashboard-metrics-spec.md](./dashboard-metrics-spec.md), upcoming).

---

## 1. Metric inventory

Every numeric field surfaced to a user, traced back to the SQL that produces it.

| Metric ID | Field name | Endpoint | SQL source | Dedup key | Time window | Scope | Status filter |
|---|---|---|---|---|---|---|---|
| `dash.stats.total_active_projects` | `total_active_projects` | `GET /dashboard/stats` | [app/routers/dashboard_main.py:78-80](../app/routers/dashboard_main.py#L78-L80) | none | lifetime | portfolio | `project_status = 1` |
| `dash.stats.total_sboms` | `total_sboms` | `GET /dashboard/stats` | [dashboard_main.py:81](../app/routers/dashboard_main.py#L81) | none | lifetime | portfolio | none |
| `dash.stats.total_findings` | `total_findings` | `GET /dashboard/stats` | [dashboard_main.py:83-90](../app/routers/dashboard_main.py#L83-L90) | none (raw rows) | implicit (latest run) | latest successful run per SBOM | `OK / FINDINGS / PARTIAL` |
| `dash.stats.total_distinct_vulnerabilities` | `total_distinct_vulnerabilities` | `GET /dashboard/stats` | [dashboard_main.py:91-98](../app/routers/dashboard_main.py#L91-L98) | `vuln_id` | implicit (latest run) | latest successful run per SBOM | successful |
| `dash.severity.{severity}` | severity dict | `GET /dashboard/severity` | [dashboard_main.py:147-159](../app/routers/dashboard_main.py#L147-L159) | none | implicit (latest run) | latest successful run per SBOM | successful |
| `dash.activity.active_30d` | `active_30d` | `GET /dashboard/activity` | [dashboard_main.py:131](../app/routers/dashboard_main.py#L131) | none | last 30d on `created_on` | portfolio | n/a (SBOM table) |
| `dash.activity.stale` | `stale` | `GET /dashboard/activity` | [dashboard_main.py:132-133](../app/routers/dashboard_main.py#L132-L133) | none | derived | portfolio | n/a |
| `dash.posture.severity` | `severity` | `GET /dashboard/posture` | [dashboard_main.py:184-195](../app/routers/dashboard_main.py#L184-L195) | none | implicit (latest run) | latest successful run per SBOM | successful |
| `dash.posture.kev_count` ⚠️ | `kev_count` | `GET /dashboard/posture` | [dashboard_main.py:198-205](../app/routers/dashboard_main.py#L198-L205) | `vuln_id` | implicit | latest successful run per SBOM | successful |
| `dash.posture.fix_available_count` | `fix_available_count` | `GET /dashboard/posture` | [dashboard_main.py:210-220](../app/routers/dashboard_main.py#L210-L220) | `vuln_id` | implicit | latest successful run per SBOM | successful, `fixed_versions` non-empty |
| `dash.posture.last_successful_run_at` | `last_successful_run_at` | `GET /dashboard/posture` | [dashboard_main.py:223-227](../app/routers/dashboard_main.py#L223-L227) | n/a | lifetime max | portfolio | successful |
| `dash.posture.total_findings` | `total_findings` | `GET /dashboard/posture` | [dashboard_main.py:235-242](../app/routers/dashboard_main.py#L235-L242) | none | implicit | latest successful run per SBOM | successful |
| `dash.posture.distinct_vulnerabilities` | `distinct_vulnerabilities` | `GET /dashboard/posture` | [dashboard_main.py:243-250](../app/routers/dashboard_main.py#L243-L250) | `vuln_id` | implicit | latest successful run per SBOM | successful |
| `dash.posture.net_7day_added` ⚠️ | `net_7day_added` | `GET /dashboard/posture` | [services/dashboard_metrics.py:314-360](../app/services/dashboard_metrics.py#L314-L360) | `vuln_id` | today vs 7 days ago | latest successful run per SBOM as-of-date | successful |
| `dash.posture.net_7day_resolved` ⚠️ | `net_7day_resolved` | `GET /dashboard/posture` | [services/dashboard_metrics.py:314-360](../app/services/dashboard_metrics.py#L314-L360) | `vuln_id` | today vs 7 days ago | latest successful run per SBOM as-of-date | successful |
| `dash.posture.headline_state` | `headline_state` | `GET /dashboard/posture` | [services/dashboard_metrics.py:52-83](../app/services/dashboard_metrics.py#L52-L83) | derived | n/a | n/a | n/a |
| `dash.lifetime.sboms_scanned_total` | `sboms_scanned_total` | `GET /dashboard/lifetime` | [services/dashboard_metrics.py:399](../app/services/dashboard_metrics.py#L399) | none | lifetime | portfolio | n/a |
| `dash.lifetime.projects_total` | `projects_total` | `GET /dashboard/lifetime` | [services/dashboard_metrics.py:400](../app/services/dashboard_metrics.py#L400) | none | lifetime | portfolio | n/a |
| `dash.lifetime.runs_executed_total` ⚠️ | `runs_executed_total` | `GET /dashboard/lifetime` | [services/dashboard_metrics.py:401](../app/services/dashboard_metrics.py#L401) | none | lifetime | portfolio | none — counts ALL runs incl. ERROR |
| `dash.lifetime.runs_executed_this_week` | `runs_executed_this_week` | `GET /dashboard/lifetime` | [services/dashboard_metrics.py:402-410](../app/services/dashboard_metrics.py#L402-L410) | none | last 7d on `started_on` | portfolio | none |
| `dash.lifetime.findings_surfaced_total` ⚠️ | `findings_surfaced_total` | `GET /dashboard/lifetime` | [services/dashboard_metrics.py:415-430](../app/services/dashboard_metrics.py#L415-L430) | `vuln_id\|component_name\|component_version` | lifetime | all findings (all runs) | none — counts findings from ERROR runs too |
| `dash.lifetime.findings_resolved_total` | `findings_resolved_total` | `GET /dashboard/lifetime` | [services/dashboard_metrics.py:291-306](../app/services/dashboard_metrics.py#L291-L306) | `(vuln_id, component_name, component_version)` | lifetime | consecutive successful pairs | successful only (in pair builder) |
| `dash.lifetime.first_run_at` | `first_run_at` | `GET /dashboard/lifetime` | [services/dashboard_metrics.py:434-438](../app/services/dashboard_metrics.py#L434-L438) | n/a | lifetime min | portfolio | successful |
| `dash.lifetime.days_monitoring` | `days_monitoring` | `GET /dashboard/lifetime` | [services/dashboard_metrics.py:440-448](../app/services/dashboard_metrics.py#L440-L448) | derived | derived | derived | derived from successful |
| `dash.trend.points[d].{severity}` ⚠️ | per-day severity counts | `GET /dashboard/trend` | [services/dashboard_metrics.py:103-161](../app/services/dashboard_metrics.py#L103-L161) | **none — sums raw rows** | last `days` on `started_on` | **all successful runs in window (NO latest-per-SBOM)** | successful |
| `dash.trend.avg_total` | `avg_total` | `GET /dashboard/trend` | [routers/dashboard.py:54](../app/routers/dashboard.py#L54) | n/a | derived | derived | derived |
| `dash.trend.earliest_run_date` | `earliest_run_date` | `GET /dashboard/trend` | [routers/dashboard.py:60-65](../app/routers/dashboard.py#L60-L65) | n/a | lifetime min | portfolio | successful |
| `dash.trend.annotations[].sbom_uploaded` | upload markers | `GET /dashboard/trend` | [services/dashboard_metrics.py:182-201](../app/services/dashboard_metrics.py#L182-L201) | `created_on` day | window | `sbom_source` | n/a |
| `dash.trend.annotations[].remediation` | resolved markers | `GET /dashboard/trend` | [services/dashboard_metrics.py:208-224](../app/services/dashboard_metrics.py#L208-L224) | `(vuln_id, component_name, component_version)` | window | consecutive successful pairs | successful |
| `run.detail.id, run_status, ...` | run row | `GET /api/runs/{id}` | [routers/runs.py:259-264](../app/routers/runs.py#L259-L264) | n/a | single run | run | n/a |
| `run.detail.total_findings` | `total_findings` | row attribute | precomputed in run row by analysis pipeline | none | single run | run | n/a |
| `run.detail.{severity}_count` | severity counts on run row | row attribute | precomputed by analysis pipeline | none | single run | run | n/a |
| `run.detail.kev_badge` ⚠️ | "N KEV" pill | `GET /api/runs/{id}/findings-enriched` (FE derives) | [routers/runs.py:303-317, 360-396](../app/routers/runs.py#L303-L317), FE [RunDetailHero.tsx:167](../frontend/src/components/analysis/RunDetailHero.tsx#L167) | derived per finding | single run | run | per-finding `in_kev = vuln_id OR any alias ∈ kev_entry` |
| `run.detail.worst_risk` | `Worst risk score` hint | derived in FE from `findings-enriched` | derived | single run | run | n/a |
| `runs.recent[]` | sidebar list | `GET /api/runs/recent` | [routers/runs.py:157-196](../app/routers/runs.py#L157-L196) | n/a | most-recent N | portfolio | none — all statuses |
| `recent_sboms[]` | recent SBOMs | `GET /dashboard/recent-sboms` | [dashboard_main.py:117-124](../app/routers/dashboard_main.py#L117-L124) | n/a | most-recent N | portfolio | n/a |

⚠️ flagged rows are involved in the contradictions documented in §2.

---

## 2. Contradiction matrix

What the user sees on the screen (per the attached screenshots):

| Surface | Number shown | Apparent metric | Maps to |
|---|---|---|---|
| Run #4 detail · "Findings" tile | **513** | findings count in run #4 | `run.detail.total_findings` (run row attribute) |
| Run #4 detail · severity strip totals | 53 + 212 + 171 + 70 + 7 = **513** | severity within run | `run.detail.{severity}_count` (run row attributes) |
| Run #4 detail · KEV badge | **6 KEV** | KEV findings in run #4 | derived FE: filter(`in_kev`) on enriched findings (vuln_id ∪ aliases ∩ kev_entry) |
| Dashboard hero · headline | **88 critical findings across 3 SBOMs** | aggregate criticals | `dash.posture.severity.critical` (latest-per-SBOM) |
| Dashboard hero · severity bar totals | 88 + 370 + 301 + 115 + 12 = **886** | aggregate total findings | sum of `dash.posture.severity` |
| Dashboard hero · "KEV exposed" | **0** | KEV count, portfolio-wide | `dash.posture.kev_count` (vuln_id only ∩ kev_entry) |
| Dashboard hero · "Net 7-day change" | **+513 / −0** | adds/resolves vs prior 7 days | `dash.posture.net_7day_*` |
| Findings trend legend | Critical 123 · High 528 · Medium 431 · Low 160 · Unknown 17 = **1,259** | trend totals | sum across `dash.trend.points` rows |
| Findings trend empty-state | "1 run so far" | run count for trend | FE-derived `populatedDays` (count of distinct dates with `total > 0`) |
| "Your Analyzer, So Far" · Findings surfaced | **513** | lifetime distinct findings | `dash.lifetime.findings_surfaced_total` |
| "Your Analyzer, So Far" · Runs executed | **4** | lifetime run count | `dash.lifetime.runs_executed_total` |
| Sidebar · Recent runs | 4 distinct rows | recent runs visible | `runs.recent` |

### Contradictions (must reconcile, currently don't):

| # | Pair | Surface A | Value A | Surface B | Value B | Should reconcile because | Currently reconciles? |
|---|------|-----------|---------|-----------|---------|--------------------------|-----------------------|
| C1 | Run KEV vs Dashboard KEV | run #4 KEV badge | **6** | dashboard "KEV exposed" | **0** | dashboard KEV must equal Σ KEV across the latest run of each SBOM; run #4 is the latest run of its SBOM | ❌ NO |
| C2 | Trend run count vs Lifetime run count | trend empty state copy | **1 run so far** | lifetime "Runs executed" | **4** | both claim to describe "runs the user has done" | ❌ NO |
| C3 | Trend severity totals vs Lifetime "Findings surfaced" | trend legend Σ | **1,259** | lifetime distinct findings | **513** | sum of trend daily severity counts MUST be ≤ lifetime distinct (each daily count is a snapshot of distinct findings on that day; the union over 30 days cannot exceed the all-time union) | ❌ NO (1,259 > 513 is mathematically impossible if each were correct) |
| C4 | Trend severity totals vs Dashboard hero totals | trend legend Σ | **1,259** | dashboard hero severity Σ | **886** | trend recent days should reflect today's-as-of state, which equals dashboard hero | ❌ NO |
| C5 | Lifetime findings vs sum across SBOMs | lifetime "Findings surfaced" | **513** | dashboard hero severity Σ (latest-per-SBOM, 3 SBOMs) | **886** | lifetime distinct ≥ snapshot total when SBOMs share no findings, and ≤ snapshot total only when there is full overlap; 513 < 886 with 3 distinct SBOMs implies near-total overlap, OR a bug counting only one SBOM | ⚠️ SUSPICIOUS (probable bug) |
| C6 | Net 7-day vs first-scan reality | net 7-day | **+513 / −0** | trend empty state | "1 run so far" | if there are no prior-period runs, the comparison is undefined; the metric should signal `is_first_period`, not silently emit `+N / −0` | ❌ NO (silent fallthrough) |
| C7 | Trend empty state condition vs run count | empty state shown | yes | run count | **4** | the empty state's purpose is "not enough history to chart"; with 4 runs over 30 days the chart should at least try to render | ❌ Empty state fires when it shouldn't |
| C8 | Run KEV badge math | run #4 says 6 KEV but dashboard's KEV catalog returns 0 across that same run | -- | -- | the two should not be capable of disagreeing for the same input | ❌ NO |

### Reconciliations that DO hold (sanity-check baseline)

| Pair | Holds? |
|---|---|
| Run severity strip Σ == Run "Findings" tile (513 == 513) | ✅ |
| Sidebar count of recent runs == lifetime "Runs executed" (4 == 4) | ✅ |
| Hero severity bar Σ == hero "X critical findings across N SBOMs" headline scope | ✅ structural (888 sum = posture severity total) |

---

## 3. Per-bug code references (verbatim)

### Bug 1 — KEV count contradiction (P0)

**Symptom:** run #4 detail shows `6 KEV`, dashboard shows `0 KEV exposed`.

**Run-detail KEV** uses CVE aliases ([routers/runs.py:303-317](../app/routers/runs.py#L303-L317), then [runs.py:360-366](../app/routers/runs.py#L360-L366)):

```python
def _cve_aliases_for(finding: AnalysisFinding) -> list[str]:
    """Pull every CVE ID we can find on a finding (vuln_id + aliases JSON)."""
    ids: list[str] = []
    if finding.vuln_id:
        ids.extend(_CVE_RE.findall(finding.vuln_id))
    if finding.aliases:
        try:
            parsed = json.loads(finding.aliases)
            if isinstance(parsed, list):
                for a in parsed:
                    if isinstance(a, str):
                        ids.extend(_CVE_RE.findall(a))
        except (TypeError, ValueError):
            ids.extend(_CVE_RE.findall(finding.aliases))
    return sorted({i.upper() for i in ids if i})
...
finding_cves: dict[int, list[str]] = {f.id: _cve_aliases_for(f) for f in findings}
...
kev_set: set[str] = lookup_kev_set_memoized(db, cve_list) if cve_list else set()
...
in_kev = any(c in kev_set for c in cves)
```

The run-detail page derives `kev_count` on the FE by filtering `findings.in_kev`
([RunDetailHero.tsx:167](../frontend/src/components/analysis/RunDetailHero.tsx#L167)):

```tsx
const kevCount = useMemo(() => (findings ?? []).filter((f) => f.in_kev).length, [findings]);
```

**Dashboard KEV** ignores aliases ([dashboard_main.py:198-205](../app/routers/dashboard_main.py#L198-L205)):

```python
kev_count = (
    db.execute(
        select(func.count(func.distinct(AnalysisFinding.vuln_id)))
        .join(KevEntry, KevEntry.cve_id == AnalysisFinding.vuln_id)  # vuln_id only
        .where(AnalysisFinding.analysis_run_id.in_(latest_runs))
    ).scalar_one()
    or 0
)
```

**Root cause.** Two different KEV-membership predicates. A finding whose
`vuln_id` is `GHSA-xxxx-yyyy-zzzz` but whose `aliases` JSON contains
`CVE-2024-1234` (which IS in `kev_entry`) is counted as KEV by the run-detail
endpoint and NOT counted by the dashboard. With 6 GHSA-prefixed-but-CVE-aliased
KEV findings in run #4, the contradiction is exactly the observed `6 vs 0`.

---

### Bug 2 — Run count contradiction (P1)

**Symptom:** trend empty state says "1 run so far"; lifetime says 4 runs.

**Source** ([FindingsTrendChart.tsx:138-142, 238](../frontend/src/components/dashboard/FindingsTrendChart/FindingsTrendChart.tsx#L138-L142)):

```tsx
const populatedDays = useMemo(
  () => points.filter((p) => (p.total ?? 0) > 0).length,
  [points],
);
const showEmptyState = populatedDays > 0 && populatedDays < 7;
...
<EmptyTrendState runsSoFar={populatedDays} />
```

`populatedDays` is the count of distinct calendar dates with any findings in the
30-day window — **not** a run count. With 4 runs all completing on the same
day, `populatedDays === 1` and the FE renders "1 run so far". The variable name
"runsSoFar" is the lie. The backend never sends a real run count to this
component.

---

### Bug 3 — Trend legend totals are structurally impossible (P0)

**Symptom:** trend legend sums to 1,259 in the last 30 days; lifetime distinct
is 513. 1,259 > 513 with the same database is mathematically impossible if both
were defined consistently.

**Source** ([services/dashboard_metrics.py:103-132](../app/services/dashboard_metrics.py#L103-L132)):

```python
def build_trend_points(db: Session, *, days: int) -> list[TrendDataPoint]:
    cutoff = (datetime.now(UTC) - timedelta(days=days - 1)).date().isoformat()
    date_expr = func.substr(AnalysisRun.started_on, 1, 10).label("day")
    rows = db.execute(
        select(
            date_expr,
            AnalysisFinding.severity.label("severity"),
            func.count(AnalysisFinding.id).label("count"),
        )
        .join(AnalysisRun, AnalysisRun.id == AnalysisFinding.analysis_run_id)
        .where(
            AnalysisRun.started_on >= cutoff,
            AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES),
        )
        .group_by(date_expr, AnalysisFinding.severity)
    ).all()
```

**Root cause.** The query joins **every successful run in the window** to its
findings and counts the rows. There is:

1. No `latest-run-per-SBOM` scoping — if SBOM #1 has runs on days D, D+5, D+10,
   the same finding shows up three times (once per run).
2. No deduplication on `(vuln_id, component_name, component_version)` — a
   finding present in N consecutive runs gets counted N times.

The legend then sums `points[].critical` across **all 30 days**, multiplying
the over-count again. The result diverges arbitrarily from any honest
"distinct findings active over the period" definition.

The shape the legend is *trying* to communicate is **per-day distinct findings
active as-of-that-day**, but the implementation is **sum of raw finding rows
across all runs in the window**.

---

### Bug 4 — "Findings surfaced" lifetime equals a single-run count (P1)

**Symptom:** lifetime "Findings surfaced" reads 513, exactly equal to run #4's
finding count.

**Source** ([services/dashboard_metrics.py:415-430](../app/services/dashboard_metrics.py#L415-L430)):

```python
findings_surfaced = (
    db.execute(
        select(
            func.count(
                func.distinct(
                    func.coalesce(AnalysisFinding.vuln_id, "")
                    + "|"
                    + func.coalesce(AnalysisFinding.component_name, "")
                    + "|"
                    + func.coalesce(AnalysisFinding.component_version, "")
                )
            )
        )
    ).scalar()
    or 0
)
```

This **does** dedup by `(vuln_id, component, version)` over **all** findings —
so the SQL is correct in shape. The 513-equals-run-#4 coincidence still
indicates a bug because of the surrounding context:

- Hero severity bar Σ across 3 SBOMs = **886**.
- If 3 distinct SBOMs together produce 886 finding-rows in their latest runs,
  the **distinct-tuple union** across them is at minimum 513 only if the
  overlap between SBOMs is enormous (∼42% reduction).
- More likely, runs from the **other two SBOMs are filtered out** somewhere
  upstream of this query, or the `findings_surfaced` query is silently scoped
  to one SBOM in the user's working data.

**Root cause is the lack of a status filter** — this query reads from
`AnalysisFinding` with no join to `AnalysisRun`, so it includes findings from
ERROR/PENDING runs (which can be partial / orphaned). It also has no documented
reconciliation with `dash.posture.severity.*` (which IS scoped to successful
latest runs). The two metrics walk past each other instead of relating.

The Phase 2 spec re-grounds `findings.distinct_lifetime` on **successful runs
only** and locks an invariant: `findings.distinct_lifetime ≥ findings.latest_per_sbom.total`
when SBOMs do not overlap, and `≥ max(over SBOMs) of findings.in_run.total`
unconditionally.

---

### Bug 5 — Net 7-day change is misleading on first scan (P1)

**Symptom:** dashboard reads `+513 / −0` even though "1 run so far" elsewhere
implies no prior period existed to compare against.

**Source** ([services/dashboard_metrics.py:314-360](../app/services/dashboard_metrics.py#L314-L360)):

```python
def compute_net_7day_change(db: Session) -> tuple[int, int]:
    seven_days_ago = (datetime.now(UTC) - timedelta(days=7)).isoformat()
    today_runs = (
        select(func.max(AnalysisRun.id))
        .where(AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES))
        .group_by(AnalysisRun.sbom_id)
        .scalar_subquery()
    )
    today_vulns: set[str] = {...}  # current latest-per-SBOM vuln_ids
    historical_runs = (
        select(func.max(AnalysisRun.id))
        .where(AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES))
        .where(AnalysisRun.started_on <= seven_days_ago)
        .group_by(AnalysisRun.sbom_id)
        .scalar_subquery()
    )
    historical_vulns: set[str] = {...}  # latest-per-SBOM as-of-7-days-ago

    added = len(today_vulns - historical_vulns)
    resolved = len(historical_vulns - today_vulns)
    return added, resolved
```

When the user ran their first scans this week, `historical_runs` returns no
rows, `historical_vulns = set()`, and the math falls through to
`added = |today_vulns|, resolved = 0`. **No flag is set** to tell the FE this
is a degenerate "first period" case, so the UI dutifully renders `+513 / −0`.

The signature itself encodes the bug — `tuple[int, int]` has nowhere to put a
`is_first_period` boolean. The Phase 3 fix replaces the return type with a
result struct.

---

### Bug 6 — Trend empty-state condition triggers on same-day runs (P2)

**Symptom:** trend shows the empty state ("Trend will appear after a week of
regular scanning") even though there are 4 runs and 30 days of date range.

**Source** ([FindingsTrendChart.tsx:138-142](../frontend/src/components/dashboard/FindingsTrendChart/FindingsTrendChart.tsx#L138-L142)):

```tsx
const populatedDays = useMemo(
  () => points.filter((p) => (p.total ?? 0) > 0).length,
  [points],
);
const showEmptyState = populatedDays > 0 && populatedDays < 7;
```

The condition is "fewer than 7 distinct dates with any findings". With 4 runs
on the same day, `populatedDays === 1` and the empty state fires — even though
the chart has plenty of data to render (a single tall column on day-zero is a
legitimate view; later days zero-fill).

The intended threshold is "fewer than 7 days of *history*" — i.e.,
`days_since_first_run < 7` — not "fewer than 7 days each had findings".

---

## 4. Structural root causes

These six bugs share two underlying causes. Fixing them in isolation guarantees
a seventh:

**A. No canonical metric definition layer.**
Every endpoint (`/dashboard/posture`, `/dashboard/lifetime`, `/dashboard/trend`,
`/api/runs/{id}/findings-enriched`) reinvents its aggregation. There is no
shared definition of "KEV count", "findings total", or "findings distinct" that
all queries agree on. The KEV contradiction (Bug 1) is the most visible
example, but the latent risk is uniform.

**B. Aggregation scope is ambiguous.**
"Findings across all runs" is currently meant in three different ways
simultaneously:

* sum every finding row in every run (over-counts) — Bug 3 (trend);
* take the deduplicated union — Bug 4 (lifetime, partly correct);
* take the latest run per SBOM and aggregate (current state) — `dash.posture.*`.

Each is valid for a different question. Phase 2 locks the *two* canonical
conventions and forbids the third.

---

## 5. Open questions for owner review

These ambiguities surfaced during the audit. Phase 2 will resolve each before
any code is touched.

1. **KEV alias scope.** The run-detail endpoint considers any CVE alias on a
   finding when matching against `kev_entry`. The dashboard does not. The fix
   is to consolidate — but **which direction**? Answer expected: **always
   include aliases** (matches user mental model: "this CVE on the KEV catalog
   is exploitable, regardless of which advisory we tracked it under"). Phase 2
   will write this into the `findings.kev_in_scope` definition.

2. **Lifetime status filter.** `findings.distinct_lifetime` currently has no
   `run_status` filter, while `dash.posture.*` is locked to successful runs.
   Inconsistency. Phase 2 proposal: **lifetime joins to successful runs only**,
   so a half-completed ERROR run does not inflate the cumulative number. This
   is a soft change — if a user re-scans and the run errors, that scan's
   findings are excluded from the cumulative tile until the next successful
   run.

3. **Run count: all runs vs successful runs.** `dash.lifetime.runs_executed_total`
   currently counts ALL runs (including ERROR). The trend's empty-state copy
   probably wants successful-only. Phase 2: **expose both** — `runs_total`
   (all) and `runs_completed` (successful) — and let the consumer pick. Default
   the empty-state copy to `runs_total` because "you have done X runs" reads
   most honestly that way (an ERROR run is still a run).

4. **First-period semantics for net 7-day.** When all runs are within the past
   7 days, what does `is_first_period` mean? Phase 2 proposal: `is_first_period
   = (no successful run completed before today − 7 days)`. The FE then renders
   "first scan this week — comparison available next week" instead of `+N/−0`.

5. **Trend daily-distinct: as-of-date vs daily increment.** The trend has been
   showing "daily severity counts across all analysis runs" but the math the
   user expects is "distinct findings active **as of the end of that day**".
   Phase 2 locks the latter — every day's bar represents the snapshot, so the
   chart trends like a posture series, not a finding-arrival series.

6. **`runs_executed_this_week` semantics.** Currently `started_on >= 7d_ago`
   without a status filter. Should this be **completed** within the window, or
   **started** within the window? Phase 2 proposal: **completed** — a run
   that started 8 days ago and finished yesterday is "this week's work" from
   the user's perspective.

---

## 6. Inventory of metrics that do NOT match a future canonical definition

Documented here so Phase 4 has a clean cutover list.

* `GET /dashboard/stats` — `total_findings`, `total_distinct_vulnerabilities`
  duplicate `posture.total_findings` and `posture.distinct_vulnerabilities`.
  Phase 4 routes them through the canonical metrics; the response shape stays
  but the SQL collapses.
* `GET /dashboard/severity` — duplicates `posture.severity`. Same plan.
* `GET /dashboard/posture` — `kev_count` definition replaced (aliases-aware).
  `net_7day_added/resolved` augmented with `is_first_period`.
* `GET /dashboard/lifetime` — `findings_surfaced_total` re-defined with
  successful-only filter. `runs_executed_total` documented as "all statuses",
  `runs_completed_total` added. Optional `runs_distinct_dates` exposed.
* `GET /dashboard/trend` — `points` re-derived from `findings.daily_distinct_active`,
  not raw row sums. `runs_total` and `runs_distinct_dates` added to the
  response so the FE empty-state copy can stop lying.
* `GET /api/runs/{id}/findings-enriched` — `in_kev` derivation moved into the
  shared `findings.kev_in_scope` helper. The returned shape is unchanged.
* FE [FindingsTrendChart.tsx:138-142](../frontend/src/components/dashboard/FindingsTrendChart/FindingsTrendChart.tsx#L138-L142) — the
  empty-state condition switches to `runs_distinct_dates < 7` (server-supplied)
  and the copy uses `runs_total` (server-supplied).
* FE [HeroMetricRow.tsx:67-85](../frontend/src/components/dashboard/HeroPostureCard/HeroMetricRow.tsx#L67-L85) — net 7-day tile branches on `is_first_period`
  to render "first scan this week" copy.

---

## 7. Phase 1 gate

**Asks of the owner before Phase 2 begins:**

1. Confirm the diagnosis above is the bug they observed (the screenshots
   reconcile to the contradiction matrix in §2).
2. Resolve the six open questions in §5 (default answers proposed; thumbs-up
   acceptable).
3. Approve the structural framing — two canonical aggregation conventions,
   one shared metric module — before the spec doc is written in Phase 2.

No code has been touched. No commits made.
