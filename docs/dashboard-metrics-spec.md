# Dashboard metrics — canonical specification

**Status:** Phase 2 / 6 — definitions only. No code yet. This document is the
single source of truth for "what does each number on the dashboard mean."
**Phase 1 audit:** [dashboard-metrics-audit.md](./dashboard-metrics-audit.md).
**Date:** 2026-05-02.

> If you are about to add a new metric, **read §2 first**. Pick from the
> canonical catalog (§3). If your need is not in the catalog, extend the
> catalog before writing the SQL.

---

## 1. Resolution of Phase 1 open questions

These are locked by this document. Phase 3 implementation must respect them.

| Q | Decision | Rationale |
|---|----------|-----------|
| Q1 — KEV alias scope | KEV matches on `vuln_id` **AND every CVE alias** on the finding. | The CISA KEV catalog is keyed by CVE. A finding tracked under a GHSA/OSV identifier whose alias is a KEV-listed CVE *is* exploitable; suppressing it on the dashboard hides risk. The run-detail page already does this; the dashboard joins the same convention. |
| Q2 — Lifetime status filter | `findings.distinct_lifetime` joins to **successful runs only** (`OK`, `FINDINGS`, `PARTIAL`). | Symmetric with every other dashboard metric. An ERROR run can have orphaned, partial, or wrong findings; including them in the lifetime tile would inflate "you have ever surfaced" with junk data. |
| Q3 — Run count semantics | Expose **both**: `runs.total_lifetime` (all statuses) and `runs.completed_lifetime` (successful only). The lifetime tile uses the former; the trend empty-state copy uses the former. | "Runs executed" reads honestly as "every run, including ones that errored", which is the user mental model. The empty-state copy reads "X runs so far" which is the same convention. |
| Q4 — Net 7-day first-period | `is_first_period = true` when no successful run completed strictly before `today − 7 days`. The FE renders "first scan this week — comparison available next week" instead of `+N / −0`. | A delta vs an empty prior period is undefined, not zero. Honesty over false precision. |
| Q5 — Trend daily semantics | Each day's bar = **distinct findings active as of end-of-day** in the latest successful run of each SBOM as-of that date. **Never** sum raw rows across runs. | Eliminates the "1,259 in 30 days when lifetime is 513" impossibility. Each day's count is independently sane and the Σ over days is meaningful as "total exposure-days" (not as "total findings"). |
| Q6 — `runs_executed_this_week` | Count of runs whose `completed_on` falls in the last 7 days, all statuses. | "This week's work" reads better as completion than as start. ERROR runs still count — the user did the work, even if the run failed. |

---

## 2. The two aggregation conventions (locked)

Every metric in the catalog follows exactly one of these. **There is no third
convention.**

### Convention A — "Latest state."

Used for portfolio-wide *current* numbers (dashboard hero, KEV exposed,
severity distribution, fix-available count). Aggregates over the **latest
successful run of each SBOM**.

* "Successful" = `run_status ∈ {OK, FINDINGS, PARTIAL}` (per ADR-0001).
* "Latest" = `MAX(analysis_run.id)` per `sbom_id`, restricted to successful
  statuses. (`id` is monotonic with `started_on` for our writer; documented
  in [dashboard_main.py:48-60](../app/routers/dashboard_main.py#L48-L60).)
* Answers: **"What does my portfolio look like right now?"**

### Convention B — "Lifetime distinct."

Used for cumulative-value numbers (lifetime stats, trend chart, time-window
deltas). Aggregates over **distinct `(vuln_id, component_name, component_version)`
tuples** from the rows that match a status filter.

* Dedup key: `(vuln_id, component_name, component_version)` — the same key
  used by `_finding_keys_for_run` and `findings_resolved_total`. Locked.
* Status filter: successful runs only, unless explicitly noted otherwise.
* Answers: **"How many real, unique findings has this tool surfaced?"** (or
  active as-of, or active during a window).

### What is forbidden

> **Never sum raw `analysis_finding` rows across multiple runs.**
> A finding present in 10 runs becomes 10 instead of 1. This is the root
> cause of Bug 3 (trend totals exceed lifetime). Implementations that need a
> daily aggregate compute distinct **as-of-day** snapshots and either return
> the per-day number or sum *those* — never the raw rows.

If you find yourself tempted to write `SUM(...)` or `COUNT(*)` across multiple
runs without a `latest-per-SBOM` filter or a distinct-tuple dedup, stop.
Re-read this section.

---

## 3. Canonical metric catalog

Every numeric field on every dashboard / run-detail surface maps to exactly
one of these. The implementation in Phase 3 (`app/metrics/`) is one Python
function per metric ID, returning a typed result.

### 3.1 Findings — single run (Convention A, scope=run)

#### `findings.in_run.total`

* **Plain English.** How many finding-rows are in this specific run.
* **Definition.** `count(analysis_finding.id) WHERE analysis_run_id = :run_id`.
* **Dedup.** None — each row is a finding-instance.
* **Time window.** Single run.
* **Used by.** Run-detail "Findings" tile, run-detail PDF, run-list table.
* **Reconciliation invariants.**
  * `Σ findings.in_run.severity_distribution.values() == findings.in_run.total`.
  * Equals the precomputed `analysis_run.total_findings` column (writer-side
    invariant; if it ever drifts, the writer is buggy).
* **Edge cases.** Returns 0 when run has no findings.

#### `findings.in_run.severity_distribution`

* **Plain English.** How findings split by severity in this run.
* **Definition.** `dict[severity → count(*)]` over rows where
  `analysis_run_id = :run_id`, grouped by `severity`. Severities are
  case-folded; unknown/null falls into `unknown`.
* **Dedup.** None.
* **Used by.** Run-detail severity strip, run-list inline bars.
* **Reconciliation invariants.**
  * `sum(values()) == findings.in_run.total`.
  * Equals `(critical_count, high_count, medium_count, low_count, unknown_count)`
    on the `analysis_run` row (writer-side invariant).

#### `findings.in_run.kev`

* **Plain English.** How many findings in this run are listed in CISA KEV.
* **Definition.** `count(*) WHERE analysis_run_id = :run_id AND _is_kev_listed(finding)`,
  where `_is_kev_listed` is the **shared helper** (see §3.5).
* **Dedup.** None — counts finding-rows, not distinct CVEs. This is what the
  badge "{N} KEV" on the run-detail page already shows; locking it as the
  canonical answer.
* **Used by.** Run-detail KEV badge, run-detail PDF, the cross-surface
  reconciliation invariant in §4.
* **Reconciliation invariants.**
  * For the latest successful run of an SBOM, `findings.in_run.kev` equals
    `findings.kev_in_scope(scope=run, run_id=that_run)`.
  * Σ over the latest successful run of each SBOM equals
    `findings.kev_in_scope(scope=latest_per_sbom)` — **this is the dashboard
    KEV invariant**.

### 3.2 Findings — latest state (Convention A, scope=latest_per_sbom)

#### `findings.latest_per_sbom.total`

* **Plain English.** How many finding-rows live in the latest successful run
  of each SBOM, summed across SBOMs.
* **Definition.** `count(analysis_finding.id) WHERE analysis_run_id ∈ latest_run_ids`,
  where `latest_run_ids` is the set of `MAX(id) GROUP BY sbom_id` for
  successful runs (the shared `_latest_run_per_sbom_cte` from §3.5).
* **Dedup.** None — finding-rows in the latest run; the same vuln on the
  same component in two different SBOMs counts twice (which is correct: it's
  exposure in two products).
* **Used by.** Dashboard hero severity bar Σ, `dash.posture.total_findings`,
  `dash.stats.total_findings`.
* **Reconciliation invariants.**
  * `Σ findings.latest_per_sbom.severity_distribution.values() == findings.latest_per_sbom.total`.
  * Equals `Σ over SBOMs of findings.in_run.total(latest_run_id_for_sbom)`.

#### `findings.latest_per_sbom.severity_distribution`

* **Plain English.** Severity breakdown of the latest-state finding rows.
* **Definition.** Same as `findings.in_run.severity_distribution` but with the
  `latest_run_per_sbom` CTE in place of a single run id.
* **Used by.** Dashboard hero severity bar segments, `dash.posture.severity`,
  `dash.severity` (deprecated standalone endpoint), the headline copy
  ("{critical} critical findings across {sbom_count} SBOMs").
* **Reconciliation invariants.**
  * `sum(values()) == findings.latest_per_sbom.total`.
  * For each SBOM, the per-SBOM contribution equals
    `findings.in_run.severity_distribution(latest_run_id)` — partial-sum
    consistency.

#### `findings.latest_per_sbom.distinct_vulnerabilities`

* **Plain English.** Distinct CVE-equivalent identifiers across the latest
  state.
* **Definition.** `count(distinct vuln_id) WHERE analysis_run_id ∈ latest_run_ids`.
* **Dedup.** By `vuln_id` (one CVE on N components → 1).
* **Used by.** `dash.posture.distinct_vulnerabilities`, the "of N distinct"
  caption on the Fix-available tile.

#### `findings.latest_per_sbom.fix_available`

* **Plain English.** Distinct vulns in the latest state with at least one
  upstream-suggested fixed version.
* **Definition.** `count(distinct vuln_id) WHERE analysis_run_id ∈ latest_run_ids
  AND fixed_versions IS NOT NULL AND fixed_versions NOT IN ('', '[]')`.
* **Dedup.** By `vuln_id`.
* **Used by.** `dash.posture.fix_available_count`.
* **Reconciliation invariants.** `≤ findings.latest_per_sbom.distinct_vulnerabilities`.

### 3.3 KEV — cross-cutting (Convention A, parameterised scope)

KEV is the metric the audit identified as having two divergent implementations.
**Single canonical definition; multiple scopes; one shared SQL helper.**

#### `findings.kev_in_scope`

* **Plain English.** How many findings, in the requested scope, are listed in
  CISA KEV — counted as **finding-rows** (not distinct CVEs), so it matches the
  run-detail badge "{N} KEV" semantics.
* **Definition.** `count(*) WHERE row matches scope filter AND _is_kev_listed(row)`.
* **Scopes.**
  * `scope=run, run_id=:r` → finding-rows in run `:r` that are KEV-listed.
  * `scope=latest_per_sbom` → finding-rows in the latest successful run of each
    SBOM that are KEV-listed.
  * `scope=portfolio` (reserved for future use) — distinct vulns across all
    successful runs that are KEV-listed.
* **Shared KEV-membership predicate.** A finding "is KEV-listed" iff its
  `vuln_id` (uppercased) **OR** any string parsed out of its `aliases` JSON
  matches a row in `kev_entry.cve_id`. This is the alias-aware predicate the
  run-detail page already uses; the dashboard adopts it.
* **Used by.** Run-detail KEV badge (`scope=run`), dashboard "KEV exposed"
  tile (`scope=latest_per_sbom`).
* **Reconciliation invariants.** **The lock for Bug 1.**
  * `findings.kev_in_scope(scope=latest_per_sbom)` ==
    `Σ over SBOMs of findings.kev_in_scope(scope=run, run_id=latest_run_id_for_sbom)`.
  * `findings.kev_in_scope(scope=run, run_id=:r)` ==
    `findings.in_run.kev(run_id=:r)`.
* **Edge cases.** Empty `aliases` JSON or unparseable alias strings → fall
  back to `vuln_id` only. Never crashes.

### 3.4 Findings — lifetime distinct (Convention B)

#### `findings.distinct_lifetime`

* **Plain English.** Total unique findings the tool has ever surfaced.
* **Definition.** `count(distinct (vuln_id, component_name, component_version))
  FROM analysis_finding f JOIN analysis_run r ON f.analysis_run_id = r.id
  WHERE r.run_status IN successful`.
* **Dedup.** By `(vuln_id, component_name, component_version)` — the locked
  finding-key tuple.
* **Status filter.** Successful runs only (Q2 decision).
* **Time window.** All time.
* **Scope.** Portfolio.
* **Used by.** "Findings surfaced" tile in "Your Analyzer, So Far" panel.
* **Reconciliation invariants.**
  * `findings.distinct_lifetime ≥ max over SBOMs of (distinct keys in latest run)`.
  * `findings.distinct_lifetime ≤ Σ over SBOMs of (distinct keys in latest run)`
    (equality when SBOMs share no findings).
  * Note: this does **not** require `≥ findings.latest_per_sbom.total` because
    `total` is a row count, not a distinct-key count. The relation is
    `findings.distinct_lifetime ≥ max over runs of findings.in_run.distinct_keys`
    — strict invariant, used by the consistency test in Phase 5.
* **Edge cases.** No successful runs → 0. No findings → 0.

#### `findings.distinct_active_as_of(date)` (helper)

* **Plain English.** Distinct findings present in the *as-of-date* snapshot,
  per Convention B.
* **Definition.** Distinct `(vuln_id, component_name, component_version)`
  tuples found in the latest successful run of each SBOM whose
  `completed_on <= date`. Implemented via the latest-as-of CTE in §3.5.
* **Used by.** `findings.daily_distinct_active` (below) and
  `findings.net_change.{n}d` (§3.7).
* **Edge cases.** No successful runs as of `date` → empty set.

#### `findings.daily_distinct_active`

* **Plain English.** Per day, the distinct findings active in the
  latest-state snapshot **as of end-of-day**, broken down by severity.
* **Definition.** For each day `d` in the requested window, compute
  `findings.distinct_active_as_of(d)` and group by severity. Returns one
  row per `(day, severity)`.
* **Dedup.** Yes — `(vuln_id, component_name, component_version)` distinct
  *within each day*.
* **Time window.** Caller-specified, default 30 days ending today.
* **Scope.** Portfolio as-of-date.
* **Status filter.** Successful only (the as-of CTE filters for it).
* **Used by.** Trend chart points. Replaces the broken `build_trend_points`.
* **Reconciliation invariants.**
  * For day = today: equals `findings.latest_per_sbom.severity_distribution`
    (modulo the difference between row-count and distinct-key-count — the
    latter is `≤` the former; we expose distinct-key as an additional
    `dash.posture.findings_distinct` metric so the trend's "today" column
    matches the hero exactly).
  * For any day `d`: `Σ severities ≤ findings.distinct_lifetime` (the day's
    snapshot cannot exceed the all-time union — the lock for Bug 3).
* **Edge cases.** Days before the first run → all-zero row.

### 3.5 Shared SQL helpers

These are the building blocks every metric uses. They live in
`app/metrics/_helpers.py` and are the only place these CTEs / clauses appear.
**Do not inline them at metric-call sites.**

#### `_latest_run_per_sbom_cte()`

```python
def _latest_run_per_sbom_cte() -> CTE:
    """One row per SBOM, with that SBOM's latest successful run id."""
    return (
        select(
            AnalysisRun.sbom_id,
            func.max(AnalysisRun.id).label("latest_run_id"),
        )
        .where(AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES))
        .group_by(AnalysisRun.sbom_id)
        .cte("latest_run_per_sbom")
    )
```

`MAX(id)` is preferred over `MAX(completed_on)` — `id` is monotonic with the
writer's serialisation per ADR-0001 and is `NOT NULL`, while `completed_on`
can drift from `started_on` for long-running scans.

#### `_latest_run_per_sbom_as_of_cte(as_of_date)`

```python
def _latest_run_per_sbom_as_of_cte(as_of_iso: str) -> CTE:
    """One row per SBOM, with that SBOM's latest successful run completed on or before as_of_iso."""
    return (
        select(
            AnalysisRun.sbom_id,
            func.max(AnalysisRun.id).label("latest_run_id"),
        )
        .where(AnalysisRun.run_status.in_(SUCCESSFUL_RUN_STATUSES))
        .where(AnalysisRun.completed_on <= as_of_iso)
        .group_by(AnalysisRun.sbom_id)
        .cte("latest_run_per_sbom_as_of")
    )
```

Used by `findings.daily_distinct_active` and `findings.net_change.{n}d`. Note
this filters by `completed_on` not `started_on` — a run that started before
`as_of` but completed after has not yet contributed to the as-of snapshot.

#### `_kev_aliases_clause(finding_alias)` and `_is_kev_listed(finding_alias)`

```python
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _kev_cves_for_finding(finding) -> list[str]:
    """Every CVE id we can extract from a finding (vuln_id + aliases JSON)."""
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


def _is_kev_listed(finding, kev_set: set[str]) -> bool:
    """True iff any CVE id in finding.vuln_id ∪ finding.aliases is in kev_set."""
    for cve in _kev_cves_for_finding(finding):
        if cve in kev_set:
            return True
    return False
```

This is the shared row-side predicate. `kev_set` is loaded once per query
(via `lookup_kev_set` over the candidate vuln_ids + aliases on the page)
so the SQL stays Pythonic-friendly without N+1 queries. For the dashboard
KEV count we batch-fetch the kev set for ALL distinct CVE-like strings
(vuln_id + parsed aliases) across the in-scope rows, then filter in Python.

This means **the dashboard KEV count will not be a single SQL query** —
it's "load candidate rows, parse aliases, intersect with `kev_entry`,
count". That is fine for our scale (~10k findings) and dramatically
simpler than building a SQL JSON-alias-extraction; benchmark the warm path
in Phase 3.

#### `_finding_key(row) -> tuple[str, str, str]`

```python
def _finding_key(row) -> tuple[str, str, str]:
    return ((row.vuln_id or ""), (row.component_name or ""), (row.component_version or ""))
```

The locked dedup tuple. Used by lifetime-distinct, daily-distinct, net-change,
and `compute_findings_resolved_total`. **One definition.**

### 3.6 Run metrics

#### `runs.total_lifetime`

* **Plain English.** Every run, all statuses.
* **Definition.** `count(*) FROM analysis_run`.
* **Used by.** "Runs executed" lifetime tile, trend empty-state copy
  ("X runs so far").
* **Note.** Counts ERROR / RUNNING / PENDING runs too. This is intentional
  per Q3 — "the user kicked off X runs" reads honestly with all of them.

#### `runs.completed_lifetime`

* **Plain English.** Completed-successfully runs.
* **Definition.** `count(*) FROM analysis_run WHERE run_status IN successful`.
* **Used by.** Internal sanity checks; reserved for FE.

#### `runs.completed_this_week`

* **Plain English.** Runs whose `completed_on` falls in the last 7 days.
* **Definition.** `count(*) FROM analysis_run WHERE completed_on >= now() − 7d`.
* **Used by.** "Runs executed" tile caption ("N this week").

#### `runs.distinct_dates_with_data`

* **Plain English.** How many distinct calendar dates have ≥ 1 successful run.
* **Definition.** `count(distinct date(started_on)) FROM analysis_run WHERE
  run_status IN successful`. Date computed in user TZ (UTC for v1; per-user TZ
  is out of scope per the constraints doc).
* **Used by.** Trend empty-state condition (`< 7` → show empty state). The
  empty-state **copy** uses `runs.total_lifetime`, the **condition** uses this.

#### `runs.first_completed_at`

* **Plain English.** Timestamp of the very first successful run.
* **Definition.** `min(completed_on) FROM analysis_run WHERE run_status IN successful`.
  Returns `None` when no successful runs exist.
* **Used by.** "Monitoring for X days" tile.

### 3.7 Time-window metrics (Convention B with explicit windows)

#### `findings.added_in_window(n_days)`

* **Plain English.** Distinct findings present in the latest snapshot today
  that were NOT present in the latest snapshot `n_days` ago.
* **Definition.**
  ```
  added = findings.distinct_active_as_of(today) - findings.distinct_active_as_of(today - n_days)
  ```
  Returns the **count** of the set difference.
* **Edge cases.** When the prior snapshot is empty → see `is_first_period`
  in `findings.net_change` below.

#### `findings.resolved_in_window(n_days)`

* **Plain English.** Distinct findings present in the snapshot `n_days` ago
  that are NOT in today's snapshot.
* **Definition.** Inverse of above.

#### `findings.net_change(n_days) → NetChangeResult`

* **Plain English.** Combined added / resolved with explicit first-period
  signaling.
* **Result struct.**
  ```python
  @dataclass
  class NetChangeResult:
      added: int
      resolved: int
      is_first_period: bool   # True iff no successful run completed before (today - n_days)
      window_days: int
  ```
* **Definition.**
  1. `today_set = findings.distinct_active_as_of(today)`.
  2. `prior_set = findings.distinct_active_as_of(today - n_days)`.
  3. `is_first_period = (no successful run completed strictly before today - n_days)`.
  4. If `is_first_period`: return `(added=len(today_set), resolved=0, is_first_period=True, ...)`.
  5. Else: return `(added=len(today_set - prior_set), resolved=len(prior_set - today_set), ...)`.
* **Used by.** `dash.posture.net_7day_*`. The FE sees `is_first_period` and
  switches copy from `+N / −0` to "first scan this week".
* **Reconciliation invariants.**
  * When `is_first_period=False`: `added - resolved == |today_set| - |prior_set|`.
  * When `is_first_period=True`: `resolved == 0`. Always.

### 3.8 Portfolio counts

#### `sboms.total`

* `count(*) FROM sbom_source`. Used by hero "across N SBOMs", lifetime tile.

#### `projects.active_total`

* `count(*) FROM projects WHERE project_status = 1`. Used by `dash.posture.total_active_projects`.

#### `projects.total`

* `count(*) FROM projects`. Used by lifetime tile.

#### `findings.resolved_lifetime`

* Carries forward the existing semantics: sum of finding-keys present in run N
  but absent from run N+1, across all consecutive successful run pairs of the
  same SBOM. Implementation already exists at
  [services/dashboard_metrics.py:291-306](../app/services/dashboard_metrics.py#L291-L306);
  Phase 3 moves it to `app/metrics/findings.py` and renames to
  `findings.resolved_lifetime`. Behaviour unchanged.

---

## 4. Cross-surface reconciliation invariants

These are the equalities that must hold at all times. Phase 5 implements a
test for each.

| ID | Invariant | What it locks |
|---|---|---|
| **I1** | `dash.posture.severity` Σ == `dash.posture.total_findings`. | Hero severity bar segments sum to total. |
| **I2** | `dash.posture.total_findings` == Σ over SBOMs of `findings.in_run.total(latest_run_id)`. | Hero total reconciles to the per-run table. |
| **I3** | `dash.posture.kev_count` == Σ over SBOMs of `run.detail.kev_badge(latest_run_id)`. | **Bug 1 lock** — dashboard KEV equals sum of run KEVs. |
| **I4** | For any day `d` in trend: `Σ severities[d] ≤ findings.distinct_lifetime`. | **Bug 3 lock** — no day's snapshot exceeds the all-time union. |
| **I5** | For day = today in trend: `Σ severities[today] == Σ over SBOMs of findings.in_run.distinct_keys(latest_run_id)`. | Trend's "today" column matches the hero's distinct-keys count. |
| **I6** | `dash.lifetime.findings_surfaced_total` ≥ `max over SBOMs of findings.in_run.distinct_keys(latest_run_id)`. | **Bug 4 lock** — lifetime cannot equal a single run's distinct count when more runs exist. |
| **I7** | `dash.lifetime.runs_executed_total == count(GET /api/runs/recent?limit=large_number)`. | **Bug 2 lock** — lifetime run count equals the sidebar's full list. |
| **I8** | `trend.runs_total == dash.lifetime.runs_executed_total`. | Trend's empty-state run count equals the lifetime tile. |
| **I9** | `dash.posture.net_7day.is_first_period == (no successful run completed before today - 7d)`. | **Bug 5 lock** — first-period flag is honest. |
| **I10** | When `is_first_period == True`: `resolved == 0`. | First-period contract. |
| **I11** | `dash.lifetime.findings_resolved_total ≤ findings.distinct_lifetime`. | Resolved-ever cannot exceed total-ever. |
| **I12** | `Σ findings.in_run.severity_distribution.values() == findings.in_run.total` for every run. | Per-run sanity. |

---

## 5. Wire-format additions

The Phase 4 endpoint refactor will add these fields. Consumers can ignore
them; they are additive.

### `GET /dashboard/posture` adds

```jsonc
{
  ...,
  "kev_count": 6,                          // RE-DEFINED, not new — see §3.3
  "net_7day": {                            // NEW envelope, replaces flat fields
    "added": 0,
    "resolved": 0,
    "is_first_period": true,
    "window_days": 7
  },
  "net_7day_added": 0,                     // KEPT for one-release back-compat
  "net_7day_resolved": 0                   // KEPT for one-release back-compat
}
```

### `GET /dashboard/lifetime` adds

```jsonc
{
  ...,
  "runs_executed_total": 4,                // unchanged semantics
  "runs_completed_total": 4,               // NEW — successful only
  "runs_distinct_dates": 1                 // NEW — distinct calendar dates with successful runs
}
```

### `GET /dashboard/trend` adds

```jsonc
{
  ...,
  "points": [...],                         // re-derived from findings.daily_distinct_active
  "runs_total": 4,                         // NEW — for empty-state copy ("4 runs so far")
  "runs_distinct_dates": 1                 // NEW — for empty-state condition (< 7 → show empty)
}
```

### `GET /api/runs/{id}/findings-enriched`

* No shape change. The `in_kev` boolean per finding is now derived via the
  shared `_is_kev_listed` helper instead of an inline duplicate. Same value
  for the same input.

---

## 6. Caching policy

| Metric family | TTL | Rationale |
|---|---|---|
| `findings.in_run.*` | none (per-request) | Single-run reads are <50ms; cache cost > miss cost. |
| `findings.latest_per_sbom.*` | 5 minutes | Hero reads — needs to feel live but not hammered. |
| `findings.kev_in_scope` | 5 minutes | Same hero scope. |
| `findings.distinct_lifetime` | 1 hour | Heavy distinct query; lifetime by definition slow-moving. Cache invalidates on new run id. |
| `findings.daily_distinct_active` | 15 minutes | Trend; expensive (N day × M SBOM CTEs). |
| `findings.net_change.*` | 5 minutes | Hero context. |
| `runs.*` | 1 minute | Cheap; mostly used to gate empty-state copy. |

Cache keys must include the cheapest invalidation tuple
`(max(analysis_run.id), count(analysis_run), count(sbom_source))` so any
new run / SBOM busts the cache immediately. The lifetime cache already does
this (see [services/dashboard_metrics.py:373-381](../app/services/dashboard_metrics.py#L373-L381));
Phase 3 generalises that pattern.

**Cap.** No metric that drives headline copy may have a TTL >1 hour. Stale
"+N / −0" or "0 KEV exposed" being visible for a day is itself a consistency
failure.

---

## 7. Module layout (Phase 3 preview)

```
app/metrics/
  __init__.py           # public API; re-exports the metric functions below
  base.py               # NetChangeResult, AsOfDate type aliases, _COMPLETED_STATUSES
  _helpers.py           # _latest_run_per_sbom_cte, _latest_run_per_sbom_as_of_cte,
                        #  _kev_cves_for_finding, _is_kev_listed, _finding_key
  findings.py           # findings.in_run.*, findings.latest_per_sbom.*,
                        #  findings.distinct_lifetime, findings.distinct_active_as_of,
                        #  findings.daily_distinct_active
  kev.py                # findings.kev_in_scope (single function, parameterised by scope)
  runs.py               # runs.total_lifetime, runs.completed_*, runs.distinct_dates_*,
                        #  runs.first_completed_at
  windows.py            # findings.added_in_window, findings.resolved_in_window,
                        #  findings.net_change
  cache.py              # the cache-key helper, ttl decorators
```

* Each metric is a top-level async-aware function (current code is sync; we
  keep that but the helpers are stateless so the upgrade to async sessions
  is a search-and-replace away).
* Each function has a single docstring line referencing its catalog entry
  (e.g. `"""findings.in_run.total — see metrics-spec.md §3.1"""`).
* `app/metrics/__init__.py` re-exports the canonical names with their
  hierarchical structure flattened (`from app.metrics import findings_in_run_total, ...`)
  so callers get autocomplete.
* The existing `app/services/dashboard_metrics.py` becomes a thin adapter
  that re-exports for backwards-compat in tests; no new logic lands there.

---

## 8. Anti-patterns (deny list)

These will trip the consistency tests in Phase 5. If you find them in a PR,
reject the PR.

* `select(func.count(AnalysisFinding.id))` joined to `analysis_run` over a
  date window without a `latest_run_per_sbom` filter. (Bug 3 shape.)
* Two different KEV-membership clauses in the same codebase. (Bug 1 shape.)
* `compute_net_7day_change` returning `tuple[int, int]`. The shape itself
  is the bug. (Bug 5.)
* FE counting "runs" by counting populated days in a trend payload. (Bug 2.)
* Empty-state condition based on `populatedDays < 7` rather than
  `runs_distinct_dates < 7` from the server. (Bug 6.)
* New "metric" added inline in a router file. Extend `app/metrics/` first.
* Adding a new metric without filling out the catalog entry in §3.

---

## 9. Phase 2 gate

This document locks the catalog. **Phase 3 implementation will follow it
verbatim** — each function in `app/metrics/` will reference a §3.X entry
by ID in its docstring.

**Asks of the owner:**

1. Confirm the catalog (§3) is the right shape and naming.
2. Confirm the invariants (§4) are the ones we actually want to enforce —
   particularly I3 (the dashboard KEV lock) and I6 (the lifetime ≥ max-run
   lock). These have UX implications.
3. Approve the wire-format additions (§5) — `is_first_period` flag,
   `runs_total` / `runs_distinct_dates` on the trend.

Reply `continue` to begin Phase 3 (`app/metrics/` module).
