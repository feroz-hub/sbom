# ADR-0009 — Dashboard canonical metrics layer

- **Status:** Accepted (2026-05-02)
- **Context:** [docs/dashboard-metrics-audit.md](../dashboard-metrics-audit.md), [docs/dashboard-metrics-spec.md](../dashboard-metrics-spec.md)
- **Authors:** Feroze Basha (FBT) / Claude
- **Supersedes:** none
- **Related:** [ADR-0001](./0001-dashboard-posture-model.md), [docs/runbook-metric-debugging.md](../runbook-metric-debugging.md)

## Context

Six P0/P1 contradictions were observed simultaneously in the dashboard
(diagnosed in `docs/dashboard-metrics-audit.md`):

1. Run-detail "6 KEV" vs dashboard "0 KEV exposed" for the same database (P0).
2. Trend empty-state "1 run so far" with 4 same-day runs visible elsewhere (P1).
3. Trend legend Σ = 1,259 with lifetime distinct = 513 — mathematically impossible (P0).
4. Lifetime "Findings surfaced" matching one run's count exactly (P1).
5. Net 7-day rendering `+513 / −0` on a first scan — silently misleading (P1).
6. Trend empty-state firing for 4 runs because the condition tested distinct dates (P2).

The structural root cause was not six independent bugs. Every endpoint
(`/dashboard/posture`, `/dashboard/lifetime`, `/dashboard/trend`,
`/api/runs/{id}/findings-enriched`) reinvented its aggregation. There was
**no shared definition** of any metric, no shared SQL helpers, and no
reconciliation tests. New endpoints drifted from existing ones the day they
shipped.

A second root cause: aggregation scope was ambiguous. "Across all runs" was
implemented three different ways simultaneously — sum raw rows, take the
deduplicated union, and take latest-per-SBOM — each correct for a different
question, but mixed without a convention.

## Decision

### 1. A canonical metrics layer at `app/metrics/`

Every numeric field on every dashboard, run-detail, or lifetime surface MUST
be backed by a function in this module. Routers compose canonical metric
calls; **inline metric SQL in router files is forbidden.**

Module shape:

```
app/metrics/
  __init__.py     # public API
  base.py         # NetChangeResult, TrendPoint, COMPLETED_RUN_STATUSES, severity keys
  _helpers.py     # latest_run_per_sbom_subquery, latest_run_per_sbom_as_of_subquery,
                  #  cves_for_finding, is_kev_listed, finding_key
  cache.py        # invalidation_key, memoize_with_ttl
  findings.py     # in_run, latest_per_sbom, distinct_lifetime, daily_distinct_active
  kev.py          # findings_kev_in_scope (single function, parameterised by scope)
  runs.py         # total/completed/this_week/distinct_dates/first_completed
  windows.py      # findings_net_change with NetChangeResult
  sboms.py        # sboms_total, projects_total/active
```

The full catalog of metric IDs, definitions, dedup keys, time windows,
scopes, status filters, and reconciliation invariants lives in
[docs/dashboard-metrics-spec.md](../dashboard-metrics-spec.md) §3.

### 2. Two locked aggregation conventions

- **Convention A — "Latest state."** Aggregates over the latest successful
  run of each SBOM. Used for portfolio-wide *current* numbers (hero severity
  bar, KEV exposed, fix available). Answers "what does my portfolio look
  like right now?"

- **Convention B — "Lifetime distinct."** Aggregates over distinct
  `(vuln_id, component_name, component_version)` tuples from rows that
  match a status filter (default: successful). Used for cumulative-value
  numbers (lifetime stats, trend chart, time-window deltas). Answers "how
  many real, unique findings has this tool surfaced?"

**There is no third convention.** Summing raw `analysis_finding` rows
across multiple runs over-counts every finding by the number of runs it
appears in; doing so is the shape-bug behind Bug 3.

### 3. A single shared KEV-membership predicate

The function `_is_kev_listed(vuln_id, aliases, kev_set)` in
`app/metrics/_helpers.py` is called by both:

- `findings.kev_in_scope(scope="run", ...)` — used by the run-detail page
  via `/api/runs/{id}/findings-enriched`'s `in_kev` field.
- `findings.kev_in_scope(scope="latest_per_sbom")` — used by the dashboard
  posture's `kev_count` field.

A finding is KEV-listed iff `vuln_id` *or* any CVE alias parsed from the
`aliases` JSON appears in `kev_entry`. This matches the user mental model
("a finding is exploitable when its CVE is on KEV, regardless of which
identifier we tracked it under") and locks invariant I3.

### 4. Twelve cross-surface reconciliation invariants

Spec §4 defines twelve invariants that must hold at all times. Each is
asserted by a test in `tests/test_metric_consistency.py`:

| # | Invariant | Bug locked |
|---|---|---|
| I1 | hero severity Σ == hero total | structural |
| I2 | hero total == Σ over SBOMs of latest-run totals | structural |
| **I3** | **hero KEV == Σ over SBOMs of run KEVs** | **Bug 1** |
| **I4** | **trend Σ for any day ≤ findings.distinct_lifetime** | **Bug 3** |
| I5 | trend "today" column == latest-state distinct keys | structural |
| **I6** | **lifetime distinct ≥ max-run distinct keys** | **Bug 4** |
| **I7** | **lifetime runs_executed_total == sidebar count** | **Bug 2** |
| I8 | trend.runs_total == lifetime.runs_executed_total | structural |
| **I9** | **net_7day.is_first_period reflects "no prior run"** | **Bug 5** |
| I10 | when first_period: resolved == 0 | first-period contract |
| I11 | resolved ≤ surfaced | sanity |
| I12 | per-run severity Σ == per-run total | writer-side sanity |

The tests carry the `metric_consistency` pytest marker and run on every PR
via `pytest -m metric_consistency`. **Failure blocks merge.**

### 5. Wire-format additions

- `GET /dashboard/posture` adds `net_7day: {added, resolved, is_first_period, window_days}`.
  Flat aliases `net_7day_added` / `net_7day_resolved` kept one release for
  FE back-compat.
- `GET /dashboard/lifetime` adds `runs_completed_total` (successful-only) and
  `runs_distinct_dates`.
- `GET /dashboard/trend` adds `runs_total` and `runs_distinct_dates` so the
  FE empty-state copy/condition stops lying about run counts.
- `/api/runs/{id}/findings-enriched` shape unchanged; `in_kev` derivation now
  routes through the shared canonical predicate.

## Consequences

### Positive

- Six P0/P1 contradictions fixed and locked — no possible regression while
  the consistency tests run on every PR.
- Adding a new metric has a clear procedure (spec catalog → impl → test →
  wire). New endpoints cannot drift from existing ones because they call
  the same functions.
- KEV detection consolidated to one predicate. Future "include EPSS-listed",
  "exclude past-due", or any other refinement lands once and propagates
  everywhere.
- The audit + spec + runbook docs make the structural shape obvious to a
  future engineer who joins the project.

### Negative

- One new module surface (`app/metrics/`) for engineers to learn. Mitigation:
  the catalog in spec §3 is the only thing they need to read.
- Tests now run a 12-test suite per PR that didn't exist before. Marginal CI
  cost: ~1.3s after the KEV-fetch stub.
- The wire format carries deprecated aliases (`net_7day_added/resolved`) for
  one release. Drop after the v2 FE bundle is fully deployed.

### Risks

- If a PR introduces a new metric in a router file, the consistency tests
  may not catch it (they assert relationships, not where SQL lives). Spec
  §8 deny list documents the forbidden shapes; reviewers should check.
- The KEV-membership predicate runs per-row in Python rather than as SQL,
  so its complexity is O(rows × CVEs/row). At ~10k findings this is
  sub-millisecond; if scale grows past 1M findings, revisit with a SQL
  JSON-extraction approach.

## Migration notes

- No DB schema changes; no backfill required. The fix is read-side only.
- FE consumers should switch to `posture.net_7day` (envelope) and
  `trend.runs_total` / `trend.runs_distinct_dates`. Flat `net_7day_*`
  aliases continue to work.
- `compute_net_7day_change` in `app/services/dashboard_metrics.py` is now
  a back-compat shim returning `(added, resolved)`. New callers should use
  `app.metrics.findings_net_change` directly to access `is_first_period`.

## Rollout

- No feature flag. This is a P0 bug fix; ship to staging, run
  `pytest -m metric_consistency`, deploy to prod.
- Post-deploy verification: hit the same DB from production and assert
  reconciliation per [docs/runbook-metric-debugging.md](../runbook-metric-debugging.md) §8.
