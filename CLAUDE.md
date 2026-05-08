# Project context for Claude Code

## Calculations and counts

Never write a direct query against `analysis_finding` or `analysis_run` in router or service code. Use the functions in `app/metrics/` instead. If a needed function doesn't exist, add it to the metric layer first, then call it.

Every count, percentage, ratio, or aggregate displayed in the UI must follow exactly one of three conventions — `A` (latest state), `B` (lifetime distinct), or `C` (total raw rows). See [`docs/metric-conventions.md`](./docs/metric-conventions.md) for the decision flowchart and hard rules.

The architectural test `tests/test_metric_consistency.py::test_no_new_direct_finding_or_run_queries_outside_metrics` enforces this at PR review time. Files known at audit time (2026-05-08) to violate the rule are in `_LEGACY_DIRECT_QUERY_ALLOWLIST` in that file — that allowlist is the migration backlog. Don't add to it; remove from it.

## Run-status names (ADR-0001)

The backend emits canonical run statuses: `OK`, `FINDINGS`, `PARTIAL`, `ERROR`, `RUNNING`, `PENDING`, `NO_DATA`. The legacy aliases `PASS` and `FAIL` are accepted on inbound only — never use them in display logic, never hard-code them in filters. The FE helper `canonicalRunStatus()` at `frontend/src/lib/analysisRunStatusLabels.ts:102` maps legacy → canonical.

If you're filtering runs by status anywhere, use the helper.
