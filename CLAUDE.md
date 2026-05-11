# Project context for Claude Code

## Calculations and counts

Never write a direct query against `analysis_finding` or `analysis_run` in router or service code. Use the functions in `app/metrics/` instead. If a needed function doesn't exist, add it to the metric layer first, then call it.

Every count, percentage, ratio, or aggregate displayed in the UI must follow exactly one of three conventions — `A` (latest state), `B` (lifetime distinct), or `C` (total raw rows). See [`docs/metric-conventions.md`](./docs/metric-conventions.md) for the decision flowchart and hard rules.

The architectural test `tests/test_metric_consistency.py::test_no_new_direct_finding_or_run_queries_outside_metrics` enforces this at PR review time. Files known at audit time (2026-05-08) to violate the rule are in `_LEGACY_DIRECT_QUERY_ALLOWLIST` in that file — that allowlist is the migration backlog. Don't add to it; remove from it.

## Run-status names (ADR-0001)

The backend emits canonical run statuses: `OK`, `FINDINGS`, `PARTIAL`, `ERROR`, `RUNNING`, `PENDING`, `NO_DATA`. The legacy aliases `PASS` and `FAIL` are accepted on inbound only — never use them in display logic, never hard-code them in filters. The FE helper `canonicalRunStatus()` at `frontend/src/lib/analysisRunStatusLabels.ts:102` maps legacy → canonical.

If you're filtering runs by status anywhere, use the helper.

## TanStack Query — mutation invalidation

Every `useMutation` that creates, updates, or deletes a server-side resource MUST invalidate every list query that could include or exclude that resource. If a new mutation is added without this, list views silently show stale data until the user refreshes (F5).

Use the helpers in [`frontend/src/lib/queryInvalidation.ts`](./frontend/src/lib/queryInvalidation.ts) — they encode the "this entity touches these caches" mapping in one place so a new sidebar/recent/palette panel doesn't drift away from upload/delete flows.

```ts
import { invalidateSbomLists, invalidateProjectLists } from '@/lib/queryInvalidation';

onSuccess: () => {
  invalidateSbomLists(queryClient);
  invalidateProjectLists(queryClient);
}
```

### What to invalidate

For each mutation, ask: "What lists, recents, or summaries could change as a result?" Walk the answer through the helpers — every entity-affecting helper is composed at the call site:

- Direct list: `invalidateSbomLists` / `invalidateProjectLists` / `invalidateRunLists` / `invalidateScheduleLists` — bundles every sibling list view for that entity (main table + sidebar + dashboard activity + ⌘K palette).
- Dashboard rollups: `invalidateDashboardTiles` — posture, 30-day trend, lifetime totals. Add this whenever the universe of findings or runs changes.
- Analysis completion: `invalidateAnalysisCompletion(qc, { sbomId? })` — the convenience for "a run just landed" (runs + dashboards + per-SBOM detail).
- AI credentials: `invalidateAiCredentialSurfaces` — credentials list, Settings join, analysis-config.
- AI fixes: `invalidateAiFixCaches` — drops every cached fix, used after deleting a provider or cancelling a batch.

`setQueryData(['sboms'], …)` is fine as an optimistic UX touch-up, but it does NOT replace invalidation — sibling caches like `['sidebar-recent-sboms']`, `['recent-sboms']`, `['palette-recent-sboms']`, `['sboms', 'for-schedules']` are separate and need explicit invalidation.

### Bypassing useMutation is also a violation

Raw `await someApiCall()` inside an event handler dodges the convention. Wrap it in a `useMutation` hook (see `useUploadSbom` / `useRevalidateSbom` in [`frontend/src/hooks/useSbomMutations.ts`](./frontend/src/hooks/useSbomMutations.ts)) so the test below covers it.

### Exceptions

Mutations that have no server-side cache effect — test-connection probes, validation-only requests — may skip invalidation. Mark these with `// @no-invalidation-needed` (anywhere in the 250 chars preceding the `useMutation(` call, or inside the block) so the architectural test allows them. Misusing the marker should fail code review.

### Architectural test

[`frontend/src/__tests__/mutation-invalidation.test.ts`](./frontend/src/__tests__/mutation-invalidation.test.ts) scans every non-test `.ts` / `.tsx` under `frontend/src` and fails CI if any `useMutation` lacks `invalidateQueries` / `setQueryData` / `refetchQueries` / an `invalidate*(` helper call, and is not marked with the escape-hatch comment.

### Why this matters

The May 2026 audit caught five missing-invalidation bugs (upload, SBOM delete, project delete, schedule run-now ×2, SBOM revalidate); a follow-up audit in May 2026 closed eight more (D1–D8 in [`docs/cache-invalidation-audit.md`](./docs/cache-invalidation-audit.md)) and installed the forbidding test. Don't ship the next one.
