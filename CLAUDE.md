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

# VEX Dashboard & Investigation Workstream

## Source of truth
[`docs/requirements/vex-dashboard-investigation.md`](./docs/requirements/vex-dashboard-investigation.md)
is the authoritative specification. Every requirement has an ID (e.g. VEX-REC-002, GAP-003).
Reference these IDs in code comments, commit messages, test names and PR descriptions. If the
code and the spec disagree, the spec wins. If the spec is ambiguous, stop and ask — do not guess.

## Non-negotiable invariants (from the spec)
- VEX never deletes, hides or suppresses an `AnalysisFinding` (VEX-DATA-004).
- VEX-only vulnerabilities never fabricate an `AnalysisFinding` (VEX-DATA-003).
- VEX never rewrites severity (VEX-DATA-005).
- Manual/internal decisions outrank later imported VEX until explicitly changed (VEX-INV-004).
- Analyser finding with no applicable VEX → effective `UNDER_INVESTIGATION`, reconciliation `ANALYZER_ONLY` (VEX-REC-002 A).
- Conflicting independent VEX assertions → `CONFLICT_REVIEW_REQUIRED`, never resolved by status priority or row recency (VEX-INV-005).
- Analyser redetects a VEX-`FIXED` vuln → `UNDER_INVESTIGATION` + `REVALIDATION_REQUIRED` (VEX-REC-002 G).
- Ambiguous weak component match → `UNRESOLVED_MAPPING`, never attach to the first candidate (VEX-MAP-001).
- Version applicability is checked before a VEX assertion becomes effective (VEX-MAP-002).
- Context identity = tenant + sbom + component + canonical_vulnerability_id (VEX-CTX-001). A CVE alone is never global.
- Source-native status is preserved separately from normalized status (VEX-STAT-002).
- `UNKNOWN` is source evidence only; effective status maps to `UNDER_INVESTIGATION` (section 8).
- Four canonical effective statuses only: AFFECTED, NOT_AFFECTED, FIXED, UNDER_INVESTIGATION (VEX-STAT-001).
- Dashboard counts + investigation queue use the existing eligible-SBOM scope (active tenant/project/product/SBOM, HEAD versions, latest successful run) (VEX-DASH-004/005, VEX-INV-002).
- `total_contexts == affected + not_affected + fixed + under_investigation` for mapped contexts; unresolved mappings are reported separately (VEX-DASH-002).
- All manual decision changes are append-only and audited (VEX-AUD-001); updates use optimistic concurrency via `row_version` (VEX-AUD-002).
- `vex:read` / `vex:write` enforced server-side; tenant isolation on every query (VEX-SEC-001/002).

## Architecture rule
EXTEND the existing VEX architecture (`VexDocument`, `VexStatement`, `VexOverrideAudit`,
existing services, existing component-scoped APIs, `ComponentVexManager` UI). Do not rewrite or
remove them. Introduce a new persistent `VexInvestigation` (vulnerability context) entity that
links `AnalysisFinding`, `VexStatement` and manual decisions (VEX-DATA-001). Existing API
response fields (e.g. `unknown_count`) stay for compatibility.

Specific reuse obligations — do not reimplement these:
- Canonical vulnerability identity → `app/services/vex/identity.py`, which wraps
  `app/integrations/cve/identifiers.py:114 resolve()`. Note `resolve()` alone is **not** enough:
  it preserves an already-canonical GHSA rather than preferring that advisory's CVE, so
  `identity.py` applies CVE preference itself (VEX-CTX-002).
- Eligible-SBOM scope → `app/services/dashboard_scope.py` (`DashboardScope.eligible_sbom_ids`).
- Latest successful run → `app/metrics/_helpers.py latest_run_per_sbom_subquery()`.
- NOT_AFFECTED / FIXED validation → `_validate_vex_result` in `app/services/lifecycle/vex_provider.py`.
- Reconciliation → `app/services/vex/reconciliation.py:recompute_for_sbom`. Call it inside
  `db.begin_nested()`: swallowing a reconciliation error without a savepoint leaves the session's
  transaction aborted and takes the caller's work down with it.
- Component mapping → `app/services/vex/matching.py:match_component`, which returns candidates and
  a confidence. The legacy `_match_component` returns the first hit and must not be used for new
  VEX mapping decisions.
- `choose_vex_result` / `VEX_PRIORITY` in `app/services/lifecycle/decision_engine.py` currently has
  zero callers. It must NEVER be wired up as conflict-resolution policy (VEX-INV-005).

## Explicitly out of scope (section 50) — do not touch
General component inventory dashboard, SBOM active/inactive implementation changes, EOL/EOS,
upload validation redesign, alternative-library recommendations.

## Working rules
- Read the relevant spec sections before writing code for a task.
- Run the existing test suite before and after changes; never leave it red.
- Migrations are additive and reversible, with a backfill step where existing data needs it.
- One PR per session, following the sequence in spec section 49 (PR-1 … PR-7).
- Every acceptance scenario in spec section 47 must map to at least one automated test named with
  the scenario and requirement ID.
- Keep the plan file [`docs/plans/vex-implementation-plan.md`](./docs/plans/vex-implementation-plan.md)
  updated: mark tasks done, record decisions and open questions at the end of every session.
- Ask before: changing a public API shape, deleting anything, or making a schema change not
  listed in the plan.
