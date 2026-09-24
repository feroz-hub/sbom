# VEX Dashboard & Investigation — Implementation Plan

**Spec:** [`docs/requirements/vex-dashboard-investigation.md`](../requirements/vex-dashboard-investigation.md) (v1.0)
**Branch:** `SBOM_VEX`
**Session 0 completed:** 2026-09-24 — discovery + this plan. No production code.

Update this file at the end of every session: tick completed items, record decisions, list open
questions. It is the state that carries between PR sessions.

---

## 0. Stack discovered

| Concern | Finding |
|---|---|
| Backend | FastAPI, routers in `app/routers/`, mounted in `app/main.py:707-770` with a shared `_protected` dependency list |
| ORM | SQLAlchemy 2.0 declarative, all models in a single `app/models.py`; `TenantOwnedMixin` + `SoftDeleteMixin` |
| Migrations | Alembic, `alembic/versions/NNN_name.py`, inspector-guarded, **both** `upgrade()` and `downgrade()`. Head = `055_ai_model_registry` |
| Tests (BE) | pytest, flat `tests/`, `pytest.ini` markers, `tests/conftest.py` with `client` / `seeded_sbom` / `mock_external_sources` |
| Frontend | Next.js App Router (v16, Turbopack), TanStack Query v5, Tailwind + local `@/components/ui` kit |
| Tests (FE) | Vitest + RTL, tests beside source, `// @vitest-environment jsdom` pragma per file |

---

## 1. ⚠️ PR-0 — Unblock the test suite (do this first)

Every PR below assumes a green suite. Replicating the scan logic of
`tests/test_metric_consistency.py` by hand against the current tree shows two architectural tests
that should already be failing:

1. `test_no_new_direct_finding_or_run_queries_outside_metrics` — **confirmed failing.**
   `app/services/lifecycle/vex_provider.py` matched `select(\s*AnalysisFinding` at :415 and :461
   and is not in `_LEGACY_DIRECT_QUERY_ALLOWLIST` (`tests/test_metric_consistency.py:781-797`).
2. `test_legacy_allowlist_does_not_grow_unnoticed` — **was NOT failing.** The Session-0 prediction
   was wrong: `app/services/dashboard_metrics.py` does match, via a multi-line
   `select(
    AnalysisRun` at :283 and :316 that a line-based grep cannot see but the test's
   whole-file `re.search` does. The allowlist entry is legitimate and was left alone.

**Verify:** `pytest tests/test_metric_consistency.py -k "direct_finding or allowlist"`

**Done in commit `eeaecd2`:** added `app/metrics/vex.py` with `vex_component_findings()` and
`vex_sbom_finding_pairs()` (the two queries lifted unchanged), exported from
`app/metrics/__init__.py`, and pointed `component_vulnerabilities()` / `list_vex_statements()` at
them. `AnalysisFinding` and `AnalysisRun` no longer appear in `vex_provider.py`. The allowlist was
not touched. Both new functions are Convention C; GAP-008's rescope stays in PR-2.

**Local test-DB note.** `tests/conftest.py:56` defaults to port **55439**; this machine's Postgres
is on **5432**. Create `sbom_analyser_test` once and run every suite with
`TEST_DATABASE_URL=postgresql+psycopg://sbom:sbom@127.0.0.1:5432/sbom_analyser_test`, or pytest
dies with a connection timeout before collection.

- [x] PR-0 complete — commit `eeaecd2`, targeted suites green (47 passed)

---

## 2. Design decisions (Session 0)

**D1 — `VexInvestigation` identity.** Unique on
`(tenant_id, sbom_id, component_id, canonical_vulnerability_id)`. Postgres treats NULLs as
distinct, so unresolved mappings (`component_id IS NULL`) would multiply on every recompute. Add a
deterministic `unresolved_discriminator` (hash of the owning statement's identity) that is `''`
for mapped contexts, and include it in the unique key so recompute is idempotent.

**D2 — Current vs historical.** Contexts absent from the latest successful run are marked
`is_current = false`, never deleted (VEX-INV-001/002). Queue and tiles filter on `is_current`.

**D3 — Engine placement and execution.** New `app/services/vex/reconciliation.py` exposing a pure,
idempotent `recompute_for_sbom(db, *, tenant_id, sbom_id)`. Called **synchronously** from
analysis-run success, VEX import and manual decision, plus a repair/backfill entry point. Decided
with the user: no Celery/Redis dependency. Structure it so it could move behind a queue later
without changing callers.

**D4 — Metric-layer compliance.** The engine needs `AnalysisFinding`/`AnalysisRun` data, which
router/service code may not query directly (CLAUDE.md). All such access goes through
`app/metrics/vex.py`.

**D5 — Conflict definition (VEX-INV-005).** "Independent" = different author **or** different
source document. A newer version of the *same* `source_document_id` supersedes its predecessor and
is **not** a conflict. `choose_vex_result` is never used.

**D6 — Backward compatibility.** Every existing `/dashboard/vex` field stays, `unknown_count`
included (documented deprecated). New metrics fold `unknown` into `under_investigation_count`.
Existing component-scoped endpoints and report/CSV/ZIP exports keep working (DoD 19).

**D7 — Scope is passed explicitly.** `vex_dashboard_summary(db)` currently relies on ambient
session state: `app/db.py:238` applies `VexStatement.sbom_id.in_(scope.eligible_sbom_ids())` as ORM
loader criteria, which works only because the dashboard router carries `dashboard_scope_dependency`
(`app/routers/dashboard_main.py:58`). New VEX functions take tenant + filters as parameters so a
caller outside a scoped session cannot silently read cross-tenant.

---

## 3. Gap map

| Gap | Code responsible | Fixed in |
|---|---|---|
| GAP-001 analyser-only has no VEX state | `tests/test_vex_decisions.py:63` asserts `statements == []` | PR-2 (test inverted) |
| GAP-002 dashboard counts statements only | `vex_provider.py:626 vex_dashboard_summary` | PR-3 |
| GAP-003 exact-id matching, aliases unused | `vex_provider.py:419` keys on `vuln_id.strip().upper()` | PR-1 (identity), PR-2 (use) |
| GAP-004 native state normalized too early | `_normalize_vex_status`, `CYCLONEDX_ANALYSIS_STATUS_MAP:26` | PR-1 |
| GAP-005 no reconciliation status | — (does not exist) | PR-1 (enum), PR-2 (engine) |
| GAP-006 conflicts hidden by recency | `vex_provider.py:385 effective_vex_statements` ranks `(is_manual, id)` | PR-2 |
| GAP-007 ambiguous mapping auto-assigned | `_match_component` returns first match | PR-2 |
| GAP-008 findings across all runs | `vex_provider.py:415` joins `AnalysisRun` with no latest-run filter | PR-2 |

---

## 4. PR-1 — VEX Reconciliation Foundation

**Spec:** §5–10, §33–36, §49 (PR-1). Data only — no UI, no reconciliation logic.

**Create / modify**
- `app/models.py` — `VexInvestigation` (§35 fields + `is_current`, `unresolved_discriminator`,
  `row_version`); extend `VexStatement` with `source_format`, `source_status`, `normalized_status`,
  `asserted_at`, `match_strategy`, `match_confidence`, `version_applicable` (keep `status`);
  extend `VexDocument` with `source_document_id`, `source_document_version`, `source_hash`,
  `asserted_at` (VEX-ING-003; keep discovery/provider-error fields).
- `app/services/vex/enums.py` (VEX-REC-001) — `EffectiveVexStatus` (4), `ReconciliationStatus` (6),
  `AnalyzerDetectionState` (5), `MappingConfidence`.
- `app/services/vex/identity.py` (VEX-CTX-002) — canonical id service **wrapping**
  `app/integrations/cve/identifiers.py:114 resolve()`; reads `AnalysisFinding.aliases` (:1239).
- `app/services/lifecycle/vex_provider.py` — importers populate
  `source_format`/`source_status`/`normalized_status` (VEX-DATA-002); `unknown` → normalized
  `UNDER_INVESTIGATION` with `source_status='unknown'` (§8); preserve raw source data.
- Document idempotency (VEX-ING-002): stable `source_hash` on import; identical document →
  "already imported", no duplicate statements; new version appends and marks the prior superseded.
- `alembic/versions/056_vex_investigation_foundation.py` — additive + reversible, with backfill
  (a) `source_format`/`source_status`/`normalized_status` on existing `VexStatement` rows from
  `status` + source fields, (b) `source_hash` for existing `VexDocument` rows with `raw_document_json`.

**Tests:** model constraints, tenant scoping, per-format importer field population, idempotent
re-upload, new-version append, canonical-id resolution (GHSA→CVE, OSV→CVE, no-CVE), UNKNOWN
mapping, CycloneDX `false_positive` native preservation.

**Not in this PR:** `vex_dashboard_summary`, `effective_vex_statements`, the matcher, APIs, frontend.

- [ ] PR-1 complete

---

## 5. PR-2 — Reconciliation Engine

**Spec:** §3 (GAP-001/003/006/007/008), §4, §11, §14–20, §30–32, §37–39.

**Create / modify**
- `app/services/vex/matching.py` — matcher returns **candidates + strategy + confidence**.
  Priority: bom-ref → normalized PURL → CPE → canonical package identity + exact version →
  supplier+name+version → name+version. Name-only is weak; >1 candidate on a weak strategy →
  `component_id` unresolved + `UNRESOLVED_MAPPING`. Never pick the first candidate. Completely
  unmatched evidence is still retained (existing behaviour).
- Version applicability (VEX-MAP-002): exact / list / range per format. Not applicable → statement
  retained as evidence, `version_applicable=false`, not eligible to be effective.
- Embedded CycloneDX detection (VEX-ING-001): a `vulnerabilities[]` entry becomes a VEX assertion
  only with `analysis.state` / `justification` / `response` or equivalent affects/status evidence.
- `app/services/vex/reconciliation.py` — rules VEX-REC-002 A–H exactly as specified; multi-source
  dedup (VEX-REC-003); analyser detection state (VEX-REC-004) from existing run/provider error data
  — source failures must never render as "not detected"; re-analysis behaviour (VEX-INV-001).
- `app/metrics/vex.py` — latest-run finding fetch for eligible SBOMs, reusing
  `app/services/dashboard_scope.py` and `app/metrics/_helpers.py:33`. **Do not reimplement scope.**
- Triggers: analysis-run success, VEX import, manual decision + idempotent recompute entry point.
- **Invert `tests/test_vex_decisions.py:63`** — a detected CVE with no VEX now yields a context with
  `UNDER_INVESTIGATION` / `ANALYZER_ONLY`. Call this out explicitly in the PR description.

**Tests (engine level):** VEX-only NOT_AFFECTED/AFFECTED/FIXED; analyser-only; analyser+VEX
AFFECTED / NOT_AFFECTED / UNDER_INVESTIGATION; redetected FIXED; GHSA alias = same context; same
CVE two components = two contexts; two versions = two contexts; multi-scanner = one context;
ambiguous mapping; range not applicable; conflicting sources; re-analysis preserves manual
decision; source API failure → `SOURCE_ERROR`; ordinary CycloneDX vulnerability is not a VEX
determination.

**Not in this PR:** dashboard aggregation, APIs, UI.

- [ ] PR-2 complete

---

## 6. PR-3 — VEX Dashboard Metrics

**Spec:** §21–26, §45.

- Replace the `VexStatement`-only aggregation in `vex_provider.py:626` with aggregation over
  current `VexInvestigation` rows, using the same eligible-SBOM scope and Project/Product/SBOM
  filters as the rest of the dashboard (VEX-DASH-004/005). Pass scope **explicitly** (D7).
- Extend the `/dashboard/vex` response (VEX-API-001, `app/routers/dashboard_main.py:377`) with `total_contexts`,
  `analyzer_only_count`, `vex_only_count`, `matched_count`, `conflict_review_count`,
  `revalidation_required_count`, `unresolved_mapping_count`, `needs_review_count`. Keep every
  existing field including `unknown_count` (deprecated). Add a Pydantic `response_model` in
  `app/schemas_dashboard.py` — the route currently returns a bare dict.
- Keep "Analysis Finding Total" and "VEX Context Total" separate (VEX-DASH-001). Do not force equality.
- Enforce and test `total_contexts == affected + not_affected + fixed + under_investigation` for
  mapped contexts, `unresolved_mapping_count` excluded and reported separately (VEX-DASH-002).
- Reproduce the §24 scenario as an integration test (3 analyser CVEs + 1 embedded VEX-only CVE →
  findings 3, contexts 4, not_affected 1, under_investigation 3, analyzer_only 3, vex_only 1).
- Tests: inactive and superseded SBOMs excluded; tile count == the count the investigation query
  returns for the same filters.
- Fix `top_affected_components` ordering (`vex_provider.py:633` is currently unordered dict order).
- Update the FE type `DashboardVex` (`frontend/src/types/index.ts:778-787`); keep the UI compiling,
  no visual change yet. Note `LifecycleHealthTiles.tsx:10-13` types props as `any`.
- Verify report / CSV / ZIP exports still work; add a smoke test.

- [ ] PR-3 complete

---

## 7. PR-4 — Portfolio Investigation API

**Spec:** §27–29, §40–44.

- `GET /api/vex/investigations` in a new `app/routers/vex_investigations.py`, schemas in
  `app/schemas_vex.py`. **Model it on `app/routers/kev.py:266-357 list_kev_vulnerabilities`** —
  `response_model`, `q` ilike search, enum `sort_by`/`sort_order` through a `SORT_COLUMNS` map with
  a stable tiebreaker, `limit`/`offset` with `ge`/`le` bounds, separate `COUNT(*)`, envelope
  `{total, limit, offset, items}`. Filters per §28 (VEX-UI-002). Same eligible-SBOM scope as the dashboard so
  tile counts == list counts for identical filters (assert this in a test).
- `GET /api/vex/investigations/{id}` (VEX-UI-003) — §29 evidence sections: vulnerability, component, analyser
  evidence, imported VEX assertions (all, including non-applicable and conflicting, with native +
  normalized status and mapping confidence), internal decision, reconciliation, chronological
  history from `VexOverrideAudit`.
- Decision endpoint — reuse the existing override API if practical
  (`app/routers/vex.py:148 patch_vex_override`), else add POST/PUT on the investigation. Requires
  `vex:write`; reuses `_validate_vex_result`'s NOT_AFFECTED/FIXED rules (VEX-VAL-001/002); accepts `assigned_to`;
  requires `row_version`, returns **409 with the latest row** on mismatch (VEX-AUD-002); writes an
  append-only `VexOverrideAudit` record; re-runs reconciliation for that context.
- Authorization: `app/core/security.py:542` already maps `/vex` paths to `vex:read`/`vex:write` by
  method, so the new routes inherit the correct gate. **Note the asymmetry:** `GET /dashboard/vex`
  resolves to `dashboard:read` (`:536`) because the `/dashboard` branch is tested first — leave it
  for compatibility and document it.
- Tests: cross-tenant read/write by id → 404/403; missing permission → 403; concurrent update →
  409; validation failures → 4xx; every filter; sorting/pagination stability.
- Keep existing component-scoped VEX endpoints unchanged and passing.

- [ ] PR-4 complete

---

## 8. PR-5 — VEX Dashboard & Investigation UI

**Spec:** §23–24, §27–30, §46. Follow `frontend/AGENTS.md` — this Next.js version differs from
training data; check `node_modules/next/dist/docs/` before writing route code.

- New page `frontend/src/app/vex-investigation/page.tsx` (VEX-UI-001) (`'use client'`, `<Suspense>` wrapper,
  `<TopBar>` + `p-6` body), plus one entry in `frontend/src/lib/navigation.ts:26-57` with
  `permission: 'vex:read'` (filtered by `Sidebar.tsx:60-66`).
- **Copy the `frontend/src/app/kev/page.tsx` pattern** for the table — it is the repo's only true
  server-side paginated + filtered page (`app/sboms/page.tsx` fetches 500 rows and paginates in
  memory; do not copy it). Reuse: filter-state defaults, URL→state on mount (`initialState`),
  state→URL `router.replace`, 350 ms debounced search, `placeholderData: keepPreviousData`,
  page clamping, active-filter count. UI kit: `Table`/`SortableTh`/`EmptyRow`, `Pagination`,
  `TableFilterBar`/`TableSearchInput`, `Select`, `Badge`, `Dialog`, `SkeletonRow`, `useToast`.
- Summary cards (VEX-DASH-003): Total Contexts, Affected, Not Affected, Fixed, Under Investigation, Analyzer Only,
  VEX Only, Matched, Needs Review, Unresolved Mapping. Clicking a card applies the matching filter.
- Scope selector reusing the existing Tenant→Project→Product→SBOM controls.
- Visually flag VEX-only AFFECTED, `CONFLICT_REVIEW_REQUIRED`, `REVALIDATION_REQUIRED`,
  `UNRESOLVED_MAPPING` rows. Severity always the vulnerability's severity, unchanged by VEX.
- Detail drawer (VEX-UI-003): §29 sections side by side — Analyzer Evidence vs Imported VEX (all assertions,
  native + normalized) vs Internal Decision, plus Reconciliation and History.
- Decision action (VEX-INV-003, `vex:write` only): client-side validation mirroring the backend — reuse the
  rules in `SbomDetail.tsx:909-922 validateVexOverride`; on 409 show "updated by someone else —
  reload" and refresh.
- **Permissions:** use `usePermission('vex:read')` / `('vex:write')` from
  `frontend/src/hooks/usePermission.ts`. Do **not** copy `SbomDetail.tsx:219-230
  canManageEvidenceFromClient()`, which reads roles from `localStorage`. There is no `vex:write`
  string in the frontend today; this page introduces it.
- **Cache invalidation (repo CLAUDE.md):** use `useMutation` — the architectural test
  `frontend/src/__tests__/mutation-invalidation.test.ts` scans for it, and `SbomDetail.tsx`'s raw
  `await someApiCall()` handlers are exactly the pattern that rule forbids. Call
  `invalidateVexSurfaces(qc, sbomId)` in `onSuccess`, and **add the new portfolio query key to
  `invalidateVexSurfaces` (`frontend/src/lib/queryInvalidation.ts:124`) as an unscoped prefix** —
  every key in that helper is currently sbomId-scoped, so a portfolio table would otherwise go
  stale after an override.
- Home dashboard VEX card (`LifecycleHealthTiles.tsx:210-268`): keep the compact card, make it a
  drill-down link, optionally show Needs Review. "Investigating" = `under_investigation_count`
  (now including former `unknown`).
- Keep `ComponentVexManager` and the component-first "Manage VEX" flow working; link a component's
  VEX row to its investigation detail where cheap.
- Never rely on UI hiding for authorization; backend remains the gate.
- Tests (Vitest + RTL, `// @vitest-environment jsdom`, `vi.hoisted()` API mock as in
  `app/kev/page.test.tsx:16-38`): cards render counts from the API, filters map to query params,
  decision form validation, 409 handling, read-only rendering without `vex:write`.

- [ ] PR-5 complete

---

## 9. PR-6 — Audit, Concurrency & RBAC Hardening

**Spec:** §40–43.

- Audit review: every path changing `effective_status`, `assigned_to`, or resolving a
  conflict/revalidation/unresolved mapping writes an append-only `VexOverrideAudit` record with
  tenant, sbom, component, vulnerability, previous status, new status, reason, evidence,
  changed_by, changed_at. Extend the model if a field is missing (it is currently component-scoped
  with `old_value_json`/`new_value_json`). Include reconciliation transitions caused by manual actions.
- Optimistic concurrency: `row_version` increments on every write; all mutation endpoints require
  it; reconciliation recomputes triggered by analysis/import bump the version **without clobbering
  an in-flight manual decision** — define the rule explicitly and test it.
- Assignment/reviewer endpoints or fields, audited.
- Authorization regression tests across every new endpoint: `vex:read`, `vex:write`, no permission,
  and the other roles in `app/core/permissions.py` (SECURITY_ANALYST has both at `:146-147`;
  DEVELOPER and VIEWER have `vex:read` only).
- Tenant isolation: matching and reconciliation never cross tenants (a VEX statement in tenant A
  must not map to a component or finding in tenant B even with identical PURL/CVE); all
  list/detail/mutation endpoints reject cross-tenant ids.
- Manual resolution of `UNRESOLVED_MAPPING`: an analyst with `vex:write` binds an unresolved
  assertion to a specific component; audited; triggers reconciliation.

- [ ] PR-6 complete

---

## 10. PR-7 — Full End-to-End VEX Test Suite

**Spec:** §47–48.

- Fixtures (extend `samples/vex/`, which already has `demo-01-cyclonedx-vex-sbom11.json`,
  `demo-02-openvex-sbom11.json`, `telemetry-service-{1.0.0,1.1.0}-vex.json`): a CycloneDX SBOM with
  embedded VEX including a `false_positive` entry, an `in_triage` entry and a plain vulnerability
  entry with no analysis block; an OpenVEX document; a CycloneDX standalone VEX; a CSAF VEX; a
  second supplier document conflicting with the first; a version-range document that does not apply.
- One test per §47 row, named `test_<scenario>__<REQ_ID>`, driven through public entry points
  (upload SBOM, run analysis with mocked NVD/OSV/GHSA via `mock_external_sources` including a
  timeout, import VEX, call `/dashboard/vex` and `/api/vex/investigations`, make a decision, rerun).
- Include: dashboard/tile-vs-table count equality; exports (report, CSV, ZIP) contain effective and
  native statuses; migration backfill on a seeded pre-enhancement dataset yields a context for
  every current finding.
- Produce `docs/vex/acceptance-report.md`: each §47 row, the covering test, pass/fail; plus the 20
  §48 Definition-of-Done items with evidence. Anything unmet is listed as an open item, never
  silently omitted.

- [ ] PR-7 complete

---

## 11. Acceptance matrix (§47) — checklist

- [ ] Embedded VEX CVE not found by analyser → `VEX_ONLY`
- [ ] Analyser CVE with no VEX → `UNDER_INVESTIGATION` + `ANALYZER_ONLY`
- [ ] Same CVE in analyser + VEX → one context, no duplicate
- [ ] Analyser + VEX AFFECTED → AFFECTED + MATCHED
- [ ] Analyser + VEX NOT_AFFECTED → NOT_AFFECTED + MATCHED
- [ ] Analyser + VEX UNDER_INVESTIGATION → UNDER_INVESTIGATION + MATCHED
- [ ] Analyser redetects FIXED CVE → UNDER_INVESTIGATION + `REVALIDATION_REQUIRED`
- [ ] VEX-only AFFECTED → AFFECTED + `VEX_ONLY`
- [ ] VEX-only NOT_AFFECTED → NOT_AFFECTED + `VEX_ONLY`
- [ ] VEX-only FIXED → FIXED + `VEX_ONLY`
- [ ] GHSA finding aliases VEX CVE → same context
- [ ] Same CVE on two components → two contexts
- [ ] Same CVE on two component versions → separate contexts
- [ ] Multiple scanners find same vulnerability → one context, multiple evidence sources
- [ ] Ambiguous component mapping → `UNRESOLVED_MAPPING`
- [ ] VEX version range doesn't apply → VEX not applied
- [ ] Conflicting VEX sources → `CONFLICT_REVIEW_REQUIRED`
- [ ] Duplicate VEX document upload → idempotent
- [ ] Re-analysis after manual decision → manual decision preserved
- [ ] Source API fails → `SOURCE_ERROR`, not `NOT_DETECTED`
- [ ] `not_affected` without evidence → validation failure
- [ ] Ordinary CycloneDX vulnerability with no analysis → not a VEX determination
- [ ] CycloneDX `false_positive` → native value preserved, normalized mapping retained
- [ ] Inactive SBOM → excluded from current dashboard
- [ ] Superseded SBOM → excluded from current dashboard
- [ ] Cross-tenant access → rejected
- [ ] Concurrent analyst updates → conflict detected

## 12. Definition of Done (§48) — checklist

- [ ] 1 Every current analyser finding has a VEX investigation state
- [ ] 2 New findings without VEX default to `UNDER_INVESTIGATION`
- [ ] 3 Embedded/imported VEX-only vulnerabilities are retained
- [ ] 4 Scanner findings and VEX assertions reconciled without duplication
- [ ] 5 CVE/GHSA/OSV aliases reconciled correctly
- [ ] 6 VEX status is component/version/product-context specific
- [ ] 7 Source-native VEX status preserved
- [ ] 8 Conflicting assertions visible
- [ ] 9 Fixed-but-redetected vulnerabilities require revalidation
- [ ] 10 Manual decisions survive re-analysis and later imports
- [ ] 11 Current investigation uses latest successful analysis state
- [ ] 12 Historical findings and decisions remain auditable
- [ ] 13 Dashboard counts include analyser-only and VEX-only contexts correctly
- [ ] 14 Dashboard status totals reconcile mathematically
- [ ] 15 Unresolved mappings remain visible and cannot reduce risk
- [ ] 16 Dedicated VEX Investigation UI available
- [ ] 17 Tenant/Project/Application/SBOM filters apply consistently
- [ ] 18 `vex:read` / `vex:write` enforced server-side
- [ ] 19 Current exports continue to work
- [ ] 20 All mandatory acceptance scenarios pass automated tests

---

## 13. Open questions

**Q1 (blocks PR-1 sign-off, not PR-1 start).** §35 lists no `is_current` field, but §20
(VEX-INV-002) requires current-vs-historical separation and PR-2 must define the mechanism. This
plan adds `is_current` in PR-1 so the engine has it. Confirm this is the intended reading rather
than a separate history table.

**Q2 (PR-1).** §33 requires "a stable document identity" but does not say what the hash covers.
Proposed: SHA-256 over the canonical JSON serialisation of `raw_document_json` with whitespace and
key order normalised, so a byte-different but semantically identical re-upload is still idempotent.

**Q3 (PR-4).** §44 says "reuse existing manual override APIs where practical". The existing
`PATCH .../vex-override` is component+vulnerability scoped and has no `row_version`. Adding
optimistic concurrency to it changes an existing public API shape, which CLAUDE.md says to ask
about. Proposal: leave the existing endpoint untouched and add a new investigation-scoped decision
endpoint that carries `row_version`.

**Q4 (PR-5).** §27 requires a Reviewer/Owner column, but `assigned_to`/`reviewed_by` only arrive in
PR-6. Render them read-only/empty in PR-5 and wire the assignment action in PR-6.

---

## 14. Session log

| Date | Session | Outcome |
|---|---|---|
| 2026-09-24 | PR-0 | `app/metrics/vex.py` added; `vex_provider.py` off direct finding queries. Corrected a Session-0 error: only one architectural test was failing, not two. |
| 2026-09-24 | Session 0 | Discovery + this plan. Spec vendored to `docs/requirements/`, CLAUDE.md addendum appended. Decided: synchronous reconciliation, plan-only session. Found two pre-existing red architectural tests → added PR-0. |
