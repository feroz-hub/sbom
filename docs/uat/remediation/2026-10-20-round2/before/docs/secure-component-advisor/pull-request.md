# Pull request

**Title:** Secure Component Advisor (FR-SCA-001..024) — component intelligence, policies, recommendations, review and UI

**Source:** `feat/secure-component-advisor` → **Target:** `feat/native-user-management`

---

## Summary

Adds the **Secure Component Advisor**: a tenant-scoped, advisory-only capability that turns analysed SBOM data into
component intelligence and evidence-based safer-version / alternative-component recommendations, with mandatory human
review and an append-only audit trail.

Spec: `docs/specs/Secure_Component_Advisor_Requirements_v1_1.docx`. Phase 0 analysis and the approved decisions
(D-1…D-11): `docs/secure-component-advisor/phase0-analysis.md`. Running log, results and open items:
`docs/secure-component-advisor/implementation-plan.md`.

**Advisory only:** the advisor writes only its own tables. It never changes a dependency, manifest, source file, SBOM,
component, finding or VEX record (tested: T33 and the no-write tests).

## What's included (one commit per spec step)

| Step | Commit | Scope |
|---|---|---|
| 0–1 | `6abb9b8`, `12f28c0`, `78abaf7` | Spec, Phase 0 analysis and plan, CLAUDE.md workstream section |
| 2 | `9ae6266` | Unique-version intelligence over eligible SBOMs × latest run × current VEX context; pure risk classification; migration 067 (indexes and `component_advisor:*` permissions) |
| 3 | `0f210bc` | `/api/component-advisor` summary, components, detail and search; KPIs that reconcile with drill-down; `meta` envelope; memoized snapshot |
| 4 | `d352746` | Versioned, append-only accepted-risk / trust policies; purpose metadata with provenance; SBOM description extraction and backfill; adoption; migration 068 |
| 5 | `3925939` | Recommendation work items (idempotent), triggers validated against evidence, same-family discovery, Celery task; migration 069 |
| 6 | `c4806bb` | Alternative discovery (tenant-observed → external adapters → manual), 14 compatibility gates with blocking rules; migration 070 |
| 7 | `3958cc0`, `d6d8c2e` | 24-month vulnerability history with coverage, versioned transparent scoring, confidence, freshness, explanations; migration 071 |
| 8 | `353c310` | Human decisions (recommend / accept / reject / defer / request evidence / close), append-only events, audit endpoints, isolation sweep; migration 072 |
| 9 | `4096ee8` | Next.js dashboard, component detail and recommendation review pages; accessible badges; 11 explicit degraded states; shared `Table` a11y fix |
| 10 | `5115605`, `2493ac7` | Analytics, observability events, migration verification on real data, docs, benchmark |

Docs: `docs/secure-component-advisor/{api,configuration,migration-notes,runbook,traceability}.md`.

## Database migrations

067 → 072, all additive with working downgrades. Verified on a clone of the development database
(059 → 072 → 066 → 072, data intact). After deploying, run:

```
python scripts/backfill_component_descriptions.py --dry-run
python scripts/backfill_component_descriptions.py --apply
```

## Permissions

New: `component_advisor:read`, `…:recommendation:create`, `…:recommendation:review`, `…:recommendation:accept`,
`…:audit:read`, `tenant:advisor-policy:read`, `tenant:advisor-policy:update`. Role defaults follow spec §9: only
Tenant Admin can accept or edit policies. The full matrix is in `runbook.md`.

## Tests

- **Backend advisor suites:** 15 test files, 221 test functions (more cases after parametrization), covering prompt §10 T1–T34 and T44. They include
  cross-tenant 404 sweeps, append-only guards, optimistic concurrency and the no-modification guarantee.
- **Frontend:** `componentAdvisor.test.tsx` (T35–T43, including axe checks). Full frontend suite: 159/160 files pass.
  The remaining failure, `src/lib/auth/shared-session-store.test.ts`, needs a local `redis-server` binary.
  `tsc --noEmit` and ESLint are clean.
- **T44 performance at sign-off scale** (200k occurrences / 25k unique versions, measured under concurrent load): warm
  p95 summary 1.71 s, drill-down 1.25 s, search 1.20 s (targets 2 s / 3 s); recommendation create + evaluate 2.29 s.
- **T45 full regression:** the full backend suite takes about 29 h locally. Clean-`HEAD` baseline and branch runs are
  in progress, and the comparison will be posted on this PR. Already identified as pre-existing on clean `HEAD`:
  `test_rbac_permissions.py::test_platform_admin_has_all_permissions`, `::test_high_value_permission_separation`,
  `test_vex_scoped_authorization.py::test_platform_override_stays_tenant_bound`. A fourth,
  `test_operator_comparison_reports_zero_mismatches`, is fixed here.

## Notable changes outside the advisor

- `scripts/compare_authorization_catalog.py`: fixed a `tuple | frozenset` TypeError (pre-existing).
- `app/services/dashboard_scope.py`: `scope_metadata` moved here from `dashboard_main.py` so both routers share it.
- Parsers (CycloneDX JSON/XML, SPDX) now keep component `description`.
- `frontend/src/components/ui/Table.tsx`: the column-resize separator now exposes `aria-valuenow`, `aria-valuemin`,
  `aria-valuemax` and `aria-valuetext` (an axe violation on every resizable table); `Th` accepts `colSpan` /
  `scope="colgroup"`.
- `tests/conftest.py`: replays the 067/068 permission seeds after truncation.

## Decisions needing product confirmation (baselines implemented)

1. **POLICY_VIOLATION trigger:** a configured trust policy evaluates the version as "not trusted".
2. **Product constraints:** the ecosystems used by the source's products. There is no platform/runtime model, so
   those checks are UNKNOWN.
3. **License gating:** uses the trust policy's allow/deny lists. Lifecycle gating uses trust `allowed_lifecycle`;
   otherwise EOL is blocked and EOS needs review.
4. **Stale evidence:** lowers confidence but does not move a component into Review Required.
5. **Default scoring weights and normalizations:** need review.
6. **Separation of duties:** the same user may currently recommend and accept.
7. **"Frequently adopted" threshold:** ≥ 3 products.

## Known follow-ups

- Platform-default policy write API (needs changes to the frozen Platform Admin V2 allowlist).
- Cold snapshot build at 200k occurrences takes about 14–24 s. Per-SBOM incremental rollup (NFR-SCA-006) if that's
  unacceptable.
- No external package-metadata source is registered until an approved source list exists (spec §12).
- No browser E2E harness in the repo; T35–T43 are Vitest page tests (decision D-9).

🤖 Generated with [Claude Code](https://claude.com/claude-code)
