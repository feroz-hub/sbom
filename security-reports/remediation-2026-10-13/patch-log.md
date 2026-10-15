# Incremental patch/validation log

The baseline report was written before application edits. All changes remain uncommitted in the shared working tree; these are logical review groups, not claims of independently committed patches. Existing untracked security assessment artifacts were preserved.

| Group | Diff summary | Focused validation | Next patch identified |
| --- | --- | --- | --- |
| 1 | Remediation close/actor and project restore tenant/actor guards: initial 3 application files, 19 insertions / 5 deletions | Reproduction: 4 failures / 3 passes; corrected guard tests plus existing KEV routes: 29 passes | Global catalog mutations |
| 2 | Lifecycle route/service platform guards, KEV platform dependency, platform-context selection; KEV service fixture updated with a legitimate platform actor | New negative tests failed against original behavior; 46 focused/KEV/worker passes, then positive lifecycle CRUD/import passed | Explicit route catalog/export policies |
| 3 | Replace URL heuristic/fallback mapper with explicit catalog and registration coverage, preserve secondary dependencies, protect health metadata, separate platform/tenant permission evaluation | Reproduction: 16 failures / 24 passes; 70 focused/KEV/worker passes | Authentication/legacy/proxy hardening |
| 4 | Validate production auth/modes before startup DB work, enabled auth default, legacy context adapters, trusted transport IPs, production compose environment | Initial four hardening regressions reproduced; missing default/production catalog controls separately reproduced; broader existing provider/Native/catalog failures recorded, not bypassed | Job actor and attribution |
| 5 | Carry and revalidate AI actor/tenant, bind trusted actor for execution; secure project/SBOM/version/schedule/VEX attribution | Extra attribution reproduction: 3 failures / 78 passes; old AI job completed at original commit in reproduction; 122 focused/KEV/native-session passes | Service/report export guards |
| 6 | Remediation service write/tenant checks and effective closure; report export authority revalidated through shared service | Two missing-service guards reproduced; 134 focused/KEV/native-session passes | Final coverage and deployment-risk review |
| Validation follow-ups | Selected-route metadata lookup, explicit framework classification, canonical guard recognition, keep prior coarse gates, update-only project restore, prevent rejected/foreign AI jobs changing progress | Route-policy borrowing and foreign progress overwrite reproduced; complete selected run: 230 passes / 6 baseline HCL principal cases deselected | Fresh disposable PostgreSQL baseline, remaining Core/bulk/job review |

Final tracked application/test diff: 25 files changed; new catalog, policy validation, job authorization and regression test files are additional untracked deliverables. Exact current diff is available through Git. Reports contain no deployed credentials. Ruff and whitespace checks pass. No frontend files, live databases, grants, or deployed services changed.

## Regression boundaries

Existing HCL/legacy/tenant/KEV SQLite baseline: 53 passes, 8 failures, 16 setup errors. Entra original-commit comparison: 33 passes, 8 failures, 2 errors. A broader modified HCL/Entra run: 135 passes, 11 failures, 2 errors. A wider Native/catalog selection: 111 passes, 50 failures; catalog seeding and persistent SQLite fixture data do not support a clean integration baseline. Some old platform fixtures also violate the newly enforced platform/tenant separation. These are documented, not reported as green.

The final selected run includes all new regression cases, existing KEV route/worker suites, native session lifetime, HCL claim/signature/startup tests, and Entra token/configuration tests. Authorization HTTP matrix covers all five built-in roles and GET/POST/PUT/PATCH/DELETE. Additional tests cover unauthenticated/invalid tokens, disabled accounts, removed memberships, cross-tenant restore/jobs, closure and exports. Real router/service tests coexist with small HTTP policy gates using business-access sentinels. Full rendering, background broker operation, PostgreSQL and complete application lifespan integrations remain separate verification work.

## Reproduce focused checks safely

Use a fresh disposable SQLite TEST_DATABASE_URL and explicitly empty TEST_POSTGRES_DATABASE_URL. The project conftest otherwise defaults to PostgreSQL and performs cleanup/seeding.

```bash
TEST_DATABASE_URL=sqlite:////tmp/sbom_security_review_test.db TEST_POSTGRES_DATABASE_URL= \
.venv/bin/python -m pytest \
  tests/test_security_remediation_patches.py \
  tests/test_kev_router.py tests/test_kev_sync_worker.py \
  tests/test_native_session_lifetime.py -q
```

The final 230-case verification additionally selected HCL tests except `PrincipalTenantResolution`, and the eight Entra token/configuration test functions listed in `test-results.json`/the implementation report's provider-validation scope. Running all existing tests is encouraged only against a genuinely disposable, seeded PostgreSQL database; no such run has been performed here.
