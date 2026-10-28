from pathlib import Path
import json,collections,xml.etree.ElementTree as E
D=Path(__file__).resolve().parent;R=D.parent
reg='''# Round 3 regression results

**ROUND3_UAT_PARTIALLY_COMPLETED — FULL_UAT_SIGNOFF_WITHHELD.** No full backend-green or complete485-case rerun is claimed.

## Inventory and execution populations

Current collection: **4,368 nodes**,4,349 selected by repository defaults and19 excluded by existing integration/bench markers. Every node, marker, fixture list and inspection category is recorded in [pytest-inventory.json](evidence/pytest-inventory.json). Category labels are discovery aids; final fixture/product-contract triage is incomplete.

The interrupted diagnostic collected4,339 nodes at its earlier source point. It completed **3,645 PASS /244 FAIL /0 ERROR /9 SKIP /0 XFAIL**, with19 deselected and422 nodes unfinished in that execution. Four passing subtests are separate from testcases. JUnit reports3,902 including those four subtests;3,898 ordinary testcases completed. Duration7,067.05s. The first interrupt did not terminate the process; the second produced its normal partial report. No failures or remaining nodes were discarded. [Terminal log](evidence/pytest-full-baseline.log), [JUnit](evidence/pytest-full-baseline.xml), [exact unfinished selectors](evidence/backend-not-run.json), [resource/interruption record](evidence/backend-resource-interruption.json).

Source corrections overlapped that diagnostic process; it is not final frozen-source acceptance. The collection used a generated datetime parameter ID; its one timestamp drift is explicitly reconciled against the source expression, not treated as another test.

Across actual diagnostic and later focused evidence, **4,022 current inventory nodes have execution evidence;346 have none**. Reconciled observed outcomes:3,785 PASS /228 FAIL /9 SKIP /346 NOT RUN. Targeted retests take precedence over the earlier diagnostic for corrected nodes. These are mixed execution observations, not a frozen current-source full-suite summary. [Per-node runs and qualifications](evidence/backend-execution-inventory.json), [summary](evidence/backend-coverage-summary.json).

Of the244 diagnostic failures, **17 exact nodes are corrected and retested;227 remain failing or unresolved**. An additional optional Advisor benchmark failed fixture setup, making228 distinct unresolved observed nodes. All raw node IDs and diagnostics remain in [backend-failure-classification.json](evidence/backend-failure-classification.json). Diagnostic groupings such as likely obsolete integer fixtures are not confirmed application root causes or passing results.

## Completed focused and frontend runs

| Execution | PASS | FAIL | ERROR | SKIP/XFAIL | Evidence |
|---|---:|---:|---:|---:|---|
| R1/R2 VEX/public IDs/Dashboard/scoring/native guards |163|0|0|0|[JUnit](evidence/pytest-round1-round2-protection.xml)|
| Expanded correction selection, initial |156|8|0|0|[JUnit](evidence/pytest-round3-corrections.xml)|
| Corrected repair/conversion files, intermediate |86|1|0|0|[JUnit](evidence/pytest-repair-conversion-uuid.xml)|
| Final current-source conversion node |1|0|0|0|[JUnit](evidence/pytest-conversion-final.xml)|
| Reconciliation fixture, before |0|1|0|0|[log](evidence/pytest-reconciliation-before.log)|
| Reconciliation module after + negative scope controls |25|0|0|0|[JUnit](evidence/pytest-reconciliation-after.xml)|
| Domain logging unit reproduction |20|3|0|0|[JUnit](evidence/pytest-domain-logging-before.xml)|
| Domain logging current corrected mocks |23|0|0|0|[JUnit](evidence/pytest-domain-logging-final.xml)|
| Legacy boundary initial new-fixture attempt |22|0|10|0|[JUnit](evidence/pytest-legacy-public-boundary.xml)|
| Legacy boundary intermediate |31|1|0|0|[JUnit](evidence/pytest-legacy-public-boundary-final.xml)|
| Final legacy/policy/repair/VEX boundary selection |32|0|0|0|[JUnit](evidence/pytest-legacy-public-boundary-accepted.xml)|
| Repair immutable-byte focused |1|0|0|0|[log](evidence/pytest-repair-fix.log)|
| Cron/timezone focused |20|0|0|0|[log](evidence/pytest-cron.log)|
| Signed schema/deferred signature focused |8|0|0|0|[log](evidence/pytest-signature-schema-final.log)|
| Controlled Native absolute expiry |3|0|0|0|[log](evidence/pytest-session-clock.log)|
| Session bootstrap initial reproduction |26|3|0|0|[log](evidence/vitest-session-before.log)|
| Session bootstrap after correction |29|0|0|0|[log](evidence/vitest-session-after.log)|
| Final full Vitest |1,805|0|0|0|[log](evidence/vitest-full-final.log);199 files|

Do not add overlapping focused results as unique tests. The8 initial repair/conversion failures all have individually passing outcomes; the intermediate1FAIL came from a module collected before its missing model import was corrected. [Every node](evidence/repair-conversion-failure-classification.json). All original13 SBO-54 VEX regression nodes independently PASS in the163-case guard run: [exact reconciliation](evidence/original-13-vex-retest.json).

The first legacy fixture omitted required completed_on, causing10 setup errors; the next expected configured VulnDB success without credentials, causing1 failure. The final test retains the actual required-provider400 contract, plus four configured-free existing-run success paths and negative checks on all five routes. No credential was fabricated and no provider gate was weakened. All five existing snapshot/active-run cases pass without golden snapshot replacement.

## Optional marker reconciliation

All19 originally default-deselected nodes were separately attempted: **18 PASS /1 FAIL**, not silently excluded. The13 validation corpus cases passed within the expanded164-case correction selection. Real free lifecycle-provider smoke:1PASS. Bounded optional run:6PASS (two1,000-finding cost-free AI load/cache cases, two realistic validation assertions and two validation benchmarks). [Optional index](evidence/optional-execution-summary.json), [lifecycle](evidence/pytest-live-lifecycle.xml), [bounded optional](evidence/pytest-optional-bounded.xml).

Advisor benchmark:1FAIL at its initial raw SQL tenant insert, correctly rejected by the current SQLAlchemy tenant guard. No20,000-component performance measurement was accepted. [Exact log](evidence/pytest-advisor-benchmark.log). Required follow-up: replace unsafe fixture bootstrap/read paths with explicit scoped ORM/Core operations and test-owned maintenance where justified; preserve p95 targets, noise-tenant checks and deferred product scope. Do not disable the guard, accept unsafe SQL, or relabel this failure as a hardware skip.

## Commands and checks

All backend commands use `.venv/bin/python`, `PYTHONPATH=.` and a wrapper which validates fresh test-owned PostgreSQL databases. The main Greenfield database is never a destructive fixture target. Exact commands/selectors and run metadata are retained in the harness files, JUnit and [frontend-final-commands.json](evidence/frontend-final-commands.json).

```text
PYTHONPATH=. .venv/bin/python docs/uat/round3/evidence/run-fix-regressions.py tests/test_vex_investigations_api.py tests/test_vex_confidence_serialization.py tests/test_vex_scoped_authorization.py tests/test_vex_audit_concurrency.py tests/test_vex_source_public_identity.py tests/test_policy_public_identity.py tests/test_dashboard_scope.py tests/test_component_advisor_scoring.py tests/test_native_iam_phase2.py
PYTHONPATH=. .venv/bin/python docs/uat/round3/evidence/run-fix-regressions.py tests/test_legacy_analysis_public_identity.py tests/test_analyze_endpoints_snapshot.py tests/test_policy_public_identity.py tests/test_repair_candidate_public_boundary.py tests/test_vex_confidence_serialization.py
PYTHONPATH=. .venv/bin/python docs/uat/round3/evidence/run-bounded-optional.py tests/ai/test_batch_load.py tests/validation/test_perf.py -o addopts=
PYTHONPATH=. .venv/bin/python docs/uat/round3/evidence/run-live-lifecycle.py tests/test_lifecycle_provider_live.py -o addopts=
PYTHONPATH=. .venv/bin/python docs/uat/round3/evidence/run-bounded-optional.py tests/test_component_advisor_bench.py -o addopts=
.venv/bin/python -m ruff check app tests
```

Final TypeScript exit0, ESLint exit0/zero errors/52 warnings across612 files, production frontend build exit0, full Ruff exit0. Frontend used bundled Node and one Vitest worker. Initial Ruff25 diagnostics were import/fixture-registration maintenance; no tests were removed. No global policy was changed to satisfy lint or tests. [Final frontend commands](evidence/frontend-final-commands.json), [Ruff](evidence/ruff-current.log), [source diff](evidence/round3-source.patch).

## Resource and source qualifications

DBs:sbom_greenfield_uuid_round3_test_20261020, sbom_greenfield_uuid_round3_fix_test_20261020 and sbom_greenfield_uuid_round3_inventory_test_20261020. Wrappers use distinct locks and strict database-name checks. No main/historical/production schema reset or migration run. Per-test cleanup measurements did not justify speculative conftest changes.

The overlapping-load browser attempt timed out with swap over9GiB. After the diagnostic stopped, two8-module navigation rounds plus clean-context concurrent session reads passed18checks; same Next PID, no additional restart warning/empty response. This is bounded navigation acceptance, not a leak-free or load-performance sign-off. No OS swap settings or unrelated processes were changed.

## Resume

[remaining-backend-nodes.json](evidence/remaining-backend-nodes.json) lists346 current nodes without execution evidence. `PYTHONPATH=. .venv/bin/python docs/uat/round3/evidence/run-remaining-backend.py` selects exactly those nodes through the safe wrapper and records before/after source hashes. Do not overlap that DB with other focused runs. Separately remediate/retest the228 unresolved observed nodes, then run a complete frozen current-source backend inventory and the agreed Ubuntu/staging/CI gates. No full repository-green claim is made.
'''
(R/'ROUND3_REGRESSION_RESULTS.md').write_text(reg)
for name in ['ROUND3_UAT_RESULTS.md','LINEAR_RESULTS.md']:
 p=R/name;s=p.read_text().replace('all244 exact failed nodes indexed; individual triage/fixes incomplete and422initial nodes unfinished.','244 exact diagnostic failures indexed,17 corrected/retested;227 plus1 optional benchmark failure unresolved. Deduplicated current inventory346 nodes have no execution evidence.').replace('finish serial stability follow-up','serial stability follow-up18PASS completed; investigate load limits').replace('Finish serial stability follow-up','Serial stability follow-up18PASS completed; investigate load limits').replace('Finish current-source R1/R2 backend/UI safeguards and browser project/upload/report flows.','R1/R2 guards and affected browser retests are complete locally; finish broader role/module E2E and full backend reconciliation.').replace('Six technical defects corrected and focused/live retested','Six technical defects corrected and focused/live retested').replace('after final verification','in the final evidence bundle')
 p.write_text(s)
p=R/'LINEAR_RESULTS.md';s=p.read_text();s+='''\n\nRound3 coverage disposition: **14PASS/5BLOCKED** across the exact19 historical outstanding IDs. The original485 baseline remains unchanged. Backend current inventory has4,022 nodes with evidence across diagnostic/targeted runs and346 without; reconciled observed outcomes3,785PASS/228FAIL/9SKIP/346NOT RUN, with source qualifications. This is not frozen full-suite acceptance. Optional19:18PASS/1FAIL (unsafe Advisor benchmark fixture bootstrap, not an application permission defect).\n\n5. Legacy analysis UUID boundary (R3-DEF-006): exact five advertised legacy routes now use existing scoped UUID translation after analysis:run authorization; numeric run IDs stay numeric and successor links use SBOM UUIDs. Files: app/public_api.py, tests/test_legacy_analysis_public_identity.py, tests/test_analyze_endpoints_snapshot.py, tests/public_id_fixture.py. Final32focusedPASS; real OSV/boundary/persistence7PASS. Missing VulnDB credentials remain required400; no paid-provider acceptance claimed.\n\nSBO-54 follow-up:227 baseline nodes remain failing/unresolved plus1 Advisor benchmark fixture failure;346 current inventory nodes still unexecuted. Retain In Progress. SBO-55: real repair UI10PASS and serial navigation18PASS now available; Ubuntu acceptance remains unexecuted. SBO-59: WITHHELD. SBO-73: retain Decision Needed and the unchanged [OptionA/B proposal](../remediation/2026-10-20-round2/SBO-73_DECISION_PROPOSAL.md). No automatic tracker changes.\n\nReview the exact Round3-only [source patch](evidence/round3-source.patch), [file/hash manifest](evidence/round3-source-files.json), [per-node regression inventory](evidence/backend-execution-inventory.json) and [resumable checkpoint](evidence/CHECKPOINT.json). Existing dirty work and previous fixes are preserved; no commit, push, merge or deployment.\n''';p.write_text(s)
p=R/'ROUND3_UAT_RESULTS.md';s=p.read_text();s+='''\n\n## Final checkpoint reconciliation\n\nThe exact19 target register is **14PASS/5BLOCKED**. Five blockers: three platform account-state lifecycle cases lack a policy-authorized status-management capability; cryptographic signed/tampered verification is unimplemented; the original independent idle-expiry criterion lacks a Native product/security contract. SBO-73 separately remains Decision Needed. No seeded identities or privileges were changed.\n\nCurrent backend inventory4,368:4,022 nodes have actual evidence across diagnostic and focused runs;346 have none. Reconciled observations3,785PASS/228FAIL/9SKIP/346NOT RUN retain per-run source qualifications and are not a frozen current-source full execution. The interrupted run's original3,645PASS/244FAIL/9SKIP remains intact;17 of its exact failures now pass independently,227 remain unresolved, plus1 newly executed Advisor benchmark fixture failure. All19 optional marker exclusions were separately attempted:18PASS/1FAIL.\n\nSix confirmed technical defects were corrected and retested. Final current-source legacy/policy/repair/VEX boundary suite32PASS; R1/R2 guard suite163PASS; original13 VEX nodes eachPASS. Full frontend1,805PASS, TypeScript/build/Ruff exit0, ESLint zero errors/52 warnings. Actual repair review/reject/approve UI10PASS; KEV six-role UI7PASS/zero catalogue writes; later bounded serial navigation18PASS, preserving the initial load timeout.\n\n**ROUND3_UAT_PARTIALLY_COMPLETED. FULL_UAT_SIGNOFF_WITHHELD.** Remaining work is enumerated in [CHECKPOINT.json](evidence/CHECKPOINT.json), [regression results](ROUND3_REGRESSION_RESULTS.md) and [Linear drafts](LINEAR_RESULTS.md). Formal acceptance requires remaining backend execution/remediation, unresolved criterion/owner decisions and agreed Ubuntu/staging/CI evidence. No full application UAT sign-off or Linear Done transition is granted.\n''';p.write_text(s)
print('Finalized regression report and release/Linear checkpoint reconciliation')
