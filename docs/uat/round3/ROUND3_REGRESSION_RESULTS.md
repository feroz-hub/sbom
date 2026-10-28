# Round 3 regression results

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

## Existing runtime skips — separate from marker exclusions

The interrupted execution's9 SKIPs remain SKIP, never PASS. Exact nodes/reasons:[backend-skips.json](evidence/backend-skips.json). Four hosted-provider smoke tests require absent Gemini, Grok, Anthropic or OpenAI keys; no paid credentials were activated. One Redis progress round-trip needs an explicit isolated AI_TEST_REDIS_URL (its fixed test run ID must not target shared application progress). Four opt-in acceptance cases cover isolated backup/restore, completely empty DB/Mailpit population and two real two-BFF HTTP cases; their required opt-in topologies were not configured in this execution. Existing hardcoded ports/historical-bootstrap assumptions must be checked against Greenfield100 on new task-owned databases before enabling them. Local six-role Chrome and controlled expiry evidence does not relabel these skipped node IDs as passing.
