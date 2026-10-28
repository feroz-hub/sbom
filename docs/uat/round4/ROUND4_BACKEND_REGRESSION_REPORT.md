# Round 4 backend regression report

`ROUND4_BACKEND_REGRESSION_COMPLETED`

Generated: 2026-10-20T18:24:04.754742+00:00. Full application UAT and production sign-off: **WITHHELD**. Backend qualification: **Zero failures with documented runtime skips**; skipped acceptance gates are not implicitly accepted.

## Current result

| Execution | Actual result | Qualification |
|---|---|---|
| Original 485-case UAT | 454 PASS / 12 FAIL / 11 BLOCKED / 8 NOT RUN | Historical execution, unchanged |
| 346 previously unexecuted backend nodes | 346 PASS; 0 FAIL/ERROR/SKIP; 8 additional passing subtests | Exact selection, 428.08s pytest runtime; unchanged source during this run |
| 228 originally unresolved backend nodes | 228 PASS in focused retests | Per-node evidence; overlapping selections are not summed |
| First complete frozen run | 4,383 PASS / 1 FAIL / 8 SKIP / 0 ERROR or XFAIL | 5,518.60s; unchanged source; all original 228 PASS; preserved independently |
| Final frozen backend run | {"PASS": 4385, "SKIP": 7, "FAIL": 0, "ERROR": 0, "XFAIL": 0, "XPASS": 0, "NOT RUN": 0}; subtests {"PASS": 12} | FINISHED; 4392 collected; no marker exclusions |
| Final frontend and static checks | PASS | Separate current-source checks, detailed below |
| Live six-account API safeguards | 7 PASS | Six login/context/session/audit-logout checks and Olympus four-member directory |

The original 4,368-node observations came from mixed diagnostic runs. Collection preservation independently confirms all original nodes remain represented, with the three identically redacted historical database-safety selectors compared by multiplicity. The current collection contains 4,392 nodes, including 24 new regression cases. No old PASS totals are combined with new outcomes. Subtests are reported separately from collected nodes. One dynamic datetime parameter is normalized explicitly; every other original selector remains traceable, including the changed invalid-integer expectation from HTTP 400 to the intended UUID validation HTTP 422.

## Source and environment provenance

Branch: `feat/native-user-management`; base HEAD: `2f48ff835d9e692fc84b31aaa951aad2495888ac`. The existing dirty worktree is preserved. Round 4 is uncommitted; there was no push, merge or deployment.

The complete run command is recorded verbatim in [the manifest](evidence/frozen-acceptance-attempt2-manifest.json). It invokes pytest against `tests -o addopts= --durations=25`, removing default integration/benchmark marker exclusions. The manifest records every source hash before and after. Source unchanged during complete run: **True**. Complete runtime: **6119.849 seconds**. Exit code: **0**.

All schema-reset tests target new task-owned PostgreSQL databases. The final acceptance database is `sbom_greenfield_uuid_round4_acceptance2_test_20261020`; the first attempt used `sbom_greenfield_uuid_round4_acceptance_test_20261020`. Each has its own lock; concurrent test processes cannot share either database. Historical migration tests use independently owned random databases and unchanged migration sources for the precise historical transition under test. No populated application database was migrated, truncated or recreated. Redis integration uses a task-owned ephemeral loopback server. Backup/restore is explicitly opted in against disposable databases.

## Reproduction

The exact executed command and opt-ins are in the final frozen manifest; it invoked `PYTHONPATH=. .venv/bin/python docs/uat/round4/evidence/run-frozen-acceptance-attempt2.py`, which selected all `tests` with `-o addopts=`. The wrapper refuses to overwrite its existing manifest. For a new independent execution, first copy the harness/plugin into a new evidence location and give its database, lock, telemetry files and manifest distinct task-owned names. Do not invoke the preserved child runner directly: its telemetry filename belongs to this completed evidence. Start a fresh task-owned Redis and update only the new runner's private connection reference. Redis was deliberately shut down after acceptance. Never point schema-reset fixtures at the main application database. Private setup credentials are loaded in memory; no connection string is printed. Source hashes, commands, complete collection and all outcomes are retained for reproduction.

## Confirmed technical defects and corrections

| Finding | Before | Correction | Observed focused evidence |
|---|---|---|---|
| Public identity response translation N+1 | 12 distinct references issued 12 scoped SQL queries; unchanged Advisor benchmark timed out at 300s | Collect exact identity fields, resolve in scoped chunks of 500, then perform the existing translation with request-local cache | 5 new tests pass; 12 references use one query, 501 use two; missing and foreign references fail closed; benchmark passes |
| Finding-count reconciliation CLI lacked owner context | Real CLI and original test raised `TenantContextRequired` | Discover active owners through existing maintenance authorization and bind each owner explicitly; preserve rollback, dry-run and audit | Existing 4 tests and 6 new scope/rollback/idempotency tests pass |
| Fresh Greenfield marker width differed from installation contract | Newly created Alembic marker used varchar(64), existing test required 128 | Future fresh creation uses varchar(128) | Current contract test passes on a new test database; no live schema change |

Benchmark scale and thresholds were preserved: 100 SBOMs, 20,000 component occurrences, 4,908 unique versions, 5,930 findings, separate noise tenant. Focused benchmark: cold 2.68s, warm summary p95 1.101s and components p95 0.855s, within existing 2s/3s limits. Benchmark execution was 93.61s. The prior timeout and initial failed fixture attempts remain in evidence.

Most prior failures were obsolete public-integer API fixtures; only wire identifiers and response assertions were corrected to actual persisted UUIDv4 values. Internal integer primary/foreign keys, service/job identifiers, authorization, conflict and foreign-tenant assertions remain. Historical migration tests now run on their intended historical ranges rather than attempting forbidden downgrade of revision 100. Global-directory HTTP denial is explicitly asserted under the existing V5 policy; projection matching remains direct-handler unit coverage. No policy change is implied by those unit tests.

## First full-run correction

The first complete frozen attempt is preserved separately: 4,383 PASS, 1 FAIL, 8 SKIP and 12 passing subtests; source unchanged during 5,518.60 seconds. It discovered one incorrect logging-test expectation: the test assumed the final log entry was the HTTP completion event, but installed Starlette uses `httpx2`, which logs a transport line afterward. Actual HTTP 413, correlation headers and the structured 413 event were present. The isolated reproduction and event metadata are in `evidence/logging-failure-classification.json` and `pytest-logging-isolated-before.xml`. The test correction selects the exact completion event and strengthens count/status/method/path/correlation assertions, without changing application logging or permissions. The entire logging module passed after the correction: 27 PASS in 22.42s (`pytest-logging-isolated-after.xml`). The final complete run follows this correction; its outcomes are not merged with attempt 1.

## Exact failures and limitations

No failing outcome has been observed in the frozen run.

### Actual skipped or expected-failure nodes

| Node | Outcome | Reason |
|---|---|---|
| `tests/ai/test_real_provider_smoke.py::test_real_gemini_free_tier_test_connection` | SKIP | ('/Users/ferozebasha/sbom/tests/ai/test_real_provider_smoke.py', 25, 'Skipped: GEMINI_API_KEY not set — skipping real-provider smoke') |
| `tests/ai/test_real_provider_smoke.py::test_real_grok_free_tier_test_connection` | SKIP | ('/Users/ferozebasha/sbom/tests/ai/test_real_provider_smoke.py', 38, 'Skipped: GROK_API_KEY not set — skipping real-provider smoke') |
| `tests/ai/test_real_provider_smoke.py::test_real_anthropic_test_connection` | SKIP | ('/Users/ferozebasha/sbom/tests/ai/test_real_provider_smoke.py', 50, 'Skipped: ANTHROPIC_API_KEY not set — skipping real-provider smoke') |
| `tests/ai/test_real_provider_smoke.py::test_real_openai_test_connection` | SKIP | ('/Users/ferozebasha/sbom/tests/ai/test_real_provider_smoke.py', 61, 'Skipped: OPENAI_API_KEY not set — skipping real-provider smoke') |
| `tests/test_native_greenfield_empty.py::test_empty_database_to_native_population` | SKIP | ('/Users/ferozebasha/sbom/tests/test_native_greenfield_empty.py', 20, 'Skipped: explicit empty DB/Mailpit acceptance') |
| `tests/test_native_http_acceptance.py::test_two_actual_bffs_logout_recovery_and_security_revocation` | SKIP | ('/Users/ferozebasha/sbom/tests/test_native_http_acceptance.py', 162, 'Skipped: opt-in real HTTP acceptance') |
| `tests/test_native_http_acceptance.py::test_actual_http_expiry_denies_mutation` | SKIP | ('/Users/ferozebasha/sbom/tests/test_native_http_acceptance.py', 234, 'Skipped: opt-in real HTTP acceptance') |

Four hosted-provider integrations require external credentials, which were not activated. Existing empty-population and BFF HTTP opt-ins require their declared topology and supported platform-account setup; this run does not invent those prerequisites. Real local Redis and backup/restore checks are enabled. In the first frozen attempt, the free live lifecycle-provider opt-in was omitted from its harness; its runtime SKIP is a harness configuration limitation, not evidence of provider failure or unavailability. The separate current-source preflight passed (1 PASS, 4.50s; `pytest-live-lifecycle-preflight.xml`). The second frozen run enabled the flag and the live lifecycle case passed in the full final population. The first-run SKIP remains historical; its focused preflight and final frozen outcome are separate actual executions. No test is excluded by a pytest marker. Exact observed skip reasons and nodes are recorded above when executed.

SBO-73 remains Decision Needed. Platform account-status management, idle-expiry policy and cryptographic signature verification have no new approval. Ubuntu/staging, CI and full browser E2E release gates were not executed in Round 4. Local API/TestClient evidence does not replace those gates. The long-running live API process was not restarted to load the new serializer; its authentication safeguard checks do not claim live verification of that new code. Current-code integration verification uses isolated PostgreSQL and FastAPI.

### Final validation checks

| Check | Result | Runtime seconds | Evidence |
|---|---|---:|---|
| vitest-full-final | PASS | 155.102 | evidence/vitest-full-final.log |
| typescript-final | PASS | 2.209 | evidence/typescript-final.log |
| ruff-final | PASS | 0.091 | evidence/ruff-final.log |
| eslint-full-final | PASS | 16.419 | evidence/eslint-full-final.log |
| build-final | PASS | 10.665 | evidence/build-final.log |
| diff-whitespace-final | PASS | 0.074 | evidence/diff-whitespace-final.log |

## Previous remediation protection

The full inventory includes VEX serialization, stale-version concurrency, role restrictions and tenant isolation; Dashboard UUID hierarchy; Advisor history; KEV authorization; Native IAM/Users & Access; repair candidate-byte integrity; CUSTOM cron; session HTTP 503 recovery; and legacy analysis UUID boundaries. Their actual individual outcomes are in [the complete register](ROUND4_TEST_RESULTS.json) and [the protection register](evidence/prior-round-protection-register.json). Frontend-specific behavior is covered by the completed full current Vitest run: 1,805 PASS across 199 files, including Dashboard UUID filters, popup interaction, provider-neutral wording and HTTP 503 session recovery. TypeScript, Ruff, production build and full frontend ESLint passed; ESLint scanned 628 files with zero errors and 52 warnings. Source hashes remained unchanged from the backend run through final validation. No inferred PASS is assigned to an unobserved node.

The seven live API safeguard checks show all six seed identities authenticate with the expected roles, platform has no inherited tenant, and Olympus has the four expected active, verified members. Admin requires explicit tenant selection in the current multi-membership state; the harness now selects the authorized Olympus tenant. Native logout audit HTTP 200 is not described as bearer-token revocation. No seed credentials, roles or memberships were changed.

## Evidence, preservation and next gates

All 2,192 protected earlier report/evidence hashes are rechecked in [historical preservation](evidence/historical-preservation.json). Round 4 source changes are isolated from pre-existing dirty changes in [task-only patch](evidence/round4-source.patch) and [file hashes](evidence/round4-source-files.json). The original 485-case baseline is unchanged. Focused attempts, collection failures, timeouts and corrected retests are retained, not overwritten with passing logs.

- [Per-node current outcomes and original 228 reconciliation](ROUND4_TEST_RESULTS.json)
- [Root-cause classification](ROUND4_FAILURE_CLASSIFICATION.md)
- [Full frozen run manifest](evidence/frozen-acceptance-attempt2-manifest.json), [log](evidence/pytest-full-frozen-attempt2.log), [JUnit XML](evidence/pytest-full-frozen-attempt2.xml)
- [Resumable checkpoint](evidence/CHECKPOINT.json)
- [Linear drafts](ROUND4_LINEAR_RESULTS.md)

The task-owned ephemeral Redis instance was shut down after PID/port ownership and no-persistence verification (`evidence/isolated-redis-cleanup.json`). Task-owned PostgreSQL databases remain for reproducibility; no shared service or main application database was removed. Public node metadata uses stable hash labels for three synthetic database-safety URL parameters; exact selectors remain privately in mode0600 task files (`evidence/selector-sanitization.json`).

SBO-54 requires review of the final frozen run plus current frontend/static results. SBO-55 retains its Ubuntu browser/E2E acceptance gate. No Linear status was changed, no duplicate issue was created, and no full application or release sign-off is granted.

## Round 4 changed source files

- `app/public_api.py` (modified)
- `scripts/greenfield_uuid.py` (modified)
- `scripts/reconcile_analysis_run_finding_counts.py` (modified)
- `tests/public_id_fixture.py` (modified)
- `tests/test_auth_integration.py` (modified)
- `tests/test_component_advisor_api.py` (modified)
- `tests/test_component_advisor_bench.py` (modified)
- `tests/test_component_advisor_recommendations_api.py` (modified)
- `tests/test_component_advisor_review_api.py` (modified)
- `tests/test_component_deduplication.py` (modified)
- `tests/test_component_extraction_reconciliation.py` (modified)
- `tests/test_component_finding_reconciliation.py` (modified)
- `tests/test_cves_router.py` (modified)
- `tests/test_dashboard_posture_evidence.py` (modified)
- `tests/test_dashboard_priority_findings.py` (modified)
- `tests/test_dashboard_v4_metrics.py` (modified)
- `tests/test_entra_migration.py` (modified)
- `tests/test_functional_security_compatibility.py` (modified)
- `tests/test_hierarchical_scheduler_migration.py` (modified)
- `tests/test_identity_administration.py` (modified)
- `tests/test_large_sbom_upload_integrity.py` (modified)
- `tests/test_lifecycle_cache_upsert.py` (modified)
- `tests/test_lifecycle_enrichment.py` (modified)
- `tests/test_lifecycle_provider_e2e.py` (modified)
- `tests/test_lifecycle_xeol_openeox.py` (modified)
- `tests/test_metric_consistency.py` (modified)
- `tests/test_native_backup_acceptance.py` (modified)
- `tests/test_native_identity_migration.py` (modified)
- `tests/test_openapi_security.py` (modified)
- `tests/test_phase3_identity_migration.py` (modified)
- `tests/test_phase4_auth_context.py` (modified)
- `tests/test_phase5_identity_migration.py` (modified)
- `tests/test_phase6_platform_concurrency.py` (modified)
- `tests/test_phase7_initial_tenant_admin.py` (modified)
- `tests/test_phase7_tenant_creation.py` (modified)
- `tests/test_phase9_role_assignment_api.py` (modified)
- `tests/test_platform_admin_default_context.py` (modified)
- `tests/test_platform_directory_regression.py` (modified)
- `tests/test_platform_tenant_v2.py` (modified)
- `tests/test_postgresql_integration.py` (modified)
- `tests/test_report_migrations.py` (modified)
- `tests/test_sbom_assign_and_edit.py` (modified)
- `tests/test_sbom_latest_analysis_summary.py` (modified)
- `tests/test_sbom_lifecycle_remediation.py` (modified)
- `tests/test_sbom_operational_lifecycle.py` (modified)
- `tests/test_sbom_quality_integration.py` (modified)
- `tests/test_sbom_repair_migration.py` (modified)
- `tests/test_sbom_repair_release.py` (modified)
- `tests/test_sbom_revalidate_endpoint.py` (modified)
- `tests/test_sbom_spdx_integration.py` (modified)
- `tests/test_sbom_spdx_release.py` (modified)
- `tests/test_sbom_upload_validation_persisted.py` (modified)
- `tests/test_sbom_upload_version_lineage.py` (modified)
- `tests/test_sbom_validation_report_endpoint.py` (modified)
- `tests/test_sbom_vulnerability_excel_report.py` (modified)
- `tests/test_sboms_analyze_snapshot.py` (modified)
- `tests/test_sboms_analyze_stream.py` (modified)
- `tests/test_schedules_api.py` (modified)
- `tests/test_scoped_configuration.py` (modified)
- `tests/test_soft_delete.py` (modified)
- `tests/test_structured_logging.py` (modified)
- `tests/test_tenant_boundary_hardening.py` (modified)
- `tests/test_tenant_isolation.py` (modified)
- `tests/test_user_search.py` (modified)
- `tests/historical_migration_fixture.py` (new)
- `tests/test_reconcile_analysis_run_scope.py` (new)
- `tests/test_round4_uuid_regression.py` (new)
- `tests/test_public_identity_batch_serialization.py` (new)
