# SBOM Auto-Repair Phase 2 release validation

## Result

**READY FOR REVIEW — no unresolved Phase 2 release blockers.**

Branch: `feat/sbom-auto-repair-phase2`. Clean integration baseline: `6762d55`.
Initial scope: 16 added / 22 modified files; current scope: 18 added / 22 modified
files, unstaged and uncommitted. This task
adds release regression coverage and retains the complete scoring policy in
hash-bound evidence. No commit, push, deployment, production migration or AI
repair is authorized or performed.

## Test results

Final verification completed after the last source fix:

| Check | Result |
|---|---|
| Full backend/application | 3,592 passed / 58 failed / 10 skipped / 0 execution errors; 12 subtests passed |
| Clean-base rerun of all current failures | 58 failed on clean `6762d55`; no new failed nodes |
| Consolidated repair/security/migration | 192 passed / 0 failed / 0 skipped / 0 execution errors |
| Release quality unit guards | 43 cases passed within consolidated suite |
| Browser E2E | 19 passed / 0 failed / 0 skipped / 0 execution errors; 2.9 min |
| Full frontend | 1,290 passed / 0 failed / 0 skipped; 163 files |
| Application TypeScript | Passed |
| E2E TypeScript | Passed |
| Changed Python lint | 25 Python files passed |
| Full `ruff check app tests` | 40 violations, identical on clean `6762d55` |
| Entire repository `ruff check .` | 109 violations, identical on clean `6762d55` |
| Frontend lint | 0 errors / 52 existing warnings; clean base has the same warnings (one referenced hook line shifts with inserted UI) |
| Production Webpack build | Passed |
| Alembic head | Sole head `074_sbom_repair_jobs` |
| Migration schema/downgrade/re-upgrade | 1 passed / 0 failed / 0 skipped; temporary PostgreSQL 18.2, default durability |

Full backend execution selected 3,660 of 3,678 cases; 18 are deselected by the
repository's default integration/benchmark marker policy. The completed run
took 1,879.18 s (31:19), with 12 additional passing runtime subtests. JUnit
counts those subtests as cases (3,672 total); the primary counts above use
pytest's normal test summary. All 58 current failures reproduce on clean
`6762d55` under the same temporary PostgreSQL configuration, in 32.07 s.
49 primary failure messages are byte-identical; the remaining differences are
generated UUIDs, checkout paths, object addresses, unordered set output and
truncated object representations of the same failure. No Phase 2 regression
was found in the full suite. Initial helper/import-path setup
errors and an interrupted preliminary run are not final suite evidence.

The full suite uses four independent PostgreSQL worker databases, independent
workspace directories and the Phase 1 temporary reset helper: identical reset
SQL executes in one transaction, and a datetime-derived parameter display ID is
stabilized for xdist collection. Application code and assertions are unchanged.
Disposable test databases use `synchronous_commit=off`; production settings are
unchanged. Clean base is extracted with `git archive`, without changing the
working checkout. Baseline failures are reproduced in separate databases.

## Release blockers and defects fixed

1. **Incomplete retained configuration evidence.** Snapshots retained a hash and
   dimension weights but omitted the grade thresholds and scoring limits needed
   to reproduce historical evidence. Store the complete policy with each
   assessment and verify its fingerprint when supplied for persistence. Tests
   reconstruct policy/grade/hash after settings change and reject inconsistent
   evidence without replacing history.
2. **Numeric representation affected the configuration hash.** Unvalidated
   integer defaults and equivalent reconstructed float values produced different
   fingerprints. Validate defaults into the same canonical model representation.
   Formula tests cover zero, 100, mixed/decimal values and reconstructed hashes.

3. **Candidate quality could be exposed before checking retained bytes.** Repair
   status serialization trusted candidate/source hash labels in its quality
   comparison. Verify the actual candidate content hash and both comparison
   artifact bindings before exposing the job. Corrupt stored candidate bytes
   produce HTTP 409 without scores; approval remains rejected. Restoring exact
   bytes restores normal status and approval. A database corruption regression
   covers the complete sequence.

4. **Repair availability was not bound to retained configuration.** Changing
   Auto-Repair enablement changed finding classifications while retaining the
   same configuration hash, allowing stale findings to be reused. Capture the
   resolved enabled flag in the quality policy/fingerprint. Numeric scores stay
   unchanged; classifications are reproducible, setting changes append history,
   and restoring the original setting reuses the original immutable assessment.
   Unit and API regression cases cover the complete sequence.

These are changes only to Phase 2 evidence; Phase 1 acceptance/repair policy is
unchanged. No unresolved Phase 2 release blocker remains. The existing application failures below remain outside scope.

## Phase 1 regression verification

Consolidated tests and real-browser workflows cover valid/invalid uploads,
duplicate bom-ref and dependencies, dangling references, partial repair,
approval/rejection and terminal states, reviewed hashes, tenant/role boundaries,
signed and unsupported documents, rollback, bounded passes, idempotency,
concurrent decisions and validation truncation. The final consolidated suite passed 192 cases and the browser suite passed 19 cases.

## Quality correctness

The nine dimensions, applicability heuristics, weights and grades are described
in [SBOM quality scoring](sbom-quality-scoring.md). Weights total 100%; scores
remain 0–100 and are rounded to one decimal. Grades use the actual score and
centralized thresholds; the UI displays the server grade even when the summary
number rounds across a boundary. Exact 0/49.9/50/69.9/70/79.9/80/89.9/90/100
boundaries are tested.

Repeated fresh-process calculations preserve overall/dimension scores,
findings/paths, grade, artifact hash, configuration hash and engine version
`2.0.0`; timestamps intentionally differ. Quality remains advisory and separate
from validation and vulnerability severity. Truncated non-blocking noise cannot
hide a late blocking schema error or change a valid upload into a failed one.
Before/after values use actual source/candidate bytes, preserve unaffected
coverage dimensions, and faithfully support zero or negative differences.

## Expanded repair safety

PURL canonicalization uses `packageurl-python`, rejecting lossy encodings,
ambiguous qualifiers and parent subpaths. It never supplies missing identity
facts. CPE normalization only trims whitespace from an already valid CPE 2.3.
Dependency cleanup removes explicitly prohibited self-edges and redundant empty
records without deleting legal edges or adding relationships. Canonical identity
matching refuses multiple equivalent declarations. All rules advertise and
respect the declared CycloneDX 1.4/1.5/1.6 schema; no version is upgraded.
Idempotency and complete revalidation remain mandatory.

## Security, snapshots and audit

Quality routes reuse existing tenant access and role permissions. Foreign IDs
return established not-found/denied envelopes without scores, findings, paths,
hashes or repairability. Immutable snapshots append to existing validation
history, retain engine/configuration/artifact bindings and cannot be updated
through the ORM. New policies append evidence rather than overwriting it.

Quality reads and candidate decisions reuse existing session locks; mixed
quality/repair and quality/approval concurrency tests verify bindings. Signed
sources remain unchanged and repair remains manual. Stale draft review disables
approval and explains that the comparison belongs to earlier bytes. Existing
hash-bound approval checks remain authoritative; quality never authorizes a
failed candidate.

Summary audit events CALCULATED, RECALCULATED and IMPROVED include existing
request/tenant/user/session/job/hash/score/version fields. Full payloads,
credentials and component inventories are not logged. Deletion uses established
workspace cascades and retention policy, preserving unrelated sessions/artifacts.

## Performance

Equivalent fixture bytes were analyzed twice in fresh clean-base and Phase 2
processes, with identical existing validation logic. Approximate local results:

| Components | Clean `6762d55` median (range) | Phase 2 median (range) |
|---:|---:|---:|
| 1,001 | 4.060 s (3.449–4.671) | 3.148 s (2.818–3.478) |
| 4,001 | 57.965 s (55.783–60.146) | 47.172 s (41.908–52.437) |

These runs share a loaded local host; timing differences are observations, not
claims of a validator speedup or an SLA. Phase 2 analysis adds one safe proposal
that base does not recognize. No material Phase 2 regression is observed.
Peak RSS in the Phase 2 benchmark remained about 116 MiB for both inventories.

Stable instrumentation wraps the unchanged `jsonschema` `uniqueItems` generator
and equality function without changing results:

| Components | uniqueItems calls | Recursive equality calls | uniqueItems time / total |
|---:|---:|---:|---:|
| 1,001 | 1,003 | 2,499,500 | 3.359 / 4.889 s |
| 4,001 | 4,003 | 39,998,000 | 55.025 / 60.500 s |

`jsonschema._keywords.uniqueItems` delegates unhashable object arrays to
`jsonschema._utils.uniq` pairwise deep equality comparisons. Equality calls grow
approximately 16× for 4× inventory and account for about 91% of the larger run.
The clean-base instrumented run produced exactly the same call counts: 1,003 /
4,003 uniqueItems calls and 2,499,500 / 39,998,000 recursive equalities. Its
uniqueItems/total times were 2.318/3.125 s and 34.440/38.267 s.
This implementation is unchanged on clean base; no validator rewrite was needed
or performed. Quality's shared index remains approximately linear. Earlier
quality timings were 0.627 / 2.477 s, with candidate recalculation 0.488 / 3.652 s,
reusing completed reports. The previously crashing optional profiler is not used
as evidence; this stable run completed successfully.

## Existing and environment failures

Current classification: 58 PRE_EXISTING_FAILURE; 0 PHASE_2_REGRESSION;
0 UNRELATED_FAILURE; 0 TEST_ENVIRONMENT_FAILURE in the completed full suite.
The historical KEV metadata and early-body logging failures passed this full
run; earlier fresh clean-base order-sensitive reproductions confirm fragility,
not a Phase 2 fix. Both platform concurrency failures reproduced in the fresh
same-environment baseline run. No assumption of historical failure counts is
used. Historical lint count 43 is not assumed:
current commands above provide fresh scope-specific, clean-base comparisons.

A temporary profiling script initially shadowed Python's standard `profile`
module during helper setup; rename/remove its temporary cache and restart the
suite. This is TEST_ENVIRONMENT_FAILURE, not an application defect. Initial
browser warm-up attempts timed out during cold Webpack compilation while other
verification jobs were active, before cases ran. The locked optional native
SWC compiler was installed only in ignored `node_modules`, with its package
integrity verified; no manifest or lockfile changed. A native-compiler run had
18 passes and a first-login timeout. Two additional prewarm attempts hit the
tenant-selection login step; the full run against the warmed isolated server
then passed the valid-upload scenario. That diagnostic run finished with 18 passes and one Viewer-role helper failure.
The Viewer-role scenario exposed an E2E synchronization race: the
helper treated disappearance of the tenant chooser during loading as completed
authentication. The helper now waits for the protected Dashboard heading before
navigating; no product code, assertion, permission or timeout is weakened. E2E
TypeScript passes after that change. A later direct `page.goto` run encountered Chromium navigation retries; the
helper now uses the actual SBOMs navigation link after protected content appears.
Overloaded diagnostic runs are interrupted rather than counted as final coverage.
Final backend/clean-base and browser runs use an independent temporary PostgreSQL
18.2 cluster. After the migration passed with default durability, `fsync=off` is
used only on this disposable test cluster to avoid filesystem-sync contention;
transactions, constraints, locks and assertions remain intact. Crash-durability
is not part of these application tests. No existing/production instance or
application database configuration is changed. Final full backend, same-environment clean-base, consolidated and browser results are recorded above.

Concurrent migration attempts timed out at the existing 300-second test limit
inside `DROP DATABASE ... WITH (FORCE)` cleanup. The unchanged roundtrip passed on a separate temporary native PostgreSQL
18.2 instance with default durability settings: 1 passed in 57.92 s. These setup/cleanup attempts are environment diagnostics, not passing
migration evidence.
No unrelated production functionality or existing lint violation is modified.

## Migration and limitations

No new migration/table: assessments reuse append-only validation-history JSON.
The sole head remains `074_sbom_repair_jobs`; roundtrip/bootstrap evidence passed on disposable PostgreSQL tests. No production migration was applied.

CycloneDX JSON 1.4–1.6 only. Signed documents, ambiguous identifiers and unknown
facts remain manual. CPE repair is whitespace-only. License validity uses current
vendored schema/application support; no external legal/license inference occurs.
Coverage eligibility is advisory and may need producer-specific refinement.
Full dashboard analytics, custom tenant-formula UI, external lookups and AI repair
remain outside this phase. Existing large-array validation remains quadratic.

## Recommended commit structure

1. `feat(sbom): add deterministic quality scoring and policy evidence` — quality
   engine/models/index/policy, shared JSON preflight and settings.
2. `feat(sbom): retain hash-bound quality snapshots and expose APIs` — history
   immutability, service/upload/repair integration, routes and audit.
3. `feat(sbom): expand specification-aware deterministic repairs` — rules,
   registry metadata and canonical ambiguity-safe reference matching.
4. `feat(ui): add SBOM quality findings and candidate comparison` — quality
   card/types/API, workspace/details and repair review.
5. `test(sbom): verify phase 2 release safety and browser flows` — focused guards,
   integration/concurrency/deletion tests and E2E assertions.
6. `docs(sbom): document phase 2 scoring and release validation` — quality,
   Auto-Repair and this release report.

No commits are created by this validation task.

## Per-node existing failure classification

Every current failed node below reproduced on clean `6762d55` in the same
PostgreSQL test environment. No unrelated production fixes were made.

| Test node | Classification | Clean base |
|---|---|---|
| `tests/test_500_no_leak.py::test_500_from_db_error_returns_generic_envelope` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_500_no_leak.py::test_500_from_generic_exception_returns_generic_envelope` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_ai_model_registry_migration.py::test_ai_model_registry_is_single_head_and_schema_is_installed` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_analysis_domain_logging.py::test_active_run_does_not_emit_duplicate_lifecycle` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_analysis_domain_logging.py::test_analysis_lifecycle_has_one_terminal_event_and_aggregates` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_analysis_domain_logging.py::test_excel_logs_filtered_row_aggregates` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_auth_integration.py::test_authenticated_tenant_write_preserves_context` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_component_advisor_recommendations_api.py::test_T17_critical_component_creates_and_evaluates_a_work_item__FR_SCA_011` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_component_deduplication.py::test_api_dedupe_on_upload` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_component_deduplication.py::test_component_list_does_not_modify_stored_sbom` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_component_deduplication.py::test_component_list_pagination_respects_duplicate_filter` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_component_deduplication.py::test_component_list_search_hides_and_includes_duplicates` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_component_deduplication.py::test_export_mode_original_vs_normalized` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_component_deduplication.py::test_validation_warnings_for_duplicates` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_connection_pool_fix.py::test_auth_context_is_re_resolved_for_immediate_revocation` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_connection_pool_fix.py::test_upsert_user_no_dirty_commits` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_entra_migration.py::test_downgrade_preserves_suspended_accounts` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_entra_migration.py::test_upgrade_preserves_existing_providers_and_downgrade_protects_entra` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_hcl_iam_auth.py::TestPrincipalTenantResolution::test_active_database_platform_grant_allows_explicit_tenant_selection` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_hierarchical_scheduler_migration.py::test_hierarchical_scheduler_is_single_head` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_identity_administration.py::test_authorization_audit_metadata_contains_no_secrets` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_identity_administration.py::test_last_active_tenant_admin_is_protected` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_identity_administration.py::test_membership_lifecycle_validation_and_audit` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_identity_administration.py::test_platform_grant_lifecycle_and_immediate_revocation` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_metric_consistency.py::test_no_new_direct_finding_or_run_queries_outside_metrics` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_native_iam_phase4.py::test_resend_route_is_throttled_before_token_or_email_work` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_native_iam_phase5.py::test_operational_endpoints_are_platform_only` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_native_iam_phase5.py::test_outbox_downgrade_refuses_pending_delivery` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_native_identity_migration.py::test_compatibility_migration_preserves_duplicates_pending_and_membership` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_native_identity_migration.py::test_downgrade_refuses_native_records_without_deleting_anything` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_nvd_ssl_regression.py::test_nvd_analysis_module_has_no_sslcontext_references` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_nvd_ssl_regression.py::test_nvd_analysis_module_has_no_verify_kwargs` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_phase3_identity_migration.py::test_duplicate_legacy_identity_aborts_without_merging` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_phase3_identity_migration.py::test_missing_issuer_fails_without_fabricating_identity` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_phase3_identity_migration.py::test_upgrade_from_045_preserves_ids_access_and_audit_references` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_phase5_identity_migration.py::test_downgrade_and_reupgrade_are_safe` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_phase5_identity_migration.py::test_upgrade_preserves_users_memberships_grants_and_verification_state` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_phase6_platform_concurrency.py::test_concurrent_grants_create_one_idempotent_effective_grant` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_phase6_platform_concurrency.py::test_concurrent_revoke_and_grant_leave_one_consistent_row` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_postgresql_integration.py::test_postgresql_feature_smoke` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_rbac_permissions.py::test_high_value_permission_separation` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_rbac_permissions.py::test_platform_admin_has_all_permissions` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_report_migrations.py::test_report_migrations_round_trip_preserves_inventory` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_sbom_lifecycle_remediation.py::test_sbom_editing_and_versioning` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxConversionPerformance::test_convert_api_returns_before_enrichment_finishes` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxConversionPerformance::test_convert_does_not_call_lifecycle_in_persist_path` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxConversionPerformance::test_run_post_conversion_enrichment_marks_completed` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionApi::test_conversion_report_saved_and_retrievable` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionApi::test_convert_spdx_creates_converted_sbom` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionApi::test_export_conversion_report_json` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionApi::test_export_enriched_cyclonedx_includes_lifecycle_properties` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionService::test_valid_spdx_converts_to_valid_cyclonedx` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_user_search.py::test_active_verified_user_without_tenant_claim_or_membership_is_returned` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_user_search.py::test_existing_tenant_membership_does_not_hide_global_search_result` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_user_search.py::test_inactive_and_unverified_users_are_returned_with_ineligible_state` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_user_search.py::test_platform_search_finds_exact_email_case_insensitively` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_user_search.py::test_platform_search_matches_partial_email_display_name_and_username` | PRE_EXISTING_FAILURE | FAILED |
| `tests/test_vex_scoped_authorization.py::test_platform_override_stays_tenant_bound` | PRE_EXISTING_FAILURE | FAILED |

## Final working state and reproduction

- `feat/sbom-auto-repair-phase2`, HEAD remains `6762d55`.
- 22 modified / 18 new files; no staged changes or commits.
- No generated artifacts, credentials, screenshots or temporary databases in Git scope.
- `git diff --check` passed. No production migration or deployment performed.
- Final full frontend: 1,290 tests in 163 files, 118.59 s; both TypeScript checks,
  lint and production Webpack build passed after the final source fix.
- Final full Python lint: 40 app/tests violations and 109 repository violations,
  identical to clean base; all 25 changed Python files pass.

Normal repository commands, using a dedicated PostgreSQL test URL (never production):

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest -q tests/test_sbom_repair_release.py tests/validation/test_release_truncation.py tests/test_sbom_quality.py tests/test_sbom_quality_release.py tests/test_sbom_quality_integration.py tests/test_sbom_auto_repair.py tests/test_sbom_repair_migration.py tests/validation/test_errors.py
.venv/bin/python scripts/run_sbom_repair_e2e.py
.venv/bin/python -m ruff check app tests
npm --prefix frontend test -- --run --maxWorkers=2 --testTimeout=15000
cd frontend
npx tsc --noEmit
npx tsc --noEmit -p e2e/tsconfig.json
npm run lint
npm run build
```

The release full run adds four isolated xdist workers and the temporary reset/
parameter-ID helper described above. Diagnostic logs/XML and clean-base archive
are retained outside the repository in `/tmp/sbom-phase2-validation/`.
No Phase 3 or AI repair was started.

**PHASE 2 READY FOR COMMIT/REVIEW**
