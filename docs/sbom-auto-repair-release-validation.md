# SBOM Auto-Repair Phase 1 release validation — 2026-10-06

## Result

**READY FOR REVIEW for Phase 1.** No unresolved Auto-Repair release blockers or implementation-introduced test failures were found after the fixes below. The full application backend and repository-wide Python lint remain non-green because of independently reproduced existing failures. This is review evidence, not production deployment approval. The initial release-validation pass made no commits, deployments, production migrations, history rewrites, or Phase 2 changes. The subsequent authorized commit-separation pass is recorded below.

Branch: `feat/native-user-management`; baseline HEAD: `4a37778`.

## Exact final verification

| Check | Final result |
|---|---|
| Full backend/application suite | **3,478 passed, 60 failed, 10 skipped; 0 execution/collection errors; 12 subtests passed**; 4,891.78 seconds |
| Backend collection | 3,548 selected of 3,566; 18 integration/benchmark cases excluded by repository defaults |
| Full frontend suite | **1,270 passed**, 162 files; 334.96 seconds; no failures or skips |
| Real browser E2E | **15 passed**, no failures/skips; 13.4 minutes |
| Consolidated repair/release/security/truncation/migration checks | **80 passed**, no failures/skips; 552.79 seconds |
| Focused frontend repair checks | **45 passed**, six files |
| Migration 074 round-trip | **1 passed**, included in the 80; fresh PostgreSQL bootstrap → downgrade 073 → re-upgrade 074 |
| TypeScript application / isolated E2E | Both passed |
| Changed Python lint | **33 changed/new Python files passed** |
| Full Python lint | **43 errors**, same 43 on clean HEAD; no introduced lint failures |
| Full frontend lint | **0 errors, 52 warnings**, same warnings on clean HEAD |
| Production Webpack build | Passed; 45 static pages generated |
| Whitespace / Alembic head | `git diff --check` passed; sole head `074_sbom_repair_jobs` |

The final backend run executes the complete default-selected suite with four isolated PostgreSQL worker databases and separate workspace directories. A temporary, uncommitted test helper batches the repository's identical reset queries into one transaction, and stabilizes only a datetime-generated test display ID for xdist collection. Assertions and application code are unchanged. Disposable worker databases use `synchronous_commit=off`; application/production database configuration was untouched. The interrupted preliminary serial run is not counted as completed evidence. Full serial command remains `.venv/bin/python -m pytest -q`.

Clean HEAD was extracted with `git archive`, with its own test database. Every final failed test reproduced there. The KEV cache failure is order-dependent: running an existing source-cache fixture first removes `SourceResponseCache` from shared SQLAlchemy metadata; the subsequent KEV test then fails on clean HEAD as well. The platform grant/revoke race passed one baseline attempt and failed another, reproducing the same existing 409 race. Two report-notification load failures from the preliminary run passed both isolation and the final full run; they were preliminary `TEST_ENVIRONMENT_FAILURE` observations, not final failures.

Evidence remains locally under `/tmp/sbom-phase1-release/`: `backend-batched-final.{log,xml}`, `backend-collection-final.log`, `frontend-final.{log,xml}`, `browser-complete-final.log`, `browser.xml`, `focused-complete-final.{log,xml}`, baseline JUnit reports, lint/build/type-check logs and `log-audit-final.json`. Browser diagnostics are private; do not commit generated credentials, manifests, keys, or artifacts.

## Historical application areas rechecked

| Area | Current full-suite evidence |
|---|---|
| Tenant user candidates | 22 passed |
| AI progress | Five passed, one existing environment-gated Redis test skipped |
| SPDX → CycloneDX | 13 passed, eight existing failures (duplicate document bom-ref / conversion rejection) |
| Component deduplication | Two passed, six existing failures (fixtures rejected by current validation) |
| Connection pooling | Three passed, two existing failures (removed private `_upsert_user` import) |
| NVD TLS | Two passed, two existing static SSL-contract failures |
| Error envelopes | Two passed, two existing exception propagation failures |
| Platform concurrency | Three passed, two existing grant/idempotency expectation failures |

Inventory after validation: 15 tracked modified files and 35 new files; one new
migration, four new backend test modules, one modified validation-test module,
one new frontend unit-test file, one browser spec with 15 cases, and two new
documentation files. The architecture handoff lists the implementation paths.

## Defects found and fixed

| Issue and root cause | Fix | Regression evidence |
|---|---|---|
| Candidate import lost the original validated application, versions, parent and current-version selection because quarantine creation did not retain upload context | Retain validated upload metadata and pass it through the existing authorized import/lineage flow | Selected-product E2E plus application/version/parent/current-selection API tests |
| Approval could import without the normal application-assignment permission | Require repair revalidation, SBOM upload **and** `product:assign_sbom`; mirror capabilities in UI | Direct API denial and role/capability tests |
| Approval request did not bind the user's reviewed candidate hash | Review UI sends hash; reject mismatches before retry/idempotency handling; independently verify stored candidate bytes | Incorrect review hash, DB-content tamper, restoration and correct-hash retry |
| Duplicate-ref safety scan missed BOM-Link fragments | Decode and conservatively inspect existing BOM-Link references; keep distinct referenced duplicates suggested/manual | BOM-Link ambiguity regression with no mutation |
| Signed/unsupported repair results lacked an explicit reason | Return supported/manual-review reason through analyze/result and display it | Signed JSON plus XML/SPDX real-browser tests |
| Rolled-back attempts were not retained as review evidence and remained advertised as automatically repairable | Retain attempted changes, emit rollback event, classify unresolved rolled-back issues manual | Full-revalidation rollback regression and audit test |
| Repair start/failure/rule logs lacked consistent job/status correlation | Allocate job ID before execution; retain safe correlation fields and failure/rollback events | Structured logging tests; live browser log inspection |
| UI could show misleading partial-success or valid-upload controls and permit stale review attempts | Accurate fixed/remaining/failed states, hide valid-upload controls, disable stale approval, invalidate relevant caches and wrap narrow layouts | Four additional frontend tests and real stale/partial/responsive scenarios |

The independent validation truncation fix is covered separately in `tests/validation/test_errors.py` and `tests/validation/test_release_truncation.py`: many informational entries cannot hide a later strict-NTIA blocking error or turn a failed report into a pass.

## Application and browser scenarios

The 15 real-browser cases cover valid upload without jobs/candidates, realistic repair/diff/approval and accepted artifact, rejection/original download/terminal denial, partial repair, ambiguous references, analyst approval, Developer restrictions, Viewer restrictions, tenant B enumeration/access denial, signed manual handling, wrong review hash then correct approval, mobile/light/dark diff layout, stale manual draft and new repair, CycloneDX XML, and SPDX JSON. Tests use actual native sign-in, BFF, API, Redis and isolated PostgreSQL, without API mocking. Accepted state updates without manual refresh. The main browser contexts reported no page errors or React hydration warnings.

The valid-upload API regression additionally runs the existing vulnerability-analysis endpoint with external vulnerability sources stubbed, preserving original content and creating no repair job. Backend checks cover unsupported accepted formats, immutable originals/stored JSON, existing accepted-source preservation, idempotent repaired candidates, bounded passes, rollback after a newly introduced blocking error, stale source jobs, invalid IDs, terminal decisions, deletion constraints and retained-file policy.

## Security verification

- Tenant-scoped session/job predicates prevent cross-tenant status, diff, candidate/report downloads and decisions; foreign IDs return the existing safe 404 envelope.
- Existing role matrix is retained: Admin and Security Analyst can repair/approve with normal upload/assignment permissions; Developer and Viewer can read status but cannot mutate or download candidates. Configuration uses validated deployment settings; there is no new tenant configuration endpoint.
- Wrong reviewed hashes and tampered stored candidate content return conflicts; correct restored candidates can be approved. Original/source/current-draft checks and full revalidation remain mandatory.
- Concurrent repair requests retain one job; concurrent approvals import one candidate; approval/rejection yields one terminal decision. Rejection cannot later activate a candidate.
- Signed documents are never rewritten; ambiguous references are never guessed; missing SBOM facts remain manual. Partial/failed/truncated candidates cannot be approved.
- All proposal paths/operations are server generated and checked; untrusted strings render as escaped text. No SBOM content is executed or sent to AI.
- The real browser run produced **254 structured repair events**: 46 analyzed, 26 started, 122 rules applied, 26 revalidated, 26 completed, six approved and two rejected. Request/tenant/user/status fields were present throughout; job/rule/SBOM IDs appear where they exist. Failure and rollback logging were exercised by backend tests. Scans found no generated passwords, bearer tokens, private keys or full SBOM payloads in API/UI logs.

## Migration and branch assessment

074 adds one repair-job table using existing IDs, timestamps and tenant conventions. Review/round-trip checked primary key, tenant/session indexes, non-null candidate hashes/evidence/status/timestamps, nullable source/decision fields, JSON columns, source/imported SBOM foreign keys and session `ON DELETE CASCADE`. Application permanent deletion handles SBOM job references explicitly. Existing policy retains workspace files; unrelated retained artifacts/jobs remain intact. No production migration was applied.

**C — the branch is acting as an integration branch.** Committed history already combines Native User Management, Secure Component Advisor and lifecycle changes. The user explicitly confirmed this is an intentional integration branch. The Phase 1 work is organized into logical commits on `feat/native-user-management`; no branch move or history rewrite was performed.

## Authorized commit organization

1. `fix(validation): preserve blocking errors beyond report truncation` — validator report accounting plus independent truncation tests.
2. `feat(sbom): add deterministic auto-repair engine` — engine, models, policy, classifier, registry, diff/report, five rules, settings and environment placeholders.
3. `feat(sbom): persist repair jobs and approval workflow` — migration, ORM/job service, router/auth wiring, upload/workspace/import/deletion integration.
4. `feat(ui): add SBOM repair review workflow` — panel/types/API client and upload/workspace integration.
5. `test(sbom): add auto-repair release and browser coverage` — backend tests, isolated E2E package, test runner and E2E TypeScript exclusion/configuration.
6. `docs(sbom): document auto-repair phase 1 validation` — architecture/handoff and this evidence report.

The user subsequently authorized this exact six-commit organization. Mixed engine/API tests are split through the Git index; the final validated source bytes are preserved. Documentation-only updates record the commit handoff.

## Known limitations and extension points

CycloneDX **JSON only** for repair; signed documents and unsupported formats require manual handling; ambiguous references are not guessed; no component versions, suppliers, licenses, hashes, PURLs, CPEs, dependency relationships, vulnerabilities or findings are invented. Normal validation still runs. AI is disabled; the no-op advisor and structured proposal/method models are future extension points only. Report counts describe the existing capped/staged validator's visible issues; repairing an earlier stage can expose later blockers. Elapsed-time limits are checked between validator calls. Historical sessions cannot recover policy flags that old code never retained. Storage cleanup follows existing retained-file policy. Default Turbopack cannot run on this workstation's missing native SWC bindings; the requested production Webpack build passed.

See `sbom-auto-repair.md` for the API matrix, file inventory, deterministic before/after example and commands to run tests/migrations. No unresolved Phase 1 release blocker remains; the existing application failures below need separate ownership before a broader application release.

## Every final backend failure

All rows are **PRE_EXISTING_FAILURE**, reproduced against clean HEAD. Final classification totals: `AUTO_REPAIR_REGRESSION=0`, `PRE_EXISTING_FAILURE=60`, `TEST_ENVIRONMENT_FAILURE=0`, `UNRELATED_FAILURE=0`. This classification concerns the final run; preliminary environment failures are described above.

| Test | Classification | Baseline evidence |
|---|---|---|
| `tests/test_500_no_leak.py::test_500_from_db_error_returns_generic_envelope` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_500_no_leak.py::test_500_from_generic_exception_returns_generic_envelope` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_ai_model_registry_migration.py::test_ai_model_registry_is_single_head_and_schema_is_installed` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_analysis_domain_logging.py::test_active_run_does_not_emit_duplicate_lifecycle` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_analysis_domain_logging.py::test_analysis_lifecycle_has_one_terminal_event_and_aggregates` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_analysis_domain_logging.py::test_excel_logs_filtered_row_aggregates` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_auth_integration.py::test_authenticated_tenant_write_preserves_context` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_component_advisor_recommendations_api.py::test_T17_critical_component_creates_and_evaluates_a_work_item__FR_SCA_011` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_component_deduplication.py::test_api_dedupe_on_upload` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_component_deduplication.py::test_component_list_does_not_modify_stored_sbom` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_component_deduplication.py::test_component_list_pagination_respects_duplicate_filter` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_component_deduplication.py::test_component_list_search_hides_and_includes_duplicates` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_component_deduplication.py::test_export_mode_original_vs_normalized` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_component_deduplication.py::test_validation_warnings_for_duplicates` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_connection_pool_fix.py::test_auth_context_is_re_resolved_for_immediate_revocation` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_connection_pool_fix.py::test_upsert_user_no_dirty_commits` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_entra_migration.py::test_downgrade_preserves_suspended_accounts` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_entra_migration.py::test_upgrade_preserves_existing_providers_and_downgrade_protects_entra` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_hcl_iam_auth.py::TestPrincipalTenantResolution::test_active_database_platform_grant_allows_explicit_tenant_selection` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_hierarchical_scheduler_migration.py::test_hierarchical_scheduler_is_single_head` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_identity_administration.py::test_authorization_audit_metadata_contains_no_secrets` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_identity_administration.py::test_last_active_tenant_admin_is_protected` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_identity_administration.py::test_membership_lifecycle_validation_and_audit` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_identity_administration.py::test_platform_grant_lifecycle_and_immediate_revocation` | PRE_EXISTING_FAILURE | `baseline-first.xml` |
| `tests/test_kev_enrichment_service.py::test_persist_analysis_run_records_kev_metadata_in_raw_report` | PRE_EXISTING_FAILURE | `baseline-kev-order.xml` |
| `tests/test_metric_consistency.py::test_no_new_direct_finding_or_run_queries_outside_metrics` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_native_iam_phase4.py::test_resend_route_is_throttled_before_token_or_email_work` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_native_iam_phase5.py::test_operational_endpoints_are_platform_only` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_native_iam_phase5.py::test_outbox_downgrade_refuses_pending_delivery` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_native_identity_migration.py::test_compatibility_migration_preserves_duplicates_pending_and_membership` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_native_identity_migration.py::test_downgrade_refuses_native_records_without_deleting_anything` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_nvd_ssl_regression.py::test_nvd_analysis_module_has_no_sslcontext_references` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_nvd_ssl_regression.py::test_nvd_analysis_module_has_no_verify_kwargs` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_phase3_identity_migration.py::test_duplicate_legacy_identity_aborts_without_merging` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_phase3_identity_migration.py::test_missing_issuer_fails_without_fabricating_identity` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_phase3_identity_migration.py::test_upgrade_from_045_preserves_ids_access_and_audit_references` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_phase5_identity_migration.py::test_downgrade_and_reupgrade_are_safe` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_phase5_identity_migration.py::test_upgrade_preserves_users_memberships_grants_and_verification_state` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_phase6_platform_concurrency.py::test_concurrent_grants_create_one_idempotent_effective_grant` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_phase6_platform_concurrency.py::test_concurrent_revoke_and_grant_leave_one_consistent_row` | PRE_EXISTING_FAILURE | `baseline-final-unknown.xml` |
| `tests/test_postgresql_integration.py::test_postgresql_feature_smoke` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_rbac_permissions.py::test_high_value_permission_separation` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_rbac_permissions.py::test_platform_admin_has_all_permissions` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_report_migrations.py::test_report_migrations_round_trip_preserves_inventory` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_sbom_lifecycle_remediation.py::test_sbom_editing_and_versioning` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxConversionPerformance::test_convert_api_returns_before_enrichment_finishes` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxConversionPerformance::test_convert_does_not_call_lifecycle_in_persist_path` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxConversionPerformance::test_run_post_conversion_enrichment_marks_completed` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionApi::test_conversion_report_saved_and_retrievable` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionApi::test_convert_spdx_creates_converted_sbom` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionApi::test_export_conversion_report_json` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionApi::test_export_enriched_cyclonedx_includes_lifecycle_properties` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionService::test_valid_spdx_converts_to_valid_cyclonedx` | PRE_EXISTING_FAILURE | `baseline-second.xml` |
| `tests/test_structured_logging.py::test_early_body_rejection_logged` | PRE_EXISTING_FAILURE | `baseline-final-unknown.xml` |
| `tests/test_user_search.py::test_active_verified_user_without_tenant_claim_or_membership_is_returned` | PRE_EXISTING_FAILURE | `baseline-extra.xml` |
| `tests/test_user_search.py::test_existing_tenant_membership_does_not_hide_global_search_result` | PRE_EXISTING_FAILURE | `baseline-extra.xml` |
| `tests/test_user_search.py::test_inactive_and_unverified_users_are_returned_with_ineligible_state` | PRE_EXISTING_FAILURE | `baseline-extra.xml` |
| `tests/test_user_search.py::test_platform_search_finds_exact_email_case_insensitively` | PRE_EXISTING_FAILURE | `baseline-extra.xml` |
| `tests/test_user_search.py::test_platform_search_matches_partial_email_display_name_and_username` | PRE_EXISTING_FAILURE | `baseline-extra.xml` |
| `tests/test_vex_scoped_authorization.py::test_platform_override_stays_tenant_bound` | PRE_EXISTING_FAILURE | `baseline-final-unknown.xml` |


## Commit-preparation verification

The authorized six-commit grouping preserves all validated product-source bytes.
Only documentation and one browser assertion changed during preparation: the
approval test now waits for the settled **SBOM Details** heading and accepted
SBOM URL, rather than the transient **SBOM Detail** loading heading. This fixes
a timing-dependent test selector without changing application behavior.

Repeated checks passed: **12** independent truncation checks, **24** engine unit
cases, **80** consolidated backend repair/security/migration checks, **45**
focused frontend checks, application and E2E TypeScript, frontend lint (**zero
errors / 52 existing warnings**) and the production Webpack build. The complete
real browser harness passed **15/15 in 1.9 minutes** after the selector correction.
A preliminary browser launch used the wrong cache path; selecting the existing
`PLAYWRIGHT_BROWSERS_PATH` resolved that environment failure without source changes.
Fresh isolated browser servers and their disposable databases were cleaned up.

The full 3,548-selected backend and 1,270-test frontend results above remain the
release baseline; the full backend was not rerun solely to organize commits.
No unrelated backend/lint failure was modified. No push, PR creation, production
migration, deployment, branch movement, history rewrite or Phase 2 work occurred.
