# SBOM Auto-Repair Phase 3 release validation

Validated 2026-10-06–07; final report dated 2026-10-07 (Asia/Kolkata).
Branch: `feat/sbom-auto-repair-phase3-spdx`. Base and unchanged HEAD: `4f32088`.
This release-validation task performed no commit, push, deployment, production
migration or Phase 4/AI repair. Subsequent commit preparation is separately authorized.

## Result

**READY FOR REVIEW — PHASE 3 READY FOR COMMIT/REVIEW**

No unresolved Phase 3 release blocker remains. The full application backend
suite is **not green**: 58 baseline-confirmed failures remain untouched.

## Test results

| Verification | Passed | Failed | Skipped | Deselected / notes |
|---|---:|---:|---:|---|
| Full configured backend application suite | 3,697 | 58 | 10 | 18 opt-in integration/bench tests excluded by repository defaults; 12 subtests passed |
| Consolidated SPDX/CycloneDX repair, quality, security, migration and truncation checks | 297 | 0 | 0 | Overlaps full suite |
| SPDX quality/repair unit tests | 53 | 0 | 0 | Included in consolidated/full runs |
| SPDX application integration tests | 14 | 0 | 0 | Included in consolidated/full runs |
| Added SPDX release gates | 38 | 0 | 0 | Included in consolidated/full runs |
| Complete SPDX-to-CycloneDX conversion suite | 13 | 8 | 0 | Same eight failures reproduced on clean base |
| Full frontend | 1,291 | 0 | 0 | 163 files |
| Browser E2E | 27 | 0 | 0 | Fresh isolated application against final source |

Full backend: **0 execution errors, 0 collection errors**. Independent collection
confirmed **3,765 selected / 3,783 collected**, with 18 deselected by configured
markers. JUnit also counts the 12 passing subtests; do not add those to the
ordinary pytest passed count or sum overlapping selections.

- Application TypeScript: passed.
- E2E TypeScript: passed, including added unsupported-format scenarios.
- Changed Python lint: **23 files passed**.
- Full repository Python lint: **109 existing violations**, identical by file,
  code, line and message to clean base; no added violations. `app tests` alone
  contain 40 of those existing violations.
- Frontend lint: **0 errors / 52 existing warnings**; normalized output matches
  clean base. New browser coverage adds no lint errors.
- Production Webpack build: passed.
- `git diff --check`: passed.
- Alembic head: **074_sbom_repair_jobs**, sole head.
- Isolated PostgreSQL migration downgrade/re-upgrade: passed in consolidated checks.

## Failure classification and clean-base comparison

| Classification | Final failures |
|---|---:|
| PHASE_3_REGRESSION | 0 |
| PRE_EXISTING_FAILURE | 58 |
| TEST_ENVIRONMENT_FAILURE | 0 |
| UNRELATED_FAILURE | 0 |

Every failed full-suite node was reproduced using the clean archived `4f32088`
source and separate isolated PostgreSQL databases. Initial directed baseline
reproduction yielded **57 failed / 1 passed** among 58 historical targets. The
remaining platform revoke/grant concurrency case then reproduced independently:
**1 failed**, with the same `IAM_PLATFORM_ADMIN_ALREADY_GRANTED` conflict.
This is an intermittent existing failure, not a reason to change platform IAM.
No claim is made that a new complete clean-base application suite was run.

Baseline areas include error envelopes, tenant/user and IAM behavior, migration
head expectations, component deduplication, connection pooling, NVD TLS,
platform concurrency, AI progress and the independent conversion workflow.
The exact failing nodes are listed at the end of this report.

Superseded diagnostic runs are excluded from final counts: backend runs were
interrupted when fixes changed source; live browser servers briefly loaded mixed
module revisions during edits (ImportError/AttributeError), and loaded-host login
timing failures occurred. Fresh-server browser validation passed afterward.
A test-authoring mismatch assumed unsupported engine runs return `None`; the
existing engine returns unchanged original bytes. The test was corrected.
The YAML browser expectation was corrected to its existing **422 / E014**
contract, reproduced identically on clean base. A stopped temporary PostgreSQL
cluster was restarted before final focused checks; no application test used a
production database.

## Release blockers

**None unresolved.** Native candidates remain SPDX; no conversion-dependent
repair, fabricated facts, ambiguous reference guessing, source mutation,
cross-tenant access, invalid-candidate approval, signature rewriting or unbounded
repair was observed.

## Defects found and fixed

### Numeric exponent overflow in strict JSON preflight

- Root cause: `parse_constant` rejects NaN/Infinity tokens but Python's float
  parser still turns a finite-looking token such as `1e999` into infinity.
- Fix: shared preflight rejects float results that are not finite. SPDX validation,
  quality and repair consistently reject the input; CycloneDX quality/repair use
  the same guard without changing ordinary valid numeric behavior.
- Regression coverage: malformed SPDX numeric inputs and CycloneDX overflow
  cases across 1.4–1.6, plus existing strict JSON and cross-format suites.

### Repeated SPDX projection/diagnostic construction

- Root cause: each repair proposal rebuilt whole-document alias/reference indexes
  and diagnostics; extracted-license evidence was also scanned for each assertion.
- Fix: context-local, read-only analysis scope caches one shared index, diagnostics,
  reference paths, deduplication paths, identity occurrences and extracted-license
  IDs. Scope resets on exit, including exceptions. No cache survives across
  artifacts or requests; independent rule calls remain fresh.
- Regression coverage: exactly one index for many findings in analysis/quality,
  one extracted-license scan for many assertions, and mutated-document standalone
  rule calls proving no stale identity reuse. Existing concurrent tenant/repair
  and idempotency tests also passed.

### Malformed extracted-license IDs suppressing unrelated valid license credit

- Root cause: building a set from untrusted non-string `licenseId` values raised
  a TypeError caught as an invalid license expression, incorrectly reducing
  completeness for an otherwise valid standard assertion such as MIT.
- Fix: index only string IDs. Schema validation still rejects malformed evidence;
  it no longer changes the interpretation of independent valid assertions.
- Regression coverage: list/object IDs keep validation FAILED while the existing
  MIT/NONE assertions retain their correct license completeness credit.

## CycloneDX regression verification

Phase 1/2 critical scenarios passed: valid upload without repair artifacts,
duplicate bom-ref and dangling references, PURL/CPE normalization, dependency
cleanup, partial repair, approve/reject, reviewed-hash checks, tamper recovery,
tenant/role enforcement, signed/unsupported inputs, rollback, bounded passes,
idempotency, concurrent decisions and actual before/after quality.

CycloneDX engine stays **2.0.0**. A fresh-process comparison against clean base
matched quality evidence exactly after excluding calculation timestamps and the
additive format field. Historical assessments are not rewritten.

## SPDX quality verification

Native SPDX JSON **2.2 / 2.3** uses engine **3.0.0**. Document strings remain
`SPDX-2.2` / `SPDX-2.3`; API versions normalize to `2.2` / `2.3`.
Version-specific external categories remain `PACKAGE_MANAGER` / `PACKAGE-MANAGER`;
wrong-version categories are not silently changed.

Weights: schema 20%, identifiers 15%, relationships 15%, package/file completeness
15%, PURL 10%, CPE 5%, licenses 7.5%, checksums 5%, metadata 7.5% — **100% total**.
Weighted scores are bounded 0–100 with deterministic one-decimal rounding.
Repeated/fresh-process calculations preserve dimensions, findings, metrics, grade
and configuration fingerprint, excluding calculation timestamps.

Valid incomplete artifacts remain acceptable. Quality cannot authorize invalid
content. Eligibility, metadata, files, license expressions/WITH exceptions,
local/external LicenseRef evidence, checksum algorithms and malformed values
were exercised. NONE receives explicit assertion credit; NOASSERTION remains
valid but incomplete evidence. Both are retained without rewriting.

## SPDX repair verification

- Unreferenced duplicate IDs: stable deterministic disambiguation; referenced
  duplicates stay manual. Missing facts/identities are not invented.
- References: exact unique local IDs/PURLs/CPEs/name-version aliases only.
- Relationships: type, direction, comments, inverse forms and legal sentinel
  targets remain intact. Self-relations are manual, not deleted.
- documentDescribes: local/exact matches only; ambiguity stays manual.
- External documents: uniquely declared full references retained; missing,
  duplicate or malformed declarations stay manual. No external fetch occurs.
- Deduplication: exact relationships, describes entries, externalRefs and
  checksums only; packages are never merged by name/version.
- PURL: existing packageurl-python canonicalization; CPE: safe outer whitespace
  only; checksums: existing hex casing/whitespace only, never recalculated.
- Full native revalidation, rollback, iteration bounds and idempotency passed.
- Cross-format registry/evaluator isolation and compatible rule metadata passed.

## Conversion regression verification

The complete conversion selection yielded **13 passed / 8 failed**. The eight
failures match clean base, including invalid duplicate document bom-ref in the
converted CycloneDX artifact and dependent API/enrichment expectations.
Production conversion code is unchanged. Native repair/approval never calls it.

## Security, audit, deletion and concurrency

Tenant isolation and supported roles passed through backend enforcement and real
browser logins. Original bytes/hashes survive analyze, repair, review and decisions.
Approval verifies source state, actual candidate bytes and reviewed SHA256;
tampering/staleness, invalid/partial candidates and terminal rejected/failed jobs
cannot activate. Candidate restoration allows normal review again.

Strict JSON, signed/nested-signature guards and untrusted finding rendering passed.
Audit summaries retain request/tenant/user/session/job/format/spec/rule/status and
appropriate hash/engine fields without full payloads or credentials. Generic
failure/rollback audit checks and native SPDX success audits passed.

Concurrent repair, double approval, approve/reject race, quality during repair and
quality during approval passed. Deletion removes the associated job/session and
quality-event rows while retaining unrelated artifacts. Original filesystem files
remain under the existing retention policy; audit retention is unchanged.

## Browser scenarios

Valid native SPDX upload, repair/diff/actual quality/approval, exact relationship
cleanup, ambiguous manual relationships, NOASSERTION without invented licenses,
tenant isolation, CycloneDX critical flows, roles, responsive/dark presentation,
stale state and unsupported formats passed. Added API-driven browser cases cover
SPDX YAML and SPDX 3 JSON-LD with no automatic repair controls. Their rejection
behavior is retained, not converted into an accepted repair format.

## Performance

Two fresh runs per fixture, local loaded-host medians in seconds. Native workload
includes scoring and repair unavailable on base; its full RSS cannot be compared
directly with base's validator-only RSS.

| Packages | Quality | Analysis | Full repair | Revalidation | Recalculation | Peak RSS MiB |
|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 1.011 | 0.376 | 0.855 | 0.244 | 0.214 | 127.0 |
| 4,000 | 1.758 | 1.509 | 4.620 | 1.107 | 1.053 | 156.0 |

Warm shared validation CPU medians (base → Phase 3): **0.339 → 0.363 s** at 1,000
packages and **1.370 → 1.510 s** at 4,000. Added native checks cost about 7%/10%
CPU in those observations; scheduling-sensitive wall time varied more. No material
new regression was identified in these comparable shared-path observations.

Many-finding analysis after caching: **0.979 s / 5.680 s** for 1,000/4,000
repairable PURL findings; the prior loaded-host 1,000-finding run took 77.287 s.
The structural regression test enforces one index, rather than a brittle timing
limit. Native candidate JSON serialization/revalidation completed for both large
fixtures. Peak RSS growth was bounded in those fresh processes; no persistent
cross-request index retention exists.

A single repaired reference left the rounded score **97.8 → 97.8** on both large
fixtures; fixes do not guarantee a displayed numeric increase. These are local
observations, not SLAs or guaranteed speedups. Existing schema uniqueItems scaling
was not modified, and exhaustive workload/performance guarantees are not claimed.

## Migration

No Phase 3 migration. Sole head remains **074_sbom_repair_jobs**. Isolated
PostgreSQL downgrade/re-upgrade sanity passed; no production migration applied.

## Known limitations

- Native repair/scoring: SPDX JSON 2.2/2.3 and existing CycloneDX JSON 1.4–1.6 only.
- XML, Tag/Value, YAML, RDF/XML and SPDX 3 JSON-LD gain no quality/repair support.
- Signed documents and ambiguous/referenced duplicate identities remain manual.
- No package merge, self-edge removal, remote artifact verification, unknown
  license/hash/version inference, AI repair or external enrichment.
- CPE repair is conservative; producer assertions are not independently verified.
- Snippet IDs participate in integrity; snippet-body completeness is out of scope.
- Findings and repairability analysis are capped by existing policy limits.
- No custom tenant scoring UI or dashboard-wide analytics.
- Existing backend/lint failures and schema uniqueItems bottleneck remain.

## Reproduction and evidence

Use isolated PostgreSQL only. Serial repository commands avoid sharing a resettable
DB between workers; parallel validation requires one database/storage scope per
worker. This release used four isolated PostgreSQL workers, the prior release
reset strategy and deterministic display IDs for time-generated test parameters.

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest -q tests/test_sbom_spdx_quality_repair.py tests/test_sbom_spdx_integration.py tests/test_sbom_spdx_release.py
.venv/bin/python -m pytest -q tests/test_sbom_spdx_cyclonedx_conversion.py
.venv/bin/python -m pytest -q tests/test_sbom_auto_repair.py tests/test_sbom_repair_release.py tests/test_sbom_quality.py tests/test_sbom_quality_release.py tests/test_sbom_quality_integration.py tests/test_sbom_repair_migration.py tests/validation/test_errors.py tests/validation/test_release_truncation.py
.venv/bin/python scripts/run_sbom_repair_e2e.py
.venv/bin/python -m alembic heads
ruff check .
cd frontend
npm test -- --run --maxWorkers=2 --testTimeout=15000
npx tsc --noEmit
npx tsc --noEmit -p e2e/tsconfig.json
npm run lint
npm run build
```

Local logs/JUnit and benchmark evidence are outside Git in
`/tmp/sbom-phase3-release/`; browser evidence is retained in the runner's
`/tmp/sbom-repair-release-*` directories. No generated artifacts/secrets are added
to the working tree.

## Recommended commit structure (not executed)

1. `feat(sbom): add native SPDX quality scoring` — quality domain/projections,
   strict JSON and native validation prerequisites.
2. `feat(sbom): add deterministic SPDX repair rules` — registry/rules/engine and
   their format/version metadata.
3. `feat(sbom): integrate SPDX quality and repair workflows` — immutable history,
   cache compatibility, service orchestration and audit integrations.
4. `feat(ui): add SPDX quality and repair review` — existing quality panel/types.
5. `test(sbom): add SPDX phase 3 safety and release coverage` — backend release,
   native integration and browser coverage.
6. `docs(sbom): document SPDX quality and auto-repair phase 3` — three feature/
   release documents and validation error-code updates.

## Exact baseline-confirmed failed nodes

- `tests/test_500_no_leak.py::test_500_from_db_error_returns_generic_envelope`
- `tests/test_500_no_leak.py::test_500_from_generic_exception_returns_generic_envelope`
- `tests/test_ai_model_registry_migration.py::test_ai_model_registry_is_single_head_and_schema_is_installed`
- `tests/test_analysis_domain_logging.py::test_analysis_lifecycle_has_one_terminal_event_and_aggregates`
- `tests/test_analysis_domain_logging.py::test_active_run_does_not_emit_duplicate_lifecycle`
- `tests/test_analysis_domain_logging.py::test_excel_logs_filtered_row_aggregates`
- `tests/test_component_deduplication.py::test_api_dedupe_on_upload`
- `tests/test_component_deduplication.py::test_component_list_search_hides_and_includes_duplicates`
- `tests/test_auth_integration.py::test_authenticated_tenant_write_preserves_context`
- `tests/test_component_deduplication.py::test_component_list_pagination_respects_duplicate_filter`
- `tests/test_component_deduplication.py::test_component_list_does_not_modify_stored_sbom`
- `tests/test_component_deduplication.py::test_validation_warnings_for_duplicates`
- `tests/test_component_deduplication.py::test_export_mode_original_vs_normalized`
- `tests/test_connection_pool_fix.py::test_upsert_user_no_dirty_commits`
- `tests/test_connection_pool_fix.py::test_auth_context_is_re_resolved_for_immediate_revocation`
- `tests/test_entra_migration.py::test_upgrade_preserves_existing_providers_and_downgrade_protects_entra`
- `tests/test_entra_migration.py::test_downgrade_preserves_suspended_accounts`
- `tests/test_metric_consistency.py::test_no_new_direct_finding_or_run_queries_outside_metrics`
- `tests/test_hcl_iam_auth.py::TestPrincipalTenantResolution::test_active_database_platform_grant_allows_explicit_tenant_selection`
- `tests/test_hierarchical_scheduler_migration.py::test_hierarchical_scheduler_is_single_head`
- `tests/test_identity_administration.py::test_membership_lifecycle_validation_and_audit`
- `tests/test_identity_administration.py::test_last_active_tenant_admin_is_protected`
- `tests/test_identity_administration.py::test_platform_grant_lifecycle_and_immediate_revocation`
- `tests/test_identity_administration.py::test_authorization_audit_metadata_contains_no_secrets`
- `tests/test_component_advisor_recommendations_api.py::test_T17_critical_component_creates_and_evaluates_a_work_item__FR_SCA_011`
- `tests/test_phase5_identity_migration.py::test_upgrade_preserves_users_memberships_grants_and_verification_state`
- `tests/test_phase5_identity_migration.py::test_downgrade_and_reupgrade_are_safe`
- `tests/test_native_iam_phase4.py::test_resend_route_is_throttled_before_token_or_email_work`
- `tests/test_native_iam_phase5.py::test_operational_endpoints_are_platform_only`
- `tests/test_native_iam_phase5.py::test_outbox_downgrade_refuses_pending_delivery`
- `tests/test_native_identity_migration.py::test_compatibility_migration_preserves_duplicates_pending_and_membership`
- `tests/test_native_identity_migration.py::test_downgrade_refuses_native_records_without_deleting_anything`
- `tests/test_phase6_platform_concurrency.py::test_concurrent_grants_create_one_idempotent_effective_grant`
- `tests/test_phase6_platform_concurrency.py::test_concurrent_revoke_and_grant_leave_one_consistent_row`
- `tests/test_postgresql_integration.py::test_postgresql_feature_smoke`
- `tests/test_nvd_ssl_regression.py::test_nvd_analysis_module_has_no_sslcontext_references`
- `tests/test_nvd_ssl_regression.py::test_nvd_analysis_module_has_no_verify_kwargs`
- `tests/test_rbac_permissions.py::test_platform_admin_has_all_permissions`
- `tests/test_rbac_permissions.py::test_high_value_permission_separation`
- `tests/test_report_migrations.py::test_report_migrations_round_trip_preserves_inventory`
- `tests/test_sbom_lifecycle_remediation.py::test_sbom_editing_and_versioning`
- `tests/test_phase3_identity_migration.py::test_upgrade_from_045_preserves_ids_access_and_audit_references`
- `tests/test_phase3_identity_migration.py::test_missing_issuer_fails_without_fabricating_identity`
- `tests/test_phase3_identity_migration.py::test_duplicate_legacy_identity_aborts_without_merging`
- `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionService::test_valid_spdx_converts_to_valid_cyclonedx`
- `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionApi::test_convert_spdx_creates_converted_sbom`
- `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionApi::test_conversion_report_saved_and_retrievable`
- `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionApi::test_export_enriched_cyclonedx_includes_lifecycle_properties`
- `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxToCyclonedxConversionApi::test_export_conversion_report_json`
- `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxConversionPerformance::test_convert_does_not_call_lifecycle_in_persist_path`
- `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxConversionPerformance::test_run_post_conversion_enrichment_marks_completed`
- `tests/test_sbom_spdx_cyclonedx_conversion.py::TestSpdxConversionPerformance::test_convert_api_returns_before_enrichment_finishes`
- `tests/test_user_search.py::test_platform_search_finds_exact_email_case_insensitively`
- `tests/test_user_search.py::test_platform_search_matches_partial_email_display_name_and_username`
- `tests/test_user_search.py::test_active_verified_user_without_tenant_claim_or_membership_is_returned`
- `tests/test_user_search.py::test_existing_tenant_membership_does_not_hide_global_search_result`
- `tests/test_user_search.py::test_inactive_and_unverified_users_are_returned_with_ineligible_state`
- `tests/test_vex_scoped_authorization.py::test_platform_override_stays_tenant_bound`
