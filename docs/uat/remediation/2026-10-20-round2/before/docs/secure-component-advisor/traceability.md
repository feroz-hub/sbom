# Secure Component Advisor — traceability matrix

Requirement → code → tests. Test files are under `tests/` unless marked **FE** (`frontend/src/app/component-advisor/componentAdvisor.test.tsx`).
Code paths are relative to `app/`. "T#" is the prompt §10 test matrix.

## Functional requirements

| ID | Requirement | Code | Tests |
|---|---|---|---|
| FR-SCA-001 | Component intelligence per unique version | `metrics/component_advisor.py` `component_intelligence_snapshot`; `services/component_advisor/identity.py`, `intelligence_service.py` | `test_component_advisor_intelligence.py` (usage, evidence, duplicates, unattributed); `test_component_advisor_api.py::test_component_detail_includes_usage_lifecycle_and_evidence__FR_SCA_001`; FE column groups |
| FR-SCA-002 | Dashboard and KPIs | `services/component_advisor/filters.py` `kpis`; `routers/component_advisor.py /summary`; FE `page.tsx` | `test_component_advisor_api.py::test_summary_kpis…`, `::test_T13_every_kpi_reconciles…`; FE T35, T36 |
| FR-SCA-003 | No Known Actionable Vulnerabilities semantics | `services/component_advisor/classification.py` | T1–T7 in `test_component_advisor_classification.py` and `test_component_advisor_intelligence.py` |
| FR-SCA-004 | Accepted-risk policy | `services/component_advisor/policy.py`, `policy_service.py`, migration 068 | T8 (`test_component_advisor_policy.py`, `test_component_advisor_policies_api.py`); `test_disabled_policy_blocks_platform_default…`; FE T37 |
| FR-SCA-005 | Trusted-component policy | `policy.py` `validate_trust_rules` / `evaluate_trust` | T9 (both policy test files); `test_trusted_kpi_renders_only_with_a_policy_and_reconciles__FR_SCA_005` |
| FR-SCA-006 | Hierarchical filters | `services/dashboard_scope.py` (reused); `dashboard_scope_dependency` | `test_T12_cross_tenant_scope_ids_are_404__FR_SCA_006`, `test_child_scope_without_parent_is_400__US_SCA_05`, `test_scope_narrowing_updates_every_widget__US_SCA_05`; FE T35 |
| FR-SCA-007 | Risk filters | `filters.py` `AdvisorFilters` / `apply_filters` | `test_T13_filters_apply_identically…`, `test_risk_filter_accepts_repeat_and_comma_forms…`, `test_informational_filter_is_accepted_but_reported_unsupported__D4` |
| FR-SCA-008 | Search | `filters.py` `matches_search` / `search_families`; `/search` | T14 `test_T14_search_by_name_purl_ecosystem_supplier__FR_SCA_008`; FE T38 |
| FR-SCA-009 | Purpose metadata with provenance | `purpose.py`, `purpose_service.py`, parsers (`parsing/cyclonedx.py`, `spdx.py`), `scripts/backfill_component_descriptions.py` | T15, T16 (both policy test files); `test_cyclonedx_json_and_xml_and_spdx_keep_component_descriptions…`; `test_backfill_fills_only_missing_descriptions…`; FE T38, T39 |
| FR-SCA-010 | Tenant adoption intelligence | `intelligence_service.py` `adoption_view` | `test_adoption_view_lists_products_and_observed_versions__FR_SCA_010`; FE T39 |
| FR-SCA-011 | Recommendation work item | `recommendations/workflow.py`, `service.py`, migration 069, `workers/component_advisor_tasks.py` | T17–T20 (`test_component_advisor_recommendation_rules.py`, `test_component_advisor_recommendations_api.py`) |
| FR-SCA-012 | Alternative discovery | `recommendations/alternative_discovery.py`, `services/component_advisor/sources.py` | T22, T23 (`test_component_advisor_alternatives.py`); `test_same_family_versions_come_before_alternatives__T21_T22` |
| FR-SCA-013 | Same-family safer versions | `recommendations/version_discovery.py`; `metrics … advisor_remediation_hints` | T21 (`test_component_advisor_recommendation_rules.py`, `test_component_advisor_recommendations_api.py`) |
| FR-SCA-014 | Compatibility checks | `recommendations/compatibility.py`, migration 070 | `test_every_candidate_gets_all_fourteen_checks__FR_SCA_014`, `test_every_candidate_has_fourteen_persisted_checks__FR_SCA_014`, `test_missing_evidence_is_unknown_never_pass` |
| FR-SCA-015 | Blocking gates cannot be overridden | `compatibility.py`; ranking in `service._persist_candidates`; `decisions.check_candidate` | T24–T26; `test_score_never_lifts_a_blocked_candidate__FR_SCA_015`; `test_blocked_candidate_cannot_be_recommended__FR_SCA_015` |
| FR-SCA-016 | Vulnerability history | `recommendations/history.py`; `metrics … advisor_version_history` | T28, T30 (`test_component_advisor_scoring.py`, `test_component_advisor_scoring_api.py`) |
| FR-SCA-017 | Transparent versioned scoring | `recommendations/scoring.py`, migration 071, SCORING policy kind | T29 (both scoring test files) |
| FR-SCA-018 | Structured explanation | `recommendations/explanation.py` | `test_explanation_is_generated_from_structured_codes__FR_SCA_018`; FE T40 |
| FR-SCA-019 | Confidence | `recommendations/confidence.py` | T27; `test_unobserved_candidate_without_history…`; `test_insufficient_evidence_candidate_cannot_be_recommended__FR_SCA_019` |
| FR-SCA-020 | Freshness | `confidence.freshness_view`; `metrics … advisor_vulnerability_source_freshness`; `meta.freshness` | `test_stale_evidence_lowers_confidence…`, `test_unavailable_analysis_never_silently_passes…`, `test_summary_meta_reports_vulnerability_source_freshness…` |
| FR-SCA-021 | Human decisions | `recommendations/decisions.py`, `service.decide`, `/decisions`; FE decision dialog | T31; `test_recommend_then_accept_then_close…`, `test_request_more_evidence_returns_to_review__US_SCA_14`; FE T41 |
| FR-SCA-022 | Audit | `recommendations/audit.py`, migration 072, mirrored to `audit_log` | T32, T34; `test_policy_publishes_are_in_the_tenant_audit_history…` |
| FR-SCA-023 | Tenant isolation | `TenantOwnedMixin`, explicit tenant predicates, 404 convention | T11, T12 across `test_component_advisor_intelligence.py`, `_api.py`, `_policies_api.py`, `_recommendations_api.py`, `_alternatives_api.py`, `_analytics_api.py`; `test_T12_every_advisor_endpoint_rejects_foreign_ids_without_leaking__FR_SCA_023`; FE T42 |
| FR-SCA-024 | Analytics (Could) | `services/component_advisor/analytics.py`; `metrics … advisor_recommendation_analytics` | `test_component_advisor_analytics_api.py` |

## Non-functional requirements

| ID | Code / mechanism | Evidence |
|---|---|---|
| NFR-SCA-001 Security | `permission_for_request` branches, per-route `require_permission` / `require_configuration_permission`, capabilities | `test_missing_read_permission_is_403__NFR_SCA_001`, role matrices in the policies, recommendations and review test files |
| NFR-SCA-002 Integrity | `evidence` (SBOM + run ids), policy version ids on classifications, events and factors | `test_evidence_references_exact_sbom_and_analysis_run__NFR_SCA_002`, T8, T29, T34 |
| NFR-SCA-003 Availability | `sources.query_sources` (timeout + breaker), evaluation savepoint, `DISCOVERY_FAILED` | `test_failing_adapter_degrades…`, `test_circuit_breaker…`, `test_external_source_failure_degrades_without_breaking_anything__NFR_SCA_003` |
| NFR-SCA-004 Observability | `log_event` events (see runbook), correlation ids on items and events, Celery task | `test_structured_events_cover_the_recommendation_lifecycle__NFR_SCA_004`, `test_creation_and_evaluation_are_audited_with_correlation…`, background task tests |
| NFR-SCA-005 Performance | Memoized snapshot, identity memo, indexes from 067 | T44 `test_component_advisor_bench.py` (results in the implementation plan) |
| NFR-SCA-006 Scalability | Per-scope cache with change markers; per-SBOM incremental rollup deferred | Benchmark; open item in the plan |
| NFR-SCA-007 Auditability | Append-only `advisor_policy_version` and `component_recommendation_event` (ORM guard) | `test_policy_versions_are_append_only_in_the_orm__NFR_SCA_007`, `test_events_are_append_only__NFR_SCA_007`, `test_stale_row_version_is_409…` |
| NFR-SCA-008 Accessibility | `AdvisorBadges` (icon + text + aria), `AdvisorNotice`, focus management, the `Table` separator fix | FE axe tests (dashboard, recommendation view), T43 (11 states) |
| NFR-SCA-009 Testability | Pure modules: `classification`, `lifecycle_mapping`, `identity`, `filters`, `policy`, `purpose`, `workflow`, `decisions`, `version_discovery`, `compatibility`, `history`, `scoring`, `confidence`, `explanation` | Unit test files `test_component_advisor_classification.py`, `_policy.py`, `_recommendation_rules.py`, `_alternatives.py`, `_scoring.py` |

## User stories

| Story | Covered by |
|---|---|
| US-SCA-01 | FR-001/002/006 rows; FE T35 |
| US-SCA-02 | FR-003; T1–T4, T10 |
| US-SCA-03 | FR-004; T8; `/classification` endpoint |
| US-SCA-04 | FR-005/010; T9 |
| US-SCA-05 | FR-006; scope tests |
| US-SCA-06 | FR-007; T13 |
| US-SCA-07 | FR-008/009; T14–T16; FE T38 |
| US-SCA-08 | FR-010; adoption tests; FE T39 |
| US-SCA-09 | FR-011/013; T17–T21 |
| US-SCA-10 | FR-012/014/015; T22–T26 |
| US-SCA-11 | FR-016; T28, T30 |
| US-SCA-12 | FR-017/018; T29 |
| US-SCA-13 | FR-019/020; T27 |
| US-SCA-14 | FR-021; T31, T33; FE T41 |
| US-SCA-15 | FR-022; T32, T34; audit access test |
| US-SCA-16 | FR-023; T11, T12 sweep; FE T42 |
| US-SCA-17 | FR-024; analytics tests |

## Prompt §10 test matrix

T1–T7 → classification + intelligence · T8–T9 → policy · T10–T13 → intelligence / api · T14–T16 → api / policies ·
T17–T21 → recommendation rules / api · T22–T26 → alternatives · T27–T30 → scoring · T31–T34 → review ·
T35–T43 → FE (page-level Vitest, decision D-9) · T44 → `test_component_advisor_bench.py` ·
T45 → full-suite regression (results in the implementation plan).
