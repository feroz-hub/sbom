# SBO-54 — Original failure reconciliation

All 13 original nodes reproduced in `pytest-vex-before.log`: 55 passed / 13 failed. The same four-file suite after corrections passed 69 / 0 (`pytest-vex-after.log`), including the added integer-ID negative control. No original node was deleted or skipped.

| Original node | Classification / correction | Final outcome |
|---|---|---|
| `test_vex_investigations_api.py::test_filter_by_sbom__VEX_UI_002` | Obsolete integer SBOM query IDs. Use the fixture UUID; an unknown valid UUID now correctly asserts 404 at the existing boundary. | PASS |
| `test_vex_investigations_api.py::test_tile_counts_equal_row_counts_for_the_same_filters__VEX_DASH_004` | Obsolete integer SBOM query ID. UUID in HTTP; integer eligible-SBOM IDs remain in direct metrics-service calls. | PASS |
| `test_vex_investigations_api.py::test_component_vulnerabilities_endpoint_still_responds` | Obsolete integer SBOM/component path IDs. Use both public UUIDs. | PASS |
| `test_vex_investigations_api.py::test_sbom_vex_list_endpoint_still_responds` | Obsolete integer SBOM path ID. Use public UUID. | PASS |
| `test_vex_investigations_api.py::test_resolve_finds_the_context_for_a_pair` | Resolve helper now uses SBOM/component public UUIDs; response assertion uses component UUID. CVE/GHSA and investigation identities unchanged. | PASS |
| `test_vex_investigations_api.py::test_resolve_returns_404_when_nothing_has_asserted_it` | Resolve helper now uses SBOM/component public UUIDs; response assertion uses component UUID. CVE/GHSA and investigation identities unchanged. | PASS |
| `test_vex_investigations_api.py::test_resolve_matches_an_alias__VEX_CTX_002` | Resolve helper now uses SBOM/component public UUIDs; response assertion uses component UUID. CVE/GHSA and investigation identities unchanged. | PASS |
| `test_vex_investigations_api.py::test_resolve_is_tenant_scoped__VEX_SEC_002` | Foreign fixture now exposes separate public UUID values for HTTP; preserve internal integer keys and unchanged foreign-row snapshots. | PASS |
| `test_vex_audit_concurrency.py::test_analyst_can_bind_an_unresolved_assertion__VEX_MAP_001` | Obsolete integer component request body. Use component public UUID; DB foreign keys and audit JSON assertions remain integers. Existing 200/409/404 semantics retained. | PASS |
| `test_vex_audit_concurrency.py::test_binding_is_audited_while_component_was_null__VEX_AUD_001` | Obsolete integer component request body. Use component public UUID; DB foreign keys and audit JSON assertions remain integers. Existing 200/409/404 semantics retained. | PASS |
| `test_vex_audit_concurrency.py::test_binding_a_resolved_context_is_refused` | Obsolete integer component request body. Use component public UUID; DB foreign keys and audit JSON assertions remain integers. Existing 200/409/404 semantics retained. | PASS |
| `test_vex_audit_concurrency.py::test_binding_to_a_component_in_another_sbom_is_refused__VEX_CTX_001` | Obsolete integer component request body. Use component public UUID; DB foreign keys and audit JSON assertions remain integers. Existing 200/409/404 semantics retained. | PASS |
| `test_vex_audit_concurrency.py::test_cross_tenant_mutations_are_rejected__VEX_SEC_002` | Mapping request now carries a valid component UUID, so existing foreign-investigation 404 is exercised; decision/assignment and foreign snapshot assertions retained. | PASS |

The new `test_integer_resource_ids_are_rejected_at_public_boundary` asserts 422 for integer SBOM query/path and component query/body IDs, plus unchanged row_version after rejected mapping. This repairs obsolete wire fixtures without accepting integer resource IDs in the application.

Broader VEX and other affected regressions are reported separately in RESULTS.md; the 69-test result does not claim every repository test is green.
