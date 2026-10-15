# Component identity and finding reconciliation — engineering report

Development implementation, 15 October 2026. No production deployment, migration, re-analysis, backfill, container restart, cache clearing, or historical finding modification was performed.

## Baseline and confirmed defects

- Development branch: `codex/component-finding-reconciliation`.
- Base commit: `67c5bb7f4b8f8027ca62b58bee225e1d5f444e68`, from `feat/native-user-management`.
- Existing untracked `security-reports/` artifacts were left untouched.
- Read-only Docker inspection found backend, worker, and beat image tags `sbom-analyser-backend:native-67c5bb7`. This confirms tag correspondence, not byte-for-byte source reproducibility.
- Read-only PostgreSQL inspection found production schema revision `077_sbom_selection_mode`. Run 15 remains `FINDINGS`, with 113 persisted findings: 42 NVD (all scored), 71 OSV (all unscored), and 67 findings with no stored component ID. These totals were checked again after development verification and remain unchanged. Its four GitHub errors are HTTP **401 Unauthorized**, classified as authentication failures. Credentials were neither printed nor changed. No live authenticated provider retry was attempted.
- Baseline targeted tests: **18 passed, 1 failed**. The failing maintenance-script test is described under validation.

Confirmed root causes:

1. `_component_input()` omitted the stored primary key, SBOM, and tenant context.
2. OSV preserved query/result correspondence through hydration but subsequently flattened advisories globally, deduplicated by advisory ID, and reconstructed component identity from `affected[0]`. That lost the input component, version, and additional affected occurrences. Cache replay followed the same faulty normalization.
3. Component resolution selected the first CPE/PURL/name candidate, including ambiguous candidates. Upload CPE backfill could overwrite a different document reference. Reference-less re-sync could insert additional rows.
4. CPE-only and weaker name identities could automatically group components. Maven/Go PURL case and version normalization could erase meaningful distinctions. Representative metadata was overwritten with aggregate metadata.
5. Provider deduplication and persisted-row metrics used different finding identities and score policies. The provider merger only adopted scores when relative severity increased; the metrics merger independently chose maximum scores and maximum textual severity.
6. OSV stripped vector version prefixes without calculating numeric CVSS. NVD could select score, vector, and version through separate routines.
7. The old database uniqueness constraint used `(run, vulnerability, CPE)`, allowing provider duplicates with NULL/differing CPEs while potentially rejecting distinct components with the same CPE.
8. Detailed provider observations were not reliably queryable from a canonical finding. CSV/SARIF and comparison readers also had independent reconciliation behavior.

## Architecture and identity policy

Before: provider observations → different name/CPE-based deduplicators → partially reconstructed component IDs → flattened ratings → provider-oriented rows and aggregates.

After:

```text
Original SBOM + dependency graph retained
  → normalize existing component identity fields
  → group confident package releases, mark original occurrences
  → load stored occurrences from the selected SBOM only
  → query providers / replay shared raw intelligence caches
  → bind each applicable observation to its originating occurrence
  → reconcile verified vulnerability aliases within that occurrence/run
  → select a complete validated CVSS assessment
  → persist canonical finding + structured provider evidence
  → canonical API, findings UI, metrics, CSV/SARIF, comparison, risk
```

**Occurrence identity:** `SBOMComponent.id`, scoped to its SBOM and tenant, with original BOM-Ref/SPDXID and original name/version retained. Both canonical and duplicate occurrence rows are loaded for analysis. This deliberately preserves independently actionable occurrence/VEX contexts; package grouping does not transfer a decision between occurrences. Shared queries and raw caches reuse intelligence across occurrences.

**Package release identity:** valid normalized, version-qualified PURL. Ecosystem-specific case rules, qualifiers, build/version strings and subpaths remain meaningful. npm's semver `v` prefix is normalized; Maven and Go versions retain it. Percent-encoded names are not decoded twice. CPE-only and name-only identities remain unresolved candidates. Conflicting component/PURL/CPE versions are flagged and skipped by source routing. Different declared CPEs, scopes, dependency parents, or conflicting well-formed digests of the same algorithm distinguish groups. Digests of different algorithms do not prove either equality or conflict. Hashes do not independently establish a package-release merge.

Grouping selects a representative deterministically using metadata and document reference. Every occurrence keeps its own metadata. Aggregated license/hash metadata is separately recorded for the explicit normalized export. The original document/relationships remain intact; the normalization report includes the original dependencies and the derived reference mapping/graph. Duplicate document-scoped references are rejected, supplementing existing validation.

**Finding identity:** `(analysis_run_id, resolved component occurrence ID, canonical vulnerability ID)`. Different occurrences, versions, SBOMs, tenants, and runs remain distinct. Repeated observations of the same occurrence/vulnerability are reconciled. Legacy ID-less observations remain unresolved rather than being joined by CPE or display name. An exact repeated observation can be suppressed without inferring component equivalence.

A uniquely verified CVE alias canonicalizes an advisory. An advisory spanning multiple CVEs does not bridge those CVEs; conflicting alias claims retain the advisory identity. Selection and evidence ordering are independent of provider completion order and reconciliation is idempotent.

## Provider mapping, ownership, and caches

- Provider inputs now contain stored component ID, SBOM ID, tenant ID, source reference, original display metadata, normalized PURL/ecosystem and matching evidence.
- NVD observations retain those IDs. A single CPE/CVE intelligence result fans out to all corresponding selected input components, with applicability evaluation before emitting findings. Mirror and legacy injected-mirror paths retain occurrence context too.
- OSV querybatch maintains indexed correspondence across batches and per-query pagination. Hydration occurs once per advisory, followed by normalization for each originating component. Advisory `affected[0]` is never used to reconstruct the queried component.
- Package matching constrains evidence and fixes to the matching `affected` blocks. Explicit versions and supported ranges reject contradictions; full raw advisory evidence is retained separately. Semver comparisons use `semantic-version`; Python uses `packaging`; simple numeric Maven bounds are comparable. Other range dialects retain the authoritative version-qualified OSV query as their applicability evidence instead of using an invented ordering.
- Both fallback and cached replay follow equivalent mapping rules. Duplicate PURLs reuse intelligence while retaining every occurrence. Incomplete batches, pagination failures, and failed hydration are not cached as negative results. Missing queries can retry individually.
- GHSA queries use full Maven/npm/Go package coordinates, preserve original component IDs, evaluate package/version applicability against query coordinates, and retain advisory aliases.
- Shared cache payloads contain provider intelligence, not tenant-specific component IDs. IDs are rebound on replay from the current authorized inputs.
- Persistence validates component membership against the selected SBOM's loaded rows before reconciliation. Ambiguous PURL/name-version candidates return unresolved; CPE alone cannot resolve an occurrence. Supplied conflicting IDs do not fall back to another occurrence. Existing-run ownership is checked before persistence. Re-analysis with known IDs does not rewrite component rows from enriched input projections.

## CVSS, severity, and risk

Dependencies: pinned `cvss==3.6`; `semantic-version==2.10.0` is explicitly declared (already present in the requirements lock).

A selected assessment contains score, full vector, version, provider, assessment type, and original evidence. Numeric values must be finite and within `[0,10]`; booleans are rejected. Full CVSS 3.0/3.1/4.0 vectors are validated/calculated with the CVSS library. Declared v2 vectors remain supported when explicitly versioned. Malformed, unsupported, ambiguous stripped vectors, version conflicts, and numeric/vector discrepancies do not produce a measured canonical score. Valid vector-only OSV ratings can produce scores. Missing trustworthy scores remain NULL.

Selection uses source authority and version policy, not maximum magnitude: applicable NVD assessments for CVEs, then GitHub, then OSV; within a provider use CVSS 3.1, 3.0, 4.0, then 2.0 for report comparability. NVD primary/NVD-authored assessments are preferred within NVD. Original alternatives remain in `provider_raw` and source observations. Numeric score/vector/version are selected atomically. Canonical severity follows the selected numeric assessment; without one, deterministic provider classification is used. Conflicting source classifications or scores trigger a disagreement indicator.

The approved formula and risk thresholds are unchanged:

`risk = cvss_input × (1 + 5 × epss_probability) × (2 if in_kev else 1)`

Risk runs once per canonical finding. The existing severity-derived input remains available when unscored; API/UI/risk detail explicitly label it estimated and keep measured `score` NULL. EPSS probability and percentile are separate fields.

## Schema, persistence, historical data

Migration: `078_finding_reconciliation` (development only).

- Adds nullable JSON `analysis_finding.evidence_json` for source observations, selected CVSS provenance, disagreement, original reference/PURL, and resolution status.
- Adds nullable `reconciliation_key` (SHA-256 of component ID and canonical vulnerability ID).
- Replaces `uq_analysis_finding_run_vuln_cpe` with unique `(analysis_run_id, reconciliation_key)`.
- Historical keys stay NULL; no historic findings are rewritten or automatically backfilled. Existing foreign keys and tenant enforcement remain in place, supplemented by application-level run/SBOM/component ownership checks.
- JSON evidence is queryable with PostgreSQL JSON operations and is served directly in findings APIs. The existing raw run report also retains structured observations. A separate global package table or observation table is unnecessary for this implementation.
- Historical findings with missing evidence remain readable. Read reconciliation keeps source classifications as available; historically unresolved component observations are not silently reassigned.

## UI, workflow, metrics, exports

The existing table retains sorting, filters, pagination, VEX, remediation and source coverage patterns. Each canonical occurrence/vulnerability has one row. Applicable contributing sources appear once; GitHub is labelled GHSA. Expanded details show original ID/reference/PURL, selected CVSS/version/provider/vector, EPSS probability and percentile, KEV/risk, estimated input labels, provider disagreements, all observations, package applicability, fixes, aliases, query trace and source links. Historical absence of detailed evidence is explained explicitly.

VEX matching stays occurrence-specific and supports unambiguous advisory aliases; conflicting alias decisions are not automatically selected. Existing project/name/version remediation records remain compatible, with unambiguous vulnerability aliases and verified alternate display names supported. Remediation remains the application's existing project/package workflow; this patch does not invent an occurrence-specific remediation schema.

Run metrics separately expose total component entries, confidently identified unique package releases, unresolved component entries, raw observations, canonical findings, unique vulnerability identities, scored/unscored counts and CVSS coverage. Run hero displays package/entry distinctions and coverage when available; historical absent metrics are not fabricated. Dashboard authorization, inactive/superseded behavior and latest-run selection remain in the existing scoped implementation; their canonical finding helpers now use the shared reconciliation policy. CSV/SARIF read canonical rows, retain provenance, and CSV avoids a per-finding component lookup. Comparison consumes canonical rows and preserves declared package/artifact/occurrence context; its cache key is versioned so stale pre-policy comparisons are not reused.

## Verified fixture measurements

These are synthetic fixtures, **not post-fix production totals**.

| Fixture | Before | After |
| --- | --- | --- |
| Same Log4j occurrence/CVE from NVD and OSV | 2 provider rows | 1 finding, 2 retained observations, NVD CVSS 10.0 |
| API fixture with Log4j provider overlap plus one unscored CVE | 3 observations | 2 findings / 2 unique vulnerabilities; 1 scored, 1 unscored; 50% coverage |
| Run-15-shaped fixture | 113 observations: 42 scored NVD + 71 unscored OSV (37.17% numeric coverage across raw rows) | 82 findings, 113 retained observations; 74 scored, 8 unscored; 90.24% canonical coverage |

The large fixture intentionally has 31 overlapping component/CVE pairs and eight genuinely unscored canonical findings. Its distribution is controlled test data and does not predict actual production overlap or scoring coverage. Baseline raw-row coverage and corrected canonical coverage have explicitly different denominators.

## Validation

Actual completed checks:

- Broad backend compatibility run: **252 passed**, **8 subtests passed**, **1 deselected** known baseline failure; 331.36 seconds. Scope: the new reconciliation suite plus existing component normalization/deduplication, OSV eligibility/cache, GHSA cache, adapters, persistence/provenance, source errors, risk, NVD, tenant isolation, dashboard scoping, comparison, export and VEX suites.
- Fresh focused verification after the final identity/comparison/range changes: **94 passed**, 112.44 seconds. This repeats affected tests; it is not an additional 94 distinct tests.
- Four additional final regressions: **4 passed**, 47 deselected, 9.10 seconds: literal PURL encoding/RPM case/Go tags, numeric overflow/malformed OSV ratings, occurrence-specific risk aggregation, and persistence of the same CVE/CPE on distinct owned component IDs. The new regression file contains **51 parameterized cases** in total.
- Frontend: **40 tests passed** across six files, including evidence details, filters, selection, match provenance and run/source status rendering.
- TypeScript: `npm exec tsc -- --noEmit` passed.
- Frontend production build: passed with the development placeholder API origin; 47 static pages generated.
- Ruff on changed Python modules/tests: passed. `compileall` and `git diff --check`: passed.
- ESLint on changed frontend files: zero errors; one pre-existing unused `KeyRound` import warning in `RunDetailHero.tsx`.
- PostgreSQL: fresh bootstrap to 078, downgrade to 077 and upgrade to 078 passed on the dedicated migration database. A historical-shaped finding survived the round trip with ID, CVE, score and component display metadata unchanged; both added columns stayed NULL. The new uniqueness constraint and columns were verified through PostgreSQL metadata.
- The initial normalized-export failure was corrected by keeping aggregated metadata separate from stored occurrence metadata and applying it only in explicit normalized exports; its regression passes in the final runs.

Regression coverage includes `test_provider_order_independence_and_duplicate_replay`, `test_multicve_and_conflicting_alias_bridges_do_not_merge_cves`, `test_osv_query_mapping_hydration_and_cache_replay`, `test_osv_partial_responses_do_not_cache_failures_as_clean`, `test_osv_querybatch_pagination_keeps_original_indices`, `test_github_namespace_queries_and_per_occurrence_alias_mapping`, `test_nvd_intelligence_fans_out_to_every_original_component`, `test_persistence_api_evidence_metrics_vex_and_pagination`, `test_upsert_preserves_occurrences_ids_and_ambiguous_ownership`, `test_analysis_loads_only_selected_sbom_and_preserves_original_ids`, CVSS boundary/vector cases, SPDX relationship preservation, workflow aliases, and the Run-15-shaped fixture. Existing suites exercise risk/KEV, tenant isolation, dashboard scope, VEX, CSV/SARIF and comparison.

The pre-existing `test_reconcile_script_updates_stale_cached_counts` fails because the maintenance subprocess reads tenant-owned models without a verified tenant context. This was reproduced before editing; tenant authorization was not weakened to make it pass. It is excluded from the final compatibility run and remains an operational maintenance-script issue.

The first frontend production build compiled but prerendering failed because `NEXT_PUBLIC_API_URL` was unset. The verified build uses `NEXT_PUBLIC_API_URL=http://127.0.0.1:59999`, a development placeholder, without editing environment files or pointing build-time calls at production.

## Files changed

- Normalization: `app/normalization/{component_normalizer,component_deduplicator,purl_normalizer,version_normalizer}.py`.
- Providers/reconciliation: `app/analysis.py`, `app/sources/{component_observation,cvss_assessment,reconciliation,dedupe,nvd,osv_fallback,routing,severity}.py`, `app/services/nvd_enrichment_service.py`.
- Persistence/API/metrics: `app/models.py`, `app/schemas.py`, `app/services/{sbom_service,analysis_orchestrator,analysis_service,finding_metrics,risk_score,compare_service}.py`, `app/routers/{runs,analysis,sbom_versions}.py`, migration `078_finding_reconciliation.py`.
- UI: `frontend/src/types/index.ts`, `frontend/src/components/analysis/{FindingsTable,RunDetailHero}.tsx`, new `FindingsTable.evidence.test.tsx`.
- Tests: new `tests/test_component_finding_reconciliation.py`; corrected identity/coherent-rating fixtures in `test_component_deduplication.py`, `test_analysis_finding_persistence_regression.py`, `test_sources_adapters.py`, and `tests/sources/test_nvd_applicability.py`.
- Dependencies: `pyproject.toml`, `requirements.txt`; this report.

## Remaining limitations and deployment impact

- SPDX 3.0 remains explicitly unsupported by the existing schema/semantic validation pipeline. This patch preserves that rejection rather than pretending its JSON-LD element IDs are SPDX 2.x IDs. Supported CycloneDX and SPDX 2.x paths are covered.
- Package identity without reliable version-qualified metadata remains unresolved. No global package cross-SBOM uniqueness is introduced.
- Original artifacts are not downloaded to verify hash contents. Declared digest conflicts only prevent merges; digest equality is not used as an independent package-release identity.
- Complex distro/Maven/custom range dialects rely on the authoritative version-qualified OSV response; unsupported GHSA local range forms retain the existing conservative rejection behavior.
- Historical missing component IDs cannot be reconstructed safely without evidence. They stay unresolved; detailed missing observations cannot be recreated retrospectively.
- All original occurrences are now analyzed independently. Finding totals can legitimately increase where an old package group hid separate occurrences, even while provider-duplicate totals decrease. Validate representative customer documents in staging before rollout.
- Evidence JSON and raw reports grow with provider detail. No new provider call per finding is introduced. Monitor large-run payload size and PostgreSQL storage; pagination still follows the existing in-memory canonical reader pattern.
- GitHub 401 errors require an operator to correct the configured credential separately. No authentication bypass or TLS workaround is provided.
- The full repository suite is not claimed; the recorded scope covers the affected pipeline and its principal integrations.

## Safe deployment and rollback plan — requires separate approval

1. Review the branch and migration, back up PostgreSQL and raw run reports, and deploy first to an isolated staging environment.
2. Build backend, worker and beat images from the same reviewed revision with the pinned dependencies; build the frontend using the real approved API origin.
3. In the approved deployment window, coordinate consumers and apply migration 078 before starting application code that queries its new columns. Use the existing server deployment procedure; do not run a schema-changing application against revision 077.
4. Create a fresh explicitly approved validation run on a designated staging/test SBOM. Inspect component ownership, evidence counts, CVSS, VEX, remediation, exports, coverage errors and dashboard scope. Do not overwrite Run 15 or automatically reprocess historical runs.
5. Promote only after staging results meet the approved acceptance criteria.

Rollback: restore matching application images and a compatible database backup when required. A downgrade to 077 is tested on an empty development database, but can correctly fail if new findings have the same `(run, vulnerability, CPE)` on distinct components. Do not delete findings to force the old constraint. JSON columns are removed by downgrade, so preserve raw reports/backups first. Prefer coordinated image/database restoration when the old constraint cannot represent new data.

### Read-only verification commands after approved deployment

Run only in the approved environment, with an authorized token and the ID of the **new** validation run supplied by the operator. These commands do not deploy or start analysis.

```bash
cd /home/hcluser1/sbom_native/sbom
git branch --show-current
git rev-parse HEAD
docker exec sbom-native-backend-1 python -c "from importlib.metadata import version; print(version('cvss')); print(version('semantic-version'))"
curl --fail --silent --show-error --header "Authorization: Bearer $SBOM_VERIFY_TOKEN" "$SBOM_API_ORIGIN/api/runs/$NEW_RUN_ID"
curl --fail --silent --show-error --header "Authorization: Bearer $SBOM_VERIFY_TOKEN" "$SBOM_API_ORIGIN/api/runs/$NEW_RUN_ID/findings-enriched?page_size=100"
```

Use the normal trusted CA configuration for HTTPS; never disable verification. Database checks below use the container's configured PostgreSQL role without displaying credentials; replace `12345` with the approved new validation run ID.

```bash
docker exec -i sbom-native-postgres-1 sh -c 'psql -U "$POSTGRES_USER" -d sbom_analyser_native -v ON_ERROR_STOP=1' <<'SQL'
SELECT version_num FROM alembic_version;
SELECT count(*) AS findings, count(score) AS scored,
       count(*) FILTER (WHERE score IS NULL) AS unscored,
       count(DISTINCT vuln_id) AS unique_vulnerabilities,
       sum(jsonb_array_length(COALESCE(evidence_json::jsonb->'source_observations', '[]'::jsonb))) AS observations
FROM analysis_finding WHERE analysis_run_id = 12345;
SELECT component_id, vuln_id, count(*) FROM analysis_finding
WHERE analysis_run_id = 12345 AND component_id IS NOT NULL
GROUP BY component_id,vuln_id HAVING count(*) > 1;
SELECT f.id FROM analysis_finding f
JOIN analysis_run r ON r.id=f.analysis_run_id
JOIN sbom_component c ON c.id=f.component_id
WHERE r.id=12345 AND (c.sbom_id<>r.sbom_id OR c.tenant_id<>r.tenant_id OR f.tenant_id<>r.tenant_id);
SQL
```

The last two queries should return no rows. Inspect provider errors separately from the finding outcome and verify the returned run's SBOM ID matches the selected document.

### Reproduce development tests

A separate container `sbom-reconciliation-test-postgres` was created on `127.0.0.1:55439`, with database `sbom_analyser_test`; it does not use the production database or volume. A separate `sbom_reconciliation_migration_test` database was used for migration checks. Recreate the disposable container with:

```bash
docker run -d --name sbom-reconciliation-test-postgres -e POSTGRES_USER=sbom -e POSTGRES_PASSWORD=sbom -e POSTGRES_DB=sbom_analyser_test -p 127.0.0.1:55439:5432 postgres:16
.venv/bin/python -m pytest tests/test_component_finding_reconciliation.py -q
cd frontend
npm test -- src/components/analysis/FindingsTable.evidence.test.tsx
npm exec tsc -- --noEmit
NEXT_PUBLIC_API_URL=http://127.0.0.1:59999 npm run build
```

For cleanup, remove only this explicitly named disposable test container after tests finish: `docker rm -f sbom-reconciliation-test-postgres`.

## References

- [OSV querybatch ordering and per-query pagination](https://google.github.io/osv.dev/post-v1-querybatch/).
- [Red Hat Product Security CVSS implementation](https://github.com/RedHatProductSecurity/cvss).
