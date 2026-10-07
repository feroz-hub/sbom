# SBOM quality scoring — Phase 2

Phase 2 extends the pushed Phase 1 implementation at `6762d55` on
`feat/sbom-auto-repair-phase2`, based on `origin/feat/native-user-management`.
It is deterministic and advisory. **Quality is data completeness/integrity, not
vulnerability severity. Low quality never rejects an otherwise valid upload.**
AI, registry/network lookups, license inference, package upgrades and dashboard
aggregation are outside this phase.

## Architecture and reused extension points

Quality validation status follows the canonical full error count. Display truncation
is separately exposed; the existing stricter repair approval completeness gate
remains unchanged. A limited non-blocking report does not make a valid upload fail.

The existing parser, vendored schemas, complete validation pipeline, normalized
reference discovery, repair classifier, restricted proposal/diff operations,
bounded copy-on-write engine and approval service remain authoritative. Quality
uses one document index per assessment, cached validators derived from each
supported schema, and the existing classifier to report repair availability.
The existing strict JSON transformation preflight is shared by repair and
quality; ambiguous duplicate keys/non-JSON numbers are never authoritative.

`app/services/sbom/quality/` contains models, inspection/indexes, engine,
comparison and snapshot orchestration. Platform weights/grades are defined in
`app/core/sbom_quality_policy.py` and validated through existing settings.
The rule registry and classifier are extended, rather than replaced. The
validation pipeline still controls upload and candidate approval.

## Formula, dimensions and eligibility

`overall = round(sum(dimension_score * weight / 100), 1)`; all scores remain
within 0–100. UI summaries round to whole numbers; comparisons retain one decimal.
Default weights total exactly 100%. Invalid/negative/non-finite configurations
are rejected. Scores and findings are deterministic for the same artifact,
engine version (`2.0.0`), schema and policy; calculation timestamps vary. Policy defaults are validated into the same numeric representation used on reconstruction, so equivalent integer/float inputs retain the same fingerprint. The resolved Auto-Repair enabled flag is included because it changes finding repairability, although it does not change numeric scores. A setting change therefore appends new evidence rather than returning stale repair classifications.

| Code | Dimension | Weight | Calculation |
|---|---|---:|---|
| QD-01 | Schema Compliance | 20% | 100 minus 25 per blocking ingress/detection/schema error, clamped at zero; semantic issues affect the relevant integrity dimensions |
| QD-02 | Identifier Integrity | 15% | Percentage of declaration, present-identifier and dependency-reference checks without duplicate/invalid/unresolved/inconsistent identity defects; canonical formatting adds an explicit check |
| QD-03 | Dependency Integrity | 15% | Percentage of node/edge checks without invalid, dangling, ambiguous, duplicate or prohibited self-reference defects; redundant empty records add an explicit check |
| QD-04 | Component Completeness | 15% | Earned useful-field points / applicable points: name 40, type 20, bom-ref 15, software version 15; supplier/manufacturer 10 for application/device/firmware/OS where supported |
| QD-05 | PURL Coverage | 10% | Valid PURLs / eligible components |
| QD-06 | CPE Coverage | 5% | Valid present CPEs / eligible components |
| QD-07 | License Completeness | 7.5% | Components with non-empty schema-valid license choices / eligible components; SPDX ID, name and expression counts are exposed |
| QD-08 | Hash Coverage | 5% | Components with non-empty schema-valid hashes and supported algorithms/lengths / eligible components |
| QD-09 | Metadata Completeness | 7.5% | Known useful metadata points / 100: serialNumber 10, document version 10, timestamp 25, metadata.component 25, tools 20, producer 10; invalid declared supported lifecycles deduct 10 |

Software eligibility covers application, framework, library, container,
platform, operating-system, device-driver and firmware. PURL coverage also
includes any component explicitly declaring a PURL. Pure device, data, file
and cryptographic assets without a PURL are not penalized for PURL absence.
CPE eligibility is application, operating-system, device, firmware and
device-driver, plus any component already declaring a CPE. Libraries without
CPEs are not penalized. These are documented platform heuristics, not claims
that every eligible component must have an identifier.

Licenses apply to software, data and ML models, or components declaring licenses.
Hashes apply to software, files and ML models, or components declaring hashes.
Missing supplier/version/identifier/license/hash metadata is advisory when the
schema permits absence; no unknown value is inferred. Components, nested
components, metadata.component and tool components are assessed. Services
participate in reference integrity, but not component coverage.

An empty component inventory scores zero for Component Completeness and receives
a manual advisory finding; empty coverage dimensions still remain Not applicable.

Coverage metrics expose eligible, valid, missing, invalid and not_applicable
counts plus coverage_percentage. Hash metrics additionally expose components
with/without hashes, invalid values and unsupported algorithms. Zero eligible
components receive a neutral 100 dimension score and **Not applicable** in the
UI; this does not claim that identifier coverage exists. An absent dependency
graph is not penalized by inventing an expected graph. Legitimate cycles remain
under the existing validator's warning policy; no cycle edge is removed.

Schema 1.4, 1.5 and 1.6 come from the application's detection support. Field
validity and manufacturer/lifecycle availability come from each vendored schema;
no version is upgraded and no unsupported field is inserted.

## Grades and findings

Defaults: Excellent >=90, Good >=80, Fair >=70, Poor >=50, Critical Quality <50.
Grades are presentation labels; the numeric score is authoritative. Finding
severity is **BLOCKING / MAJOR / MINOR / INFORMATIONAL**, separate from
vulnerability severity. Each finding includes dimension, path, explanation,
recommended action, estimated dimension-point impact and repair classification.
The impact explains the dimension deduction, not a promised overall increase.

Both PURL/component version conflicts and unescaped literal CPE/component
version conflicts are manual. Name differences may be aliases and are
informational, without a guessed identity change. Escaped CPE identity
reconciliation is deliberately unsupported.

Displayed findings are capped at 500; score calculations include all components.
To avoid repeated graph scans for large documents, classifier proposals are
bounded to 100 diagnostic assessments. Additional potentially repairable
findings set `repairability_assessed=false` and show **Analysis required**.
Running the existing repair analysis remains the authority for available repairs.

## Deterministic repair extensions

The original five rules remain. Three rules extend the registry:

- **PURL canonicalization** uses the installed `packageurl-python` parser:
  ecosystem-defined casing, percent encoding, qualifier ordering and valid
  subpath normalization. Duplicate/blank qualifiers, malformed/non-UTF8 escapes
  and `..` subpaths stay manual rather than letting the parser lose identity data.
- **CPE normalization** trims whitespace only when the existing CPE 2.3 grammar
  already recognizes the complete identity. It never invents or changes fields.
- **Dependency cleanup** removes only exact self-edges prohibited by the existing
  integrity validator and redundant empty dependency records with no extra
  metadata. Identical nodes/edges still use Phase 1 deduplication. Other records
  and all other graph edges are retained.

The existing dangling-reference rule adds canonical PURL/CPE matching after its
Phase 1 exact matching tiers. Only a unique existing declaration can win;
ambiguous identities remain suggested/manual. Each rule advertises ID, name,
format, supported schema versions, classification, affected dimensions and safe
status. Metadata describes an eligible proposal; the classifier still decides
per-issue repairability.

Quality-only deterministic normalization can be offered for a valid SBOM, but
requires the same explicit repair execution, candidate review, full revalidation
and hash-bound approval. Missing facts do not become repair proposals.

## Snapshots, API and security

**No new table or migration is required.** Immutable snapshots reuse existing
append-only tenant-owned `SBOMValidationSessionEvent` records with type
`SBOM_QUALITY_CALCULATED`; their JSON metadata holds artifact role/hash,
configuration hash, engine version, full scoring policy, assessment and optional SBOM/job IDs. The retained policy includes weights, grade thresholds and limits; its normalized fingerprint is verified before supplied assessment persistence.
Roles are ORIGINAL, DRAFT, REPAIR_SOURCE, CANDIDATE and ACCEPTED. ORM evidence
updates are prohibited; new artifact/policy assessments append rows. Reads
reuse matching snapshots under the existing session lock. Deletion uses the
existing workspace cascade and retained-artifact cleanup policy.

Repair jobs retain `quality.before`, `quality.after`, `improvement`, `comparable`
and changed dimensions in the immutable report. Both scores are calculated from
actual source/candidate bytes with the completed validation reports. Rolled-back
changes do not affect the retained after-score. Comparisons require the same
engine version, schema and configuration; they never estimate proposed gains.

- `GET /api/sbom-validation-sessions/{session_id}/quality`: enabled, current
  assessment and immutable history; existing `sbom:repair:read` permission.
- `GET /api/sboms/{sbom_id}/quality`: enabled and actual accepted-artifact
  assessment; existing `sbom:read` permission. Historical SBOMs reuse the existing
  workspace backfill path.
- Existing repair analyze/status/report APIs expose rule metadata, the separate
  quality issue count and candidate-specific comparison. No redundant repair API
  or scoring authorization model is introduced.

Both read routes verify tenant access before disabled-feature handling. Foreign
IDs return the established 404 without scores, paths or artifact metadata.
Hash checks reject mismatched assessments; candidates still require Phase 1
source/hash/role/assignment checks and full validation. Signed documents are
scored read-only but never repaired. Unsupported formats get **Not assessed**,
not a misleading zero-quality verdict.

Summary-only structured events are SBOM_QUALITY_CALCULATED,
SBOM_QUALITY_RECALCULATED and SBOM_QUALITY_IMPROVED, with existing request,
tenant/user, session/SBOM/job, hash, score and engine correlation. No per-component
payload, credential or SBOM content is logged. Existing audit persistence is
reused. Quality data is never sent to AI or external services.

## UI and configuration

Workspace and accepted SBOM details show score/grade, validation status,
dimensions, expandable findings and hash/version evidence. Repair review shows
actual before/after scores and changed dimensions, with stale-draft warnings.
Repair, approval and manual edits invalidate quality queries automatically.
The main dashboard and tenant-customizable formula UI are unchanged.

`SBOM_QUALITY_ENABLED=true`; optional JSON environment overrides
`SBOM_QUALITY_WEIGHTS` and `SBOM_QUALITY_THRESHOLDS` use the defaults above.
Phase 1 repair settings/passes/confidence remain authoritative. Platform defaults
prepare future tenant policy work without introducing per-tenant formula editing.

## Verification commands

```bash
.venv/bin/python -m pytest -q tests/test_sbom_quality.py tests/test_sbom_quality_integration.py \
  tests/test_sbom_auto_repair.py tests/test_sbom_repair_release.py \
  tests/test_sbom_repair_migration.py tests/validation/test_errors.py tests/validation/test_release_truncation.py
.venv/bin/python -m ruff check app/core/sbom_quality_policy.py app/parsing/strict_json.py \
  app/services/sbom/quality app/services/sbom/repair tests/test_sbom_quality*.py
.venv/bin/python -m pytest -q tests/validation tests/test_validation_repair_workspace.py \
  tests/test_sbom_upload_validation_persisted.py tests/test_sbom_revalidate_endpoint.py \
  tests/test_sbom_upload_version_lineage.py tests/test_sbom_delete_service.py
cd frontend
npm test -- --maxWorkers=2 --testTimeout=15000
npx tsc --noEmit
npm run lint
npm run build -- --webpack
cd ..
REPAIR_E2E_NODE=/path/to/node PLAYWRIGHT_BROWSERS_PATH=/path/to/browsers \
  .venv/bin/python scripts/run_sbom_repair_e2e.py
```

Run backend suites against a dedicated disposable test database, sequentially within each database: fixtures reset shared tables and parallel suites must use different databases. E2E uses disposable PostgreSQL, native login, BFF and real browsers. No production
migration/deployment, commit or push is part of this implementation. Existing
Alembic head remains `074_sbom_repair_jobs`.

## Limitations and deferred work

CycloneDX JSON 1.4–1.6 only; XML/SPDX quality and repair require manual handling.
Signed artifacts are never rewritten. Ambiguous identifiers and missing facts
remain manual. CPE escaping/identity inference, external license-expression
interpretation beyond the current schema, service-specific completeness,
dashboard aggregates, quality filters, configurable tenant formulas and AI
repair are deferred. Quality eligibility is advisory and may need future
producer/type-specific refinement. Engine versions/config hashes preserve the
meaning of historical scores when defaults evolve.

Final verification and performance evidence follow.

Integration review found that adding both quality cards to the fixed-height
workspace could collapse its existing editor. The quality/repair review area is
now independently scrollable and bounded to 40vh; the existing stale-draft E2E
scenario exercises editing after a completed repair, with quality still present.

## Implementation-stage verification evidence

| Check | Passed | Failed | Skipped | Notes |
|---|---:|---:|---:|---|
| Consolidated backend quality/repair/security/migration | 142 | 0 | 0 | 62 new Phase 2 checks plus the existing 80 Phase 1 checks; isolated PostgreSQL |
| Broader backend validation/upload/workspace/deletion | 238 | 0 | 0 | 15 integration/benchmark cases deselected by repository defaults; independent PostgreSQL |
| Full frontend | 1,285 | 0 | 0 | 163 test files |
| Browser E2E | 19 | 0 | 0 | Existing 15 scenarios plus four Phase 2 scenarios, real native login/BFF/API |
| Migration roundtrip | 1 | 0 | 0 | Included in the consolidated backend count; disposable PostgreSQL only |

Backend suites reported zero execution errors. The two backend totals overlap and should not be added as a unique-test count. No unresolved PHASE_2_REGRESSION was found.

Main and E2E TypeScript checks passed. All 24 changed Python files passed Ruff.
Frontend lint has zero errors and 52 existing warnings; the production Webpack
build passed with 45 static pages. `git diff --check` passed.

Full Python lint still reports 43 unrelated existing errors. Import architecture
checks still report two existing broken contracts, reproduced on clean integration
HEAD; the quality policy lives in core to avoid introducing a new dependency.
The full 3,500+ backend application suite was not rerun in this phase. Its prior
Phase 1 evidence remains historical: 3,478 passed / 60 baseline failures / 10
skipped. This implementation does not claim a green full backend application suite.

Defects found and resolved during integration:

- Quality/repair cards could collapse the fixed-height workspace editor. Bound
  the review region and retain its independent scrolling; the existing stale-edit
  browser scenario and mobile overflow checks now pass.
- Quality-improvement structured logs lacked the session correlation field.
  Added session ID and verified summary-only audit records in integration tests.
- A truncated but non-blocking validation report could make the new quality UI
  show FAILED for a valid artifact. Use the canonical error count and expose
  truncation separately, preserving Phase 1's stricter candidate approval policy.
- Canonical PURL/CPE aliases could let a literal identifier match choose one of
  several semantically identical declarations. Detect canonical ambiguity before
  choosing a literal non-bom-ref match; regression tests keep the edge unresolved.
- Updated the existing workspace-history assertion for the newly appended quality
  audit event and verified its original artifact hash.

Early overlapping tests against the same disposable database caused reset/deadlock
errors (TEST_ENVIRONMENT_FAILURE); final runs use independent databases. An
optional faulthandler-instrumented performance diagnostic exited 139 in the local
interpreter shim (ENVIRONMENT_FAILURE); it is not counted as a passing check.
Normal uninstrumented performance runs completed both fixture sizes.

## Performance observations

| Components | Artifact bytes | Quality calculation | Repair analysis | Candidate quality recalculation |
|---:|---:|---:|---:|---:|
| 1,001 | 346,152 | 0.627 s | 2.029 s | 0.488 s |
| 4,001 | 1,399,152 | 2.477 s | 65.729 s | 3.652 s |

Each fixture contains one deterministic PURL normalization and a real changed
candidate hash. Quality timing reuses the already completed validation report,
as in the upload/repair integration. Repair analysis includes full validation.
These are approximate local observations, not SLAs. Profiling located the large
repair-analysis cost in existing `jsonschema` object-array `uniqueItems` pairwise
comparisons before quality scoring. The shared quality index scales approximately
with inventory size; no existing validator is weakened or rewritten to improve
these measurements. Some existing semantic checks omit nested/metadata identifier
cases: quality can report these advisory defects while canonical validation PASS
remains authoritative.

## File inventory

**Added (16):**

- `app/core/sbom_quality_policy.py`
- `app/parsing/strict_json.py`
- `app/services/sbom/quality/__init__.py`
- `app/services/sbom/quality/engine.py`
- `app/services/sbom/quality/inspection.py`
- `app/services/sbom/quality/models.py`
- `app/services/sbom/quality/policy.py`
- `app/services/sbom/quality/service.py`
- `app/services/sbom/repair/rules/dependency_cleanup.py`
- `app/services/sbom/repair/rules/identifier_canonicalization.py`
- `docs/sbom-quality-scoring.md`
- `frontend/src/components/sboms/SbomQualityPanel.test.tsx`
- `frontend/src/components/sboms/SbomQualityPanel.tsx`
- `frontend/src/types/sbomQuality.ts`
- `tests/test_sbom_quality.py`
- `tests/test_sbom_quality_integration.py`

**Modified (22):**

- `.env.example`
- `app/models.py`
- `app/routers/sbom_auto_repair.py`
- `app/routers/sboms_crud.py`
- `app/services/sbom/repair/classifier.py`
- `app/services/sbom/repair/engine.py`
- `app/services/sbom/repair/registry.py`
- `app/services/sbom/repair/rules/base.py`
- `app/services/sbom/repair/rules/dangling_dependency_ref.py`
- `app/services/sbom/repair/service.py`
- `app/services/validation_repair_service.py`
- `app/settings.py`
- `docs/sbom-auto-repair.md`
- `frontend/e2e/sbom-repair.spec.ts`
- `frontend/src/app/sboms/[id]/page.tsx`
- `frontend/src/components/sboms/SbomAutoRepairPanel.test.tsx`
- `frontend/src/components/sboms/SbomAutoRepairPanel.tsx`
- `frontend/src/components/sboms/ValidationRepairWorkspace.test.tsx`
- `frontend/src/components/sboms/ValidationRepairWorkspace.tsx`
- `frontend/src/lib/api.ts`
- `frontend/src/types/sbomAutoRepair.ts`
- `tests/test_validation_repair_workspace.py`

## Final release validation

See [Phase 2 release validation](sbom-auto-repair-phase2-release-validation.md) for the complete application-suite baseline comparison, release guards, browser coverage and stable performance profiling. Earlier results above describe implementation-stage checks, not the final release decision.

## Phase 3: native SPDX JSON

[SPDX Phase 3](sbom-spdx-auto-repair.md) extends the same engine with a native
SPDX 2.2/2.3 evaluator, the same weights/thresholds and format-specific eligibility.
QD-03 is displayed as Relationship Integrity, QD-04 as Package / File Completeness
and QD-08 as Checksum Coverage. Quality remains advisory and separate from
validation and vulnerabilities. SPDX evidence uses engine 3.0.0; CycloneDX retains
engine 2.0.0 and historical evidence is not reinterpreted. Formats share a 0–100
indicator, not a guarantee of equivalent semantic completeness.

Final application release validation: [Phase 3 release report](sbom-auto-repair-phase3-release-validation.md).
The configured backend suite has 3,697 passes, 58 clean-base-confirmed failures
and 10 skips; no Phase 3 regression remains. Browser E2E: 27 passes; consolidated
repair/quality/security/migration checks: 297 passes. The release-validation task
performed no commit or deployment; commit preparation is a subsequent authorized task.
