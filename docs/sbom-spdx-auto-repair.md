# SPDX JSON quality and deterministic auto-repair — Phase 3

## Architecture and existing support

Phase 3 branches from the merged Phase 2 integration state `4f32088` (PR #34),
not from an unreviewed working tree. It extends `QualityEngine`, `RepairEngine`,
their shared classifier/registry, existing validation sessions, immutable repair
jobs, candidate storage, restricted JSON patches, hash-bound approval, audit and
Quality/Repair UI. It does not convert an uploaded SPDX artifact to CycloneDX.

Existing components reused:

- `app/parsing/spdx.py`: package extraction, external references, supplier,
  license and checksum projection used by ordinary processing.
- `app/validation/stages/detect.py`: capped JSON parsing and SPDX version detection.
- Vendored SPDX 2.2/2.3 JSON schemas and the existing schema validator.
- `semantic_spdx.py`: document metadata, SPDX identifiers, license-expression
  library, checksum algorithms and DESCRIBES intent checks.
- `normalize_spdx` / integrity validation: native relationship types and source/
  target paths, declared IDs, external document declarations and graph checks.
- `sbom_conversion_service.py`: an independent SPDX-to-CycloneDX conversion
  workflow, unchanged by Phase 3.
- Existing upload, source persistence, tenant access, role permissions, session
  locks, audit, download, approval/rejection and deletion flows.

`quality/spdx_inspection.py` builds shared SPDX indexes: document/package/file/
snippet IDs, external-document IDs, package PURL/CPE/name-version aliases and
relationship/documentDescribes references and valid extracted-license IDs.
Read-only projections and repair diagnostics are cached within one analysis
using a context-local scope, reset on exit; independently called rules always
rebuild their index. No cache crosses artifacts, requests or tenant contexts. `quality/spdx_evaluator.py` is a
format evaluator called by the existing engine, not a parallel quality engine.
SPDX proposals use the existing `RepairRule` interface and registry.

## Supported formats

| Format | Quality | Auto-Repair |
|---|---|---|
| CycloneDX JSON 1.4–1.6 | Yes, engine 2.0.0 | Yes |
| SPDX JSON 2.2 / 2.3 | Yes, engine 3.0.0 | Yes |
| CycloneDX XML | Not assessed | Unsupported |
| SPDX Tag/Value | Not assessed | Unsupported |
| SPDX YAML, RDF/XML, 3.x JSON-LD | Not assessed | Unsupported |
| AI-assisted repair | Disabled | Disabled |

SPDX version strings in documents remain `SPDX-2.2` / `SPDX-2.3`; new quality
and repair responses expose the normalized version `2.2` / `2.3`. Rules advertise
their exact format/version compatibility and cannot execute across formats.
The vendored 2.2 schema uses `PACKAGE_MANAGER`, while 2.3 uses `PACKAGE-MANAGER`.
The external-reference adapter respects this declared-version distinction.

## Quality policy

Quality is an advisory data-quality indicator, independent of validation and
vulnerability severity. A valid incomplete SBOM can be accepted with low quality;
a high quality score cannot authorize an invalid candidate. Scores across formats
share a numeric range but are not claims of equivalent semantic completeness.

| Code | SPDX dimension | Weight | Calculation |
|---|---|---:|---|
| QD-01 | Schema Compliance | 20% | 100 minus 25 per blocking ingress/detect/schema issue, floored at zero |
| QD-02 | Identifier Integrity | 15% | Valid unique local IDs, external identifiers and uniquely resolved references; deductions for duplicate/noncanonical/inconsistent identities |
| QD-03 | Relationship Integrity | 15% | Reference/type integrity, exact duplicates and application-prohibited self-relations; retains relationship type/direction |
| QD-04 | Package / File Completeness | 15% | Weighted useful metadata, validated against declared-version field schemas |
| QD-05 | PURL Coverage | 10% | Packages with valid PURL externalRefs divided by eligible packages |
| QD-06 | CPE Coverage | 5% | Applicable packages with valid CPE 2.3 externalRefs divided by eligible packages |
| QD-07 | License Completeness | 7.5% | Complete valid declared/concluded/file license assertions divided by assessed assertions |
| QD-08 | Checksum Coverage | 5% | Applicable package/file records with valid supported checksums divided by eligible records |
| QD-09 | Metadata Completeness | 7.5% | Document version, data license, ID, name, namespace, creationInfo and describes intent |

Overall = sum(dimension score × configured weight / 100), rounded to one decimal.
Weights total 100%; every score stays within 0–100. Existing platform defaults,
configuration canonicalization, thresholds and policy fingerprints are reused:
Excellent >=90, Good >=80, Fair >=70, Poor >=50, Critical Quality below 50.

Package completeness weights: name 40, SPDXID 20, versionInfo 15,
downloadLocation 15, supplier 10. File completeness assesses fileName 40 and
SPDXID 20; package-only fields do not penalize files. Missing or NOASSERTION
metadata is not counted as complete producer evidence.

PURL eligibility includes software packages unless primaryPackagePurpose is
DOCUMENT/OTHER; explicitly supplied supported PURLs are always assessed. Files
without a PURL are not penalized. CPE eligibility includes APPLICATION,
OPERATING-SYSTEM, FIRMWARE and DEVICE packages, or an explicitly supplied CPE 2.3.
Absent package purpose does not make CPE mandatory. Package/file checksums are
applicable except DOCUMENT/OTHER packages without any supplied checksum.
Coverage exposes eligible, valid, missing, invalid and not-applicable counts.

`NONE` is an explicit valid license assertion and receives completeness credit.
`NOASSERTION` is valid SPDX syntax but supplies no asserted license information,
so reduces completeness. Neither value is rewritten. License expressions reuse
`license-expression`, including proper WITH-exception context. Local LicenseRef
quality credit requires matching extracted license information. External license
assertions cannot be verified locally and remain manual. Unknown licenses never
become inferred identifiers.

Checksum quality verifies known algorithm/encoding/length and tracks absent,
invalid and unsupported entries. No checksum is calculated from package content.
File records participate in identifier, metadata, checksum and license scoring;
snippet IDs participate in reference integrity, but detailed snippet-body scoring
and aggressive file/snippet repair are not implemented.

## Deterministic repair rules

| Rule | Safe operation | Manual boundary |
|---|---|---|
| `SPDX_IDENTIFIER` | Trim a valid unreferenced local ID; assign a stable path-derived suffix to an unreferenced duplicate | Any ambiguous/reference-bearing ID is retained; no package merging |
| `SPDX_REFERENCE` | Resolve an exact unique existing local ID, PURL, CPE, name@version or canonical external identity | Multiple matches, unknown names/versions and external identities are never guessed |
| `SPDX_DEDUPLICATION` | Remove exact duplicate relationships, documentDescribes, externalRefs or checksums, retaining first order | Different comments, categories, types, inverse forms and package records are retained |
| `SPDX_EXTERNAL_REFERENCE` | Reuse packageurl-python canonicalization and conservative CPE 2.3 whitespace trimming | Lossy/ambiguous encodings, missing PURL facts and CPE identity inference are prohibited |
| `SPDX_CHECKSUM` | Normalize existing hexadecimal casing/outer whitespace | Never create/recompute a checksum or guess an algorithm |

License normalization is deliberately not automatic. Self-relationships remain
manual: the existing application prohibits them, but deletion could erase SPDX
semantics. `DEPENDS_ON`, `DEPENDENCY_OF`, `CONTAINS`, `DESCRIBES`, `GENERATED_FROM`
and other schema-defined relationships keep their types and direction. Inverse
relationships are retained even when apparently equivalent.

`documentDescribes` is checked against declared local elements. Declared external
relationship IDs use `DocumentRef-id:SPDXRef-id`; the declaration must be unique.
The referenced external artifact is not fetched or inspected. Bare, malformed,
undeclared or ambiguous external references stay manual and fail integrity
validation. Legal RHS `NONE` / `NOASSERTION` relationship sentinels are preserved.

## Validation and approval safeguards

Every proposal uses the existing copy-on-write engine, bounded passes, seen-hash
loop prevention, complete native SPDX revalidation and rollback. Source SPDX
bytes remain immutable; the candidate remains SPDX JSON with the same version.
Before/after quality uses the actual revalidated bytes, not estimates.

Narrow SPDX validator corrections required by the feature:

- Detect duplicate SPDXIDs before normalization can collapse them into a set.
- Require local IDs to use SPDXRef syntax; DocumentRef is an external declaration.
- Check documentDescribes, file checksum lengths and declared file license expressions.
- Resolve external relationship declarations rather than accepting any prefix.
- Preserve legal RHS NONE/NOASSERTION sentinels.
- Apply strict JSON preflight to SPDX validation, quality and repair, including
  duplicate keys, NaN/Infinity and exponent overflow that would become infinity.
- Normalize supported checksum algorithm lookup keys consistently.

These checks reuse existing validation stages/codes; duplicate SPDXIDs add
`SBOM_VAL_E048_SPDXID_DUPLICATE` (422). They do not weaken or bypass validation.

Signed/integrity-protected documents must not be silently rewritten. SPDX 2.x
native signing is not implemented; opaque `signature` fields encountered anywhere
use the existing manual-review guard. Wrapped/unsupported signing formats remain
unsupported. External-document checksums do not authorize changes to external
artifacts; no such artifacts are changed or fetched.

## Evidence, APIs and security

No new API family, table or migration. The existing endpoints work for SPDX:

- `GET /api/sbom-validation-sessions/{session_id}/quality`
- `GET /api/sboms/{sbom_id}/quality`
- Existing repair analyze/run/status/changes/report/download/approve/reject routes.

Responses include format, specification version, compatible rule metadata and
actual before/after quality. Existing approval/rejection transition rules, role
permissions, tenant/resource access, source hash checks and reviewed candidate
SHA256 checks are unchanged. Candidate byte tampering prevents status exposure
and approval. Quality cannot approve partial/failed candidates.

Snapshots retain artifact hash, complete scoring policy/fingerprint, engine
version, format, spec version and artifact role in existing append-only validation
history. SPDX uses engine 3.0.0; CycloneDX retains 2.0.0 and its prior numeric policy.
Old 2.0.0 evidence/reports remain readable and are never rewritten. Historical
Phase 2 unsupported SPDX repair jobs are retained but cannot suppress a new
native SPDX run.

Summary audit events retain tenant/user/request/session/job correlation and add
format/version metadata. Logs do not include full SPDX payloads or credentials.
All fields are untrusted data, escaped by React; values never become executable
code or AI instructions. Existing restricted server-generated patches enforce
allowed operations and pointer/precondition safety.

## Example

```diff
- "relatedSpdxElement": "pkg:npm/foo@1.0.0"
+ "relatedSpdxElement": "SPDXRef-Package-foo"
- "referenceLocator": " pkg:npm/foo@1.0.0 "
+ "referenceLocator": "pkg:npm/foo@1.0.0"
```

The existing package already declares that exact PURL and unique SPDXID. No
package/version/license/checksum/dependency is generated. Original bytes are
retained; approving the hash-bound candidate persists native SPDX bytes.

## Verification

Dedicated test databases are mandatory; never point test reset/migration
commands at production. Verification against base `4f32088`:

- Final consolidated repair/quality/security/migration selection: **247 passed**, no failures/skips.
- SPDX unit tests: **53 passed**, no failures/skips.
- Quality/API/semantic/integrity evidence checks: **128 passed**, no failures/skips.
- Full frontend: **1,291 passed** across **163 files**.
- Browser E2E: **25 passed**, no failures/skips (two complete successful runs).
- Application and E2E TypeScript, production Webpack build: passed.
- Frontend lint: **0 errors**, **52 existing warnings**.
- Changed Python lint: **21 files passed**; whitespace checks passed.
- Broader backend regression selection: **328 passed / 8 failed / 15 deselected**.
  All eight failures are existing SPDX-to-CycloneDX conversion failures and
  reproduce on clean base: **13 passed / 8 failed** in the conversion suite.
  Existing conversion produces an invalid duplicate document bom-ref; its API
  failures follow the same baseline defect. Conversion production code was not
  changed. Classification: **PHASE_3_REGRESSION=0**, **PRE_EXISTING_FAILURE=8**;
  final test runs have no execution/environment failures.
- Separate validator selection: **158 passed / 15 deselected**.
- A fresh-process compatibility comparison found CycloneDX 2.0.0 quality evidence
  unchanged, excluding calculation timestamp and the additive format field.
- Alembic sole head remains **074_sbom_repair_jobs**; downgrade/re-upgrade was
  tested only against isolated PostgreSQL. No new migration is required.

These selections overlap; their counts must not be summed. At implementation handoff, the complete
application backend suite had not yet been rerun. The final application release
evidence superseding these implementation checks
is recorded in [Phase 3 release validation](sbom-auto-repair-phase3-release-validation.md).

### Large-document observations

Two fresh calculations per fixture; medians in seconds on the local loaded host:

| Packages | Bytes | Quality | Analyze | Full repair | Revalidate | Recalculate with report |
|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 657,758 | 0.357 | 0.262 | 0.770 | 0.194 | 0.164 |
| 4,000 | 2,646,757 | 1.439 | 1.012 | 3.283 | 0.811 | 0.674 |

No obvious new quadratic scaling appeared in these native SPDX observations.
They are not SLAs, guaranteed timings or a confirmed improvement over another
format. One repaired reference in a large document left the rounded overall
score at 97.8 before and after; a repair need not change the displayed score.
The existing large-document schema uniqueItems bottleneck is not optimized here.
Same-name/version packages are reported for manual review and never merged;
different origins can legitimately share those fields.

```sh
.venv/bin/python -m pytest -q tests/test_sbom_spdx_quality_repair.py tests/test_sbom_spdx_integration.py tests/test_sbom_spdx_release.py
.venv/bin/python -m pytest -q tests/validation tests/test_sbom_spdx_cyclonedx_conversion.py
.venv/bin/python -m pytest -q tests/test_sbom_auto_repair.py tests/test_sbom_repair_release.py tests/test_sbom_quality.py tests/test_sbom_quality_release.py tests/test_sbom_quality_integration.py tests/test_sbom_repair_migration.py
.venv/bin/python scripts/run_sbom_repair_e2e.py
npm --prefix frontend test -- --run --maxWorkers=2 --testTimeout=15000
cd frontend
npx tsc --noEmit
npx tsc --noEmit -p e2e/tsconfig.json
npm run lint
npm run build
```

Implementation and release validation performed no commit, push, deployment,
production migration, AI repair or external lookup. Subsequent commit preparation
is separately authorized.

## Specification references

- [SPDX 2.3 relationships and legal sentinel targets](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/)
- [SPDX 2.3 license expressions](https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/)
- Vendored repository schemas remain authoritative for supported field versions.
