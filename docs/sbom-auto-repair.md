# Deterministic SBOM auto-repair, Phase 1

## Architecture and existing integrations

Rejected uploads do **not** have trusted SBOM IDs. They already live in
`SBOMValidationSession`, with immutable original bytes, editable drafts, tenant
ownership and an import gate. Repair therefore operates on that existing
quarantine workspace, not a parallel upload/validation stack.

Flow: upload → existing ingress/format detection/capped parser/schema/semantic/
integrity/security/NTIA/signature/normalization validator → workspace → classify
reported errors → copy-on-write deterministic proposal → full revalidation after
**each** change → retained candidate + before/after reports + structured diff →
explicit approve/reject → existing `ValidationRepairService.import_session` →
existing parser/component synchronization/enrichment queue.

Services live under `app/services/sbom/repair/`: engine, typed proposal/status
models, classifier, immutable policy, report, diff, registry, job service and
independent rule modules. No validation rules or schema files are copied.

The engine additionally reuses the existing security walk before manipulating
parsed data because the normal pipeline short-circuits on earlier failures.
The validator's response cap now prioritizes blocking errors over informational
entries: truncation can no longer hide a later security/strict-NTIA error.
Candidates with truncated validation reports cannot be approved.

## Storage and migration

Migration `074_sbom_repair_jobs`, after `073_sbom_operational_lifecycle`, adds
one tenant-owned table. Original uploads remain in the existing workspace;
there is no need for another original-artifact table. Each job stores:

- workspace/source/original/candidate hashes and optional source SBOM association;
- immutable candidate text, before/after reports, changes and validation options;
- status, approval decision, actor/timestamps and imported SBOM ID.

Candidate/evidence fields are immutable through an ORM flush guard, matching
existing application conventions. Privileged direct SQL is outside that guard;
approval independently checks hashes and reruns validation.

Pending jobs never change the original, draft or accepted SBOM. Approval is one
DB transaction that validates/imports only the stored candidate, records the
approval and updates the workspace to a new draft storage path. Previous files
are preserved. If a workspace already refers to an accepted SBOM, approval
creates a separate repaired SBOM rather than overwriting its data/history.
Approval preserves the originally validated project/application selection, declared
SBOM/application versions, lineage parent, and explicit current-SBOM selection.
Normal post-upload enrichment is scheduled after commit. Repeated approval
returns the same imported ID without scheduling enrichment again.

The existing storage cleanup policy retains workspace files after permanent
database deletion; repair does not introduce a new filesystem garbage collector.
The release test verifies retained files and unrelated repair jobs remain intact.

The existing permanent-delete service accounts for jobs in impact previews,
known foreign keys and ordered deletion. An explicitly confirmed permanent
SBOM deletion can delete associated repair history. Ordinary rejection cannot.

Apply after backup using the deployment's configured database:

```sh
.venv/bin/python -m alembic upgrade head
```

Upgrade and downgrade/re-upgrade of 074 were verified on the dedicated PostgreSQL test database.

Rollback to `073_sbom_operational_lifecycle` drops job candidates and reports.
It does not remove original workspace uploads or trusted SBOM data. Coordinate
code and schema rollback; do not downgrade a database with history you need.

## API and permissions

All paths below start with `/api/sbom-validation-sessions/{session_id}`.
Existing SBOM validation-report/workspace links resolve the corresponding
workspace for persisted SBOMs.

| Method | Suffix | Permission |
|---|---|---|
| POST | `/repair/analyze` | `sbom:repair:read` |
| POST | `/repair` | `sbom:repair:update` |
| GET | `/repair` | `sbom:repair:read`; latest retained job |
| GET | `/repair/{job_id}` | `sbom:repair:read` |
| GET | `/repair/{job_id}/changes` | `sbom:repair:read` |
| GET | `/repair/{job_id}/download` | `sbom:repair:download` |
| GET | `/repair/{job_id}/report` | `sbom:repair:download` |
| POST | `/repair/{job_id}/approve` | `sbom:repair:revalidate` AND `sbom:upload` AND `product:assign_sbom` |
| POST | `/repair/{job_id}/reject` | `sbom:repair:update` |

The existing `/download-original` route serves original bytes. No endpoint
accepts arbitrary patch operations, replacement candidate bytes, JSON paths,
confidence overrides or a caller-selected tenant. Tenant membership/permissions
come from the established authentication context. Workspace/job lookups include
tenant predicates and foreign IDs return 404. Expired workspaces return 410.

Approval accepts an optional `{"candidate_sha256": "<reviewed hash>"}` body; the
review UI sends it. A mismatched reviewed hash returns 409, including on retries.
Stored candidate content is independently hash-verified even without that body.

Approval rejects a changed source draft, project assignment, SBOM association,
source SBOM hash, original hash or candidate hash (409). Partial/failed/rejected
candidates cannot be approved. Approval revalidation preserves original strict
NTIA/signature policy and any stricter current signature setting. Policy flags
are retained on the existing immutable workspace creation event. Old sessions
can recover strict NTIA from stored error severity, but flags never retained by
historical code cannot be recovered with certainty.

## Rules and classifications

Every reported **error** is AUTO_FIX, SUGGEST_FIX or MANUAL_ONLY. Warnings remain
part of validation reports. Unrecognized codes, missing facts, unsupported
representations and unsafe input are MANUAL_ONLY.

1. **Duplicate bom-ref:** stable UUIDv5 for an unreferenced duplicate declaration.
   Identical repeated declarations in the same array can be removed, preserving
   every existing reference's target. References to **distinct** duplicate
   declarations are ambiguous and SUGGEST_FIX, never guessed. All document
   reference/extension locations, including BOM-Link fragments, are conservatively
   inspected before renaming.
2. **Dangling dependency ref/dependsOn:** exact declared bom-ref, exact existing
   PURL, exact CPE, exact `name@version`, then whitespace-normalized identifier.
   The first matching tier must identify exactly one declaration. Multiple
   matches are SUGGEST_FIX; no match is MANUAL_ONLY. No relationships are invented
   or deleted to hide a dangling reference.
3. **Duplicate dependency entries:** remove identical dependency records or
   dependsOn entries while preserving first occurrence order. Different records
   for the same source are not merged. JSON type distinctions are preserved.
4. **Enum normalization:** unique case-insensitive/trimmed match for component
   `type` in the exact vendored CycloneDX schema enum. License/hash/signature enums
   are deliberately excluded.
5. **PURL whitespace:** remove surrounding whitespace from an existing PURL only
   if the existing PURL parser accepts the trimmed value. No PURL is synthesized;
   package/version/qualifier facts are never changed.

Only proposals with method DETERMINISTIC and confidence 1.0 are produced. Each
proposal contains a stable repair ID, existing error code, restricted operation,
JSON pointer, old/new values, rule, explanation and confidence. Every proposal
must remove its relevant error; new errors at an already reached stage or new
warnings at such stages roll it back. Fixing one stage can expose previously
hidden errors in later stages: the job remains partial/FAILED until those are
resolved. Rolled-back proposals remain in `rolled_back_changes`, receive a
RULE_ROLLED_BACK audit event, and their unresolved errors require manual review.
No repair changes component versions, suppliers, licenses, hashes,
CPEs, vulnerabilities or security findings.

## Configuration and bounds

```dotenv
SBOM_AUTO_REPAIR_ENABLED=true
SBOM_REPAIR_MAX_PASSES=3
SBOM_REPAIR_AUTO_APPLY_CONFIDENCE=1.0
SBOM_REPAIR_MAX_BYTES=5242880
SBOM_REPAIR_MAX_SECONDS=30
```

Pydantic settings validate passes (1–10), confidence (0–1), byte limit
(1 KiB–50 MiB) and time budget (1–120 seconds). Default maximum is 3 passes with
100 individually revalidated proposals per pass. Hash-based cycle detection
prevents loops without retaining every full intermediate document in memory.
The elapsed-time budget is checked between proposals, not inside an individual
validator call. Larger files retain the existing large-file manual workspace.

With auto-repair disabled, original validation errors and upload behavior are
unchanged. Analyze returns disabled/manual classifications; run returns 409.
No automatic acceptance mode exists. Tenant policy/AI repair modes are future
extensions to the policy interface; they are not exposed as permissive flags.

## User interface

The existing upload failure and small/large validation workspace show counts of
safe, suggested and manual issues, View Errors, Auto-Repair Safe Issues and a
validation-report download. Repair results offer changes, accept/reject,
original/candidate/report downloads and a link to the approved SBOM. Partial
candidates have disabled acceptance. Diff rows show error, JSON pointer, old/new
values, rule, reason and confidence. Values are escaped React text, not HTML.
A refresh restores the latest retained job. Manual draft edits invalidate repair
classification; stale results visibly disable acceptance and allow a new repair.
View Errors shows the candidate's remaining issues after repair. Signed/unsupported
formats show an explicit manual-handling reason. The server rejects stale
approvals independently of UI state. Valid uploads do not require repair controls.

## Audit and security

Existing structured logger, authenticated correlation context, tenant audit log
and workspace events record SBOM_REPAIR_ANALYZED, STARTED, RULE_APPLIED,
REVALIDATED, APPROVED, REJECTED, COMPLETED and FAILED. Logs carry IDs, hashes,
rule IDs and counts; never SBOM content, proposal values or filename secrets.

SBOM data is untrusted. No document field is executed, interpreted as an
instruction, or sent to an AI provider. The existing capped parser and security
walk run before repair. Signed documents are not modified. Duplicate JSON object
keys and non-JSON numbers are refused because serialization could lose facts.
Only server-generated replace/remove proposals and validated preconditions pass
through the existing JSON pointer patch engine. Original artifacts are immutable
through this feature; candidate/evidence ORM changes are rejected.

## AI extension

`RepairAdvisor` is a structured-proposal protocol with a `NullRepairAdvisor`.
RepairMethod already distinguishes DETERMINISTIC, INFERRED and AI_ASSISTED.
Phase 1 invokes neither the advisor nor the application's existing AI suggestion
workflow. A future provider must keep document fields in a data boundary, return
structured proposals, satisfy a separate policy/permission gate, and use the same
revalidation, hash binding and explicit approval. It must never rewrite a full
SBOM or fabricate unknown facts.

## Example

Before:

```json
{
  "components": [{"bom-ref": "a"}, {"bom-ref": "b", "purl": "pkg:npm/beta@2.0"}],
  "dependencies": [{"ref": "a", "dependsOn": ["pkg:npm/beta@2.0", "pkg:npm/beta@2.0"]}]
}
```

After (other original SBOM fields are unchanged):

```json
{
  "components": [{"bom-ref": "a"}, {"bom-ref": "b", "purl": "pkg:npm/beta@2.0"}],
  "dependencies": [{"ref": "a", "dependsOn": ["b"]}]
}
```

The existing edge is resolved to its unique declared target and duplicate
occurrences removed. This fragment illustrates the change; a full SBOM still
needs all fields required by the existing validator.

## Files

Added: `app/services/sbom/repair/{__init__,engine,models,classifier,policy,report,diff,registry,service}.py`,
`rules/{__init__,base,duplicate_bom_ref,dangling_dependency_ref,duplicate_dependency,enum_normalization,purl_normalization}.py`,
`app/routers/sbom_auto_repair.py`, `alembic/versions/074_sbom_repair_jobs.py`,
`frontend/src/types/sbomAutoRepair.ts`, `frontend/src/components/sboms/SbomAutoRepairPanel.tsx`
and its test, `tests/test_sbom_auto_repair.py`, `tests/test_sbom_repair_release.py`,
`tests/test_sbom_repair_migration.py`, `tests/validation/test_release_truncation.py`,
`frontend/e2e/` (standalone Playwright harness),
`scripts/run_sbom_repair_e2e.py`, and this document.

Modified: `.env.example`, `app/{settings,models,main}.py`, `app/core/security.py`,
`app/routers/{sbom_upload,sboms_crud}.py`, `app/services/{validation_repair_service,sbom_delete_service}.py`,
`app/validation/errors.py`, `tests/validation/test_errors.py`, `frontend/src/lib/api.ts`,
existing `SbomUploadModal.tsx` / `ValidationRepairWorkspace.tsx`, and
`frontend/tsconfig.json` (exclude the separately installed E2E package from the
application build).

## Validation commands and limitations

Use a dedicated PostgreSQL **test** database following `tests/conftest.py`.
Never point test commands at a development/production database. The repository
fixture validates the test database name and migrates it automatically.

```sh
SBOM_WORKSPACE_STORAGE_DIR=/tmp/sbom-repair-test-workspaces \
  .venv/bin/python -m pytest -q tests/test_sbom_auto_repair.py tests/validation \
  tests/test_validation_repair_workspace.py tests/test_sbom_upload_validation_persisted.py \
  tests/test_sbom_revalidate_endpoint.py tests/test_sbom_upload_version_lineage.py \
  tests/test_sbom_delete_service.py
.venv/bin/python -m ruff check app/services/sbom/repair app/routers/sbom_auto_repair.py
cd frontend
npm test -- src/components/sboms/SbomAutoRepairPanel.test.tsx \
  src/components/sboms/ValidationRepairWorkspace.test.tsx \
  src/components/sboms/SbomUploadModal.repair.test.tsx \
  src/lib/api.upload.test.ts src/lib/sbomValidation.test.ts src/__tests__/mutation-invalidation.test.ts
npx tsc --noEmit
npx next build --webpack
```

Tests cover copy immutability, deterministic/stable IDs, referenced duplicates,
all identity-match tiers, ambiguous matches, duplicate edges, normalization,
full revalidation/rollback, no invented facts, partial repairs, pass/byte bounds,
idempotency, hash tampering, stale drafts, strict NTIA retention, authorization,
HTTP tenant isolation, atomic candidate-only import, rejection, accepted-source
preservation, deletion integration and report-cap safety. Frontend tests cover
explicit review, escaped diffs, failed/partial approvals, permissions and errors.

Phase 1 deterministically repairs supported CycloneDX JSON only. XML, YAML,
SPDX, malformed JSON, signed documents and ambiguous identity mappings remain
manual. The existing validator caps displayed entries and short-circuits after
failed stages; analyze counts therefore describe visible reported errors, not
all possible latent errors. Scope is structural quality, not security attestation.

The integration found the report-cap bug described above. SQLite full-app tests
also encountered the existing tenant-role bootstrap failure; PostgreSQL is the
verified integration path. The workstation's default Node executable has a
missing Homebrew library; checks used the Codex bundled Node runtime instead.
No production database migration or deployment is performed by these changes.


Recorded verification: expanded backend validation/upload/lineage suites passed
256 tests (15 benchmark/slow tests deselected); final focused repair/deletion/error
report checks passed 63 tests. Focused frontend checks passed 41 tests in six
files. TypeScript passed. ESLint reported zero errors and five existing warnings
in the workspace/API files. Python lint and whitespace checks passed. The production Webpack build passed;
the default Turbopack build could not run because native SWC bindings are absent. This was the initial focused implementation evidence. Final application release
validation is recorded below.


## Application release validation (2026-10-06)

Full backend command: `.venv/bin/python -m pytest -q`. `pytest.ini` excludes
opt-in integration/benchmark markers by default. Full frontend command:
`npm test -- --maxWorkers=2 --testTimeout=15000`. Also run `npm run lint`,
`npx tsc --noEmit`, and `npx next build --webpack`.

The real browser harness uses native sign-in, the existing BFF and Redis, an
isolated FastAPI/Next instance, and a uniquely named disposable PostgreSQL test
database bootstrapped to 074. It never uses the application database or prints
credentials. Its temporary manifest/keys are private; failure snapshots redact
generated test passwords. Test-only HTTPS trusts the generated localhost
certificate. Cold Webpack routes are warmed before the existing authentication
bootstrap timer starts; application auth behavior is unchanged.

```sh
npm ci --prefix frontend/e2e
cd frontend/e2e
npx playwright install chromium
cd ../..
.venv/bin/python scripts/run_sbom_repair_e2e.py
# For interactive diagnostics, use --serve and the emitted private manifest path:
# REPAIR_E2E_MANIFEST=<path> npm test --prefix frontend/e2e
(cd frontend && npx tsc --noEmit -p e2e)
```

`REPAIR_E2E_NODE` can specify a working Node binary. The runner owns and cleans
up its processes and unique test database. It retains private local diagnostics.

Application boundaries cover normal valid uploads (no job/candidate), reviewed
and stored hash tampering, preservation of application/version/lineage/current
selection, role/tenant authorization, terminal decisions, concurrent requests,
rollback audit evidence, deletion/retention, and real migration round-trip.
The dedicated truncation regression is separate from repair rule tests.


Final application evidence: **3,478 backend passed / 60 failed / 10 skipped / 0
execution errors**, with 12 passed subtests and 18 default marker exclusions.
Every final failure independently reproduced on clean HEAD; none is an
Auto-Repair regression. **1,270 frontend tests**, **80 consolidated backend
repair/security/migration checks**, **45 focused frontend checks**, and **15
real browser E2E scenarios** passed. Application/E2E TypeScript, changed-file
Python lint and production Webpack build passed. Full Python lint retains the
same 43 errors as HEAD; frontend lint retains the same 52 warnings (zero errors).
Migration 074 is the sole head and passed another real PostgreSQL round-trip.

See [the complete release validation report](sbom-auto-repair-release-validation.md)
for exact evidence, every baseline failure, defects fixed, security/concurrency
results, branch assessment and recommended commit groupings. Phase 1 is ready
for review; the full application backend remains non-green due to those existing
failures. The initial release-validation pass made no commits. The subsequent authorized commit-separation handoff is recorded in the release report. No production migrations, deployment or Phase 2 work were performed.
