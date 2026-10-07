# Logical SBOMs and independent revision history

## Architecture decision

Keep `sbom_source` as the uploaded **version** table and add `logical_sbom` as its parent.
Existing SBOM IDs, component IDs, files, validation workspaces, analysis runs/findings, VEX,
reports, lifecycle fields and audits stay in place. Product remains the Application domain entity.
`sbom_version` and `productver` remain independent. Operational Active/Inactive remains per version.
Product's explicit current SBOM scheduler target remains per uploaded version.

Before this change, uploads are grouped only by explicitly declared `parent_id` chains and
name/version uniqueness spans the entire tenant. Product pages list individual uploads.
After this change, each Product contains logical masters and each master owns independent versions.
Existing version detail/analysis/report APIs continue to take stable `sbom_source.id` values.

## Migration strategy

Migration 076 adds masters and a version-to-master relationship without moving or deleting evidence.
Backfill follows explicit parent relationships only when tenant, Product and Project match. Unlinked
uploads stay independent even when names match. A conflicting version label within a legacy chain
starts a separate master to preserve every original row and label. Legacy unassigned rows retain
nullable Product ownership until assigned. Soft-deleted and inactive versions are included in backfill.
Uniqueness becomes `(logical_sbom_id, sbom_version)`; only one unversioned row is allowed per master.
No product-version uniqueness is introduced. Existing version labels are never parsed as decimals.

Dotted numeric ordering reuses the existing version parser and zero-padding comparison. Arbitrary
release labels use upload order as the documented fallback. Latest here means highest comparable
numeric revision when all labels are numeric, otherwise newest uploaded revision; it does not
change explicit scheduler selection.

Uploads can explicitly select a logical master or create a new one. The legacy `parent_sbom_id`
path remains supported and attaches to that parent's master. Editing and restoring keep master
ownership, choose a fresh revision label, and preserve prior versions. Format conversions remain
separate derived documents (their own master), preserving source/conversion links. Moving an
individual version through the legacy assignment API detaches it into a new master at its new
Product, leaving other versions and their evidence untouched.

New APIs reuse SBOM read/upload permissions, tenant context, standard HTTP errors and pagination.
Platform-only authority cannot substitute for tenant SBOM access.

## API and UI changes

- `POST /api/products/{product_id}/logical-sboms`: create a master (name, optional description).
- `GET /api/products/{product_id}/logical-sboms`: paginated masters, version counts and latest revision metadata.
- `GET /api/logical-sboms/{id}`: master details and latest revision.
- `GET /api/logical-sboms/{id}/versions`: ordered version history, including inactive revisions.
- `POST /api/sboms/upload`: accepts `logical_sbom_id` for an existing master or
  `create_new_logical_sbom=true` for a new identity and its first revision. Existing fields, file detection,
  validation/repair flow and 202 response remain; the response includes the new master ID.
- Existing `/api/sboms/{version_id}` detail, component, analysis, VEX and report APIs stay version-specific.
  `/api/sboms/{version_id}/versions` now uses master ownership, retaining its legacy list format/order.
- Legacy JSON creation accepts `logical_sbom_id`. Repair workspaces retain original master/Product/version choices.
- Duplicate revisions return the existing 409 `duplicate_sbom_version` error shape. Database constraints also
  prevent bypasses, including tenant/Product mismatches and multiple unversioned revisions per master.
- The upload modal offers existing/new identity selection. Product detail groups logical SBOMs with version counts,
  latest revision and history links. `/sboms/logical/{id}` lists revisions, Product versions, dates, actors, status
  and analysis actions. Existing SBOM list/detail screens link to the logical history.

## Compatibility and rollout

Use a coordinated rollout: stop old API/worker writers, apply `alembic upgrade head`, deploy/restart the updated
API/workers, then release frontend changes. Old writers cannot supply the required logical identity after migration. Migration 076 is intentionally not automatically reversible: the previous tenant-wide unique
name/version rule may no longer hold. Preserve the normal database backup before rollout.
No production database migration or service restart is performed by this implementation task.

Legacy records with repeated/missing version labels in an explicit chain receive separate identities where necessary
so no upload or original label is lost. Runtime legacy unversioned ORM clones use the same conservative handling.
Users select the appropriate logical identity for future revisions; this feature does not automatically merge unrelated
historical uploads that happen to share a name.

The existing SPDX-to-CycloneDX conversion tests expose a pre-existing duplicate `SPDXRef-DOCUMENT` bom-ref validation
failure (`SBOM_VAL_E051_BOM_REF_DUPLICATE`). The same pure conversion test reproduces on the unchanged pre-feature
commit. Conversion code and its failing assertions were not changed as part of logical SBOM version management.

## Verification

- Final focused backend run: **64 passed** across logical identities/revisions, migration, upload lineage, Product
  hierarchy, SBOM assignment/editing, and deletion.
- Migration tests cover SQLite and PostgreSQL, plus the real frozen PostgreSQL baseline upgraded from 075 to 076
  with existing SBOMs, components, analyses, findings, VEX documents, reports and audits; original IDs/data survive.
- Final frontend run: **67 passed** across upload/repair handoff, independent SBOM selection, grouped Product display,
  version history and analysis targeting, inactive controls, existing detail/list pages and analysis-stream behavior.
- TypeScript and Python Ruff checks pass. ESLint passes on the logical-history, upload and Product UI implementations; existing upload-test
  mocks have four unused-parameter warnings.
- The broader backend run exercised lifecycle, validation persistence and automatic repair successfully. Eight existing
  SPDX conversion checks failed from the duplicate document bom-ref issue reproduced on the pre-feature commit.

## Files changed

Backend: `app/models.py`, `app/schemas.py`, `app/core/security.py`, `app/main.py`,
`app/routers/logical_sboms.py`, `app/routers/sbom_upload.py`, `app/routers/sboms_crud.py`,
`app/routers/sbom_versions.py`, `app/services/logical_sbom_service.py`,
`app/services/validation_repair_service.py`, `app/services/version_control_service.py`,
and `alembic/versions/076_logical_sbom_versions.py`.

Frontend: `frontend/src/components/sboms/SbomUploadModal.tsx`,
`frontend/src/components/sboms/LogicalSbomHistory.tsx`, `frontend/src/components/sboms/SbomDetail.tsx`,
`frontend/src/components/sboms/SbomsTable.tsx`, `frontend/src/app/products/[id]/page.tsx`,
`frontend/src/app/sboms/logical/[id]/page.tsx`, `frontend/src/lib/api.ts`,
`frontend/src/lib/queryInvalidation.ts`, and `frontend/src/types/index.ts`.

Tests: `tests/test_logical_sbom_versions.py`, `tests/test_logical_sbom_migration.py`,
`frontend/src/components/sboms/LogicalSbomHistory.test.tsx`,
`frontend/src/components/sboms/SbomUploadModal.repair.test.tsx`,
`frontend/src/app/products/[id]/page.test.tsx`, and `frontend/src/lib/api.upload.test.ts`.
New coverage includes successive revisions under one master, independent masters sharing revision labels,
constant Product release across revisions, exact duplicate/database enforcement, numeric/fallback ordering,
independent components/analysis, first upload to an empty master, tenant/RBAC denial, inactive history,
metadata duplicate rejection, repair import, edit/restore, and migration evidence preservation.
