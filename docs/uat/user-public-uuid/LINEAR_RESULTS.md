# Linear implementation issue draft — not published

Team: **Platform & Identity**

Title: **Implement immutable UUIDv4 public IAM User identities while retaining integer relationships**

References: **SBO-20, SBO-22, SBO-55, SBO-66, SBO-73**.

## Draft description

The six business resources already expose public UUIDs, while IAM User API references remain integers. Add separately versioned migration 101 with backfill, UUIDv4/variant validation, uniqueness, NOT NULL and independent identity guards. Keep integer user keys, memberships/grants, provider issuer/subject mappings and token subjects internally unchanged. Extend the scoped public translation boundary and User-specific frontend contracts; preserve ordinary Platform Admin global discovery restrictions.

Deliverables: IMPLEMENTATION_REPORT.md, IDENTIFIER_CONTRACT_MATRIX.md, API_MIGRATION_MATRIX.md, DATABASE_MIGRATION_PLAN.md, TEST_RESULTS.md and sanitized evidence in this directory.

Acceptance: real PostgreSQL fresh/upgrade fixture integrity; authorized UUID user flows; malformed/integer syntax rejection; authorization/concealment and tenant isolation; browser Native session UUID stability; existing six-resource and integer Analysis Run regressions; complete static/full regression inventories with honest limitations.

Cutover: the populated Greenfield database is not migrated by this implementation. Exact schema, backup/recovery, row-count, service-window and source review remains a separate approval gate. HCL.CS/Entra live acceptance needs the configured providers. The existing SBO-73 privacy/global-discovery decision remains unchanged and must not be inferred from this issue.

## External actions

No Linear issue was created or edited, no issue status changed, and SBO-73 was not modified. This is a local draft for operator review; no UAT or production sign-off is asserted.

## Implementation evidence attached to this draft

Final local verification: backend 4,414 PASS / 7 documented SKIP / zero FAIL/ERROR plus 12 passing subtests; frontend 1,812 PASS; final-source Chrome 9 PASS. Disposable schema101 and synthetic populated upgrade accepted. Populated Greenfield remains schema100; exact migration/backup/cutover approval and staging/live-provider gates remain pending. This evidence is local only and does not change any Linear status or SBO-73 decision.
