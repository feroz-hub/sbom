# Guarded development startup: 101 → 102

Implemented and validated locally on 2026-10-22, following the operator's approval to add the startup flow. **The populated database was not connected to or migrated, and application services were not restarted.** Git publication was authorized separately; publishing this source does not authorize executing the populated migration.

## Use

From the repository, run:

```bash
python3 scripts/dev.py start
```

On the verified existing Greenfield database at revision 101, the launcher performs read-only source/schema/security checks and displays the actual cluster identity and affected row counts. It then requires this exact confirmation:

```text
UPGRADE sbom_greenfield_uuid 101 TO 102
```

Entering that phrase authorizes the displayed local backup/restore rehearsal and one migration attempt. Pressing Enter cancels before any backup or database write. A plain `yes`, the old 100→101 confirmation, noninteractive input, an unknown revision or a partial schema cannot authorize this unit. There is no automatic 100→102 chain.

After confirmation, the launcher:

1. Creates a private encrypted full backup and restores it into a **new retained** `sbom_greenfield_uuid_pre102_<random>` rehearsal database. It compares the revision, complete original schema, owners, ACLs, default privileges, sequences and all original table values before proceeding. These are new recovery resources, not a replacement of the populated database.
2. Rechecks source, target, client exclusion and the original snapshot. It records an exclusive attempt claim, acquires advisory key 7160085102 and NOWAIT locks on the version table and the three target tables, and repeats the checks under lock.
3. Uses one caller-owned, non-autocommit transaction under `greenfield_owner`. It runs the unchanged revision-102 body and its guarded 101→102 marker transition exactly once. The migration's statement/lock/idle limits remain 30 seconds / 250 ms / 5 seconds; preflight queries retain their existing two-second statement limit.
4. Verifies that only the reviewed three UUID columns, three unique indexes, six constraints, six triggers and one guard function were added. Every original row value, including all seven existing public UUID identities, integer keys, credentials, memberships, grants, findings and history, must remain unchanged. UUID values, exact constraint/trigger definitions, owners and owner-only function execution ACLs are checked.
5. Requires acknowledged COMMIT, physical writer closure and independent read-only schema/data/revision acceptance with rollback and connection closure. Only then can normal API/frontend/worker startup proceed.

A database already at 102 is inspected for the required UUID schema/security before startup; it is not migrated or prompted again. A failed precommit attempt requires rollback and closure, while an uncertain COMMIT stops for reconciliation. An attempt claim is retained after failure and blocks subsequent starts. Never delete that claim, stamp a marker, replay a migration or restore automatically to bypass a failure. Recovery requires independent review of the retained evidence and backup.

Existing active clients block the upgrade. Close database GUI sessions and stop incompatible writers through their normal controls before confirming; the migration does not terminate arbitrary clients. Credentials are loaded privately, with no ambient PG/service/passfile fallback and no credential-bearing diagnostics printed.

## Source changes

- `scripts/greenfield_migrations.py`: shares the existing owned transaction/backup/read-back lifecycle between explicitly selected next-only units; preserves the original 100→101 unit. Snapshot exclusion is unit-specific, includes default ACLs, and supports only the two reviewed rehearsal name patterns.
- `scripts/greenfield_resource_migrations.py`: new source-pinned 101→102 unit, exact confirmation, full preflight snapshot, three-table catalog delta and independent acceptance.
- `scripts/dev.py`: updates the lifecycle description; service launch ordering is unchanged.
- `tests/test_greenfield_startup_migrations.py`: retains the legacy controls and replaces the superseded unconditional-102-denial assertion with explicit dispatch/unknown-revision coverage.
- `tests/test_greenfield_resource_startup.py`: confirmation, source, read-only, marker, backup, locking, data/catalog/security, rollback, closure and uncertain-COMMIT regressions.
- `scripts/test_greenfield_resource_startup.py`: opt-in real acceptance using newly created `sbom_startup102_<random>_test` databases only. It never connects to `sbom_greenfield_uuid`, never starts services, and retains its test/rehearsal databases for review.

Frozen migrations 100, 101 and 102, their identity guards/helpers, application models, API/frontend implementation, existing reports, source manifests and private historical evidence remain unchanged.

## Verification actually executed

| Check | Result |
|---|---|
| Final focused offline launcher/control suites | **247 PASS, 0 FAIL, 0 ERROR, 0 SKIP** |
| Real PostgreSQL synthetic startup acceptance | **3 PASS, 0 FAIL, 0 ERROR, 0 SKIP** |
| Ruff lint and format on all six changed/new Python files | PASS |
| Python AST/compilation, pinned migration/helper preservation and Git whitespace | PASS |

The offline suites are `tests/test_greenfield_startup_migrations.py`, `tests/test_greenfield_resource_startup.py`, `tests/test_dev_greenfield.py`, `tests/test_dev_launcher.py` and `tests/test_dev_lifecycle.py`. They ran with explicit SQLite test configuration and an isolated unavailable broker, without database or service access. The PostgreSQL tests ran separately, outside the application test conftest, on newly created synthetic databases with users, provider links, Native credential rows, memberships, role assignments, a platform grant, logical SBOM/source, analysis run, finding and audit history.

The three real checks prove: successful 101→102 backup/restore and independent read-back, including a subsequent read-only current-102 startup check; injected failure after the actual 102 body/marker with complete rollback to 101 and retained no-retry claim; and successful legacy 100→101 backup/restore/upgrade. The runtime sources and PostgreSQL test script were unchanged between those passing checks and final verification. Mocked unknown-COMMIT tests do not claim a real lost-acknowledgement event.

Development evidence is preserved privately under `~/.sbom-public-resource-uuid/startup102-20261022T035356322761Z/`. Initial offline checks passed 220 cases, then 242, then the final 247. Four earlier PostgreSQL attempts each reported three **fixture setup errors**, before entering the startup migration: an unsupported private-file API, an invalid synthetic password-hash placeholder, and omitted logical-SBOM / client-defaulted run fields. The fixture was corrected to honor the existing constraints and defaults; no database constraint or migration guard was weakened. An initial unused-import Ruff finding was also corrected. Original failed XML/logs remain private; they were not rewritten as passes. New test/rehearsal databases are retained, including failed-setup targets, with no automatic cleanup.

The earlier complete backend/frontend/Chrome acceptance remains historical evidence for its published source. It was not rerun or relabeled as validation of this launcher change. Real populated cutover, application startup and post-cutover login/browser acceptance are still pending the operator's interactive confirmation and subsequent execution results.

**POPULATED_DATABASE_MIGRATION_102_NOT_APPLIED by the implementation or Git publication.** No production/historical database, existing seeded identity, Docker lifecycle, application service or external issue was modified. Only the separately authorized source publication changes Git history.
