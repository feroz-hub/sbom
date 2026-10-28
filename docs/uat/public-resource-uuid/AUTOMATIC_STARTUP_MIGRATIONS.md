# Automatic migration discovery at development startup

`python3 scripts/dev.py start` now discovers the active Alembic head and database-to-head path. Adding a new supported migration no longer requires editing the launcher, its expected revision constant, or a separate source-pin list. Backend/frontend-only changes require no database upgrade when the schema revision is already current.

The operator selected **auto-detect migrations; confirm upgrades**. Each pending revision displays its transition and requires its own exact confirmation, for example `UPGRADE sbom_greenfield_uuid 101 TO 102`. There is no blanket approval of future migrations, silent schema synchronization from ORM models, historical replay, downgrade, marker stamping or automatic retry. If several units are pending, each completes its own backup, transaction, COMMIT, physical closure and independent read-back before the next is offered. Cancel or failure stops the path and service startup.

## Migration author workflow

1. Add an ordinary forward Alembic revision under `alembic/versions/`, with a unique numeric-name revision such as `103_example_change` and `down_revision` set to the actual active head. Update application metadata as appropriate for that schema change. Do not rewrite frozen migrations.
2. Include the startup contract and read-only acceptance hooks in that same new migration. Copy `scripts/templates/greenfield_migration.py.tmpl` as a starting point. Set a literal `startup` mapping containing exactly `version=1`, `tables` (1–32 distinct existing affected tables), a positive migration-specific `advisory_key`, and a concise printable `description`.
3. Implement `startup_preflight(connection)` to inspect exact predecessor schema, security and migration-specific prerequisites, returning `True` only on acceptance. Implement `startup_validate(connection, before)` to prove the exact permitted catalog/security/data delta both before COMMIT and on independent read-back. `before` contains the original complete catalog and per-table row-count/digest snapshot; when it is `None`, validate the already-current target state without replaying changes. These functions must support server-enforced read-only sessions.
4. `upgrade()` uses Alembic `op.get_bind()` in the caller-owned PostgreSQL transaction. It must not create connections, commit/rollback independently, change target/credentials, relax security, start services or retry. The launcher owns the conditional predecessor→successor marker update. Use the module's function bodies for application imports; top-level declarations must remain inert. No top-level application configuration or environment loading is allowed.
5. Test the migration on disposable PostgreSQL fixtures and review its data/security effects. Run the existing startup regressions plus its own acceptance tests. Then run the usual `dev.py start`; detection is automatic, but the actual populated upgrade is approved only by its displayed confirmation.

The template deliberately raises until its preconditions, body and acceptance checks are implemented. A plain migration without the startup contract is reported by revision name and blocks before Docker/credential/database access. This preserves the requirement for meaningful migration-specific validation; it does not substitute a marker for schema correctness. Historical 101 and 102 retain their existing exact pinned validators without modifying their migration sources.

New-table-only migrations must still list an existing affected serialization/ownership anchor table. A migration needing nontransactional DDL, a larger lock/timeout budget, unusual import-time behavior, a branched graph or an incompatible data transformation needs a separately designed contract version; it cannot bypass these controls.

## Discovery and safety

- The active graph is read using Python AST, never by importing historical migration 001 or executing `alembic/env.py`. It requires one linear graph, all ancestors, unique revisions, and unchanged frozen 100/101/102 bytes. Duplicate revisions, disconnected cycles, branches, missing ancestors and unsupported declarations stop startup.
- The expected revision is discovered dynamically, including callers importing `greenfield_uuid.REVISION`. An unknown database marker, marker before the accepted Greenfield baseline or multiple markers is rejected.
- Before resource or credential access, the full pending contract set is checked. A snapshot of application, script and migration Python source plus installed SQLAlchemy/psycopg/Alembic versions is captured and repeatedly revalidated. Changed/new/deleted source or dependency changes after review stop execution. The exact snapshot is retained privately in each confirmed backup folder as `approved-source-snapshot.json`.
- Connections remain fixed to the existing local Greenfield target with clean PostgreSQL options, explicit read-only preflight/read-back, no service/password-file fallback and sanitized driver errors. Runtime source is not fetched from GitHub or another environment.
- Every confirmed unit uses the existing encrypted full-backup and new retained restore-rehearsal mechanism. Restore schema/data/owner/ACL/default-privilege/sequence parity must pass before mutation. Rehearsal names are generated from the discovered successor revision, not a new per-revision launcher constant.
- Each write uses one owned non-autocommit transaction, advisory and version/table NOWAIT locks, rechecks under lock, a conditional atomic marker update, bounded timeouts and explicit acceptance. Generic future units retain maximum 30-second statement, 250 ms lock and 5-second idle-transaction settings. The existing 101/102 contracts retain their original limits.
- Known precommit failure rolls back and closes. Unknown COMMIT or incomplete independent acceptance retains the attempt claim and blocks restart for manual reconciliation. No automatic cleanup, recreation, downgrade, marker repair or second attempt is performed.
- The explicit fresh installer retains its validated 100→101→102 bootstrap. Future migration bodies and acceptance hooks then run in that fresh install's existing owned transaction; the installer retains COMMIT and independent read-back ownership. Ordinary startup never invokes fresh bootstrap or `create_all()`.

## Implementation and verification

New modules: `scripts/greenfield_migration_graph.py` and `scripts/greenfield_auto_migrations.py`. The existing lifecycle delegates discovery/selection, and the existing fresh installer obtains the head dynamically. Existing 101/102 transaction/UUID validators remain intact. Unit tests for those exact lifecycles now invoke the same internal owned-unit runner explicitly; separate tests exercise the public automatic dispatcher, including real PostgreSQL.

No populated migration or application restart is part of implementing this feature. The original ten-resource application regression results remain historical; focused startup tests and newly owned synthetic PostgreSQL fixtures establish this launcher change's acceptance separately. Live identity/provider tests are not implied.

Actual final verification on 2026-10-22:

| Check | Result |
|---|---|
| Focused startup, graph, source-lock and process-lifecycle regressions | **282 PASS / 0 FAIL / 0 ERROR / 0 SKIP** |
| Real PostgreSQL acceptance on newly created synthetic databases | **4 PASS / 0 FAIL / 0 ERROR / 0 SKIP** |
| Ruff lint/format, Python AST/compilation, frozen migration preservation and Git whitespace | PASS |

The real checks cover confirmed 101→102 encrypted backup/restore and independent acceptance, precommit rollback to unchanged 101 with a retained attempt claim, the legacy 100→101 unit, and automatic 101→102→synthetic-103 selection with separate confirmations, separate verified backups and already-current read-only validation. The synthetic 103 revision exists only in a private copied checkout, never active application migration discovery. Original application rows and the populated revision were not queried or changed. All four tests were repeated on final frozen source. The fresh-install future-tail binding has separate mocked coverage; a full fresh installer through a real future application revision still needs that revision's own PostgreSQL acceptance.

Initial focused checks passed 278 cases; final coverage passed 282. An unused-import Ruff finding was corrected before the final checks. Private original execution logs/XML and source hashes are retained under `~/.sbom-public-resource-uuid/automatic-startup-20261022T043402432822Z/`; no raw database diagnostics, credentials or authenticated browser artifacts are published. Newly created test and backup-rehearsal databases are retained without automatic deletion. No Git commit or push was performed for this change.
