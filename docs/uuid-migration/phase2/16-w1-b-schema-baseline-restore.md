# W1.5A — B schema-only export, D restore and structural parity

**CURRENT OUTCOME: SCHEMA BASELINE IMPLEMENTED / ACCEPTED.** Actual B schema-only export, private archive review, one committed D-only restore and independent normalized structural parity passed. All72 restored tables are empty; Alembic table exists with zero rows, so revision079 remains UNESTABLISHED pending W1.5B. The following earlier blocked records remain historical; the final authorized execution record is appended below.

**LATEST OUTCOME: authorization RECEIVED; fresh preflight executed; BLOCKED at the ownership gate. No export or restore attempted.** One source object-owner role is absent in D; no ownership/ACL exception or role creation is approved. See the authorized continuation below. The following offline-preparation outcome remains historical evidence.

**Outcome: BLOCKED — required separate operator authorization absent. Offline preparation complete; export, restore and parity NOT EXECUTED.** W1.4g's historical D infrastructure acceptance is preserved. No new B/D connection, Docker inspection, credential read, archive or private restore evidence was created.

## Authorization and scope

Section 1 of the W1.5A request explicitly requires this separate affirmative confirmation before B access or D mutation:

> I authorize W1.5A to read and export schema definitions only from the verified local development Database B, restore those definitions into the verified disposable Database D, and perform read-only structural parity checks. I do not authorize business-data export, changes to B, Alembic stamping, or UUID migration execution.

The task contains that required template, but the operator has not separately supplied the confirmation. W1.4g's GO to request authorization does not satisfy it. Stop at offline preparation; no runtime permission is inferred from this report or tracker update.

Future authorized scope would be the actual complete relevant B schema, not only the six UUID tables; schema definitions alone restored into exact D with no business data, sequence values or revision-marker row. Expected future mutations are D schema objects only. This task's actual database/runtime mutation count is zero. Integer PK/FK relationships and B's actual drift must be preserved; no UUID columns, indexes, backfill, migrations or unrelated repair.

## Current offline checks and historical target evidence

Required tracker, W0.1, W1.1, W1.2, W1.4g and complete Phase 1 PostgreSQL report were read. W1.5A authority, targets, prerequisites, expected mutations, stopping conditions and acceptance criteria were recorded IN PROGRESS in the tracker before preparation.

| Item | Evidence / current status |
| --- | --- |
| Git | Branch `feat/native-user-management`; HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`; verified this task. Existing dirty tree snapshotted: 63 modified/untracked file contents including tracker; 20 tracked modified files. No fetch, branch/index/history change or fresh origin-equivalence claim |
| B selection | Historical managed launcher selects `.env.dev.local`, independent of root `.env` A. [W0.1 selection](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/00-deployment-target-readiness.md:50). Neither protected file opened in this task; exact source database/user/current credential source not freshly verified or printed |
| B endpoint/revision | Historical authorized local endpoint 55439, revision `079_lifecycle_provider_verification`; A historically055 on the same PostgreSQL instance. [W0.1 evidence](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/00-deployment-target-readiness.md:73). Port/name alone cannot distinguish them. No fresh B identity/revision/schema query |
| B catalog sanity evidence | Historical 72 tables including Alembic, 1,143 columns and143 FKs. Counts are not a current fingerprint or full parity proof. [W0.1 catalogs](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/00-deployment-target-readiness.md:92), [Phase 1 comparison](/Users/ferozebasha/sbom/docs/uuid-migration/phase1/04-postgresql.md:13) |
| Accepted D | Historical W1.4g ACCEPTED at2026-10-16 16:08:55 UTC: database uuid_w1_d_rehearsal/user uuid_w1_d_bootstrap, host127.0.0.1:56041, actual PG16.15, system identifier `7697252084555804711`; no application relations/Alembic table. [Acceptance](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/15-d-readonly-acceptance-final.md:1). Not reconnected or reverified here |
| D infrastructure pins | Container `fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e`; original volume sbom-uuid-w1_d_pgdata; sole network sbom-uuid-w1_d_access; local daemon `1f8c7fe5-5972-4adc-8d6e-363a38572be1` via unix:///Users/ferozebasha/.docker/run/docker.sock. Full image/network/storage pins remain in W1.4g; no Docker commands this task |
| Compose baseline | Previously reviewed SHA256 `13e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab`; preservation check only, not config/runtime validation or new D acceptance |
| Tools/capacity/privileges | PG16-compatible dump/restore tooling, source/destination privileges, disk/WAL/temp capacity, extension dependencies and owner/ACL topology NOT VERIFIED. No PostgreSQL tool execution or capacity measurement |
| Export/restore/parity | NOT RUN. Archive path/hash/size, source fingerprint, restore transaction/commit/error and parity differences are N/A, not successful or empty results |

No current database identity is inferred from historical evidence. Fresh preflight is mandatory after explicit authority; do not reuse W1.4g acceptance as an indefinite freshness assertion.

## Critical runbook conflict: ownership and grants

[W1.2 restore proposal:99](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/03-disposable-target-preparation.md:99) suggests `no-owner/no-privileges` remapping. **That proposal is not approved by this task.** W1.5A expressly forbids silently omitting ownership/grants and requires an explicit reviewed parity exception if D's role topology cannot reproduce them. Prior report remains unchanged as historical design evidence.

Before restore, inventory schema/object owners, ACLs/default ACLs, sequence ownership links, referenced roles, SECURITY DEFINER owners and RLS policy roles. Compare them with D's approved role topology and public-schema owner/privileges. The D bootstrap role differs conceptually from B's source role; an actual incompatibility is UNVERIFIED until authorized inspection. Do not assume a role exists or create one, grant membership, elevate privileges, suppress archive objects or select no-owner/no-acl/no-privileges merely to make restoration pass.

If exact ownership/ACL fidelity is impossible under existing approved roles, stop before restore. Present the exact proposed role mapping and security consequences for explicit exception approval. Table/sequence ownership dependencies and SECURITY DEFINER/RLS semantics must still be preserved or individually reviewed. No exception is granted here.

D already has normal `public` and `plpgsql` objects. Privately review how the actual archive handles those existing definitions, ownership and ACLs before restore; do not ignore duplicate-object errors, remove the existing schema or silently suppress entries to obtain success. This compatibility is unverified, not a confirmed archive defect.

## Future execution gates — plan only, no commands executed

| Gate | Required action after authorization | Stop / required evidence |
| --- | --- | --- |
| A — authority/credentials | Receive the exact separate confirmation. Identify and explicitly approve the protected source of B credentials and narrowly scoped parsing of `.env.dev.local`; no application imports, automatic dotenv or root-A fallback. Keep values private and use non-URL explicit connection settings with isolated libpq configuration | Missing approved credential provenance or redirected/nonlocal target stops access; do not print database URL, process environment or credentials |
| B — source identity | Verify local Docker/resource mapping and actual B database/user/cluster, explicit loopback55439, revision079, server version and normalized relevant catalogs using bounded read-only sessions. Compare parsed intended B selection to connected identity, excluding A/production. Capture source fingerprint/revision and stability window | Wrong target/current revision, unexpected objects/drift or inability to establish identity stops. Historical totals are sanity checks only; do not repair B |
| C — D readiness | Reverify exact local daemon/container/image/volume/network/loopback publication/password metadata, SQL database/user/systemID7697252084555804711 and control-file/storage correlation; no application objects or Alembic baseline. Inspect actual tools, available disk and permitted extension/role requirements; record existing SBOM resource/process metadata | Any unknown/drift, nonfresh D, missing tool/capacity budget or privilege mismatch stops; no recreation, port fallback or credential change |
| D — bounded export | Use reviewed PG16-compatible pg_dump, explicit schema-only plus custom format, entire agreed application dependency graph including Alembic structure. Controlled read-only source settings and bounded connection/statement/lock budget; no data/large objects/sequence state/globals/roles/password hashes/database creation. Private outside-checkout0700 directory, exclusive0600 archive/evidence, no inherited PG*/dotenv or credential-bearing arguments | Source activity/revision/schema must stay within reviewed window. Record tool version, safe operation/options/times/result, archive size/SHA256 and fingerprint; do not print archive/definitions. Scope not silently reduced to six tables or public-only without complete dependency review |
| E — private archive review | Offline pg_restore TOC and generated SQL inspection; match every relevant schema object/dependency to source catalogs. Verify no TABLE DATA/SEQUENCE SET/BLOB data, business COPY/INSERT/setval or unrelated DB target. Review functions/extensions/custom types/defaults/checks/index expressions/triggers/rules/event triggers/policies, FDWs/subscriptions and potential network/security side effects | Schema-only is not automatically safe: extension installation, handlers or object expressions can execute code. Stop for destructive operations, unsupported transactional objects, external connectivity, unsafe extension or unapproved ownership/role/ACL need. Do not accept a TOC check alone as SQL safety review |
| F — one D restore | Reconfirm exact D just before mutation. One schema-only pg_restore, single transaction, exit-on-error, no parallel jobs, bounded statement/lock/connection timeouts. Preserve owners/grants unless an exact exception was separately approved. No clean/create/drop-database/disable-triggers/object suppression or ORM create_all | First error stops. Confirm rollback versus unknown commit from actual evidence; no blind rerun, cleanup, volume deletion or cluster recreation. No source-side restore connection |
| G — independent parity | Normalize only catalog representation/order/OIDs, not security semantics; compare B and D actual full agreed object graph, including deliberate B drift. Recheck source revision/fingerprint after export/parity and D system/storage identity | Any unexpected/unknown diff, changed source revision/schema, data presence or uncertain outcome prevents acceptance. No marker insertion/stamp or automatic repair |
| H — preservation/report | Compare selected existing container IDs/start/state/images/mounts/ports/networks/volumes and process birth tuples; account expected private artifact directory changes and compare ID sets without enumeration order. Record all operation outcomes and safe hashes/differences | No A data access; B receives read-only schema/catalog access only. Metadata equality is not exhaustive data-equivalence proof; no service restart or silent preservation claim |

These are review requirements, not an executable invocation or a validated runner. Concrete source identities, protected connection mechanism, operation budgets and archive object/security manifest remain to be reviewed. No real approval manifest or scripts were created.

## Structural parity and no-data acceptance matrix — NOT RUN

| Domain | Required normalized comparison / evidence |
| --- | --- |
| Schemas and tables | Relevant namespace set/ownership/ACLs; ordinary/partitioned/foreign tables, partition bounds/inheritance/persistence/storage parameters/tablespaces and applicable dependencies. Reject unapproved foreign connectivity |
| Columns and types | Column order/name, PostgreSQL type/schema/typmod/domain/enum definitions, nullability, defaults, generated/identity flags, collation and applicable attributes. Do not replace physical schema with ORM declarations |
| Constraints | PK/FK/check/unique/exclusion column order/expression, referenced table/columns, match/delete/update actions, deferrability, validation/enforcement state and inheritance behavior |
| Indexes | Names/table/dependencies, method, keys/includes/order/opclasses/collations, predicates/expressions, uniqueness/null handling, valid/ready/live and constraint attachment. Normalize generated OIDs only, never drop material differences |
| Sequences | Definitions/type/bounds/start/increment/cache/cycle, schema/object ownership and owned-by table/column links; do not export/restore sequence last/current values or call nextval/setval |
| Executable/dependent objects | Views/materialized-view definitions and unpopulated state, functions/procedures/signatures/language/body/security/configuration/owner/ACLs, triggers/enabled state, rules, extensions/version/schema, RLS enable/force and complete policies/roles; applicable types/collations/operators/text-search/dependencies included in agreed inventory. Sensitive bodies stay private; compare canonical definitions/hashes without public contents |
| Security and environment | Owners, ACL/default ACL, grants, policy roles, extension/public schema requirements and tablespace/role topology; distinguish exact match from each explicitly approved environment-specific exception. No exception exists yet |
| Data absence | Archive review excludes data entries and business writes; verify every restored application base table empty using bounded existence probes, including partitions as appropriate; inspect materialized/foreign-object implications before restore. No business-row content export or logging; no estimates-only empty-data claim. Read Alembic table only if present and confirm zero rows |
| Source stability/preservation | Capture B revision/fingerprint before/after within reviewed consistent snapshot/window; compare selected infrastructure metadata. Schema dump's snapshot and later catalog snapshots are not automatically the same snapshot. Stop if source changes invalidate agreed baseline/parity; no source quiescing or DDL lock escalation authorized |

Known drift to reproduce as actual B: missing `vex_documents.superseded_by_id → vex_documents.id` FK (ORM SET NULL), unbounded `report_subscription.deactivated_by` versus ORM128, plus recorded index/default/constraint differences. [W0.1 drift](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/00-deployment-target-readiness.md:111), [Phase 1 B differences](/Users/ferozebasha/sbom/docs/uuid-migration/phase1/04-postgresql.md:246), [W1.1 baseline](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/02-w1-additive-schema-design.md:13). A fresh source difference requires disposition rather than treating the historical inventory as today's truth. No missing FK repair is part of import.

Schema-only restore may create `public.alembic_version` structure with zero rows. That is **revision UNESTABLISHED**, not revision079. A marker is never inferred from B's source revision or a matching table graph. No Alembic command, stamp or marker INSERT is included or authorized by W1.5A.

## Actual result and next gate

| Required execution evidence | This task |
| --- | --- |
| Separate affirmative operator authorization | **ABSENT / BLOCKING** |
| Fresh B identity/credentials/revision/fingerprint | NOT RUN |
| Fresh D identity/freshness/storage/tool/capacity check | NOT RUN; W1.4g historical ACCEPTED preserved |
| Archive/TOC/SQL/security/ownership review and hash/size | NOT RUN / no archive exists from this task |
| D restore and confirmed transaction outcome | NOT RUN; no D objects created |
| Structural parity / empty data / empty marker | NOT RUN, not PASS |
| Live infrastructure preservation | NOT REPEATED; no Docker/process/runtime actions. Repository content preservation checked separately |
| Application/migration tests | NOT RUN |

**W1.5A BLOCKED. NO-GO for export/restore/parity execution until the required confirmation arrives.** Then repeat fresh preflight and resolve credential/ownership/privilege/archive-safety gates before any restore. Do not automatically begin execution because this offline plan is complete.

Exact authorized outputs: created this report; updated [master tracker](/Users/ferozebasha/sbom/docs/uuid-migration/MIGRATION_MASTER_TRACKER.md:1). No prior report, staged W1.6 source, active Alembic file, application/runtime/Compose configuration, credential or Git history changed. No database connections, pg_dump/pg_restore/psql/Alembic, Docker commands, service actions, business-data handling or migration/application tests executed.

Final offline verification:62 other pre-existing file contents, tracked binary diff, Compose hash and branch/HEAD preserved;26 historical task-ledger rows and all12 Phase1 issue rows retained verbatim;53 local links/line locations and report/tracker whitespace verified. git -c core.fsmonitor=false diff --check passed. No application tests, database/Docker/credential/tool/archive actions. W1.5A BLOCKED on separate authorization; D historical infrastructure ACCEPTED remains unchanged.

## Authorized continuation — source/target preflight and confirmed ownership blocker

Operator confirmation received verbatim:

> I authorize W1.5A to read and export schema definitions only from the verified local development Database B, restore those definitions into the verified disposable Database D, and perform read-only structural parity checks. I do not authorize business-data export, changes to B, Alembic stamping, or UUID migration execution.

Tracker updated IN PROGRESS before access. The authorization clears the earlier missing-confirmation blocker only. This continuation preserved the same branch/HEAD and dirty work; no role/topology/ownership exception was inferred.

### Actual preflight operations and results

| Check | Actual executed evidence |
| --- | --- |
| Local infrastructure | Fresh filtered Docker/host snapshot2026-10-16T16:23:28.214445Z matches accepted W1.4g final snapshot: exact local daemon/socket, D/container/image/original volume/access network/loopback publication/private credential and existing SBOM resource/process identities. Dictionary key order normalized and inventories compared as identifier sets; zero actual differences |
| Source selection | Privately parsed only task-named protected `.env.dev.local` with interpolation disabled; O_NOFOLLOW/fstat verified unchanged UID501/mode0600 regular file. Explicit scheme/local host/port55439 and fixed managed-development database identity match scripts/dev.py:33 and426. No app/settings import, root .env/ambient PG*/dotenv fallback or configuration mutation. Credentials/connection string and sensitive configured identities suppressed from public evidence |
| B authenticated identity | One explicit loopback source connection; actual database/current_user/session_user match privately selected B. Repeatable-read read-only transaction verified on; server major16, server bridge172.18.0.2:5432 matches existing SBOM container endpoint. Source system identifier differs from pinned D and is retained privately; no A connection |
| B revision / drift | Exactly079_lifecycle_provider_verification from bounded version-marker read. Missing superseded_by_id VEX FK remains absent; no repair. Actual72 tables,1,143 base-table columns and143 FKs; no user routines/triggers/rules/policies/event triggers/foreign servers/subscriptions observed in inspected catalogs; only normal plpgsql1.0 extension |
| D authenticated identity | One explicit D read-only connection; exact database/current/session user uuid_w1_d_rehearsal/uuid_w1_d_bootstrap, server160015/16.15, bridge172.20.0.2:5432, data_directory /var/lib/postgresql/data/pgdata, systemID7697252084555804711. Zero user relations, public.alembic_version absent. Same exact accepted Docker volume/mount/exclusive attachment |
| Compatible tooling | On explicit local Docker endpoint, exact D container ran read-only pg_dump --version and pg_restore --version, both PostgreSQL16.15 Debian16.15-1.pgdg13+2. These did not export or restore anything. Host PATH resolves PostgreSQL18 tools; not chosen or executed for dump/restore |
| Capacity | Host private-artifact filesystem had54,089,256,960 free bytes. Target-volume free capacity/WAL/temp budget not completed before ownership stop; no sufficient-capacity assertion or restore estimate |
| Owner gate | **BLOCKED:** source owner alias SOURCE_OWNER_1 is absent from D pg_roles. It owns644 source relations:72 tables,60 sequences,512 indexes (index ownership follows owning tables). No user routines require owner transfer. Real role name is in protected catalog evidence, not disclosed as a configuration value here |
| Security context | Source and D public-schema owner is normal pg_database_owner; plpgsql1.0 present on both. This does not waive per-object ownership, extension-owner/ACL/default-ACL/grant review or approve an exception. No role creation, SET ROLE/grant/elevation or no-owner/no-privileges suppression performed |
| Stop/lifecycle | Ownership gate emitted BLOCKED, then both read-only transactions/connections closed. No dump process, TOC/SQL generation, archive, restore, D mutation or automatic retry. No SQL error/SQLSTATE: this is a verified precondition failure, not a failed restore |

Connection settings were explicit, with clean env-i process, no PG* variables, passfile /dev/null, explicit hostaddr127.0.0.1, connect timeout5s, statement timeout10s, lock timeout1s, default_transaction_read_only on and search_path pg_catalog/client UTF8. B password came only from protected selected configuration; D password only from its unchanged dedicated private file. Neither password appeared in arguments, environment, logs or report. No business-record query; source Alembic marker is the specifically authorized metadata exception.

Source catalog fingerprint **905bd7819a87ef48e643ec932352e6713ddc58f558e72a3498e8c1f6620e05a7** covers the captured sorted preflight catalog representation: schemas/relations/columns/constraints/indexes/routines/types/extensions/default ACLs/policies/triggers/rules/sequences and selected external/event objects. This is a preflight snapshot fingerprint, not an archive hash, complete agreed parity fingerprint or proof of source stability after the snapshot. No post-export source comparison exists because export never began. No sequence values were read. The initial1968 column-metadata count included index attributes; filtering to base-table relations yields1143, matching historical B. This is counting scope, not evidence of schema drift.

### Private evidence retained

New private directory outside checkout, UID501/mode0700:

`/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w15a-20261016T162520331271Z`

- `preflight.jsonl`: labels/status/timestamps/sanitized stop evidence, final preservation and counting-scope clarification;0600, no credentials.
- `catalog-preflight.private.json`: actual protected source catalog and owner-role identity/D-role evidence,0600; SHA256 **4bccf86eca8bc25a43f856f11ba036dfde5ba1680d0113429a2af1f2d1cb3b20**. Treat definitions/role metadata as private; contents not printed in tracker/report.
- `preservation.private.json`: safe before/after infrastructure snapshots, result and comparison,0600.

No dump archive exists from this task; archive size/hash and TOC/SQL security review are **N/A / NOT RUN**. Private files were created exclusively with O_EXCL/O_NOFOLLOW and fsynced. No persistent credential file was created or changed.

### Preservation and final disposition

Final filtered inventory2026-10-16T16:25:52.786007Z matches before for exact existing D, sbom-postgres-1, Redis, Mailpit, original volumes/networks/mounts/ports/start/state/images, launcher/API/worker/Beat/frontend process birth/executable/ownership tuples, environment/password-file metadata and full identifier sets. Four containers,26 volumes,six networks unchanged. Parent directory size160→192, links5→6 and mtime/ctime changed solely in the expected new evidence-directory creation window; parent inode/owner0700 and password metadata unchanged. No Docker resources or application services modified. Selected resource metadata equality is not exhaustive proof that live B application data did not change independently; no data-equivalence claim or source business scan.

**W1.5A BLOCKED on a confirmed unapproved restore dependency. D remains fresh and infrastructure ACCEPTED; structural baseline NOT IMPLEMENTED / NOT ACCEPTED.** Structural parity, empty-restored-data checks and restore commit/rollback evidence NOT RUN. D Alembic table is still absent, not revision079. The historical offline-only outcome above is superseded only as to received authority and executed preflight.

Smallest next decision: explicitly review an ownership/ACL parity exception mapping the privately identified SOURCE_OWNER_1 to D's existing uuid_w1_d_bootstrap, including all affected security/ownership/grant semantics, or authorize a separate D-only role-topology preparation plan. Neither is approved here. No role creation, blanket ACL omission or ownership remapping follows automatically. After an exact reviewed decision, refresh all gates and privately review the actual full schema archive before any single-transaction restore. Other archive/public-schema/extension/capacity/security compatibility remains unverified; owner-name compatibility alone will not prove restoration safety.

No source changes, business-data export, schema import, revision establishment, Alembic/UUID migration/index/backfill, application tests, Docker lifecycle or Git delivery occurred. Exactly the existing phase2/16 report and master tracker updated, plus the three protected evidence files outside the repository. Earlier reports/Compose/application/runtime/staged migration sources preserved. Next gate is ownership/ACL disposition approval, not079 stamping or UUID080–085 execution.

Authorized-continuation final verification:62 other pre-existing file contents and tracked binary diff preserved;27 prior task-ledger rows,12 Phase1 issue rows and original phase2/16 offline report retained;54 local links/line locations, whitespace, Compose hash, branch/HEAD and private0700 directory/three0600 evidence files verified. git -c core.fsmonitor=false diff --check passed. No archive exists, no restore or migration/application tests executed. W1.5A BLOCKED on confirmed ownership dependency; D infrastructure acceptance retained, B-shaped schema baseline unimplemented.

## Final authorized continuation — real export, restore and accepted parity

**W1.5A IMPLEMENTED / ACCEPTED (schema baseline only), 2026-10-16.** This is actual database execution, not documentation-only completion. All five requested stages were completed. No W1.5B marker establishment, UUID migration or application test followed.

### Narrow authority and stop conditions

The operator explicitly approved existing D `plpgsql` extension ownership remaining different from B **only** if version/schema/functional definition/relevant privileges/security were compatible; prohibited owner/privilege changes or generalizing that exception to application objects; reaffirmed schema-only B export/D restore/parity authority and required real execution through acceptance. The tracker recorded this authority, prerequisites, expected D-only mutation, acceptance and failure boundaries IN PROGRESS before execution. Earlier missing-confirmation/role/extension-owner blockers remain historical outcomes.

The approved exception was applied only to the extension owner. No role changes, memberships, blanket --no-owner/--no-acl/--no-privileges, owner remapping, source modification, database recreation/cleaning, trigger disabling, stamp/marker INSERT, UUID080–085/index/backfill or deployment/Git delivery. Restoring existing B baseline index definitions was part of the full-schema restore; no future UUID index was created.

### Stage1 — fresh targets, security, tools and capacity: PASS

| Gate | Actual evidence |
| --- | --- |
| Git / Compose | Branch feat/native-user-management; HEAD2f48ff835d9e692fc84b31aaa951aad2495888ac; dirty tree preserved. Compose SHA25613e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab unchanged; no fresh origin-sync claim |
| Local infrastructure | Preflight2026-10-16T16:46:05.591545Z: same explicit local Docker Desktop socket/daemon, exact D container/image/original dedicated volume/sole d_access network/127.0.0.1:56041 and existing SBOM identities. No remote daemon/resource lifecycle action |
| B source | Protected .env.dev.local selection parsed without interpolation or fallback; exact intended local55439 database/user matches authenticated current/session identity and source-container172.18.0.2:5432 mapping. B cluster matches prior protected identity and differs from D; actual16.15 and exact079_lifecycle_provider_verification. No root-A access or process-environment credential discovery |
| D target | Existing containerfb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e; actual16.15, database uuid_w1_d_rehearsal/current and session user uuid_w1_d_bootstrap, cluster7697252084555804711 and expected PGDATA. Pre-restore application relations/Alembic table absent |
| Restricted role / maintenance authority | Exact protected source owner exists as OID16389, NOLOGIN/no password/no elevated attributes/no memberships, unchanged. Existing bootstrap already has required maintenance authority; source connection already has read/catalog and dump access. No elevation or grant |
| Extension | Only normal plpgsql1.0 in pg_catalog, nonrelocatable/no config-table payload. Source/D extension descriptor, language trust/ACL/handlers and all three handler-function definitions/security/configuration/privileges compare equal. Descriptor SHA2560c78e1933f91879ce3def0e14196feccae92d5719c01b0c41dad2732f47fb05c. Source owner differs from retained D bootstrap owner only; exact approved exception. No extension command/owner/privilege change in archive or restore |
| Source schema |72 tables/1,143 base-table columns/512 indexes/60 sequences/143FKs. Known missing VEX superseded_by_id FK still absent. No user routines/triggers/rules/views/materialized views/RLS policies/external servers/wrappers/subscriptions/publications/event triggers/custom collations/operators/opclasses/families/text-search definitions/security labels/default ACLs in agreed catalogs. Existing schema/object owners and ACLs reviewed |
| Tools / capacity | Exact B and D containers expose native PG16.15 pg_dump/pg_restore. Host candidates17.5/18 were not used to dump/restore. D filesystem df showed218,598,568KiB free (about208GiB); private host filesystem exceeded1GiB free. Archive380,123 bytes. Resource checks supported this bounded schema-only operation, not a future backfill/WAL capacity benchmark |

All host connections used explicit loopback host/hostaddr/port/database/user, existing dedicated protected credentials, clean env-i process/no ambient PG*/dotenv/application engine, passfile/dev/null, bounded connection/query/lock timeouts and verified read-only transactions. Passwords were read from their existing protected sources and passed in memory/private stdin only; never copied into arguments, environment, new files, logs or archive contents. No credential generation/rotation or source business-record query. Administrative identities are not copied to D as login/superuser roles.

### Stage2 — complete real schema archive and private safety review: PASS

A read-only REPEATABLE READ B transaction captured the catalog snapshot and exported a PostgreSQL snapshot identifier. Native PG16.15 pg_dump imported that same snapshot while the transaction remained open; schema capture and archive therefore share a source snapshot. The dump connected through exact verified source container5d8b97a004f68e02095f0bec101c3191d1910eee06d2edcda4b98fe7c1c1433f loopback5432, which is the pinned source instance behind host55439. Explicit selected B database/user and password authentication; no implicit source database selection.

Executed operation/options, with sensitive selected names replaced by labels here:

```text
<verified-local-docker> exec -i <exact-B-container> env -i <controlled-nonsecret-PG16-path/timeouts>
  pg_dump --host=127.0.0.1 --port=5432 --username=<verified-B-user>
  --dbname=<verified-B-database> --password --schema-only --format=custom
  --no-large-objects --lock-wait-timeout=1000 --snapshot=<shared-read-only-snapshot>
```

No table/schema subset filter, globals/role dump, data/sequence-state export, ownership/ACL suppression or CREATE DATABASE option. Forced password prompt read privately through stdin without a TTY; no password-bearing argv/environment/passfile. This uses PostgreSQL's frontend stdin prompt fallback, not a credential file created in either container. [PG16 frontend prompt source](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/common/sprompt.c).

| Artifact | Actual evidence |
| --- | --- |
| Custom archive | B-schema-only.dump, **380,123 bytes**, SHA256 **8d82d9a24373d62af0be9231ffe4ba695b67142a139b8fc1a3908966b7e2a5ec** |
| Complete unfiltered TOC | archive-toc.private.txt; SHA25631379f872a0e75bd9b6898e86461c39c11673737278a8bd4645a7ffe87b5d7c2 |
| Generated schema SQL | archive-schema.private.sql;8,542 lines/1,051 statements; SHA2569f16ab39e1d49d0843ba002c5f3aaf20e258836e16d4b460ca29f8691a715750; kept private |
| TOC coverage |72 TABLE,60 SEQUENCE,60 SEQUENCE OWNED BY,60 DEFAULT,111 CONSTRAINT,401 INDEX,143 FK CONSTRAINT. PK/unique constraints account for the other111 indexes:512 total. Composite/array types derive from table definitions; no separate custom enum/function/view objects were present |
| Data/external/unsafe entries | Zero TABLE DATA/SEQUENCE SET/BLOB/materialized-data/function/procedure/trigger/rule/policy/external/subscription/event/security-label entries; no business COPY/INSERT, setval, role/database creation, cleanup or unsafe execution operation |
| Ownership / grants |132 application owner statements retained for72 tables/60 sequences; derived indexes/types follow ownership. No blanket suppression. Source explicit relation/type ACLs/default ACLs absent; public schema ACL matches pre-existing D and survives unchanged. No custom grant omitted |

Private SQL review used a string/comment/identifier-aware lexer with a narrow statement allowlist and source-catalog cross-checks: standard session SETs/search_path setup, CREATE TABLE/SEQUENCE, application ALTER OWNER/default/constraint/sequence ownership operations and existing baseline indexes. No unreviewed executable function body, external extension code, trigger disabling, database/role DDL or object suppression. Source CHECK/default/index expressions use the captured ordinary trusted PostgreSQL object graph; no custom execution/external dependency discovered. This was source review, not a claim that lexical review is a general PostgreSQL parser.

Native pg_dump intentionally omits initdb extension definitions while checking ACL differences, so the TOC has no plpgsql CREATE EXTENSION or ACL delta. It was not filtered out by this task; compatible existing plpgsql was independently verified before/after and left untouched. [PG16 selectDumpableExtension policy](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/bin/pg_dump/pg_dump.c). Existing public schema/ACL also matched independently. No application object was skipped to make restoration work.

### Stage3 — one real D-only restore: COMMITTED

Immediately before mutation, independent read-only checks reconfirmed B schema unchanged from shared snapshot, pinned D still empty with correct role/cluster, and extension compatibility unchanged. Full D role/membership state captured. Archive copied byte-for-byte into a new root-owned0700 directory in D's temporary container filesystem, file0600; sha256sum matched the host archive. No credential file was copied, no image/resource recreation or persistent storage substitution. This private restore artifact is intentionally retained, not automatically cleaned up.

Executed exactly one restore:

```text
<verified-local-docker> exec -i <exact-D-container> env -i <controlled-nonsecret-PG16-path/timeouts>
  pg_restore --host=127.0.0.1 --port=5432 --username=uuid_w1_d_bootstrap
  --dbname=uuid_w1_d_rehearsal --password --schema-only --single-transaction
  --exit-on-error --verbose /tmp/w15a-final-20261016T165049746829Z/B-schema-only.dump
```

Explicit session read-write for the approved restore only; statement timeout30s, lock timeout1s, idle-transaction timeout120s, connect timeout5s and overall client timeout120s. No parallel jobs, --clean/--create, --no-owner/--no-acl/--no-privileges, --disable-triggers, SET ROLE or retry. Native schema SQL executed against D only. [PG16 single-transaction restore semantics](https://www.postgresql.org/docs/16/app-pgrestore.html).

**Start16:54:41.845887Z; exit0 at16:54:42.548445Z. Commit acknowledged by successful pg_restore, then independently verified from new read-only connections.** Stdout0 bytes; verbose stderr70,119 bytes of prompt/progress retained privately. No SQL error, rollback or uncertain database outcome occurred. No automatic retry or cleanup. These timestamps are execution evidence, not a performance benchmark.

### Stage4 — actual independent structural parity: PASS after representation normalization

Independent new B and D read-only transactions compared31 catalog categories: database encoding/collation properties, schemas/ACL/comments, relations/owners/ACL/RLS/storage properties, all columns/types/defaults/nullability/identity/generated/collation/storage/comments, PK/FK/check/unique/exclusion details, indexes/validity, composite/array/types/enums, sequences and owned-by links, routines, triggers, rules, views/materialized views, policies, default ACLs, inheritance, collations/operators/opclasses/families/text search, applicable external/publication/event/security objects, ordinary dependencies and shared-role ownership dependencies. Full actual B catalogs were used, not ORM declarations or six-table-only comparisons.

| Check | Actual result |
| --- | --- |
| B source stability | Pre-export shared-snapshot and independent post-restore catalog fingerprints identical: **1d35d1651f7bf3acd348368f35751434c17371276407538599a946e1580abb70**; B still079 and same source cluster. Source data not scanned or mutated |
| Raw D catalog fingerprint |990a33b059b58d36f7136e3d31318ff3a97cf89d6a9a11cc687b38f1bdafe42f; raw representation differences retained privately, not hidden or claimed byte-identical |
| Normalized source/D fingerprint |Both **e3e60c1a3c30fdcbe54d43d5f36d30fa88096a3aabe4af56f095f86dd4366225**;31 categories, **zero unexpected structural/security differences** |
| Application owner / ACL / role state |Exact protected source owner name preserved for application objects; schemas/ACL/default ACL/security settings match. Restricted owner OID16389/attributes/password absence and all D roles/memberships unchanged from pre-restore. No role/grant changes |
| Table graph |72 tables,1,143 base-table columns,512 indexes,60 sequences,143 FKs on both; sequence definitions/ownership preserved without copying values |
| Known source drift |Missing vex_documents.superseded_by_id FK remains absent in D; report_subscription.deactivated_by remains unbounded varchar; other original index/default/constraint properties retained. No ORM repair or unrelated constraint addition |
| Empty data |Bounded EXISTS probes over every restored base table: **72/72 empty**, including Alembic. No target business records displayed; no source business data read/exported |
| Alembic |public.alembic_version definition restored, **zero rows**. Target revision **UNESTABLISHED**, not079; no marker INSERT/stamp/upgrade |
| Extension |Functional/security/privilege descriptor still identical; plpgsql1.0/pg_catalog retained, only explicitly approved owner difference. No owner/privilege/definition change performed |

#### Raw difference reconciliation — representation only, no extra parity exception

The initial raw comparison recorded PARTIAL differences in four categories, retained in parity-result.private.json/parity-differences.private.json. Investigation performed no DDL or restore retry. Every difference was narrowed and independently verified before acceptance:

1. **24 CHECK definitions and one partial-index predicate:** PostgreSQL deparse/reparse distributed a varchar-array-to-text-array cast onto literal elements. Canonicalization accepts only those exact varchar literal-array forms, retains literal values/order and every other operator/expression token.29 unique literal-array sets passed bounded read-only equivalence checks on PG16; varchar→text cast verified binary/implicit in pg_cast. No general expression rewriting or CHECK removal.
2. **572 internal RI-trigger dependency names:** only generated numeric OID suffix differs. Normalization preserves trigger kind, table/constraint identity and multiplicity. Additional independent catalog comparison matched all572 complete internal trigger definitions/event flags/functions/deferral/enabled state after replacing those suffixes. No user trigger was disabled or ignored.
3. **132 shared owner edges:** B's initdb bootstrap owner is pinned OID10, so pg_shdepend does not store its owner dependency rows; D's same-name restricted owner is OID16389 and explicitly records72 table/60 sequence owner edges. Both application owners match by name. Canonicalization reconstructs the same logical owner edges from actual owner catalogs and checks exact extra-edge set; it does not omit grants, owners or security differences. PostgreSQL documents omission of dependencies to pinned objects. [PG16 pg_shdepend](https://www.postgresql.org/docs/16/catalog-pg-shdepend.html).

These are catalog/deparser/OID representations, not environment-specific structural or security exceptions. The only approved exception remains plpgsql extension owner. All raw evidence and initial comparison outcome are retained; normalized acceptance supersedes only the unclassified raw mismatch. No failed migration/SQL operation was recast as successful.

Offline harness issues were corrected transparently before final acceptance: initial expectation of an EXTENSION TOC definition contradicted native initdb policy; an unnecessary byte-equality check on regenerated SQL wrapper output was removed in favor of reviewing the original retained artifact; case-mismatched whitelist checks corrected; a duplicate status keyword in the post-check logger was fixed after all read-only assertions/artifacts had succeeded. No archive edits, source change, restore repetition, schema correction, relaxed safety condition or extra environment exception resulted. Exactly one export and one restore occurred; auxiliary offline SQL rendering was repeated for review.

### Stage5 — preservation, retained artifacts and acceptance

Preflight16:46:05.591545Z / final17:00:11.870315Z selected Docker/host/process metadata matched: same existing SBOM PostgreSQL/Redis/Mailpit container IDs/images/start/state/mounts/ports/attachments, sbom_postgres_data/sbom_redis_data/sbom_default, exact D image/original volume/access/private networks, same launcher/API/worker/Beat/frontend OS birth/executable/ownership tuples and environment/password-file metadata. Full sorted sets remain4 containers/26 volumes/six networks. No resource lifecycle, application-service restart/reconfiguration or A/production access. D's schema and private temporary archive are the intentional changes; data-volume identity is preserved, not asserted byte-unchanged.

New private evidence directory UID501/0700 outside checkout:

`/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w15a-final-20261016T165049746829Z`

All24 files0600, including archive/TOC/SQL, protected catalog snapshots, extension comparison, restore result/private progress, raw/normalized parity, trigger comparison, infrastructure preservation, private workflow source and execution/manifest evidence. Source passwords are never retained. Total private artifacts about6.3MB. Private manifest SHA256 **4ea21e45be604302653fb1ce616a0dcf4cbf69d0d6a662f497dd0a9d925839ef**; parity acceptance artifact SHA256 **3887ad8c9c8343b0d3ddd5792c213047fdeecee850f24913e78f62ebfa6f7f9a**. The manifest hashes the preceding23 files; it does not hash itself. Further inline review/normalization source remains in task tool-call evidence.

D also retains root0700 `/tmp/w15a-final-20261016T165049746829Z` with the same0600 archive/hash, outside PGDATA. No automatic cleanup, secret file, Docker mount or network was created. Parent host directory metadata changed consistently with the one new private evidence directory; original inode/owner0700/password metadata preserved. Selected metadata/source schema equality does not certify that the live application's business data never changed independently; no business-data equivalence claim.

**Final W1.5A schema baseline: IMPLEMENTED / ACCEPTED.** Real export, complete archive review, one committed transactional restore, independent normalized structural/security parity and empty data/marker checks passed. B received only authorized read-only catalog/schema access and dump locks; no task-issued source mutations. Existing SBOM infrastructure preservation passed. No blanket owner/ACL exception or application object omission.

**Next gate: W1.5B, separately authorized revision079 establishment after reviewing this accepted evidence.** Do not run it automatically. D has schema equivalent to the captured079 source baseline but no established revision row. Staged UUID080–085/index/backfill artifacts remain NOT EXECUTED / NOT ACCEPTED; no application tests, deployment or Git delivery. Exact repository changes: appended this report/current-outcome notice and updated master tracker only; prior reports, source/configuration/credentials/staged migrations/history preserved.

W1.5A final execution documentation verification PASS:63 other pre-existing file contents and tracked binary diff preserved;29 prior task-ledger rows/all12 Phase1 issues and entire prior phase2/16 history retained.56 local links/line locations, whitespace, Compose hash/branch/HEAD and all24 private artifact modes/hashes verified against manifest. Real restore exit0, independent normalized B/D equality/source stability and72 empty-table/empty-marker evidence verified. git -c core.fsmonitor=false diff --check passed. No additional DB action or application test. Exactly existing phase2/16 and tracker updated; baseline ACCEPTED,079 establishment NOT AUTHORIZED/NOT EXECUTED pending W1.5B.
