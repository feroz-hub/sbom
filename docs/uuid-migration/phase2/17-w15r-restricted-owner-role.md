# W1.5R — Restricted D-only ownership role

**IMPLEMENTED / ACCEPTED — role creation only.** Exactly one restricted ownership role was created in the verified disposable D cluster and independently verified after acknowledged commit. No memberships, explicit privilege grants, ownership transfers, export/restore, schema changes or revision establishment followed. W1.5A was not resumed.

## Authority and acceptance boundary

Operator authorization:

> I authorize W1.5R to create exactly one restricted NOLOGIN ownership role in the verified disposable PostgreSQL Database D cluster, using the exact source-owner role name from the protected W1.5A evidence, subject to fresh identity and ownership/ACL compatibility checks.
> I accept that this is a D-only rehearsal role and that its NOLOGIN attribute may differ from the source role. I do not authorize role memberships, privilege grants, changes to B, schema export/restore, Alembic stamping or UUID migration execution.
> If further privileges, role dependencies or exceptions are required, stop for separate approval.

Scope, prerequisites, stopping conditions and acceptance criteria were recorded IN PROGRESS in the [master tracker](/Users/ferozebasha/sbom/docs/uuid-migration/MIGRATION_MASTER_TRACKER.md:1) before database access. This authorized one role in D's cluster, not reproducing source authentication/superuser capabilities or modifying existing owners/grants. Role names are cluster-wide; isolation is provided by the pinned separate D instance. [PostgreSQL 16 CREATE ROLE](https://www.postgresql.org/docs/16/sql-createrole.html).

## Fresh source-evidence and infrastructure gates

Branch `feat/native-user-management`; HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`; dirty work snapshotted and preserved. Reviewed Compose SHA256 `13e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab` unchanged. No Git delivery or fresh origin-equivalence claim.

| Gate | Executed result |
| --- | --- |
| Protected source evidence | Existing W1.5A catalog snapshot verified regular/non-symlink, UID501/mode0600; SHA256 `4bccf86eca8bc25a43f856f11ba036dfde5ba1680d0113429a2af1f2d1cb3b20` matched before parsing. Exactly one missing owner role; same role owns captured relations/types. Name taken directly from evidence, not guessed, regenerated or taken from environment |
| Dependency review | Captured source has zero explicit relation/type ACLs, default ACLs, RLS policies or user routines. Only public user schema, owned by built-in pg_database_owner; its ACL matches fresh D. No additional role, membership or grant needed for this role-only creation. Captured source metadata was not freshly queried from B |
| Local Docker | 2026-10-16T16:32:55.535751Z: exact local UID501 Unix socket `unix:///Users/ferozebasha/.docker/run/docker.sock`, Docker Desktop daemon `1f8c7fe5-5972-4adc-8d6e-363a38572be1`, Engine29.8.2/Compose5.6.0; current filtered metadata matches W1.5A final baseline |
| Exact D | Container `fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e`, same image `sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54`, original sbom-uuid-w1_d_pgdata volume/exclusive mount; only sbom-uuid-w1_d_access; actual host127.0.0.1:56041 unchanged |
| SQL target | Exact uuid_w1_d_rehearsal / uuid_w1_d_bootstrap current/session user; actual PostgreSQL16.15, internal172.20.0.2:5432, PGDATA /var/lib/postgresql/data/pgdata; cluster system identifier `7697252084555804711` matches |
| Fresh role/schema state | Exact source-owner name absent before execution; zero user relations, public.alembic_version absent; existing schema/extension/role-setting state captured. Bootstrap already superuser; no elevation performed. Source public-schema ACL matches current D |
| Existing extension | plpgsql1.0 remains owned by D bootstrap; source snapshot records source-owner ownership. This pre-existing difference requires later W1.5A parity disposition. It is not a dependency or privilege required for creating the empty ownership role; no extension owner transfer or parity exception was performed/accepted here |

No B/A connection, source configuration/password read or live source role-attribute comparison. D's existing private password file alone authenticated both D connections; unchanged regular/non-symlink0600 metadata checked before each use. No credentials exposed or generated.

## Exact mutation and transaction evidence

The inline probe used the existing repository virtual environment/psycopg in a clean `env -i PATH=/usr/bin:/bin` process, explicit host/hostaddr/port/database/user, passfile `/dev/null`, no ambient PG*/dotenv/application initialization, connect timeout5s, statement timeout10s, lock timeout1s, search_path pg_catalog and UTF8. Labels were flushed/fsynced to exclusive0600 private evidence before each phase; no raw exception/credential output. Offline Python source syntax parsing passed before execution.

The role name was safely quoted with psycopg.sql.Identifier. The only mutation statement was:

```sql
CREATE ROLE <exact protected source-owner identifier>
WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
     NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 0 PASSWORD NULL;
```

The placeholder is documentation only; execution used the exact protected name, publicly aliased **SOURCE_OWNER_1**. No IN ROLE/ROLE/ADMIN clauses, GRANT/REVOKE, ALTER ROLE, ownership changes, cleanup or automatic retry.

One initial D connection performed a read-only preflight transaction, then one explicitly read-write transaction containing the CREATE ROLE and read-only verification queries. Full role/membership state was compared immediately before creation. Before committing, the probe required exactly one added role, all requested restrictions, password-is-null boolean, no memberships, no role settings/shared dependencies and unchanged existing roles/schemas/relations/extensions. Any failed assertion would abort the transaction; none failed. No password hash/value was selected.

| Check | Actual result / UTC on2026-10-16 |
| --- | --- |
| Fresh SQL identity / owner/ACL gate | PASS16:35:10.366066; correct D, role absent, existing bootstrap authority sufficient, no further role privilege required |
| Single CREATE ROLE / precommit checks | PASS16:35:10.382254; exactly one new role, **OID16389**; all restrictions/no password/no memberships/grants verified |
| Commit acknowledgement | ACKNOWLEDGED16:35:10.384145; initial connection closed afterward |
| Independent postcommit verification | PASS16:35:10.398709 through a new read-only connection/transaction to pinned D; same role name/OID/attributes, password absent; all other roles, memberships, role settings, schemas/relations/extensions unchanged; Alembic table absent |
| Final infrastructure preservation | PASS16:35:12.101837; final metadata snapshot16:35:11.960628, zero infrastructure/process/credential differences |

No transaction error or uncertain commit outcome. Two D connections total, no automatic reconnect/retry. Independent verification is real PostgreSQL execution, not a mocked commit or application test.

## Committed role contract

| Property | Verified committed value |
| --- | --- |
| Exact name / identity | Matches protected source snapshot; alias SOURCE_OWNER_1; new OID16389 |
| Login/password | NOLOGIN; no password; connection limit0 |
| Administrative capabilities | NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOBYPASSRLS |
| Inheritance/settings | NOINHERIT; no per-role configuration; no credential expiry configured |
| Memberships / direct grants | Full pg_auth_members unchanged; zero memberships involving new role; no GRANT issued; zero shared owner/ACL dependencies for new role |
| Objects owned now | None; application schema not imported |

This is not a claim of zero ambient PUBLIC privileges or inability of existing superusers to SET ROLE. Existing PUBLIC permissions were unchanged; no membership or privilege was granted to make another ordinary role assume it. A future object owner has inherent ownership rights, so NOLOGIN is not equivalent to a read-only owner. Future ownership assignment/schema restore is outside W1.5R. Login refusal was established from committed attributes, not an additional login attempt. NOINHERIT controls membership inheritance defaults in PG16; memberships remain absent. [PostgreSQL role attributes](https://www.postgresql.org/docs/16/sql-createrole.html).

## Preservation and private execution evidence

Existing D/SBOM container IDs/images/start/state/restart/mount/port/network metadata, original D and SBOM volumes, access/private/application networks and sorted full resource identifier sets remained equal. Existing launcher/API/worker/Beat/frontend exact process birth/executable/owner/parent/group/session tuples and environment/password-file metadata unchanged. Four containers,26 volumes,six networks retained; no Docker lifecycle or service action. The only PostgreSQL state change is the authorized one role in isolated D. No A/B access or business-data equivalence claim.

New UID501/0700 private evidence directory:

`/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w15r-20261016T163510317390Z`

| Exclusive0600 artifact | SHA256 |
| --- | --- |
| role-execution.private.jsonl | `39917f00c075b427938330457143847533a820576891a6a0465a1620f497446b` |
| role-before-after.private.json | `fc8a049090f736d74efa1f48c69e6bb57d2f11ce64b98a15cc4d7b9114e38201` |
| preservation.private.json | `e103e10abad1c1a983f9c165050d3d46fcbeb5ef2be91e131a9d3622e9eb63d4` |

Real role names and filtered catalog metadata remain private. Expected evidence-directory creation was baselined after mkdir; parent inode/owner/mode, subsequent metadata and entry set remained stable through preservation checks; password file unchanged. All pre-existing evidence retained. Inline execution source remains in task tool-call evidence, not a repository helper or migration.

## Outcome and next gate

**W1.5R IMPLEMENTED / ACCEPTED, role-only.** The missing owner-role-name prerequisite identified in W1.5A is resolved in D. Historical W1.5A blocked outcomes remain intact; W1.5A is NOT RESUMED and its baseline/structural parity is NOT ACCEPTED. No extra privilege or membership was needed for the authorized role creation.

**STOP before further work.** Existing plpgsql extension ownership differs from the protected source; role creation leaves it unchanged. Before any later W1.5A continuation, review that specific environment difference and any fresh archive/role/ACL/security dependencies; obtain explicit approval for any required exception or further mutation. No extension-owner transfer, implicit ACL omission or blanket parity exception is approved here. Fresh B/revision/schema, D capacity/tooling, private archive SQL/TOC safety and full structural parity gates remain pending; do not infer restore compatibility from the new role alone.

No schema export/restore, pg_dump/pg_restore operation, role membership/privilege grant, B change, Alembic stamp/revision insertion, UUID080–085/index/backfill, application test/startup, production access or Git delivery. Integer PK/FK and public UUID architecture unchanged. Exact repository delta: this new report and master tracker update only; source/application/Compose/prior reports/staged migrations preserved.

W1.5R final verification:63 other pre-existing file contents and tracked binary diff preserved;28 prior task-ledger rows and12 Phase1 issue rows retained;46 local evidence links/line locations, whitespace, pinned Compose/branch/HEAD and private0700/0600 artifact hashes checked. Exactly one acknowledged role commit and independent committed-state verification confirmed from evidence, one role delta/no membership delta. git -c core.fsmonitor=false diff --check passed. No application/migration tests, B access or export/restore. New phase2/17 report and tracker only, plus protected external evidence. W1.5R role-only ACCEPTED; W1.5A not resumed.
