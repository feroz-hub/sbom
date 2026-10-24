# W1.7B — Isolated E provisioning and085 baseline acceptance

**BLOCKED before provisioning. E NOT CREATED / NOT ACCEPTED.** 2026-10-17, Asia/Kolkata. Branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`; existing dirty work preserved. Explicit human W1.7B resource/schema-export/restore/restricted-owner/E085-marker authority was received. Integrity tests were not authorized or executed.

The mandatory source-D pre-provisioning check failed with **`psycopg.errors.UndefinedColumn`, SQLSTATE `42703`**, at16:45:44.294886UTC. The new private probe contains an invalid role-metadata query selecting `rolconfig` from `pg_authid`. This is an avoidable defect in this task's private inspection helper, not an observed change to D's schema/roles, a missing privilege or a revoked prior085 acceptance. The complete fresh source gate did not return PASS. No new E resource, credential, Compose file, archive, owner role, schema or marker was created. No failed database operation was retried.

## Authority and immutable inputs

Operator approved exact original proposal `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17a-20261017T152612952531Z/e-provisioning-execution-proposal.json`, byte SHA256 **49f7942fa62e8865ed044357f8b0144cb4abf9c1ed786b0de5b83320eb073709**, expiry **2026-10-18T15:45:39.587814+00:00**. File bytes/fullJSON/source pins/expiry verified before work; original preserved. Its acceptedfalse/seven pending flags/empty approvals were unchanged and never interpreted as test authority.

Required sourceD:127.0.0.1:56041/databaseuuid_w1_d_rehearsal/useruuid_w1_d_bootstrap/PG16.15/cluster7697252084555804711/sole085. Accepted runner13 `85507e89a3946cda7611e5498e816fcf5708af18a6549b08a4fbfe3ae1f0d80a`; independent31 `760c7e7b0b50688fd4f7c3471219a35fa3b025f67bf3303cc15a50f44800fd30`. Prior W1.6I accepted085 protected final manifest02177e95f9c6def0294f9c2162cbee849ac9fda6ee1dd3177d0101e187e4ca4a/all18referenced artifacts and immutable expand/common/all six source hashes reverified through inert source/helper checks. No historical migration/code/config or evidence file changed. W1.7A's193cases remain unexecuted.

Allowed later E resources remain exactly projectsbom-uuid-w17-e/servicepostgres_e/databaseuuid_w17_e_integrity/127.0.0.1:56042/original-proposal newe_pgdata/e_access/pinned image and CPU-memory-shm-PID/PG settings. New unique private E credential and one exact restricted source-owner NOLOGIN role may be created only after fresh preflight. Explicit ordinaryNATbridge egress acceptance was received; no app/D network attachment or widened exposure authorized. No A/B/production authority, imagepull/build/reuse/reset/cleanup/automaticretry, fixture/helperDDL/test authority. These are recorded permissions, not executed operations.

## Actual operations and preflight results

| Check | Actual observed result |
| --- | --- |
| Git/source/proposal | Required branch/HEAD match; exact original proposal/source hashes match and unexpired; private evidence only plus tracker IN PROGRESS before execution |
| Local Docker | Socket `/Users/ferozebasha/.docker/run/docker.sock` user-ownedUnix socket; verified DockerCLI SHA31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f; daemon1f8c7fe5-5972-4adc-8d6e-363a38572be1/DockerDesktop29.8.2/Compose5.6.0; no remote daemon contacted |
| Image | Already locally present sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54 / digestpostgres@sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54; no pull/build |
| E collisions | No proposed project/container/service/volume/network collision in filtered inventories; credential namespace `/Users/ferozebasha/.sbom-uuid-w17-e` absent;56042has no listener. Point-in-time only, no port bound/reserved |
| Host capacity |54,957,887,488bytes filesystem available; memory_pressure reported30%free of8,589,934,592bytes, estimate2,576,980,377bytes. Above2GiBstorage/1GiBheadroom gates at observation, not a future reservation |
| Docker VM capacity | Filesystem available223,818,866,688bytes; `/proc/meminfo` MemAvailable3,385,520,128bytes. Above2GiBstorage/1GiBmemory gates. Read-only `docker exec` `/bin/df -Pk /var/lib/postgresql/data` and `/bin/cat /proc/meminfo` on existing D for filesystem/VM metadata only; no SQL or resource/lifecycle mutation |
| PostgreSQL tools | Existing D image `pg_dump --version` and `pg_restore --version` both16.15. Tools were not used to dump/restore anything |
| Existing infrastructure baseline | Filtered local Docker/resources/process/listener/runtime/env/credential metadata captured before2026-10-17T16:44:46.508701+00:00 and after2026-10-17T16:47:01.364230+00:00; comparison identical exceptUTC. Same original D and SBOM resources, no E resources. Final exact times in preservation evidence |
| New private helper import | Initial normal import failed before any DB connection because filename has `.private.py`; corrected offline by explicit importlib file loading. Original import failure recorded, not relabelled success; no resource mutation |
| Source-D probe | One explicit existing-D-credential authenticated connection; bounded REPEATABLE READ READ ONLY context. Source checker executes identity/085/prefix/two catalog hashes/roles-extension/71empty-table/no-other-client checks before its new restricted-role query. No individual subcheck PASS/snapshot artifact was written before failure, so this report does not certify a completed fresh composite preflight or invent an independent complete snapshot |
| Failure | SOURCE-D-PREPROVISION STARTED16:45:42.673157UTC; FAILED_STOP16:45:44.294886, UndefinedColumn42703. Owned read-only transaction unwound/rolled back and physical connection context exited before outer catch; no reconnect/retry. Error catch retained only class/SQLSTATE, not raw driver DETAIL/statement-position; independently proven invalid source query is the concrete defect consistent with observed error |
| Stop boundary | User explicitly requires mandatory source/security preflight success before creation and “No automatic recovery, retry”. No corrective connected probe or further database access occurred. Existing acceptedD085 history retained; this task's new preflight remains incomplete |

All read-only host/Docker commands used explicit local endpoint/filtered nonsecret fields and clean subprocess environment. No environment-file contents, process environments, passwords or connection strings were displayed. The existing disposable credential was read only by the approved D connection helper; its content was never logged/copied/rotated. PostgreSQL short metadata statements used existing reviewed bounded D options, not application settings.

## Exact source defect and smallest correction

Original helper `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b-20261017T164341068380Z/w17b_lib.private.py` (retained), SHA256 **f1f163850ccca7e7d414865e13a3e92d4814e7b2907c192bf6741f43701f33fd**, includes:

```sql
SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin,
       rolreplication, rolbypassrls, rolconnlimit, rolconfig,
       rolpassword IS NULL
FROM pg_authid WHERE oid = 16389;
```

`rolconfig` is exposed by `pg_roles`, not by `pg_authid`. This is confirmed by the PostgreSQL16 catalog/view definitions: [pg_authid](https://www.postgresql.org/docs/16/catalog-pg-authid.html), [pg_roles](https://www.postgresql.org/docs/16/view-pg-roles.html). The password-null predicate must continue to use pg_authid; pg_roles blanks its password field, so substituting pg_roles for the entire query would not prove the required no-password condition. No password value needs to be returned.

Smallest safe correction is **two bounded read-only queries**, parameterized on the restricted roleOID:

```sql
SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin,
       rolreplication, rolbypassrls, rolconnlimit, rolconfig
FROM pg_catalog.pg_roles WHERE oid = :role_oid;

SELECT rolpassword IS NULL
FROM pg_catalog.pg_authid WHERE oid = :role_oid;
```

Expected first result: sevenfalse attribute flags, connlimit0, rolconfigNULL; second result `(true)`. Keep exact protected name/owner-purpose and memberships checks, all other source identity/catalog/security gates and acceptance criteria. Do not change the role or grants to make a query pass. The existing old reviewed role_state helper already uses separated catalog access; pinned repository sources were not faulty or edited here.

A separate **offline-only corrected draft** `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b-20261017T164341068380Z/w17b_lib-corrected-not-executed.private.py`, SHA256 **f3f6c4de384d18e969dc69e12307c362bf5a93b99f72b87fb9a05b5b0e173b54**, preserves the original helper and changes only the role-query split plus an explicit NOT EXECUTED header. Python AST/compile and SQLAlchemy PostgreSQL text compilation passed; draft was not imported/executed against any DB and no live retry occurred. Compiler checks are not server grammar/privilege/runtime acceptance. Diagnostic and original failures remain protected.

This is a helper/source defect, **not evidence that the restricted owner has a password, wrong permissions, changed ACLs or wrong identity**. Exact failing driver column/statement diagnostic was not captured in the original sanitized catch; the independently invalid source query and matching42703 are recorded without inventing that missing diagnostic. A corrected fresh probe is required before any source baseline is accepted for W1.7B.

## Provisioning / restore / marker / tests disposition

| Requested stage | Actual outcome |
| --- | --- |
| E-specific Compose file/review/config validation | NOT CREATED / NOT RUN; stopped at earlier mandatory source gate |
| E private directory/password | NOT CREATED; no OS randomness/credential reuse occurred |
| E container/image/storage/network/listener/database/cluster | NOT CREATED; no new identities exist; approved image merely inspected |
| E initial freshness/authenticated infrastructure acceptance | NOT RUN |
| E restricted owner role/plpgsql owner/security compatibility | NOT RUN; no role creation/grant/ownership change |
| D schema-only snapshot/export/archive/TOC/SQL review | NOT RUN; no archive/hash/sequence values/business rows exported |
| Restore timeout feasibility | Tool16.15available, but actual archive/statement review not reached; compatibility with2sstatement/250mslock/5sidle settings **UNVERIFIED**, no weakening/override applied |
| E single-transaction schema restore/COMMIT/close/parity | NOT RUN; no restore attempt/transaction outcome |
| Pre-marker semantic31 parity/business-table emptiness | NOT RUN; no E accepted schema |
| E sole085 INSERT/serialization/COMMIT/read-back | NOT RUN; marker absent because E does not exist |
| E fresh raw13/normalized31 | UNAVAILABLE; do not copy D fingerprints as invented E observations |
| New E execution candidate/hash/expiry | NOT CREATED; no accepted E identity/catalog exists. Original approved resource proposal unchanged; no live test attestations/actionrefs invented |
|193integrity cases/helpers/fixtures/index/backfill | NOT EXECUTED; zero synthetic rows, helper DDL, UUID index or backfill |

No partial new E resource or secret is left behind. No schema/role/version-table data mutation on D, A/B/production access, source business-data export, source sequence advancement, Docker startup/restart/recreation/down/cleanup or application lifecycle/configuration change. Existing sourceD085 and W1.7A staged harness acceptance statuses are not overwritten by this task's failure.

## Preservation and protected evidence

Before/after filtered snapshots compare container/image/state/start/restart/mount/port/network, volume/network identity sets and exclusive attachments, current repository process/listener identities, safe runtime/env/credential file metadata. All unchanged except UTC. Historical launcher/API/worker/Beat/frontend PIDs remain absent/stale runtime/no18000/13000listeners; existing tool/runtime processes unchanged, no claim those app services were running. A/B data was not connected/compared. No secrets opened except explicit D authentication file handling.

Private evidence `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b-20261017T164341068380Z`:0700UID501,11files0600; original source and corrected-not-executed draft, capacity/collision/tool observations, full pre/post nonsecret infrastructure snapshots, failure event log/offline diagnosis/blocked outcome/repository baseline.10-entry manifest SHA256 **e13fc6cac8b9368800c584aebe2a007a49b830a920350e7f67b431e3d191b6fd**. No archive, Ecredential, executable test manifest or business records. Full earlier report24/25, approved proposal, W1.6I/W1.7A private manifests and pinned sources preserved.

Repository changes: **new report26 and master-tracker update only**. Intended ECompose was not created after failed prerequisite; accepted DCompose/runtime/application/configuration remain untouched. No Git commit/push/checkout/reset.

## Decision and exact next gate

**W1.7B BLOCKED; E NOT CREATED / NOT ACCEPTED.** Capacity/local source pins/resource collision checks passed, but mandatory source preflight failed on the private query defect. The task's explicit no-automatic-retry rule was honored. This is not a documentation-only success or an implementation claim.

Smallest next action: operator-directed W1.7B continuation accepting only the corrected private read-only role probe, then repeat all fresh mandatory gates under the original unchanged/unexpired proposal and existing exact scope. No extra role/grant, ownership exception, source mutation, resource substitution or test permission is needed for this correction. If proposal expires first, renewed independent proposal review is required; do not extend expiry automatically. Successful future gates may proceed through actual E provisioning/schema-only export/restore/085 marker/parity as previously scoped, but this task issued no retry.

**NO-GO for E integrity-test execution candidate or193case execution now.** After actual accepted E baseline, prepare a new candidate with real E identity/raw13/semantic31/source pins/credential provenance/seven pending flags/empty approvals and independent operator action approval. No test authority was supplied by W1.7B.


Final documentation/preservation verification PASS:2,107 pre-existing repository contents except authorized tracker unchanged; exact new file report26 only. Branch/HEAD/tracked binary diff unchanged;45 historical completed-task ledger rows/12 Phase1 issue rows retained verbatim;62 local report/tracker evidence links/line locations/whitespace/git diff --check PASS. Original proposal/source pins/pending test approvals/private0700-0600UID501 modes and initial10-entry evidence manifest verified. Final12-entry/13file manifest SHA256ecfa64d60c101767649029abc29b41c49b7b38889a735ecf641082311ffbb9eb retains original source/failure/offline correction/capacity/preservation plus documentation verification. Before2026-10-17T16:44:46.508701UTC/after16:47:01.364230UTC filtered resources/processes identical exceptUTC. One D-only authenticated read-only source session/zero database mutations/no connected retry/no further DB access; E credential namespace absent and no E resources/export/restore/marker/test candidate. W1.7B remains BLOCKED on private preflight query defect, not implemented or accepted.


## Operator-directed continuation after42703 — actual E provisioned, baseline PARTIAL

**W1.7B PARTIAL; E infrastructure created and running, E baseline NOT ACCEPTED.** 2026-10-17. New human continuation explicitly approved one corrected fresh source-D preflight and the original E-only workflow if gates passed. The original failed42703 attempt above, original helper/draft and all protected historical evidence remain unchanged. This continuation resolved the SQL query defect, exported/reviewed the actual D085 schema, generated new E credentials and started exactly the approved E service/resources. A new **literal secret-mount source-path assertion** failed before E PostgreSQL authentication, restricted-owner creation or restore. Work stopped; no automatic mutation retry, source-guard edit, resource replacement, cleanup or test execution.

### Reviewed correction, authority and fresh prerequisites

Original failed helper `f1f163850ccca7e7d414865e13a3e92d4814e7b2907c192bf6741f43701f33fd`, corrected-not-executed draft `f3f6c4de384d18e969dc69e12307c362bf5a93b99f72b87fb9a05b5b0e173b54` and prior final manifest `ecfa64d60c101767649029abc29b41c49b7b38889a735ecf641082311ffbb9eb`/all12 referenced artifacts hash/mode verified. Both originals retained byte-for-byte. Full original→draft diff records only header plus `pg_roles` attributes/config and separate `pg_authid` password-null boolean query; no role data is modified or password value returned.

Separate protected execution copy `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b-resume-20261017T165355805285Z/w17b_execution.private.py` SHA256 **a0381c2e453a4a5c69dbc04b342f6d30854f485d06be90294a9122fbb568ee3f** adds bound `(16389,)` parameters to both reviewed queries and flushed individual-gate labels. Existing predicates are retained; extra exact protected-owner-name and no-public-UUID-index assertions tighten checks. No pinned migration/harness/application code changed. Offline AST/Python syntax/SQLAlchemy text compilation and catalog-column source compatibility review PASS before any connected attempt; compilation is not runtime acceptance. Full diffs, original hashes and new source hash preserved privately.

Original resource proposal byte SHA256 **49f7942fa62e8865ed044357f8b0144cb4abf9c1ed786b0de5b83320eb073709**, fullJSON/source pins and expiry **2026-10-18T15:45:39.587814+00:00** verified again unchanged/unexpired. Its acceptedfalse/seven pending test flags/empty approvals unchanged. Operator accepted ordinary-bridge outbound risk for E, not a zero-egress boundary or test authority.

Fresh branch/HEAD remained feat/native-user-management /2f48ff835d9e692fc84b31aaa951aad2495888ac. Local Desktop/socket/CLI/daemon/image and accepted D container/image/original volume/network/credentials/current SBOM metadata matched. E project/service/container/volume/network/secret namespace absent;56042free point-in-time, no reservation. Fresh capacity16:54:59.410538UTC: hoststorage56,089,370,624bytes; hostmemory34%free≈2,920,577,761bytes; Dockerfilesystem223,818,866,688bytes available; VM MemAvailable3,392,684,032bytes. All2GiBstorage/1GiBmemory thresholds PASS. PG dump/restore tools16.15already local; no pull/build/installation.

### Exactly one newly authorized corrected source preflight

One explicit D-only REPEATABLE READ READ ONLY session STARTED16:54:59.863249UTC, physical close **16:55:00.686926UTC**. Each label flushed STARTED before work and PASS only after its assertions. No SQL error/correction/reconnect in this attempt.

| Label | Actual result |
| --- | --- |
| D01 identity/revision | PASS16:55:00.303306UTC — exact D database/user/cluster7697252084555804711/PG16.15/sole085/READ ONLY |
| D02 six UUID/catalogs | PASS16:55:00.534942 — exact source Runner13 `85507e89a3946cda7611e5498e816fcf5708af18a6549b08a4fbfe3ae1f0d80a`, semantic31 `760c7e7b0b50688fd4f7c3471219a35fa3b025f67bf3303cc15a50f44800fd30`; accepted catalog equality, six nullable native UUID/default/NOT VALID CHECK/two enabled triggers/shared guard, no publicUUID index,72tables1149columns512indexes60sequences143FKs |
| D03 roles/extensions/catalog security | PASS16:55:00.538274 — actual role/ACL/membership/extension state equals accepted085, original integer graph and missing VEX FK/drift preserved |
| D04 data/writers | PASS16:55:00.568390 —71empty business tables, zero competing D client sessions |
| D05 restricted owner/purpose | PASS16:55:00.569776 — boundOID16389/exact protected name; NOLOGIN/NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOINHERIT/NOREPLICATION/NOBYPASSRLS/connlimit0/configNULL/passwordNULL, no unexpected memberships/owner set. Sole required missing application owner planned for E; no role change |
| D06 database/plpgsql/security | PASS16:55:00.571428 — database/bootstrap owner and plpgsql owner uuid_w1_d_bootstrap, existing ACL/security properties unchanged; no external/event/subscription objects |

The historical42703 remains a failed earlier attempt. This successful attempt was explicitly operator-directed, not an automatic retry or rewritten history. SourceD had zero schema/data/marker/role/sequence mutations.

### Real consistent schema-only export and archive review

A separate authorized source-D READ ONLY session for export used an exported consistent snapshot, rechecked the same D01–D06 gates and matching accepted fingerprints, and held the snapshot while **one** PG16.15 `pg_dump --schema-only --format=custom --no-large-objects --snapshot=... --lock-wait-timeout=1000` ran against verified D container loopback5432 (correlated with host56041). No A/B connection or ambient settings. D password supplied only via private non-TTY stdin forced password prompt; no argv/env/log credential. Source catalog was checked unchanged within the snapshot after export; session closed16:56:28.642925UTC. No business rows or sequence values exported.

Archive `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b-resume-20261017T165355805285Z/D085-schema-only.dump` **387668bytes**, SHA256 **93af6e8eff8b8702803748dd197b45ce429e1e559c033aee7529428b630d894e**. Offline pg_restore `--list`/`--schema-only --file=-` read archive via stdin, never connected to E/D databases. TOC SHA **7beaa65d17dd26aa6d35820e4cdd565ffc07826076bcc39eb05fd1d74e701e02**; generatedSQL SHA **cecf03e7d50396a218a00eef7abd2ac4957bbaef6307f7db7063b16ebe34effb**. Full TOC/SQL retained privately and reviewed before creation/restoration.

Review PASS16:57:34.433718UTC:926TOC items =1shared function/72tables/60sequences/60sequence ownership links/60defaults/111existing constraints/6unvalidated UUID CHECKs/401standalone indexes/12identity triggers/143FKs. Remaining original constraint-backed indexes account for source512total; no new UUID unique index. All source owner statements retained (133), no blanket no-owner/no-acl/no-privileges, no rows/COPY/INSERT/setval/data/blobs/foreign server/event/subscription/untrusted extension/role creation/destructive commands. Shared guard body hash exact. Missing VEX FK remains absent. Builtin initdb plpgsql is omitted by native pg_dump policy; **independent E plpgsql owner/version/function/ACL/security parity remains required**, no inherited exception/adoption claim.

The generated SQL preamble has three standard `SET ... =0` timeout resets. To preserve the exact approved limits rather than silently disable them, an **unused reviewed restore stream** replaces only those three statements with2sstatement/250mslock/5sidle; every object/ownership SQL statement retained. Comment removal and psql restrict/unrestrict control removal support a proposed one-owned-psycopg-transaction/sequential-statement/fail-on-first-error restore, not direct pg_restore --dbname that resets limits0. Offline SQL lexer examples for comments/quotes/dollar function bodies passed; full1071statements enumerated/allowlisted and guard body verified. Reviewed stream SHA **bc682cee88f02f043c1bf3ac987f52168a704ade807c6a5889d0fe7fad43407c**. No restore performed and no timeout override executed. Actual empty-target lock/statement timing remains unmeasured/unaccepted; limits must not be weakened if later restore is attempted.

### Actual E-only resources, configuration and credential

Created [docker-compose.uuid-w17-e.yml](/Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w17-e.yml:1), SHA256 **49b0989250be326a373aa76cc13e5a935faaf21705449e19f14c04ad5182949b**. Accepted DCompose unchanged. Sole postgres_e service/projectsbom-uuid-w17-e/pinned local digest, no apps/dependencies/env-files/build/pull, restartno, dedicated managed e_pgdata/e_access, strict127.0.0.1:56042, CPU1/memory536870912/shm67108864/PID128; command max_connections12/shared_buffers64MB/work_mem4MB/statement2s/lock250ms/idle5s/passwordencryptionscram. Actual per-server SHOW checks not reached; Compose command and Docker resource limits verified.

Fresh OS CSPRNG256bit E-only password created exclusively at `/Users/ferozebasha/.sbom-uuid-w17-e/postgres-password`; new0700parent/regular single-link0600UID501/65bytes/inode75943438, mtime/ctime/provenance retained privately and unchanged afterward. No D/A/B/rootenv credential reuse, overwrite, rotation, content/hash/log/argv/env exposure. Secret is supplied only as file-backed read-only mount at `/run/secrets/e_password`.

Clean invocation uses explicit local Unix endpoint/project/single absolute file/`--env-file /dev/null`, `COMPOSE_DISABLE_ENV_FILE=1`, only HOME/PATH/LC_ALL and nonsecret E password filepath variable. `config --quiet` exit0; resolved nonsecret JSON review PASS soleE/ports/network-volume/secret/limits. Exactly one service-up invocation STARTED16:58:52.345921UTC /exit0 **16:58:58.453455UTC**, no retry:

```sh
env -i HOME=/Users/ferozebasha PATH=/usr/bin:/bin LC_ALL=C \
  COMPOSE_DISABLE_ENV_FILE=1 \
  UUID_W17_E_PASSWORD_FILE=/Users/ferozebasha/.sbom-uuid-w17-e/postgres-password \
  /Applications/Docker.app/Contents/Resources/bin/docker \
  --host unix:///Users/ferozebasha/.docker/run/docker.sock compose \
  --project-name sbom-uuid-w17-e \
  --file /Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w17-e.yml \
  --env-file /dev/null up --no-build --pull never --no-deps --wait --wait-timeout 60 postgres_e
```

| Resource | Actual safe identity / observation |
| --- | --- |
| Container | `05745ce4998f26f3b46467f13315e50affc7a689e0e2bde664b3d9e8ce4fa98a`, name sbom-uuid-w17-e-postgres_e-1, correct project/service labels; created2026-10-17T16:58:52.582028672Z/start16:58:52.767457922Z/running/healthy/restarts0 |
| Image | `sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54`, locally available approved image, no pull/build. Actual PostgreSQL server-side version not yet authenticated/observed on E |
| Volume | `sbom-uuid-w17-e_e_pgdata`, localdriver/optionsNULL/created2026-10-17T16:58:52Z, project/disposableE labels; mount `/var/lib/docker/volumes/sbom-uuid-w17-e_e_pgdata/_data`→`/var/lib/postgresql/data`, exclusive attachment to only new E container |
| Network | `sbom-uuid-w17-e_e_access`, ID `311da1a7411dbf72e7a84804b0a61f5ff320b1054c4e9722f96dd9e511d8a144`, created16:58:52.488150963Z/ordinarybridge/internalfalse/IPv6false/soleE member. NAT/ICCfalse/masqueradetrue/host_binding127.0.0.1 options. Distinct from D/application networks |
| Endpoint | Actual Docker publication exactly127.0.0.1:56042→5432, no wildcard/IPv6. New matching Docker-backend listener is the only added host listener. Internal address172.21.0.2:5432 from Docker metadata, not SQL observation |
| Limits | Actual Docker CPU1/memory512MiB/shm64MiB/PID128/restartno match; no lifecycle action to D/SBOM |
| Database/cluster | E configured dbuuid_w17_e_integrity/bootstrapnameuuid_w1_d_bootstrap/PGDATA expected; **system identifier/databaseOID/authenticated database-user/fresh-schema observations UNAVAILABLE**. Health is not authenticated acceptance |

### New acceptance stop — literal Docker Desktop mount-source predicate

`E-INFRA-IDENTITY` STARTED16:59:33.400192UTC and **FAILED_STOP16:59:33.535799UTC**, AssertionError/noSQLSTATE. The private check compared the secret mount's Source literally with the host path:

```text
Expected host Source: /Users/ferozebasha/.sbom-uuid-w17-e/postgres-password
Observed Docker Source: /host_mnt/Users/ferozebasha/.sbom-uuid-w17-e/postgres-password
Destination: /run/secrets/e_password
Mount type: bind
Read-only: true
```

Filtered post-stop inspection confirms the actual metadata above. Docker Desktop VM and host paths are represented differently; the immediate failure is a **literal host/VM namespace assumption**, not evidence that the password is wrong or that the mount is writable. However, equivalent-file correlation/readability/authentication was **not established** by the failed predicate, so no PASS was substituted. The hash-pinned [uuid_integrity_control.py:176](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_integrity_control.py:176) makes the same Source==str(PASSWORD) assumption. It is unchanged at approved hash087d2f9e12d79a250cc71b57506b052bc51dbb2b98ab0fbf6aa05e208682296c. No pinned-source patch/new hash/adoption was authorized or performed.

This gate failed **before** container secret-readability checks and E authenticated connection, not during schema restore or COMMIT. Only filtered read-only Docker/host inventory was performed afterward to explain/retain actual state. No E-only SQL session, role/grant/owner change, restore, marker or connected integrity validation occurred. Exact initial metadata checker command is retained in task tool evidence; private `mount-predicate-diagnosis.private.json` records the literal predicate/expected/actual, shared pinned-source assumption and missing proof without inventing a SQL diagnostic. No failed DB transaction/reconnect/retry/unknownCOMMIT.

**Smallest next review:** operator-directed read-only correlation of Docker Desktop `/host_mnt` representation with the exact protected host secret/file provenance and read-only mount destination; then narrowly review the compatible pinned E guard/checker correction and new source pins if approved. Do not accept arbitrary path aliases, copy/rotate the secret, weaken permissions, change resources/ports, restart/recreate E or silently update the approved proposal. This is not a demonstrated infrastructure misconfiguration needing runtime repair. An accepted canonical mapping could allow acceptance to resume without resource replacement, but this task stops at the failed identity/security assertion as instructed.

### Actual stage disposition and retained resources

| Stage | Actual outcome |
| --- | --- |
| Original42703 source defect | Resolved in one newly human-authorized corrected source preflight; originals/failure preserved |
| Fresh sourceD085/catalog/owner/security/data | PASS; one corrected preflight connection closed; export session separately reverified source and snapshot/catalog stability |
| D schema-only archive/review | COMPLETED/PASS;387668bytes/SHA93af6e8eff8b8702803748dd197b45ce429e1e559c033aee7529428b630d894e, no rows/sequence state |
| New E private credential/config/service/volume/network | IMPLEMENTED; up exit0/runninghealthy/actual loopback and resource limits. Retained in place, no teardown/retry |
| E infrastructure authentication/readability/freshness/systemID | NOT ACCEPTED / NOT RUN after failed literal mount-source gate; no clusterID invented |
| Exact restricted E NOLOGIN owner / plpgsql parity | NOT RUN; no explicit restricted-owner role creation/membership/grant/exception; bootstrap/initdb expected as part authorized new cluster startup, not independently catalog-accepted |
| E restore/transaction/independent31 parity | NOT RUN; restore attempts0/no COMMIT/rollback/unknown outcome. Reviewed SQL stream unused |
| E sole085 marker/serialized INSERT/COMMIT/read-back | NOT RUN; marker not established/observed |
| E raw13/semantic31 fingerprint/newexecutioncandidate | UNAVAILABLE / NOT CREATED; cannot substitute D fingerprints or infer pins from Docker metadata |
|193integrity cases/helperDDL/fixtures/backfill/index | NOT EXECUTED, all0; no new integrity_validate/integrity_execute references or attestation approvals |

Actual connections: one corrected source-D application read-only preflight; one separately authorized D application read-only export-snapshot session; one source-D pg_dump tool connection sharing the snapshot. Offline pg_restore TOC/SQL generation did not connect to any DB. E SQL connections0, A/B/production0, sourceD mutations0. No connected retry or source migration replay. The latest source catalog/71empty-table observation is within the export snapshot before E creation; no additional source SQL query was made after the E gate failed. Existing D resource metadata remained unchanged.

### Preservation, evidence and files

Before2026-10-17T16:54:32.842595+00:00/after2026-10-17T17:00:54.789798+00:00 filtered snapshots prove existing D/SBOM Postgres/Redis/Mailpit container/image/start/state/restart/mount/port/network, original volumes/networks/exclusiveD attachment, runtime/env/credential safe metadata unchanged. Exactly one new E container/volume/network and127.0.0.1:56042listener account for inventory deltas. Existing process identities/listeners retained; comparison canonicalizes PID/command/endpoint independent of descriptor enumeration and allows only new E listener. Historical service PIDs absent/stale runtime/no18000or13000listeners remain, no app-running/A-B-data equality claim. Parent metadata changes for new private evidence/secret directories are expected; existing D password metadata unchanged, new E credential inode75943438/0600UID501/mtime-ctime unchanged after startup.

New private evidence `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b-resume-20261017T165355805285Z`:0700UID501,31files0600,30-entry manifest SHA256 **24291da1cb8e217e3ac0d3b27cc5b3f789d3a2772df23ca9624db2b2b68df1a8**. Contains repository baseline/authority-hash checks/diffs/source and capacity labels/catalog/source schema archive+TOC+SQL/offline review/prepared unused restore stream/new E input metadata/config/up output/failed gate/actual post-stop E inventory/preservation/partial outcome. No passwords/secret hashes/full connection strings/process environments/business data retained. Corrected sourceSQL asserts boolean-only passwordNULL; protected role name/function bodies remain private. Later documentation verification may add a separate final manifest without altering this initial one.

Repository delta: new [E Compose](/Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w17-e.yml:1), report26 append and tracker update only. Original DCompose, application/runtime/env, active/staged migrations, integrity suite/fixtures/common/runner/report25/priorreport26prefix/oldprivate42703evidence/proposal/sourcepins/Git work preserved. No commit/push/reset/checkout.

**Decision: W1.7B PARTIAL, E baseline NOT ACCEPTED.** The corrected source gate and actual authorized infrastructure/export work are completed, not rolled back or mislabelled as full success. E remains running with its dedicated new storage/credential; no automatic cleanup or recreation. The new mount-source predicate/guard compatibility review is the precise remaining blocker. After independently authorized correlation/correction, fresh existing-E identity/authentication/freshness/security acceptance must precede restricted-owner creation/restore/parity/085marker/finalacceptance. No re-provisioning is needed or authorized by tracking alone. Original proposal expiry remains unchanged; if it expires, renewed independent review is required.

**NO-GO for a real E integrity-execution candidate or193case run.** No E baseline fingerprints/systemID/marker exist as accepted evidence yet. All live DML/concurrency/recovery/performance/application release groups remain unexecuted. The original seven test attestations/action approvals remain pending even after future E baseline acceptance.


### Final continuation documentation verification

At 2026-10-17T17:05:39.429265UTC, offline preservation verification passed: 2,107 pre-existing repository files remain unchanged except the authorized tracker/report26 edits; the only new repository file is the E Compose configuration. Branch, HEAD and pre-existing tracked binary diff remain unchanged. All 46 historical completed-task ledger rows and 12 Phase1 open-issue rows were preserved; 66 local report/tracker evidence links and line references were checked. Original failed helper, corrected draft, approved proposal, migration/runner/integrity source pins and private credential metadata remain unchanged. Private evidence directory/file modes remain 0700/0600 with UID501. `git diff --check` passed. These are documentation/source-preservation checks, not PostgreSQL acceptance or integrity-suite execution.

Protected `documentation-verification.private.json` records those results. The separate final evidence manifest `artifact-manifest-final.private.json` contains 32 entries covering 33 files, SHA256 **6b12bf89d8182567f708a46f658620bcb9979b735d090e7fe399ed0b67d5be27**; the earlier 30-entry manifest is retained unchanged. No database connection or runtime retry was made for this final documentation verification.

Final status remains **W1.7B PARTIAL; E baseline NOT ACCEPTED**. The corrected source preflight passed and E infrastructure exists, but the literal host/VM secret-mount path gate failed. E authentication, cluster/database identifiers, restricted-owner preparation, schema restore, revision marker, catalog fingerprints and integrity execution candidate remain unverified or unexecuted. All 193 integrity cases remain unexecuted. Next action requires independent operator review of exact host/VM path correlation and the narrow pinned guard compatibility change before resuming acceptance of the existing E resources; no automatic recreation, cleanup or approval renewal.


## W1.7B.1 — Docker Desktop secret correlation and guard correction review

**IMPLEMENTED (STAGED) / OFFLINE VERIFIED; STOPPED AT INDEPENDENT BASELINE-CONTINUATION REVIEW.** 2026-10-18, Asia/Kolkata. Secret correlation PASS; E baseline remains **NOT ACCEPTED**, W1.7B remains PARTIAL. This task opened **zero PostgreSQL connections** and performed zero database mutations or Docker lifecycle/configuration changes. No integrity case ran. Historical SQLSTATE42703, authorized query correction and mount-source assertion failure above remain unchanged.

### Authority, prerequisites and preserved originals

The human W1.7B.1 instruction authorized exact-existing-E metadata, one bounded in-memory host/container secret comparison, minimum E guard/private-checker compatibility corrections, offline tests and a new review candidate, followed by STOP before SQL. Tracker IN PROGRESS recorded before runtime inspection. Branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`; existing dirty work preserved. No origin/ref freshness or deployment claim.

Verified original proposal `49f7942fa62e8865ed044357f8b0144cb4abf9c1ed786b0de5b83320eb073709` and unchanged expiry `2026-10-18T15:45:39.587814+00:00`, original E Compose `49b0989250be326a373aa76cc13e5a935faaf21705449e19f14c04ad5182949b`, archive `93af6e8eff8b8702803748dd197b45ce429e1e559c033aee7529428b630d894e`, earlier32-entry final manifest `6b12bf89d8182567f708a46f658620bcb9979b735d090e7fe399ed0b67d5be27`/all referenced artifacts. Original failed helper `f1f163850ccca7e7d414865e13a3e92d4814e7b2907c192bf6741f43701f33fd` and corrected draft `f3f6c4de384d18e969dc69e12307c362bf5a93b99f72b87fb9a05b5b0e173b54` remain byte-identical. The original guard was copied byte-for-byte to new private evidence before editing; original proposal/source pin was never overwritten. Old-hash authority cannot silently authorize this changed guard.

### Independently observed mount and content correlation

| Check | Actual safe result |
| --- | --- |
| Exact local endpoint | `/Users/ferozebasha/.docker/run/docker.sock`, owned Unix socket; DockerCLI SHA31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f. Daemon `1f8c7fe5-5972-4adc-8d6e-363a38572be1`, name docker-desktop, OS Docker Desktop, OSType linux; no remote daemon |
| Existing E | Container `05745ce4998f26f3b46467f13315e50affc7a689e0e2bde664b3d9e8ce4fa98a`, approved image sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54, original creation/start/restarts/project sbom-uuid-w17-e/service postgres_e/running-health/limits/ports unchanged |
| Storage/network | Original exclusive `sbom-uuid-w17-e_e_pgdata`/mount/creation/labels unchanged. Sole `sbom-uuid-w17-e_e_access`, ID `311da1a7411dbf72e7a84804b0a61f5ff320b1054c4e9722f96dd9e511d8a144`, member/gateway/options unchanged; no D/application network attachment. Actual loopback127.0.0.1:56042 only; ordinary-bridge outbound risk persists |
| Host source | Exact `/Users/ferozebasha/.sbom-uuid-w17-e/postgres-password`; UID501/inode75943438/65bytes/regular/non-symlink/single-link/mode0600, parent0700. mtime_ns=ctime_ns=1792256311406882987 match original provenance. All path components non-symlink/canonical; no credential contents or digest recorded |
| Actual mount | Exactly one bind to `/run/secrets/e_password`, RW=false, Source `/host_mnt/Users/ferozebasha/.sbom-uuid-w17-e/postgres-password`; no duplicate/alternate/extra mount. Derived equivalence is exactly `/host_mnt` + the verified original absolute host path |
| Content check | **PASS at 2026-10-18T02:59:50.494869+00:00**: exactly one bounded5s root-context read in the pinned E container, captured bytes compared with the pinned host file using in-memory constant-time equality; only boolean true and safe metadata persisted. No secret in argv/environment/log/new file/hash. No inode equality assumed across macOS/VM |
| Initialization-context readability | PASS: explicit UID0 shell verifies regular/non-symlink/readable file before bounded `head` read; pinned container Config.User empty and docker-entrypoint.sh confirm root startup context. No chmod/chown/credential replacement. This establishes mounted-byte readability/equivalence, **not PostgreSQL authentication or password correctness** |
| Post-check preservation | Host secret provenance and E/D/SBOM container/image/storage/network/publication/limits/current process-listener/runtime/env safe metadata unchanged before/after; no content reread. Historical application PIDs remain absent/stale, not claimed running; no A/B contents inspected |

One metadata-only helper attempt exited2 with JSONDecodeError **before** secret reading: Docker's `ps -aq --format` ignores the format and emits raw IDs (warning observed). Original helper/stop evidence retained; a separate private copy changed only `-aq`→`-a`, preserving exact exclusive-attachment equality. Its fresh read-only metadata passed, followed by the sole authorized content comparison. This is not a repeated content check, database reconnect or rewritten historical success. The source guard shares the same Docker formatting defect; removing quiet is included explicitly in the proposed diff to retain a functioning exclusive-volume gate.

### Exact source correction and reviewed diff

| Artifact | Original / proposed SHA256 |
| --- | --- |
| [uuid_integrity_control.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_integrity_control.py:146) | Original **087d2f9e12d79a250cc71b57506b052bc51dbb2b98ab0fbf6aa05e208682296c** → proposed **86661e10a6058dd2ae250eec9dd441147e0ee127d4a3902c4f8cb03a6db07c17** |
| [New offline regression tests](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/test_uuid_integrity_mount_offline.py:1) | `0337c19a14ff96340b8af09f5e26c834fbf9f5ec0f7cc8c995fe587c6aa4fdfa` |
| Private future baseline checker | `a86fe78181a4e6b576c8b279de882230b2bd30c5a2a02d7a2e6dcd95b5b6e209`; new `e_mount_checker.proposed.private.py`, syntax/pending-expiry refusals checked offline, **NOT executed against resources**. Calls the common guard without copying the defective predicate; requires independent future baseline action approval before metadata access |
| Full unified diff | `55fabe28c432054b3cf4a32b235412d027786e129868d62b5c517d5c6fc72c21`, private `control-review.diff`; exact full text also embedded in this candidate and below |

Only existing `verify_resources` definition changed;10other existing function/class definitions are AST-identical, including approval validation, PostgreSQL sessions/transactions and failure classification. Three helpers select the exact mount, check pinned host metadata and perform the bounded in-memory correlation. No arbitrary prefix/endswith/basename/traversal rewriting. Translation is allowed only on darwin with pinned local daemon/CLI/socket and exact Docker Desktop name/OS/type; non-Desktop/Linux retain the exact-host-only rule. Both representations require byte correlation **after** the existing container/project/service/image/port/limits/exclusive-volume/network/preservation gates. Bind type/one destination/RW=false are mandatory. Symlink-free canonical host path, private owner/mode/link/size and pinned inode/mtime/ctime are checked before the read and identity metadata rechecked afterward. VM inode is not compared. Unknown/malformed daemon fails closed with SafetyStop. The sole metadata command compatibility adjustment removes --quiet while retaining JSON formatting and the exact exclusive container assertion.

```diff
--- original/uuid_integrity_control.py
+++ proposed/uuid_integrity_control.py
@@ -7,11 +7,13 @@
 from __future__ import annotations
 
 import hashlib
+import hmac
 import json
 import os
 import re
 import stat
 import subprocess
+import sys
 import threading
 import time
 from contextlib import contextmanager
@@ -141,8 +143,116 @@
     return json.loads(result.stdout)
 
 
+def secret_mount(mounts, desktop):
+    """Exact E path only; Desktop translation requires verified local context.
+
+    Pure selector: it does not establish byte equivalence or read credentials.
+    Both representations still require correlate_secret after all resource gates.
+    """
+    expected = "/Users/ferozebasha/.sbom-uuid-w17-e/postgres-password"
+    require(str(PASSWORD) == expected, "Configured E secret path changed")
+    selected = [m for m in mounts if m.get("Destination") == "/run/secrets/e_password"]
+    require(len(selected) == 1, "Exactly one E secret mount required")
+    mount = selected[0]
+    allowed = {expected}
+    if desktop is True:
+        allowed.add("/host_mnt" + expected)
+    require(
+        mount.get("Type") == "bind" and mount.get("RW") is False and mount.get("Source") in allowed,
+        "E secret mount mismatch",
+    )
+    return mount
+
+
+def credential_metadata(info):
+    return {
+        "inode": info.st_ino,
+        "uid": info.st_uid,
+        "size": info.st_size,
+        "mtime_ns": str(info.st_mtime_ns),
+        "ctime_ns": str(info.st_ctime_ns),
+    }
+
+
+def correlate_secret(plan):
+    """Bounded root initialization-context read; secret bytes never leave memory.
+
+    Caller must first verify daemon, container, mount, exclusive storage/network
+    and preservation. No SQL, credential fallback, logging, file copy or retry.
+    Host inode is checked only against macOS provenance, never against VM inode.
+    """
+    require(plan.get("password_file") == str(PASSWORD), "Dedicated E credential required")
+    require(
+        not any(p.is_symlink() for p in (PASSWORD, *PASSWORD.parents))
+        and str(PASSWORD.resolve(strict=True)) == str(PASSWORD),
+        "E secret path must be canonical and symlink-free",
+    )
+    parent = PASSWORD.parent.lstat()
+    require(
+        parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700,
+        "E secret parent must be private",
+    )
+    fd = os.open(PASSWORD, os.O_RDONLY | os.O_NOFOLLOW)
+    with os.fdopen(fd, "rb") as stream:
+        before = os.fstat(stream.fileno())
+        require(
+            stat.S_ISREG(before.st_mode)
+            and before.st_nlink == 1
+            and before.st_uid == os.getuid()
+            and stat.S_IMODE(before.st_mode) == 0o600
+            and 0 < before.st_size <= 1048576,
+            "E secret file privacy mismatch",
+        )
+        require(credential_metadata(before) == plan.get("credential_metadata"), "E secret provenance changed")
+        raw = stream.read(1048577)
+        require(len(raw) == before.st_size, "E secret read length changed")
+        # CLI/socket were pinned by the preceding resource checks. Explicit endpoint,
+        # root UID and fixed read-only script; no secret in argv, environment or logs.
+        result = subprocess.run(
+            [
+                DOCKER,
+                "--host",
+                "unix://" + SOCKET,
+                "exec",
+                "--user",
+                "0:0",
+                plan["container_id"],
+                "/bin/sh",
+                "-c",
+                'test "$(id -u)" = 0 && test -f /run/secrets/e_password '
+                "&& test ! -L /run/secrets/e_password && test -r /run/secrets/e_password "
+                "&& exec head -c 1048577 /run/secrets/e_password",
+            ],
+            capture_output=True,
+            check=False,
+            timeout=5,
+            env={"HOME": str(Path.home()), "PATH": "/usr/bin:/bin", "LC_ALL": "C"},
+        )
+        require(result.returncode == 0, "E initialization-context secret read failed")
+        equal = hmac.compare_digest(raw, result.stdout)
+        del raw, result
+        require(
+            credential_metadata(os.fstat(stream.fileno())) == plan["credential_metadata"]
+            and credential_metadata(PASSWORD.lstat()) == plan["credential_metadata"],
+            "E secret changed during correlation",
+        )
+        require(equal, "E secret content correlation failed")
+    return {"content_equal": True, "initialization_root_readable": True}
+
+
 def verify_resources(plan):
-    require(docker("info", "--format", "{{json .ID}}") == DAEMON, "Local daemon changed")
+    daemon = docker(
+        "info",
+        "--format",
+        '{"id":{{json .ID}},"os":{{json .OperatingSystem}},"name":{{json .Name}},"type":{{json .OSType}}}',
+    )
+    require(isinstance(daemon, dict) and daemon.get("id") == DAEMON, "Local daemon changed")
+    desktop = (
+        sys.platform == "darwin"
+        and daemon.get("os") == "Docker Desktop"
+        and daemon.get("name") == "docker-desktop"
+        and daemon.get("type") == "linux"
+    )
     fmt = (
         '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},'
         '"ports":{{json .NetworkSettings.Ports}},"mounts":{{json .Mounts}},'
@@ -171,13 +281,9 @@
         all(x["Destination"] in ("/var/lib/postgresql/data", "/run/secrets/e_password") for x in state["mounts"]),
         "Unexpected E mount",
     )
-    secret_mount = [x for x in state["mounts"] if x["Destination"] == "/run/secrets/e_password"]
-    require(
-        len(secret_mount) == 1 and secret_mount[0]["Source"] == str(PASSWORD) and secret_mount[0]["RW"] is False,
-        "E secret mount mismatch",
-    )
+    secret_mount(state["mounts"], desktop)
     attached = docker(
-        "ps", "-aq", "--no-trunc", "--filter", "volume=sbom-uuid-w17-e_e_pgdata", "--format", "{{json .ID}}"
+        "ps", "-a", "--no-trunc", "--filter", "volume=sbom-uuid-w17-e_e_pgdata", "--format", "{{json .ID}}"
     )
     require(attached == plan["container_id"], "E volume not exclusive")
     volume = docker(
@@ -208,6 +314,7 @@
     }.items():
         require(config["options"].get(k) == v, "Reviewed E bridge controls absent")
     require(digest(preservation()) == plan["preservation_sha256"], "Existing SBOM/D resources changed")
+    correlate_secret(plan)
 
 
 def preservation():
```

No migration/default/CHECK/trigger/shared guard/fixture/suite/common/expand source changed. No application/runtime/Compose/environment changes. The existing integrity CLI still validates exact independent manifest/expiry/source/target/action/attestations before calling resource verification; this correction supplies no runtime test authority. The corrected guard's content-read branch was tested offline with synthetic bytes; the independent one-off real comparison above is recorded separately, not mislabelled as a full connected integrity validation.

### Offline checks executed

Run from `/Users/ferozebasha/sbom`:

```sh
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_offline.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_expand_one_step.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_mount_offline.py
.venv/bin/python -B infra/uuid-migration/staged-runner/expand_one_step.py --mode offline
.venv/bin/python -B infra/uuid-migration/staged-runner/uuid_integrity_suite.py --mode offline
.venv/bin/python -B infra/uuid-migration/staged-runner/verify_offline.py
.venv/bin/python -B -m ruff check --no-cache infra/uuid-migration/staged-runner
.venv/bin/python -B -m ruff format --no-cache --check infra/uuid-migration/staged-runner
git -c core.fsmonitor=false diff --check
```

**53 existing integrity +21 expand +25 new mount tests =99 distinct unit tests PASS.** Integrity offline CLI separately reran its53 tests; not additional distinct coverage. All11runner Python files Ruff lint/format PASS; syntax/AST PASS; graph79active+6staged/sole085 combined/source pins PASS. Verifier42templates/14literal/18dynamic/sixDDL compilations PASS; compilation/mocks are not PostgreSQL grammar/transaction/integrity acceptance. Two additional private-checker pending/expired refusal assertions passed without Docker/SQL. Six historical migration import-order warnings remain outside this source correction; migration files unchanged.

Regression coverage: exact host source; verified Desktop source; non-Desktop/Linux strict behavior; arbitrary prefix/different user/traversal/noncanonical source; missing/multiple/wrong-destination/non-bind/read-write mounts; wrong container/project/service/image/daemon/network/preservation; malformed daemon; wrong/private/symlink/hardlink/provenance/empty-file cases; mismatch/read failure/timeout/no retry/post-read mutation; missing/expired approvals; fixed endpoint/clean environment/no database fallback. Host file fixtures contain labelled synthetic bytes only.

Initial new23-test run had3errors/1failure because macOS `/var` temp-path symlink correctly failed the production guard; only the test fixture now uses its canonical resolved temp directory. Existing53 initially exposed a string-shaped fake daemon TypeError; production validation now raises intended SafetyStop. First new-file Ruff import/unused-import findings corrected. Earlier outputs/tool history and private development summary retained; final passes do not erase these development failures. No live SQL or content retry occurred during offline development.

### New independent baseline-continuation review candidate

[Full nonsecret candidate JSON](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b1-20261018T025835274982Z/e-baseline-continuation-review-candidate.json) (private directory0700/file0600/UID501):

- Byte SHA256 **ec0014b78243040eec65a41fa7d82283620f07af6995957534659a7440499f91**.
- Created `2026-10-18T03:05:52.534943+00:00`; **expires `2026-10-18T09:05:52.534943+00:00`** (2026-10-18,14:35:52.534943 IST). This is a new independent review window; original proposal expiry2026-10-18T15:45:39.587814UTC is unchanged, not renewed or replaced.
- Purpose: exact guard/private-checker source review and **existing E baseline continuation**, not provisioning or integrity execution. Contains full diff, old/new pins,99-test evidence, actual existing E identities/mount/provenance/content boolean, original proposal/archive/preserved D085 fingerprints, historical failures, exact remaining operations and exclusions. `baseline_continuation_approved=false`, `baseline_action_approvals={}`, `accepted=false`; all seven integrity flagsfalse and `approvals={}` unchanged.
- Preserved D085 Runner13 `85507e89a3946cda7611e5498e816fcf5708af18a6549b08a4fbfe3ae1f0d80a` and Independent31 `760c7e7b0b50688fd4f7c3471219a35fa3b025f67bf3303cc15a50f44800fd30` are **verified historical protected observations**, not freshly computed today. No D SQL/re-export authorized or performed in W1.7B.1. Existing archive reused only after future integrity/source-stability review.
- E clusterID/databaseOID/authentication/raw13/semantic31 remain unknown/null; no fabricated085 marker or schema acceptance. All71-business-table emptiness on E remains unverified. Role/plpgsql owner/version/function/ACL/security compatibility and actual restore-timeout feasibility remain mandatory. No inherited broad owner exception, blanket no-owner/no-acl, new grants/memberships or timeouts exceeding2sstatement/250mslock/5sidle.

**STOPPED at operator review.** Next independent authorization must approve this exact candidate hash/full diff/new source pins/unchanged original proposal and bounded future baseline-only scope. Before any restore, separately accepted existing-E authentication/freshness/cluster identity and ownership/security checks are required. Then only reviewed restricted-owner preparation, one E schema-only restore/commit/close/independent parity, guarded sole085 INSERT/commit/close/read-back and final acceptance may proceed under explicit continuation authority. No E recreation or source re-export is proposed. A changed/expired candidate requires fresh review, not automatic renewal.

**E PostgreSQL authentication/role creation/schema restore/marker/integrity tests remain UNEXECUTED.** Zero SQL connections to E/D/A/B/production, zero DDL/DML/fixture/helper/index/backfill actions and zero Docker lifecycle/config/credential changes in this task. All193live integrity cases and DML/concurrency/recovery/performance/application acceptance remain open; final public/production cutover NO-GO.

Repository changes: control guard, new mount regression tests, this report append and master tracker only. New private evidence/source copies/diff/checker/candidate are under `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b1-20261018T025835274982Z`; originals and previous acceptance/failure records retained. W1.7B remains PARTIAL/E baseline NOT ACCEPTED; W1.7B.1 implementation/offline review is complete, pending independent source/continuation approval.


Final W1.7B.1 preservation verification at2026-10-18T03:08:04.940127UTC:2,107 other existing repository file contents unchanged; only the authorized guard/report26/tracker edited and one new mount regression test file added. Branch/HEAD/pre-existing tracked binary diff unchanged. All49historical ledger table rows (including headers) and12Phase1 issue rows retained verbatim;70local evidence links/line references valid. Prior report26 retained as exact byte prefix. Original proposal/Compose/archive/old helpers/private original guard/source pins except the explicitly proposed control replacement remain unchanged. Candidateec0014b78243040eec65a41fa7d82283620f07af6995957534659a7440499f91/expiry/pending authority and private0700/0600UID501 verified;99distinct unit tests PASS, no SQL.34-entry/35file protected evidence manifest SHA256155a2ae776ad13403cf71c7a6f188e1af3ba80bd597c955c3610aeec7dfa2b24. `git -c core.fsmonitor=false diff --check` exit0. Documentation verification added no Docker or database action, no additional content check. STOP remains at independent candidate/source review; E authentication/role/restore/marker/193livecases remain unexecuted and E baseline NOT ACCEPTED.


## W1.7B.2 — Operator-approved existing E baseline continuation

**Continuation BLOCKED at E connection creation; no new E database mutation. W1.7B's earlier provisioned infrastructure remains PARTIAL / baseline NOT ACCEPTED.** 2026-10-18, Asia/Kolkata. Fresh reviewed resource/secret guard and D085 preflight passed. Exactly one E connection-constructor attempt raised `psycopg.OperationalError` before the first identity query or transaction. No retry, role creation, restore, marker insertion, integrity test or Docker lifecycle action followed. Previous SQLSTATE42703/mount failure/correction review remain unchanged.

### Exact authority, source pins and protected approval plan

Human W1.7B.2 explicitly approved existing E baseline-only work: fresh E/D checks, E owner role if sole compatible dependency, one reviewed restore, independent parity and separate sole085 INSERT, followed by a pending test candidate. The193integrity cases were explicitly excluded. Tracker recorded IN PROGRESS before connected work; branch feat/native-user-management/HEAD2f48ff835d9e692fc84b31aaa951aad2495888ac and pre-existing dirty work preserved.

Original candidate `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b1-20261018T025835274982Z/e-baseline-continuation-review-candidate.json` verified byte SHA256 **ec0014b78243040eec65a41fa7d82283620f07af6995957534659a7440499f91**, complete contents/source/resource pins and unchanged expiry **2026-10-18T09:05:52.534943+00:00**; unexpired throughout this attempt. Original preserved. New protected `operator-approved-baseline-plan.json` byte SHA256 **a3d3ec1688dc339453ef76490c0213d22b6d7143d6f9293f44eff6fa63928456** changes only `baseline_continuation_approved=true` and the supplied baseline action entries:

```json
{
  "baseline_validate": "W17B2-E-BASELINE-VALIDATE-20261018",
  "baseline_execute": "W17B2-E-BASELINE-EXECUTE-20261018"
}
```

`accepted=false`, all seven integrity flagsfalse and integrity `approvals={}` unchanged. No test references invented. The reviewed private checker internally looks up `baseline_preflight`; an ephemeral interface view binds that key to the exact supplied baseline_validate reference for its authorized read-only metadata action. The persisted approved plan retains only operator-supplied baseline_validate/execute keys. This is an interface-name binding, not a new action/reference, source change or expansion of authority. The checker itself remains byte-identical.

Verified hashes: control **86661e10a6058dd2ae250eec9dd441147e0ee127d4a3902c4f8cb03a6db07c17**, full diff55fabe28c432054b3cf4a32b235412d027786e129868d62b5c517d5c6fc72c21, privatecheckera86fe78181a4e6b576c8b279de882230b2bd30c5a2a02d7a2e6dcd95b5b6e209, mounttests0337c19a14ff96340b8af09f5e26c834fbf9f5ec0f7cc8c995fe587c6aa4fdfa. All remaining `source_sha256_proposed` entries match; no pinned repository source was edited. Active graph remains079, staged080–085 unregistered/unreplayed. Original proposal/old guard evidence/Compose/archive/correction history preserved.

### Actual executed stage results

| Stage/check | Actual safe result |
| --- | --- |
| Resource/guard validation | START03:47:40.531519UTC / **PASS03:47:43.580685UTC**. Existing Econtainer05745ce4998f26f3b46467f13315e50affc7a689e0e2bde664b3d9e8ce4fa98a/image1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54/project-service/original creation/start/running-health/restarts/limits/mounts/actual127.0.0.1:56042 unchanged; original exclusive volume and sole accessnetwork311da1a7411dbf72e7a84804b0a61f5ff320b1054c4e9722f96dd9e511d8a144, precise localdaemon1f8c7fe5-5972-4adc-8d6e-363a38572be1/Unixsocket/CLI unchanged |
| Credential/mount | New approved guard/private checker actually invoked: exact host private UID501/inode75943438/65bytes/singlelink0600/0700parent/mtime-ctime provenance, bind/RWfalse/exact Desktop translated Source and destination verified; bounded root-context in-memory equality PASS. Corrected formatted ps command verifies sole volume attachment. Only booleans/nonsecret metadata persisted; no secret/hash/copy/rotation. This does **not** prove PostgreSQL authentication |
| Capacity | Host/Docker storage>=2GiB and memory>=1GiB headroom observed and recorded privately. Approved1CPU/512MiB/64MiBshm/PID128/PGsettings command retained; no limit/timeouts changed. Ordinary NAT outbound risk persists; not zero-egress |
| D01 identity/revision | PASS03:47:44.132445UTC — explicit D READ ONLY/PG16.15/cluster7697252084555804711/sole085 |
| D02 catalog/guards | PASS03:47:44.403449UTC — Runner13 **85507e89a3946cda7611e5498e816fcf5708af18a6549b08a4fbfe3ae1f0d80a**, Independent31 **760c7e7b0b50688fd4f7c3471219a35fa3b025f67bf3303cc15a50f44800fd30**, exact respective accepted catalog/prefix;72tables/1149columns/512indexes/60sequences/143FKs, six UUID sets/shared guard/integer graph/known B drift, no publicUUID index |
| D03–D06 security/data | PASS03:47:44.407268–.454828UTC — roles/ACLs/memberships/extensions unchanged, bound16389 exact protected owner/restrictions/configNULL/passwordNULL;71business tables empty, zero competing D clients; database/plpgsql ownership/security unchanged, no unapproved external objects |
| Source D closure | **PASS03:47:44.566642UTC**, physical connection closed. One D-only readonly session/no source mutation; not re-exported. Captured D state equals original schema-export snapshot exactly in an additional offline comparison; fresh artifact SHA256 **c0e214ba35ed0d00ef4e8004aa43955799b912ad7a8497b6cbf0638d54aab04e** |
| E connection/identity | START03:47:44.567344UTC / **FAILED_STOP03:47:44.602584UTC**, `OperationalError`, SQLSTATE unavailable/null, phase NO_TRANSACTION. Failure in `psycopg.connect` inside econnect before a connection handle was returned, before identity query or transaction entry. E authentication/identity/server version/settings/freshness/owner absence/writer checks did not run |
| Archive preservation | Existing archive93af6e8eff8b8702803748dd197b45ce429e1e559c033aee7529428b630d894e/TOC7beaa65d17dd26aa6d35820e4cdd565ffc07826076bcc39eb05fd1d74e701e02/rawSQLcecf03e7d50396a218a00eef7abd2ac4957bbaef6307f7db7063b16ebe34effb/streambc682cee88f02f043c1bf3ac987f52168a704ade807c6a5889d0fe7fad43407c bytes unchanged. Original reviewed archive source matches newly captured D state. This preservation check is not completed E owner/ACL/plpgsql/restore-dependency acceptance; fresh restore-review function was not reached |
| E owner/restore/pre-marker parity | **NOT ATTEMPTED**. Restricted-role presence/OID/attributes unknown on E; no role/grants/memberships created, no restore statement executed, no E write transaction or COMMIT, no timeout relaxation/failed-restore retry |
| E085 marker/final acceptance | **NOT ATTEMPTED**. No E clusterID/databaseOID/raw13/semantic31 observed; no marker INSERT/stamp/replay or independent E baseline acceptance. Do not infer freshness/marker absence from Docker health |
| Integrity candidate/tests | **NOT CREATED / NOT EXECUTED**. No accepted E identity/catalog exists. All193cases, synthetic fixtures, helperDDL, unique indexes/backfill/concurrency/recovery/performance/app acceptance remain unexecuted |

Exact invocation, once, with no root dotenv/PG* or database URL selection:

```sh
env -i HOME=/Users/ferozebasha PATH=/usr/bin:/bin LC_ALL=C \
  /Users/ferozebasha/sbom/.venv/bin/python -B \
  /Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b2-20261018T034519653246Z/baseline.private.py preflight
```

Process exit2; helper source SHA256 **71a205da8d0efaa8cd6c0f7673d08d74d24933d361f5568fb048ace9b7173077** retained. It imports only inert staged helpers and AST-extracted reviewed catalog definitions, excluding old initialize/main, application engine/settings, root Alembic and source export paths. Explicit D/E hostaddr127.0.0.1, distinct ports/database names/protected files, bounded options and no retry. One D read-only connection completed/closed; one E connection-constructor attempt returned no handle. No E SQL/query or transaction was observed. The failed constructor's underlying connection cleanup was not independently verified by a subsequent E session; no session-retry claim.

### Exact failure, missing evidence and recovery boundary

**Confirmed failed subcheck: E-FRESH-AUTHENTICATED / econnect / psycopg.connect, before its first SQL query.** `OperationalError`/no SQLSTATE were captured. The catch did **not retain the driver's primary reason text or server diagnostic**, so the exact cause is **UNKNOWN**. That missing diagnostic is a helper evidence limitation, not proof of invalid credentials, wrong database, service-file error, PostgreSQL security mismatch, networking failure or unavailable server. No raw driver statement, credential or connection string is reconstructed or invented.

The guard and secret-byte comparison passed, so the previous literal-path problem is resolved for this observed check. Byte equality/readability cannot establish which password the database accepts or prove connection readiness. No secret rotation, settings/source change, permission weakening, new endpoint, E restart/recreation or root-cause-specific fix is justified by the recorded evidence alone.

Smallest next operator-directed scope: **one new bounded E-only connection diagnosis retaining the sanitized primary driver reason, exception class/SQLSTATE and exact labelled failure point**, under fresh target/source/expiry/credential/resource gates. Do not automatically reconnect under this failed invocation. Preserve E volume/container/credential and all evidence. If a configuration/source/credential change is indicated, obtain its exact separate authority before correction; do not assume service, password or server configuration is the cause. Candidate expiry remains unchanged; if it expires, independent renewed review is required. No test authority transfers from the baseline references.

### Preservation, tests and files

Read-only post-stop snapshots compare D/SBOM container/image/state/start/restarts/ports/mounts/original volumes/networks, existing E full metadata, credential/environment safe metadata and current process/listener/runtime records. **PASS unchanged**; no second secret content read or database connection was used. Historical application PIDs remain absent/stale and no18000/13000 listeners; no service-running or A/B-data equivalence claim. Existing E retained running with original storage/network/port/credentials, no lifecycle/cleanup action. Source D's newly observed accepted085 catalog/data remain the pre-E-attempt observation, not a post-failure database query.

Executed checks: branch/HEAD/dirtywork/source/candidate/expiry/approved-plan preservation; new private helper syntax/AST review; real reviewed resource/private-checker/secret correlation/capacity checks; actual D readonly identity/catalog/security/71empty-table checks and physical closure; one failed E connection creation; filtered metadata post-check; offline captured-source/archive equivalence and original archive integrity. W1.7B.1's99unit/Ruff/compiler PASS remain historical against unchanged pins, **not rerun or newly claimed as PostgreSQL acceptance here**. No application/migration/integrity/benchmark tests.

Protected evidence `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b2-20261018T034519653246Z` (0700UID501/files0600): original-scope approved plan/authority/interface binding/repository baseline/helper/execution labels/resource guard/metadata/capacity/D catalog/failed E stage/source-archive correlation/preservation/error diagnosis. No password or secret hash, full connection string, business row, process environment or sensitive SQL/function body printed. Repository changes only this report append and master tracker; all pinned sources/Compose/prior reports/proposal/archive/Git work preserved.

**Decision: W1.7B.2 BLOCKED before E database mutation. Overall W1.7B retains its historical PARTIAL provisioning outcome; E baseline remains NOT ACCEPTED.** No known or unknown E COMMIT occurred because no E transaction began. No new integrity candidate/hash/expiry invented. Live integrity execution remains **NO-GO**. The original42703, subsequent mount assertion, W1.7B.1 correction and this newly failed connection remain separately evidenced.


Final W1.7B.2 documentation verification at2026-10-18T03:52:19.454636UTC:2,109 other existing repository files preserved, no new repository files; exact delta report26 append/tracker only. Branch/HEAD/pre-existing tracked binary diff unchanged;50historical ledger table rows (including headers)/12Phase1 issue rows retained;71local links/line references valid; prior report26 exact prefix preserved. Original candidate/approved two-field change/expiry/seven false integrity flags/empty test approvals/source pins/Compose/archive/privacy and E host credential metadata unchanged. Private0700/0600UID50118-entry/19file evidence manifest SHA256e7561ecd0f3f5b37740b46677c5614b8cb834a89238fbdbb8f65988c6aaa298b. Whitespace check PASS. Documentation verification made no database connection or further content comparison. Final continuation BLOCKED before E query/role/restore/marker; E baseline NOT ACCEPTED, prior provisioning PARTIAL retained and all193integrity cases unexecuted.


## W1.7B.3 — Single E connection diagnosis: complete, connection failed

**W1.7B.3 DIAGNOSIS COMPLETE — CONNECTION FAILED.** 2026-10-18, Asia/Kolkata. Exactly one fresh operator-authorized constructor attempt produced the sanitized client reason **`connection is bad: definition of service "" not found`**. The explicit unchanged `service=""` option causes an empty-name service configuration error in this attempt. No returned handle, query, transaction, COMMIT, retry or correction. E baseline remains **NOT ACCEPTED**; no role/restore/marker/integrity execution occurred.

### New authority and preserved history

Human action **W17B3-E-CONNECT-DIAG-20261018** authorizes one E-only bounded original-options diagnosis, expiring **2026-10-18T15:45:39.587814+00:00**. Verified unexpired before metadata and again immediately before the constructor. The expired W1.7B.1 baseline candidate was **not execution authority**; only its immutable source/resource reference data was read. No old baseline or integrity action was renewed/reused. Separate protected `diagnostic-authorization.private.json` records this instruction, attempt budget1/query budget0/mutation budget0 and no integrity approval.

Original W1.7B.2 helper `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b2-20261018T034519653246Z/baseline.private.py` verified SHA256 **71a205da8d0efaa8cd6c0f7673d08d74d24933d361f5568fb048ace9b7173077**, copied byte-for-byte into new private evidence, originals unchanged. W1.7B.2 final manifest e7561ecd0f3f5b37740b46677c5614b8cb834a89238fbdbb8f65988c6aaa298b/all18 referenced artifacts verified. That attempt's primary diagnostic remains missing historically; this new result does not invent an earlier captured message. Original42703/corrected source success/mount failure/guard correction+99offline tests/W1.7B.2 OperationalError remain separate preserved outcomes. Report24/25/26 and tracker read/rechecked, branch feat/native-user-management/HEAD2f48ff835d9e692fc84b31aaa951aad2495888ac/dirtywork preserved.

### Preflight and process-baseline reconciliation

Pinned guard **86661e10a6058dd2ae250eec9dd441147e0ee127d4a3902c4f8cb03a6db07c17**, exact source_sha256_proposed map and original connection-helper bytes match. Approved project .venv/psycopg3.3.4 used. Exact local Unix socket, daemon1f8c7fe5-5972-4adc-8d6e-363a38572be1, Econtainer05745ce4998f26f3b46467f13315e50affc7a689e0e2bde664b3d9e8ce4fa98a/image1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54/projectservice/start/restarts/limits, actual loopback127.0.0.1:56042, original exclusive volume and network311da1a7411dbf72e7a84804b0a61f5ff320b1054c4e9722f96dd9e511d8a144/full recorded metadata match. No Docker lifecycle/configuration change or remote daemon.

First private metadata invocation exited2 **before any constructor or secret correlation**, because it compared all host listeners/repository tool processes with the older03:48UTC baseline. Read-only reconciliation confirmed no E/D/SBOM resource or application-runtime drift: original repository process identities remain; two additional processes are ChatGPT Codex node_repl PID62024 and UV-managed Python PID62151 (parent chain through62036/48081 verified), with no observed E/D TCP connection. Same rapportd PID989 changed its unrelated wildcard listeners62103/62104→62105/62106. These are tooling/system-listener differences outside E/D/SBOM preservation, not a waived target/credential/security mismatch. Native historical SBOM PIDs/runtime metadata remain absent/stale as before; no new API/worker/Beat/frontend signatures or18000/13000listeners.

Original first helper SHA **18295294e87ab3302839bac202d655a2c09968fb24b7127f5bdfd72e2dff2724** and exit2/stopped record retained. Separate execution copy uses the captured current verified process baseline, retaining every exact historical target/resource check; only that private historical-process-reference and new evidence filenames changed. Original connection AST/meaningful options remained byte-equivalent at AST level. No constructor ran during reconciliation; this was not a second PostgreSQL attempt. No pinned repository source was changed to reconcile the overly broad private comparison.

Fresh preflight **PASS2026-10-18T13:57:32.702384UTC**: exact target/resources/provenance/private0600single-link UID501/inode75943438/65bytes/0700parent/unchanged timestamps, exact Desktop host/VM bind mapping and RWfalse destination. Approved guard performed **one** bounded in-memory host/mounted-secret correlation, equal=true, no value/digest/copy/log. Exclusive E volume and sole network membership verified with corrected formatted ps. Non-SQL E process metadata showed six postgres commands and no unexpected visible administration command; this cannot prove zero SQL sessions/locks. No D SQL/refreshed D085 catalog/export or A/B/production connection was performed; D085 hashes quoted elsewhere remain historical references in this task.

### Diagnostic helper and offline checks

Actual executed private helper: `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b3-20261018T135226273263Z/connection-diagnosis-reconciled.private.py`, SHA256 **323f031fe7fe7fca6ed63c531b9c322d07ce1f028e59a55fb872ac9446e19044**. Directory0700/files0600UID501. Syntax/import/AST checks and9synthetic sanitizer samples plus synthetic client-error fallback/classification and mocked constructor assertions PASS before live use. First and reconciled offline evidence retained separately. These are not PostgreSQL integrity tests; the historical99offline suite was not rerun here.

The helper contains **one** psycopg.connect call, AST-identical to original W1.7B.2, including literal host/hostaddr127.0.0.1/port56042/databaseuuid_w17_e_integrity/useruuid_w1_d_bootstrap, password from exact protected file in memory, service empty string, passfile/dev/null, SSL/gssdisable, connect_timeout5, autocommittrue, same application_name and original read-only/statement2s/lock250ms/idle5s/search_path/row_security options. No connection string, alternate endpoint, cursor/execute/transaction/retry path. Clean environment, no PG*/dotenv/application/service-file override supplied; suspicious service argument deliberately **not removed**. One flushed private attempt-start record before calling constructor. Success branch would close the handle without a query; actual failure branch captured safe diagnostics and stopped.

Sanitizer removes exact literal secret in memory, URI credentials/connection URIs, password/passfile/token/auth parameters, hash-like values/control characters, bounds output to1024characters, rejects multi-parameter DSN/unsafe text as UNCLASSIFIED_REDACTED; does not serialize exception args or environment. It uses sanitized diag.message_primary where present, otherwise sanitized primary client/libpq text. No secret value/hash, raw DSN or passfile contents persisted. Synthetic redaction inputs are clearly fake; no real password used by offline tests.

### Single actual connection result

| Field | Actual evidence |
| --- | --- |
| Label/stage | E-CONNECT-DIAG / psycopg.connect |
| UTC result timestamp | **2026-10-18T13:57:32.706770+00:00** (19:27:32.706770IST) |
| Actual constructor attempts | **1**, fresh operator-directed diagnosis; no prior constructor during metadata-only stop |
| Result / class | CONNECTION_FAILED / OperationalError |
| SQLSTATE | **null**, unavailable; not inferred from failure class |
| Server diag.message_primary | **null**, no server primary diagnostic supplied |
| Sanitized primary client diagnostic | **`connection is bad: definition of service "" not found`** |
| Classification / confidence | **service_configuration_error — CONFIRMED for this attempt** |
| Elapsed | **0.001991958008147776seconds**, observed constructor duration only, not a benchmark |
| Handle / queries / transactions | No handle returned; queriesfalse/transactionfalse/commits0. No second session used to verify server-side cleanup; no acquired handle to close |
| Retry/correction | None. No password/host/port/SSL/service/passfile/transaction-option change or alternate psql/pg_isready attempt |
| Process result | Diagnosis helper exit0 means useful diagnostic captured/preservation completed, **not successful PostgreSQL connection or E acceptance** |

Exact live invocation, once after offline checks and metadata reconciliation:

```sh
env -i HOME=/Users/ferozebasha PATH=/usr/bin:/bin LC_ALL=C \
  /Users/ferozebasha/sbom/.venv/bin/python -B \
  /Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b3-20261018T135226273263Z/connection-diagnosis-reconciled.private.py diagnose
```

Protected `connection-diagnostic.private.json` contains the labelled safe result; `attempt-start.private.json` contains the single flushed label/action/budget1. `preservation.private.json` at13:57:33.528272UTC verifies existing E/D/SBOM resources and current process/listener baseline unchanged. Only filtered nonmutating metadata followed the attempt, no SQL or secret reread. No unrestricted PostgreSQL logs/full process environments collected.

### Root cause and smallest proposed correction — NOT IMPLEMENTED

1. **Evidence:** unchanged original [W1.7B.2 private econnect:93](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b2-20261018T034519653246Z/baseline.private.py:93) explicitly passes `service=''`; the exact same call reproduced a libpq empty-service-definition error under clean explicit target configuration. This confirms the immediate client configuration failure in the new diagnostic and supplies an evidenced explanation consistent with the earlier constructor failure. The original earlier error text remains unrecoverable; no claim of a previously captured identical reason.
2. **Affected code:** private baseline E connection constructor; the same explicit empty service option also exists in pinned [uuid_integrity_control.py:493](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_integrity_control.py:493), a future E integrity connection path. The current source guard remains hash86661e10a6058dd2ae250eec9dd441147e0ee127d4a3902c4f8cb03a6db07c17, unchanged. D's separate constructor was not executed here or modified.
3. **Smallest proposal:** omit the explicit empty `service` keyword in a separately reviewed new E constructor copy, retaining exact target, protected credentials/passfiledev/null, clean environment/PG* refusal, SSL settings and bounded read-only protections. This avoids asking for an empty-named service without creating a service definition or changing environment/configuration. Add an offline regression asserting the service key is absent and PG*/target fallback still rejected.
4. **Impact:** no credential, Docker, role/ACL or database mutation is inherently required by this client-option correction. Updating the future pinned integrity control would change its source hash/security-sensitive connection configuration, requiring a reviewed diff/new source pins and approval reconciliation. A new private baseline helper should preserve the original failing source as evidence. No change was made in this task.
5. **Next authority:** separately approve the narrow E client-option correction/offline checks/new pins and, if desired, a new bounded E-only read-only acceptance attempt. Expired baseline approvals must be independently renewed before role/restore/marker continuation. A corrected connection has **not** been tested, and no baseline or integrity acceptance follows automatically.

The diagnostic does not establish whether E credentials, actual server identity, schema, roles or startup state would pass after the client option is corrected. Do not infer invalid credentials or repair E runtime state from this result. No schema export/restore, role/permission change,085marker, index/backfill or193test case was attempted.

### Files, preservation and final decision

Repository changes only this report append and master tracker. Original helper/evidence/report history/proposal/archive/Compose/pinned migrations/control/suite/fixtures/common/Git dirty work preserved. New protected evidence `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b3-20261018T135226273263Z` contains authorization, originals, failed metadata-only helper/stop/reconciliation, current baseline, actual helper/offline results, preflight/one attempt/diagnostic and post-metadata preservation. No live integrity approval candidate created. SourceD085 Runner13 **85507e89a3946cda7611e5498e816fcf5708af18a6549b08a4fbfe3ae1f0d80a** / Independent31 **760c7e7b0b50688fd4f7c3471219a35fa3b025f67bf3303cc15a50f44800fd30** retained as historical reference only, **not freshly measured**.

**Final: W1.7B.3 DIAGNOSIS COMPLETE — CONNECTION FAILED.** Confirmed empty-service client configuration error for one unchanged-options E attempt; proposed correction unimplemented. E baseline remains NOT ACCEPTED; previous W1.7B provisioning PARTIAL preserved. No acquired E handle/query/transaction/commit or uncertain COMMIT, no reconnect/corrective action. All193UUID integrity cases remain unexecuted; no live test approval or automatic progression.


Final W1.7B.3 documentation verification at2026-10-18T14:01:12.618802UTC:2,109 other existing repository files preserved/no new repo files; exact delta report26append/tracker only. Branch/HEAD/tracked binary diff unchanged;51historical ledger table rows including headers and12Phase1 open issue rows preserved;74local links/line references valid; prior report26 retained as exact byte prefix. Originalhelper/approvedguard/sourcepins/credentialprivacy unchanged. One constructor/zero query-transaction-commit counts verified from labelled artifacts; no connection for documentation. Private0700/0600UID50122-entry/23file evidence manifest SHA256e9e07a2eea58dc575c6044797c491871ce01cf281299f56a3ceb4ae6de42bebf; git whitespace PASS. DIAGNOSIS COMPLETE—CONNECTION FAILED, confirmed empty-service configuration error; no fix/retry/role/restore/marker/193cases, E baseline NOT ACCEPTED.


## W1.7B.4 — Empty-service correction and source-pin review

**IMPLEMENTED (STAGED) / OFFLINE VERIFIED — 2026-10-18.** The exact minimum E connection correction is implemented and source-pinned. All **119 distinct offline tests passed, 0 failed, 0 skipped**. This is source/mock acceptance only; the changed control has not received independent operator approval or real PostgreSQL authentication acceptance. **E BASELINE NOT ACCEPTED; all 193 live integrity cases NOT EXECUTED.**

### Authority, history and preservation

The operator authorized offline removal of explicitly empty `service` from the staged E constructor and a separate corrected private W1.7B.2 helper, regression tests and a fresh unapproved W1.7B.5 review candidate. No Docker commands, PostgreSQL connection attempts, real password reads, database queries/mutations, infrastructure/process actions, application changes or Git delivery occurred. Existing E resource/credential metadata is referenced from earlier protected observations, not freshly verified against a running target here.

Branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`; existing dirty work retained. Report24/report25/entire report26/tracker and actual source reviewed. W1.7B.3 evidence manifest `e9e07a2eea58dc575c6044797c491871ce01cf281299f56a3ceb4ae6de42bebf` and all 22 referenced artifacts verified offline. The original W1.7B SQLSTATE 42703, its authorized correction, mount assertion failure, W1.7B.1 correction, W1.7B.2 OperationalError and W1.7B.3 single-attempt outcome remain unchanged historical evidence.

Confirmed W1.7B.3 immediate reason: `connection is bad: definition of service "" not found`; OperationalError, null SQLSTATE/server primary, no returned handle/query/transaction/commit. This reason was captured by W1.7B.3, not retroactively recovered from W1.7B.2. Removing the empty keyword addresses the evidenced client-option defect; it does not establish credential, server, role or schema readiness.

### Exact implementation and source pins

| Artifact | Original SHA256 | New SHA256 / disposition |
| --- | --- | --- |
| `uuid_integrity_control.py` | `86661e10a6058dd2ae250eec9dd441147e0ee127d4a3902c4f8cb03a6db07c17` | `b35b286e3ba1deabfaae499c211b6280e4e1d340e584575b5ba0e069cd843188` — exact one-line deletion below |
| Failed W1.7B.2 `baseline.private.py` | `71a205da8d0efaa8cd6c0f7673d08d74d24933d361f5568fb048ace9b7173077` | Original unchanged; new protected copy `a6957973c16273c9f30758933dd202ce340dbcef6235ccfe0b965f2acc470552` |
| Executed W1.7B.3 diagnostic helper | `323f031fe7fe7fca6ed63c531b9c322d07ce1f028e59a55fb872ac9446e19044` | Unchanged; sanitizer/classifier/diagnostic AST reused unchanged |
| Earlier original guard | `087d2f9e12d79a250cc71b57506b052bc51dbb2b98ab0fbf6aa05e208682296c` | Historical original preserved |
| New `test_uuid_integrity_connection_offline.py` | New file | `ff54868ef102d2a42646d4c76bd461ab4419f653d3ef98014f605856ac9ac8f6` |
| Complete public correction diff | New artifact | `6d0ba96958194da12b544d3fe3f998cc8be11a2b4460311bf8efee2f0fc3e563` |
| Complete private correction diff | New artifact | `48d4600c052fb63be3dbd8db481b44cdee19be83eaa6652dd0d920c431fa4bb5` |

Public source: [uuid_integrity_control.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_integrity_control.py:480). All unrelated bytes, Docker Desktop translation/content correlation, credential/resource/provenance, manifest/hash/expiry/action gates, transaction/fixture/cleanup semantics remain unchanged. No `service=None`, DSN, kwargs merge or alternative service entry was introduced. The D constructor was not modified.

Complete public unified diff:

```diff
--- original/uuid_integrity_control.py
+++ proposed/uuid_integrity_control.py
@@ -490,7 +490,6 @@
                 user="uuid_w1_d_bootstrap",
                 password=raw.decode().strip(),
                 passfile="/dev/null",
-                service="",
                 sslmode="disable",
                 connect_timeout=5,
                 autocommit=True,
```

Private review artifact: [baseline-corrected.private.py](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b4-20261018T141154944489Z/baseline-corrected.private.py). Created with 0600 permissions under a 0700 UID501 directory, preserving both failed originals. Its E constructor changes only the service keyword; all other constructor arguments are AST-identical to W1.7B.2. Three diagnostic functions are AST-identical to W1.7B.3; the exception handler captures sanitized primary reason/SQLSTATE then re-raises without retry. Other original function bodies, role/catalog/transaction safeguards and D-source constructor remain unchanged. The private module, top-level initialization and historical baseline CLI were **not imported or executed**; tests extracted selected AST definitions only with mocked I/O and synthetic credentials.

Complete private unified diff:

```diff
--- original/W17B2-baseline.private.py
+++ proposed/baseline-corrected.private.py
@@ -86,11 +86,62 @@
  event(name,'PASS',physical_connection_closed=True,runner13=data['runner13'],independent31=data['independent31'])
  return data
 
+def sanitize(value, secret):
+    """Bounded primary text only; no exception-args/DSN/environment serialization."""
+    if not isinstance(value, str) or len(value) > 16384:
+        return 'UNCLASSIFIED_REDACTED'
+    text = value
+    for literal in (secret.decode(errors='replace'), secret.decode(errors='replace').strip()):
+        if literal:
+            text = text.replace(literal, '[REDACTED]')
+    text = re.sub(r'(?i)\b[a-z][a-z0-9+.-]*://[^\s<>]+', '[REDACTED_URI]', text)
+    text = re.sub(r'(?i)\b(?:SCRAM-SHA-256\$[^\s]+|md5[0-9a-f]{32}\b)', '[REDACTED_HASH]', text)
+    text = re.sub(r'(?i)\b(?:password|passfile|sslpassword|token|access_token|auth_token|PGPASSWORD|PGSERVICEFILE)\s*=\s*(?:\'(?:[^\']|\'\')*\'|"[^"]*"|[^\s,;]+)', '[REDACTED_PARAMETER]', text)
+    text = re.sub(r'(?i)\b(?:Bearer|Basic)\s+[^\s]+', '[REDACTED_AUTH]', text)
+    if len(re.findall(r'(?i)\b(?:host|hostaddr|port|dbname|user|service|options)\s*=', text)) > 1:
+        return 'UNCLASSIFIED_REDACTED'
+    if '-----BEGIN' in text or '\x00' in text:
+        return 'UNCLASSIFIED_REDACTED'
+    text = ''.join(ch if ch.isprintable() else ' ' for ch in text)
+    text = re.sub(r'\s+', ' ', text).strip()
+    return text[:1024] if text else 'UNCLASSIFIED_REDACTED'
+
+def classify(reason):
+    patterns = (
+        ('service_configuration_error', r'definition of service .* not found|service file|service name'),
+        ('authentication_rejected', r'password authentication failed|authentication failed|no pg_hba.conf entry'),
+        ('database_or_role_unavailable', r'(?:database|role) .* does not exist'),
+        ('connection_refused', r'connection refused'),
+        ('network_timeout', r'connection timeout|timeout expired|timed out'),
+        ('postgresql_startup', r'database system is starting up|database system is not yet accepting'),
+        ('invalid_connection_option', r'invalid connection option|invalid .* parameter|invalid value for parameter'),
+        ('ssl_configuration_error', r'ssl error|ssl connection|server does not support ssl'),
+    )
+    for category, pattern in patterns:
+        if re.search(pattern, reason, re.I):
+            return category
+    return 'unknown_or_unclassified'
+
+def diagnostic(error, secret):
+    code = getattr(error, 'sqlstate', None)
+    if not isinstance(code, str) or not re.fullmatch(r'[0-9A-Z]{5}', code):
+        code = None
+    primary = getattr(getattr(error, 'diag', None), 'message_primary', None)
+    server = sanitize(primary, secret) if primary else None
+    # str(error) is sanitized in memory; never persist raw exception/args.
+    client = None if server and server != 'UNCLASSIFIED_REDACTED' else sanitize(str(error), secret)
+    reason = server if server and server != 'UNCLASSIFIED_REDACTED' else client
+    return {'exception_class': type(error).__name__, 'sqlstate': code, 'server_primary': server,
+            'client_primary': client, 'reason_classification': classify(reason or '')}
+
 def econnect():
  gate('baseline_validate');info=ctl.PASSWORD.lstat();require(ctl.credential_metadata(info)==PLAN['secret_correlation']['credential_metadata'],'E credential changed')
  secret=common.private_file(ctl.PASSWORD)
  try:
-  return psycopg.connect(host='127.0.0.1',hostaddr='127.0.0.1',port=56042,dbname='uuid_w17_e_integrity',user='uuid_w1_d_bootstrap',password=secret.decode().strip(),passfile='/dev/null',service='',sslmode='disable',gssencmode='disable',connect_timeout=5,autocommit=True,application_name='uuid_w17b2_E_baseline',options='-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=5000 -c search_path=pg_catalog -c row_security=on')
+  return psycopg.connect(host='127.0.0.1',hostaddr='127.0.0.1',port=56042,dbname='uuid_w17_e_integrity',user='uuid_w1_d_bootstrap',password=secret.decode().strip(),passfile='/dev/null',sslmode='disable',gssencmode='disable',connect_timeout=5,autocommit=True,application_name='uuid_w17b2_E_baseline',options='-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=5000 -c search_path=pg_catalog -c row_security=on')
+ except Exception as error:
+  event('E-CONNECT-DIAG','CONNECTION_FAILED',**diagnostic(error,secret))
+  raise
  finally:del secret
 
 def identity(conn,expected=None):
```

### Connection invariants and existing differences

Both E calls now omit `service` completely, with no conninfo/DSN or merged implicit service. Explicit host127.0.0.1, port56042, database `uuid_w17_e_integrity`, user `uuid_w1_d_bootstrap`, dedicated existing password-file selection, passfile `/dev/null`, SSL disable, connect timeout5s, autocommit, application name and original bounded session options are preserved per path. All ambient PG overrides remain refused, including PGSERVICE/PGSERVICEFILE/PGSYSCONFDIR/PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD/PGPASSFILE/PGOPTIONS; no dotenv/app-engine selection.

**Pre-existing differences are not silently harmonized:** the public integrity constructor never explicitly set hostaddr, gssencmode or row_security; its application name is `uuid_w17_e_integrity`. The private baseline constructor retains hostaddr127.0.0.1, gssencmode disable, row_security on and application name `uuid_w17b2_E_baseline`. Both retain search_path pg_catalog, default_transaction_read_only on, statement2000ms/lock250ms/idle5000ms; options order differs. Tests assert all remaining public options equal the original public source, and all remaining private options equal W1.7B.2. They do **not** claim the two historical constructors are identical. Further harmonization would require separate review; W1.7B.5 proposes the stricter corrected private constructor and no live integrity execution.

The new copy deliberately retains the historical helper's PLAN initialization and wider workflow as evidence. **Do not invoke that module/CLI for W1.7B.5:** a separately reviewed E-only entrypoint must use the vetted constructor/diagnostics, new unexpired task authority and new limited read-only scope; it must not call historical main/source-check or reuse expired plans. Candidate records this execution boundary explicitly.

### Actual offline verification

| Check | Actual result |
| --- | --- |
| Existing integrity offline suite | 53 PASS / 0 FAIL / 0 SKIP |
| Existing expand-runner suite | 21 PASS / 0 FAIL / 0 SKIP |
| Existing Desktop mount regressions | 25 PASS / 0 FAIL / 0 SKIP |
| New E connection regressions | 20 PASS / 0 FAIL / 0 SKIP with explicit artifact directory |
| Expand offline mode / real in-memory graph | PASS:79 active revisions, sole active079 head, six staged successors through085; no registration or execution |
| Integrity offline CLI | PASS; reruns the same53 tests, not additional distinct coverage |
| Existing SQL/DDL compilation verifier | PASS:12 Python files;42 SQL templates/14 literal/18 dynamic/six DDL compilations; no PostgreSQL grammar/runtime proof |
| Python syntax/AST and exact source/function comparisons | PASS public/new test/private copy; no baseline module execution |
| Ruff lint / format --check | PASS all12 runner Python files |

Actual commands (repository root; no application startup):

```text
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_offline.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_expand_one_step.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_mount_offline.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_connection_offline.py --artifact-dir /Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b4-20261018T141154944489Z
.venv/bin/python -B infra/uuid-migration/staged-runner/expand_one_step.py --mode offline
.venv/bin/python -B infra/uuid-migration/staged-runner/uuid_integrity_suite.py --mode offline
.venv/bin/python -B infra/uuid-migration/staged-runner/verify_offline.py
.venv/bin/python -B -m ruff check --no-cache infra/uuid-migration/staged-runner
.venv/bin/python -B -m ruff format --no-cache --check infra/uuid-migration/staged-runner
```

The new tests intercept `psycopg.connect`, mock credential reads/stat/identity, use synthetic credentials, verify no service/DSN/config merge, exact remaining options, immutable target/passfile/timeouts/read-only scope, all11 listed ambient overrides, approval expiry/refusal/resource/source failures, sanitized client/server primary/SQLSTATE, one attempt on failure and no role/restore/marker/live-test effects. Private-copy tests require `--artifact-dir`; generic discovery without it skips the private-artifact review class, so the exact CLI above is required to reproduce the complete20 PASS result. Initial20-test run and initial Ruff lint passed; formatting adjusted only the new test file before the final full run. No new test failures were observed; historical failed executions were retained. Mocks, compilation and graph inspection do not establish PostgreSQL behavior/authentication or193-case acceptance.

### New unapproved W1.7B.5 read-only acceptance candidate

Exact nonsecret JSON: [w17b5-e-readonly-acceptance-candidate.json](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b4-20261018T141154944489Z/w17b5-e-readonly-acceptance-candidate.json).

- Byte SHA256: **62e597cdce45606a1ba878390b3d51be5e39cf9ec8cd4a1168255e882793de01**.
- Created `2026-10-18T14:18:51.915560+00:00`; proposed expiry **2026-10-19T14:18:51.915560+00:00** (19 October2026,19:48:51.915560IST).
- New review candidate, **not approved** and not renewal of the original W1.7A or expired W1.7B.1 authority. Originals unchanged. `accepted=false`, baseline/source/read-only approval flags false, action approvals empty, all seven integrity attestations false and integrity actions empty.
- Includes full diffs, original/replacement source hashes, all six migration/runner/common/fixture/suite pins, test evidence, historical E container/image/volume/network/daemon/socket and secret-metadata references. No credential contents or digest.
- Existing E references: container05745ce4998f26f3b46467f13315e50affc7a689e0e2bde664b3d9e8ce4fa98a, volume `sbom-uuid-w17-e_e_pgdata`, network `sbom-uuid-w17-e_e_access` / ID311da1a7411dbf72e7a84804b0a61f5ff320b1054c4e9722f96dd9e511d8a144, local daemon1f8c7fe5-5972-4adc-8d6e-363a38572be1, loopback127.0.0.1:56042. These are historical observations requiring fresh preflight under new authority.
- Proposed scope: exactly one E constructor, maximum one simultaneous connection, connect5s, at most64 catalog SELECT/SHOW queries and4 transaction controls, statement2s/lock250ms/idle5s, cooperative client60s; explicit READ ONLY verified, finish ROLLBACK/physical close; safe diagnostics, no fallback/retry. No business-record reads, D/A/B/production connection or mutation.
- Proposed observations: actual PostgreSQL version/cluster/databaseOID/user/session/nonrecovery/internal endpoint/data-directory correlation; fresh empty application schema/Alembic absence; role/owner/ACL/extension/auth/security/privilege/session/lock state. E's actual cluster/OID/catalog hashes/revision/version/interface remain **unknown/null**, not fabricated. Expected freshness is a predicate, not an observation.
- Historical D085 Runner13 `85507e89a3946cda7611e5498e816fcf5708af18a6549b08a4fbfe3ae1f0d80a`, Independent31 `760c7e7b0b50688fd4f7c3471219a35fa3b025f67bf3303cc15a50f44800fd30` are referenced only; no new D session. Original D085 archive SHA256 `93af6e8eff8b8702803748dd197b45ce429e1e559c033aee7529428b630d894e` verified unchanged offline; no export or restore. Existing E Compose unchanged.

**Next independent approval:** review this exact candidate SHA256, replacement control/private source diffs and limited W1.7B.5 scope; supply new unexpired action-specific read-only authority. Then fresh source/resource/secret preflight and exactly one corrected E-only authenticated read-only acceptance may be proposed through a reviewed E-only entrypoint. **STOP again after read-only evidence review, before owner-role creation/restore/marker.** Those later E mutations require a separate fresh baseline-execution authorization; no integrity-test approval transfers.

### Files, limits and final disposition

Repository delta: one-line control correction, new connection test, this report append and master tracker update. New private sources/diffs/test evidence/candidate remain in `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b4-20261018T141154944489Z`; original evidence preserved. No Compose/application/staged migration/fixture/common/expand source changes. Database/Docker mutation count0; actual PostgreSQL connection attempts0 and real secret reads0. No resources/processes queried or reconfigured in this offline task.

**W1.7B.4 IMPLEMENTED (STAGED) / OFFLINE VERIFIED.** E baseline **NOT ACCEPTED**; historical provisioning PARTIAL preserved. All193live integrity cases **NOT EXECUTED**; generation/immutability/concurrency/rollback/recovery/performance and real corrected authentication remain unverified. **STOPPED at W1.7B.5 candidate review.**


Final W1.7B.4 preservation verification at 2026-10-18T14:23:13.467424+00:00: PASS. Exactly three pre-existing repository files changed (control/report26/tracker), one new connection test; 2,108 other existing files and tracked binary diff unchanged. Original report26 exact byte prefix and all452 prior table rows outside the explicitly updated current-readiness row preserved. Candidate/source/history pins, unknown E PostgreSQL fields, empty approvals, seven false integrity attestations, private UID501/0700/0600 permissions and local evidence links verified. Whitespace PASS. Private evidence manifest SHA256 `cdd5e9b8b51326479248f30c961afd41e466fa31afaac8f42705843caceee70a` with 22 referenced artifacts; this verification performed no database/Docker/password/target access. W1.7B.4 IMPLEMENTED (STAGED) / OFFLINE VERIFIED; E baseline NOT ACCEPTED,193live cases NOT EXECUTED. STOP at W1.7B.5 review.


## W1.7B.5 — Independent candidate verification (OFFLINE ONLY)

**OFFLINE CANDIDATE REVIEW COMPLETE / OPERATOR APPROVAL PENDING.** Reviewed at 2026-10-18T14:39:31.792670+00:00. All119offline tests passed again,0failed/0skipped. Original candidate/source pins/full diffs match; no renewal, approval population or source changes. No PostgreSQL connections, Docker commands, password reads/secret correlation, resource/process access, DDL/DML or live integrity tests occurred. E BASELINE NOT ACCEPTED;193cases NOT EXECUTED.

### Original-file verification and representation

Exact original: [w17b5-e-readonly-acceptance-candidate.json](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b4-20261018T141154944489Z/w17b5-e-readonly-acceptance-candidate.json). SHA256 **62e597cdce45606a1ba878390b3d51be5e39cf9ec8cd4a1168255e882793de01**,25,226bytes. Original regular non-symlink/single-link file, UID501/mode0600; original parent UID501/mode0700. JSON parsed with duplicate-key rejection:0duplicates,35top-level fields reviewed. Original creation2026-10-18T14:18:51.915560UTC and expiry **2026-10-19T14:18:51.915560+00:00** unchanged; timezone-aware/UTC and valid at review. Final metadata/hash preservation checked below. No regenerated candidate, source edits, new approvals or silent expiry extension.

The following block contains the **complete original UTF-8 JSON, copied verbatim**, not pretty-printed/reserialized. **Zero redactions**: reviewed values are nonsecret source hashes, paths, credential metadata, synthetic/source-code expressions and historical observations; no password value/digest is present. The JSON payload between the fences, including its original terminal LF, has the same byte SHA256 above. Markdown fences/headings are not part of that hash. A separate protected verbatim review copy was byte-compared with the original; it is not a replacement candidate.

<!-- W17B5-ORIGINAL-JSON-BEGIN -->
```json
{
  "Docker_metadata_reference": {
    "Docker_CLI_sha256": "31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f",
    "E_compose_sha256": "49b0989250be326a373aa76cc13e5a935faaf21705449e19f14c04ad5182949b",
    "container": {
      "cpu": 1000000000,
      "created": "2026-10-17T16:58:52.582028672Z",
      "health": "healthy",
      "id": "05745ce4998f26f3b46467f13315e50affc7a689e0e2bde664b3d9e8ce4fa98a",
      "image": "sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54",
      "memory": 536870912,
      "mounts": [
        {
          "Destination": "/run/secrets/e_password",
          "Mode": "",
          "Propagation": "rprivate",
          "RW": false,
          "Source": "/host_mnt/Users/ferozebasha/.sbom-uuid-w17-e/postgres-password",
          "Type": "bind"
        },
        {
          "Destination": "/var/lib/postgresql/data",
          "Driver": "local",
          "Mode": "z",
          "Name": "sbom-uuid-w17-e_e_pgdata",
          "Propagation": "",
          "RW": true,
          "Source": "/var/lib/docker/volumes/sbom-uuid-w17-e_e_pgdata/_data",
          "Type": "volume"
        }
      ],
      "networks": {
        "sbom-uuid-w17-e_e_access": {
          "Aliases": [
            "sbom-uuid-w17-e-postgres_e-1",
            "postgres_e"
          ],
          "DNSNames": [
            "sbom-uuid-w17-e-postgres_e-1",
            "postgres_e",
            "05745ce4998f"
          ],
          "DriverOpts": null,
          "EndpointID": "ec3e9673ef1b123c7224398473d481018c6ca152cd02bb8ec784206913c7a615",
          "Gateway": "172.21.0.1",
          "GlobalIPv6Address": "",
          "GlobalIPv6PrefixLen": 0,
          "GwPriority": 0,
          "IPAMConfig": null,
          "IPAddress": "172.21.0.2",
          "IPPrefixLen": 16,
          "IPv6Gateway": "",
          "Links": null,
          "MacAddress": "ea:e6:c3:a4:83:d7",
          "NetworkID": "311da1a7411dbf72e7a84804b0a61f5ff320b1054c4e9722f96dd9e511d8a144"
        }
      },
      "pids": 128,
      "ports": {
        "5432/tcp": [
          {
            "HostIp": "127.0.0.1",
            "HostPort": "56042"
          }
        ]
      },
      "project": "sbom-uuid-w17-e",
      "restart_policy": "no",
      "restarts": 0,
      "running": true,
      "service": "postgres_e",
      "shm": 67108864,
      "started": "2026-10-17T16:58:52.767457922Z"
    },
    "daemon": {
      "id": "1f8c7fe5-5972-4adc-8d6e-363a38572be1",
      "name": "docker-desktop",
      "os": "Docker Desktop",
      "type": "linux"
    },
    "fresh_preflight_required": true,
    "last_live_observation_utc": "2026-10-18T13:57:32.702384+00:00",
    "live_verified_in_W17B4": false,
    "network": {
      "containers": {
        "05745ce4998f26f3b46467f13315e50affc7a689e0e2bde664b3d9e8ce4fa98a": {
          "EndpointID": "ec3e9673ef1b123c7224398473d481018c6ca152cd02bb8ec784206913c7a615",
          "IPv4Address": "172.21.0.2/16",
          "IPv6Address": "",
          "MacAddress": "ea:e6:c3:a4:83:d7",
          "Name": "sbom-uuid-w17-e-postgres_e-1"
        }
      },
      "created": "2026-10-17T16:58:52.488150963Z",
      "driver": "bridge",
      "id": "311da1a7411dbf72e7a84804b0a61f5ff320b1054c4e9722f96dd9e511d8a144",
      "internal": false,
      "ipam": {
        "Config": [
          {
            "Gateway": "172.21.0.1",
            "Subnet": "172.21.0.0/16"
          }
        ],
        "Driver": "default",
        "Options": null
      },
      "ipv6": false,
      "name": "sbom-uuid-w17-e_e_access",
      "options": {
        "com.docker.network.bridge.enable_icc": "false",
        "com.docker.network.bridge.enable_ip_masquerade": "true",
        "com.docker.network.bridge.gateway_mode_ipv4": "nat",
        "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"
      }
    },
    "ordinary_NAT_egress_risk": "Not zero-egress; keep existing accepted scope, no network/lifecycle/config change",
    "resource_evidence_path": "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b3-20261018T135226273263Z/E-resources-before.private.json",
    "resource_evidence_sha256": "1fd48386fa7b0cdc63a9fb3f51f168a6761f1612b9ff7a23fcfd08e65de5c749",
    "socket": "/Users/ferozebasha/.docker/run/docker.sock",
    "volume": {
      "created": "2026-10-17T16:58:52Z",
      "driver": "local",
      "labels": {
        "com.docker.compose.config-hash": "5981fbaa129d23f8755a580958ecd6f3a3857aceebd7cbf4998ea7c8bb9b34fc",
        "com.docker.compose.project": "sbom-uuid-w17-e",
        "com.docker.compose.version": "5.6.0",
        "com.docker.compose.volume": "e_pgdata",
        "io.sbom.uuid-migration.disposable": "true",
        "io.sbom.uuid-migration.target": "E"
      },
      "mountpoint": "/var/lib/docker/volumes/sbom-uuid-w17-e_e_pgdata/_data",
      "name": "sbom-uuid-w17-e_e_pgdata",
      "options": null
    }
  },
  "accepted": false,
  "approval_required": "Independent exact candidate/source-diff/hash/scope/expiry approval and new W17B5 single E read-only action reference. All action approvals remain empty. Later owner/restore/085 baseline execution and live integrity tests require separate fresh authorizations.",
  "approvals": {},
  "archive_reference": {
    "hash_verified_offline": true,
    "path": "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b-resume-20261017T165355805285Z/D085-schema-only.dump",
    "restore_or_reexport_authorized": false,
    "sha256": "93af6e8eff8b8702803748dd197b45ce429e1e559c033aee7529428b630d894e"
  },
  "baseline_accepted": false,
  "created_utc": "2026-10-18T14:18:51.915560+00:00",
  "credential_provenance_reviewed": false,
  "credential_reference": {
    "container_destination": "/run/secrets/e_password",
    "file_mode": "0600",
    "fresh_guard_required_before_future_attempt": true,
    "host_or_exact_verified_Desktop_translation_only": true,
    "last_correlation_result": "PASS historical W1.7B.3",
    "metadata": {
      "ctime_ns": "1792256311406882987",
      "inode": 75943438,
      "mtime_ns": "1792256311406882987",
      "size": 65,
      "uid": 501
    },
    "mount_read_only": true,
    "parent_mode": "0700",
    "password_read_in_W17B4": false,
    "path": "/Users/ferozebasha/.sbom-uuid-w17-e/postgres-password",
    "regular_non_symlink_single_link": true,
    "secret_contents_or_digest_recorded": false
  },
  "exclusive_test_window_reviewed": false,
  "expires_utc": "2026-10-19T14:18:51.915560+00:00",
  "fixture_ddl_reviewed": false,
  "historical_source_D085": {
    "freshly_measured_in_W17B4": false,
    "independent31": "760c7e7b0b50688fd4f7c3471219a35fa3b025f67bf3303cc15a50f44800fd30",
    "new_D_SQL_authorized": false,
    "role_reference": "Protected source snapshot owner_name; no guessed owner name or required cross-cluster OID equality",
    "runner13": "85507e89a3946cda7611e5498e816fcf5708af18a6549b08a4fbfe3ae1f0d80a"
  },
  "integrity_action_approvals": {},
  "not_authorized": [
    "Docker commands or SQL under this unapproved candidate",
    "Executing full historical baseline helper",
    "E owner role creation or grants",
    "Schema restore or re-export",
    "Alembic marker INSERT or stamp",
    "UUID migrations/indexes/backfill",
    "Business fixtures/temporary test DDL/193integrity cases",
    "integrity_validate/integrity_execute",
    "Application lifecycle/config/deployment/Git delivery",
    "Changing hostaddr/GSS/row_security/application_name in the integrity constructor without further review"
  ],
  "offline_verification": {
    "Ruff": "PASS lint and format all12runner Python files",
    "compiler": "PASS42templates/14literal/18dynamic/sixDDL compilations; not PostgreSQL execution",
    "failures_in_this_task": [],
    "graph": "PASS79active/6staged/combined085; active head079; no registration/execution",
    "historical_failures": "Retained in report26 and protected evidence; not rewritten",
    "python_AST_syntax": "PASS",
    "result_evidence_path": "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b4-20261018T141154944489Z/offline-results.private.json",
    "result_evidence_sha256": "c62b1c80faa59f0b04390ae4a64e28ba5e426a24821fca561fbc4c6a6a7bd652",
    "unit_tests": {
      "FAIL": 0,
      "PASS": 119,
      "SKIP": 0,
      "existing_expand": 21,
      "existing_integrity": 53,
      "existing_mount": 25,
      "new_connection": 20
    }
  },
  "original_approvals": {
    "W17A_original_expiry": "2026-10-18T15:45:39.587814+00:00",
    "W17A_original_proposal_sha256": "49f7942fa62e8865ed044357f8b0144cb4abf9c1ed786b0de5b83320eb073709",
    "W17B1_expired_candidate_sha256": "ec0014b78243040eec65a41fa7d82283620f07af6995957534659a7440499f91",
    "W17B1_original_expiry": "2026-10-18T09:05:52.534943+00:00",
    "note": "This new proposal is unapproved. Its review expiry does not extend or renew any older authorization, consumed diagnostic attempt or baseline permission.",
    "renewed_or_reused_as_authority": false,
    "unchanged": true
  },
  "outbound_risk_reviewed": false,
  "prepared_by_task": "W1.7B.4",
  "private_helper_execution_boundary": {
    "all_other_private_functions": "Preserved AST-identically; no gate bypass or executable approval created",
    "corrected_full_module_import_or_CLI_permitted": false,
    "future_entrypoint": "Separately reviewed/pinned E-only entrypoint using the vetted constructor and bounded catalog observations under new W17B5 authority. No historical initialize/main/source_check or expired approval reuse.",
    "reason": "Full historical baseline workflow includes a D source SQL preflight and historical PLAN loading. Preserve it as review evidence; do not run it as the new E-only read-only entrypoint."
  },
  "privileges_and_writers_reviewed": false,
  "proposed_W17B5_scope": {
    "D_A_B_production_connections": 0,
    "E_mutations": 0,
    "actual_connection_or_query_execution_in_W17B4": false,
    "automatic_retry": false,
    "business_record_queries": 0,
    "connection_timeout_seconds": 5,
    "cooperative_client_budget_seconds": 60,
    "fresh_source_resource_secret_preflight": true,
    "idle_transaction_timeout_ms": 5000,
    "lock_timeout_ms": 250,
    "maximum_E_constructor_attempts": 1,
    "maximum_catalog_SELECT_SHOW_queries": 64,
    "maximum_simultaneous_connections": 1,
    "maximum_transaction_controls": 4,
    "read_only_transaction": "Explicit bounded READ ONLY; verify transaction_read_only=on; finish ROLLBACK and physical close",
    "server_restart_or_container_lifecycle": false,
    "source_mutations": 0,
    "statement_timeout_ms": 2000
  },
  "proposed_assertions": [
    "Exact current source pins/approved fresh action/expiry before any runtime; current E resource/process baseline reconciled, exact daemon/socket/container/image/original exclusive storage/sole network/loopback/caps/start-restarts preserved",
    "Existing credential privacy/provenance/exact mount translation/read-only bind and fresh bounded in-memory correlation under new authority; no secret output or fallback",
    "Exactly one corrected explicit E connection; actual database/current_user/session_user; READ ONLY on; server160015/non-recovery/origin, host(server addr) compared with fresh Docker bridge IP:5432, separately host publication56042",
    "New E system identifier via permitted pg_control_system and positive database OID; cluster must differ from D7697252084555804711; record newly observed values, no fabricated historical equality",
    "PGDATA/postmaster start/storage correlation and exact bounded timeouts/authentication settings/maxconnections12/sharedbuffers64MB/workmem4MB; no config changes",
    "Fresh user schema: expected public schema only, no application tables/functions/triggers/rules/policies or imported schema; safely test alembic_version absence without assuming it exists",
    "Database/public schema owners/ACLs/default ACLs and built-in role/membership topology match reviewed fresh expectations; exact protected source-owner role presence observed, expected absent before future creation; no role/grant action",
    "plpgsql owner/version/schema/functional/security/ACL properties checked against protected source reference; no inherited exception",
    "Only boolean catalog predicates for authentication properties; never read/hash/log password values; permitted catalogs and relevant privilege checks only",
    "No competing clients/incompatible locks observed in bounded metadata; first failed assertion or unavailable privilege stops with sanitized evidence, no retry/elevation",
    "Known rollback/physical close and independent offline evidence review; post-attempt non-SQL E/D/SBOM resources/processes preserved",
    "STOP after this read-only observation/review boundary, even if authentication succeeds. No role/schema/marker or integrity-test approval follows"
  ],
  "proposed_connection": {
    "application_name": "uuid_w17b2_E_baseline",
    "autocommit": true,
    "connect_timeout": 5,
    "dbname": "uuid_w17_e_integrity",
    "environment": "Explicit clean environment, all ambient PG* overrides refused including PGSERVICE/PGSERVICEFILE/PGSYSCONFDIR; no dotenv/application engine",
    "gssencmode": "disable",
    "host": "127.0.0.1",
    "hostaddr": "127.0.0.1",
    "options": "-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=5000 -c search_path=pg_catalog -c row_security=on",
    "passfile": "/dev/null",
    "password": "Existing protected E file only; never a literal or repository copy",
    "port": 56042,
    "safe_diagnostics": "Reviewed sanitizer; preserve primary client/server reason and SQLSTATE; no retry or secrets",
    "service_keyword_present": false,
    "source": "Corrected private econnect AST, no service keyword, no DSN/kwargs merge; preserve all original W17B2 other arguments",
    "sslmode": "disable",
    "user": "uuid_w1_d_bootstrap"
  },
  "purpose": "INDEPENDENT SOURCE-PIN AND SINGLE E READ-ONLY AUTHENTICATION/FRESHNESS REVIEW; NO DDL OR TEST EXECUTION",
  "read_only_scope_approved": false,
  "remaining_preexisting_constructor_differences": {
    "application_name": {
      "integrity_control": "uuid_w17_e_integrity",
      "private_baseline": "uuid_w17b2_E_baseline"
    },
    "gssencmode": {
      "integrity_control": "NOT EXPLICIT",
      "private_baseline": "disable"
    },
    "hostaddr": {
      "integrity_control": "NOT EXPLICIT",
      "private_baseline": "127.0.0.1"
    },
    "options": {
      "integrity_control": "-c search_path=pg_catalog -c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=5000",
      "private_baseline": "-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=5000 -c search_path=pg_catalog -c row_security=on"
    }
  },
  "root_cause_evidence": {
    "current_task_connections": 0,
    "diagnostic_sha256": "9513c7b50daf68a6f1bc91192d0b7fd6b9056e0b9fd4c2e64f9afd4f3300d28c",
    "executed_helper_sha256": "323f031fe7fe7fca6ed63c531b9c322d07ce1f028e59a55fb872ac9446e19044",
    "original_failed_baseline_sha256": "71a205da8d0efaa8cd6c0f7673d08d74d24933d361f5568fb048ace9b7173077",
    "outcome": {
      "client_primary": "connection is bad: definition of service \"\" not found",
      "commits": 0,
      "connection_handle_returned": false,
      "constructor_attempts": 1,
      "elapsed_seconds": 0.001991958008147776,
      "exception_class": "OperationalError",
      "label": "E-CONNECT-DIAG",
      "no_retry": true,
      "physical_connection_closed": "No handle returned; no extra connection used to verify server-side cleanup",
      "queries_began": false,
      "reason_classification": "service_configuration_error",
      "server_primary": null,
      "sqlstate": null,
      "stage": "psycopg.connect",
      "status": "CONNECTION_FAILED",
      "transaction_began": false,
      "utc": "2026-10-18T13:57:32.706770+00:00"
    }
  },
  "schema_parity_reviewed": false,
  "source_review": {
    "Docker_calls": 0,
    "archive_hash_preserved": true,
    "constructor_no_service_no_DSN_no_kwargs_merge": true,
    "control_diff": "--- original/uuid_integrity_control.py\n+++ proposed/uuid_integrity_control.py\n@@ -490,7 +490,6 @@\n                 user=\"uuid_w1_d_bootstrap\",\n                 password=raw.decode().strip(),\n                 passfile=\"/dev/null\",\n-                service=\"\",\n                 sslmode=\"disable\",\n                 connect_timeout=5,\n                 autocommit=True,\n",
    "control_diff_sha256": "6d0ba96958194da12b544d3fe3f998cc8be11a2b4460311bf8efee2f0fc3e563",
    "corrected_private_sha256": "a6957973c16273c9f30758933dd202ce340dbcef6235ccfe0b965f2acc470552",
    "database_connections": 0,
    "new_control_sha256": "b35b286e3ba1deabfaae499c211b6280e4e1d340e584575b5ba0e069cd843188",
    "new_security_control_is_independently_accepted": false,
    "new_test_file": "infra/uuid-migration/staged-runner/test_uuid_integrity_connection_offline.py",
    "new_test_sha256": "ff54868ef102d2a42646d4c76bd461ab4419f653d3ef98014f605856ac9ac8f6",
    "old_control_sha256": "86661e10a6058dd2ae250eec9dd441147e0ee127d4a3902c4f8cb03a6db07c17",
    "password_reads": 0,
    "preserved_preexisting_constructor_differences": {
      "application_name": {
        "integrity_control": "uuid_w17_e_integrity",
        "private_baseline": "uuid_w17b2_E_baseline"
      },
      "gssencmode": {
        "integrity_control": "NOT EXPLICIT",
        "private_baseline": "disable"
      },
      "hostaddr": {
        "integrity_control": "NOT EXPLICIT",
        "private_baseline": "127.0.0.1"
      },
      "options": {
        "integrity_control": "-c search_path=pg_catalog -c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=5000",
        "private_baseline": "-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=5000 -c search_path=pg_catalog -c row_security=on"
      }
    },
    "private_all_other_args_exact_W17B2": true,
    "private_diagnostics_AST_identical_to_W17B3": true,
    "private_diff": "--- original/W17B2-baseline.private.py\n+++ proposed/baseline-corrected.private.py\n@@ -86,11 +86,62 @@\n  event(name,'PASS',physical_connection_closed=True,runner13=data['runner13'],independent31=data['independent31'])\n  return data\n \n+def sanitize(value, secret):\n+    \"\"\"Bounded primary text only; no exception-args/DSN/environment serialization.\"\"\"\n+    if not isinstance(value, str) or len(value) > 16384:\n+        return 'UNCLASSIFIED_REDACTED'\n+    text = value\n+    for literal in (secret.decode(errors='replace'), secret.decode(errors='replace').strip()):\n+        if literal:\n+            text = text.replace(literal, '[REDACTED]')\n+    text = re.sub(r'(?i)\\b[a-z][a-z0-9+.-]*://[^\\s<>]+', '[REDACTED_URI]', text)\n+    text = re.sub(r'(?i)\\b(?:SCRAM-SHA-256\\$[^\\s]+|md5[0-9a-f]{32}\\b)', '[REDACTED_HASH]', text)\n+    text = re.sub(r'(?i)\\b(?:password|passfile|sslpassword|token|access_token|auth_token|PGPASSWORD|PGSERVICEFILE)\\s*=\\s*(?:\\'(?:[^\\']|\\'\\')*\\'|\"[^\"]*\"|[^\\s,;]+)', '[REDACTED_PARAMETER]', text)\n+    text = re.sub(r'(?i)\\b(?:Bearer|Basic)\\s+[^\\s]+', '[REDACTED_AUTH]', text)\n+    if len(re.findall(r'(?i)\\b(?:host|hostaddr|port|dbname|user|service|options)\\s*=', text)) > 1:\n+        return 'UNCLASSIFIED_REDACTED'\n+    if '-----BEGIN' in text or '\\x00' in text:\n+        return 'UNCLASSIFIED_REDACTED'\n+    text = ''.join(ch if ch.isprintable() else ' ' for ch in text)\n+    text = re.sub(r'\\s+', ' ', text).strip()\n+    return text[:1024] if text else 'UNCLASSIFIED_REDACTED'\n+\n+def classify(reason):\n+    patterns = (\n+        ('service_configuration_error', r'definition of service .* not found|service file|service name'),\n+        ('authentication_rejected', r'password authentication failed|authentication failed|no pg_hba.conf entry'),\n+        ('database_or_role_unavailable', r'(?:database|role) .* does not exist'),\n+        ('connection_refused', r'connection refused'),\n+        ('network_timeout', r'connection timeout|timeout expired|timed out'),\n+        ('postgresql_startup', r'database system is starting up|database system is not yet accepting'),\n+        ('invalid_connection_option', r'invalid connection option|invalid .* parameter|invalid value for parameter'),\n+        ('ssl_configuration_error', r'ssl error|ssl connection|server does not support ssl'),\n+    )\n+    for category, pattern in patterns:\n+        if re.search(pattern, reason, re.I):\n+            return category\n+    return 'unknown_or_unclassified'\n+\n+def diagnostic(error, secret):\n+    code = getattr(error, 'sqlstate', None)\n+    if not isinstance(code, str) or not re.fullmatch(r'[0-9A-Z]{5}', code):\n+        code = None\n+    primary = getattr(getattr(error, 'diag', None), 'message_primary', None)\n+    server = sanitize(primary, secret) if primary else None\n+    # str(error) is sanitized in memory; never persist raw exception/args.\n+    client = None if server and server != 'UNCLASSIFIED_REDACTED' else sanitize(str(error), secret)\n+    reason = server if server and server != 'UNCLASSIFIED_REDACTED' else client\n+    return {'exception_class': type(error).__name__, 'sqlstate': code, 'server_primary': server,\n+            'client_primary': client, 'reason_classification': classify(reason or '')}\n+\n def econnect():\n  gate('baseline_validate');info=ctl.PASSWORD.lstat();require(ctl.credential_metadata(info)==PLAN['secret_correlation']['credential_metadata'],'E credential changed')\n  secret=common.private_file(ctl.PASSWORD)\n  try:\n-  return psycopg.connect(host='127.0.0.1',hostaddr='127.0.0.1',port=56042,dbname='uuid_w17_e_integrity',user='uuid_w1_d_bootstrap',password=secret.decode().strip(),passfile='/dev/null',service='',sslmode='disable',gssencmode='disable',connect_timeout=5,autocommit=True,application_name='uuid_w17b2_E_baseline',options='-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=5000 -c search_path=pg_catalog -c row_security=on')\n+  return psycopg.connect(host='127.0.0.1',hostaddr='127.0.0.1',port=56042,dbname='uuid_w17_e_integrity',user='uuid_w1_d_bootstrap',password=secret.decode().strip(),passfile='/dev/null',sslmode='disable',gssencmode='disable',connect_timeout=5,autocommit=True,application_name='uuid_w17b2_E_baseline',options='-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=5000 -c search_path=pg_catalog -c row_security=on')\n+ except Exception as error:\n+  event('E-CONNECT-DIAG','CONNECTION_FAILED',**diagnostic(error,secret))\n+  raise\n  finally:del secret\n \n def identity(conn,expected=None):\n",
    "private_diff_sha256": "48d4600c052fb63be3dbd8db481b44cdee19be83eaa6652dd0d920c431fa4bb5",
    "private_helper_path": "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b4-20261018T141154944489Z/baseline-corrected.private.py",
    "public_all_other_args_exact_prior_control": true,
    "public_exact_one_line_removal": true
  },
  "source_review_approved": false,
  "source_sha256": {
    "080_uuid_public_id_expand.py": "2fc6e6f9992d0763ddf6818b9e7b62d573eef2b7cda01a39689b8fffcbc623f8",
    "081_uuid_projects_expand.py": "28f803f5c5c439f1ae0f0fdb0748368b244c2c31b060bb1a61ff6302a3d2d95e",
    "082_uuid_products_expand.py": "76d830f79e699cbdd5116c1e848cc5923f10281a764a17f0abd6c1cf8c4b5ace",
    "083_uuid_logical_sbom_expand.py": "d7f8dbe4c262f4a045572c173b7fd61e38d003fa87f9ec28093427161234495e",
    "084_uuid_sbom_source_expand.py": "13a84b0d6d3201a64be7ba90a32560a5c5738a319be1fc8af29d2364aec49803",
    "085_uuid_sbom_component_expand.py": "45f331390609e52ceddbf0968651b5ec817bf26811f6f67845d1fb6d99cdbb0f",
    "expand_one_step.py": "57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b",
    "uuid_integrity_control.py": "b35b286e3ba1deabfaae499c211b6280e4e1d340e584575b5ba0e069cd843188",
    "uuid_integrity_fixture_catalog.json": "569c40a05306bea1651556047e512629e2cca9d0723a8379b861105740c27270",
    "uuid_integrity_fixtures.py": "7eaa30d1c16653d4b700b97f9730d704ebce68ca4ba7968290d29d7f4f7e44c5",
    "uuid_integrity_suite.py": "298b5cfc1a65b62eaa8dc808758b724608282d1f4cf33af192a97f8308d40504",
    "uuid_w1_common.py": "4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94"
  },
  "synthetic_only_reviewed": false,
  "target": {
    "E_Alembic_marker": null,
    "E_database_oid": null,
    "E_independent31": null,
    "E_postmaster_started_at": null,
    "E_runner13": null,
    "E_server_address": null,
    "E_system_identifier": null,
    "database": "uuid_w17_e_integrity",
    "expected_PostgreSQL_server_version": 160015,
    "expected_before_restore": "No application objects/alembic_version table; must be observed, not assumed",
    "host": "127.0.0.1",
    "hostaddr": "127.0.0.1",
    "observed_E_PostgreSQL_version": null,
    "port": 56042,
    "user": "uuid_w1_d_bootstrap"
  },
  "task": "W1.7B.5"
}
```
<!-- W17B5-ORIGINAL-JSON-END -->

### Field-by-field independent review

| Original top-level field | Finding / approval state |
| --- | --- |
| `Docker_metadata_reference` | PASS historical reference: exact E container/image/project/service, original volume/network/daemon/socket/loopback/caps and evidence hash; no live inspection. Fresh checks required under later authority. |
| `accepted` | PENDING: false; no E acceptance or execution authority. |
| `approval_required` | PENDING: independent exact-source/candidate/expiry review and new single-E-read-only action. Later role/restore/marker/integrity authority excluded. |
| `approvals` | PENDING: empty object; no action approved. |
| `archive_reference` | PASS historical protected D085 archive93af6e8e…; no restore/re-export authorization. Candidate references earlier offline byte verification. |
| `baseline_accepted` | PENDING: false; E baseline remains NOT ACCEPTED. |
| `created_utc` | PASS original2026-10-18T14:18:51.915560+00:00 unchanged. |
| `credential_provenance_reviewed` | PENDING integrity attestation1: false. |
| `credential_reference` | PASS metadata/path/mode/mount references only; no secret contents/digest. No password stat/read/correlation in this review. |
| `exclusive_test_window_reviewed` | PENDING integrity attestation2: false. |
| `expires_utc` | PASS original2026-10-19T14:18:51.915560+00:00; UTC-aware and unexpired at review; no renewal. |
| `fixture_ddl_reviewed` | PENDING integrity attestation3: false; no helper DDL permitted. |
| `historical_source_D085` | PASS exact historical Runner13/Independent31; not newly measured; no D SQL authority. |
| `integrity_action_approvals` | PENDING: empty; integrity_validate/integrity_execute absent and not approved. |
| `not_authorized` | PASS explicit exclusions: full helper, source SQL, role/grants, restore/re-export, marker, migrations/index/backfill/fixtures/tests, application and lifecycle changes. |
| `offline_verification` | PASS candidate retains original119PASS/0FAIL/0SKIP evidence; separately rerun119 here. Mocks/compiler are not PostgreSQL acceptance. |
| `original_approvals` | PASS old hashes/expiries retained; renewed_or_reused_as_authority=false; no expired permission inherited. |
| `outbound_risk_reviewed` | PENDING integrity attestation4: false; historical NAT egress risk recorded, no network changes. |
| `prepared_by_task` | PASS W1.7B.4 provenance unchanged. |
| `private_helper_execution_boundary` | REVIEW CONDITION: full private module/CLI explicitly prohibited. Old PLAN/initialize/D preflight retained historically. Future E-only entrypoint must be separately reviewed/pinned. |
| `privileges_and_writers_reviewed` | PENDING integrity attestation5: false; fresh future metadata required. |
| `proposed_W17B5_scope` | PASS proposed oneattempt/oneconnection/64catalog/4transactioncontrols/connect5s/statement2s/lock250ms/idle5s/cooperative60s/READONLY/ROLLBACK/close/no retry/no business queries or D/A/B SQL. Runtime enforcement not yet implemented by a W17B5-specific entrypoint. |
| `proposed_assertions` | PASS read-only identity/freshness/role/ACL/privilege/security/session checks, first failure STOP and no elevation/retry; scope not baseline restoration. |
| `proposed_connection` | PASS strict private constructor arguments preserved except service omitted; no DSN/merge/fallback; passfiledevnull/host+hostaddr/SSL+GSSdisable/readonly/row_securityon. |
| `purpose` | PASS independent source-pin/single-E-read-only review only; no DDL/tests. |
| `read_only_scope_approved` | PENDING: false; no new PostgreSQL authority. |
| `remaining_preexisting_constructor_differences` | PASS public/private original hostaddr/GSS/row_security/appname/options-order differences explicitly retained; no assumption of original equality. |
| `root_cause_evidence` | PASS preserved W17B3 single client empty-service error/nullSQLSTATE/nohandle/query/transaction/commit and original helper pins; no new attempt. |
| `schema_parity_reviewed` | PENDING integrity attestation6: false; E SQL state unknown. |
| `source_review` | PASS complete current public/private diffs and old/new/test hashes verified independently; new_security_control_is_independently_accepted=false remains. |
| `source_review_approved` | PENDING: false; technical source review is not operator approval. |
| `source_sha256` | PASS all12 current source pins (six staged migrations plus control/fixture catalog/fixture/suite/expand/common) match actual file bytes. |
| `synthetic_only_reviewed` | PENDING integrity attestation7: false;193 live cases remain NOT EXECUTED. |
| `target` | PASS exact E127.0.0.1:56042/database/user. Eight actual PostgreSQL identity/state fields null; expected160015/fresh schema are future predicates only. |
| `task` | PASS W1.7B.5 review candidate; no substituted task authority. |

All35top-level fields have a separate review above. Nested identity, budget, source and approval assertions were independently checked in60labelled review checks, retained in [independent-review.private.json](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5-review-20261018T143748015507Z/independent-review.private.json). The candidate is a review proposal, not an executable authorization manifest accepted by the integrity suite.

### Source hashes and exact changes

| Current source | Verified SHA256 | Result |
| --- | --- | --- |
| `080_uuid_public_id_expand.py` | `2fc6e6f9992d0763ddf6818b9e7b62d573eef2b7cda01a39689b8fffcbc623f8` | PASS |
| `081_uuid_projects_expand.py` | `28f803f5c5c439f1ae0f0fdb0748368b244c2c31b060bb1a61ff6302a3d2d95e` | PASS |
| `082_uuid_products_expand.py` | `76d830f79e699cbdd5116c1e848cc5923f10281a764a17f0abd6c1cf8c4b5ace` | PASS |
| `083_uuid_logical_sbom_expand.py` | `d7f8dbe4c262f4a045572c173b7fd61e38d003fa87f9ec28093427161234495e` | PASS |
| `084_uuid_sbom_source_expand.py` | `13a84b0d6d3201a64be7ba90a32560a5c5738a319be1fc8af29d2364aec49803` | PASS |
| `085_uuid_sbom_component_expand.py` | `45f331390609e52ceddbf0968651b5ec817bf26811f6f67845d1fb6d99cdbb0f` | PASS |
| `expand_one_step.py` | `57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b` | PASS |
| `uuid_integrity_control.py` | `b35b286e3ba1deabfaae499c211b6280e4e1d340e584575b5ba0e069cd843188` | PASS |
| `uuid_integrity_fixture_catalog.json` | `569c40a05306bea1651556047e512629e2cca9d0723a8379b861105740c27270` | PASS |
| `uuid_integrity_fixtures.py` | `7eaa30d1c16653d4b700b97f9730d704ebce68ca4ba7968290d29d7f4f7e44c5` | PASS |
| `uuid_integrity_suite.py` | `298b5cfc1a65b62eaa8dc808758b724608282d1f4cf33af192a97f8308d40504` | PASS |
| `uuid_w1_common.py` | `4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94` | PASS |
| New connection regression test | `ff54868ef102d2a42646d4c76bd461ab4419f653d3ef98014f605856ac9ac8f6` | PASS |
| Protected corrected private baseline helper | `a6957973c16273c9f30758933dd202ce340dbcef6235ccfe0b965f2acc470552` | PASS |

Complete public diff SHA256 `6d0ba96958194da12b544d3fe3f998cc8be11a2b4460311bf8efee2f0fc3e563` and private diff `48d4600c052fb63be3dbd8db481b44cdee19be83eaa6652dd0d920c431fa4bb5` were recomputed independently with unified-diff generation from preserved originals and current bytes; both equal the complete candidate diff fields, with no omitted hunk. Public source is exactly original86661e10a6058dd2ae250eec9dd441147e0ee127d4a3902c4f8cb03a6db07c17 minus one `service="",` line. Private source changes only the E constructor keyword plus the separately documented safe diagnostic functions/handler; all other original function bodies are AST-identical. Sanitizer/classifier/diagnostic definitions equal the actual executed W17B3 definitions. No private module import/top-level/CLI execution.

Each constructor was compared against its **own original**, not each other. Corrected calls have zero positional DSN arguments, no conninfo/service keyword, no kwargs expansion/config merging, and one explicit psycopg constructor. Every other original keyword's AST is unchanged. Public original has no explicit hostaddr/GSS/row_security; private original retains host+hostaddr127.0.0.1, SSL/GSSdisable, row_securityon. Application names/options-order differences remain recorded. No D constructor change; credential/passfile/ambient-PG refusal and readonly/timeouts retained.

### Proposed scope and actual pending authority

The reviewed future target is only **127.0.0.1:56042 / uuid_w17_e_integrity / uuid_w1_d_bootstrap**. Maximum one authenticated constructor attempt and one simultaneous connection, connect5s,64catalog SELECT/SHOW statements,4transaction-control statements, statement2s/lock250ms/idle5s,60sclient window. Explicit READ ONLY must be verified; completion requires ROLLBACK/physical close and offline evidence review. No retry, fallback endpoint, business-record query, source-D/A/B/production connection or database mutation is permitted.

`accepted`, `baseline_accepted`, `source_review_approved`, `read_only_scope_approved` remain false; `approvals={}`, `integrity_action_approvals={}`. Seven integrity attestations remain false: synthetic_only_reviewed, schema_parity_reviewed, privileges_and_writers_reviewed, credential_provenance_reviewed, exclusive_test_window_reviewed, outbound_risk_reviewed, fixture_ddl_reviewed. No integrity_validate/integrity_execute, restore/role/marker action exists. Original W17A and expired W17B1/W17B2 authority not inherited. This offline-review request itself grants no connection permission.

Exact historical E container05745ce4998f26f3b46467f13315e50affc7a689e0e2bde664b3d9e8ce4fa98a, original E volume/network/networkID311da1a7411dbf72e7a84804b0a61f5ff320b1054c4e9722f96dd9e511d8a144 and daemon1f8c7fe5-5972-4adc-8d6e-363a38572be1 match candidate/protected historical evidence. These are **not live observations from this review**. Historical D085 Runner13/Independent31 match supplied values, not remeasured. Actual E SQL version/cluster/OID/postmaster/interface/catalog fingerprints/marker remain unknown/null. No assertion that E business tables are fresh/empty has been observed; that is a future read-only predicate.

### Connection and execution-path findings

No mismatch was found in the original byte hash, expiry, source pins, reviewed diffs or proposed numerical budgets. However, the proposal is **not ready for direct runtime invocation**:

1. **Confirmed full-helper exclusion:** the corrected private helper retains top-level old PLAN reads/initialize and historical CLI `resource_check();source_check('D-PREFLIGHT');fresh_e();review_archive()`. Direct execution introduces an unauthorized D connection and more than the proposed one E-only path, and reuses historical authority. Import also performs initialization/file reads. It was never imported/run here. The candidate explicitly rejects this module/CLI and requires a separately reviewed/pinned E-only entrypoint. Do not pass this candidate to the historical helper.
2. **No new bounded E-only entrypoint is pinned yet.** The constructor source is reviewed; the complete query/control orchestration, action parsing, one-attempt accounting and rollback/close/first-failure behavior for W17B5 still need source review before runtime. Integrity `Sessions.open` is not a replacement W17B5 executor: its identity expectations require already accepted E pins; its module contains separate synthetic-write/fixture functions that are excluded by this candidate. No secondary connection, worker, app initialization or mutation is permitted in the eventual limited entrypoint.
3. **60-second bound:** the original JSON calls this a cooperative client budget. It is not proof of an enforced wall-clock deadline; per-statement2s alone does not cap64queries at60s. A future entrypoint must enforce the60sremaining budget, stop scheduling queries when exhausted and close/rollback within its bounded lifecycle. Do not weaken the requested maximum or treat mock results as live timeout proof.
4. **Fresh target/security observations are unexecuted.** Operator review may approve or reject the exact source/scope proposal, but source approval alone does not establish E identity, resource/credential preservation, permissions, no conflicting writers or schema freshness. All must be checked under later explicit one-attempt authority. No generic integrity approval or later E mutation follows.

These are explicit runtime review conditions, not newly discovered database failures or permission to expand scope. This task creates no new entrypoint and modifies no source or candidate.

### Rerun evidence

| Offline check | Actual result in this review |
| --- | --- |
| Existing integrity tests |53PASS /0FAIL /0SKIP |
| Expand-runner tests |21PASS /0FAIL /0SKIP |
| Desktop mount regressions |25PASS /0FAIL /0SKIP |
| Connection regressions with explicit artifact-dir |20PASS /0FAIL /0SKIP |
| Total distinct tests |**119PASS /0FAIL /0SKIP** |
| Offline graph/source mode |PASS79active/sixstaged/combined085; active head079; no execution |
| Existing compiler |PASS12Python files/42templates/14literal/18dynamic/sixDDL compilations |
| Syntax/AST |PASS public control/new test/private helper; only compile/parse, no private import |
| Ruff lint / format |PASS all12runner files |

Exact commands, run under a clean subprocess environment without ambient PG overrides:

```text
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_offline.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_expand_one_step.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_mount_offline.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_connection_offline.py --artifact-dir /Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b4-20261018T141154944489Z
.venv/bin/python -B infra/uuid-migration/staged-runner/expand_one_step.py --mode offline
.venv/bin/python -B infra/uuid-migration/staged-runner/verify_offline.py
.venv/bin/python -B -m ruff check --no-cache infra/uuid-migration/staged-runner/
.venv/bin/python -B -m ruff format --no-cache --check infra/uuid-migration/staged-runner/
```

Protected results: [offline-results.private.json](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5-review-20261018T143748015507Z/offline-results.private.json); per-command outputs retain test discovery/counts/exit codes and hashes. All eight commands exited0. No failures/SKIPs observed; previous failures remain historical evidence. Compilation/mocks are not authenticated PostgreSQL, trigger behavior, concurrency/recovery or performance acceptance. Original W17B4 evidence manifest cdd5e9b8b51326479248f30c961afd41e466fa31afaac8f42705843caceee70a and its22 referenced artifacts match. Report26/tracker prior119PASS/source/candidate/historical-status statements remain consistent.

### Operator decision and STOP

**Next independent decision:** approve or reject exact candidate SHA25662e597cdce45606a1ba878390b3d51be5e39cf9ec8cd4a1168255e882793de01, replacement public/private source diffs and proposed single E-only READ ONLY scope. If approving a later attempt, supply an explicit new unexpired action-specific reference, while requiring the separately reviewed E-only entrypoint/source pins and budget/closure controls before any connection. Do not approve the historical full-helper CLI or inherit expired references. No reference has been invented here.

Stop again after that future single connection/read-only evidence review, even if it succeeds. Later owner-role creation/schema restore/085marker needs separate fresh baseline authority. All193integrity cases require another independent authorization; seven attestations/actions remain pending.

Repository changes in this task: **report26 append and master tracker only**. No source/test/Compose/proposal/archive changes. New protected review evidence under `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5-review-20261018T143748015507Z`,0700/0600UID501; original candidate unchanged. Existing branch/HEAD/dirty work and all prior blocked/accepted outcomes retained. **W1.7B.5 OFFLINE REVIEW COMPLETE; LIVE AUTHORIZATION PENDING. E BASELINE NOT ACCEPTED. All193live cases NOT EXECUTED. STOP.**


Final W1.7B.5 independent-review preservation verification at 2026-10-18T14:42:46.080252+00:00: PASS. Exactly report26append/tracker changed;2,110other existing repository files/branch/HEAD/tracked binary diff preserved and no new repository files. All prior nonempty tracker lines and original report26 exact byte prefix retained. Original candidate bytes/inode/UID/mode/linkcount/size/mtime/ctime/expiry unchanged; verbatim embedded JSON hash62e597cdce45606a1ba878390b3d51be5e39cf9ec8cd4a1168255e882793de01/0redactions. Source pins/full diffs/history/privacy/82local links/whitespace PASS. All119tests PASS/0FAIL/0SKIP; no live DB/Docker/secret/target access. Protected evidence manifest SHA256 `fce2c70f94966fa3f22b6abd1712efc3b22bd266abe2bceeccb52332ba963518` (17 referenced artifacts). OFFLINE CANDIDATE REVIEW COMPLETE, operator authority and reviewed bounded E-only entrypoint pending; no direct historical helper use. E baseline NOT ACCEPTED/all193integrity cases NOT EXECUTED. STOP.


## W1.7B.5A — Dedicated E-only read-only entrypoint

**IMPLEMENTED (STAGED) / OFFLINE VERIFIED.** A dedicated independently runnable entrypoint and55new offline tests are implemented. Final required regression run: **119existing +55new =174PASS /0FAIL /0SKIP**. No live PostgreSQL connection, Docker command/inspection, real password read, database mutation, schema import, role/marker operation, fixture or integrity case ran. **STOP for independent executable-source review. E BASELINE NOT ACCEPTED; all193live integrity cases NOT EXECUTED.**

### Scope, prerequisites and exact artifacts

Correct branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`; existing dirty work preserved. Original candidate remains [exact62e597cd file](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b4-20261018T141154944489Z/w17b5-e-readonly-acceptance-candidate.json), regular/single-link/non-symlink/ownedUID501/0600 with0700parent, unchanged expiry **2026-10-19T14:18:51.915560+00:00**, valid at package creation and final verification. The offline-implementation authorization did not populate source/execution approvals or renew any earlier authority.

| Artifact | Exact SHA256 / disposition |
| --- | --- |
| New [w17b5_e_readonly.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/w17b5_e_readonly.py) | `b219834b9bd54c915d52d04bdf48efc37a90d323356b4e7990b4845561e4fb75` |
| New [test_w17b5_e_readonly.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/test_w17b5_e_readonly.py) | `be32d2ecdba1555c768e9a0cefca27485bdebbe2edaf7fc3f86ae9616d6c6c1d` |
| Existing public control | `b35b286e3ba1deabfaae499c211b6280e4e1d340e584575b5ba0e069cd843188` unchanged |
| Existing connection regressions | `ff54868ef102d2a42646d4c76bd461ab4419f653d3ef98014f605856ac9ac8f6` unchanged |
| Corrected private constructor reference | `a6957973c16273c9f30758933dd202ce340dbcef6235ccfe0b965f2acc470552` unchanged; AST review only |
| Original candidate | `62e597cdce45606a1ba878390b3d51be5e39cf9ec8cd4a1168255e882793de01` unchanged |
| **Final protected executable-source review package** | **`ce8f5bc1b42654ac74e58abd79ccc9fe10d9116d9599c6cb2de40ff53b0be487`** |
| Pending execution manifest template | `7d38be29bb76d947d1936d3fd76f922d8d39937fb1b1045bc9d4648764fd2264` — NOT APPROVED |

Final package: [execution-entrypoint-review-package.v2.json](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5a-20261018T145738055997Z/execution-entrypoint-review-package.v2.json). It contains complete UTF-8 entrypoint/test source, byte hashes, complete entrypoint addition diff, exact repository/dependency pins, full live-control flow, target/credential gates, CLI/manifest contract, actual test evidence, failure/cleanup/evidence schema and pending operator decisions. Protected exact source copies also accompany it. Directory `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5a-20261018T145738055997Z` is0700; files0600/UID501. No original candidate/helper/source/proposal/archive was overwritten. Earlier package draft362e7a20a43ce981b24ff251aa3b6f5978ac54413cebef2775901243f9373a03 retained; final packaging shell-quotes formal CLI placeholders only, with no source/expiry/authority change.

### Source isolation and dependency review

The new module imports only standard-library modules at import time and defines inert constants/functions/classes. It performs no credential access, network action, filesystem mutation, app initialization or old PLAN load. Runtime import of the pinned public integrity control occurs only after new authority/source/dependency checks. Only its reviewed local Docker wrapper, exact Desktop secret-mount selector, secret correlation, credential metadata and protected-file read helpers are used. The historical private helper is never imported/executed; no initialize/main/source_check/D connection or old approval path is reachable.

The new single constructor was AST-compared with the a695private reference: all meaningful kwargs identical, password expressions treated as existing-file reads; no `service`, `service=None`, positional DSN, conninfo, kwargs expansion or configuration merging. Exact host+hostaddr127.0.0.1, port56042, database/user, passfile/dev/null, SSL/GSSdisable, connect5s, autocommit, `uuid_w17b2_E_baseline` appname and original options retained. `default_transaction_read_only=on`, `row_security=on`, search_pathpg_catalog, statement2000ms/lock250ms/idle5000ms. Existing public/private constructor differences were not harmonized and no pinned control changed.

Source pins include all six080–085 staged revisions, public control/common/expand, fixtures/catalog/suite, unchanged connection tests and both new files. No active Alembic registration or migration executor is called. Python executable SHA256 `172ed5e8e9c2ed086fdd1c335d35416ea9bb290cc974c0280f4c6d00bcd44843` / version recorded in package; standard-library imports are listed there. Installed driver and transitive repository-import distributions are independently byte-pinned over their installed `.py`/native code files (not merely version names):

| Distribution | Actual version | Aggregate installed-code SHA256 |
| --- | --- | --- |
| SQLAlchemy | 2.0.51 | `571a14db78053020576d141258d60eedc0174233f127e040896dde5a9cccb467` |
| alembic | 1.18.5 | `3ca745fd289082df8fdf24d43092c41dc8f0af582c7d4f6f215804af832bbfb6` |
| psycopg | 3.3.4 | `56c1db5f535dc66dd6b2b7d9c00794e249a5012f4bfc52d5644da9c9a2073acb` |
| psycopg-binary | 3.3.4 | `e48a4bb7e925033bdc16ba543a288f15ec6df6d574afe02808de8b5af44700de` |

A protected inert catalog reference from prior D evidence is pinned to `c0e214ba35ed0d00ef4e8004aa43955799b912ad7a8497b6cbf0638d54aab04e`. It supplies expected fresh schema/role/owner/ACL/plpgsql semantics, not executable Python or an old approval plan; it makes no D SQL connection. The exact known noncredential reference alone has a4MiB read cap because its preserved size is2,368,729bytes; manifest/candidate file cap remains1MiB. Secret reads continue through the unchanged reviewed private-file/secret guards.

### Full reviewed future live-control flow

1. Parse explicit offline/live CLI; live requires manifest/action/private evidence and exact reviewed env -i environment, no ambient PG*/PYTHONPATH/other overrides.
2. Verify original candidate exact bytes/expiry/privacy/unique JSON keys; pin new and existing sources plus installed dependencies; require target-specific operator source+readonly approval and matching sole read_only_execute ref BEFORE runtime imports, Docker or credentials.
3. Import only hash-verified inert public control/common/expand dependencies; never import historical helper or run migration/integrity functions.
4. Start cooperative monotonic60s budget, create exclusive private0600 evidence in owned0700 outside checkout.
5. Capture bounded current D/SBOM Docker metadata before/after; verify D container/image/data volume/sole access network/loopback metadata; no PostgreSQL D connection or application lifecycle call.
6. Fresh E-only local daemon/socket/CLI/container/image/start/restarts/health/limits/loopback/sole network/exclusive original volume equality with original pins; before each metadata command check deadline.
7. Reuse reviewed exact Desktop secret_mount and correlate_secret after resource gates; private-file provenance checked; one bounded in-memory host/container correlation, no secret value/digest persisted.
8. Read pinned historical source catalog REFERENCE as inert JSON only (4MiB cap for that exact SHA/path); do not execute historical helper/source preflight or load old PLAN.
9. Refresh source/dependency/approval expiry; read only original E secret using reviewed private_file guard and unchanged metadata; recheck expiry immediately before authentication.
10. One explicit connect constructor: host+hostaddr127.0.0.1/56042/db/user fixed, no service/DSN/merge, passfile/dev/null, SSL+GSSdisable,5s timeout, original private appname/session options. No retry/second connection.
11. BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; verify readonly on; run fixed23catalog SELECT/SHOW operations over22 query templates, each counted/deadline checked (max64). No supplied SQL/business row queries.
12. Identity/config/storage/publication correlation; empty schema/version absence; approved role/owner/membership/default ACL/privilege/extension security checks; exact expected source semantics, no OID equality or E cluster guess; competing clients/locks checks. On first failure stop.
13. Always reserve cleanup capacity (max4 controls; plannedBEGIN+ROLLBACK2); mandatory ROLLBACK attempt and close on success/failure/deadline with sanitized SQLSTATE/primary, no COMMIT, retry or elevation. No rollback if no handle obtained. Cleanup may exceed cooperative deadline; never suppress close because deadline expired.
14. After physical close, fresh E metadata without secret content reread and before/after D/SBOM Docker equality; remaining deadline applies. Emit read-only PASS only after preservation, never E schema-baseline/integrity acceptance.
15. STOP. No owner creation/restore/marker/fixtures/migrations/index/backfill/deployment. Future baseline mutations and193tests require independent authority.

No live mode is approved by this report/package. Original E container05745ce4998f26f3b46467f13315e50affc7a689e0e2bde664b3d9e8ce4fa98a, daemon1f8c7fe5-5972-4adc-8d6e-363a38572be1, image/original volume/sole E network and credential metadata are historical pins only. Future runtime refreshes those facts before authentication. Docker publication is checked against actual NetworkSettings metadata, and PostgreSQL server-side host address/5432 is compared to the freshly verified bridge IP; never to127.0.0.1:56042. Original ordinary-bridge outbound risk persists; no zero-egress claim or network/lifecycle change.

### Catalog, budget and cleanup contract

Exactly one owned E connection; no connection pool, worker, reconnect, fallback, psql/pg_isready or other PostgreSQL client path. Query API selects only22fixed catalog templates by label; arbitrary SELECT/DDL/DML SQL is refused. Planned successful path issues23catalog SELECT/SHOW statements, including read-only verification twice. The protected source-owner name uses a bound parameter. No business-table SELECT exists; freshness is established from catalogs/user-relation absence and safe to_regclass absence. No business data, role-password value or connection arguments are logged.

Checks cover: actual160015 database/current/session user/OID/cluster different from D7697252084555804711, nonrecovery/origin/internal endpoint/postmaster/data_directory; exact read-only/timeouts/auth/maxconnections/sharedbuffers/workmem/row_security/search_path; database/schema ownership/ACL/locale; no user relations/functions/types/default ACL/event trigger/server/FDW/publication/subscription, absent Alembic table; source-compatible built-in roles/memberships and restricted-owner absence; no role-setting overrides; privileges, boolean-only SCRAM properties and compatible plpgsql owner/function/security/ACL definitions; zero competing E clients/relation locks. Any mismatch/privilege/query error stops, with no grant/elevation/repair or second connection.

Budgets are independent counters: one constructor attempt, one concurrent connection,64catalog queries,4transaction controls; planned controls are BEGIN READ ONLY and ROLLBACK. Non-cleanup controls reserve a rollback slot. Monotonic60s starts after pure authority/source checks and before runtime metadata; it is checked before scheduling subsequent metadata/connection/query/control operations and after catalog results. Exhaustion prevents further catalog queries. **Cooperative is not a hard wall-clock guarantee**: a bounded operation may finish after the deadline; server2s statement/250ms lock/5s idle/connect5s are retained. Mandatory rollback/physical close are attempted even after exhaustion; cleanup does not silently disappear because the time budget ran out.

On connection failure before a returned handle: safe primary/SQLSTATE retained, no transaction/rollback/close or retry is fabricated. After any acquired handle: ROLLBACK attempted on success/error/deadline, then close and `.closed` acknowledgement; rollback failure logged and close still attempted. Secret reference cleared in finally; no COMMIT path exists. Post-close resource failure cannot become full success. Evidence is exclusive new0600 JSONL outside checkout in private0700 parent, labels fsynced before connection/statements, safe catalog/metadata hashes and actual accepted identity fields, sanitized bounded primary/client driver diagnostics and SQLSTATE on errors; never full kwargs/password/hash/process environment. No unknown-COMMIT recovery is needed because no COMMIT is sent; failure is retained without retry.

Application lifecycle and process startup are absent. This entrypoint compares current D/SBOM **Docker** resource metadata before/after; it does not newly certify all host application-process/listener state. The historical PID exception is preserved; any required additional host-process review belongs to explicitly authorized applicable fresh preflight. No process or Docker inspection occurred in this offline task.

### Actual offline verification and retained development failures

| Verification | Actual final result |
| --- | --- |
| Existing integrity suite |53PASS/0FAIL/0SKIP |
| Existing expand suite |21PASS/0FAIL/0SKIP |
| Existing Desktop mount suite |25PASS/0FAIL/0SKIP |
| Existing connection suite with explicit artifact-dir |20PASS/0FAIL/0SKIP |
| New dedicated entrypoint suite |55PASS/0FAIL/0SKIP |
| **Distinct total** |**174PASS/0FAIL/0SKIP** |
| New entrypoint offline mode |Exit0; actual source/dependency/candidate/reference hashes verified,0live actions |
| Existing graph/source offline mode |PASS79active/sixstaged/combined085, active head079; no execution |
| Existing SQL/DDL compiler |PASS14Python files/42templates/14literal/18dynamic/sixDDL compiles |
| New catalog SQL compilation |All22templates compiled by SQLAlchemy in new tests; not PostgreSQL grammar/runtime proof |
| AST/syntax / constructor/source assertions |PASS both new files, exactlyone constructor/no service/no historical/app/D connection path |
| Ruff lint and format |PASS all14runner Python files |

Final commands (repository root):

```text
.venv/bin/python -B -m ruff format --no-cache infra/uuid-migration/staged-runner/w17b5_e_readonly.py infra/uuid-migration/staged-runner/test_w17b5_e_readonly.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_offline.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_expand_one_step.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_mount_offline.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_connection_offline.py --artifact-dir /Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b4-20261018T141154944489Z
.venv/bin/python -B infra/uuid-migration/staged-runner/test_w17b5_e_readonly.py
.venv/bin/python -B infra/uuid-migration/staged-runner/expand_one_step.py --mode offline
.venv/bin/python -B infra/uuid-migration/staged-runner/verify_offline.py
.venv/bin/python -B -m ruff check --no-cache infra/uuid-migration/staged-runner/
.venv/bin/python -B -m ruff format --check --no-cache infra/uuid-migration/staged-runner/
.venv/bin/python -B infra/uuid-migration/staged-runner/w17b5_e_readonly.py --mode offline
```

Protected [frozen-offline-results.private.json](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5a-20261018T145738055997Z/frozen-offline-results.private.json) and per-command outputs retain counts, exit codes and hashes. “accepted” in these private offline filenames means the final passing source-verification run, **not** E/database/operator acceptance.

Development history retained, not rewritten: first40new-test run had37PASS/1FAIL/2ERROR (incorrect expected21check count and two temporary paths under macOS's symlinked temp directory). Tests corrected to canonical private temporary directories and actual count without relaxing symlink controls. A46-test intermediate run passed. First standalone offline CLI returned exit2/Refusal because the already pinned noncredential reference exceeded1MiB; a separate offline diagnosis established its actual size and led to the exact-reference-only4MiB cap. Later51/53/54 intermediate suites and final55tests passed. No live connection/retry occurred in any development run. No historical SQLSTATE42703/mount/empty-service failure or source evidence was amended.

### Pending manifest, exact future CLI and operator decision

[execution-manifest.v2.pending.json](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5a-20261018T145738055997Z/execution-manifest.v2.pending.json) is a **nonexecutable pending template**, byte SHA256 `7d38be29bb76d947d1936d3fd76f922d8d39937fb1b1045bc9d4648764fd2264`. Required keys and exact pins are in the package. It retains original candidate expiry, accepted=false, source_review_approved=false, read_only_execution_approved=false, approvals={}, integrity_action_approvals={} and all seven integrity attestations false. No read_only_execute reference was invented, no original candidate flag populated, no expired baseline authority inherited.

After independent exact-package/source review, only a **separate explicit operator authorization** may populate a new protected approved manifest's source/read-only flags and sole distinct `read_only_execute` reference. CLI reference must match it exactly; all source/dependency/target/resource/credential/budget/reference/expiry fields remain pinned. No integrity_validate/integrity_execute, role/restore/marker permission transfers. Expired candidate or any source/identity/dependency mismatch must STOP for independent review, without renewal/substitution.

Future invocation contract — **NOT AUTHORIZED / NOT EXECUTED**; quoted formal placeholders are not approvals:

```sh
/usr/bin/env -i HOME=/Users/ferozebasha PATH=/usr/bin:/bin LC_ALL=C PYTHONDONTWRITEBYTECODE=1 /Users/ferozebasha/sbom/.venv/bin/python -B /Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/w17b5_e_readonly.py --mode live --manifest /Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5a-20261018T145738055997Z/operator-approved-readonly.json --approval-id '<operator-issued-read_only_execute-reference>' --evidence '/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5a-20261018T145738055997Z/<new-exclusive-evidence>.jsonl'
```

Offline-only invocation is runnable now and was actually executed:

```sh
/Users/ferozebasha/sbom/.venv/bin/python -B /Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/w17b5_e_readonly.py --mode offline
```

**Next decision:** independently review final package SHA256 `ce8f5bc1b42654ac74e58abd79ccc9fe10d9116d9599c6cb2de40ff53b0be487` and the two new source hashes; approve/reject a later new one-attempt E-only read-only action with an explicit fresh reference before any runtime inspection/authentication. Even successful future read-only observation stops before owner-role creation/schema restore/085marker. Those later baseline mutations and193integrity cases require separate approvals.

### Final source review addition

The final new-source review added a JSON-only review-file admission check before any stat/open, so an accidentally supplied E password path cannot be read as an execution manifest. A new mocked regression proves refusal without opening the path; no real secret was inspected. Original controls/constructor semantics are untouched. Earlier unapproved source packages/templates remain preserved; only the v2 package/new source pins above are current for independent review. No action authority changed. The final exact verification commands and output hashes are in frozen-offline-results.private.json; all119existing plus55new passed after this addition.

### Final status and remaining verification

Dedicated entrypoint **IMPLEMENTED (STAGED) / OFFLINE VERIFIED**, source/package approval pending. Actual PostgreSQL authentication, catalog/driver grammar, actual rollback/close, runtime resource/secret/timeout behavior, E identity/schema/security readiness remain unexecuted. Mocks/compilation do not prove those. No real DML/concurrency/recovery/performance or UUID behavior acceptance. E actual system identifier/OID/version/marker/catalog fingerprints remain unknown; accepted D085 evidence stays historical, not remeasured.

Exact repository files created: `infra/uuid-migration/staged-runner/w17b5_e_readonly.py`, `infra/uuid-migration/staged-runner/test_w17b5_e_readonly.py`. Existing files modified: this report append and migration master tracker only. Existing control/tests/080–085/common/fixture/suite/active Alembic/Compose/config/archive/secret/history untouched; no Git delivery. **E BASELINE NOT ACCEPTED. All193live integrity cases NOT EXECUTED. STOP for independent review.**


Final W1.7B.5A preservation verification at 2026-10-18T15:24:14.977868+00:00: PASS. Two new source/test files and report26append/tracker only;2,110other baseline repository files preserved. Branch/HEAD/tracked binary diff unchanged; original report26 exact prefix and all prior nonempty tracker lines retained. Original62e597cd candidate bytes/inode/UID/mode/linkcount/size/mtime/ctime/expiry unchanged/unexpired. Current source b219834b9bd54c915d52d04bdf48efc37a90d323356b4e7990b4845561e4fb75 / tests be32d2ecdba1555c768e9a0cefca27485bdebbe2edaf7fc3f86ae9616d6c6c1d and v2 package ce8f5bc1b42654ac74e58abd79ccc9fe10d9116d9599c6cb2de40ff53b0be487 consistent; pending manifest/action/integrity flags unapproved.173test intermediate run retained; final174PASS/0FAIL/0SKIP after last guard regression. Source/AST/graph/compiler/Ruff/whitespace/private0700/0600UID501/89local links PASS. Protected evidence manifest SHA256 `2f96e429ee75d2ec4f339bc09278406181d7c39faf50a7f009651f8db5091f94` with76referenced artifacts. No PostgreSQL/Docker/secret/target access or mutation. IMPLEMENTED (STAGED) / OFFLINE VERIFIED; STOP independent executable-source review, E baseline NOT ACCEPTED,193live cases NOT EXECUTED.


## W1.7B.5A.1 — Manifest-byte binding and HBA evidence hardening

**IMPLEMENTED (STAGED) / OFFLINE VERIFIED.** Narrow authorized corrections completed in the existing E-only entrypoint and its offline tests. **174prior offline tests +19new focused tests =193offline unit tests PASS /0FAIL /0SKIP.** This numerical total is separate from the **193live PostgreSQL integrity cases, all NOT EXECUTED**. No PostgreSQL connection, Docker inspection/command, real password read, database mutation, role/restore/marker/fixture operation or Git delivery occurred. **W1.7B.5 live action NOT APPROVED; E BASELINE NOT ACCEPTED. STOP for independent review.**

### Verified starting artifacts and exact changes

Before mutation: branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`, existing dirty work snapshot; exact starting entrypoint/test/candidate/previous-package bytes verified. Original candidate retains UID501/0600regular-singlelink/non-symlink and0700parent; original expiry **2026-10-19T14:18:51.915560+00:00** unchanged/unexpired at verification. Prior packages, source copies, evidence, historical SQLSTATE42703, mount assertion, empty-service connection failure/corrections, and accepted D085 history remain intact.

| Artifact | Before SHA256 | After SHA256 / disposition |
| --- | --- | --- |
| [w17b5_e_readonly.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/w17b5_e_readonly.py) | `b219834b9bd54c915d52d04bdf48efc37a90d323356b4e7990b4845561e4fb75` | `54511bf0cf486e6838d27b943420956fb778782024fce0df3eb1b6d5904d214e` |
| [test_w17b5_e_readonly.py](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/test_w17b5_e_readonly.py) | `be32d2ecdba1555c768e9a0cefca27485bdebbe2edaf7fc3f86ae9616d6c6c1d` | `22be2f08c13c131766c57c5c41383218c139be27a1d495f7405e1f054f2f172c` |
| Original candidate | `62e597cdce45606a1ba878390b3d51be5e39cf9ec8cd4a1168255e882793de01` | Unchanged |
| Original W1.7B.5A package | `ce8f5bc1b42654ac74e58abd79ccc9fe10d9116d9599c6cb2de40ff53b0be487` | Unchanged; superseded for source review only, never executed/approved |
| Complete minimal entrypoint diff | New artifact | `a3ddef88081e0824558a7234e0c1c29de56a0a72d154f57eeab3d72767e469d3` |
| Complete test diff | New artifact | `d2f15bc80a72e8b36d7a698f7e664745c3584b9e468143b837c8910d9639af42` |
| **New protected source-review package** | New artifact | **`229b0d8810400c1eaa5fbd311e756a216c7f3123500a9aa77cd96a6ac76467a9`** |
| Pending execution-manifest template | New artifact | `775bd39803723803b8117bb3e466b3e95faf7cff743f575ffbafac7fdb78547f` — artifact hash only, NOT an operator-approved execution hash |

Package: [w17b5a1-source-review-package.json](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5a1-20261018T153700670886Z/w17b5a1-source-review-package.json); private0700 directory `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5a1-20261018T153700670886Z`,0600files/UID501. Includes complete current entrypoint/test source, both complete unified diffs, starting pins, current imported dependency/source pins, actual test results, revised CLI/raw-hash/evidence contract, HBA limitations, exact unchanged E restrictions, pending template and operator questions. Original artifacts were not replaced.

### Raw execution-manifest hash contract

New live option: `--manifest-sha256`, a separate operator-approved64lowercasehex SHA256 of the **actual approved execution-manifest file bytes**. It is distinct from the permanently pinned original candidate hash62e597cd. No operator-approved hash or action ID was generated/populated here.

Initial authority gate reads the protected manifest once as original bytes, checks the supplied byte hash **before JSON parsing**, then parses with duplicate-key rejection and validates the existing target/action/source/dependency/resource/expiry/budget contract. Missing/malformed/mismatched hash refuses before runtime control import, Docker or credential access. The original reader's JSON-only/private owner/mode/singlelink/no-symlink/outside-checkout/bounded-size safeguards are unchanged.

Evidence now records:

```text
manifest_sha256            = SHA256(original execution-manifest bytes)
manifest_canonical_sha256  = separately labelled digest(parsed plan)
candidate_sha256           = unchanged original candidate SHA256
```

The runner-specific canonical digest is not a substitute for byte approval and is not claimed to be an RFC canonicalization scheme. Whitespace/newline changes alter the raw byte hash even where parsed semantics and normalized digest stay the same. Evidence records hashes, not manifest contents or credentials.

At the existing immediate pre-authentication boundary, `recheck_manifest` reopens **the same original private manifest path**, verifies the operator-approved raw hash and exact equality to initially stored bytes, rejects duplicates anew, and requires parsed equality with the initial plan. It refreshes the original candidate/expiry and recomputes source/dependency pins; existing target/budget/resource/credential/action rules are revalidated. Changed fields are never silently adopted. `manifest_pre_auth` records both separately labelled hashes after success. On mismatch no E constructor follows; no retry or fallback is added. The resource/secret correlation that precedes this boundary still belongs to the initially verified future authority; a failed initial hash never reaches it.

Complete runtime entrypoint diff:

```diff
--- before/w17b5_e_readonly.py
+++ after/w17b5_e_readonly.py
@@ -154,6 +154,39 @@
     return json.loads(raw, object_pairs_hook=pairs)
 
 
+def approved_manifest(path, approved_sha256, original_raw=None):
+    """Bind operator authority to exact private bytes, before parsing any values."""
+    require(
+        isinstance(approved_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", approved_sha256),
+        "Operator-approved manifest byte SHA256 required",
+    )
+    raw = private_bytes(path)
+    require(sha(raw) == approved_sha256, "Approved manifest bytes changed")
+    require(original_raw is None or raw == original_raw, "Original manifest bytes changed")
+    plan = unique_json(raw)
+    require(isinstance(plan, dict), "Manifest object required")
+    return raw, plan
+
+
+def recheck_manifest(path, approved_sha256, original_raw, original_plan, original_candidate, action_ref):
+    """Reread the same path; never adopt changed values at the pre-auth boundary."""
+    raw, plan = approved_manifest(path, approved_sha256, original_raw)
+    require(plan == original_plan, "Initial manifest semantics changed")
+    fresh_candidate = candidate()
+    require(fresh_candidate == original_candidate, "Original candidate changed before authentication")
+    validate_manifest(plan, fresh_candidate, action_ref, source_pins(fresh_candidate), dependency_pins())
+    return raw, plan
+
+
+def hba_evidence():
+    """The catalog view parses the current file; it is not the loaded-rule set."""
+    return {
+        "hba_evidence_scope": "current_file_contents_and_parse_only",
+        "active_hba_rules": "UNKNOWN",
+        "password_challenge": "UNKNOWN",
+    }
+
+
 def private_bytes(path, maximum=1048576):
     """Explicit review files only; this helper is never used for the password."""
     p = Path(path)
@@ -499,7 +532,7 @@
     def check(self, label, expected, params=None):
         rows = self.query(label, params)
         require(rows == expected, "Catalog assertion failed: " + label)
-        self.evidence.emit(label, "PASS", result_sha256=digest(rows))
+        self.evidence.emit(label, "PASS", result_sha256=digest(rows), **(hba_evidence() if label == "auth" else {}))
         return rows
 
     def run(self, connect, read_secret, observe):
@@ -523,6 +556,13 @@
                 autocommit=True,
                 application_name="uuid_w17b2_E_baseline",
                 options=OPTIONS,
+            )
+            self.evidence.emit(
+                "E-CONNECT",
+                "CONNECTED",
+                credential_supplied=True,
+                authentication_method="UNKNOWN",
+                password_challenge="UNKNOWN",
             )
             self.budget.before()
             self.control(CONTROLS[0])
@@ -640,17 +680,24 @@
     parser = argparse.ArgumentParser(description=__doc__)
     parser.add_argument("--mode", choices=("offline", "live"), required=True)
     parser.add_argument("--manifest")
+    parser.add_argument("--manifest-sha256", help="Separately operator-approved exact execution-manifest byte SHA256")
     parser.add_argument("--approval-id")
     parser.add_argument("--evidence")
     args = parser.parse_args(argv)
     if args.mode == "offline":
-        require(not any((args.manifest, args.approval_id, args.evidence)), "Offline mode has no live options")
+        require(
+            not any((args.manifest, args.manifest_sha256, args.approval_id, args.evidence)),
+            "Offline mode has no live options",
+        )
         print(json.dumps(offline(), sort_keys=True))
         return 0
-    require(all((args.manifest, args.approval_id, args.evidence)), "Explicit live authority/evidence required")
+    require(
+        all((args.manifest, args.manifest_sha256, args.approval_id, args.evidence)),
+        "Explicit live authority/manifest byte SHA256/evidence required",
+    )
     require(dict(os.environ) == CLEAN_ENV, "Live mode requires the exact reviewed env -i invocation")
     c = candidate()
-    plan = unique_json(private_bytes(args.manifest))
+    manifest_raw, plan = approved_manifest(args.manifest, args.manifest_sha256)
     validate_manifest(plan, c, args.approval_id, source_pins(c), dependency_pins())
     # Import only after authority/source validation. Never import historical private source.
     import uuid_integrity_control as ctl
@@ -658,7 +705,13 @@
     budget = Budget()
     evidence = Evidence(args.evidence)
     try:
-        evidence.emit("authority", "PASS", manifest_sha256=digest(plan), candidate_sha256=CANDIDATE_SHA)
+        evidence.emit(
+            "authority",
+            "PASS",
+            manifest_sha256=sha(manifest_raw),
+            manifest_canonical_sha256=digest(plan),
+            candidate_sha256=CANDIDATE_SHA,
+        )
         before = preservation(ctl, budget)
         server_ip = resource_preflight(c, ctl, budget, evidence=evidence)
         budget.before()
@@ -666,7 +719,12 @@
         require(sha(reference) == REFERENCE_SHA, "Protected catalog reference changed")
         budget.before()
         # Refresh source/expiry gates immediately before secret/authentication.
-        validate_manifest(plan, candidate(), args.approval_id, source_pins(c), dependency_pins())
+        refreshed_raw, _ = recheck_manifest(
+            args.manifest, args.manifest_sha256, manifest_raw, plan, c, args.approval_id
+        )
+        evidence.emit(
+            "manifest_pre_auth", "PASS", manifest_sha256=sha(refreshed_raw), manifest_canonical_sha256=digest(plan)
+        )
 
         def read_secret():
             budget.before()
@@ -686,7 +744,10 @@
         require(preservation(ctl, budget) == before, "Existing D/SBOM resource metadata changed")
         evidence.emit(
             "readonly_acceptance",
-            "PASS",
+            "UNKNOWN",
+            catalog_checks="PASS",
+            reason="Current HBA file and supplied-password session do not establish effective authentication policy",
+            **hba_evidence(),
             queries=budget.queries,
             controls=budget.controls,
             attempts=budget.attempts,
@@ -697,7 +758,8 @@
         raise
     finally:
         evidence.close()
-    return 0
+    # Do not accept a mandatory active-authentication requirement from file-only evidence.
+    return 3
 
 
 if __name__ == "__main__":
```

Full test diff: [tests.diff](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5a1-20261018T153700670886Z/tests.diff), also embedded completely in the review package. Original55entrypoint tests retained;19focused tests added. Two existing mocked CLI invocations supplied the newly mandatory synthetic byte-hash argument to continue exercising their intended original refusal gate; no safety expectation was removed.

### HBA evidence: file contents are not loaded policy

The **exact SQL whitelist is unchanged**, including the same `pg_catalog.pg_hba_file_rules` query. The `auth` check's PASS is now explicitly labelled **current_file_contents_and_parse_only**, with `active_hba_rules=UNKNOWN` and `password_challenge=UNKNOWN`. It verifies the current file rows/parse and expected listed methods; it does not prove the effective last-loaded rules, successful reload, full ordered matching policy or which rule authenticated this session.

A returned handle records **CONNECTED / credential_supplied=true**, while actual authentication method/password challenge remain UNKNOWN. Subsequent unchanged identity checks verify the database/current_user/session_user for that established session. Supplying a password does not alone prove the server challenged or validated it; trust or another effective method cannot be excluded from file contents plus connection creation alone. Stored SCRAM booleans likewise describe stored-role properties, not wire authentication.

**If password-based challenge were independently proved**, success would establish credential acceptance for that specific role/endpoint/session at that moment; it would still not establish the entire loaded HBA rule set/order or file reload state. This source adds no such extra driver/server probe. No extra SQL, PostgreSQL connection, reload, privilege/configuration change or permission waiver was introduced.

Because effective authentication is a mandatory requirement not established by this evidence, the future end-of-run record is deliberately **readonly_acceptance=UNKNOWN / catalog_checks=PASS / baseline_accepted=false**, with **live exit3** even if all catalog/resource checks otherwise pass. A file parse PASS cannot silently become authentication/overall ACCEPTED. Normal failures retain STOP/no-retry behavior. Operator review must resolve the required evidence boundary separately; the runner does not downgrade the requirement or automatically broaden diagnosis.

### Preserved execution safeguards

Independent AST comparison: **all existing constants/global assignments and all fixed SQL unchanged**. Every prior top-level definition except main/Probe is AST-identical; Probe methods except evidence additions in check/run are unchanged. The exact constructor call is AST-identical, still exactlyone connect call. No change to host+hostaddr127.0.0.1:56042/database/user, image/container/daemon/network/volume, Desktop mount/content correlation, absent service, passfile/devnull, SSL/GSSdisable, clean env, options, E-only selection, source/reference controls, no historical Python import or D PostgreSQL access.

Budget/transaction/cleanup classes and operations unchanged: one attempt/one connection,64catalog queries/four controls, connect5s/statement2s/lock250ms/idle5s, cooperative60s, BEGIN READ ONLY/readonly verification/mandatory ROLLBACK and physical close on success/error/deadline. No COMMIT/DDL/DML/fixture/index/backfill or second connection introduced. The current file/HBA classification changes no SQL or scope. All original candidate and integrity restrictions remain; no wider authority-model change was needed.

### Actual offline results

| Suite/check | Actual final outcome |
| --- | --- |
| Existing integrity suite |53PASS/0FAIL/0SKIP |
| Existing expand suite |21PASS/0FAIL/0SKIP |
| Existing Desktop mount suite |25PASS/0FAIL/0SKIP |
| Existing connection suite, explicit artifact-dir |20PASS/0FAIL/0SKIP |
| Entry-point suite |74PASS/0FAIL/0SKIP: original55 +19new |
| **Total offline unit tests** |**193PASS/0FAIL/0SKIP**, including all174previous tests |
| New source offline mode |Exit0; no runtime access |
| Graph/source verification |PASS79active/sixstaged/combined085; active head079 |
| Compilation |Existing42SQLtemplates/14literal/18dynamic/sixDDL/14Python checks PASS; new fixed catalog SQL compilation retained in entrypoint tests |
| Syntax/AST/minimal-scope/constructor assertions |PASS |
| Ruff lint/format |PASS all14runner files |

Exact final commands:

```text
.venv/bin/python -B -m ruff format --no-cache infra/uuid-migration/staged-runner/w17b5_e_readonly.py infra/uuid-migration/staged-runner/test_w17b5_e_readonly.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_offline.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_expand_one_step.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_mount_offline.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_connection_offline.py --artifact-dir /Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b4-20261018T141154944489Z
.venv/bin/python -B infra/uuid-migration/staged-runner/test_w17b5_e_readonly.py
.venv/bin/python -B infra/uuid-migration/staged-runner/w17b5_e_readonly.py --mode offline
.venv/bin/python -B infra/uuid-migration/staged-runner/expand_one_step.py --mode offline
.venv/bin/python -B infra/uuid-migration/staged-runner/verify_offline.py
.venv/bin/python -B -m ruff check --no-cache infra/uuid-migration/staged-runner/
.venv/bin/python -B -m ruff format --check --no-cache infra/uuid-migration/staged-runner/
```

Outputs/exit codes/hashes: [offline-results.private.json](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5a1-20261018T153700670886Z/offline-results.private.json). All11commands exited0; initial development74-test and Ruff run also passed. **No new development test failures observed** in this task; prior task failures remain separately preserved, not rewritten. Tests use only synthetic credentials and mocked reads/connectors/metadata. Mocked `main --mode live` refusal/flow cases are not CLI connected validation or real PostgreSQL execution.

New focused regressions demonstrate raw byte hashing, whitespace versus semantics, canonical hash refusal, absent/malformed/mismatched hash before runtime, unique-key parsing, exact pre-auth reread, mutated target/source/action/bytes/initial plan/candidate refusal, refreshed dependencies/action verification, correct raw/canonical evidence fields, no pre-auth constructor after modification, and HBA/connection evidence UNKNOWN classification. Existing one-connection/query/control/deadline/rollback/closure tests all reran. Static preservation proof: [minimal-scope-review.private.json](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5a1-20261018T153700670886Z/minimal-scope-review.private.json).

### New pending package and operator review

[execution-manifest.pending.json](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5a1-20261018T153700670886Z/execution-manifest.pending.json) contains only pending authority: accepted=false, source_review_approved=false, read_only_execution_approved=false, approvals={}, integrity_action_approvals={}, seven integrity attestations false. New source/dependency pins are populated as review facts only. Its recorded artifact SHA is **not** an approved execution-manifest hash; actual operator-approved byte hash and action reference remain null in the package. Never substitute the original candidate SHA or pending-template SHA as authority.

Future CLI contract — **NOT AUTHORIZED / NOT EXECUTED**, all formal placeholders require separate independent operator approval:

```sh
/usr/bin/env -i HOME=/Users/ferozebasha PATH=/usr/bin:/bin LC_ALL=C PYTHONDONTWRITEBYTECODE=1 /Users/ferozebasha/sbom/.venv/bin/python -B /Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/w17b5_e_readonly.py --mode live --manifest /Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5a1-20261018T153700670886Z/operator-approved-readonly.json --manifest-sha256 '<operator-approved-execution-manifest-byte-sha256>' --approval-id '<operator-issued-read_only_execute-reference>' --evidence '/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b5a1-20261018T153700670886Z/<new-exclusive-evidence>.jsonl'
```

After source/package approval, the actual separately prepared approved manifest will have different bytes from the pending template once the explicitly authorized flags/action reference are populated. Its final raw SHA must be independently reviewed/approved by the operator and supplied through `--manifest-sha256`; no self-reference field inside the manifest and no inferred approval is used.

Operator decisions pending: approve/reject exact new package/source/test hashes and minimal diffs; independently approve actual future manifest bytes and fresh read_only_execute reference if authorizing a later attempt; review what separate nonmutating evidence is required for mandatory active-HBA/password-challenge assurance. No extra probe/reload/connection or authentication exception is automatically permitted. Original candidate expiry stays2026-10-19T14:18:51.915560UTC; expiration or changed pins requires a new independent review, not renewal here.

**Remaining live limitations:** E actual cluster/OID/version/schema/marker, credentials, role/ACL/security readiness, runtime rollback/close/deadline/resource behavior and effective authentication policy remain unverified. Accepted D085 facts are historical only, not remeasured. No193live integrity/DML/concurrency/recovery/performance tests ran. Exactly four existing repository files changed: entrypoint, test module, this report append and tracker. No new repository files, pinned control/active migration/Compose/config/archive/private-original changes or Git delivery.

**Final W1.7B.5A.1 IMPLEMENTED (STAGED) / OFFLINE VERIFIED. W1.7B.5 LIVE READ-ONLY EXECUTION NOT APPROVED. E BASELINE NOT ACCEPTED. All193LIVE integrity cases NOT EXECUTED. STOP at independent source/package review.**


Final W1.7B.5A.1 preservation verification at 2026-10-18T15:48:53.268036+00:00: PASS. Exactly entrypoint/tests/report26append/tracker changed;2,110other baseline repository files preserved/no new repo files. Branch/HEAD/tracked binary diff unchanged; original report26prefix/all prior nonempty tracker lines preserved. Old b219/be32 source snapshots, original ce8f5package and62e597candidate/metadata/expiry retained; original expiry2026-10-19T14:18:51.915560UTC valid and unrenewed. Current source54511bf0cf486e6838d27b943420956fb778782024fce0df3eb1b6d5904d214e/tests22be2f08c13c131766c57c5c41383218c139be27a1d495f7405e1f054f2f172c/package229b0d8810400c1eaa5fbd311e756a216c7f3123500a9aa77cd96a6ac76467a9 consistent; no operator hash/action approved or filled. All193OFFLINE unit tests(174prior+19new) PASS/0FAIL/0SKIP, distinct from193LIVE integrity cases NOTEXECUTED. Minimal-scope/SQL/constructor/budget preservation, AST/graph/compiler/Ruff/source/whitespace/private0700/0600UID501/97links PASS. Protected evidence manifest SHA256 `0ec0797ac08511963c16bde4ad4a6d63245058a969acf902c95ac90c1c3586b3` with28referenced artifacts. No PostgreSQL/Docker/real-secret/DB mutation. IMPLEMENTED (STAGED) / OFFLINE VERIFIED; live NOTAPPROVED, E baseline NOT ACCEPTED; future authpolicy/password-challenge UNKNOWN/liveexit3, STOP source/package review.
