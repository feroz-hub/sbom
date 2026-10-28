# W1.5B — Revision 079 establishment in disposable D

**Outcome: BLOCKED at fresh application-process preservation preflight. NOT IMPLEMENTED / NOT ACCEPTED.** Date: 2026-10-17, Asia/Kolkata. Explicit operator authorization was received and recorded before investigation. No PostgreSQL connection, transaction, INSERT or commit was attempted. No database or Docker resource was changed.

## Scope and acceptance

Authority permits exactly one parameterized INSERT of `079_lifecycle_provider_verification` into existing D `public.alembic_version`, after all prerequisites pass, followed by acknowledged commit, physical connection closure and independent read-only verification. It excludes A/B access, application settings/startup, Alembic execution/stamping, historical migrations, schema/role/resource changes and UUID revisions080–085.

Required evidence was read completely: [tracker](/Users/ferozebasha/sbom/docs/uuid-migration/MIGRATION_MASTER_TRACKER.md:1), [W1.5A](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/16-w1-b-schema-baseline-restore.md:1), [W1.5R](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/17-w15r-restricted-owner-role.md:1) and [isolated runner review](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/12-w1-isolated-expand-runner.md:1). Prior accepted outcomes remain historical evidence; this task does not repeat or revoke their successful execution.

Acceptance requires fresh exact D and existing-infrastructure identities; accepted schema/role/extension compatibility; empty version table supporting the exact35-character literal;72 empty base tables; absent UUID expand objects; one serialized INSERT/commit; independent exact marker/schema/data/role/resource verification. The operator explicitly requires stopping on unexpected process/resource drift. That gate failed before database access.

## Checks actually executed

| Check | Result | Evidence / limit |
| --- | --- | --- |
| Git | PASS | Branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`; initial dirty files and tracked diff recorded before tracker modification. No switch/reset/pull/commit/push |
| Active graph | PASS, static | AST-only inspection:79 unique active revisions, sole head `079_lifecycle_provider_verification`, full79-revision ancestry. Actual079 depends on078. No migration module, application initialization or Alembic environment executed |
| Staged graph | PASS, static | Six exact080–085 files form sequential successors of079; hashes below match reviewed implementation evidence. Common runner hash `4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94` unchanged |
| W1.5A protected evidence | PASS, historical integrity | Manifest SHA256 `4ea21e45be604302653fb1ce616a0dcf4cbf69d0d6a662f497dd0a9d925839ef`,23 referenced artifact hashes/private permissions verified. Recorded restore exit0, normalized source/target equality,31 categories/zero unexpected differences and empty marker. This is not a new live parity check |
| Local Docker | PASS, metadata | At `2026-10-17T03:09:49.719939+00:00`, explicit local Unix socket `/Users/ferozebasha/.docker/run/docker.sock`, owner501; daemon `1f8c7fe5-5972-4adc-8d6e-363a38572be1`, docker-desktop/29.8.2; Compose5.6.0. No remote endpoint or lifecycle commands |
| Compose | PASS | SHA256 `13e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab`; no edit/config execution |
| D container/image | PASS, metadata | Container `fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e`, image `sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54`; state/start/mount/port/network metadata match accepted W1.5A final evidence |
| D storage/network/port | PASS, metadata | Original `sbom-uuid-w1_d_pgdata`, sole D attachment/mount `/var/lib/postgresql/data`; sole access network `6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65`; actual loopback publication/listener `127.0.0.1:56041`. Retained unused private network and existing SBOM resource metadata match |
| Credentials | PASS, metadata only | Existing dedicated password file remains regular/non-symlink/nonempty, UID501/mode0600/inode75679830/65bytes, parent0700. Contents not read; no credential generated or changed; root/dev dotenv contents and process environments not read |
| Existing SBOM Docker resources | PASS, metadata | Compared filtered container/image/state/start/mount/port/network/volume fields and order-independent resource sets with accepted preservation evidence: no difference. PostgreSQL/Redis/Mailpit, persistent volumes and application network retained |
| Existing application processes | **FAIL — stop gate** | All five recorded process identities absent; exact observations below. Cannot claim preservation of running services or silently replace their historical baseline |
| Current D cluster/version/role/schema/empty tables | NOT RUN | No PostgreSQL connection after failed host preflight. Historical systemID7697252084555804711, PG16.15, roleOID16389, schema/extension exception and72 empty tables are not freshly verified |
| Version INSERT / commit / post-commit verification | NOT RUN | Zero sessions, zero INSERT attempts, zero commits. No SQLSTATE; failure is a host process-identity precondition |

The private accepted archive is380123bytes, SHA256 `8d82d9a24373d62af0be9231ffe4ba695b67142a139b8fc1a3908966b7e2a5ec`. Accepted normalized B/D fingerprint `e3e60c1a3c30fdcbe54d43d5f36d30fa88096a3aabe4af56f095f86dd4366225`; raw D snapshot fingerprint `990a33b059b58d36f7136e3d31318ff3a97cf89d6a9a11cc687b38f1bdafe42f`. The accepted snapshot shows `version_num character varying(128) NOT NULL`, sufficient for the35-character identifier. No current DB state is inferred from these historical hashes.

## Exact failed gate

Native macOS libproc metadata inspection used only AST-extracted `process_info` and `matches` definitions from [dev_runtime.py](/Users/ferozebasha/sbom/scripts/dev_runtime.py:25), with no launcher/application import or execution. `None` means absent under that function; inspection errors raise separately. At03:11:47.306461UTC the current private `.dev-runtime.json` process records were checked individually:

| Recorded role | Recorded PID | Recorded birth identity | Live observation | Identity match |
| --- | --- | --- | --- | --- |
| Launcher |23095|1792137702:755614|Absent|FAIL|
| API |23229|1792137714:732547|Absent|FAIL|
| Celery worker |23230|1792137714:736336|Absent|FAIL|
| Celery Beat |23231|1792137714:738942|Absent|FAIL|
| Frontend launcher |23232|1792137714:742176|Absent|FAIL|

These are also the historical W1.5A preservation PIDs. The first aggregate mismatch was `processes`; an attempted strict reconciliation asserted `launcher` before any DB access. Subsequent labelled metadata observations confirmed all five absent rather than attributing failure to an unknown assertion. Runtime-state records were read only for whitelisted process identity/root metadata; no service command/environment or secret values were displayed.

**Confirmed:** expected process identities cannot be verified and differ from the accepted preservation baseline. **Unknown:** when/why those processes exited, whether replacement processes exist, and actor/workflow responsible. Runtime-file timestamp proximity is not causation. No claim is made that the task stopped them or that API/frontend/worker/Beat are currently running. No services were started/restarted to repair this precondition.

## Serialization and transaction review — not executed

The [shared runner key](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_w1_common.py:33) is bigint `7160085085`; its existing implementation obtains a [session advisory lock](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/uuid_w1_common.py:595). A resumed authorized W1.5B transaction would obtain `pg_catalog.pg_try_advisory_xact_lock` with that same single-bigint key and require true, then the runner's [EXCLUSIVE NOWAIT version-table lock](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:488). Session/transaction locks share the same namespace and conflict across sessions; see [PostgreSQL16 advisory-lock documentation](https://www.postgresql.org/docs/16/explicit-locking.html#ADVISORY-LOCKS).

Under those locks it must recheck the exact empty marker and accepted schema/identity, parameterize the one literal INSERT, require rowcount1/one exact RETURNING value and no other marker rows, acknowledge one commit, close physically, then verify independently in a new bounded read-only D connection. No lock, SQL or commit was executed here. Unknown commit outcome must never cause automatic retry, stamp or cleanup.

## Staged file integrity

| File under infra/uuid-migration/staged-alembic | SHA256 |
| --- | --- |
|080_uuid_public_id_expand.py|2fc6e6f9992d0763ddf6818b9e7b62d573eef2b7cda01a39689b8fffcbc623f8|
|081_uuid_projects_expand.py|28f803f5c5c439f1ae0f0fdb0748368b244c2c31b060bb1a61ff6302a3d2d95e|
|082_uuid_products_expand.py|76d830f79e699cbdd5116c1e848cc5923f10281a764a17f0abd6c1cf8c4b5ace|
|083_uuid_logical_sbom_expand.py|d7f8dbe4c262f4a045572c173b7fd61e38d003fa87f9ec28093427161234495e|
|084_uuid_sbom_source_expand.py|13a84b0d6d3201a64be7ba90a32560a5c5738a319be1fc8af29d2364aec49803|
|085_uuid_sbom_component_expand.py|45f331390609e52ceddbf0968651b5ec817bf26811f6f67845d1fb6d99cdbb0f|

## Evidence, preservation and next action

Protected nonsecret metadata/static results: `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w15b-20261017T031208145678Z/preflight.private.json`, exclusive0600 file in new0700/UID501 directory, SHA256 `aa1aba03630fe92d6d7843da4103d5ce90682566a61748bcf4384dba9403d1c4`. Creating this authorized evidence directory changes its parent directory metadata; this expected filesystem change is not a Docker/database change. No credential file was opened or overwritten.

Repository changes: this report created and master tracker updated only. Existing dirty source/configuration/migration/report files and Git history preserved. Actual checks were static AST/graph/hash/source review, protected artifact integrity and read-only host/Docker/process metadata; no application/migration/runtime SQL tests. Historical role/schema acceptance remains intact; current preservation acceptance and live catalog checks remain incomplete. No task-issued schema/data/role operation occurred and no A/B data-equivalence claim is made.

Marker before: historical W1.5A zero rows/UNESTABLISHED; fresh value **NOT VERIFIED**. Marker after: **NOT VERIFIED**, no task-issued change. Transaction **NOT STARTED**, commit **NOT ATTEMPTED**, independent post-commit verification **NOT RUN**.

**Next gate:** reconcile the stopped/stale application process records and establish an explicitly reviewed current preservation baseline, without this task restarting or reconfiguring services. Then repeat W1.5B's complete fresh preflight under its target-specific authority before attempting the one marker INSERT. **NO-GO for requesting UUID expansion execution on an established079 baseline:** that marker has not been established or independently verified. No automatic080 follows from a later successful W1.5B.

## Authorized continuation — final outcome ACCEPTED

**Latest outcome: W1.5B IMPLEMENTED / ACCEPTED, revision marker only.** On2026-10-17 the operator authorized read-only reconciliation and continuation, explicitly accepting absent/superseded historical application PIDs without waiving any D identity/schema/security/role/storage/network/transaction gate. The earlier BLOCKED outcome above is retained as historical evidence and is superseded only by this executed continuation. IN PROGRESS scope/prerequisites/acceptance were recorded in the tracker before execution.

The actual operation completed: empty version table before; exactly one committed row `079_lifecycle_provider_verification` afterward, independently verified after physical closure of the write connection. No Alembic command, historical migration, application startup, schema/role change or UUID revision ran.

### Application-process reconciliation and preservation baseline

Fresh baseline `2026-10-17T03:21:06.539250+00:00`; final comparison `03:22:41.254331UTC`. Historical PIDs23095/23229/23230/23231/23232 remained absent at both observations. Current `.dev-runtime.json` still records those identities and is stale as a description of running services. It was not edited. Expected development API/frontend ports18000/13000, defined in `scripts/dev.py`, had no listeners. No replacement launcher/uvicorn/Celery/Beat/Next service signatures were found among inspected user-owned repository Python/Node processes. No claim is made that those services were running.

The current repository process inventory contained tool-runtime Node processes9011/9012/9089 and Python9091, with exact executable/birth/UID/parent/group/session/cwd identities retained privately. Python9091's application role is unconfirmed; no inspected SBOM service/migration/backfill signature or established D host connection was found. All four identities and the complete recorded listener/process metadata were identical after execution. These are observations, not authority inferred from process names. D catalog checks independently found zero other client sessions before the write, under its serialization lock and in the independent verification session.

Observed host boot epoch1792133218 predates the historical launcher/process birth times. A reboot since those processes started is not supported by that evidence. Their termination time, actor and launcher lifecycle cause remain UNKNOWN; no timestamp-based attribution or cause was invented. Historical absence is accepted application-runtime drift under the explicit exception, with no observed interference with D. No service was started, restarted, stopped, killed or reconfigured.

### Fresh gates and executed results

| Check | Actual result |
| --- | --- |
| Git/source preservation | Required branch/HEAD unchanged. Active graph AST:79 unique revisions/full ancestry/sole head079; staged080–085 exact hash chain above and common-source hash unchanged. No migration/application imports. Repository content baseline captured before report/tracker changes |
| Accepted W1.5A evidence | Protected manifest and all23 referenced hashes/modes match; accepted archive/normalized parity/restore evidence internally consistent. Only private historical evidence used; no B/A connection or dotenv read |
| Local Docker/D | Same local Desktop daemon/socket, D container `fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e`, image `sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54`, original `sbom-uuid-w1_d_pgdata` and sole access network `6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65`; actual loopback56041 listener/publication. Reviewed Compose hash unchanged; no Docker lifecycle/config changes |
| Explicit connection | Three bounded D-only connections: read-only preflight, one write transaction, new independent read-only verification. Explicit host/hostaddr127.0.0.1/port56041/database uuid_w1_d_rehearsal/user uuid_w1_d_bootstrap/existing private D password. Clean environment with no ambient PG overrides, no application settings/dotenv, passfile `/dev/null`; password not in argv/environment/evidence. Connect5s/statement15s/lock1s/idle-transaction60s bounds |
| Server identity | PG16.15/server_version_num160015; correct database/current_user/session_user; server-side172.20.0.2:5432 distinct from host publication. PGDATA `/var/lib/postgresql/data/pgdata`; system identifier7697252084555804711 at preflight/locked/postcommit checks |
| Exact schema | All31 catalog categories equal accepted raw D snapshot before, under lock, and afterward; fingerprint `990a33b059b58d36f7136e3d31318ff3a97cf89d6a9a11cc687b38f1bdafe42f`.72tables/1143base columns/512indexes/60sequences/143FKs unchanged. Actual B drift, including missing VEX superseded_by_id FK, retained |
| Roles/privileges | All captured role flags/configurations and membership edges equal accepted pre-restore role state. Exact protected owner name still OID16389; NOLOGIN/no password/no elevated flags/NOINHERIT/connection limit0/no memberships. Schema/object ACL/ownership/dependency categories unchanged; no grants or role operation |
| Extension exception | plpgsql1.0/pg_catalog descriptor, language trust/handlers/function definitions/security/configuration/ACLs unchanged and equal accepted compatibility evidence. Only the already approved plpgsql extension-owner difference remains; D owner bootstrap unchanged. No additional parity exception |
| Version-table compatibility | Existing single version_num column `character varying(128) NOT NULL`, no default, accepted constraints/indexes/RLS/rules/triggers unchanged. Exact approved35-character marker fits. Empty before and under lock; exactly one literal value after |
| Empty data / UUID absence | All72base tables empty before and under lock; after commit,71other tables empty and only version table has one row. No six-table public_id columns, shared guard/user triggers/functions/rules/event triggers or other staged080–085 schema objects. No sequence values advanced by the INSERT |
| Writer/serialization gate | No other D client session observed at each catalog gate. Transaction-scoped `pg_try_advisory_xact_lock(%s)` with bigint7160085085 returned true; `LOCK TABLE ONLY public.alembic_version IN EXCLUSIVE MODE NOWAIT` succeeded. Full identity/schema/role/extension/empty-state rechecks passed under locks |
| Sole INSERT | One `INSERT INTO public.alembic_version (version_num) VALUES (%s) RETURNING version_num`, parameter tuple containing only approved079 literal. Cursor rowcount1, returned exactly one correct version, precommit marker query exactly one correct row |
| Commit and physical close | COMMIT sent03:22:28.497633UTC, acknowledged03:22:28.508013UTC; physical connection closed03:22:28.508244UTC. Exactly one write transaction/one INSERT/one commit; no retry or unknown outcome |
| Independent verification | New read-only connection opened03:22:28.508407UTC; exact committed marker/schema/security/identity/71empty-table checks passed and connection closed03:22:28.788973UTC. Read-only mode explicitly checked; inspection transactions ended with ROLLBACK |
| Final host/resource comparison | Zero before/after metadata differences excluding observation timestamp. All four existing containers, relevant volumes/networks/mounts/ports/start/state/image, order-independent container/volume/network sets, password/env metadata and newly captured process/listener/runtime-file baseline unchanged. Same exact D volume and cluster; no A/B data-equivalence assertion |

Application schema fingerprints exclude the authorized version-table row contents; marker queries verify that sole logical data delta independently. Empty-table verification uses bounded EXISTS, not business-record export. No application tests, UUID/index/backfill tests or performance measurements were run. This task establishes the accepted schema's marker and does not replay schema migrations.

### Evidence and execution limits

Private directory: `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w15b-resume-20261017T032000035695Z`, UID501/mode0700. Twelve files mode0600: repository baseline, metadata/source harnesses, before/after infrastructure, PRE/LOCKED/POST catalogs, flushed labelled execution JSONL, database result, acceptance and artifact manifest. Manifest references11files, SHA256 `72af1772bc8622ca0c93835f5ef79c7e50662dadb243a0debfd6605c6de69482`; acceptance SHA256 `0534716add982deb5d82aa9abc2ae4a994a79cb2c743b502bf73a64fa1b00033`. Protected role identifiers/function definitions stay private; no passwords/connection strings/process environments stored. Expected private-directory metadata changes from evidence creation are separate from credential/resource preservation.

Initial host comparison stopped before DB access on container enumeration order; an independent set comparison proved no missing/added IDs, and the comparison was corrected to sort all identity sets. This was a comparison artifact, not resource drift or a weakened identity check. Initial Git enumeration emitted fsmonitor daemon warnings; content/diff preservation checks use `core.fsmonitor=false`. No SQL failed, no write retry, restoration, cleanup or rollback of issued mappings occurred. Private script syntax was checked before execution; this is not an application test.

Repository changes in this continuation: append to this existing report and update master tracker only. No application/runtime/Compose/active or staged migration source modifications. All earlier blocked/accepted task records and open issues remain.

**Next gate: GO to request a separately scoped D-only UUID expand rehearsal authorization.** D now has independently verified revision079 and the accepted baseline. This does not approve revision080 or waive staged-runner/source-review findings, target-specific approval manifest, PG16 trigger/lock/privilege/writer/recovery verification or UUID-preserving rollback requirements. Ordinary-bridge outbound-access risk and unknown historical process-exit cause remain documented. No automatic next migration was executed.

Final documentation verification PASS:2,094 other existing repository files and tracked binary diff unchanged; exact repository file set unchanged. Earlier report retained as an unchanged prefix;31 historical task-ledger rows and12 Phase1 issue rows retained verbatim. Branch/HEAD, local evidence links/line numbers, whitespace, all private manifest hashes/modes and `git -c core.fsmonitor=false diff --check` passed. Exact repository delta is this report and master tracker only. No further DB connection was used for documentation verification.
