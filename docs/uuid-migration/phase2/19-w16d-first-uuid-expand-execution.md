# W1.6D — First PostgreSQL UUID expansion rehearsal: execution gate review

2026-10-17, Asia/Kolkata. **BLOCKED at required operator review of the target-specific candidate manifest. Migration NOT EXECUTED / NOT ACCEPTED.** Explicit task authority was received for preflight, offline tests, manifest preparation and exactly one080 execution if all gates pass. The operator also explicitly instructed stopping when the manifest contract requires further review. That gate applies here; this is not a missing general D-only task authorization.

**Observed revision: `079_lifecycle_provider_verification`; no task-issued change.** Zero migration invocations, zero DDL/DML, no commit attempt for080, no new column/function/check/trigger/index/backfill. One authenticated D-only read-only preflight session completed. No execution failure/rollback/unknown commit occurred because execution never started.

## Scope, baseline and source selection

The tracker was marked IN PROGRESS before tests/runtime preflight with prerequisites, authority, acceptance and stop conditions. Read the current tracker, W1.5B report18, W1.6A.1 report10, W1.6B report11, W1.6C report12, actual080, isolated expand runner, common dependencies and tests. W1.5A accepted schema/extension/role evidence and W1.5B committed079/private evidence remain baseline; no source B/A/configuration selection or database access.

Git branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`; dirty work preserved. No checkout/pull/reset/commit/push. Actual active graph has79 unique revisions/full ancestry/sole079 head; six staged080–085 form the exact successor chain. Only080 would be selected through next_only for this task.

| Source | SHA256 / selection |
| --- | --- |
| Table-scoped staged080 | `2fc6e6f9992d0763ddf6818b9e7b62d573eef2b7cda01a39689b8fffcbc623f8`, matches operator pin; target tenants, exact079 predecessor |
| Common runner | `4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94`, matches operator pin |
| Isolated expand runner | `57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b`, matches report12 |
| Other staged sources | All five hashes match pinned discover()/report10; not eligible under requested next080 |
| Historical monolith | Archived .py.txt outside root staged .py discovery; not selected/imported/executed. Accepted fresh-D→schema-restore→079 evidence and current absent expansion objects support its exclusion; marker text alone is not historical proof |

The isolated runner uses synthetic079 boundary plus verified staged bytes, not application Alembic env/config, command.upgrade or historical migration traversal. Its mutation context owns one transaction; session advisory key7160085085, version-table EXCLUSIVE NOWAIT, and migration080 ONLY tenants ACCESS EXCLUSIVE NOWAIT precede DDL. Conditional079→080 marker UPDATE shares the DDL transaction. NullPool closes the write connection before a new read-only verification. These are source-reviewed contracts, not executed transaction proof from W1.6D.

Intended080 delta, **not applied**: tenants.public_id native nullable UUID added without ADD default; separate pg_catalog.gen_random_uuid INSERT default; NULL-allowing NOT VALID v4/variant CHECK; shared SECURITY INVOKER guard/search_path=pg_catalog; BEFORE INSERT explicit-NULL allocation and conditional AFTER UPDATE immutability trigger. Integer graph/legacy columns remain; no index/backfill/NOT NULL/API work. Downgrade fails closed.

## Known C-B02–C-B06 findings: actual source impact

| Finding | Impact on this proposed080 unit | Disposition |
| --- | --- | --- |
| C-B02 common Evidence initialization failure can leak its descriptor/partial evidence | Expand uses its own Evidence class, which closes the stream if initial emit fails; common Evidence is not called | Not an080 execution blocker; existing W1.6B defect remains unfixed |
| C-B03 index reset failure can mask original SQLSTATE after autocommit DDL | No index/reset/autocommit-DDL path is used by expand; distinct commit-phase classifications retained | Not applicable to080; remains open before future index acceptance |
| C-B04 common load_plan malformed types | Expand uses validate_manifest, exact integer port/OID and string/hash checks, not common.load_plan fixed085 parser | Not an080 blocker; no malformed values in candidate. Independent approval cannot be inferred from parser acceptance |
| C-B05 backfill run-budget limitation | Backfill controller is not invoked.080 uses bounded statement/lock timeouts, finite checks and no loop over revisions; no claim of a hard wall-clock bound on COMMIT/network/fsync/Docker scheduling | Not the backfill defect in080; hard failure/network budgets remain runtime requirements |
| C-B06 strict deparser/approval assumptions | Real read-only079 prefix()/snapshot query path passed. Expanded080 CHECK/trigger/function rendering has not been exercised; a strict mismatch would stop inside the owned transaction before commit, or mark committed state unverified if observed after commit | Runtime uncertainty retained; never relax checks automatically. Independent operator review of the newly captured prefix/hash is the present mandatory gate |

No new confirmed execution-critical migration-source defect was demonstrated in this review. This does not certify SQL/PLpgSQL execution, privilege behavior, trigger ordering, competing writers or recovery. Existing source files were not repaired or repinned. Source/graph/offline gates passed except the explicitly disclosed repository import-order lint warnings below; complete execution/approval gates have **not** passed.

## Fresh D-only preflight

Host/resource baseline at `2026-10-17T03:39:10.695603+00:00`, after at `03:40:24.931285UTC`. Private labelled metadata checks flushed before queries. Fixed approved credentials only, explicit loopback endpoint, no inherited PG overrides/application settings/dotenv, existing0600 password read privately. The actual runner common.connect and catalog primitives were exercised only as authorized read-only preflight helpers; neither runner --mode validate nor --mode execute was invoked.

| Gate | Executed result |
| --- | --- |
| Local daemon | PASS: explicit Unix socket /Users/ferozebasha/.docker/run/docker.sock; Desktop daemon1f8c7fe5-5972-4adc-8d6e-363a38572be1/29.8.2, Compose5.6.0. No remote contact |
| D container/image | PASS: fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e; image sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54; same state/start/mount/network/port metadata |
| Original storage/network | PASS: original sbom-uuid-w1_d_pgdata exclusively attached to D; expected PGDATA mount; sole sbom-uuid-w1_d_access/6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65; no application-network attachment. Retained private network untouched |
| Port/secret/Compose | PASS: actual127.0.0.1:56041 publication/listener; existing password UID501/regular/nonlink/0600/inode75679830/nonempty65bytes/private0700 parent unchanged. Compose SHA25613e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab unchanged; no config/lifecycle execution |
| PostgreSQL identity | PASS: uuid_w1_d_rehearsal/current+session user uuid_w1_d_bootstrap/databaseOID16384, actual16.15, cluster7697252084555804711, PGDATA /var/lib/postgresql/data/pgdata, no recovery/session_replication_role origin/read-only transaction on |
| Endpoint representation | Host published127.0.0.1:56041; server internal172.20.0.2:5432. Common IDENTITY_SQL uses inet_server_addr()::text, so its exact pinned plan representation is172.20.0.2/32; this is not compared with host loopback |
| Accepted schema | PASS: all31 categories exactly equal accepted raw D fingerprint990a33b059b58d36f7136e3d31318ff3a97cf89d6a9a11cc687b38f1bdafe42f;72tables/1143base columns/512indexes/60sequences/143FKs. Known missing VEX superseded_by_id FK preserved; no repair |
| Role/extension/security | PASS: exact restricted ownerOID16389/flags/no password/no memberships and captured role edges unchanged; extension functionality/language trust/handlers/config/security/ACL descriptor matches baseline. Only existing approved plpgsql owner exception. No user functions/triggers/write rules/event triggers; maintenance schema/language/allocator/TRIGGER/owner-role privileges checked |
| Marker/data/expansion | PASS: sole079 marker;71business tables empty by bounded EXISTS. No six-table public_id/shared guard/proposed checks/user triggers. No unique public UUID index/backfill activity |
| Runner-compatible baseline | PASS: actual runner identity(), marker(), prefix(079), snapshot() and common.verify_docker primitives exercised read-only.13-category runner catalog hash0697c32119526e94c02bdeb926fe8d82bcbded2dea7e038d57fa37f6c1bc027e captured; not confused with the fuller31-category accepted hash |
| Process/writer reconciliation | PASS: same W1.5B-approved current process/listener baseline; absent historical five PIDs/stale runtime records remain accepted, no resurrection required. Tool-runtime PIDs9011/9012/9089 and Python9091 unchanged, no18000/13000listeners or replacement inspected SBOM signatures. Zero other D client sessions observed. No actor/exit-cause assumption |
| Final preservation | PASS: zero before/after filtered resource/process/listener/credential/env/runtime metadata differences except observation time. Same sorted container/volume/network sets and original storage; no Docker/service manipulation. No A/B data-equivalence claim |

No post-migration verification took place. The read-only observation is079, and the task performed no marker/schema write; no080 transaction/commit/rollback/unknown result exists to reconcile.

## Offline checks actually executed

| Command / check | Result |
| --- | --- |
| .venv/bin/python -B infra/uuid-migration/staged-runner/test_expand_one_step.py |21tests PASS; mock lifecycle/unknown commit/rollback, source/graph/next-only/manifest/legacy/prefix checks. Mocked commits are not PG16 proof |
| .venv/bin/python -B infra/uuid-migration/staged-runner/expand_one_step.py --mode offline | PASS; exact hashes and isolated079–085 graph, no runtime action |
| .venv/bin/python -B infra/uuid-migration/staged-runner/verify_offline.py | PASS;79active+6staged,42SQL templates/14literal/18dynamic compilations,6concurrent-index DDL compilations. Nothing executed in PostgreSQL |
| Ruff repository lint, both staged directories | FAIL: six I001 import-order warnings in unchanged080–085 source. No semantic/syntax error or automatic fix. Preserve pinned hashes |
| Ruff repository lint, staged-runner directory only | PASS |
| Ruff --isolated lint, staged-alembic directory | PASS, same lint scope as W1.6A.1 |
| Ruff format --check, both directories | PASS:12files formatted |
| Python private preflight syntax; graph/hash assertions | PASS before execution; no app import |
| Pure candidate manifest refusal check | PASS_REFUSED; validate_manifest rejects pending review flags. Fixed diagnostic combines approval/old-monolith preconditions; this does not mean the excluded monolith was found. No connection by this test |
| Actual080 grammar/DDL/commit/independent catalog validation | NOT EXECUTED |
| INSERT allocator/NULL/default/CHECK/immutability/DML, concurrent writers/trigger order/failure/rollback/unknown-commit recovery | NOT EXECUTED; not passed by read-only catalog checks |
| Application/API/browser/benchmark tests | NOT RUN |

## Exact approval candidate — operator review required

The source requires review attestations and action references in [validate_manifest:132](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:132), including [action-specific matching approval:192](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:192). The reviewed [W1.6C contract:54](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/12-w1-isolated-expand-runner.md:54) explicitly says: **“These attestations are operator approval records, not cryptographic proof.”** Its [prefix contract:58](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/12-w1-isolated-expand-runner.md:58) requires the independently approved current-prefix hash. Generating fresh identity/hash values is not that operator review. The W1.6D prompt explicitly requires stopping at this condition.

Candidate file: `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16d-20261017T033839716313Z/approval-manifest-candidate.json`,0600 in0700 parent. Exact file SHA256 **f49b6c0b45d188f0248cddebf5a02f841b727e141e49f4205a353a6fe05e92ad**. The JSON below is the same parsed nonsecret content, pretty-printed; its whitespace differs from the canonical private file whose byte hash is stated. No password or connection string appears. Expires2026-10-18 09:09:54.601500IST; expiry is not approval.

The four false review flags mean **operator attestation pending**, not that the observed schema/privilege/secret checks failed. approvals is empty intentionally; no synthetic reference is represented as operator authority.

```json
{
  "accepted": true,
  "approvals": {},
  "baseline_reviewed": false,
  "container_id": "fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e",
  "container_sha256": "66f75be7578c216acbe83b5b24d49f4daeebc6216bf3a44815b62a6e01bab848",
  "current_revision": "079_lifecycle_provider_verification",
  "daemon_id": "1f8c7fe5-5972-4adc-8d6e-363a38572be1",
  "database": "uuid_w1_d_rehearsal",
  "database_oid": 16384,
  "disposable": true,
  "disposable_secret_provenance_reviewed": false,
  "docker_binary": "/Applications/Docker.app/Contents/Resources/bin/docker",
  "docker_binary_sha256": "31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f",
  "docker_socket": "/Users/ferozebasha/.docker/run/docker.sock",
  "exclusive_ddl_window_reviewed": false,
  "expires_utc": "2026-10-18T03:39:54.601500+00:00",
  "host": "127.0.0.1",
  "network_ids": {
    "sbom-uuid-w1_d_access": "6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65"
  },
  "next_revision": "080_uuid_public_id_expand",
  "old_monolith_excluded": true,
  "password_file": "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/postgres-password",
  "port": 56041,
  "postmaster_started_at": "2026-10-16 15:41:09.226049+00",
  "prefix_review_reference": "W1.5A/W1.5B accepted; W1.6D captured candidate requires operator review",
  "schema_sha256": "0697c32119526e94c02bdeb926fe8d82bcbded2dea7e038d57fa37f6c1bc027e",
  "server_address": "172.20.0.2/32",
  "system_identifier": "7697252084555804711",
  "target": "D",
  "user": "uuid_w1_d_bootstrap",
  "volume_sha256": "16b9fa5281ae2d395d61810b1ff527b3eaf417c53cf0fb9cc954700cd890a5a3",
  "writers_and_privileges_reviewed": false
}
```

Smallest remaining gate: operator review of these exact target/prefix/hash/source pins, baseline and old-monolith provenance, maintenance writer/privilege and no-unrelated-DDL window, disposable-secret provenance; explicit action-specific approval references for connected validation/execution as applicable. On approval, populate only explicitly approved attestations/action references and prefix review reference, record the final executable plan/new hash, recheck expiry and all fresh identities/state, then attempt080 once under this task's authority. Do not treat any changed identity/schema fingerprint as approved by this candidate. If it expires before review, refresh and present the changed candidate, not silently renew approval.

Future command shape, **NOT EXECUTED**, with unresolved reviewed plan/reference placeholders:

```text
env -i HOME=/Users/ferozebasha PATH=/usr/bin:/bin LC_ALL=C /Users/ferozebasha/sbom/.venv/bin/python -B /Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py --mode execute --next-revision 080_uuid_public_id_expand --plan <OPERATOR_REVIEWED_PLAN> --approval-id <EXPAND_EXECUTE_APPROVAL> --evidence <NEW_PRIVATE_EVIDENCE_JSONL>
```

No replacement runner, checker patch, manual DDL or bypass was used to obtain a migration result.

## Evidence, final decision and next action

Protected directory `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16d-20261017T033839716313Z`,0700/UID501;13files0600. Manifest references12files, SHA256 `b8bff1318915f32f9cfed89378014c0a4778f7eeec83645fd2d92f1a64490ea7`; includes candidate, source harnesses, labelled preflight events/catalogs, offline results, before/after infrastructure and outcome. Role identifiers/function bodies stay private; no credentials/process environments stored. Expected evidence-directory metadata changes do not imply password/storage drift.

Exact repository delta: new report19 and tracker update only. Prior reports, migration/runner/application/runtime/Compose/credential files and dirty work preserved. W1.5A/W1.5B acceptance remains intact; W1.6D is **BLOCKED / NOT EXECUTED / NOT ACCEPTED**. No schema delta; no080 marker or post-execution acceptance claim. **NO-GO to request081 execution:**080 has not committed or passed its mandatory catalog acceptance. Next action is review/approve the exact080 candidate, then resume080 with fresh gates; not another planning-only workstream. Existing C-B02–C-B06, real PG16 behavior/recovery and ordinary-bridge egress risks remain documented.

Final documentation verification PASS:2,095 other existing repository files and tracked binary diff unchanged; exactly one new repository file/report19 plus tracker update.32 historical task-ledger rows and12 Phase1 issue rows retained verbatim. Branch/HEAD, local links/line numbers, whitespace and git diff --check passed; all protected manifest hashes/0700-0600 modes verified. Pretty-printed report JSON equals the exact private candidate's parsed content; candidate byte hash unchanged. No further database session or runtime action was used for documentation verification.

## Operator-approved continuation — real080 execution ACCEPTED

**Latest W1.6D outcome: IMPLEMENTED / ACCEPTED for revision080 only.** On2026-10-17 the human operator approved the exact candidate hash, reviewed prefix and pinned080, all four review attestations, and distinct action references. This supersedes the earlier manifest-review BLOCKED outcome only for this continuation; all historical observations above remain unchanged.

Actual database transition: **079_lifecycle_provider_verification → 080_uuid_public_id_expand**. Exactly one existing-runner execute invocation, one acknowledged migration commit, physical write-connection closure and separate read-only runner verification completed. Additional independent catalog/security/data and final infrastructure checks passed. No081–085, unique index, backfill, test-row insertion, application/B/A/production access, Docker lifecycle, source modification or Git delivery.

### Authority and immutable approval inputs

Approval source: the human message titled “W1.6D — Operator Manifest Approval and Revision 080 Continuation” in this chat. Its exact references are `W16D-080-VALIDATE-20261017` and `W16D-080-EXECUTE-20261017`. No generated approval ID was substituted.

Original candidate byte SHA256 `f49b6c0b45d188f0248cddebf5a02f841b727e141e49f4205a353a6fe05e92ad` verified, retained and not overwritten. Approved source pins remain080 `2fc6e6f9992d0763ddf6818b9e7b62d573eef2b7cda01a39689b8fffcbc623f8`, common `4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94`, expand runner `57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b`. Actual active source graph still ends at079; staged revisions remain outside active registration. Only selected verified080 bytes executed; archived monolith excluded.

New executable plan: `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16d-execute-20261017T040147319404Z/operator-approved-plan.json`, exclusive0600 under0700/UID501 directory. Byte SHA256 **d0d0868c50cb69f6daa98ff6487aab77174e718835b4ebba56b1f68eb86377bd**. Only four approved flags changed to true, the exact two approvals were populated, and prefix_review_reference was changed to cite the operator message/candidate/prefix. Every target/identity/fingerprint/source expectation and expiry retained. Expiry remained2026-10-18T03:39:54.601500UTC and was valid during checks/execution. No silent renewal.

Runner evidence uses normalized JSON plan digest `9e72df5ac312b5237cd29f60610b6d401e15f4867a8f46246f5cd9b01b1cff64`; this differs from the file-byte hash by its documented compact JSON serialization, not different plan content. The independently approved starting runner prefix hash remained `0697c32119526e94c02bdeb926fe8d82bcbded2dea7e038d57fa37f6c1bc027e`.

### Commands actually executed

Common clean prefix in both real runner commands:

```text
env -i HOME=/Users/ferozebasha PATH=/usr/bin:/bin LC_ALL=C /Users/ferozebasha/sbom/.venv/bin/python -B /Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py
```

Exact arguments, with private directory `P=/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16d-execute-20261017T040147319404Z` as a documentation abbreviation, not a secret or runtime configuration fallback:

```text
--mode validate --next-revision 080_uuid_public_id_expand --plan P/operator-approved-plan.json --approval-id W16D-080-VALIDATE-20261017 --evidence P/runner-validation.private.jsonl
--mode execute --next-revision 080_uuid_public_id_expand --plan P/operator-approved-plan.json --approval-id W16D-080-EXECUTE-20261017 --evidence P/runner-execution.private.jsonl
```

Each returned exit0, no raw error/credential output. Offline source/hash/graph mode was rerun and passed. Earlier21offline tests remain valid against unchanged source; the acknowledged six import-order warnings were not “fixed” or confused with PostgreSQL acceptance. No application tests ran.

### Fresh gates, real transaction and independent results

| Gate / action | Actual executed evidence |
| --- | --- |
| Fresh host/source | Correct branch/HEAD2f48ff835d9e692fc84b31aaa951aad2495888ac; pinned source hashes/sole active079/staged next080/expiry verified. Same local Desktop daemon/socket, D container/image/original volume/access network/loopback56041/credential metadata and W1.5B current process baseline. Before04:01:54.527319UTC, final04:04:00.650154UTC |
| Connected validation | Existing runner --mode validate start04:02:01.520890UTC; `connected_validation_only_closed`04:02:02.380556UTC, exit0. Actual079 prefix/approved13-category fingerprint and identity/Docker gates passed; no mutation |
| Immediate independent preflight | Separate D-only read-only session after validation: exact16.15/cluster7697252084555804711/dbOID16384/db-user/PGDATA, sole079; full31-category accepted schema fingerprint990a33b059b58d36f7136e3d31318ff3a97cf89d6a9a11cc687b38f1bdafe42f; role16389/all captured roles+memberships/extension compatibility and sole plpgsql owner exception;71empty business tables/no expansion. Maintenance privileges checked, zero other D clients/tenants-version locks observed. Preflight xact advisory7160085085 available and released; authoritative lock acquisition remains inside actual runner transaction |
| One real080 invocation | Start04:02:46.589868UTC; existing runner's owned transaction acquired session advisory7160085085, ONLY public.alembic_version EXCLUSIVE NOWAIT and migration080 ONLY tenants ACCESS EXCLUSIVE NOWAIT. Exact pre-state verification, migration080 upgrade and bound conditional079→080 marker UPDATE shared the transaction. No historical upgrades or head traversal |
| Before commit | Runner verified080 semantic prefix/expected narrow delta inside transaction, then persisted precommit04:02:47.913098UTC. No failed SQL/lock/source/expiry gate or automatic retry |
| Acknowledged commit | `commit_acknowledged`04:02:47.914017UTC (09:32:47.914017IST). Exactly one migration commit; no uncertain outcome |
| Physical close and runner read-back | Existing NullPool engine/context closes first physical connection before its separately opened read-only connection. `committed_verified_closed`04:02:48.382150UTC, runner post-catalog hash858e8249c4fd4bad50840d3d2efdae0e84135142c828f759c27290d968b47905. Exit0. Source-controlled connection lifecycle plus real completed read-back supports closure; no claim of wire-packet instrumentation |
| Additional independent verification | Separate bounded D-only read-only verification completed/closed04:03:41.705670UTC; exact sole080 marker/identity/roles/extension/71empty business tables and accepted old graph checked. Full post-schema fingerprint5705d589c6db9f0e11e8c95a1de07f92282dfb2808e7d71d56ac98a2e4cada76 |
| Preservation | Final filtered Docker/process/listener/runtime/env/credential before-after differences zero. Same D storage/network/cluster, PostgreSQL/Redis/Mailpit identities/volumes/application network and all resource sets. Historical service PID absence/stale runtime records unchanged and explicitly retained; services not claimed running or manipulated |

### Exact PostgreSQL delta and mandatory acceptance matrix

| Requirement | Independent result |
| --- | --- |
| Version marker | PASS: exactly one `080_uuid_public_id_expand`; no081 |
| Native tenants column | PASS: only new base-table column public.tenants.public_id, attribute8, native uuid, nullable/not-generated. Default deparsed `gen_random_uuid()`, installed by separate SET DEFAULT after ADD without default |
| Validation check | PASS: one new ck_tenants_public_id_v4, type CHECK, convalidated=false/NOT VALID; exact NULL-allowing canonical text v4-version/variant regex matching pinned source |
| Shared function | PASS: only new public.uuid_public_identity_guard_v1, no arguments/trigger return, plpgsql/VOLATILE/SECURITY INVOKER/search_path=pg_catalog, non-strict/non-leakproof/PARALLEL UNSAFE, correct EXECUTE access; body SHA256ff93761fa4dd31fa6dff7c25f3aedf41bc960e181a234d390f540e359d2e8d58 |
| INSERT allocator trigger | PASS: trg_tenants_public_id_insert, enabled origin/O, BEFORE INSERT FOR EACH ROW, no args/column restriction/constraint attachment, exact shared guard reference |
| Immutability trigger | PASS: trg_tenants_public_id_immutable, enabled origin/O, AFTER UPDATE FOR EACH ROW, exact WHEN OLD.public_id IS DISTINCT FROM NEW.public_id and shared guard reference. Definition verified, no DML behavior test |
| Other five scoped tables | PASS: projects/products/logical_sbom/sbom_source/sbom_component still have no staged public_id/check/identity triggers;080 prefix verifier checked entire six-table prefix |
| Integer PK/FK and prior objects | PASS: every accepted old captured catalog row remains; exact old PK/FK definitions and index/sequence snapshots unchanged.72tables/512indexes/60sequences/143FKs;1144base columns (one added). Full changed categories only columns/constraints/functions/triggers/dependencies; new dependency edges expected for these objects |
| Empty data | PASS:71business tables remain empty by bounded EXISTS, version table sole080 row. No synthetic/test business rows or issued UUID mappings |
| No indexes/backfill | PASS:512indexes unchanged, no public_id unique index, no backfill statement/runner or row update besides atomic marker advance |
| Security and drift | PASS: captured roles/memberships/restricted role16389 and plpgsql functional/security/privilege properties unchanged; only preapproved extension-owner exception. Actual B drift including missing VEX superseded_by_id FK preserved |
| Infrastructure | PASS: original D volume identity/mount/exclusive attachment/access network/loopback publication/image/system ID and existing SBOM resource/process baseline unchanged |

This is real PostgreSQL16.15 DDL, deparser, narrow catalog-delta, transactional commit and committed-prefix acceptance for080 on an empty disposable baseline. It is **not** proof of explicit-NULL INSERT allocation, invalid UUID rejection, identity immutability under DML, concurrent writers, BEFORE-trigger interference, lock-contention/timeouts, failed-DDL rollback, lost-COMMIT recovery, writer privileges in deployment or performance. Those behavior/recovery tests were not run; no business-row testing was authorized.

### Additional verification-harness error retained and reconciled

The runner itself completed its precommit and independent postcommit checks successfully. A broader private follow-up harness then called the same delta function with a saved JSON baseline (list rows) against fresh database cursor tuple rows, producing the fixed `Existing catalog object modified; rollback/manual review` diagnostic. This was a harness representation error, not a database SQL/runner failure or evidence of actual catalog drift.

Offline proof demonstrated identical values round-trip from tuple to JSON list but compare unequal as Python containers. The original harness/source and failed labelled event remain preserved. A second private harness restores only the saved snapshot's outer tuple row type before the existing unchanged delta predicate. No expected definition, assertion, pinned runner, migration source or DB state changed. Subsequent read-only follow-up verified the actual expanded state and all full-catalog invariants; **080 was not retried**, no new DDL executed and no mappings/schema reset. Both the failed comparison and corrected successful observation are in evidence. No true DB failure or unknown transaction was reclassified as PASS.

### Protected evidence and final readiness

Directory `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16d-execute-20261017T040147319404Z`,0700/UID501;17files0600. Manifest references16files, SHA256 `53ea5edebe2f9c77261e2d192de1ddb516994be35092719cf66093ad50707a97`; acceptance SHA256 `f1d745dea7f47197082d2463235488423442aa7a4daadc7359feaefa23a0839d`. Authority/approved plan, actual runner validation+execution JSONL, source/readonly harnesses, pre/post full catalogs, original comparison diagnosis, before/intermediate/final infrastructure, acceptance and repository baseline retained privately. No password, full connection string or process environment in evidence. Original candidate/historical evidence unchanged; expected new evidence-directory metadata changes separated from secret/resource preservation.

Exact repository changes: append this existing report and update master tracker only. No active/staged migration, common/expand runner, ORM/API/frontend/runtime/Compose/credential source changes. All historical outcomes/open issues retained.

**GO to request separate authorization for081**, after independent review of the committed080 prefix/hash/evidence and a fresh081-specific approval manifest. This080 approval cannot be reused as081 approval. No081–085/index/backfill executed. C-B02–C-B05 future index/backfill concerns, unexecuted behavior/recovery/performance checks, ordinary-bridge egress and unknown historical process exit cause remain open. No public/API or production readiness is implied.

Final continuation documentation verification PASS:2,095 other existing repository file contents/tracked binary diff/file set unchanged;33 prior task-ledger rows and12 Phase1 issue rows retained verbatim. Entire earlier report preserved as unchanged prefix. Branch/HEAD, links/line numbers/whitespace/git diff --check, protected manifest modes/hashes, original candidate byte hash, exact six authorized plan-field changes and actual single-run commit/read-back event sequence verified. Only this report and tracker updated; no additional DB access for documentation verification. W1.6D080 ACCEPTED, future081 requires separate authority.


