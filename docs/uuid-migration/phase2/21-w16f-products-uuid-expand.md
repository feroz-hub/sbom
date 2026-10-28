# W1.6F — Products082 UUID expand preparation

2026-10-17, Asia/Kolkata. **BLOCKED at independent operator manifest review;082 NOT EXECUTED / NOT ACCEPTED.** Source/offline/read-only D preparation is complete. The operator has not approved082's attestations/action references. Neither connected runner validation nor execution was invoked. No DDL/DML, synthetic business rows, backfill/indexes, A/B/production access, Docker/application lifecycle changes or Git delivery.

**Actual sole marker observed:081_uuid_projects_expand. No task-issued revision or schema change.** Accepted081 remains intact. Two authenticated D-only read-only preflight sessions occurred: first stopped on a private harness referencing the wrong historical snapshot; corrected reference and all required current081 checks passed in the second. Both attempts/evidence retained; details below.

## Scope and baseline evidence

Read current master tracker, [accepted081 report20](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/20-w16e-projects-uuid-expand.md:156), [original source review](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/10-w1-expand-transaction-refactor.md:1), [isolated-runner contract](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/12-w1-isolated-expand-runner.md:1), relevant staged080–082 sources/current runner/common code and staged graph. IN PROGRESS authority/prerequisites/acceptance/stop conditions were recorded before tests and DB access.

Branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`; existing dirty work snapshotted and preserved. Active Alembic source head remains079, with79 unique/full-ancestry revisions. Six staged sources remain outside active registration. Current database081 is the separately verified committed prefix, not a changed active-source graph.

Protected W1.6E execution manifest SHA256 `57e95edae826f86fd9d2daae551f2bfd062d27a11e88f1ba6d733f19bb09e9bf` and all13 referenced artifact hashes/owned0600 modes verified. Actual event sequence start→precommit→commit_acknowledged→committed_verified_closed,081 commit ACK04:24:33.093361UTC/read-back04:24:33.539911UTC, accepted independent result and zero preservation differences verified. No081 failure/unknown outcome/retry is hidden. Evidence-source code was reviewed before safe reuse of metadata/catalog definitions; no previous execution manifest or action references were reused for082.

## Source pins and exact082 scope

| Gate | Verified result |
| --- | --- |
| Original082 SHA256 | Resolved from [report10:148](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/10-w1-expand-transaction-refactor.md:148), not guessed: **76d830f79e699cbdd5116c1e848cc5923f10281a764a17f0abd6c1cf8c4b5ace**. Current file bytes match |
| Declarations | [082 source:15](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/082_uuid_products_expand.py:15):082_uuid_products_expand directly depends on081_uuid_projects_expand, _TABLE products. next_only081→082 passes; skipping/ranges/head/replay rejected by existing runner |
| Nullable UUID/default | Native PostgreSQL UUID nullable ADD without default, then separate SET DEFAULT pg_catalog.gen_random_uuid. No legacy row rewrite/default backfill, NOT NULL or business-field assignment |
| CHECK/triggers | Exact NULL-allowing canonical UUIDv4/variant regex CHECK NOT VALID; reviewed BEFORE INSERT explicit-NULL allocator trigger and conditional AFTER UPDATE immutability trigger, existing shared guard only. No CHECK validation/unique index/backfill step |
| Guard reuse |082 catalog preflight checks sole existing signature/body/language/security/volatility/search_path/EXECUTE; source contains no CREATE/REPLACE FUNCTION. Already committed tenants/projects/shared guard must remain unchanged |
| Integer graph | Requires existing single int4 id PK, ordinary permanent noninherited table, no conflicting objects/INSERT triggers/write rules. No PK/FK/association alteration, ORM/API behavior change or business INSERT/UPDATE |
| Transaction/locks | Source refuses offline/autocommit/non-PG/nontransactional execution. Future one owned transaction uses shared advisory7160085085, ONLY version table EXCLUSIVE NOWAIT, ONLY products ACCESS EXCLUSIVE NOWAIT; timeout caps1s lock/10s statement retain stricter caller limits, not hard COMMIT/network deadline. Atomic conditional081→082 marker, physical close/new read-only checks mandatory |
| Isolated runner/common | expand_one_step.py **57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b**; uuid_w1_common.py **4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94**, unchanged |
| Historical replay exclusion | discover() pins exactly six staged .py sources/graph and retains selected bytes. Synthetic079 boundary prevents traversal of earlier active migrations; requested082 only would invoke its upgrade. Archived monolithic080 .py.txt is not eligible. No080/081 upgrade replay or root env/config startup |

Known finding applicability:

- **C-B02:** common Evidence initialization defect remains in W1.6B; expand uses its separate constructor with close-on-initial-emit-failure.
- **C-B03:** index autocommit/reset error masking is not on the expand path.
- **C-B04:** expand uses its own exact-type manifest parser, not fixed085 common.load_plan. Candidate malformed/false approval inputs are refused.
- **C-B05:** backfill loop-budget limitation is not the082 controller. Expand still has statement/lock bounds without a hard end-to-end acknowledgement deadline.
- **C-B06:**080–081 real deparser/prefix acceptance exists;082 products CHECK/trigger rendering/SQL/permissions and failure behavior are not yet executed. Strict comparisons must fail closed; no automatic relaxation.

None of these is silently fixed or marked generally accepted. No new execution-critical pinned-source defect was demonstrated in this preparation.

## Tests actually run

| Check | Actual result |
| --- | --- |
| Existing test_expand_one_step.py |21offline tests PASS, including real in-memory graph/source pins, next-only/manifest/prefix and mocked lifecycle/error paths |
| expand_one_step.py --mode offline | PASS source/hash/isolated079–085 graph; no target runtime action |
| verify_offline.py | PASS79active+6staged,42SQL templates/14literal/18dynamic query compilations and6index-DDL compilations. Compilation does not execute PostgreSQL |
| Additional082 AST/source assertions | PASS exact report-derived hash,081 predecessor/products scope, guard body check without function creation, no index/backfill/business write/CHECK validation/NOT NULL |
| Runner repository Ruff lint | PASS |
| Migration --isolated lint | PASS original reviewed lint scope |
| Migration repository lint | FAIL only six historical I001 import-order findings in unchanged080–085; no fix/repinning. Not an execution-critical SQL result |
| Ruff format --check | PASS12files |
| Private preflight syntax and pure pending-manifest refusal | PASS; no operator references assigned or connected validate mode invoked |
|082 PostgreSQL DDL/commit/post-082 catalog acceptance | NOT EXECUTED |
| DML allocator/invalid UUID/CHECK/immutability, concurrency/BEFORE-trigger interference, lock contention/rollback/lost COMMIT recovery, benchmarks/application tests | NOT EXECUTED |

## Fresh D-only read-only verification

Host before `2026-10-17T04:36:02.640712+00:00`; after `04:37:35.764850UTC`. Exact common.connect D-only kwargs/existing dedicated password; clean environment/no PG overrides/dotenv/app settings. Read-only transaction enforced and checked. Metadata/catalog queries and bounded business-table EXISTS only; no business export or sequence-state manipulation.

| Gate | Final executed result |
| --- | --- |
| Local Docker | PASS: explicit local Desktop Unix socket /Users/ferozebasha/.docker/run/docker.sock, daemon1f8c7fe5-5972-4adc-8d6e-363a38572be1/29.8.2, Compose5.6.0. No remote daemon |
| D identity/storage | PASS: containerfb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e; image sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54; original sbom-uuid-w1_d_pgdata exclusive mount/PGDATA. Sole access network6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65; no application-network attachment |
| Port/credentials/config | PASS: actual127.0.0.1:56041 loopback publication/listener; existing private user-owned0600 regular/nonlink password inode75679830/65bytes/0700 parent unchanged. Contents not exposed/copied/rotated. Compose hash13e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab unchanged |
| PostgreSQL identity | PASS: uuid_w1_d_rehearsal/current+session user uuid_w1_d_bootstrap/OID16384,16.15/server160015, cluster7697252084555804711, PGDATA /var/lib/postgresql/data/pgdata, no recovery/origin replication mode/read-only on |
| Endpoint representations | Host127.0.0.1:56041 separate from internal172.20.0.2:5432; runner uses raw inet text172.20.0.2/32, pinned as that format |
| Current prefix | PASS sole081; exact tenants and projects UUID column/default/NOT VALID v4 CHECK/two enabled triggers each/shared guard body-signature-security-ACL unchanged. Four future products/logical_sbom/sbom_source/sbom_component tables remain unexpanded |
| Runner13-category hash | PASS **3bee5a5f7933cd651979c05736470d9ec0e72262b17cdc713178f65ca3af1b43**, computed with snapshot()/common.digest and matched only its accepted format |
| Independent31-category hash | PASS **38c7c87eb10f0f0c01619f98bca77a94a62b8860bd4f0f7987e2dbc542973852**, computed with original normalized catalog/digest and exact accepted081 catalog equality. Not compared with runner hash |
| Roles/security/extensions | PASS exact restricted ownerOID16389/protected name/approved flags/no password/no memberships; all captured role/membership state unchanged. plpgsql functional/security/ACL properties unchanged; only already-approved extension-owner exception. No unrelated normalization or repair |
| Graph/data/B drift | PASS72tables/1145base columns/512indexes/60sequences/143FKs, original integer PK/FK/associations/index/sequence definitions unchanged.71business tables empty. Missing VEX superseded_by_id FK and known actual source drift preserved |
| Privileges/window observations | PASS8schema/language/allocator/products SELECT+TRIGGER/owner-role/shared-guard EXECUTE checks; zero other D clients and no other products/version-table locks. Proposed one082 DDL window still needs operator attestation/fresh checks; observations are not future exclusivity guarantees |
| Host/process preservation | PASS zero before-after filtered container/image/state/start/mount/port/network/volume/current process/listener/runtime/env/password metadata differences except observation time; sorted sets unchanged. Matches accepted081 current process baseline, absent historical PIDs/stale runtime/no18000or13000listeners retained. No service-running or actor/exit-cause claim |

### Private harness baseline-reference error

The first session passed exact D identity/sole081/runner13-category prefix, then stopped at FULL-CATALOG-SECURITY-DATA with AssertionError/no SQLSTATE. Offline inspection found its BASE path still pointed to accepted080 evidence even though its expected hash was081. That historical snapshot necessarily could not equal the live two-table081 prefix. The initial independent full-hash value was not persisted; it is not falsely reported as passing then.

Original harness/source and failed labelled event retained. A second private harness corrects only the evidence reference to hash-verified W1.6E accepted081, adds an explicit baseline revision assertion and saves the observed full catalog before comparison. Expected fingerprints/security/data assertions and all pinned migration/runner source remain unchanged. Second read-only session passed both exact hashes and all remaining gates. No actual target drift was accepted or normalized, no database mutation/credential change, no migration attempt/retry. No candidate file existed after the first failure; the resulting candidate is the first082 candidate, not an expired plan renewal.

## Exact fresh082 candidate for operator review

Private file: `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16f-20261017T043515627091Z/082-approval-candidate.json`, exclusive0600 in0700/UID501 directory.

**Byte SHA256:7031b7de44d8231e34f2aa4286519fb4c436ebb9ac5bd36acec57409cb2c6ad5.**

Expires **2026-10-18T04:37:13.391192UTC /2026-10-18 10:07:13.391192IST**. The four false flags mean operator approval pending, not failed read-only observations; approvals is empty. accepted=true concerns the already accepted disposable081 baseline, not approval to execute082.

source_sha256/independent_schema_sha256/review_observations add nonsecret review context to the existing runner fields. They do not replace the runner's pinned discover/prefix checks or independent full-catalog checks. No previous080/081 execution manifest/reference/pre-081 fingerprint was used to construct this candidate. Fresh measurements identify the same verified storage/daemon because D was preserved, not recreated.

Exact parsed nonsecret content, pretty-printed; file-byte hash above refers to its original private serialization:

```json
{
  "accepted": true,
  "approvals": {},
  "baseline_reviewed": false,
  "container_id": "fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e",
  "container_sha256": "66f75be7578c216acbe83b5b24d49f4daeebc6216bf3a44815b62a6e01bab848",
  "current_revision": "081_uuid_projects_expand",
  "daemon_id": "1f8c7fe5-5972-4adc-8d6e-363a38572be1",
  "database": "uuid_w1_d_rehearsal",
  "database_oid": 16384,
  "disposable": true,
  "disposable_secret_provenance_reviewed": false,
  "docker_binary": "/Applications/Docker.app/Contents/Resources/bin/docker",
  "docker_binary_sha256": "31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f",
  "docker_socket": "/Users/ferozebasha/.docker/run/docker.sock",
  "exclusive_ddl_window_reviewed": false,
  "expires_utc": "2026-10-18T04:37:13.391192+00:00",
  "host": "127.0.0.1",
  "independent_schema_sha256": "38c7c87eb10f0f0c01619f98bca77a94a62b8860bd4f0f7987e2dbc542973852",
  "network_ids": {
    "sbom-uuid-w1_d_access": "6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65"
  },
  "next_revision": "082_uuid_products_expand",
  "old_monolith_excluded": true,
  "password_file": "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/postgres-password",
  "port": 56041,
  "postmaster_started_at": "2026-10-16 15:41:09.226049+00",
  "prefix_review_reference": "W1.6E accepted081; fresh W1.6F082 candidate pending independent operator review",
  "review_observations": {
    "business_indexes": 512,
    "committed_prefix": "accepted081 tenants/projects unchanged; four remaining tables unexpanded",
    "empty_business_tables": 71,
    "evidence_reference": "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16f-20261017T043515627091Z/database-preflight.private.json",
    "exclusive_ddl_window": "proposed one082 transaction only; fresh writer and lock checks required after operator approval",
    "foreign_keys": 143,
    "maintenance_privilege_checks_passed": 8,
    "other_D_client_sessions": 0,
    "plpgsql_state": "functional/security/ACL unchanged; existing approved owner exception only",
    "postgresql_version": "16.15",
    "products_version_table_other_locks": 0,
    "restricted_owner_role_oid": 16389,
    "restricted_role_state": "matches accepted restrictions; no password/memberships",
    "sequences": 60,
    "source_provenance": "report10 pinned082 successor; shared guard reuse verified; archived monolith excluded"
  },
  "schema_sha256": "3bee5a5f7933cd651979c05736470d9ec0e72262b17cdc713178f65ca3af1b43",
  "server_address": "172.20.0.2/32",
  "source_sha256": {
    "082_uuid_products_expand.py": "76d830f79e699cbdd5116c1e848cc5923f10281a764a17f0abd6c1cf8c4b5ace",
    "expand_one_step.py": "57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b",
    "uuid_w1_common.py": "4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94"
  },
  "system_identifier": "7697252084555804711",
  "target": "D",
  "user": "uuid_w1_d_bootstrap",
  "volume_sha256": "16b9fa5281ae2d395d61810b1ff527b3eaf417c53cf0fb9cc954700cd890a5a3",
  "writers_and_privileges_reviewed": false
}
```

[validate_manifest](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:132) and the [reviewed operator-record contract](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/12-w1-isolated-expand-runner.md:54) require independently approved flags/current prefix/action references. Current W1.6F authority explicitly withholds them. The pure parser refusal test passed without opening a connection. **No connected execution validation or082 execution is permitted now.**

Exact next step: independently review/approve this candidate hash/content, four attestations and distinct082 expand_validate/expand_execute references. Then save a new protected approved manifest changing only explicitly approved fields, preserve this candidate/expiry, record its new hash, run existing connected read-only validation, refresh identity/prefix/both catalog/security/privilege/writer/lock-window/source/expiry gates, and only if all pass invoke exactly one081→082 transaction through the existing runner. Require commit acknowledgement/physical close/new independent read-only products-only delta and unchanged tenants/projects/shared guard/security/data/resource acceptance. Expired/changed approval inputs or actual drift fail closed; no silent renewal, bypass or retry. No083–085 permission transfers.

## Evidence, disposition and open limits

Protected directory `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16f-20261017T043515627091Z`,0700/UID501;15files0600. Manifest references14files, SHA256 `bdf02d08b1a14055d1de4ac48ba465442ef081c4665a80c774db2b9450fccb21`; offline/source/accepted081 integrity, original+corrected harness and diagnosis, flushed labels/catalogs, candidate, outcome and before-after preservation retained. Sensitive role identifiers/catalog definitions remain private; no passwords/full connection strings/process environments/business records stored. Expected evidence-directory metadata changes separated from secret/storage integrity.

Repository delta: new report21 and tracker update only. Existing dirty source/runtime/configuration/prior reports/migrations/runners/credentials/Git history preserved. No DDL/DML, A/B/production or infrastructure lifecycle action.

**W1.6F: BLOCKED at manifest review;082 NOT EXECUTED / NOT ACCEPTED.** Sole081 observed, no task-issued marker/schema change;082 transaction/commit/independent post-082 checks NOT RUN. Existing081 acceptance retained. Next action is exact-candidate independent operator approval as above, then resume this task. **NO-GO for automatic083 or any082 execution before that approval.** Unexecuted DML/concurrency/recovery/privileged writer/performance tests, C-B02–C-B05/future-stage concerns and ordinary-bridge egress remain open;080/081 happy-path catalog acceptance does not certify them.

Final documentation verification PASS:2,097 other existing repository file contents/tracked binary diff preserved; exact repository delta new report21 and tracker only.36 prior task-ledger rows/12 Phase1 issue rows retained verbatim. Branch/HEAD, local evidence links/line numbers/whitespace/git diff --check, protected0700/0600 manifest hashes/modes, exact candidate byte hash/report parsed-JSON equality and all pending flags/empty approvals verified. No further DB session for documentation verification.081 baseline retained;082 not executed.


## Operator-approved continuation — revision082 IMPLEMENTED / ACCEPTED

Actual execution on 2026-10-17. This appended result supersedes the preparation-only disposition above for current readiness; the earlier BLOCKED outcome and private baseline-reference failure/correction remain historical evidence. **Exactly one081→082 migration committed on disposable D. No083 was executed.** Active application Alembic source still ends at079; staged sources were not registered in its versions directory.

### Authority, source pins and executable plan

Authority is the human “W1.6F Operator Approval and Revision082 Execution” message: exact candidate7031b7de44d8231e34f2aa4286519fb4c436ebb9ac5bd36acec57409cb2c6ad5, both accepted081 catalog fingerprints, source pins, four true attestations and distinct references `W16F-082-VALIDATE-20261017` / `W16F-082-EXECUTE-20261017`. These approvals were supplied by the operator, not inferred from a generated manifest.

The original candidate file and preparation evidence were hash-verified and preserved. Its expiry remained `2026-10-18T04:37:13.391192+00:00`; no renewal. New private approved plan:

`/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16f-execute-20261017T134712005067Z/operator-approved-plan.json`

Byte SHA256 **82ab022350b035d31dff4560643b6afd79f6182713033cde10ba1f00aa8e092e**. Runner compact-JSON digest **25590f71039177bff99d424a1e45d8559f50f5bc6f5eec0c3419c30573107904**; serialization explains the different digest. Only six top-level fields changed: four approved review flags, the exact two action approvals, and prefix-review reference citing this operator approval. Identity, sources, observations, fingerprints and expiry remained unchanged. File0600, directory0700, UID501; candidate not overwritten.

| Source / baseline | Verified SHA256 |
| --- | --- |
| Staged082 source, immediate081 successor |76d830f79e699cbdd5116c1e848cc5923f10281a764a17f0abd6c1cf8c4b5ace |
| Existing isolated expand runner |57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b |
| Existing common library |4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94 |
| Starting081 runner13-category catalog |3bee5a5f7933cd651979c05736470d9ec0e72262b17cdc713178f65ca3af1b43 |
| Starting081 independent31-category catalog |38c7c87eb10f0f0c01619f98bca77a94a62b8860bd4f0f7987e2dbc542973852 |

[082 upgrade](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/082_uuid_products_expand.py:192) and [isolated transaction lifecycle](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:449) were used unchanged. The archived monolithic080 and normal application Alembic environment were excluded. No execution-critical source gate failed. C-B02–C-B05/future-stage concerns remain open;082's real syntax/deparser/transaction/catalog happy path is now verified, not its unexecuted DML/concurrency/recovery behavior.

### Fresh gates and preservation baseline

Branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`; dirty work preserved. Reviewed Compose SHA256 remains13e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab. Explicit local Docker Desktop socket `unix:///Users/ferozebasha/.docker/run/docker.sock`, daemon1f8c7fe5-5972-4adc-8d6e-363a38572be1/Engine29.8.2/Compose5.6.0 matched. No remote daemon contacted or Docker lifecycle command executed.

| Gate | Actual safe observation / result |
| --- | --- |
| Exact D infrastructure | Containerfb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e, image sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54; original sbom-uuid-w1_d_pgdata/exclusive expected mount and sole access network sbom-uuid-w1_d_access/6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65 unchanged. Actual publication127.0.0.1:56041 only |
| Credentials/target | Existing dedicated private credential metadata unchanged: UID501,0600 regular/non-symlink/nonempty, private0700 parent; no credential rotation/copy/disclosure or dotenv fallback. Actual database uuid_w1_d_rehearsal/bootstrap uuid_w1_d_bootstrap/OID16384, server16.15, system identifier7697252084555804711, data_directory /var/lib/postgresql/data/pgdata |
| Accepted081 prefix | Sole081; tenants/projects UUID definitions and shared guard match; other four target tables unexpanded. Both accepted fingerprints match their own format; full role/ACL/security/extension state matches. Owner roleOID16389 unchanged; only prior plpgsql owner exception retained; missing VEX superseded_by_id FK retained |
| Data/privilege/window |71 business tables empty; eight products/shared-guard maintenance privilege checks PASS, zero other D client sessions, zero other products/version-table locks. Required advisory transaction lock available/released in independent preflight; existing runner then acquired its reviewed actual execution locks. Source pins and unexpired approval rechecked |
| Current process baseline | Same historical SBOM service PID absence/stale runtime records/no18000or13000listeners, no resurrection or claim services running. Current tool/runtime process identities unchanged. Since the earlier preparation, only macOS rapportd PID989 dynamic listeners changed; all other listener tuples matched. This non-SBOM change was separately recorded, not attributed to a cause or hidden as an equal historical snapshot. Fresh before/after operation baseline matched exactly |

Private independent harness was adapted offline to the accepted081 baseline and explicitly reviewed products/shared-guard eight-privilege scope before database access. No pinned source changed or runtime failure was bypassed. The earlier preparation's wrong historical BASE reference/failure and correction remain intact; all14 preparation-manifest artifact hashes were verified. No new failed validation/assertion or migration retry occurred in this continuation.

### Actual invocation and transaction evidence

For the commands below, `P` denotes the exact private execution directory above, expanded to an absolute path in the actual arguments. No password or connection string was placed in arguments. Clean invocation prefix:

```text
env -i HOME=/Users/ferozebasha PATH=/usr/bin:/bin LC_ALL=C \
/Users/ferozebasha/sbom/.venv/bin/python -B \
/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py
```

Exact action arguments:

```text
--mode validate --next-revision 082_uuid_products_expand
--plan P/operator-approved-plan.json
--approval-id W16F-082-VALIDATE-20261017
--evidence P/runner-validation.private.jsonl

--mode execute --next-revision 082_uuid_products_expand
--plan P/operator-approved-plan.json
--approval-id W16F-082-EXECUTE-20261017
--evidence P/runner-execution.private.jsonl
```

| Executed check/event | Actual result / UTC timestamp |
| --- | --- |
| Connected read-only validation | Exit0; start13:48:36.687222, connected_validation_only_closed13:48:38.917706 |
| Immediate independent pre-execution verification | New bounded D-only read-only connection; identity/sole081/both catalogs/security/data/privilege/writer/lock-window/expiry/source gates PASS; closed before execution |
| Exactly one082 execute | Start13:49:04.180360, existing next-only runner/exit0; no earlier migrations or second attempt |
| Transaction/locks | One owned PostgreSQL transactional DDL unit; advisory7160085085, versionEXCLUSIVE NOWAIT and ONLY products ACCESS EXCLUSIVE NOWAIT; exact082 source and conditional081→082 marker change in same transaction |
| Precommit validation | Expected082 prefix/narrow products-only delta passed13:49:06.296312 |
| COMMIT acknowledgement |13:49:06.305955; write connection physically closed before runner independent read-back |
| Runner independent verification | New read-only connection, committed_verified_closed13:49:06.768599; exact082/prefix/delta PASS |
| Additional independent acceptance | Separate bounded read-only full31-category catalog/security/old UUID objects/integer graph/empty-business-table checks PASS |
| Resource preservation | Before13:47:45.795469 / after13:49:23.992492; filtered Docker/storage/network/image/state/start/mount/port/current process/listener/runtime/env/password metadata equal except observation timestamp; sorted identifier sets equal |

Five D-only connections total: validation, independent preflight, migration write, runner read-back, additional independent read-only acceptance. Zero A/B connections. No SQL error, lock failure, uncertain commit, automatic retry, rollback/downgrade or cleanup. Host metadata checks were read-only.

### Independently verified committed delta

| Object / invariant | Actual post-commit result |
| --- | --- |
| Alembic marker | Exactly one row:082_uuid_products_expand; before081_uuid_projects_expand |
| Added column | Only public.products.public_id, attribute23, nativeuuid, nullable, defaultgen_random_uuid(). ADD COLUMN had no volatile default; reviewed separate SET DEFAULT used |
| Added CHECK | Only ck_products_public_id_v4; NULL-allowing canonical UUIDv4/version+variant regex; NOT VALID, convalidated=false. No CHECK validation or NOT NULL enforcement |
| Added triggers | Only trg_products_public_id_insert and trg_products_public_id_immutable; exact reviewed enabled/O BEFORE INSERT allocator and conditional AFTER UPDATE immutability definitions |
| Shared function / existing UUID objects | All functions/ownership/ACL/security/search_path unchanged; shared guard bodySHA256ff93761fa4dd31fa6dff7c25f3aedf41bc960e181a234d390f540e359d2e8d58. Tenants AND projects UUID columns/checks/triggers unchanged |
| Remaining scope | logical_sbom, sbom_source, sbom_component still unexpanded |
| Other application structure | Every old captured catalog row retained; changed31-category sections only columns/constraints/triggers/dependencies. Integer PK/FK graph, old indexes/sequences and relationships unchanged;72tables/1146base columns/512indexes/60sequences/143FKs |
| Data/security/preservation |71empty business tables; roles/memberships/restricted16389/plpgsql compatibility and sole approved owner exception unchanged. Known absent VEX FK preserved. No public UUID unique indexes, backfill or business-row tests. Original D cluster/storage and existing SBOM PostgreSQL/Redis/Mailpit/application network/process baseline preserved; no A/B data-equivalence claim |

Post082 runner13-category SHA256: **75336075175c623666778eb5d5249856e83372d210ff4c5657eeaa9f4fbd1169**.

Post082 independent31-category SHA256: **b2f72585938ec875b40b28b40cfe3c0e1e342b0b394a51581f15722738d74d48**.

These are different catalog formats; future tasks must compare each with its corresponding format, not with each other.

### Evidence, tests, limits and next gate

Private execution directory above:16files0600 in0700 UID501 directory. Manifest references15files, SHA256 **c36989aa5effd126a26cf2a26e70df6e0a4711c57a301b47dcef5d64ea7e8b25**. Acceptance evidence SHA256 **90ef26c81fd9e0ae00f51d99c2800ad1a63be09f9c76bb8a9ef12bab70b04dfb**. Approved plan, authority, flushed validation/execute event sequence, independent source/catalog/pre-post checks, listener reconciliation and preservation evidence retained outside repository. No secret contents/full connection strings/process environments/business records printed or stored in reports.

Actual continuation checks: source-only runner offline mode rerun PASS; exact source/candidate/approved-plan field differences/expiry and historical protected artifact integrity verified; real connected validation,082 SQL/deparser/happy-path transaction/atomic marker/read-back plus independent catalog/security/data and host preservation checks PASS. Earlier21offline tests/compilation/graph/static results against unchanged sources retained; not represented as rerun this continuation. Six pre-existing Ruff I001 warnings acknowledged, pinned sources untouched.

**NOT RUN:** UUID INSERT/CHECK/immutability DML behavior, synthetic business rows, concurrent writers/BEFORE-trigger interference/lock contention, failed rollback/lost-commit recovery, runtime writer integration, performance and application tests. Successful catalog/transaction checks do not certify those behaviors. C-B02–C-B05/future-stage and mapping-preserving rollback requirements remain open. Ordinary bridge permits potential outbound connectivity; no zero-egress claim.

**Decision: W1.6F IMPLEMENTED / ACCEPTED for082 on disposable D only.** No remaining mandatory082 execution-acceptance blocker observed. **GO to request separate083 authorization**, using current committed082 fingerprints and a new revision-specific candidate/operator review. No automatic083, index/backfill, API cutover or production readiness. Exact repository edits for this continuation: append this report and update master tracker; no migration/runner/application/runtime/Compose/source edit or Git delivery.

W1.6F approved-continuation final documentation verification PASS:2,097 other existing repository file contents/tracked binary diff/file set unchanged;37 historical task-ledger rows and12 Phase1 issue rows retained verbatim; whole earlier report21 retained as unchanged prefix. Branch/HEAD, local links/line numbers/whitespace/git diff --check, private0700/0600 manifest hashes/modes, untouched candidate, exact six approved plan-field differences and real start/precommit/commit_acknowledged/committed_verified_closed sequence verified. Only existing report21/tracker updated; no extra database access for documentation.082 IMPLEMENTED/ACCEPTED;083 not executed or automatically authorized.
