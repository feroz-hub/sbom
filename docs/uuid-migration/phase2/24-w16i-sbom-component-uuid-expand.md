# W1.6I — Final table UUID expansion preparation: revision 085

2026-10-17, Asia/Kolkata. **BLOCKED AT MANIFEST REVIEW. Preparation checks passed; revision 085 NOT EXECUTED / NOT ACCEPTED.** Actual sole marker remains `084_uuid_sbom_source_expand`. One bounded authenticated D-only read-only session completed and closed; **actual database mutations: zero**. No connected expand_validate/expand_execute, DDL/DML, synthetic business records, UUID index/backfill, A/B/production access, Docker/service lifecycle or Git delivery.

The four independent operator attestations remain false and approvals empty. This is the expected authorization gate, not a migration failure. No reporting-helper failure occurred in this task; the earlier W1.6H exit2/KeyError/source/diagnosis are preserved and its failed helper was not rerun.

## Scope, Git state and accepted 084 execution

Read the latest tracker, [report23 real084 acceptance](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/23-w16h-sbom-source-uuid-expand.md:181), [report10](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/10-w1-expand-transaction-refactor.md:1), [report12](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/12-w1-isolated-expand-runner.md:1), actual085/current runner/common. Task authority, prerequisites, stop conditions and acceptance criteria recorded IN PROGRESS before tests or target access. Only preparation/read-only verification and a fresh candidate are authorized; no prior revision's approval transfers to085.

Branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`;2101 existing repository file contents and tracked binary diff snapshotted. Existing dirty work preserved. Active application graph still has79 revisions/sole079 head; six staged files remain outside active registration. Database084 is the independently verified committed prefix. No branch switch/pull/reset/stash/commit/push or remote-ref freshness claim.

Protected accepted084 directory `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16h-execute-20261017T144255451085Z` verified:

| Historical evidence | Integrity/result |
| --- | --- |
| Final manifest | SHA2566354f04a9a848f25ef42eac17375dad265a365ddf1d1481c14e0680d08912601; all17 referenced hashes/owned0600 modes match |
| Initial execution manifest | SHA25680c318f23208e475157d784d2c51c2917f48559132d3962c781f5d4606d030fb; all14 referenced hashes/modes match, retained by final manifest |
| Approved executable plan | ByteSHA256204fa000f143f0bffda275541581edd2396a3b523eecf9d56dd3b6fb55132ae3; runner compact digestf987006d2d7ffe1567c02999dc0d45198b1f3a94f8d298b0085ed06b8398d3f3; historical operator references retained, not reused |
| Actual084 execution | Exactly one083→084, precommit14:44:02.512590UTC/commitACK14:44:02.514272/physical write close/new read-only committed_verified_closed14:44:02.955886. Four success events/exit0 and independent full acceptance consistent; no retry/unknown commit |
| Final acceptance/ownership | SHA25640af3ab3c16e120f8cf676de9a0a968b9524dab28ff3521ee6f479279a259cf9, status ACCEPTED. Includes original acceptance and supplemental expected-owner read-only check, six historical D-only connections, unchanged current resources; no index/backfill/business fixture/085 |
| Earlier helper failure | W1.6H preparation manifest290b3fa4baefb4e58d07b8dd51f41327e98c1ff60e4464d34d8ac07017e58703/all15 artifacts verified unchanged, including exit2/stale source-key KeyError/original helper/offline diagnosis/candidate. No rewrite or rerun |

Current comparisons use accepted084 `post-success.private.json`, not079–083 snapshots. Each proper-format fingerprint was checked against its accepted snapshot and freshly measured D state.

## Original 085 source and runner review

| Requirement | Verified source and result |
| --- | --- |
| Original085 SHA256 | Extracted from [report10:151](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/10-w1-expand-transaction-refactor.md:151): **45f331390609e52ceddbf0968651b5ec817bf26811f6f67845d1fb6d99cdbb0f**. Current bytes match; not inferred from084 |
| Dependency/table | [085:15](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/085_uuid_sbom_component_expand.py:15): immediate084_uuid_sbom_source_expand predecessor, sole public.sbom_component target; branch_labels/depends_on None |
| Nullable native UUID/default | [Upgrade:192](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/085_uuid_sbom_component_expand.py:192): one nullable PostgreSQL UUID public_id, no ADD COLUMN default/server_default; separate SET DEFAULT pg_catalog.gen_random_uuid() |
| CHECK/triggers | Exact NULL-allowing canonical v4/version+variant CHECK NOT VALID; BEFORE INSERT explicit-NULL allocator and conditional AFTER UPDATE WHEN OLD.public_id IS DISTINCT FROM NEW.public_id immutability trigger. Final NEW after BEFORE triggers controls predicate; actual interference behavior remains unexecuted |
| Shared guard reuse | Catalog preflight verifies exact sole body/signature/language/volatility/invoker/security/search_path/EXECUTE. No CREATE/REPLACE FUNCTION in085; existing guard reused unchanged |
| Unexpected state | Rejects existing public_id/proposed CHECK/trigger collisions, incompatible ordinary permanent/noninherited table/int4 single PK, user BEFORE INSERT triggers/write rules. Future marker/object mismatch cannot be adopted silently |
| Preservation/exclusions | No integer PK/FK/association/sequence/index/business-field alteration; no UUID unique index/backfill/CHECK validation/NOT NULL/business-row change. Downgrade raises before operations, no drop/CASCADE/UUID mapping loss |
| Runner pin | expand_one_step.py **57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b**, unchanged |
| Common pin | uuid_w1_common.py **4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94**, unchanged |
| Graph/replay | [discover:63](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:63) AST-verifies active079 ancestry/pins six staged sources/synthetic boundary, retains verified bytes. [next_only:123](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:123) permits084→085 only; rejects head/ranges/replay/skips. Archived monolithic080 .py.txt and normal root Alembic env/settings/application engine excluded |
| Future one-unit contract | Only after separate approval: one owned085 DDL+conditional084→085 marker transaction, advisory7160085085/versionEXCLUSIVE NOWAIT/ONLY sbom_component ACCESS EXCLUSIVE NOWAIT, acknowledged commit/physical close/new read-only verification. Source lock1s/statement10s caps do not bound the whole COMMIT/network deadline |

C-B02 common evidence-constructor cleanup defect is outside expand's separate close-on-initial-emit implementation. C-B03 index-reset/autocommit failure masking and C-B05 backfill budget controller are not used. C-B04 fixed085 common.load_plan parser is not used even though the requested successor is now085: this remains the expand-specific manifest/prefix/lifecycle contract. C-B06 strict current084 guard/CHECK/trigger rendering passed;085 grammar/deparser/new-delta/behavior still requires actual authorized execution. Findings remain open for their original/future stages; no pinned source changed or comparison relaxed. No new execution-critical source defect demonstrated.

### Component foreign-key and lock dependencies

Read-only catalogs show3 outgoing FK edges: component self-reference, sbom_source and tenants. There are7 incoming edges including the same self-reference: analysis_finding, component_lifecycle_override_audit, component_recommendation, vex_investigation, vex_override_audit, vex_statements, plus sbom_component. These are9 distinct constraints; the self-edge is counted in both directions. Definitions/owners/dependencies remain exactly in accepted084 catalogs.

085 does not alter any FK or related integer field. Its explicit business-table lock is ONLY sbom_component, plus the runner's version lock and cooperative advisory lock. This does not prove PostgreSQL takes no additional namespace/function/type/catalog/TOAST/index/FK-related dependency locks. Actual lock sets, contention/timeouts and interference from concurrent privileged DDL are not measured here. No EXCLUSIVE/ACCESS EXCLUSIVE table locks or migration DDL were acquired; the proposed future window requires independent approval and fresh lock checks.

## Offline checks actually executed

Clean HOME=/Users/ferozebasha, PATH=/usr/bin:/bin, LC_ALL=C; existing `.venv/bin/python -B` and installed Ruff0.15.10 module, no application startup/dependency installation/source fixes.

| Check | Actual result / limit |
| --- | --- |
| Existing test_expand_one_step.py | **21 tests PASS**, source/hash/graph/next-only/refusal/prefix/partial-chain and mocked commit-close-readback/SQL error/unknown COMMIT/recovery classification |
| expand_one_step.py --mode offline | PASS exact source/evidence pins/active+isolated079–085 graph; no runtime input path |
| verify_offline.py | PASS79active+6staged/combined085,42SQL templates/14literal/18dynamic query compilations and6index-DDL compilations. No SQL or index execution |
|085 Python syntax/compile/AST/source assertions | PASS report-derived hash/immediate084/component-only/native nullable UUID/no ADD default/separate allocator default/NOT VALID v4CHECK/guard reuse/two triggers/no index-backfill-validation-NOTNULL/raise-only downgrade |
| Ruff repository runner lint | PASS6files |
| Ruff --isolated migration lint | PASS6files, original reviewed scope |
| Ruff repository migration lint | FAIL only six historical I001 import-order warnings in unchanged080–085. Recorded separately, not hidden or automatically a PostgreSQL blocker; no fix/repin |
| Ruff format --check | PASS12files; --no-cache used for lint/format |
| Private read-only harness syntax/source | PASS; selected inert reviewed catalog/role/source functions only, no historical main/connect/write code loaded. New helper uses dynamic source key; prior failed reporting helper not reused/rerun |
| Pending candidate parser | Pure refusal PASS for false attestations/empty approvals; no connected expand_validate mode |
|085 PostgreSQL grammar/DDL/commit/new schema acceptance, DML/concurrency/recovery/performance/app tests | **NOT RUN / NOT ACCEPTED**. Compilation and mocks are not real PostgreSQL execution |

Commands/stdout/stderr/exit codes captured privately. No new helper/source/test failure occurred. All historical failures and unexecuted acceptance groups remain explicit.

## Fresh D-only read-only verification

Host before **2026-10-17T14:55:30.719853UTC**, after **14:57:04.390268UTC**. Exactly one bounded explicit D session; BEGIN REPEATABLE READ READ ONLY verified, ROLLBACK/physical close **14:56:47.757067UTC**. Connect5s/statement10s/lock1s/idle15s limits; no PG overrides/dotenv/application fallback, no retries/reconnects, no A/B/production contact.

| Gate | Actual observation / result |
| --- | --- |
| Local Docker | Explicit UID501 Unix socket /Users/ferozebasha/.docker/run/docker.sock; Desktop daemon1f8c7fe5-5972-4adc-8d6e-363a38572be1/29.8.2/Compose5.6.0; pinned CLI hash31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f. No remote daemon |
| Original D resources | Containerfb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e/imagesha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54, start/state/health/restarts/mount/project-service labels unchanged. Original exclusive sbom-uuid-w1_d_pgdata/creation2026-10-16T13:09:16Z and sole access network6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65 preserved; no app-network attachment |
| Endpoint/config/secret | Actual127.0.0.1:56041 publication/listener only, no wildcard/IPv6 D exposure. Existing dedicated secret UID501/inode75679830/65bytes/0600/regular/non-symlink/single-link/private0700 parent unchanged; no rotation/copy/disclosure. ComposeSHA13e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab unchanged; env-file metadata unchanged, contents not inspected |
| PostgreSQL | uuid_w1_d_rehearsal/current+session user uuid_w1_d_bootstrap/OID16384, server160015/16.15, cluster7697252084555804711, PGDATA /var/lib/postgresql/data/pgdata, no recovery/origin replication/read-only on. Internal172.20.0.2:5432/raw inet172.20.0.2/32 separate from host endpoint |
| Owner/roles/extension/security | D ownerOID10/bootstrap/NULL database ACL/allowconn/not template matches captured084 ownership supplement. Restricted ownerOID16389/NOLOGIN/no password/no memberships/all approved flags and captured ACL/security unchanged. plpgsql version/schema/functional/security/privilege properties compatible; sole prior approved owner exception retained |
| Marker/prefix | Exactly one084_uuid_sbom_source_expand; five earlier UUID columns/defaults/NOT VALID v4CHECKs/two enabled identity triggers each/shared guard definition-properties-ACL unchanged. sbom_component unexpanded, no proposed UUID objects/user triggers or write rules |
| Runner13 fingerprint | **7897aaa96923950c3efc4225455200f1122a48ddbbb84aa4c81dfd75f875e5b8**, freshly computed and matched accepted084 runner snapshot/format only |
| Independent31 fingerprint | **8c310ba21c5f3fcf3c5335d6b818dd44f7d0e60601f1292fbea7fd6cd69d5252**, freshly computed; entire accepted084 post-success catalog equality. No older/cross-format comparison |
| Structure/data/B drift |72tables/1148base columns/512indexes/60sequences/143FKs; integer PK/FK/association/index/sequence definitions unchanged.71business tables empty via bounded EXISTS; no records exported or sequence positions read/advanced. Missing VEX superseded_by_id FK and actual B drift unchanged |
| Component conditions | Plain permanent/noninherited/non-RLS; existing int4 NOT NULL id/single-column PK; no public_id/proposed CHECK/trigger collisions or user triggers/write rules.3 outgoing/7 incoming FK edges observed as above; no FK repair |
| Privilege/writer/lock window | Eight component/shared-guard schema/language/allocator/SELECT/TRIGGER/owner-role/EXECUTE checks PASS. Zero other D clients/target-version locks; advisory7160085085 transaction-lock availability verified and released at ROLLBACK. No EXCLUSIVE table locks; proposed future one085 window is not reserved or approved |
| Resource/process preservation | Accepted084 current baseline and fresh before/after filtered container/image/state/start/mount/port/network/volume/process/listener/runtime/env/password metadata match except time; identifier sets sorted. Historical five service PIDs still absent/stale runtime/no18000or13000listeners; current repository tool/runtime processes unchanged, no service-running or actor claim. No A/B data-equivalence claim/lifecycle action |

Expected private evidence-directory entry creation changes its parent metadata only; credential and storage identity checks remain independent. No ordering or metadata artifact hid a genuine mismatch.

## Exact fresh085 candidate for independent review

Private file: `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16i-20261017T145438779406Z/085-approval-candidate.json`, exclusive0600 under0700 UID501 directory.

**Byte SHA256: `79aed405646cafc8effb5beeb05e5de09604ed67fe24bebf1113ff1d99290815`.** Expiry **2026-10-18T14:56:47.790898UTC /2026-10-18 20:26:47.790898IST**. First085 candidate with fresh observations/expiry; no080–084 executable plan, action reference, expired candidate or pre-084 fingerprint reused. accepted=true refers to accepted D084, not085 approval. Four attestations false/approvals empty as instructed.

Additional source_sha256/independent_schema_sha256/review_observations fields provide nonsecret review context; they do not replace source discovery/prefix/full-schema checks or operator attestations. No password value/content hash appears. Full exact nonsecret JSON:

```json
{
  "accepted": true,
  "approvals": {},
  "baseline_reviewed": false,
  "container_id": "fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e",
  "container_sha256": "66f75be7578c216acbe83b5b24d49f4daeebc6216bf3a44815b62a6e01bab848",
  "current_revision": "084_uuid_sbom_source_expand",
  "daemon_id": "1f8c7fe5-5972-4adc-8d6e-363a38572be1",
  "database": "uuid_w1_d_rehearsal",
  "database_oid": 16384,
  "disposable": true,
  "disposable_secret_provenance_reviewed": false,
  "docker_binary": "/Applications/Docker.app/Contents/Resources/bin/docker",
  "docker_binary_sha256": "31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f",
  "docker_socket": "/Users/ferozebasha/.docker/run/docker.sock",
  "exclusive_ddl_window_reviewed": false,
  "expires_utc": "2026-10-18T14:56:47.790898+00:00",
  "host": "127.0.0.1",
  "independent_schema_sha256": "8c310ba21c5f3fcf3c5335d6b818dd44f7d0e60601f1292fbea7fd6cd69d5252",
  "network_ids": {
    "sbom-uuid-w1_d_access": "6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65"
  },
  "next_revision": "085_uuid_sbom_component_expand",
  "old_monolith_excluded": true,
  "password_file": "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/postgres-password",
  "port": 56041,
  "postmaster_started_at": "2026-10-16 15:41:09.226049+00",
  "prefix_review_reference": "W1.6H accepted084; fresh W1.6I085 candidate pending independent operator review",
  "review_observations": {
    "FK_lock_dependencies": "No FK alteration; incidental catalog/function/FK-related locks unmeasured, future approved execution only",
    "advisory_transaction_lock_available": true,
    "base_columns": 1148,
    "business_indexes": 512,
    "committed_prefix": "accepted084 tenants/projects/products/logical_sbom/sbom_source and shared guard unchanged; sbom_component unexpanded",
    "component_FK_incoming": 7,
    "component_FK_outgoing": 3,
    "component_table": "ordinary permanent/noninherited/non-RLS; int4 single PK; no user triggers/write rules/UUID object collisions",
    "component_version_table_other_locks": 0,
    "container_image_id": "sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54",
    "credential_metadata": {
      "ctime_ns": "1792153211012853252",
      "inode": 75679830,
      "links": 1,
      "mode": "0o600",
      "mtime_ns": "1792153211012853252",
      "regular": true,
      "size": 65,
      "symlink": false,
      "uid": 501
    },
    "credential_provenance": "existing W1.4a disposable-only dedicated secret; regular non-symlink UID501 0600 under0700; no rotation or A/B reuse",
    "database_owner": "uuid_w1_d_bootstrap",
    "empty_business_tables": 71,
    "evidence_reference": "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16i-20261017T145438779406Z/database-preflight.private.json",
    "exclusive_ddl_window": "proposed one085 transaction only; fresh writer and lock checks required after operator approval",
    "foreign_keys": 143,
    "maintenance_privilege_checks_passed": 8,
    "observed_utc": "2026-10-17T14:56:47.790898+00:00",
    "other_D_client_sessions": 0,
    "plpgsql_state": "functional/security/ACL unchanged; sole approved extension-owner exception",
    "postgresql_version": "16.15",
    "restricted_owner_role_oid": 16389,
    "restricted_role_state": "accepted restrictions unchanged; NOLOGIN/no password/no memberships",
    "sequences": 60,
    "source_provenance": "original report10-derived085 hash; immediate084 successor; shared guard verified/reused; archived monolith excluded",
    "tables": 72,
    "volume_created": "2026-10-16T13:09:16Z",
    "volume_name": "sbom-uuid-w1_d_pgdata"
  },
  "schema_sha256": "7897aaa96923950c3efc4225455200f1122a48ddbbb84aa4c81dfd75f875e5b8",
  "server_address": "172.20.0.2/32",
  "source_sha256": {
    "085_uuid_sbom_component_expand.py": "45f331390609e52ceddbf0968651b5ec817bf26811f6f67845d1fb6d99cdbb0f",
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

## Evidence, disposition and next authorization

Protected directory `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16i-20261017T145438779406Z`:14files0600/0700 UID501 parent; manifest references13files/SHA256 **37c052238b920b62b7433de9047b5c22c71210463d3c4c983913fe78a0fccb27**. Includes repository baseline, source/offline/integrity checks, original new private read-only/metadata sources, flushed labels/catalogs/FK metadata, candidate/outcome and preservation. No secrets/full URLs/process environments/business records printed/stored; sensitive role identifiers/catalog definitions remain private. Previous candidates/executable plans/approvals/protected evidence remain intact.

**W1.6I BLOCKED AT INDEPENDENT MANIFEST REVIEW;085 NOT EXECUTED / NOT ACCEPTED.** Preparation/source/read-only gates passed. Actual D084 and committed080–084 preserved; database mutations zero, connected expand_validate/expand_execute not run. Exact repository changes: new report24 and tracker update only; prior reports/staged+active sources/runners/application/runtime/Compose/credentials/Git work preserved.

Exact next operator inputs: approve this precise candidate byte SHA256/full content/unchanged expiry,084→085/D target, both corresponding084 fingerprints and original085/runner/common source pins; explicitly approve baseline_reviewed, writers_and_privileges_reviewed, exclusive_ddl_window_reviewed and disposable_secret_provenance_reviewed; supply distinct new085 expand_validate/expand_execute references and prefix-review approval. No reference or attestation invented. Changed/expired inputs require independent review; no silent renewal.

After separate exact approval only: save a new protected executable plan changing only approved fields/original candidate+expiry retained; existing connected read-only validation, immediate independent fresh identity/prefix/both catalogs/security/data/source/expiry/privilege/writer-lock gates; then exactly one085 transaction if all authority/gates pass. Require atomic084→085 marker, acknowledged commit/physical close/new independent read-only component-only delta and old-state preservation. No automatic unique-index/backfill work follows the final expand revision.

Remaining gaps:085 SQL/deparser/DDL/transaction/catalog acceptance; allocator/explicit-NULL INSERT/invalid UUID/CHECK/immutability DML, synthetic fixtures, concurrent writers/BEFORE-trigger interference/actual lock dependencies/timeouts/failed rollback/lost COMMIT recovery, runtime writer integration, performance/application tests. Current expanded columns remain nullable/nonunique/checks NOT VALID; public issuance/API/production cutover NO-GO. C-B02–C-B05/future-stage concerns, mapping-preserving rollback and ordinary-bridge outbound-access risk remain open. Completing the sixth source review does not certify unexecuted acceptance groups or authorize later stages.

Final documentation verification PASS:2,100 other existing repository file contents/tracked binary diff preserved; exact repository delta new report24 and tracker only.42 prior task-ledger rows/12 Phase1 issue rows retained verbatim. Branch/HEAD,67 local evidence links/line locations/whitespace/git diff --check, private0700/0600 manifest hashes/modes, exact candidate/report parsed-JSON equality/expiry/four false flags/empty approvals verified.21offline tests PASS; six historical I001 warnings retained. One D-only read-only preflight/exit0/no new helper error/zero database mutations/no connected validation or085 execution; no further DB access for documentation. Earlier failure evidence unchanged/not rerun.084 remains accepted;085 BLOCKED AT MANIFEST REVIEW, NOT EXECUTED.


## Operator-approved continuation — revision 085 IMPLEMENTED / ACCEPTED

**Actual result: IMPLEMENTED / ACCEPTED, disposable D only, 2026-10-17.** Exactly one existing isolated-runner invocation committed `084_uuid_sbom_source_expand` → `085_uuid_sbom_component_expand`. Connected validation, immediate independent preflight, runner committed-state read-back, separate full-catalog acceptance and host/resource/process preservation passed. All six scoped tables now have their reviewed expand objects. This accepts the additive schema/transaction/catalog result, not DML behavior, concurrency, recovery, performance, API or production readiness. The original preparation BLOCKED record and candidate above remain unchanged.

### Authorization and immutable inputs

The human **“W1.6I Operator Approval and Final Revision 085 Execution”** message is the authority for this continuation, four attestations and the distinct `W16I-085-VALIDATE-20261017` / `W16I-085-EXECUTE-20261017` references. No prior revision reference was reused or invented. The original candidate at `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16i-20261017T145438779406Z/085-approval-candidate.json` retained byte SHA256 `79aed405646cafc8effb5beeb05e5de09604ed67fe24bebf1113ff1d99290815`, exact report JSON and expiry `2026-10-18T14:56:47.790898+00:00`; it was unexpired at validation/execution and was not replaced or renewed.

New protected evidence directory: `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16i-execute-20261017T151016361957Z` (0700, UID501); files0600. New `operator-approved-plan.json` changes only `baseline_reviewed`, `writers_and_privileges_reviewed`, `exclusive_ddl_window_reviewed`, `disposable_secret_provenance_reviewed`, `approvals` and `prefix_review_reference`. All other identity, source, fingerprint, observation, target and expiry fields are identical to the candidate. Approved plan **byte SHA256 `bd373595092d2485910cbb94c39ceb7980ab6bd06b0390c654eae299bf36aef4`**; runner compact/canonical digest **`beebc005b50d2b8482f9616c25d73b91bcaf1f20203dacadd17ea01f082d7d09`**. Their distinct serializations are recorded separately.

Git remained branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`, with the pre-existing dirty worktree preserved. Compose hash remained `13e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab`. Active migration graph still ends at079; staged files remain unregistered. Original report10-derived085 hash `45f331390609e52ceddbf0968651b5ec817bf26811f6f67845d1fb6d99cdbb0f`, expand runner `57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b` and common `4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94` match. No pinned source was edited. Only immediate084→085/component source selected; no earlier revision/archived monolith/application Alembic environment executed.

Prior integrity reverified before connection: W1.6I preparation manifest `37c052238b920b62b7433de9047b5c22c71210463d3c4c983913fe78a0fccb27`/all13 referenced artifacts; accepted084 final manifest `6354f04a9a848f25ef42eac17375dad265a365ddf1d1481c14e0680d08912601`/all17 referenced artifacts; historical W1.6H preparation manifest `290b3fa4baefb4e58d07b8dd51f41327e98c1ff60e4464d34d8ac07017e58703`/all15 artifacts and restrictive modes. Prior helper exit2/stale-key KeyError/error/offline reconciliation remain historical evidence, not successful process exits; that helper was not rerun. The new independent read-only harness extracts inert reviewed catalog definitions using AST, explicitly supplies `psycopg.sql`, and has no historical main/application initialization path. Its syntax/dependency review completed before connection; no failed database probe/retry occurred.

### Fresh gates and actual operations

| Check | Actual result |
| --- | --- |
| Local target/infrastructure | Verified local Docker Desktop Unix socket `/Users/ferozebasha/.docker/run/docker.sock`, approved CLI hash/daemon `1f8c7fe5-5972-4adc-8d6e-363a38572be1`, Engine29.8.2/Compose5.6.0; D container `fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e`, image `sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54`, original exclusive `sbom-uuid-w1_d_pgdata`, sole `sbom-uuid-w1_d_access` network `6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65`, actual loopback-only127.0.0.1:56041→5432 unchanged |
| Credential | Existing dedicated disposable-only regular/non-symlink/single-link file, UID501/inode75679830/65bytes/0600 under0700; metadata unchanged. Explicit D credential reading only; clean environment/no PG*/dotenv fallback. No secret value/hash/copy/rotation or full connection string stored/printed |
| Identity and084 prefix | Actual PG16.15/cluster7697252084555804711/databaseOID16384/bootstrap/database ownerOID10 match. Sole084; repeatable-read READ ONLY independent transaction; runner13 `7897aaa96923950c3efc4225455200f1122a48ddbbb84aa4c81dfd75f875e5b8`, independent31 `8c310ba21c5f3fcf3c5335d6b818dd44f7d0e60601f1292fbea7fd6cd69d5252` freshly recomputed, exact own-format accepted084 catalogs match |
| Existing objects/security | Five earlier UUID tables/shared guard identical; component unexpanded/plain permanent/noninherited/non-RLS/int4 single PK, no proposed objects/user triggers/write-rule collisions. All72tables/1148basecolumns/512indexes/60sequences/143FKs, nine distinct component-related constraints including self-reference match. Roles/owner/ACLs/memberships/restricted OID16389/plpgsql functional/security/privilege properties and sole approved extension-owner exception unchanged; missing VEX FK/B drift preserved |
| Data, writers and privileges |71 business-table bounded EXISTS checks all empty; eight privilege checks true; zero other D client sessions and zero other component/version-table locks. Advisory7160085085 transaction-lock availability preflight succeeded/released on close. Exact source/expiry checked again in runner. No historical PID resurrection requirement or service lifecycle action |
| Validation | Existing runner connected validate exit0; start15:13:11.914666UTC, `connected_validation_only_closed`15:13:13.524924. Independent preflight15:13:24.047279–15:13:24.792972UTC passed/physical close; immediate host metadata15:13:22.579900UTC matched before baseline |
| One085 transaction | Existing runner execute exit0; start15:13:29.543698UTC; `precommit`15:13:30.794537; **`commit_acknowledged`15:13:30.795789**; **`committed_verified_closed`15:13:31.242164**. Exactly one source upgrade and conditional084→085 marker UPDATE in the same owned transaction; no retry/failure/unknown commit |
| Lock/connection contract | Reviewed runner uses session advisory7160085085, version-table EXCLUSIVE NOWAIT;085 source acquires ONLY component ACCESS EXCLUSIVE NOWAIT, with transaction-local lock≤1s/statement≤10s caps. PostgreSQL applies additional catalog/function/FK-related dependencies. No separate lock timeline/contended-writer test or hard whole-operation/COMMIT-network deadline measured. Write connection physically closed by NullPool/dispose before a new runner read-only connection; final event emitted only after read-back and close |
| Broader independent acceptance | New read-only connection15:13:37.104395–15:13:37.922757UTC passed exact085/prefix/delta/full31 catalog/owner-role-extension-ACL/data/FK checks and closed. Every pre-existing catalog row retained. Only columns/constraints/triggers/dependencies changed; functions/shared dependencies and all other categories unchanged |

Exact nonsecret invocations (each ran once, in separate processes, in the order validate → independent preflight → execute → independent postflight):

```sh
env -i HOME=/Users/ferozebasha PATH=/usr/bin:/bin LC_ALL=C \
  /Users/ferozebasha/sbom/.venv/bin/python -B \
  /Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py \
  --mode validate --next-revision 085_uuid_sbom_component_expand \
  --plan /Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16i-execute-20261017T151016361957Z/operator-approved-plan.json \
  --approval-id W16I-085-VALIDATE-20261017 \
  --evidence /Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16i-execute-20261017T151016361957Z/runner-validation.private.jsonl

env -i HOME=/Users/ferozebasha PATH=/usr/bin:/bin LC_ALL=C \
  /Users/ferozebasha/sbom/.venv/bin/python -B \
  /Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py \
  --mode execute --next-revision 085_uuid_sbom_component_expand \
  --plan /Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16i-execute-20261017T151016361957Z/operator-approved-plan.json \
  --approval-id W16I-085-EXECUTE-20261017 \
  --evidence /Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16i-execute-20261017T151016361957Z/runner-execution.private.jsonl
```

Five D-only physical connections: validation, independent preflight, runner write, runner independent read-back, independent broader postflight. Zero A/B/production connections. No Alembic historical upgrade/stamp/application engine invoked. Session-wide advisory lock is released by physical write-connection close; independent preflight used the transaction-scoped availability variant. This distinction does not change the reviewed serialization contract.

### Independently observed committed085 delta

| Object / invariant | Actual catalog result |
| --- | --- |
| Version marker | Exactly one row: `085_uuid_sbom_component_expand`; previously sole084 |
| New column | Exactly one additional base-table column: `public.sbom_component.public_id`, attribute69, nativeuuid, nullable; separate default deparses `gen_random_uuid()` (approved pg_catalog allocator). ADD COLUMN had no default; no table-wide default rewrite/backfill source executed |
| v4 CHECK | `ck_sbom_component_public_id_v4`, NULL-allowing canonical lowercase v4/variant regexp; `convalidated=false`, deparser NOT VALID. No validation/NOT NULL enforcement |
| INSERT trigger | `trg_sbom_component_public_id_insert`, enabled O, BEFORE INSERT FOR EACH ROW calls `public.uuid_public_identity_guard_v1()`; catalog definition confirms intended explicit-NULL allocator wiring; actual row behavior NOT TESTED |
| UPDATE trigger | `trg_sbom_component_public_id_immutable`, enabled O, AFTER UPDATE FOR EACH ROW WHEN OLD.public_id IS DISTINCT FROM NEW.public_id calls the same guard; actual immutable/NULL-to-first-assignment behavior and other-BEFORE-trigger interference NOT TESTED |
| Shared/previous objects | Shared guard definition, owner, ACLs, search_path/security properties and all functions unchanged. Tenants/projects/products/logical_sbom/sbom_source UUID columns/CHECKs/defaults/triggers unchanged; all six now expanded |
| Graph/storage objects | Original integer PK/FK graph, nine distinct component-related FKs/self-reference, all512indexes and60sequences retained identically;143FKs/associations unchanged; no public UUID unique index created |
| Security/data | Database owner, roles/restricted16389/memberships/ACLs/extension state unchanged. All71business tables remain empty; only authorized version-marker contents changed. No fixtures/business DML/backfill |
| Counts |72tables, **1148→1149basecolumns**,512indexes,60sequences,143FKs; one CHECK and two user triggers added, only expected dependency additions |

**Fresh accepted post085 fingerprints** — compare each only within its own catalog format:

- Runner13-category: **`85507e89a3946cda7611e5498e816fcf5708af18a6549b08a4fbfe3ae1f0d80a`**.
- Independent31-category: **`760c7e7b0b50688fd4f7c3471219a35fa3b025f67bf3303cc15a50f44800fd30`**.

### Preservation, checks and evidence

Filtered host/Docker snapshots before15:10:25.395101UTC, immediate15:13:22.579900UTC and after15:13:38.082829UTC match in every recorded field except observation time. Container/volume/network identity sets sorted independently of enumeration order. Same original D container/image/storage/mount/cluster/network/actual port/private credential metadata; existing sbom-postgres-1/Redis/Mailpit volumes/network/mounts/states/restarts/publications preserved. Current repository process/listener identities, `.dev-runtime.json` and `.env`/`.env.dev.local` safe metadata unchanged; no environment contents opened. Historical launcher/API/worker/Beat/frontend PIDs remain absent/stale runtime, no18000/13000 listeners, as previously accepted; no claim that those services were running or that A/B business data was compared. Existing tool/runtime process identities remained unchanged. No Docker mutation/service startup/restart.

Executed again in this continuation: existing21offline runner tests PASS (0.509s), isolated `--mode offline` source/active079/six-revision isolated graph verification PASS, exact source/hash/prefix assertions and independent private-harness syntax/AST review PASS. The preparation's SQL/DDL compilation, lint and format results above remain evidence against unchanged sources; they were not mislabeled as newly executed SQL. Six historical migration import-order I001 warnings remain untouched and separate from PostgreSQL execution. A plain `git diff --check` printed `error: daemon terminated`; the read-only `git -c core.fsmonitor=false diff --check` passed with exit0. No Git configuration was changed and no DB operation was retried.

Current protected evidence includes original repository baseline, authority/approved plan, prior-artifact integrity, metadata before/immediate/after, independent source/flushed checks/pre-post catalogs, runner validation/execution events and operations/acceptance. Initial manifest16entries/17files0600 under0700: SHA256 **`ad1f6bb04ba7b50d4d999ca1608be12fffe60a7a9fd26dd533570f3dc138bbb9`**; `acceptance.private.json` SHA256 **`6cd9c1a05fc1da6b2a3e159b44cc2271a5627d5b23fa82245bca80cfee261745`**. No secret contents/connection strings/process environments/business records exposed. New nonsecret evidence filenames within this new private directory are expected; credential directory/file identity unchanged. Later documentation-only integrity supplements, if any, do not add database sessions.

Only existing report24 and master tracker updated in the repository. Prior reports, candidates/manifests/evidence, hash-pinned migration/runner sources, active Alembic configuration, application/runtime/Compose/configuration, credentials and existing Git work preserved.

### Remaining gates and next action

**GO to request a separately authorized UUID integrity-testing phase against the accepted085 D state. No further execution is authorized now.** Six per-table additive expansions have real scoped D-only happy-path SQL/transaction/catalog acceptance. Unique indexes, resumable backfill, CHECK validation, NOT NULL enforcement and public issuance are separate unexecuted stages.

Actual allocator/explicit-NULL INSERT/user-supplied valid-invalid UUID/CHECK/immutability behavior, BEFORE-trigger interference, business fixtures, concurrent writers, dependency-lock contention/timeouts, rollback/partial-chain/unknown COMMIT recovery, hard total runtime budget, performance and application/tenant/API acceptance remain NOT RUN. C-B02 common evidence-constructor issue, C-B03 index cleanup masking, C-B04 old manifest parser type handling and C-B05 backfill budget limits remain open for their separate future paths; the expand controller avoids those particular paths but does not prove every failure mode. C-B06 actual085 SQL/deparser/prefix/delta compatibility now passed on PG16.15; no broader runtime/behavior acceptance inferred. Ordinary-bridge outbound connectivity risk and mapping-preserving rollback requirements remain. Nullable/nonunique/NOT VALID transitional schema is not a public or production cutover. No automatic index/backfill/next task, approval renewal, downgrade or cleanup occurred.


Final documentation verification PASS:2,100 other existing repository files, exact file set and pre-existing tracked binary diff unchanged; only report24/tracker updated.43 historical completed-task ledger rows/12 Phase1 issue rows retained verbatim; entire preparation report24 retained as unchanged prefix. Branch/HEAD,68 local evidence links/line locations/whitespace/fsmonitor-disabled git diff --check, original candidate/six approved manifest-field changes/expiry/source pins/private0700-0600 hashes and real start/precommit/commit_acknowledged/committed_verified_closed sequence verified. Initial documentation assertion included intentionally updated current-readiness rows in historical-row scope; correcting that checker to the Completed-task ledger confirmed preservation, without any database action or history edit. Protected documentation-verification evidence retained; final18-entry/19file manifest SHA256 **02177e95f9c6def0294f9c2162cbee849ac9fda6ee1dd3177d0101e187e4ca4a**, initial16-entry manifest and acceptance retained. No further DB connection for documentation. Exactly one085 transaction accepted, five D-only connections/zero A-B; no index/backfill/behavior tests or automatic next task.
