# W1.6H — SBOM source084 UUID expansion preparation

2026-10-17, Asia/Kolkata. **BLOCKED AT MANIFEST REVIEW;084 NOT EXECUTED / NOT ACCEPTED.** Required source/offline/read-only preparation checks passed. Actual D sole marker remains `083_uuid_logical_sbom_expand`. Exactly one bounded D-only read-only session; **database mutation count zero**. No connected expand_validate/expand_execute, DDL/DML, business fixtures, UUID indexes/backfill, A/B/production, Docker/service lifecycle or Git delivery.

The private helper exited2 after the session closed and the valid candidate was saved: its final console summary used an obsolete083 source-key name. Original source/error/event retained; independent offline reconciliation verified the saved catalogs/candidate without reconnecting, rerunning the probe, changing expectations or regenerating the candidate. This reporting defect is not a database gate failure; details below. Operator attestations/action references remain unissued as required.

## Baseline, accepted083 evidence and authority

Required tracker, [report22 accepted execution](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/22-w16g-logical-sbom-uuid-expand.md:184), [report10](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/10-w1-expand-transaction-refactor.md:1), [report12](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/12-w1-isolated-expand-runner.md:1), actual084/current runner/common reviewed. W1.6H scope/prerequisites/blockers/acceptance recorded IN PROGRESS before offline tests or target access. This task authorizes preparation and D-only read-only verification, not084 execution or operator approval records.

Verified branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`; task-start2100 existing repository file contents/tracked binary diff snapshotted. Existing dirty work preserved. Active source graph remains79 revisions/sole079 head, staged six-revision chain outside active registration. Actual committed083 database prefix does not change the active application graph. No checkout/pull/reset/stash/commit/push or fresh remote-ref comparison.

Protected accepted083 directory `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16g-execute-20261017T142105585732Z`: manifestSHA256 **abc9923c5e4a030d687b0dac901635c14c8605e2881f9cdb60caabfecc545c49**, all14 referenced hashes/owned0600 modes verified. Actual four-event sequence start/precommit/commit_acknowledged/committed_verified_closed, commit ACK2026-10-17T14:22:38.495005UTC and new read-back/closure14:22:38.951332 confirmed. AcceptanceSHA25672339faa0981f6bfd72aec4f96b897f8ada090334271ce3d0b51f6d5a4b8c7b2 records exactly one082→083/no retry/independent acceptance/zero preservation differences. Current baseline references its actual post-success083 catalogs, never079–082 snapshots.

Prior W1.6G preparation manifest2aab4d38236804f0916c2168b23e00bad8052ef63fce58a4af7c3047df4f6cd2/all13 artifacts verified unchanged. Historical manifest-review blocks and earlier private-harness wrong-reference/list-vs-tuple failures/corrections remain preserved by prior reports/protected evidence. No source pin or historical outcome rewritten.

## 084 source and current runner review

| Check | Verified result / source |
| --- | --- |
| Original084 SHA256 | Extracted from [report10:150](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/10-w1-expand-transaction-refactor.md:150): **13a84b0d6d3201a64be7ba90a32560a5c5738a319be1fc8af29d2364aec49803**. Actual bytes match; not inferred from083 |
| Declarations | [084:15](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/084_uuid_sbom_source_expand.py:15): immediate predecessor083_uuid_logical_sbom_expand, sole _TABLE sbom_source/schema public, no branch/dependency override |
| Expand only | [Upgrade:192](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/084_uuid_sbom_source_expand.py:192): one nullable native PostgreSQL UUID public_id added without ADD COLUMN default/server_default; separate SET DEFAULT pg_catalog.gen_random_uuid() |
| CHECK/identity triggers | NULL-allowing canonical version4/variant regex CHECK NOT VALID, exact BEFORE INSERT explicit-NULL allocator, conditional AFTER UPDATE WHEN OLD.public_id IS DISTINCT FROM NEW.public_id immutable guard. Final-row predicate covers changes by BEFORE UPDATE triggers; actual interference behavior remains untested |
| Shared guard | Exact sole body/signature/language/invoker/security/search_path/EXECUTE catalog checks; no CREATE/REPLACE FUNCTION in084, no alteration of already committed guards/UUIDs |
| Preservation/collisions | Requires plain permanent noninherited table/existing int4 single-column id PK, no colliding UUID column/check/trigger, no existing user INSERT trigger/write rule. Existing integer PK/FK/sequence/business field/index unchanged by source operations. Downgrade raises before any operation; no adoption/drop/CASCADE/mapping removal |
| Excluded stages | No public UUID unique indexes/backfill/NOT NULL/CHECK validation/business-row update/application change |
| Runner SHA256 | expand_one_step.py **57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b**, unchanged |
| Common SHA256 | uuid_w1_common.py **4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94**, unchanged |
| Graph/replay prevention | [discover:63](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:63) pins exactly six staged files/active079 ancestry/synthetic boundary; [next_only:123](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:123) allows only083→084, rejects replay/head/ranges/skips. Archived monolithic080 .py.txt excluded; normal root env/settings/engine/launcher and earlier upgrades never imported/executed |
| Future transaction/locks | After exact separate approval only: one owned transactional084 DDL+conditional083→084 marker, shared advisory7160085085/versionEXCLUSIVE NOWAIT/ONLY sbom_source ACCESS EXCLUSIVE NOWAIT. Source caps lock1s/statement10s, not whole COMMIT/network deadline. No target/version EXCLUSIVE locks taken here; incidental namespace/function/catalog/FK-related lock dependencies and contention remain unmeasured |

C-B02 common Evidence constructor cleanup defect is outside expand's separate close-on-initial-emit implementation; C-B03 index-reset masking/autocommit path is not used; C-B04 fixed085 common manifest parser is not used; C-B05 backfill budget controller is not used, while expand still has no hard end-to-end acknowledgement deadline. C-B06 strict actual083 guard/CHECK/trigger/catalog rendering passed;084 SQL/deparser/transaction/new-delta behavior remains unexecuted. No gate relaxed, no W1.6B finding repaired or generally accepted, no new execution-critical pinned-source defect demonstrated. Privileged DDL/trigger-bypass risks still require exclusive-window/writer/security review.

## Offline verification actually executed

Existing `.venv/bin/python -B`, clean HOME=/Users/ferozebasha/PATH=/usr/bin:/bin/LC_ALL=C. Existing Ruff0.15.10 Python module; no dependency installation, cache writes to repository or application import.

| Command/check | Actual result |
| --- | --- |
| test_expand_one_step.py | **21 tests PASS**, real source/graph/next-only/manifest/prefix assertions and mocked commit-close-readback/SQL-error/unknown-COMMIT/reconciliation paths |
| expand_one_step.py --mode offline | PASS exact pins/active+isolated079–085 graph; no runtime inputs or target access |
| verify_offline.py | PASS79active+6staged/combined085,42SQL templates/14literal/18dynamic query compilations,6concurrent-index DDL compilations; no SQL/index execution |
|084 syntax/compilation/AST | PASS original report-derived hash/immediate083 predecessor/sbom_source-only nullable native UUID/separate default/NOT VALID v4CHECK/two triggers/existing guard verification/no index-backfill-business-write-validation-NOTNULL; fail-closed downgrade retained |
| Ruff repository check --no-cache, staged-runner6files | PASS |
| Ruff check --no-cache --isolated, migrations6files | PASS original reviewed lint scope |
| Ruff repository migration check --no-cache | FAIL only six historical I001 import-order warnings in unchanged080–085; no fix/repin, not a failed database check |
| Ruff format --no-cache --check | PASS12files |
| Private harness syntax/source/pending-parser test | Syntax/source PASS; accepted083 reference/target084 reviewed. Pure parser refused four false flags/empty approvals without connected validation. Reporting-stage KeyError separately retained/reconciled offline |
|084 PostgreSQL DDL/commit/new schema acceptance, DML/concurrency/recovery/performance/app tests | NOT RUN / NOT ACCEPTED; SQL compilation and mocks do not prove PostgreSQL execution |

Full test commands/output/exit codes captured privately. No pinned migration/runner source edited. An initial offline script-builder assertion found an inapplicable optional textual replacement before creating the new harness/DB access; removed that replacement and retained the diagnosis. It did not relax any actual target/catalog/security assertion.

## Fresh D-only read-only preflight and preservation

Before host snapshot **2026-10-17T14:34:48.147960UTC**; after **14:36:06.880732UTC**. Exactly one explicit D-only read-only connection; BEGIN REPEATABLE READ READ ONLY verified, connect5s/statement10s/lock1s/idle15s bounds; all mandatory checks passed then ROLLBACK/physical close **14:35:29.374027UTC**. Zero A/B/production connections or persistent schema/data mutation.

| Gate | Actual safe observation / result |
| --- | --- |
| Docker/local daemon | Explicit UID501 Unix socket /Users/ferozebasha/.docker/run/docker.sock; daemon1f8c7fe5-5972-4adc-8d6e-363a38572be1/Desktop29.8.2/Compose5.6.0; exact Desktop binary hash31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f. No remote daemon |
| Container/image | Exactfb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e and imagesha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54, running/healthy/start/restart/labels unchanged |
| Original storage/network/port | sbom-uuid-w1_d_pgdata/creation2026-10-16T13:09:16Z/exclusive /var/lib/postgresql/data mount preserved; sole sbom-uuid-w1_d_access ID6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65, no app-network attachment. Actual loopback127.0.0.1:56041/listener, no wildcard/IPv6 D publication; old private network retained unused |
| Credential/config | Existing dedicated D secret only, UID501/inode75679830/65bytes/0600/regular/non-symlink/single-link under0700 parent; unchanged metadata/provenance, no rotation/copy/disclosure. Explicit fixed common.connect kwargs/no PG overrides/URL/dotenv/app fallback. ComposeSHA13e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab and .env/.env.dev.local metadata unchanged, contents not read |
| PG identity | uuid_w1_d_rehearsal/current+session user uuid_w1_d_bootstrap/OID16384, server160015/16.15, cluster7697252084555804711, PGDATA /var/lib/postgresql/data/pgdata; no recovery/origin replication/read-only on. Internal172.20.0.2:5432/raw inet172.20.0.2/32 distinguished from host publication |
| Sole marker/prefix | Exactly one083_uuid_logical_sbom_expand. Exact tenants/projects/products/logical_sbom UUID/default/NOT VALID v4 CHECK/two enabled triggers/shared guard definition-security-properties-privileges unchanged. sbom_source/sbom_component unexpanded |
| Runner13-category fingerprint | **eb96c4740b2a70123d7e85e5a839f6f7ae7e253322fcc0428f863a0927620219**, freshly computed/matches accepted083 runner format; independently recomputed offline from saved fresh observation |
| Independent31-category fingerprint | **4064d87ce1049cd43a250c44800c98cc674b0d2e2327be6828c2d175f6b33e9f**, fresh full catalog equals accepted083 post-success. Compared only its own format, independently recomputed offline from saved observation |
| Graph/data/B drift |72tables/1147basecolumns/512indexes/60sequences/143FKs; original integer graph/associations/index/sequence definitions unchanged.71empty business tables via bounded EXISTS, no records exported or sequence positions read/advanced. Missing VEX superseded_by_id FK/other B drift preserved by full catalog equality |
| Source-table conditions | sbom_source ordinary permanent/noninherited/non-RLS, existing int4 NOT NULL id/single-column PK, zero user triggers/write rules/UUID expansion-object collisions. This is not a duplicate-value test; no UUID column exists yet |
| Security/privileges/window | Restricted ownerOID16389/exact private name/NOLOGIN/no password/no memberships/approved flags and captured ACL/security unchanged. plpgsql version/schema/functional/security/privilege configuration compatible, only prior approved owner exception. Eight sbom_source/shared-guard privileges PASS; zero other D clients/target-version locks. Advisory7160085085 transaction-lock availability checked/released at ROLLBACK, no EXCLUSIVE locks taken. Future exclusive window remains proposed/pending operator review |
| Process/resources | Exact accepted083 current baseline and fresh before/after filtered Docker/storage/network/mount/state/start/publication/process/listener/runtime/env/password metadata match except observation time; sorted identity sets. Historical five SBOM PIDs remain absent/stale runtime/no18000or13000listeners; tool/runtime process identities unchanged, no resurrection/running-service claim. No lifecycle action or A/B data-equivalence claim |

Expected evidence-directory creation changes only its parent directory's metadata; secret and infrastructure identity comparisons are independent. No ordering or metadata artifact hides actual resource drift.

### Retained private-helper summary failure

The helper's process exit was2, not0. Every mandatory labelled preflight check passed, the read-only connection closed, saved database-preflight.private.json recorded PASS/current083, and candidate creation/parser-refusal event recorded PASS/hash/expiry. The following console print then accessed `evidence['source_sha256']['083_uuid_logical_sbom_expand.py']`; actual map correctly contained084 source. This produced KeyError/no SQLSTATE and a final CANDIDATE STOP record. Original source and both events remain unchanged.

Offline reconciliation matched saved fresh31-category catalogs/roles/extensions exactly to accepted083, recomputed both proper-format fingerprints, verified candidate byte hash/source pins/transition/false flags/empty approvals, and reproduced the missing dictionary-key failure without database access. No underlying assertion or database failure was reclassified, no candidate/source/expiry changed, no PG reconnection/retry or hidden runtime repair. Protected post-summary-error-diagnosis.private.json records the exact failure. Future execution should use its separately reviewed runner, not rerun this reporting helper. The valid candidate below is the original file produced after the successful read-only checks.

## Exact fresh084 candidate for independent review

File: `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16h-20261017T143345279417Z/084-approval-candidate.json`, exclusive0600 under0700 UID501 directory.

**Byte SHA256: `6c17652a0c9c6e536dc6d83ed31e47c5ad7085ff262b82a52ba4e22aef004305`.** Expiry **2026-10-18T14:35:29.374092UTC /2026-10-18 20:05:29.374092IST**. This is the first084 candidate; no previous executable plan/action reference/expired candidate reused or renewed. accepted=true denotes accepted D083, not084 approval. Four flags false/approvals empty deliberately.

Review observations/source_sha256/independent_schema_sha256 supplement the existing contract; they do not replace source discovery/prefix/full-schema checks or human attestations. No secret value or secret-content hash is present. Full exact nonsecret JSON:

```json
{
  "accepted": true,
  "approvals": {},
  "baseline_reviewed": false,
  "container_id": "fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e",
  "container_sha256": "66f75be7578c216acbe83b5b24d49f4daeebc6216bf3a44815b62a6e01bab848",
  "current_revision": "083_uuid_logical_sbom_expand",
  "daemon_id": "1f8c7fe5-5972-4adc-8d6e-363a38572be1",
  "database": "uuid_w1_d_rehearsal",
  "database_oid": 16384,
  "disposable": true,
  "disposable_secret_provenance_reviewed": false,
  "docker_binary": "/Applications/Docker.app/Contents/Resources/bin/docker",
  "docker_binary_sha256": "31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f",
  "docker_socket": "/Users/ferozebasha/.docker/run/docker.sock",
  "exclusive_ddl_window_reviewed": false,
  "expires_utc": "2026-10-18T14:35:29.374092+00:00",
  "host": "127.0.0.1",
  "independent_schema_sha256": "4064d87ce1049cd43a250c44800c98cc674b0d2e2327be6828c2d175f6b33e9f",
  "network_ids": {
    "sbom-uuid-w1_d_access": "6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65"
  },
  "next_revision": "084_uuid_sbom_source_expand",
  "old_monolith_excluded": true,
  "password_file": "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/postgres-password",
  "port": 56041,
  "postmaster_started_at": "2026-10-16 15:41:09.226049+00",
  "prefix_review_reference": "W1.6G accepted083; fresh W1.6H084 candidate pending independent operator review",
  "review_observations": {
    "advisory_transaction_lock_available": true,
    "business_indexes": 512,
    "committed_prefix": "accepted083 tenants/projects/products/logical_sbom and shared guard unchanged; sbom_source/sbom_component unexpanded",
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
    "credential_provenance": "existing dedicated W1.4a disposable-only secret; regular non-symlink UID501 mode0600 under0700; no rotation or reuse from A/B",
    "empty_business_tables": 71,
    "evidence_reference": "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16h-20261017T143345279417Z/database-preflight.private.json",
    "exclusive_ddl_window": "proposed one084 transaction only; fresh writer and lock checks required after operator approval",
    "foreign_keys": 143,
    "maintenance_privilege_checks_passed": 8,
    "observed_utc": "2026-10-17T14:35:29.374121+00:00",
    "other_D_client_sessions": 0,
    "plpgsql_state": "functional/security/ACL unchanged; existing approved owner exception only",
    "postgresql_version": "16.15",
    "restricted_owner_role_oid": 16389,
    "restricted_role_state": "accepted restrictions unchanged; NOLOGIN/no password/no memberships",
    "sbom_source_version_table_other_locks": 0,
    "sequences": 60,
    "source_provenance": "report10-derived084 pin; immediate083 successor; existing shared guard reused; archived monolith excluded",
    "volume_created": "2026-10-16T13:09:16Z",
    "volume_name": "sbom-uuid-w1_d_pgdata"
  },
  "schema_sha256": "eb96c4740b2a70123d7e85e5a839f6f7ae7e253322fcc0428f863a0927620219",
  "server_address": "172.20.0.2/32",
  "source_sha256": {
    "084_uuid_sbom_source_expand.py": "13a84b0d6d3201a64be7ba90a32560a5c5738a319be1fc8af29d2364aec49803",
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

## Evidence, remaining gaps and exact next approval

Protected directory `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16h-20261017T143345279417Z`:16files0600/0700 UID501 parent; manifest references15/SHA256 **290b3fa4baefb4e58d07b8dd51f41327e98c1ff60e4464d34d8ac07017e58703**. Actual offline/source/integrity commands, original private helper/events, successful fresh catalog/role-extension observations, candidate, post-summary error diagnosis, outcome and before-after preservation retained. No credentials/full URLs/process environments/business records printed or persisted; role/catalog definitions remain private.

Repository delta: create report23 and update tracker only. Old reports/historical statuses/hash-pinned staged/active sources/runners/application/runtime/Compose/env/credentials/Git work preserved. No database schema/data mutation, migration/index/backfill/business fixture or service action. **Actual sole D marker083;084 NOT EXECUTED / NOT ACCEPTED.**

**STOP: BLOCKED AT INDEPENDENT OPERATOR MANIFEST REVIEW.** Exact next inputs: independently approve this candidate's byte SHA256/full content/unchanged expiry,083→084 target, both corresponding083 fingerprints and084/runner/common source pins; explicitly approve baseline_reviewed, writers_and_privileges_reviewed, exclusive_ddl_window_reviewed and disposable_secret_provenance_reviewed; supply distinct new084-specific expand_validate and expand_execute references and prefix-review approval. No references invented or inherited from080–083.

After separate approval only: new protected executable manifest changing approved fields only/original candidate+expiry retained; existing connected read-only validation, immediate independent fresh target/prefix/security/data/source/expiry/privilege/writer/lock-window gates, and exactly one reviewed084 transaction if all gates and authority pass. Require acknowledged commit/physical close/independent source-only delta and all earlier objects preserved. Expiry/drift/conflict/failure/unknown COMMIT must stop; no automatic retry, cleanup, stamp or downgrade. No085 authority transfers.

Remaining unexecuted tests:084 PostgreSQL DDL/deparser/marker transaction/catalog delta, allocator/CHECK/immutability DML, synthetic records, BEFORE-trigger interference/concurrent writers/lock contention, failed rollback/lost-COMMIT recovery, runtime writer integration/performance/application acceptance. Existing columns remain nullable/nonunique/checks NOT VALID; public issuance/API/production cutover NO-GO. C-B02–C-B05/future-stage and mapping-preserving rollback/ordinary-bridge egress risks remain open. Preparation does not certify any unexecuted acceptance group.

Final documentation verification PASS:2,099 other existing repository file contents/tracked binary diff preserved; exact repository delta new report23 and tracker only.40 prior task-ledger rows/12 Phase1 issue rows retained verbatim. Branch/HEAD,65 local evidence links/line locations/whitespace/git diff --check, private0700/0600 manifest hashes/modes, exact candidate/report parsed-JSON equality, unchanged expiry/four false flags/empty approvals verified.21offline tests passed; six historical I001 warnings retained. Helper exit2/summary error/original source and independent offline reconciliation preserved, not represented as process success. One D-only read-only session/zero persistent mutations/no connected CLI validation or084 execution, no additional DB session for documentation.083 remains accepted;084 BLOCKED AT MANIFEST REVIEW.

## Operator-approved continuation — 084 IMPLEMENTED / ACCEPTED

Executed on2026-10-17. **Exactly one083→084 migration transaction committed on disposable D; independent acceptance passed.** This updates current readiness only. The earlier BLOCKED preparation, helper exit2/stale source-key KeyError/original source and offline reconciliation are retained unchanged; that failed reporting helper was not rerun or relabelled exit0. No085 execution followed. Active application Alembic source remains at079, with no staged-source registration.

### Authority, manifest and pinned source

The human “W1.6H Operator Approval and Revision084 Execution” message approves exact candidate6c17652a0c9c6e536dc6d83ed31e47c5ad7085ff262b82a52ba4e22aef004305, transition083→084/sbom_source, both starting083 fingerprints, three source pins, four attestations and distinct `W16H-084-VALIDATE-20261017` / `W16H-084-EXECUTE-20261017`. References originate from that operator instruction; no080–083 approval reused or additional approval invented.

Original candidate byte hash/full JSON/report equality/target/source/fingerprints verified. Expiry `2026-10-18T14:35:29.374092+00:00` unchanged and valid throughout. New approved manifest:

`/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16h-execute-20261017T144255451085Z/operator-approved-plan.json`

Byte SHA256 **204fa000f143f0bffda275541581edd2396a3b523eecf9d56dd3b6fb55132ae3**; runner compact-JSON digest **f987006d2d7ffe1567c02999dc0d45198b1f3a94f8d298b0085ed06b8398d3f3**. These use different serialization formats. Exactly six top-level fields changed: four approved flags, supplied two action approvals, operator prefix-review reference. All other identity/source/target/fingerprint/expiry/review-observation fields preserved. Original candidate not overwritten. New file0600/directory0700/UID501 outside checkout.

| Source / starting baseline | Verified SHA256 |
| --- | --- |
|084 source |13a84b0d6d3201a64be7ba90a32560a5c5738a319be1fc8af29d2364aec49803 |
| expand_one_step.py |57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b |
| uuid_w1_common.py |4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94 |
|083 runner13-category catalog |eb96c4740b2a70123d7e85e5a839f6f7ae7e253322fcc0428f863a0927620219 |
|083 independent31-category catalog |4064d87ce1049cd43a250c44800c98cc674b0d2e2327be6828c2d175f6b33e9f |

[084 upgrade](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/084_uuid_sbom_source_expand.py:192) and [isolated transaction runner](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:449) used unchanged. Active79-revision/sole079 graph/six staged successors verified; selected immediate next084 only, no root env/settings/engine, upgrade-to-head, historical replay or archived monolith. Source C-B02–C-B05/future-stage findings remain open; no execution-critical source gate failed or was weakened.

### Fresh gates, actual commands and transaction

Branch feat/native-user-management/HEAD2f48ff835d9e692fc84b31aaa951aad2495888ac and dirty work preserved. Preparation manifest290b3fa4baefb4e58d07b8dd51f41327e98c1ff60e4464d34d8ac07017e58703/all15 artifacts and accepted083 execution manifestabc9923c5e4a030d687b0dac901635c14c8605e2881f9cdb60caabfecc545c49/all14 artifacts verified by hash/owned private modes. Earlier failed helper/source/error and diagnosis intact. A separate independent pre/post harness was derived offline from accepted083 execution code, with explicit accepted083 catalogs, sbom_source privileges/lock/delta and all four earlier UUID-object comparisons; no failed candidate-reporting helper execution.

Fresh exact local Desktop Unix socket/daemon1f8c7fe5-5972-4adc-8d6e-363a38572be1/29.8.2/Compose5.6.0, D containerfb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e/imagesha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54/original exclusive sbom-uuid-w1_d_pgdata/sole d_access network6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65/actual127.0.0.1:56041 and existing private credential metadata matched. ComposeSHA25613e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab unchanged. No remote Docker or lifecycle action.

Immediate independent read-only preflight verified actual PG16.15/D database/current+session bootstrap/OID16384/systemID7697252084555804711/PGDATA/internal address, sole083, both proper-format catalogs/full accepted equality and four-table UUID/shared-guard prefix. Source/component unexpanded,71 business tables empty, integer graph/indexes/sequences/security/role16389/memberships/ACL/extensions/plpgsql sole approved owner exception/B drift unchanged. Eight sbom_source/shared-guard privileges PASS, zero other D clients/target-version locks; advisory7160085085 transaction-lock availability checked and released. Source hashes/expiry and actual Docker identity rechecked by runner inside execution. No ambient PG/dotenv/application configuration fallback or A/B access.

Actual invocation prefix:

```text
env -i HOME=/Users/ferozebasha PATH=/usr/bin:/bin LC_ALL=C \
/Users/ferozebasha/sbom/.venv/bin/python -B \
/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py
```

`P` below denotes the exact private execution directory above, expanded to absolute paths in actual arguments:

```text
--mode validate --next-revision 084_uuid_sbom_source_expand
--plan P/operator-approved-plan.json
--approval-id W16H-084-VALIDATE-20261017
--evidence P/runner-validation.private.jsonl

--mode execute --next-revision 084_uuid_sbom_source_expand
--plan P/operator-approved-plan.json
--approval-id W16H-084-EXECUTE-20261017
--evidence P/runner-execution.private.jsonl
```

| Event / check | Actual result / UTC evidence |
| --- | --- |
| Connected validation | Exit0; start14:43:40.588040, connected_validation_only_closed14:43:42.224604 |
| Independent immediate pre-execution checks | Separate bounded read-only repeatable-read connection; exact083/identity/source/expiry/full catalog/security/data/privileges/writer-lock gates PASS; physically closed before migration |
| One084 execute invocation | Exit0; start14:44:00.801950, existing next-only runner/fresh process; no other revision attempt |
| Owned transaction/locks | Reviewed advisory7160085085, ONLY version table EXCLUSIVE NOWAIT, ONLY sbom_source ACCESS EXCLUSIVE NOWAIT. Exactly selected084 upgrade and conditional083→084 marker change in same PostgreSQL transactional DDL unit |
| Precommit checks |14:44:02.512590: semantic084 prefix and narrow source-only delta passed |
| COMMIT acknowledgement |14:44:02.514272. Physical write connection closed through NullPool before new read-only runner read-back |
| Runner independent read-back | committed_verified_closed14:44:02.955886; exact084/prefix/delta PASS, new read-only connection closed before exit0 |
| Additional independent acceptance | Separate bounded read-only actual084/full31-category/old-row invariance/role-extension/71empty-table and old UUID-object checks PASS |
| Resource/process preservation | Before14:43:12.188467 / after14:44:18.881894: filtered Docker/container/image/start/state/mount/port/network/volume/current process/listener/runtime/env/password snapshots identical except time; sorted identifier sets unchanged |

Six D-only connections total: validation, independent preflight, migration write, runner read-back, broader independent post-success and a final metadata-only database-ownership check. Zero A/B. No SQL/lock failure, unknown COMMIT, retry/reconnect, cleanup, downgrade or schema recovery. Successful lock acquisition establishes this one unit's window, not future exclusivity.

### Independently verified committed schema and preservation

| Invariant | Actual post084 result |
| --- | --- |
| Marker | Exactly one084_uuid_sbom_source_expand; before exactly one083_uuid_logical_sbom_expand |
| Column/default | Only public.sbom_source.public_id added, attribute55/nativeuuid/nullable/defaultgen_random_uuid(). Reviewed no-default ADD COLUMN followed by separate SET DEFAULT; no NOT NULL or old-row rewrite/backfill |
| CHECK | Only ck_sbom_source_public_id_v4; exact NULL-allowing version4/variant regex, NOT VALID/convalidated=false; no CHECK validation |
| Triggers | Only trg_sbom_source_public_id_insert and trg_sbom_source_public_id_immutable added, enabled/O, exact BEFORE INSERT allocator and conditional AFTER UPDATE WHEN OLD.public_id IS DISTINCT FROM NEW.public_id definitions |
| Shared guard / earlier expansions | All functions/ownership/ACL/security/search_path unchanged; guard bodySHAff93761fa4dd31fa6dff7c25f3aedf41bc960e181a234d390f540e359d2e8d58. Exact tenants/projects/products/logical_sbom UUID columns/checks/triggers unchanged |
| Remaining scope | sbom_component still unexpanded; no085 objects ahead of marker |
| Catalog/integer graph | Every old captured catalog row retained. Only columns/constraints/triggers/dependencies categories changed. Original integer PK/FK/association/index/sequence definitions unchanged;72tables/1148base columns/512indexes/60sequences/143FKs |
| Data/security |71empty business tables; database properties/ownership/captured roles/restricted16389/memberships/ACL/security/extensions and approved sole plpgsql owner exception unchanged. Missing VEX FK/actual B drift preserved. No UUID unique index/backfill/business-row DML/fixture |
| Database ownership | Additional read-only check14:47:23.355679–14:47:23.820816UTC: D databaseOID16384 ownerOID10/uuid_w1_d_bootstrap, datacl NULL, allowconn true/not template, matching accepted bootstrap/database-creation configuration. Sole084 and runner fingerprint reverified, zero other clients. Direct historical datdba was not separately captured by the13/31-category formats, so this is an observed expected-owner check, not a fabricated paired historical SQL comparison |
| Infrastructure/runtime | Same D cluster/storage/container/image/network/credentials and SBOM PostgreSQL/Redis/Mailpit/application network; current process baseline unchanged. Historical five service PIDs absent/stale runtime/no18000or13000listeners retained, not claimed running. No lifecycle or A/B data-equivalence claim |

**Post084 runner13-category SHA256:** `7897aaa96923950c3efc4225455200f1122a48ddbbb84aa4c81dfd75f875e5b8`.

**Post084 independent31-category SHA256:** `8c310ba21c5f3fcf3c5335d6b818dd44f7d0e60601f1292fbea7fd6cd69d5252`.

Keep these formats separate for future085 review; fingerprints do not themselves grant next-step authority.

### Evidence, executed checks, limits and next gate

Initial execution evidence set:15files0600 under0700 UID501 directory. Initial manifest references14/SHA256 **80c318f23208e475157d784d2c51c2917f48559132d3962c781f5d4606d030fb**; acceptanceSHA256 **851f43be6e6c4d829687f8f7caf4ecc817ce20b453a2e9eba1253562e408367b**. Actual approval/manifest/source-integrity/independent metadata and catalog harnesses/flushed validation+execution events/pre-post catalogs/acceptance/preservation retained privately. Original preparation/error files and expiry unchanged; no credentials/full URLs/process environments/business records in evidence/report. New private directory entry is separated from password/storage identity comparisons.

Actual continuation checks:21existing offline tests PASS again, source-only offline graph/pin mode PASS, connected validation/fresh preflight/real084 SQL+PG16 deparser/owned DDL+atomic marker commit/physical close/new read-back/full independent acceptance and preservation PASS. Preparation compilation/graph/lint-format results retained against unchanged pins; six historical I001 warnings untouched, not claimed all-lint-clean. Separate independent harness syntax/source checked before access; no new helper failure. C-B02–C-B05/future stages remain separately open, no new execution-critical gate failure.

**NOT RUN:** UUID allocator/explicit-NULL INSERT/CHECK rejection/immutability DML tests, synthetic business rows, concurrent writers/BEFORE-trigger interference/lock contention, failed-rollback/lost-COMMIT recovery, runtime writer integration, performance/application tests. Successful catalog/commit acceptance does not prove those behaviors. Expanded columns remain nullable/nonunique with CHECKs NOT VALID; no public issuance/API/production cutover accepted. UUID-preserving rollback and ordinary-bridge outbound-access risk remain open.

**Decision: W1.6H IMPLEMENTED / ACCEPTED for084 on disposable D only. No remaining mandatory084 execution-acceptance blocker observed. GO to request separate085 authorization with fresh committed084-prefix review and a new independently approved candidate.** No automatic085/index/backfill/deployment. Exact repository changes: append report23 and update tracker only; sources/runners/application/runtime/Compose/credentials/Git history preserved.

Final ownership/evidence reconciliation: final additional D-only read-only session passed expected ownerOID10/bootstrap, NULL database ACL, sole084/same runner fingerprint/no competing clients and closed14:47:23.820816UTC; no migration or mutation. Final protected evidence set18files0600 in0700 directory, final manifest17entries SHA256 **6354f04a9a848f25ef42eac17375dad265a365ddf1d1481c14e0680d08912601**, final acceptanceSHA256 **40af3ab3c16e120f8cf676de9a0a968b9524dab28ff3521ee6f479279a259cf9**. Original initial manifest/acceptance files retained unchanged and referenced by final manifest; actual total six D-only connections/zero A/B. No extra migration invocation or automatic retry.

W1.6H approved-continuation final documentation verification PASS:2,099 other existing repository file contents/tracked binary diff/file set unchanged;41 historical task-ledger rows/12 Phase1 issue rows retained verbatim; entire earlier report23 retained as unchanged prefix. Branch/HEAD,68 local links/line locations/whitespace/git diff --check, final0700/0600 manifest hashes/modes, exact original candidate/six approved plan-field differences/084 action refs and real start/precommit/commit_acknowledged/committed_verified_closed sequence verified. Earlier helper exit2/source/error/offline diagnosis hashes unchanged, not rerun. Only existing report23/tracker updated. One084 transaction acknowledged/closed/independently accepted, six authorized D-only connections including expected-owner supplement/zero A/B; no further DB access for documentation. No085/index/backfill/business-row test or automatic next action.
