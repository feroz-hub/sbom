# W1.6G — Logical SBOM083 UUID expansion preparation

2026-10-17, Asia/Kolkata. **BLOCKED AT MANIFEST REVIEW — preparation checks PASS;083 NOT EXECUTED / NOT ACCEPTED.** Actual sole D marker remains `082_uuid_products_expand`. This is the expected independent operator-approval gate, not a migration failure. One bounded authenticated D-only read-only preflight session completed and physically closed; no connected expand_validate/expand_execute, DDL/DML, business-row fixture, index/backfill, A/B/production access or Docker/application lifecycle action.

## Scope, Git baseline and accepted082 evidence

Read the master tracker, full [accepted082 report21](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/21-w16f-products-uuid-expand.md:168), [W1.6A.1 report10](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/10-w1-expand-transaction-refactor.md:1), [W1.6C report12](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/12-w1-isolated-expand-runner.md:1), actual083 and current runner/common source. Authority, prerequisites, blockers, stop conditions and acceptance criteria recorded IN PROGRESS in tracker before offline tests or database access. Scope is preparation/read-only verification only; the four review attestations and083 action references remain reserved for independent operator review.

Branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`; task-start2099-file content snapshot and tracked binary diff retained privately. Active source graph still has79 revisions/sole head079. Committed database082 is a separately verified applied prefix; no staged file was registered in active Alembic versions. Existing dirty work and Git history preserved; no branch switch/pull/reset/stash/commit/push or remote synchronization claim.

Protected accepted082 execution directory `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16f-execute-20261017T134712005067Z`: manifestSHA256 `c36989aa5effd126a26cf2a26e70df6e0a4711c57a301b47dcef5d64ea7e8b25` and all15 referenced hashes/owned0600 modes verified. AcceptanceSHA256 `90ef26c81fd9e0ae00f51d99c2800ad1a63be09f9c76bb8a9ef12bab70b04dfb`; status ACCEPTED, exactly one081→082 invocation/no retry, acknowledged commit13:49:06.305955UTC, physical-close/fresh-readback event13:49:06.768599UTC, independent full acceptance and zero preservation differences internally consistent. Actual saved post-success revision and both catalog digests match the supplied082 baseline.

Earlier W1.6F preparation manifestSHA256 `bdf02d08b1a14055d1de4ac48ba465442ef081c4665a80c774db2b9450fccb21` and all14 artifacts also verified: wrong historical BASE reference/failure/original source and correction remain intact. This task uses accepted082 post-success catalogs, not079/080/081. No failed runtime assertion, baseline substitution, candidate renewal or retry occurred during W1.6G.

## Revision083 source and isolated-runner review

| Check | Verified source/evidence and result |
| --- | --- |
| Original083 pin | [Report10:149](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/10-w1-expand-transaction-refactor.md:149) resolves **d7f8dbe4c262f4a045572c173b7fd61e38d003fa87f9ec28093427161234495e**; actual bytes match. Expected value extracted from that original row, not invented |
| Declaration/scope | [083:15](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/083_uuid_logical_sbom_expand.py:15) directly depends on082_uuid_products_expand; sole target public.logical_sbom. branch_labels/depends_on None |
| Column/default | [Upgrade:192](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/083_uuid_logical_sbom_expand.py:192): one nullable native PostgreSQL UUID public_id added without a column/default/server_default; separate ALTER SET DEFAULT pg_catalog.gen_random_uuid() for future INSERTs. No legacy-row UPDATE/rewrite/backfill |
| CHECK/identity | Exact NULL-allowing canonical v4/version+variant CHECK NOT VALID, BEFORE INSERT allocator, conditional AFTER UPDATE WHEN OLD.public_id IS DISTINCT FROM NEW.public_id immutability trigger. Final NEW after other BEFORE UPDATE triggers controls predicate; no UPDATE OF shortcut. This remains source reasoning, not083 runtime/behavior evidence |
| Shared guard | Catalog preflight verifies exact sole signature/body/properties/SECURITY INVOKER/search_path=pg_catalog/EXECUTE access. Embedded expected body is a comparison only;083 contains no CREATE/REPLACE FUNCTION. Existing shared guard is reused unchanged |
| Integer/recovery safety | Requires ordinary permanent noninherited table/existing single int4 id PK, no colliding column/check/triggers or unreviewed INSERT triggers/write rules. No integer PK/FK/association/sequence/business-field change. Downgrade raises before operations; no adoption/drop/CASCADE/UUID mapping removal |
| Excluded stages | No unique public UUID indexes, backfill, NOT NULL, CHECK validation, business-row modification or application change |
| Runner pin | expand_one_step.py **57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b**, unchanged |
| Common pin | uuid_w1_common.py **4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94**, unchanged |
| Graph/replay exclusion | [discover:63](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:63) AST-verifies active079 ancestry, pins exactly six staged sources and isolated synthetic079 boundary. [next_only:123](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:123) accepts082→083 only, rejecting replay/head/ranges/skips. Archived monolithic080 .py.txt and earlier application migrations are not eligible. Normal env/settings/database engine/launcher not imported |
| Future transaction contract | After separate approval only: existing isolated runner owns one PostgreSQL DDL+conditional082→083 marker transaction; advisory7160085085, versionEXCLUSIVE NOWAIT and ONLY logical_sbom ACCESS EXCLUSIVE NOWAIT; commit acknowledgement/physical close/new independent read-only checks. No such table locks or transaction were executed here. Lock1s/statement10s caps are not a hard total COMMIT/network deadline |

Known findings remain separately tracked:

- C-B02 common Evidence constructor cleanup defect is not reused; expand has its own close-on-initial-emit-failure implementation.
- C-B03 index autocommit/reset error masking is outside the expand path.
- C-B04 expand uses its own exact-type manifest parser; fixed085 common.load_plan is not called.
- C-B05 backfill budget controller is not used; expand still lacks a hard end-to-end acknowledgement deadline.
- C-B06 strict PG16 CHECK/trigger/catalog rendering worked for accepted080–082;083's actual DDL/deparser/delta remains unexecuted. The actual committed082 prefix passed the unchanged strict verifier. No automatic comparison relaxation is permitted.

No new execution-critical pinned-source defect demonstrated. These dispositions do not fix W1.6B or certify later-stage/recovery behavior. Cooperative locks and catalog checks do not prevent hostile privileged concurrent DDL; fresh exclusive-window/role/writer review remains mandatory.

## Offline checks actually executed

Clean subprocess environment: HOME=/Users/ferozebasha, PATH=/usr/bin:/bin, LC_ALL=C; existing `.venv/bin/python -B`, no application startup or dotenv configuration. Full command/stdout/stderr/exit records are private.

| Command/check | Actual result / limit |
| --- | --- |
| test_expand_one_step.py | **21 tests PASS**, including hash/graph/next-only/refusal, partial-chain/prefix/source tests and mocked commit-close-readback/SQL failure/unknown-commit paths |
| expand_one_step.py --mode offline | PASS source/evidence pins/active+isolated graph; no runtime target action |
| verify_offline.py | PASS79active+6staged/combined085,42SQL templates/14literal/18dynamic query compilations and6index-DDL compilations. No index execution; compilation is not PostgreSQL grammar verification |
|083 Python syntax/compilation/AST assertions | PASS report-derived pin/immediate082 predecessor/logical_sbom-only target/nullable native UUID/separate default/NOT VALID CHECK/guard reuse/two triggers/one-table lock/no index-backfill-business writes-validation-NOT NULL/raise-only downgrade |
| Runner repository Ruff check --no-cache | PASS6files |
| Migration Ruff check --no-cache --isolated | PASS6files, original reviewed lint scope |
| Migration repository Ruff check --no-cache | FAIL only six historical I001 import-order warnings in unchanged080–085. No silent fix or repin; not an execution-critical SQL failure |
| Ruff format --no-cache --check | PASS12files. Existing Ruff0.15.10 module used; no dependency installation |
| New private harness syntax/source | PASS; only selected inert reviewed catalog/role/source helper definitions extracted via AST; no historical main/connect/write code executed. Candidate parser refuses pending flags/empty approvals in a pure offline call |
|083 PostgreSQL SQL/DDL/transaction/catalog delta; behavior/concurrency/recovery/performance/application tests | **NOT RUN / NOT ACCEPTED**. Mock commits and compilation do not prove these |

The 21-suite/offline mode/verifier were initially run directly and repeated into protected evidence capture; no changed source between runs. Initial local executable lookup found no .venv/bin/ruff wrapper; the installed .venv Python module was verified and used successfully. This was not a source/runtime gate failure or dependency change.

## Fresh bounded D-only read-only preflight

Host before `2026-10-17T14:03:19.863847+00:00`; after `2026-10-17T14:05:03.854561+00:00`. PostgreSQL identity gate14:04:56.233723UTC; physical close14:04:56.598285UTC. Exactly one D connection; zero reconnects/retries and zero A/B/production connections.

| Gate | Actual safe evidence / result |
| --- | --- |
| Local Docker | Explicit `/Users/ferozebasha/.docker/run/docker.sock`, UID501 Unix socket; Desktop daemon1f8c7fe5-5972-4adc-8d6e-363a38572be1/29.8.2, Compose5.6.0. Explicit Desktop CLI pinned hash31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f. No remote contact |
| D container/image | Exactfb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e; imagesha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54, running/healthy/restarts/start/mount/project/service state unchanged |
| Storage/network/publication | Original sbom-uuid-w1_d_pgdata local volume/creation2026-10-16T13:09:16Z/exclusive mount /var/lib/postgresql/data unchanged. Sole sbom-uuid-w1_d_access ID6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65; no app-network attachment. Actual publication/listener127.0.0.1:56041 only; old private network retained unused |
| Credentials/config | Existing dedicated disposable password only: UID501/inode75679830/65bytes/0600/regular/non-symlink/single-link under0700 parent. Explicit common.connect D kwargs, no PG overrides/connection URL/dotenv/app fallback. No rotation/copy/disclosure. ComposeSHA25613e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab unchanged; .env/.env.dev.local metadata unchanged, contents not inspected |
| PG identity/read-only | Actual uuid_w1_d_rehearsal/current+session user uuid_w1_d_bootstrap/OID16384; server160015/16.15, cluster7697252084555804711, PGDATA /var/lib/postgresql/data/pgdata. BEGIN REPEATABLE READ READ ONLY verified transaction_read_only on; bounded connect5s/statement10s/lock1s/idle15s; ended ROLLBACK then physical close |
| Endpoint format | Host127.0.0.1:56041 distinct from internal172.20.0.2:5432; runner raw inet text172.20.0.2/32 correctly pinned |
| Marker/prefix | Exactly one082 marker. Exact tenants/projects/products native nullable UUID/default/NOT VALID v4 CHECK/two enabled triggers each/shared guard body/signature/security/search_path/ACL unchanged. logical_sbom/sbom_source/sbom_component unexpanded; no unexpected user rules/event triggers/RLS |
| Runner13-category fingerprint | **75336075175c623666778eb5d5249856e83372d210ff4c5657eeaa9f4fbd1169**, freshly computed, equals accepted082 runner snapshot/hash only |
| Independent31-category fingerprint | **b2f72585938ec875b40b28b40cfe3c0e1e342b0b394a51581f15722738d74d48**, freshly computed; exact whole accepted082 catalog equality. Never compared against another format or older revision |
| Structure/data/drift |72tables/1146base columns/512indexes/60sequences/143FKs unchanged; integer PK/FK/association/index/sequence definitions retained.71business tables empty by bounded EXISTS, no records exported/sequence positions read or advanced. Missing VEX superseded_by_id FK and actual B drift remain unchanged; no repair |
| Roles/extensions | Restricted source-ownerOID16389/protected name/NOLOGIN/no password/no memberships/approved restrictions unchanged; all captured role/member/ACL/security state matches. plpgsql version/schema/language/functionality/security/privileges compatible and unchanged; prior approved extension-owner difference only |
| Privileges/writers/locks | Eight logical_sbom/shared-guard schema/language/allocator/SELECT/TRIGGER/owner-role/EXECUTE checks PASS; zero other D client sessions, zero other logical_sbom/version-table locks. Transaction-scoped advisory7160085085 availability verified and released by ROLLBACK. Actual future EXCLUSIVE/ACCESS EXCLUSIVE locks not acquired here; proposed window is observation, not a guarantee or approval |
| Process/resource preservation | Exact current082 accepted host baseline and fresh before/after filtered Docker/storage/network/port/listener/process/runtime/env/password metadata match, excluding observation time; identifier sets sorted. Listener comparisons across baselines use pid/command/endpoint independent of FD enumeration. Earlier rapportd listener change remains historical; no new current mismatch. Recorded historical service PIDs still absent, runtime state stale/no18000or13000listeners; current repository tool/runtime process identities unchanged, not claimed as running SBOM services |

The private evidence directory entry changes its parent's metadata as expected. Password identity/permissions and resource snapshots are compared independently; no false parent-directory drift or ordering normalization hides a real difference. A/B database contents were not queried or certified unchanged.

## Exact fresh083 candidate for independent operator review

Private candidate: `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16g-20261017T140158476084Z/083-approval-candidate.json`, exclusive0600 under0700 UID501 directory. **Byte SHA256: `0745d2c8514f492747c2ce312570e634e9b8c111aaa15d43563dc582973a8b28`.**

Expires **2026-10-18T14:04:56.598347UTC /2026-10-18 19:34:56.598347IST**. This is the first083 candidate, not a renewed082 plan. Four flags false/approvals empty intentionally. accepted=true denotes the already accepted D082 baseline, not083 authority. Fresh measurements pin the same preserved D resources; previous080–082 executable plans/action references were not reused.

source_sha256/independent_schema_sha256/review_observations provide review context in the existing runner contract. They do not replace pinned discover/prefix checks, independent full-catalog verification or operator attestations. No password value/hash is present. Exact full nonsecret JSON:

```json
{
  "accepted": true,
  "approvals": {},
  "baseline_reviewed": false,
  "container_id": "fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e",
  "container_sha256": "66f75be7578c216acbe83b5b24d49f4daeebc6216bf3a44815b62a6e01bab848",
  "current_revision": "082_uuid_products_expand",
  "daemon_id": "1f8c7fe5-5972-4adc-8d6e-363a38572be1",
  "database": "uuid_w1_d_rehearsal",
  "database_oid": 16384,
  "disposable": true,
  "disposable_secret_provenance_reviewed": false,
  "docker_binary": "/Applications/Docker.app/Contents/Resources/bin/docker",
  "docker_binary_sha256": "31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f",
  "docker_socket": "/Users/ferozebasha/.docker/run/docker.sock",
  "exclusive_ddl_window_reviewed": false,
  "expires_utc": "2026-10-18T14:04:56.598347+00:00",
  "host": "127.0.0.1",
  "independent_schema_sha256": "b2f72585938ec875b40b28b40cfe3c0e1e342b0b394a51581f15722738d74d48",
  "network_ids": {
    "sbom-uuid-w1_d_access": "6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65"
  },
  "next_revision": "083_uuid_logical_sbom_expand",
  "old_monolith_excluded": true,
  "password_file": "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/postgres-password",
  "port": 56041,
  "postmaster_started_at": "2026-10-16 15:41:09.226049+00",
  "prefix_review_reference": "W1.6F accepted082; fresh W1.6G083 candidate pending independent operator review",
  "review_observations": {
    "advisory_transaction_lock_available": true,
    "business_indexes": 512,
    "committed_prefix": "accepted082 tenants/projects/products and shared guard unchanged; logical_sbom/sbom_source/sbom_component unexpanded",
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
    "evidence_reference": "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16g-20261017T140158476084Z/database-preflight.private.json",
    "exclusive_ddl_window": "proposed one083 transaction only; fresh writer and lock checks required after operator approval",
    "foreign_keys": 143,
    "logical_sbom_version_table_other_locks": 0,
    "maintenance_privilege_checks_passed": 8,
    "observed_utc": "2026-10-17T14:04:56.598374+00:00",
    "other_D_client_sessions": 0,
    "plpgsql_state": "functional/security/ACL unchanged; existing approved owner exception only",
    "postgresql_version": "16.15",
    "restricted_owner_role_oid": 16389,
    "restricted_role_state": "accepted restrictions unchanged; NOLOGIN/no password/no memberships",
    "sequences": 60,
    "source_provenance": "report10-derived083 pin; immediate082 successor; existing shared guard reused; archived monolith excluded",
    "volume_created": "2026-10-16T13:09:16Z",
    "volume_name": "sbom-uuid-w1_d_pgdata"
  },
  "schema_sha256": "75336075175c623666778eb5d5249856e83372d210ff4c5657eeaa9f4fbd1169",
  "server_address": "172.20.0.2/32",
  "source_sha256": {
    "083_uuid_logical_sbom_expand.py": "d7f8dbe4c262f4a045572c173b7fd61e38d003fa87f9ec28093427161234495e",
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

## Expected gate, evidence and next action

**BLOCKED AT MANIFEST REVIEW.** All authorized preparation gates passed;083 was not attempted, so there is no083 SQL error, rollback/unknown COMMIT or migration failure. No connected expand_validate or expand_execute was called; only the pure manifest parser was tested for refusal.

Independent operator inputs required: approve the exact candidate byte SHA256/content/unchanged expiry,082→083 transition/target, both matching082 fingerprints and083/common/runner source pins; explicitly approve each of baseline_reviewed, writers_and_privileges_reviewed, exclusive_ddl_window_reviewed and disposable_secret_provenance_reviewed; supply distinct new083-specific expand_validate and expand_execute approval references and prefix-review approval. Do not reuse080–082 references or infer any attestation. If expired or changed, STOP for review; no silent renewal.

After that separate approval only: new protected approved manifest changing approved fields only while preserving original candidate/expiry; existing connected read-only validation with matching083 reference; immediate fresh exact identity/source/082 catalogs/security/data/privilege/writer/expiry/lock-window checks; then exactly one existing-runner082→083 transaction if authorized/all gates pass. Require acknowledged commit/physical close and independent logical_sbom-only delta plus unchanged tenants/projects/products/shared guard/integer graph/security/data/resources. No084–085/index/backfill authority follows.

Protected directory `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16g-20261017T140158476084Z`:14files0600 in0700 UID501 parent, manifest references13files/SHA256 **2aab4d38236804f0916c2168b23e00bad8052ef63fce58a4af7c3047df4f6cd2**. Original source/offline/historical acceptance checks, private read-only harness, flushed check labels, fresh catalogs, candidate, outcome and before-after preservation retained. No credentials/connection strings/process environments/business records stored or printed; sensitive role/catalog definitions stay private.

Repository files: new report22 and updated master tracker only. Hash-pinned migrations/runners, prior reports including full W1.6F history, application/runtime/Compose/env/credentials and Git history preserved. Behavior/INSERT allocator/invalid UUID/CHECK/immutability, concurrent writers/BEFORE-trigger ordering/lock contention/failed rollback/lost COMMIT recovery, writer integration, performance and application tests remain unexecuted. Columns remain nullable/nonunique and CHECKs NOT VALID; no public UUID issuance or API cutover is accepted. C-B02–C-B05/future-stage concerns, mapping-preserving rollback and ordinary-bridge outbound-access risk remain open.

**Exact next action: independent operator review of this083 candidate and explicit four attestations plus distinct083 validation/execution references. No083 execution before that approval; no automatic084.**

Final documentation verification PASS:2,098 other existing repository file contents/tracked binary diff preserved; exact repository delta new report22 and tracker only.38 prior task-ledger rows/12 Phase1 issue rows retained verbatim. Branch/HEAD,63 local evidence links/line locations/whitespace/git diff --check, private0700/0600 artifact hashes/modes, exact candidate/report parsed-JSON equality and four false flags/empty approvals verified.21offline tests passed; six historical I001 warnings retained. One D-only read-only preflight/no migration/connected CLI validation; no further database session for documentation.082 remains accepted;083 BLOCKED AT MANIFEST REVIEW, NOT EXECUTED.

## Operator-approved continuation —083 IMPLEMENTED / ACCEPTED

Actual execution2026-10-17. **Exactly one082→083 transaction committed on disposable D and independent acceptance passed.** This appended result supersedes the earlier preparation-only current disposition; the original BLOCKED manifest-review record, candidate and historical harness-error evidence remain preserved. Active application source graph still ends079; no staged source registration or historical replay occurred. No084/085 execution followed.

### Authority and exact approved manifest

Authority: human “W1.6G Operator Approval and Revision083 Execution” instruction supplies exact candidate0745d2c8514f492747c2ce312570e634e9b8c111aaa15d43563dc582973a8b28,082→083/logical_sbom target, both accepted082 fingerprints, three source pins/four true attestations and distinct `W16G-083-VALIDATE-20261017` / `W16G-083-EXECUTE-20261017`. References originate from that operator message; no prior080–082 action approval reused or extra approval invented.

Original private candidate byte hash/full content/report JSON/target/source/fingerprint/expiry verified. Original candidate and expiry `2026-10-18T14:04:56.598347+00:00` preserved unchanged and unexpired through execution. New approved plan:

`/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w16g-execute-20261017T142105585732Z/operator-approved-plan.json`

Byte SHA256 **3c4563c5c8ca5f4a3a6d6cf8d39ecfe3e1049c656e408d38ddcab655f09e5a91**; runner compact-JSON digest **61d00e4432e40a1b3dc93916b449e77d69df2fec70a032f34f932e832c3ea41e**. Different serializations explain those distinct digests. Only six top-level fields changed: four approved attestations, the exact two action approvals, and operator prefix-review reference. All original identities, source pins, target, fingerprints, expiry and review observations preserved. New file0600/directory0700/UID501, no overwrite of original candidate.

| Source / accepted starting state | Verified SHA256 |
| --- | --- |
|083 source, immediate082 successor |d7f8dbe4c262f4a045572c173b7fd61e38d003fa87f9ec28093427161234495e |
| expand_one_step.py |57a4b222841a0a6a3f302a25356e20249bb0d07eaecf81d0bec00b596ecb043b |
| uuid_w1_common.py |4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94 |
|082 runner13-category catalog |75336075175c623666778eb5d5249856e83372d210ff4c5657eeaa9f4fbd1169 |
|082 independent31-category catalog |b2f72585938ec875b40b28b40cfe3c0e1e342b0b394a51581f15722738d74d48 |

[Exact083 upgrade](/Users/ferozebasha/sbom/infra/uuid-migration/staged-alembic/083_uuid_logical_sbom_expand.py:192) and [isolated runner lifecycle](/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py:449) used unchanged. Protected W1.6G preparation manifest2aab4d38236804f0916c2168b23e00bad8052ef63fce58a4af7c3047df4f6cd2/all13 artifacts and accepted082 execution manifest/all15 artifacts hash/mode verified. Earlier wrong-baseline harness failure/correction retained, no new harness failure or migration retry. New private independent harness uses the hash-verified accepted082 post-success baseline, logical_sbom privileges/lock/delta and explicit existing tenants/projects/products comparisons; prior JSON row-type restoration retained. No pinned source/expectation relaxation.

### Validation, fresh gates and real transaction

Branch feat/native-user-management/HEAD2f48ff835d9e692fc84b31aaa951aad2495888ac and dirty work preserved. Active79-revision/sole079 source graph, six-stage chain/old-monolith exclusion/expiry/source checks passed. Same explicit local Desktop Unix socket/daemon1f8c7fe5-5972-4adc-8d6e-363a38572be1/29.8.2/Compose5.6.0, D containerfb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e/imagesha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54/original exclusive d_pgdata/access network6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65/actual127.0.0.1:56041/credential metadata match. Compose hash13e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab unchanged.

Independent immediate read-only preflight verified actual D uuid_w1_d_rehearsal/current+session bootstrap/OID16384/16.15/systemID7697252084555804711/PGDATA/internal172.20.0.2:5432, sole082, both accepted catalog formats/full equality and exact tenant/project/product UUID prefix/shared guard/three future tables unexpanded. Roles16389/restrictions/memberships/ACL/security/extensions and prior sole plpgsql owner exception unchanged;71business tables empty, integer graph/indexes/sequences/B drift retained. Eight logical_sbom/shared-guard privileges PASS, zero other D clients/target-version locks; advisory7160085085 transaction-lock availability checked/released. Manifest/source/expiry/actual Docker verified again by runner inside the migration unit. No A/B access, application imports or ambient PG/dotenv credential fallback.

Actual clean invocation prefix:

```text
env -i HOME=/Users/ferozebasha PATH=/usr/bin:/bin LC_ALL=C \
/Users/ferozebasha/sbom/.venv/bin/python -B \
/Users/ferozebasha/sbom/infra/uuid-migration/staged-runner/expand_one_step.py
```

Here `P` is the exact private execution directory above, expanded to absolute paths in the actual commands. Exact action arguments:

```text
--mode validate --next-revision 083_uuid_logical_sbom_expand
--plan P/operator-approved-plan.json
--approval-id W16G-083-VALIDATE-20261017
--evidence P/runner-validation.private.jsonl

--mode execute --next-revision 083_uuid_logical_sbom_expand
--plan P/operator-approved-plan.json
--approval-id W16G-083-EXECUTE-20261017
--evidence P/runner-execution.private.jsonl
```

| Actual event/check | Result / UTC evidence |
| --- | --- |
| Connected read-only validation | Exit0; start14:22:05.003696 / connected_validation_only_closed14:22:06.615656 |
| Immediate separate pre-execution session | PASS sole082/both catalog formats/full schema-security-data/privilege/writer/lock/identity/source/expiry; read-only repeatable-read connection closed before migration |
| Exactly one083 execute invocation | Exit0, existing next-only runner/fresh process; no historical migrations, head/range command or normal Alembic environment |
| Transaction | One owned PostgreSQL transactional DDL unit; reviewed advisory7160085085/versionEXCLUSIVE NOWAIT/ONLY logical_sbom ACCESS EXCLUSIVE NOWAIT, selected pinned083 upgrade and conditional082→083 marker update atomic in same transaction |
| Precommit | 2026-10-17T14:22:38.493521+00:00: expected083 semantic prefix/narrow logical_sbom-only delta passed |
| COMMIT acknowledgement |14:22:38.495005; physical write connection closed through NullPool before new independent read-back |
| Runner independent post-commit verification | committed_verified_closed14:22:38.951332; new read-only connection verifies sole083/semantic prefix/delta, closes before exit0 |
| Additional independent acceptance | Separate bounded read-only exact083 identity/full31-category/roles-extensions/71empty tables/old UUID objects/integer graph/index-sequence preservation PASS |
| Host/resource/process preservation | Before14:21:13.444970 / after14:23:05.586631: filtered container/image/start/state/mount/port/network/volume/current process/listener/runtime/env/password metadata equal except timestamp; sorted identifier sets unchanged |

Five D-only connections total: connected validation, independent preflight, runner migration write, runner read-back, additional independent post-success session. Zero A/B connections. No SQL error, unavailable lock, unknown COMMIT, migration retry, cleanup or downgrade. The observed no-writer window and actual successful locks support this execution only, not future exclusivity guarantees.

### Independently verified actual083 delta

| Object / invariant | Actual committed result |
| --- | --- |
| Version marker | Before exactly one082_uuid_products_expand; after exactly one083_uuid_logical_sbom_expand |
| Added column | Only public.logical_sbom.public_id, attribute9, nativeuuid, nullable, defaultgen_random_uuid(). Source ADD COLUMN had no default; reviewed separate SET DEFAULT applied. No NOT NULL |
| Added CHECK | Only ck_logical_sbom_public_id_v4; exact NULL-allowing canonical UUIDv4/version+variant regex, NOT VALID/convalidated=false. No CHECK validation |
| Added triggers | Only trg_logical_sbom_public_id_insert / trg_logical_sbom_public_id_immutable, enabled/O, exact BEFORE INSERT allocator and AFTER UPDATE WHEN OLD.public_id IS DISTINCT FROM NEW.public_id definitions |
| Shared function / earlier UUID objects | All functions/ownership/ACL/security/search_path unchanged; shared guard bodySHAff93761fa4dd31fa6dff7c25f3aedf41bc960e181a234d390f540e359d2e8d58. Exact tenants/projects/products UUID columns/checks/triggers unchanged |
| Remaining scope | sbom_source and sbom_component remain unexpanded; no084/085 objects ahead of marker |
| Whole catalog / integer graph | Every old captured catalog row retained. Only columns/constraints/triggers/dependencies categories changed. Original PK/FK/associations/indexes/sequences unchanged;72tables/1147base columns/512indexes/60sequences/143FKs |
| Data/security |71 business tables empty; restricted16389/all accepted roles/memberships/ACLs/security/plpgsql functional properties/approved sole owner exception unchanged. Missing VEX superseded_by_id FK/actual B drift preserved. No unique UUID index/backfill/business-row DML/fixture |
| Infrastructure/runtime | Original D storage/cluster/container/image/network/credential and existing SBOM PostgreSQL/Redis/Mailpit/application network unchanged. Current process baseline matches preparation and before/after operation; historical service PIDs remain absent/stale runtime/no18000or13000listeners, not claimed running. No lifecycle action or A/B data-equivalence claim |

New post083 runner13-category SHA256 **eb96c4740b2a70123d7e85e5a839f6f7ae7e253322fcc0428f863a0927620219**.

New post083 independent31-category SHA256 **4064d87ce1049cd43a250c44800c98cc674b0d2e2327be6828c2d175f6b33e9f**.

Future084 review must compare each hash only with its matching catalog format. Neither hash automatically approves the next migration.

### Evidence, limits and next action

Protected execution directory above:15files0600/0700 UID501 parent, manifest references14/SHA256 **abc9923c5e4a030d687b0dac901635c14c8605e2881f9cdb60caabfecc545c49**; acceptanceSHA256 **72339faa0981f6bfd72aec4f96b897f8ada090334271ce3d0b51f6d5a4b8c7b2**. Authority/approved plan/integrity/source-reviewed independent and metadata scripts/flushed validation+execution events/pre-post catalogs/acceptance/preservation retained privately. Original preparation/candidate/history remain intact. No passwords/full URLs/process environments/business records in report/evidence. Expected creation of a new evidence directory is separate from password/resource identity.

Actual continuation tests:21existing offline tests PASS again; source-only offline graph/pin mode PASS. Preparation's compilation/lint/format/graph evidence retained against unchanged pins; six historical I001 warnings untouched, not presented as new runtime findings or all-lint-clean status. Real083 SQL/PG16 deparser/happy-path DDL+atomic marker transaction/commit/close/independent catalog acceptance now PASS. Source C-B02–C-B05/future-stage findings remain open; no new execution-critical source gate failed.

**NOT RUN:** allocator/explicit-NULL INSERT/CHECK rejection/immutability DML behavior, synthetic records, concurrent writers/other BEFORE-trigger interference/lock contention, failed-rollback/lost-COMMIT recovery, runtime writer integration, performance or application tests. Catalog/commit acceptance does not certify those behaviors. Columns remain nullable/nonunique/checks NOT VALID; no public issuance/cutover acceptance. Mapping-preserving rollback and ordinary-bridge outbound-access risk remain open.

**Decision: W1.6G IMPLEMENTED / ACCEPTED for083 on D only. No remaining mandatory083 execution-acceptance blocker observed. GO to request separate084 authorization and a fresh committed083-prefix manifest/operator review.** No automatic084/085/index/backfill/API cutover/production. Exact repository edits: append report22 and update tracker only; pinned migrations/runners, application/runtime/Compose/credentials/Git history unchanged.

W1.6G approved-continuation final documentation verification PASS:2,098 other existing file contents/tracked binary diff/repository file set unchanged;39 prior task-ledger rows and12 Phase1 issue rows retained verbatim; entire earlier report22 preserved as unchanged prefix. Branch/HEAD,66 local links/line locations/whitespace/git diff --check, private0700/0600 manifest hashes/modes, untouched candidate/exact six approved plan-field differences/083 action refs and real start/precommit/commit_acknowledged/committed_verified_closed sequence verified. Only report22/tracker updated; no additional database access for documentation. One083 transaction committed/independently accepted; no084/085/index/backfill/business-row tests or automatic next execution.
