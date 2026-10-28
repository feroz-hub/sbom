# W2.4E — F read-only identity/freshness acceptance preparation

**W2.4E READ-ONLY ACCEPTANCE PREPARED — PENDING LIVE APPROVAL.** 2026-10-19. This stage implements and offline-verifies a dedicated entrypoint; it does not accept F's database identity, authentication or schema freshness. No PostgreSQL constructor, operator SQL, password-content read/correlation, Docker lifecycle operation or migration ran.

## Authority and preserved inputs

Branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`, all existing dirty work preserved. Before editing, 2,196 existing repository file contents were recorded. Reports27–34/tracker and actual source/catalog/transaction/budget contracts were read. Actual protected W2.4C package `6e7b633e17ea2ff63c137c8f6829222999bae45b5dca6309122476da1f8b14df` and all15 embedded sources/full diffs verified; actual W2.4D acceptance `b7fbc90503ffcfd812f6fbd58767ade79a926539b7d87add704b3a6a9b2923d5` verified. Their historical outcomes remain intact. W2.1–W2.4C sources, source locks, frozen047, staged080–091 and active Alembic head079 remain unchanged/unactivated.

## Actual fresh infrastructure observations

[Final nonsecret metadata evidence](/Users/ferozebasha/.sbom-uuid-w2-review/w24e-20261019T062728003301Z/preflight-final-summary.json), UTC `2026-10-19T06:50:49.724615+00:00`. Explicit local socket `/Users/ferozebasha/.docker/run/docker.sock`, Desktop daemon `1f8c7fe5-5972-4adc-8d6e-363a38572be1`. F container `964fe491cf9e12f6f9cf8125f5352e301d85f0fc1a0b05142cda6393c6d9152c`, image `sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54`, project/service `sbom-uuid-w2-f/postgres_f`, running/healthy, restart0, original start `2026-10-19T06:14:07.068935636Z` unchanged. Dedicated volume `sbom-uuid-w2-f_f_pgdata`; sole network `sbom-uuid-w2-f_f_access`, ID `5347909a2fb95db230d562557e5154cf623ccb613286eca309134da6e9122447`, FIP `172.22.0.2`. Only `127.0.0.1:56043:5432`, exact1CPU/512MiB/64MiBshm/128PIDs, restartno, nonprivileged and original command/labels/health configuration retained.

Sixcontainers/eightnetworks/28volumes match preparation baseline; original A/B/D/E/SBOM resource metadata preserved. All27 relevant recorded host process identities/start times retained, old listeners retained. Historical SBOM launcher/API/Celery/Beat/frontend PIDs remain absent/stale per prior records; no resurrection or running-service assertion. A/local PostgreSQL preservation is metadata only, not authentication. Docker inspections project selected fields server-side, excluding Config.Env and healthcheck log output.

F secret metadata only: exact `/Users/ferozebasha/.sbom-uuid-w2-f/postgres-password`, UID501/GID20, inode76156846, size64, nlink1, mode0600, parent0700, mtime/ctime ns1792390446662579505. Exactly one read-only bind to `/run/secrets/f_password`, original host source unchanged. No contents or secret digest obtained. Content equivalence and credential correctness remain unexecuted. Ordinary bridge NAT outbound risk previously accepted for infrastructure; loopback publication is not zero egress. Fresh read-only scope's network review remains pending.

Actual authenticated version, system identifier, database OID, owners/security, schema freshness, business-table state, catalog fingerprints and Alembic marker remain **UNKNOWN / NOT QUERIED**. Container health/image metadata do not establish them.

## New implementation and source pins

Ten new isolated artifacts under `infra/uuid-migration/f-readonly-acceptance/`; no existing execution source edited.

| File | SHA256 |
|---|---|
| README.md | `450085feb8df09d8a0c3883647b9de7ac4ff75b87e89c0cdfca730c0243a01b7` |
| acceptance-matrix.json | `7ed47f6c6f51c94bac09479b77b71a43e0d1b5500d2bebeeaac38a50222f0d73` |
| catalog.py | `f81d3986dea0c706b09cb937dbafde61ab0e2f72402bb106ef4f1869bd8b65c4` |
| dependency-lock.json | `fbb5fb0a30ee3a9ed23fb66a141cf2ab637b3fcb3ac647e49da0a0d4ed0bc53a` |
| entry.py | `67ba1d780f39d00d556214ac1604f2fb847f3196a6612c0165256eb0dba811ed` |
| probe.py | `1a20a5621aca121d995814a7e1178571559fcaf698e757912217935155151e88` |
| runtime.py | `6cec7123d910a98d3d750306cf30ad899de2686c62c4821e7931707508b3cb07` |
| security.py | `dcd3d6d61e3af49568c8b876c631073997b19d881b1a0c194807e364d1dc73ca` |
| sql-review.json | `7b4cbedb3edeb6b27bd6f936d642f364efffdf06c1a5274d45ba692be8e6cadf` |
| test_readonly_offline.py | `dcc07533ecf39b4317f868e2fe5a563c3404476cbf361d1865e7ad1970a58be8` |

`entry.py` provides useful offline validation and future approval-gated live CLI. `security.py` verifies protected original manifest bytes, duplicate-key rejection, UTCexpiry, exact sources/SQL/budgets/target, five reviews and distinct action before runtime imports, Docker or credentials. Every pre-authentication authority recheck reopens the same bytes; canonical serialization cannot substitute for operator-approved byte SHA256. Private path reader enforces nonsymlink path components, UID, regular single-link0600file/0700parent and descriptor metadata consistency.

`runtime.py` permits exact local metadata argv only, checks whole resource baseline and exclusive F storage/network/mount identity, installed source/native dependency pins and unchanged credential metadata. Future separately approved memory-only host/mount content correlation is bounded, no secret digest/arguments/environment/log/copy. No correlation now. Dependency lock includes installed Python/psycopg/binary/Docker paths/hashes; native library provenance limitations explicit.

`probe.py` owns exactly one fixed F constructor: host+hostaddr127.0.0.1/56043, databaseuuid_w2_f_fresh/useruuid_w2_f_bootstrap, passfile/dev/null, service keyword absent, no DSN/socket/PG*/dotenv/application fallback, SSL/GSSdisabled, connect5s, prepare_thresholdNone. Clean environment required. AUTOCOMMIT is confined to this dedicated read-only probe's literal BEGIN READ ONLY/ROLLBACK; it does not activate migration transport. Server startup options enforce default_read_onlyon/statement2s/lock250ms/idle5s/search_pathpg_catalog/row_securityon/check_function_bodieson/stats_fetch_consistencynone. First query verifies active transaction read-only; actual driver INTRANS status required.

`catalog.py`, [SQL review](/Users/ferozebasha/sbom/infra/uuid-migration/f-readonly-acceptance/sql-review.json) and [acceptance matrix](/Users/ferozebasha/sbom/infra/uuid-migration/f-readonly-acceptance/acceptance-matrix.json) enumerate all30 fixed SELECT templates. Exactly33 planned queries (30templates plus identity/client/lock rechecks), hard ceiling40; max1connection/attempt,2controls,1,024rows/query/8,192total. Cooperative monotonic60s window, connect5s, query2s, metadata8s and correlation5s individual timeouts. Cooperative budget is **not** a guaranteed hard wall-clock kill deadline. Cleanup may finish later; rollback reservation and physical closure survive deadline/evidence failure. Unexpected SQL/reflection/business-table queries/DDL/DML/SET/COMMIT/marker actions are excluded.

Coverage includes PostgreSQL16.15 identity/systemID/DBOID/interface/PGDATA/start, database encoding/collation/ownership, role booleans/memberships/privileges/SCRAM-storage boolean, schemas/relations/columns/functions/types/triggers/rules/extensions/foreign/replication/event/security-label/defaultACL/roleconfig/dependency observations and clients/locks/Alembic absence. Expected PostgreSQL initialization objects are allowed explicitly; unexpected application or seed objects fail closed. No business records or stored password value/hash are selected. Existing Alembic table refuses before any marker-row query.

Future acceptance requires `PGconn.used_password is True`; supplying a password alone is insufficient. It proves password use for that session, **not** exact wire SCRAM negotiation or the complete loaded HBA policy. HBA evidence is current file content/methods/boolean parse status only; storedSCRAM boolean is a storage property. Those limitations remain explicit, and any stronger mandatory requirement remains UNKNOWN/BLOCKED. Bootstrap actual privileges must be observed; a restricted runtime/application role is needed before application use, not created here.

Durable O_EXCL0600 single-attempt JSONL under0700parent, fsync/hash chain, exact manifest byte hash, actual constructor-call count separately from budget reservations, bounded sanitized primary diagnostics/SQLSTATE, ROLLBACK/physicalclose/resource disposition. Query/error/evidence/expiry/preservation failure refuses acceptance, no retry/fallback/repair. Private attempt claim does not yet exist. No historical helper/application/Alembic entrypoint is imported.

## Actual offline verification

| Suite | PASS | FAIL | SKIP |
|---|---:|---:|---:|
| f-readonly-acceptance / test_readonly_offline.py | 145 | 0 | 0 |
| f-transaction-correction / test_transaction_offline.py | 167 | 0 | 0 |
| f-budget-reconciliation / test_budget_offline.py | 99 | 0 | 0 |
| f-activation / test_activation_offline.py | 126 | 0 | 0 |
| fresh-coordinator / test_coordinator_offline.py | 71 | 0 | 0 |
| fresh-bootstrap / test_fresh_bootstrap.py | 102 | 0 | 0 |
| finalization-tests / test_finalization_offline.py | 53 | 0 | 0 |
| staged-runner / test_expand_one_step.py | 21 | 0 | 0 |
| staged-runner / test_uuid_integrity_offline.py | 53 | 0 | 0 |
| Total | 837 | 0 | 0 |

Each suite ran separately with `.venv/bin/python -B <test-file>`; exact commands and unmodified logs/hash are in the package. New145 tests cover source/raw manifest/symlink/expiry/hash substitution/last-moment revalidation, target/resources/metadata/secret correlation mocks, role/ACL/freshness policies, SQL whitelist/row/query/control/deadline budgets, password-use/HBA limitations, authentication/query/durable-evidence failures, rollback/close/resource preservation and no retries. Existing692 tests preserve prior live-mode denials and migration contracts. Synthetic credentials only; mock successes are not live authentication or PostgreSQL acceptance.

SixnewPython AST/in-memory compiles/import checks,30catalog SQLAlchemy template compiles, existing42SQL+14literal+18dynamic+6index compilation checks, exact source/native dependency pins, graph79active/91combined/45units, Rufflint/format for all6newPythonfiles, source whitespace and Gitdiff checks PASS. SQLAlchemy compilation is not PostgreSQL grammar/runtime acceptance. Historical six migration import-order warnings remain unchanged.

Development evidence retained: initial95PASS; expanded128run had33NameErrors for necessary new-test imports removed earlier by lint, corrected in newtest source and rerunPASS; later141/144/final145PASS. Initial Rufflayout/E731/E701 findings corrected only in newfiles. Exact projected Docker metadata argv initially refused before inspect because whitelist still described previous form; corrected to exact projection and fresh metadata passed. No broad allowance, live database retry or historical failure rewrite.

## Exact candidate and protected review package

Final candidate: [f-readonly-approval-candidate.v2.json](/Users/ferozebasha/.sbom-uuid-w2-review/w24e-20261019T062728003301Z/f-readonly-approval-candidate.v2.json), actual original byte SHA256:

`3187eba1e6c7313005ec1d522f34cf022c36ec24b55eaadfd3febfa4f86d0ad2`

Created `2026-10-19T06:50:20.052975+00:00`; expiry **`2026-10-20T06:48:30.897939+00:00`** (UTC), currently unexpired at preparation. Private0700directory/0600regularfile. Complete original JSON text, parsed field review, all source/SQL pins, target/credential metadata, resource baseline hash, proposed action/limits and unknown actual identities are included in the package.

Preserved unapproved v1: SHA `7adf57cfcfb8ed72ead0e53bb24e7898cc2bb2bb8e7861a23a88d111d582e4a1` plus matching source snapshot. Final v2 corrects evidence counting of actual connector invocations versus reserved attempt budget; **original expiry unchanged**, no approval renewed or inherited. Original v1 is not the candidate for approval.

[Protected full source-review package](/Users/ferozebasha/.sbom-uuid-w2-review/w24e-20261019T062728003301Z/w24e-source-review-package.json), SHA256 `18b058d2b290b24ac29464ef2a8cca012aa6473ffb5778126ac7c563af683f9f`, review expiry same as finalcandidate. Complete ten sources/new-file diffs and hashes, exact candidate bytes, complete SQL/acceptance matrix/dependency pins, fresh metadata evidence, all observed test results/development failures and live control flow retained outside repository. Protected evidence path `/Users/ferozebasha/.sbom-uuid-w2-review/w24e-20261019T062728003301Z`.

Five pending flags remainfalse: source_reviewed, read_only_session_approved, credential_provenance_reviewed, privileged_bootstrap_read_reviewed, network_egress_reviewed. `approvals={}`, `accepted=false`, seven integrity attestationsfalse and integrityactions{}. No action reference fabricated. No execution-approved file created.

## Next independent operator decision and STOP

Review exact new package/source and final candidate byte hash. If approved, operator must separately authorize the five review flags and one distinct `read_only_execute` reference for exactly one F-only read-only attempt before expiry. Preserve originalcandidate; a separate approvedfile must change only issued approvalfields, retaining source/resource/target/budget/expiry pins, with its own operator-approved **raw-byte SHA256** supplied to CLI. Do not silently renew an expiredcandidate or adopt drift.

Safe offline command:

```sh
.venv/bin/python -B infra/uuid-migration/f-readonly-acceptance/entry.py --mode offline \
  --manifest /Users/ferozebasha/.sbom-uuid-w2-review/w24e-20261019T062728003301Z/f-readonly-approval-candidate.v2.json \
  --manifest-sha256 3187eba1e6c7313005ec1d522f34cf022c36ec24b55eaadfd3febfa4f86d0ad2
```

Future live CLI contract appears in the new README/package; it is **NOT AUTHORIZED** by this task. No next stage, migration047/048–091, role/grant/schema/seed/marker/index/backfill/application work follows automatically.

**F INFRASTRUCTURE remains ACCEPTED; F DATABASE IDENTITY/AUTHENTICATION/FRESHNESS remains NOT ACCEPTED. Frozen047 NOT RUNTIME ACCEPTED. All193live UUID integrity cases NOT EXECUTED. STOP for independent source/package/manifest review.**
