# W2.5 — Frozen047 execution readiness

**W2.5 FROZEN047 EXECUTION READY — PENDING WRITE AUTHORIZATION.** 2026-10-19. This is source integration and offline verification, not installation acceptance. **1,033 offline tests PASS / 0 FAIL / 0 SKIP** in the final runs: 115 new and 918 selected existing tests. No PostgreSQL connection, Docker command, real credential content or metadata read, schema mutation, Alembic operation, application startup or Git delivery occurred.

Frozen047 remains **NOT RUNTIME ACCEPTED**. Revisions048–091 and all193 live UUID integrity cases remain **NOT EXECUTED**. F identity/freshness was accepted by the earlier W2.4E.2 run; this task verified its original bytes rather than performing another session. STOP for independent source/package and write-candidate review.

## Verified authority and historical evidence

Branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac` preserved. Before changes, 2,210 existing repository file contents were snapshotted. Eighteen new isolated artifacts are under [frozen047-execution](/Users/ferozebasha/sbom/infra/uuid-migration/frozen047-execution/README.md). Original historical sources, W2.1/W2.3/W2.4B/W2.4C locks, migrations001–091, application sources and review packages remain unchanged. Active Alembic head remains079; combined offline graph remains91 linear revisions/45 scheduled units. No promotion occurred.

Actual original W2.4E.2 [evidence](/Users/ferozebasha/.sbom-uuid-w2-review/w24e-20261019T062728003301Z/f-readonly-attempt.jsonl) SHA256 `412ecca1fc065f25ef1b509e300c5bdd12430cef39d8cb4884e7dac4726f1076` was read and independently checked: all74 chained records, one constructor attempt,33catalog queries, all complete-probe checks PASS, ROLLBACK acknowledged, physical closure and final durable STOP. The separately saved [outcome](/Users/ferozebasha/.sbom-uuid-w2-review/w24e2-20261019T073117650237Z/outcome.json) SHA256 `9e6a5f96ae9e0c2b58a3498e67f97766375dfb9802ef232b68407f525add92c5` was also verified. Saved30catalog categories reproduce the original corrected validator assessment.

Accepted historical F:127.0.0.1:56043, database `uuid_w2_f_fresh`, user `uuid_w2_f_bootstrap`, OID16384, cluster7698258353561202726, PostgreSQL16.15; internal172.22.0.2:5432, `/var/lib/postgresql/data`, postmaster2026-10-19T06:14:08.562791+00:00. Application objects/Alembic table were absent at that observation. Bootstrap privilege, four schema owners/ACLs and exact eleven privilege rows were observed. These are verified historical observations, not fresh runtime claims. Future write preflight repeats all required checks.

Original packages verified against actual bytes and embedded sources:

| Package | SHA256 |
|---|---|
| W2.1 | `7b524fd8484116a4190b4dfeb98edb7324bdca38b1ddd4989b5f13a236080b34` |
| W2.4B | `3a9f64cac892d07bfb43fe7d2690455f069c253c18fd098da65e06b4b3effae1` |
| W2.4C | `6e7b633e17ea2ff63c137c8f6829222999bae45b5dca6309122476da1f8b14df` |
| W2.4E.1 | `278a2bba320d4ae49626c1b2acc090327378fdd50374865829e6bdd4b8ca133e` |

Original offline graph/package checker additionally reverified prior W2.1/W2.2/W2.3 evidence and113pins. The new retained-input manifest pins179 actual historical inputs. Earlier W1.7 failures, old unapproved/expired candidates and previous statuses are retained; prior NOT_ACCEPTED entries remain historical rather than overwritten.

## Implemented source integration

- `w25_inputs.py`: explicit fixed repository, raw hashes and enumerated inert loader groups. Imports no application settings/models, dotenv, historical001 body or W1.7 private helper.
- `w25_schema.py`: exact original W2.1 representation plus bounded source-derived schema model; preserves statement order and object bytes, including GIN jsonb_path_ops, partial indexes, all integer relationships and CHECKs.
- `w25_catalog.py`: complete accepted F freshness/security observations before DDL, richer post-schema projections and exact structural/owner/ACL validation. Unknown schemas, objects, representations, grants, roles or populated tables refuse.
- `w25_contract.py`: raw protected manifest bytes/hash, duplicate-key rejection, UTC expiry, eight source-specific operator reviews, fixed F target/identity, exact versioned sources/budget/SQL/dependency pins and separate unit_execute/unit_readback actions. Historical acceptance evidence is not execution authority.
- `w25_runtime.py`: original unchanged W2.4C non-autocommit Driver/Session/recipe plus W2.4B phase meter; one actual driver constructor; reviewed native adapters, SQLAlchemy Engine/NullPool/Connection and full metered dialect initialization. Reuses original F resource/secret safeguards only behind future exact operator authority.
- `w25_coordinator.py`: only frozen047, complete lifecycle/evidence and separate readback proof. No arbitrary revision selector, second automatic session or later migration route.
- `w25_entry.py`: useful offline mode, future one-action mode requiring separate exact raw manifest hash and action approval. No supplied operator references or live invocation occurred.
- `w25_test_support.py` / `test_w25_offline.py`: synthetic DBAPI metadata and connections with real installed SQLAlchemy binding; no PostgreSQL acceptance claimed.

Full new-file diffs, all18exact sources, complete SQL representation and original-to-proposed047 diff are embedded in the protected package. No original adapter was edited, monkeypatched or activated. W2.3 mock-only denial and W2.4A/W2.4C historical live denials remain intact.

## Frozen047 representation and permitted objects

Original frozen SQL SHA256 `e310421b5fea4ef93056be590756125726280671589b50d93aa85926b9833c09`; unchanged W2.1 execution SQL SHA256 `6173c58cca7061483edd1b69e9edd0c431eee808f46ae1021293549d13e8c900`. The exact558ordered statements comprise12previously reviewed transaction-local setting adjustments plus546object definitions. Complete12directive originals/replacements and exact transformation SHA are in the package. No naive semicolon splitter or SQL string rewriting was introduced. The existing quote/dollar-quote-aware framing and source hash remain authoritative.

Source-derived expected schema, **not a measured F catalog**:

| Object group | Frozen body | After separately authorized marker object |
|---|---:|---:|
| Application/base tables |45|46|
| Base columns |727|728|
| Sequences |34|34|
| Public indexes |332|333|
| Constraints |159|160|

After marker creation:46PKs,67FKs,31CHECKs,16UNIQUE constraints;34sequence ownership edges. No reference rows, historical business records, sequence current values, original credentials, customer tenants, administrators, memberships or grants are imported. Required authorization seed/reference initialization starts later at048 and is not included in047.

TOAST relations are checked as PostgreSQL relkind`t`, with source-derived public parent OIDs linked to actual observed TOAST/index pairs; their internal identities/counts are not guessed. Ownership/storage/ACL/RLS/inheritance/method properties, unexpected relation types and orphan/duplicate children fail closed. Source basis: [PostgreSQL16 pg_class](https://www.postgresql.org/docs/16/catalog-pg-class.html) and [REL_16_15 toasting.c](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/catalog/toasting.c). These source checks are not PostgreSQL runtime evidence.

## Transaction, marker and recovery contract

One future write invocation owns one connection and first runs full initialization plus30fresh read-only observations. Native autocommitFalse/READ_COMMITTED, effective read_onlyon, actual libpq password-use indication and exact identity/security are mandatory. RO rollback must be acknowledged and both driver/logical transaction idle before switching native read_onlyFalse.

One RW transaction starts implicitly on the first owned statement, advisory lock7160085085. Source/authority/resource checks and30locked observations repeat before body execution. No pre-existing table/version object exists to table-lock; any such object refuses. Newly created version-table DDL holds PostgreSQL ACCESS EXCLUSIVE through commit. The operator must approve the exclusive DDL window; advisory locking and writer snapshots do not prove exclusion of an uncooperative privileged client.

Only the558ordered source statements run. Then, and only then, create `public.alembic_version(version_num VARCHAR(128) NOT NULL PRIMARY KEY)`, reset transaction-local search_path, and validate full source-derived schema/security plus all45empty application tables and ZERO marker rows. Only after this check, parameterized INSERT of `047_email_verification_tokens`, exact rowcount1/RETURNING/sole-marker verification. Source/manifest/resource/window checks repeat before durable COMMIT intent and owned commit. No `stamp`, upgrade-head, historical replay or current ORM create_all exists.

Successful write requires acknowledgment, physical connection close, logical cleanup/engine disposal, resource preservation and durable STOP, and returns **COMMITTED_UNVERIFIED / accepted=false**. It cannot self-certify complete installation acceptance.

Separate future readback authority must pin the actual original successful write journal byte hash. The implementation checks its chain, original approved manifest bytes/action/source lock at commit time, complete ordered558driver statement hashes, both marker operations, three validated catalog snapshots, exact schema digest, one attempt, acknowledged COMMIT and physical/logical close/preservation. A summary accepted flag or fabricated receipt is insufficient. Only then may one independent RO connection verify the committed schema/sole047, roll back, close/dispose and save durable evidence before accepting047.

Known precommit failure: rollback where owned transaction state permits, require idle/closure, stop with unverified rollback status. Rollback failure is explicitly unreconciled. COMMIT sent without acknowledgment: **UNKNOWN_COMMIT_MANUAL_RECONCILIATION**, physical close before SQLAlchemy disposal, no guessed rollback/retry. Evidence/disposal/resource failures prevent acceptance. No retry, schema cleanup, marker repair, restore, downgrade, F recreation or automatic continuation exists.

## Exact budget transition and security

The original W2.4B budget/lock is unchanged. The new source-specific proposal keeps write256catalog queries and original nonquery limits. It explicitly changes post-body/readback phase75→81 and readback96→104. Exact81post observations:30catalog templates,5structural queries,45empty-table EXISTS and1marker SELECT. Richer column projection replaces one template rather than adding another query.

| Phase | Known mock execution | Proposed ceiling |
|---|---:|---:|
| Driver/dialect initialization |5|16|
| RO preflight |30|54|
| Locked RW reinspection |30|54|
| Post-body |81|81|
| Advisory plus final marker SELECT |2|2|
| Write total |148|256|
| Separate RO readback including initialization |86|104|

Write phase caps total207, rounded8→208, plus48unused legacy headroom=256. Readback16+81=97, rounded8→104. Derived metadata is recomputed, not inherited stale counts. No phase borrowing, wildcard SQL allowlist, automatic learning, arbitrary WITH/VALUES/EXPLAIN/COPY/CALL or reflection expansion is accepted. Unexpected SQL stops before its driver statement. All actually allowed driver operations are metered exactly once.

Write:558migration statements,2marker statements, at most2extra session statements,4transaction controls, one constructor/active connection. Readback additionally hard-refuses more than2controls and has empty migration/marker/session allowlists despite retained legacy category ceilings. Query rows≤1024, total observed rows≤8192; connect5s, statement30s, lock1s, idle30s and cooperative unit120s. The120s window is not a hard kill/COMMIT deadline; safe bounded cleanup may finish later. These are future proposed unit-specific settings, not the spent W2.4E read-only approval.

Fixed127.0.0.1host+hostaddr/56043/database/user/OID/cluster, passfile/dev/null, no service keyword, SSL/GSSdisable, no ambientPG/application/.env configuration. default_read_onlyon, row_securityon, check_function_bodieson, search_pathpg_catalog and prepare_thresholdNone. Original exact local daemon/container/image/network/exclusive volume/loopback/secret metadata and bounded memory-only correlation gates must refresh in the future; no real credential file was accessed now. No resource or password mutation allowed. HBA file inspection, SCRAM storage boolean and successful password use remain appropriately limited evidence; they do not certify last-loaded HBA rules or exact wire mechanism. Restricted runtime role creation remains a separate task.

## Actual offline verification and development outcomes

| Suite | PASS | FAIL | SKIP |
|---|---:|---:|---:|
| W2.1 fresh bootstrap |102|0|0|
| W2.2 finalization |53|0|0|
| W2.3 coordinator |71|0|0|
| W2.4A activation |126|0|0|
| W2.4B budgets |99|0|0|
| W2.4C transactions |167|0|0|
| Expansion runner |21|0|0|
| Integrity offline |53|0|0|
| F read-only |145|0|0|
| F read-only correction |81|0|0|
| New W2.5 |115|0|0|
| **Final total** |**1033**|**0**|**0**|

Actual logs, their exact hashes and all development logs are retained under [private logs](/Users/ferozebasha/.sbom-uuid-w2-review/w25-20261019T075117930822Z/logs). Existing suites were run directly using repository `.venv/bin/python -B` and the matching standalone offline test file; new suite:

```bash
.venv/bin/python -B infra/uuid-migration/frozen047-execution/test_w25_offline.py
.venv/bin/python -B infra/uuid-migration/frozen047-execution/w25_entry.py --mode offline
.venv/bin/python -B infra/uuid-migration/fresh-coordinator/coordinator.py --mode offline
.venv/bin/python -B infra/uuid-migration/staged-runner/verify_offline.py
ruff check --no-cache infra/uuid-migration/frozen047-execution
ruff format --check infra/uuid-migration/frozen047-execution
git diff --check
```

NinePython AST/in-memory compiles,179retainedpins, exact047model/source, complete installed compiler/driver source and native metadata pins,649template SQLAlchemy compiles/framing (88unique query templates+558body+2marker+1session), old42literal/14query/18dynamic/6DDL checks,91graph/45units, both private candidates offline/raw hashes, Ruff and whitespace PASS. No SQL was sent; SQLAlchemy compilation is not PostgreSQL grammar/semantic acceptance. Synthetic SQLAlchemy physical-close failure logs are expected negative tests, not a live environment failure.

Development outcomes preserved: CRLF CSV text-vs-byte comparison falsely refused and was corrected to original raw bytes; controlled source parser initially refused actual CHECK/bytea/GIN forms and was extended only for pinned source; early Ruff findings corrected only in new files, unavailable `.venv/bin/ruff` replaced by installed Ruff. Initial new runs92and109PASS. Two later115-test development runs each had one error: the durable synthetic evidence fixture used a symlinked macOS temporary path, then a repository-local private path; production private-file guard correctly refused both. Fixture moved to a private nonsymlink path outside repo. Subsequent115tests PASS, including full durable journal/source-model validation and rejection of omitted ordered execution proof. Static framing initially omitted terminators on standalone driver templates; the checker adds a terminator for framing only, no executed SQL/source changed. No historical failure was relabeled as a successful process exit.

## New source and package fingerprints

All filenames below are under `/Users/ferozebasha/sbom/infra/uuid-migration/frozen047-execution/`.

| New file | SHA256 |
|---|---|
| README.md | `e579d4aee7e1a4d3da4ab2a9d136d65d6471690b23e654b5e0ea89b8a0ee31fa` |
| approval.pending.json | `4a019e45477bb2ced35a1417deaa6dc303add915bb539cdfbe4acf10c8987ee0` |
| dependencies.w25.json | `a0cf957783bbcf877547404e544b0c29023d2214454f74173bed20457031483c` |
| expected-schema.w25.json | `c31ca3dce117724c3cd1067d119821cedb217277df148a0250341059fd667a46` |
| observation-budget.w25.json | `e4d04d4c4e3aac2c7462b7f267c2edaef785a5eda322bb2427ea00784a5aa30b` |
| retained-inputs.v1.json | `3c0d7302c18e21bf2110a439aaaf25c2525183cc213555af6bfc17c37537aa55` |
| runtime-acceptance-checklist.md | `a63edf3ab1c822f2920ad96587374a625d5ab5b0adb8bfe7b0a759f7ba98ee76` |
| source-lock.w25.json | `1cb13be06ac8db6e17963ec4f8dababa3369b02f9405e8b935f15aa8524cacad` |
| sql-allowlist.w25.json | `56f476f8318e3e7999a9cb18aa9530de3d871ab4ee6305e53ad457600d3de49f` |
| test_w25_offline.py | `0c5b52ca807a8ea8b53f7d474885279fe56eb3c743136a6cf66d4563bba91c45` |
| w25_catalog.py | `8549a08662600539184ea8f0ff2907e80caecde4582832a80330c46c2be38596` |
| w25_contract.py | `03ea70b8039d9c6f94c6c2fde67c492149a9038dc45c07ff3b67d2f1a8022a43` |
| w25_coordinator.py | `dc5f419faa0049a7a97240b2a792a7e38d07550bdec5133188fb60f6d1c921d2` |
| w25_entry.py | `b34fbcf2475cf3c12f8b6ac255fbf9ba07279dab7e6d78c78e0e23558f62cdb6` |
| w25_inputs.py | `6531c5aac2afe824fe42bb5878ca861775cdf3d3d2ef2d19e6ea576fd291a929` |
| w25_runtime.py | `860a652a98440138ca9b07c6ce6e80d90447d621ca67c309b217d48095efddd5` |
| w25_schema.py | `64d56cee80cbf3b32e225f8a13326f0397a123bba8a3d4ff5086c936ec785db4` |
| w25_test_support.py | `d27e0e2b8b79bb1fd577f633bb47fc723e9fdde1bc971a29bc50008628519b12` |

[Protected full review package](/Users/ferozebasha/.sbom-uuid-w2-review/w25-20261019T075117930822Z/w25-source-review-package.json) SHA256 **`c499ce5d58da03a58697eb94ca13d7c4fa5f3c214318e8521c89719e28b94a5d`**, 2,917,906bytes; all18sources/diffs, exact SQL/12directive diff, original F evidence assessment, typed expected schema, old/new budget comparison, full pending candidates, tests/log hashes, dependencies and runtime limitations. Directory0700/files0600. Package expiry **`2026-10-20T08:09:44.274290+00:00`** is new unapproved review metadata, not an extension/reuse of any operator authorization.

[Write candidate](/Users/ferozebasha/.sbom-uuid-w2-review/w25-20261019T075117930822Z/frozen047-write-candidate.v1.json) raw SHA256 **`00b5f95f85b4f0f1d27fe2d309229e10b5b88adfe61d87854d4ada7476d216bc`**.

[Separate readback candidate](/Users/ferozebasha/.sbom-uuid-w2-review/w25-20261019T075117930822Z/frozen047-readback-candidate.v1.json) raw SHA256 **`7550efeabdeb29a349c486aac289147f2ac88c40ebcb2681a57e9debf091ebee`**.

Both expire **`2026-10-20T08:09:44.274290+00:00`**; all eight reviewsfalse, actions{}, acceptedfalse, sevenintegrityflagsfalse/actions{}. Neither authorizes any connection. Readback actual-write evidence SHA remains null pending separately reviewed committed/closed write evidence; it is deliberately nonexecutable now. Public pending template also has no source-lock authority; protected candidates bind the exact proposed new source-lock byte hash. Original candidates/packages and expiries remain unchanged.

## Remaining runtime assumptions and next decision

PG14dump-derived frozen047 grammar/equivalence on16.15, actual dependency/native proxy/dialect initialization, physical implicit BEGIN/transactional DDL/COMMIT/rollback, deparsed types/defaults/ACLs/opclasses/TOAST representation, resource limits, timing and locks have not been runtime tested. Any unexpected observation requires STOP and review, not normalization or timeout/allowlist relaxation. Complete native OS-library provenance beyond pinned installed package/backend metadata is not proven. No performance, concurrency, uncertain-COMMIT fault injection, recovery, application, API, frontend or live UUID integrity acceptance is claimed.

Next operator decision: independently review this exact package, source lock, source-derived model, budget transition and write candidate; separately approve all eight review areas and issue one source-specific `unit_execute` action reference plus the exact resulting approved-manifest raw hash. Recheck F freshness/resources immediately during that later authorized operation. Write-only scope ends after one frozen047 transaction/closure/evidence, with no048–091. Then independently review the actual successful write evidence hash and separately approve the readback candidate/action; no automatic readback connection follows.

No operator approval value was invented. F storage/current schema remains unchanged by this task. STOP for independent review.


## W2.5 focused correction v2 — exact PostgreSQL setting sources

**OFFLINE VERIFIED — PENDING INDEPENDENT SOURCE / WRITE REVIEW.** 2026-10-19. This appendix supersedes the original setting-source expectation and v1 source selection for a future write. All earlier results, original source snapshots, package/candidate bytes and source-lock v1 remain historical evidence. Frozen047 is still **NOT RUNTIME ACCEPTED**; no write/readback authorization exists and all193 live integrity cases remain **NOT EXECUTED**.

### Defect, source review and narrow correction

Original package `c499ce5d58da03a58697eb94ca13d7c4fa5f3c214318e8521c89719e28b94a5d`, all18 embedded source bytes, both v1candidate hashes and source lock `1cb13be06ac8db6e17963ec4f8dababa3369b02f9405e8b935f15aa8524cacad` were verified before edits. Original sources copied into private0600 files. Branch/HEAD unchanged; all2,229existing file contents snapshotted.

[Independent synthetic reproduction](/Users/ferozebasha/.sbom-uuid-w2-review/w25-settings-20261019T084922290438Z/defect-reproduction.json) produced exactly **`ValueError: Accepted F security/session drift: settings`** with the original validator and six correct session-sourced post-body rows. The old synthetic driver fixture retained client metadata and therefore did not expose this mismatch.

PostgreSQL **REL_16_15** source files were read from the official repository and preserved with full byte hashes. [guc_funcs.c](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/utils/misc/guc_funcs.c) assigns PGC_S_SESSION for local value statements and exposes current source metadata. [guc_tables.c](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/utils/misc/guc_tables.c) supplies the actual variable types/hooks and client/session labels. [guc.c](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/utils/misc/guc.c) installs sources for successful bool/int/string assignments, including equal values, and restores local prior values/sources at transaction end. Startup option attribution was checked in postgres.c. This is source reasoning, not new F observations.

Exact16-row validation remains. Only six monitored local assignments change source; the existing bool pair now selects four explicit phases:

| Phase | readonly / after | Six local rows' source | transaction_read_only |
|---|---|---|---|
| initial_readonly | true / false | client | on / session |
| locked_pre_ddl | false / false | client | off / session |
| post_body | false / true | session | off / session |
| independent_readback | true / true | client | on / session |

Values remain statement_timeout30000, lock_timeout1000, idle_in_transaction_session_timeout30000, check_function_bodieson, row_securityon, search_pathpg_catalog after the unchanged reset. All other settings retain their exact accepted source/value metadata. The BEGIN-related transaction_read_only row already has session source; it is not changed to client or treated as a body SET. Missing/extra/duplicate/incomplete rows, wrong sources/values and invalid phase types refuse.

All12directives were checked individually against PostgreSQL type declarations/hooks: three integer timeouts, three Boolean directives, four string directives, two enum directives. Exactly six intersect the fixed monitored settings. The other six (client_encoding, standard_conforming_strings, xmloption, client_min_messages, default_tablespace, default_table_access_method) remain unmodified SQL and are not invented as source observations. Full [phase/type/source review](/Users/ferozebasha/sbom/infra/uuid-migration/frozen047-execution/setting-source-review.v2.md), complete16-row four-phase expectations, upstream source snapshots/hashes and source-derived limitations are in the package.

### Changed source and versioned lock

Only three existing source files changed; the original115-test file is unchanged:

| Source | Before SHA256 | Corrected SHA256 |
|---|---|---|
| w25_catalog.py | `8549a08662600539184ea8f0ff2907e80caecde4582832a80330c46c2be38596` | `e0b9518540ed443ca2a63775456d4f4f919eebd878ec87fb665b0b14f93ef143` |
| w25_test_support.py | `d27e0e2b8b79bb1fd577f633bb47fc723e9fdde1bc971a29bc50008628519b12` | `af0b80b2c2c59cbc7864bd077d7fdf36ddd2a737817d88c9154e7edc85312908` |
| w25_contract.py | `03ea70b8039d9c6f94c6c2fde67c492149a9038dc45c07ff3b67d2f1a8022a43` | `a812667a7c8319078a205daaf718b27ba60e82bc5901a0e86fa13970ec5f5633` |

The contract change only selects separate `source-lock.w25.v2.json` and excludes that current lock from its own hash inventory. The original lock is now an additional pinned historical input, not overwritten or selected as current authority. [New proposed lock](/Users/ferozebasha/sbom/infra/uuid-migration/frozen047-execution/source-lock.w25.v2.json) raw SHA256 **`cce0795d165c94453bdffae70302dd4c26013c8a9973945648b052374d5e1742`**; no lock/action approval issued. New [focused tests](/Users/ferozebasha/sbom/infra/uuid-migration/frozen047-execution/test_w25_settings_offline.py) SHA256 `fe48db4e2dee36e133821fbcee789902eb90c8accf1b895f3892f9571f88624e` and source-review policy SHA256 `cbe1185e85fb0084336c9a84c91a004af9e1853e4293191ec833aa6047bc7b2d`.

Original558SQL statements/12directives, SQL allowlist, model, budget, dependency pins, marker/coordinator, native connection/transaction kernel and physical-closure code are **byte-for-byte unchanged**. Write/readback query observations remain148/86 in the synthetic binding with256/104 ceilings;4write/2readback transaction controls unchanged. No source/ACL/privilege/schema/security/expiry or raw-manifest gate was relaxed. source-derived model SHA256 remains `9e64728cfa41fb493c98acadc75c216d7d749aeaa25ec51372e785b50732d9df`.

### Actual offline verification

**1,066 PASS / 0 FAIL / 0 SKIP** in final complete reruns: original1,033 plus33focused tests. Original ten older suites total918 and original W2.5 suite115 were rerun, not inferred from historical logs. Focused cases include all four phases, every monitored missing row, six source/value transitions, arbitrary source rejection, duplicated/extra/incomplete rows, same-value assignment sources, independent new-connection settings, exact schema/privilege/model/budget checks, rollback before marker INSERT, unknown COMMIT/manual reconciliation, physical close and separate authorized readback/no automatic second connection. Mocks remain synthetic; no runtime acceptance claimed.

Actual commands and exit/count evidence are in [offline-tests.json](/Users/ferozebasha/.sbom-uuid-w2-review/w25-settings-20261019T084922290438Z/offline-tests.json). Focused command:

```bash
.venv/bin/python -B infra/uuid-migration/frozen047-execution/test_w25_settings_offline.py
```

TenPythonAST/in-memory compilation checks,649unchangedSQLtemplate framing/SQLAlchemy compiles,179historical source pins, old package/graph checks (active079/combined091/45units), installed dependency/native metadata pins, source-lock integrity, both new candidates' offline entrypoint checks, Rufflint/format and whitespace PASS. No PostgreSQL grammar/equivalence or physical transaction success inferred.

Development failures are preserved: the first original115-test rerun had one error because the newly selected v2 lock did not exist yet; final v2 contract checks/pass recorded. New focused tests initially had15Ruff findings (capture bindings/style), fixed only in that new test source.33focused tests passed initially and finally. Original115passed after lock transition; no failed exit rewritten. [Protected logs](/Users/ferozebasha/.sbom-uuid-w2-review/w25-settings-20261019T084922290438Z/logs) and full exact source diffs retained.

### Protected review artifacts and STOP

[New full package](/Users/ferozebasha/.sbom-uuid-w2-review/w25-settings-20261019T084922290438Z/w25-setting-source-review-package.v2.json) SHA256 **`91f3af6d98b4879d5c9a7f5e65dfd2f6d3c5e9a862c7a02f0e44be20c4022a3e`**. All21current artifacts, sixcompletechanged/new source diffs, threeoriginal source snapshots, all PostgreSQL source hashes, reproduction, four-phase observations, tests and full pending candidate JSON included. Documentation append diffs are retained separately in [complete change evidence](/Users/ferozebasha/.sbom-uuid-w2-review/w25-settings-20261019T084922290438Z/complete-changed-file-diffs.json) to avoid a self-referential package/report hash. Private directory0700/files0600.

[Write candidate v2](/Users/ferozebasha/.sbom-uuid-w2-review/w25-settings-20261019T084922290438Z/frozen047-write-candidate.v2.json) SHA256 **`bd521c3152436a4899032e7ba3246238025c54f0e1b392648c97b42697e0a6b9`**.

[Readback candidate v2](/Users/ferozebasha/.sbom-uuid-w2-review/w25-settings-20261019T084922290438Z/frozen047-readback-candidate.v2.json) SHA256 **`50d63fb7a2bc6631ef249f4d1ca7a0042d5c2ccd754de4142b58a7f14aafbe39`**.

Both retain original expiry **`2026-10-20T08:09:44.274290+00:00`**, unchanged target/resource/budget/credential references and all other authority fields. Only source-lock pin and new evidence-directory paths changed; readback's pending write-evidence path points to the new write evidence directory, SHA stillnull. All8operatorflagsfalse/actions{}/acceptedfalse/sevenintegrityflagsfalse/actions{}. Neither is executable without separate operator review/approval. No approval was extended or manufactured. v1candidates/package remain unchanged.

Current task: **zero PostgreSQL connections, Docker commands, credential-content reads, migrations, SQL/schema/data/marker mutation or Git delivery**. Public PostgreSQL source retrieval was the only network source review. No resource baseline was refreshed and no live identities invented. ActualPG16GUC/deparse/native-driver/transaction/COMMIT/rollback and resource timing remain later runtime gates. STOP: independent exact v2source/package/candidate review, followed only by separately authorized oneF-only frozen047 write action. Independent readback still requires its own later authorization and the actual acknowledged/closed write-evidence hash.
