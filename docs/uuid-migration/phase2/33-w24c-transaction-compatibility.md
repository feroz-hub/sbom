# W2.4C — PostgreSQL transaction compatibility correction

**STAGED / OFFLINE VERIFIED — 2026-10-19.** Fifteen new isolated artifacts under `infra/uuid-migration/f-transaction-correction/`, report33 and append-only tracker. **692 OFFLINE tests PASS / 0 FAIL / 0 SKIP**: 167 new plus525 selected existing. This accepts the offline correction proposal and tests only; PostgreSQL transaction compatibility is **NOT runtime accepted**. Live CLIs remain denied. No prior source, package, lock, migration or application file was edited.

F **NOT CREATED**; frozen047 **NOT RUNTIME ACCEPTED**; all193live UUID integrity cases **NOT EXECUTED**. PostgreSQL connections/actual SQL, Docker commands, real credential reads, infrastructure/migration/promotion/application/Git delivery activity: **zero**. No new execution-approved manifest or action reference exists.

## Authority, source verification and preservation

Required branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac` verified. Snapshotted2,179 existing tracked/untracked nonignored files before source changes. Tracker scope/prerequisites/acceptance/stop appended first. Read tracker/reports29–32 and actual frozen/graph/source-lock/transaction/binding/budget/observation/migration guards; inspected installed SQLAlchemy2.0.51, psycopg3.3.4 and Alembic1.18.5 source offline.

W2.4A package `a426703bd57c74ba25a1cdddcfdd3223f7c4a2f29765a8814f639ab04991c277`, all13files and full diff hashes verified. W2.4B package `3a9f64cac892d07bfb43fe7d2690455f069c253c18fd098da65e06b4b3effae1`, all16files/full diffs verified. Their unchanged verifier/tests reverified original W2.1/W2.2/W2.3 packages and113source pins;91linear combined revisions/45units and79active/head079 remain unchanged. Parent v3proposal `591e1fcb65f5e782a9a08e86fe94033c981bf94aa5bc05f8d220ddf2638761c9`, W2.3 v2lock `f6fe5d0a823d7af3b91dd6716dad62d2d43a90c83f9f4186227af343e5e9c83f` and staged080–091 source bytes preserved. Historical W1 failures and accepted D085 evidence were not rewritten or freshly measured.

## Confirmed conflict and corrected transaction model

Actual080–085 upgrade guards require PostgreSQL/online/transactional DDL, bind.in_transaction(), execution options not AUTOCOMMIT and driver.autocommit exactlyFalse. Actual086–091 additionally require their reviewed typed F context, and the same owned non-autocommit transaction. W2.4A requires driverTrue and SQLAlchemy AUTOCOMMIT. Literal BEGIN READ WRITE cannot change those Python values: all12sources would refuse before executing their UUID body. Their guards remain unchanged; the new tests extract and execute only the original transaction-guard AST, never complete migration modules/bodies.

Simply changing True toFalse is insufficient: psycopg emits implicit BEGIN on first query; sending literal BEGIN would duplicate it. SQLAlchemy Connection.begin() establishes logical ownership but normally sends no BEGIN itself. Default create_engine initialization creates a temporary Connection, calls dialect.initialize(), then dialect.do_rollback() in finally. A separate initialization transaction plus preflight plus write could exceed four controls. The proposal avoids that automatic wrapper rather than suppressing the rollback of an unknown transaction.

[Full source/design](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/README.md) and proposed kernel/recipe:

1. One fixed F-only authenticated connection, autocommitFalse, native READ_COMMITTED enum2 while IDLE; read_onlyTrue. Exact original host/hostaddr127.0.0.1/56043/uuid_w2_f_fresh/uuid_w2_f_bootstrap, passfile/dev/null, absent service, SSL/GSSdisable, connect5s, application name and unit-specific session/timeouts retained. Clean actual environment and independent original authority/resource/credential/security gates remain mandatory. New explicit client proposal prepare_thresholdNone excludes automatic prepared/cache-maintenance commands; it needs source-specific review, not old approval inheritance.
2. Explicit dedicated Engine/NullPool/Connection construction, reset_on_returnNone and _allow_revalidateFalse. Sole pool creator returns the one proxy once. on_connect adapter/notice setup runs while IDLE and cannot issue unowned SQL. No Engine.connect automatic initializer/finally-rollback hooks. No dialect version/isolation discovery is invented or skipped.
3. One real SQLAlchemy logical RO transaction. First metered query reserves its query and implicit BEGIN control before raw execution; psycopg emits BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY. Complete dialect.initialize and full preflight share this transaction, with separate existing W2.4B initialization/preflight phases. Catalog verification still requires effective transaction_read_onlyon.
4. Owned SQLAlchemy rollback invokes DBAPI rollback once; backendIDLE and logical closure required. Only then change native read_onlyFalse while IDLE. Server default_transaction_read_onlyon remains unchanged. A second owned logical transaction starts actual READ WRITE on the advisory SELECT; no literal BEGIN is sent.
5. Existing advisory7160085085, versionEXCLUSIVE NOWAIT and reviewed all-table locks precede locked source/target/catalog/role/reference/writer reinspection. Frozen558 or exactly one isolated reviewed Operations upgrade, post-schema/old-marker acceptance and exact parameterized next-marker mutation remain atomic in this transaction. Existing Alembic binding sees the actual owned connection and unmodified guards.
6. Immediate authority/source/target/deadline recheck, durable COMMIT intent, owned SQLAlchemy commit, acknowledged DBAPI return plusIDLE, physical raw close, logical Connection cleanup and engine disposal. Independent committed catalog/marker readback needs a separate action/connection/budget. No automatic second connection or retry.

|Boundary|Write success|Known precommit failure|Separate validate/readback|
|---|---|---|---|
|RO implicit BEGIN + owned rollback|2controls|Up to2|2controls total|
|RW implicit BEGIN + end|2controls including COMMIT|Up to2 including ROLLBACK|No write transaction|
|Maximum|4|4|2|

Actual backend states IDLE/INTRANS/INERROR and logical transaction ownership are cross-checked. ACTIVE/UNKNOWN, unexpected autobegin/restart/open transaction, isolation/read-only drift, duplicate RO/RW ownership, unowned ends, extra checkout and literal controls refuse. This is a proposed transaction model, not an observation of PostgreSQL executing it.

### Native type discovery and initialization

Installed TypeInfo.fetch requires a native connection and uses conn.transaction()+nativeCursor, introducing nested SAVEPOINT and unmetered SQL if unwrapped. The new dedicated dialect subtype overrides only hstore lookup with the same PG16 pg_type projection/to_regtype predicate through the owned metered SQLAlchemy connection. Zero rowsNone, one validated rowactualTypeInfo, ambiguity/errorrefusal; original initializer retains native hstore enablement and adapter registration. No extension omission, raw unwrapping, SAVEPOINT budget or guard monkeypatch. The new exact SQL template/compiled driver hash needs independent source/allowlist review.

Installed complete psycopg dialect initialization was called against synthetic cursor results: five metered SELECT/SHOW calls, one implicitROBEGIN, no intermediate rollback and original absent-hstore semantics. Another test uses real SQLAlchemy RootTransaction and Alembic Operations objects over a synthetic DBAPI driver, with four controls and transactional DDL context. These are offline interoperability tests, **not PostgreSQL grammar/semantic/authentication/COMMIT acceptance**. Native libraries, real adapters, optional paths and PG16 hstore lookup equivalence remain runtime prerequisites.

## Metering, durable evidence and recovery

Strict classifier wraps unchanged W2.4B ScopedMeter and pinned W2.4A Meter. All45unit action/phase caps and non-query quotas stay exact. Initialization uses its existing16-query ceiling; source growth/business/reference observations, three write-side passes, independent readback, reflection and bounded executemany retain their own budgets. SELECT/SHOW always consume catalog quota once at the driver boundary; no logical double charge. Reviewed DDL/DO includes server-internal operations within its single client statement, not additional client cursor calls.

WITH, VALUES, TABLE, EXPLAIN/ANALYZE, CALL, COPY, unknown families, multiple statements, unbounded batches, unreviewed cursor/native protocols and literal transaction SQL fail before raw execution, even with an exact allowlist hash. This prevents WITH/EXPLAIN from falling into migration quota. CREATE/ALTER/DROP/COMMENT/DO/INSERT/UPDATE/DELETE/SET/LOCK require exact category/hash and RW ownership. No wildcard, quota learning or blanket increase. Any needed unsupported runtime SQL is a STOP for review.

One shared durable journal must cover both driver meter and transaction kernel; reserve/log before driver. Actual pinned Journal was exercised on synthetic private files, including hash-only SQL evidence and accepted phase fields. Known precommit failure rolls back; failed rollback is unconfirmed/manual reconciliation. COMMIT sent without acknowledgment is UNKNOWN and never retried/guessed rolled back. Known COMMIT remains committed if later evidence fails. Physical close occurs before logical cleanup so unknown outcome cannot cause another wire ROLLBACK; closed-driver rollback is only a no-wire logical cleanup. Close/disposal attempted independently; closure/evidence failures block acceptance. No downgrade/reset/restore/marker repair exists.

## Exact new artifacts and future source transition

|New file|SHA256|
|---|---|
|[README.md](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/README.md)|`af2d1564236562dd9e20aaadd1c856b3953862a06b6a8936ec6fc89ff222b5d7`|
|[approval.pending.json](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/approval.pending.json)|`8ea7f9eeaeef7907e8bb6b850804b20757dbf8d6398788e51cbee4c015711651`|
|[connection.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/connection.py)|`620bddca69b25feece781639a6d784b3308dbc59fe817d54de79dd5aed3d3c0f`|
|[dependency-review.v1.json](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/dependency-review.v1.json)|`81027369abd1478b5ff04d1718e56aacf987c8f13185633434b62247fcbe9fd5`|
|[dialect.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/dialect.py)|`6f3795a4e43c68c6e6a95b7faa781de30c79d71c92da47426f12ba4d97b194e9`|
|[execution-transition.v3.proposed.diff](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/execution-transition.v3.proposed.diff)|`560b1e00bcdb1fe440aa0731011c7493b6f70958954076235b2250799d11e612`|
|[execution-transition.v3.proposed.json](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/execution-transition.v3.proposed.json)|`f3d6ab072c217f50aeec56cb470cf27bc4907f116898c2e6769740cfb173b908`|
|[kernel.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/kernel.py)|`e382181363cd2c3126b7a7c90e49ee7cef32097a6020aa6ffd8ee612a8ab5dac`|
|[lifecycle.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/lifecycle.py)|`404401e6651d8a8413d2c690b4f2ccaff8ccacadc98587b147410591cfccc3f7`|
|[metering.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/metering.py)|`32c0fe4b19f99814b02cf645e0713e2ca5f319ef322202dbb83bf7d260d5e6b8`|
|[recipe.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/recipe.py)|`2aa424f9cc795a9f52db3bced1faaa1f2042050e67d21d210124ede68256d676`|
|[review.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/review.py)|`a5517d0c506cbdb68af61d4bef10ad2574be4bf92e2fcd7b0e0ea1c6a7a6f428`|
|[source-lock.v4.proposed.json](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/source-lock.v4.proposed.json)|`7d60968d602c7253a2fce884323ce5ce538e32ba92f13950a2185530ba0833b4`|
|[test_transaction_offline.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/test_transaction_offline.py)|`11b394e4dab16147ff78d6b4bf10f4dc1da480007af1f1343b6238405818c819`|
|[transport.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/transport.py)|`7466c8e59e7e6e98a5e156ca3a7201aceac520067d57fbf6d09c73c4b326904e`|

New v4source-lock proposal `7d60968d602c7253a2fce884323ce5ce538e32ba92f13950a2185530ba0833b4` retains the full original v3proposal/parent bytes, old packages/source pins and **unchanged** v2budget/phase proposal. New transaction sources and nine future-copy outputs are separately pinned. Full [unapplied execution-copy diff](/Users/ferozebasha/sbom/infra/uuid-migration/f-transaction-correction/execution-transition.v3.proposed.diff) is based on W2.4B's proposed sources; it is not applied to old files or any destination. Proposed activation preserves all original checks, frozen558/typed finalization/body/postcondition/marker/readback logic while substituting owned Session controls and moving dialect initialization into RO.

Future f-execution-v2 and f-execution-v3 directories remain absent. A NEW separately reviewed controlled loader, wrapper schema, complete source bundle, v4policy consumer and manifest builder remain required. Original v3consumer intentionally cannot consume v4; do not mutate it or silently repin. The transaction-interface diff is not a completed live activation. Future authority must bind original private raw manifest bytes/hash, repeated revalidation, exact source/dependencies/Fidentity/role/ACL/reference/credential/security/network/lock evidence and distinct action approvals. No manifest flag/mock receipt independently proves runtime facts. Pending template remains acceptedfalse, empty actions, null actual Fidentity/expiry/hash and sevenfalse integrity attestations.

## Actual offline results and development history

|Suite|PASS|FAIL|SKIP|
|---|---:|---:|---:|
|New W2.4C|167|0|0|
|W2.4B|99|0|0|
|W2.4A|126|0|0|
|W2.3|71|0|0|
|W2.1|102|0|0|
|W2.2|53|0|0|
|Expand|21|0|0|
|Integrity offline|53|0|0|
|Total|692|0|0|

Commands/logs/hashes retained in package. New command `.venv/bin/python -B infra/uuid-migration/f-transaction-correction/test_transaction_offline.py`. Review/lifecycle offline CLIs useful and live denied; original source-specific live/mock-only denials unchanged. Tests cover48guard valid/invalid cases across all12sources,45synthetic per-unit lifecycles, psycopg implicit BEGIN/SQLAlchemy autobegin, read-only/write transition, atomic fake DDL+marker, known rollback/unknownCOMMIT, journal/close failures, native lookup/reflection/executemany budgets, exact SQL refusal, one connection, source/lock/pending approval preservation and full proposed copy AST/hash validation. Original525tests retain source/manifest/target/reference/security/graph/frozen558/finalization budget coverage.

125Python AST/in-memory source compilations +9future-copy sources PASS. 113oldpins/91combined linear/45units/79active PASS.124catalog SQLAlchemy template compilations including new type lookup PASS; existing verifier42templates/14literal/18dynamic/six index DDL compilations PASS, plus existing finalization compiler coverage. New9Python Rufflint/format and whitespace/diff content checks PASS. Historical six migration import-order warnings unchanged. No broad application suite or193LIVEcase ran.

Development failures preserved, not rewritten: initial package verifier assumed list instead of mapping; initial91tests had25test-harness errors (leading-zero finalization detection/expected denial class), then passed;96tests had one wrong synthetic dialect-selection error, corrected to psycopg;147tests exposed a fixture missing meter journal, corrected with an enforced shared-journal check; transition builder twice asserted an incorrect literal-control count before writing artifacts;167tests had two macOS temporary-path symlink refusals, corrected only by canonicalizing the synthetic test directory. Initial3new-file Ruff findings and a later added-import ordering fixed only in new files. Original pinned safeguards were never weakened for green tests. All final692tests pass.

## Runtime limitations, next gate and STOP

No PG16 transaction/physical COMMIT/rollback/driver-state compatibility is claimed from mocks. Native/libpq/backend provenance, dedicated dialect subtype equivalence/adapter handling, exact runtime initializer/reflection allowlists, per-unit reservation sufficiency, real source/prefix/reference/security/loaded-authentication evidence, lock/deadlock/timeouts and frozen047PG14-to-PG16 schema equivalence remain unverified. Real behavior/concurrency/recovery/performance/application acceptance still pending. New DDL/DML/query families require independent review, not automatic enablement.

Next separately authorizable stage after source/package review: **F infrastructure only**, fresh daemon/local16.15image/collision56043/capacity/resource preservation gates, dedicated new F credentials/project/volume/network/limits and explicit ordinary NAT bridge egress approval. Stop before database authentication or047installation. Later fresh Fidentity/auth/freshness and each source-specific validate/execute/readback action need separate reviewed sources/manifests. No automatic progression.

[Protected complete review package](/Users/ferozebasha/.sbom-uuid-w2-review/w24c-20261019T053937635357Z/w24c-source-review-package.json) — byteSHA256 `6e7b633e17ea2ff63c137c8f6829222999bae45b5dca6309122476da1f8b14df`. Review expiry `2026-10-20T05:55:14.107395+00:00` is source-review metadata only, not execution authority or renewal.0700private directory/0600files. Contains all15fullsources/diffs/hashes, nine future-copy sources/full diff, source-lock transition, installed dependency evidence, exact results/development failures/recovery/runtime limitations. Execution actions empty/sevenintegrityflagsfalse.

**STOP for independent source/package review.** F NOT CREATED; frozen047 NOT RUNTIME ACCEPTED;193LIVEcases NOT EXECUTED.


Final W2.4C preservation: PASS. All2,178other contents from2,179existing files unchanged; tracker is sole existing append and retains original bytes as its prefix. Exactly16new files (15transaction-correction artifacts+report33), no missing baseline file. Branch/HEAD, original W2.1–W2.4B packages/source locks, all migrations080–091/oldguards/frozen047/app/Compose/earlier evidence unchanged. Future execution-copy destinations absent. Package bytes/hashes/all15sources/full diff hashes/0700-0600private permissions verified.692OFFLINE tests PASS/0FAIL/0SKIP. No PostgreSQL/Docker/realcredential/migration/provisioning/promotion/app/Gitdelivery activity. Package remains6e7b633e17ea2ff63c137c8f6829222999bae45b5dca6309122476da1f8b14df; STOP independent review. F NOT CREATED; frozen047NOT RUNTIME ACCEPTED;193LIVEcasesNOTEXECUTED.
