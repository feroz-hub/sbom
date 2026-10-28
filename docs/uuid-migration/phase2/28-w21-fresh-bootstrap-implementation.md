# W2.1 — Explicit fresh PostgreSQL bootstrap implementation

2026-10-18. **IMPLEMENTED (STAGED) / OFFLINE VERIFIED.** Branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`. This accepts the offline adapter, source representation and tested contracts only. Frozen047 is **NOT runtime accepted**, F is **NOT created**, E remains **BASELINE NOT ACCEPTED**, and all193 live UUID integrity cases remain **NOT EXECUTED**.

## Authority and preserved baseline

The operator authorized new isolated source/tests, an offline source-review package and documentation. The selected future installation sequence is frozen047 →048–079 →080–085 →separately implemented final UUID constraints. Legacy business-data transfer and UUID backfill are NOT REQUIRED for this fresh-install path. Existing deployments are not authorized to reset/rebuild through this path.

W2.1 prerequisites/scope/acceptance were recorded in the tracker before implementation. Verified branch/HEAD and snapshotted2115 existing repository files. Reviewed W2.0 report27 and the actual frozen snapshot/bootstrap/env/001 sources; all active and staged declarations and relevant frozen seed dependencies; prior Phase1 final audit/impact CSV, W0.2/W1.1 and W1.6/W1.7 reports remain the contract/history references. No historical migration, snapshot, bootstrap helper, app model/router/frontend, deployment configuration, prior report or private historical evidence was edited.

No PostgreSQL connection or tool, Docker command, real password read, Alembic operation, actual SQL execution, role/seed/marker operation, application startup, F provisioning or live integrity case occurred. The tests import only new inert code and approved third-party compiler code; historical migrations/private helpers are never imported or executed. Synthetic temp JSON is the only credential-like fixture input, with no real credentials.

## Actual delivered files

All eleven files are new under [fresh-bootstrap](/Users/ferozebasha/sbom/infra/uuid-migration/fresh-bootstrap/README.md:1).

| File | Implementation / SHA256 |
| --- | --- |
| `fresh_bootstrap.py` | Offline CLI, exact source/graph and approval checks, frozen dependency alternatives,39-unit schedule, reference contracts, budget and transaction-receipt state machine. `d4923784933be1158971fae02f7a0e1c08d898f80b14a10d9cc61ef219c288a1` |
| `fresh_catalog.py` |24 future fixed catalog SELECTs and pure fail-closed freshness validation. `17857e2c5c466e35e901b57b1253cd2f9cf2cea9539fcfe23635874b33219e38` |
| `frozen_047.py` | Exact pinned-snapshot statement/directive inventory and deterministic representation/diff. `fd8bf95c9b19b186aa26940541bd7d19d66df7c357d073ff7cced5dd1d332f56` |
| `pg_lex.py` | Conservative quote/comment-aware SQL framing; no execution or grammar claim. `db772d767b2157609f00402362b95969196b5dc3e4bfc4b1909c3d775617817f` |
| `test_fresh_bootstrap.py` |102 offline unittest cases and compiler checks. `fdbc5e9403ce9ae2753ee43fcec4ede0f5d1ec95e2865f0cec5b2e862a26ca27` |
| `source-lock.json` |93 immutable historical source pins, itself hard-pinned by adapter. `ea4307ed66a08da663b3826f9bdf34e3cc72849e610a5f8f70e105731ff1f632` |
| `047-execution.proposed.sql` | Review-only proposed execution text. `6173c58cca7061483edd1b69e9edd0c431eee808f46ae1021293549d13e8c900` |
| `047-transformation.diff` | Complete original-to-proposed directive diff. `69d6a2bc019bbd991dcfe3b269938992be7d516e0cd9277381859f503ac63ce7` |
| `approval.schema.json` | Future F manifest schema; Python validator adds exact-byte/expiry/source constraints. `33e29359332abbb3c82948107ba53014746a49e9b1cd2366632a3cdcdc9b6b9c` |
| `approval.pending.json` | Deliberately unusable template, unknown real F identities/expiry/credentials, empty actions. `e9fb42a512c36a43b8b2f88102393f79bdb0f24949c59e00741683cca6d523db` |
| `README.md` | CLI, scope, safeguards and integration limits. `ff30db77d2867ad71196c6881b82834edc5f9a493e4a7f0c6fa1bcdc540dd68b` |

Also created this report and updated the master tracker. Full new-file source/diffs and hashes are embedded in the protected package below. No files were promoted into active Alembic discovery.

## Frozen047 source and transformation

Actual original SQL hash matches the operator pin: `e310421b5fea4ef93056be590756125726280671589b50d93aa85926b9833c09` (143832bytes). Original bytes are unchanged and copied as nonsecret source evidence into the protected package directory.

The implementation frames the exact file into558 statements. Twelve are the exact reviewed session directives;546 are object statements:45 CREATE TABLE,34 CREATE SEQUENCE,34 sequence OWNED BY,162 ALTER TABLE,266 CREATE INDEX and5 CREATE UNIQUE INDEX. The package contains every statement's order/token inventory/hash and135 derived FK/sequence-ownership/sequence-default dependency edges. These are source inventories, not a live catalog or a complete PostgreSQL semantic dependency proof.

Transformations match **complete lexer token sequences** and replace only the directive spans, retaining leading comments/whitespace. All546 object statements are compared byte-for-byte, in order, between original and proposed output. Any changed original byte hash, unexpected family/directive, repeated/missing directive, statement count or object-byte/order mismatch refuses. Saved proposal/diff must also exactly match recomputation.

| Original setting | Proposed one-owned-transaction setting |
| --- | --- |
| statement_timeout=0 | SET LOCAL statement_timeout='30s' |
| lock_timeout=0 | SET LOCAL lock_timeout='1s' |
| idle_in_transaction_session_timeout=0 | SET LOCAL idle_in_transaction_session_timeout='30s' |
| search_path='', session set_config | SET LOCAL search_path=pg_catalog,public |
| check_function_bodies=false | SET LOCAL check_function_bodies=on |
| row_security=off | SET LOCAL row_security=on |
| client_encoding/standard_conforming_strings/xmloption/client_min_messages/default_tablespace/default_table_access_method | Same values, changed to SET LOCAL |

No INSERT/COPY/business rows, sequence current positions, credentials, owner remapping, ACL suppression, extension creation, DROP/CASCADE, arbitrary SQL or manual revision stamp is admitted from this snapshot. The single parameterized047 marker operation is a **separate transaction contract**, not imported historical data.

`pg_lex.py` handles standard quoted strings, doubled quotes/identifiers, E strings, tagged/untagged dollar bodies, line comments and nested block comments. It rejects unsupported prefixes/ordinary backslash ambiguity, psql commands, NUL, unterminated statements/strings/comments and empty statements. It is **not a general PostgreSQL parser**. Generic framing support does not authorize function-body transformation: only the exact pinned snapshot and its explicit families are eligible. No naive semicolon split or unrestricted string replacement is used.

**Equivalence limit:** the original is a PG14.18 dump; the proposal targets16.15. No PG grammar/parser execution,047 semantic schema parity, function resolution, settings acceptance, DDL timing or runtime ownership equivalence is proved offline. `pglast`/`sqlparse` are not installed; no dependency was fetched. Fail-closed exact-byte object preservation is established, so the review representation is available; actual PG16 grammar/equivalence is still a mandatory future gate, not claimed ACCEPTED or bypassed.

## Isolation, dependencies and migration sequence

Imports are inert stdlib/new pure modules only. There is no psycopg/engine/Docker wrapper/credential reader, old PLAN, historical private helper, dotenv loader, app settings import or application startup. `--mode live` **unconditionally refuses before source/manifest/resource/credential reads**, even if a caller supplies an otherwise approved contract. Offline mode only reads pinned repository sources and prints nonsecret summary JSON.

Source-lock pins79 active revisions, six staged revisions, snapshot, two frozen seed modules, inert app package initializer, current Alembic config/env and old bootstrap scripts. Discovery rejects any changed/missing/symlinked source or extra active/staged Python revision. AST graph inspection gives one linear001–079 graph plus immediate080–085; the archive monolith cannot enter that file set.

The normal env imports app.models/app.db and dotenv;001 calls live Base.metadata.create_all. Neither is loaded by this adapter.048 imports frozen seed_v1 and064 imports frozen seed_v2. The new adapter evaluates only literal containers/references/frozenset(literal) from those pinned modules; unreviewed expressions/imports fail. It constructs deterministic **inert source alternatives** replacing only those import bindings with frozen values. Complete diffs/hashes are in the package; tests prove other migration AST bodies unchanged and values preserved. AST unparse re-renders formatting, so these are reviewed alternatives, not byte-identical historical files. They are never registered/imported/executed. A future Alembic Operations/context binding and runtime loader requires separate source review; no hidden application import is used to bypass that work.

Schedule contains39 units: frozen047, each of32 revisions048–079, then six080–085. Every unit has one owned transaction, explicit predecessor/next, new process, advisory serialization7160085085, freshness recheck under lock, commit acknowledgment, physical write close and separately approved independent read-back. next_only logic rejects head/heads/ranges/skips/replays. Final UUID constraints are explicitly NOT IMPLEMENTED and require later reviewed revisions; no086 number is reserved.

All six staged migration bytes freshly equal report10/operator pins:

|080|081|082|
| --- | --- | --- |
|`2fc6e6f9992d0763ddf6818b9e7b62d573eef2b7cda01a39689b8fffcbc623f8`|`28f803f5c5c439f1ae0f0fdb0748368b244c2c31b060bb1a61ff6302a3d2d95e`|`76d830f79e699cbdd5116c1e848cc5923f10281a764a17f0abd6c1cf8c4b5ace`|

|083|084|085|
| --- | --- | --- |
|`d7f8dbe4c262f4a045572c173b7fd61e38d003fa87f9ec28093427161234495e`|`13a84b0d6d3201a64be7ba90a32560a5c5738a319be1fc8af29d2364aec49803`|`45f331390609e52ceddbf0968651b5ec817bf26811f6f67845d1fb6d99cdbb0f`|

They still implement nullable/nonunique/NOT VALID expand with allocator and immutable guard, and fail-closed downgrades; no index/backfill/NOT NULL/CHECK validation/ORM change occurred. Their PG16 and plain-table/trigger/function/transaction prerequisites remain actual execution gates. This adapter does not reuse D-only execution authority or E-only integrity guards for F.

## Complete freshness and security observation contract

Twenty-four fixed catalog SELECT templates cover identity/control-system/dbOID/version/read-only/recovery/interface/storage; schemas; relations including views/materialized views/sequences/indexes; functions/ACL/security properties; types/domains; operators; custom collations/conversions/access methods/opclasses/opfamilies/text-search/casts/transforms/languages/large objects/security labels; triggers/rules/event triggers; extensions; foreign wrappers/servers/mappings; publications/subscriptions; roles and password NULL/SCRAM booleans; memberships; database ownership/ACL; default ACL; per-role/database settings presence; shared dependencies; effective selected server settings; current HBA file rules/parse; competing clients; locks; Alembic relation absence.

No role password, subscription connection info, foreign-server options, mapping credentials or business row is selected. `pg_roles.rolconfig IS NULL` is separate from `pg_authid` password booleans, preserving the42703 lesson. SQLAlchemy compilation only validates client constructs, not catalog-column existence/permissions; insufficient privileges/errors must fail, never become empty lists.

Validation requires exact PG16.15/database/user/session user/cluster/dbOID/internal endpoint/PGDATA and READ ONLY/nonrecovery; expected system namespaces, sole plpgsql1.0 in pg_catalog, no partial application/other user objects or marker, no competing client/locks and no unapproved role/settings/default grants. Roles/ACLs/memberships/shared dependencies/settings/HBA metadata must exactly equal independently approved observations. No E/F identity is invented; a pending empty metadata object cannot stand in for live evidence. Scope includes system-namespace user-created objects by catalog identity filters. No broad “all pg_* is safe” namespace waiver is used.

HBA rows prove current file contents/parse only. Successful connection creation with a supplied password would not alone prove a password challenge or whole last-loaded HBA policy. A separate reviewed effective-authentication evidence reference is mandatory; this code cannot autoaccept missing evidence or reload configuration. D's historical plpgsql-owner exception does not transfer to F. Owner/ACL/security policy and expected fresh cluster/system role metadata require review before a real target can qualify.

## F approval and transaction contracts

F proposal remains `127.0.0.1:56043`, `uuid_w2_f_fresh`, `uuid_w2_f_bootstrap`, project `sbom-uuid-w2-f`, service `postgres_f`, new volume `sbom-uuid-w2-f_f_pgdata` and sole network `sbom-uuid-w2-f_f_access`. Availability/daemon/image/container/network/storage/secret provenance are unknown until a later approved preflight. The contract requires the separately verified local Desktop Unix socket/daemon, exact new resource pins, credential metadata reference and no D cluster reuse. It creates no credential or Docker configuration.

The pending template has accepted=false; five source/target/credential/role/egress attestations false; real cluster/dbOID/internalIP/resource/credential/effective-auth/post047-catalog/expiry fields null; action approvals empty; seven integrity attestations false and integrity approvals empty. No action reference or operator-approved manifest hash has been issued. Review-package expiry below is **not** an execution approval expiry or renewal.

The pure future manifest validator requires exact field set, fixed target/connection/budgets, exact source map, externally supplied raw-file SHA256, duplicate-key refusal, aware unexpired UTC, distinct action references and explicit reviews. Private JSON must be0700 parent/0600 owner regular nonsymlink single-link bounded file; the same exact bytes are reread and compared immediately pre-authentication. Canonical JSON digest is distinct and cannot replace raw SHA. No service keyword, passfile fallback, ambient PG*/DATABASE_URL/dotenv/PYTHONPATH/remote Docker target is admitted. Approved future connection defaults READ ONLY; only a separately authorized install transaction uses BEGIN READ WRITE.

Budgets: one constructor attempt/concurrent connection per unit phase;5sconnect,64catalog queries/four controls,30sstatement/1slock/30sidle and120s cooperative unit window. The558 exact schema statements are a separate fixed DDL budget.080–085 keep their stricter source caps. Cleanup remains mandatory after deadline; no hard network/COMMIT wall-clock guarantee is claimed. Validation/install/read-back are distinct action categories and separately scheduled connections, never an implicit hidden second connection or automatic retry.

`UnitContract` is a **pure receipt state machine**, not a fake runtime executor. It requires freshness/authority before BEGIN, correct transaction advisory-lock receipt plus recheck before any statement acknowledgment, all ordered source statement receipts before exposing CREATE version-table and parameterized INSERT047 instructions, exact rowcount/RETURNING/schema verification before precommit, COMMIT request/ack and physical-close receipt before independent approved read-back. Marker publication never precedes schema completion; no stamp079/085 or historical replay is available from it.

Failures before BEGIN stop without pretending a transaction exists. Known precommit failure requests ROLLBACK; rollback acknowledgment is distinct from an unconfirmed rollback. COMMIT_PENDING failure becomes UNKNOWN_COMMIT_STOP, no rollback claim/retry; acknowledged-but-unverified commit preserves committed state. A new independent read-only schema hash/sole047 marker/read-back-close receipt is required for mock-contract VERIFIED. All such results explicitly retain runtime_accepted=false. A future coordinator must actually implement locks/SQL/commit/driver closure/evidence and verify receipts, not manufacture them. Privileged concurrent DDL is outside cooperative advisory locking and requires an exclusive reviewed window.

## Reference and Native initialization contract

The adapter derives048's exact frozen roles/scopes/permissions/mappings and seed-audit action; final intended role-permission sets through064–068/075; role version expectations PLATFORM_ADMIN4/TENANT_ADMIN4/SECURITY_ANALYST3/DEVELOPER2/VIEWER2. These are source-derived fresh-chain expectations, not observations of F. Future validation must also check protected grants/status/system/assignability semantics and exact source seed versions; role counts alone are insufficient.

No old identities or memberships are needed. Necessary new authorization/reference/security rows and audit evidence are not legacy business-data transfer. CycloneDX/SPDX/provider/config defaults and Native one-time administrator enrollment/activation/outbox/Argon2id/platform grant are separate explicitly authorized initialization after final constraints. No customer tenant, user, password, member or admin grant is created by W2.1. Auth-enabled/fail-closed tenant/catalog/native settings, separate signing/encryption/session secrets, isolated worker/Redis/mail/storage and role privileges still require reviewed future configuration. Existing Native JWT subject and external issuer/subject semantics are unchanged.

## Actual offline results

| Check | Result |
| --- | --- |
| Dedicated unittest suite | **102PASS /0FAIL /0SKIP**; synthetic metadata/manifests/receipts only |
| Inert import/live refusal | PASS: denied credential/file/network/process access during import; no app/driver runtime; live CLI refuses before source reads |
| Source/schedule | PASS93historical pins,79active/sixstaged/combined085,39explicit units, frozen seed literals/alternatives and unchanged bodies |
| SQL representation | PASS558framed/12directives/546exact object statements; saved SQL/diff hash equality; no row/sequence-position import |
| SQLAlchemy offline compilation | PASS24catalog templates and version-table VARCHAR128 PK DDL; no engine/connection. Two inert Python migration alternatives compiled in memory, never executed |
| Python source AST | PASS90modules:79active/sixstaged/five new; no historical module import |
| Ruff | New five Python modules lint and format PASS; old hash-pinned migration import-order warnings not changed or represented as fixed |
| Whitespace/preservation | Final verification appended below; no existing source changes permitted |

Exact commands, run from repository root:

```sh
.venv/bin/python -B infra/uuid-migration/fresh-bootstrap/test_fresh_bootstrap.py
.venv/bin/python -B infra/uuid-migration/fresh-bootstrap/fresh_bootstrap.py --mode offline
.venv/bin/python -B -m ruff check --no-cache infra/uuid-migration/fresh-bootstrap/
.venv/bin/python -B -m ruff format --check --no-cache infra/uuid-migration/fresh-bootstrap/
git -c core.fsmonitor=false diff --check
```

Development evidence preserved: initial84cases83PASS/one ERROR because synthetic macOS `/var` path traversed a symlink; canonical test path fixed without relaxing guard. Initial4I001 new-file import warnings fixed in new files only. Intermediate85PASS; expanded96cases95PASS/one ERROR on malformed catalog schema row KeyError, corrected to explicit Refused;96,101and final102PASS. Two patch-context mismatches changed no file and were reapplied after reading formatted source. No failure is relabelled as a PostgreSQL result. Existing operational/greenfield tests that create databases, all193 live cases and application suites were not run.

## Protected independent-review package

[w21-source-review-package.json](/Users/ferozebasha/.sbom-uuid-w2-review/w21-20261018T164159255183Z/w21-source-review-package.json)

- Exact byte SHA256: `7b524fd8484116a4190b4dfeb98edb7324bdca38b1ddd4989b5f13a236080b34`.
- Review expiry: `2026-10-19T16:52:12.897510+00:00`, **not execution authority**. Future action/template expiry remains unissued/null.
- Directory0700/files0600; current operator UID. Includes complete11new files and diffs/pins, original snapshot plus proposedSQL/full transformation diff/inventory/dependency edges,93historical pins,39unit schedule, source-frozen seed alternatives/full diffs/reference expectations, complete102test output/static results, F manifest/schema/budgets/transaction and recovery limits, zero live activity and outstanding blockers. Initial failed test/lint outputs and later development output remain separate files.
- Pending template byte hash `e9fb42a512c36a43b8b2f88102393f79bdb0f24949c59e00741683cca6d523db` is an artifact hash only. Never use it as operator execution approval.

## Remaining limits and next independent decision

The offline contracts and reproducible representation are implemented. Live resource/secret observation, actual database driver lifecycle, isolated Alembic binding/loader, semantic post047 normalization and execution evidence are **not implemented as connected operations in this build**. The entrypoint intentionally cannot execute. Independent source/package review must precede a separately scoped connected integration; no flag or manifest alone can enable it.

047 runtime grammar/equivalence and the session changes require actual separately approved PG16 acceptance. Fresh F remains nonexistent/unverified; expected semantic047 catalog is not invented from a marker. Historical C-B concerns and E authentication/restore failures remain historical unresolved scope. Active080–085 registration, final uniqueness/NOT NULL/CHECK validation, drift corrections and ORM/API/frontend/native integration are later separate work. Source-only seed alternatives require review before use, not an edit to historical migration provenance.

**STOP for independent review of this W2.1 source/package.** No automatic W2.2 or F provisioning. W2.1 IMPLEMENTED (STAGED) / OFFLINE VERIFIED; frozen047 NOT runtime accepted, F NOT created, E baseline NOT ACCEPTED and193live UUID integrity cases NOT EXECUTED.


Final W2.1 preservation verification: PASS. Exactly11new fresh-bootstrap artifacts, report28 and tracker update;2114other baseline file contents, branch/HEAD, immutable snapshot/001–085 and all previous reports preserved. All prior nonempty tracker lines retained. Package/source/test/SQL/diff/pending pins/private0700-0600 modes and Git whitespace PASS. Initial final-checker plain-file whitespace assertion incorrectly rejected unified-diff context-only space lines; checking added lines plus exact pinned diff bytes resolved the checker without modifying the diff or source. Protected final26-artifact evidence-manifest SHA256 `958ecf2b0ce292c96e85da2b8a62c986b7be79cb9b578b024bb9499ef9ca537f`; package SHA remains `7b524fd8484116a4190b4dfeb98edb7324bdca38b1ddd4989b5f13a236080b34`.102offline tests PASS/0FAIL/0SKIP; zero PostgreSQL/Docker/real-credential activity. STOP independent source/package review.
