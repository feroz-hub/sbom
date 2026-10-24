# W2.5 — Frozen047-only first installation proposal

OFFLINE IMPLEMENTED; no write/readback authority is issued by these sources.
F identity/freshness was actually accepted in W2.4E.2. Frozen047 is NOT runtime
accepted. No database/Docker/credential operation occurred during W2.5.

## Narrow integration and unchanged history

This directory is a new source-specific consumer, not an in-place patch or
activation of W2.3/W2.4A. `retained-inputs.v1.json` preserves179 exact historical
inputs, including the113 W2.3 pins, the original W2.1–W2.4C adapters/locks,
001–079 and staged080–091. Original sources/review packages remain unchanged.
`w25_inputs.py` verifies those bytes and loads enumerated inert module groups
with isolated names. It never imports application settings, app models, the
historical001 implementation, private W1.7 helpers or any migration upgrade().
No active Alembic promotion, ORM create_all or later revision selection exists.

The original W2.1 SQL and12 directive adjustments remain exact. The558 ordered
statements comprise12 bounded transaction-local SETs and546 object definitions.
The original047 snapshot and proposed execution SQL hashes remain unchanged.
The parser is statement framing plus a bounded parser for this exact pinned
snapshot, NOT a general PostgreSQL grammar or a semantic-equivalence proof.
No rows, sequence positions, passwords, old ownership or grants are imported.

`w25_schema.py` derives all columns/defaults, PK/UK/FK/CHECK definitions,
sequences/ownership, btree/GIN opclasses and partial indexes from that source.
With the separately created marker:46 tables,728 base columns,34 sequences,
160constraints and333public indexes are expected. These are SOURCE-DERIVED,
not measured F values. All45 application tables, including the audit table,
must remain empty. Required authorization catalog/reference initialization
begins later at048; no users, admins, tenants, memberships or seeds are created.

## Authority and adapters

A future operator must independently approve each exact protected manifest's
original raw-byte SHA256, fresh UTC expiry, all eight review areas and distinct
unit_execute or unit_readback reference. Candidate accepted=false and seven
integrity flags false/actions empty remain unchanged. The public pending file
is a non-executable schema template; the protected target-specific candidates
bind the actual proposed source-lock hash. Original F read-only approval is
spent and only supplies historical acceptance evidence, never write authority.

Source-lock, SQL allowlist, derived model and versioned budget must all agree
with actual current retained/new sources. Duplicate keys/symlinks/wrong private
permissions, source drift, target/resource/credential/role/security changes,
missing/expired action or an unsupported unit fail closed. Accepted F evidence
must match its actual74-record hash chain and committed STOP/rollback/close.
New manifests bind F OID16384/systemID7698258353561202726/PG16.15 at
127.0.0.1:56043, databaseuuid_w2_f_fresh/useruuid_w2_f_bootstrap.

Future live mode refreshes the original local Desktop/container/image/network/
exclusive-volume/publication/mount/credential metadata gates, then performs the
existing bounded in-memory secret correlation. No secret contents/digests,
kwargs or DSN are logged. It requires actual libpq used_password, exact native
backend/version/API and complete installed compiler/driver source pins. HBA
file parse/content and SCRAM storage remain limited evidence, not full loaded
HBA policy or exact wire mechanism proof. Current bootstrap is privileged;
restricted application/runtime role creation is a separate later task.

Fixed host+hostaddr/port/database/user, passfile/dev/null, no service keyword,
SSL/GSSdisabled, clean environment, five-second connect. No PG*/dotenv/service/
application fallback. Native autocommit=False, READ_COMMITTED=2, explicit native
read_only property, prepare_thresholdNone. Startup default_read_onlyon,
statement30s/lock1s/idle30s, row_securityon/check_function_bodieson,
search_pathpg_catalog/stats_fetch_consistencynone. No environment or engine
factory selection is accepted from a manifest.

The exact W2.4C Driver/Session/recipe and dedicated metered dialect subtype are
reused, not copied or monkeypatched. Manual Engine/NullPool/Connection construction
avoids ordinary Engine.connect initialization rollback/reconnection. Full actual
dialect initialize() runs inside the owned initial RO logical transaction. Its
five known SELECT/SHOW calls plus optional approved paths have16 reserved queries.
All other/unknown initialization, reflection, native cursor, protocol and batch
operations stop at the exact driver allowlist/meter. No raw proxy unwrap.

## Single-unit lifecycle

1. Claim a private O_EXCL/fsynced/hash-chained attempt file; record exact authority.
2. One constructor, one connection/creator. Own initial SQLAlchemy RO transaction;
   psycopg implicitly starts it at the first metered read, counted before driver.
3. Collect30 complete fresh/security/ACL observations and compare with actual
   accepted F evidence, changing only explicitly approved transaction settings.
   Roll back this RO transaction; require idle state and logical closure.
4. Own one RW transaction. Its first SELECT acquires advisory7160085085. Recheck
   source/resources and30fresh observations in actual read_write state. There is
   no pre-existing application/version table to lock. Operator-reviewed exclusive
   DDL window is mandatory; observed writer absence is not a concurrency proof.
5. Recheck raw authority/source, execute only558 immutable ordered statements.
   Per-statement time/quota/expiry checks; complete source revalidation before
   marker creation and again before INSERT/COMMIT. CREATE version table only
   after all558 succeed. That new CREATE holds ACCESS EXCLUSIVE until commit.
6. Reset transaction-local search_path. Read81 bounded post-schema observations,
   exact source-derived object/security model and45business emptiness checks.
   Require the newly created version table has ZERO rows, not a fabricated marker.
7. One parameterized INSERT of047_email_verification_tokens, exact rowcount1 and
   RETURNING. Independently SELECT its sole row in the same transaction. Recheck
   source/resources/authority/window, durable COMMIT intent, owned commit.
8. Known acknowledgment/IDLE only; physically close first, then logical cleanup
   and engine dispose. Recheck resource preservation and durable STOP. Successful
   write returns COMMITTED_UNVERIFIED, accepted=false. No automatic second session.
9. A separately approved invocation verifies the exact original write journal,
   its original approved manifest/action/source hash,558/marker/commit/close proof,
   then opens ONE independent RO connection. Collect81 checks plus initialization,
   sole047 row and identical schema fingerprint; roll back, close/dispose,
   preserve resources and durably STOP before overall acceptance can be returned.

Readback candidate has a pending actual-write evidence SHA. Populate it only
from separately reviewed known committed/closed write evidence, never invent it
before execution. Source/plan values are not substitutes for runtime observations.
No downgrade, restore, marker repair, cleanup, recreate or automatic retry exists.

## Versioned observation accounting

W2.4B original files/limits remain unchanged. The new one-unit proposal keeps
write256 catalog queries and all original non-query ceilings. Three actual write
passes are30preflight +30locked +81post; two coordinator queries (advisory/marker)
plus five known initializer reads =148 at the driver boundary.16 initializer
slots remain reserved; phase ceilings54/54/81/2/16 sum207 (round8=208), below256. Body query
cap0;558body statements (including12SETs),2marker statements, at most2extra
session statements,4controls. Real driver SQL executes/metering exactly once.

New post accounting:30 catalog keys (richer base-table-column projection), five
additional structural queries,45 EXISTS checks and one marker SELECT =81.
All audit/business tables are checked. Compared with old post/readback75 this
requires81; readback16+81=97, rounded up to104 instead of old96. These are NEW
source-specific proposed authority values, not silently increased old budgets.
Readback has an additional hard two-control bound and EMPTY migration/marker/
session allowlists even though retained legacy non-query quotas are larger.
Each connection owns its own budget; unused phase capacity cannot be borrowed.
No arbitrary WITH/VALUES/EXPLAIN/COPY/CALL/multi-statement SQL, wildcard hashes,
allowlist learning or reflection expansion is permitted.

Per-query1024rows, per-action8192observedrows, cooperative120s. This is not a hard
process-kill/COMMIT deadline; bounded cleanup may finish later. Timeout/exhaustion
stops before the next driver call, then rolls back known precommit work if safe.

## Model normalization and PostgreSQL16 assumptions

Source definitions are executed byte-for-byte. Only expected/observed catalog
comparison normalizes unquoted token case/quoted identifiers and balanced outer
expression parentheses; literals and interior precedence remain intact. CHECK
referenced-column sets are sorted; PK/FK/index column ordering is retained.
Unknown pg_get_expr/deparse/type/collation/ACL/opclass representation stops.
There is no permissive parser fallback or runtime allowlist learning.

TOAST is PostgreSQL relkind t, not r. Internal TOAST names/OIDs are not invented;
observed table/index pairs must correlate exactly with source-derived public
parent relation OIDs, ownership, methods and dependency edges. See PostgreSQL16
[pg_class](https://www.postgresql.org/docs/16/catalog-pg-class.html) and
[REL_16_15 toasting.c](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/catalog/toasting.c).
Tables/indexes/sequences retain ordinary fresh storage flags/ACLs; no other
namespace, orphan/duplicate child, foreign object, user function/trigger, RLS,
partition, inherited object or role/security difference is accepted.

Actual PostgreSQL16 DDL grammar, PG14-dump-to-PG16 equivalence/deparse, native
adapter/dialect, physical implicit BEGIN/COMMIT/rollback, table/TOAST storage
representation, resource/time sufficiency, locks and recovery remain runtime
acceptance work. Passing mocks or compiler checks do not accept these.

## Commands and STOP

    .venv/bin/python -B infra/uuid-migration/frozen047-execution/w25_entry.py --mode offline
    .venv/bin/python -B infra/uuid-migration/frozen047-execution/test_w25_offline.py

Future invocation contract ONLY after separate exact original-byte approval:

    env -i HOME=/Users/ferozebasha PATH=/usr/bin:/bin:/usr/local/bin LC_ALL=C \
      PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 \
      /Users/ferozebasha/sbom/.venv/bin/python -B \
      /Users/ferozebasha/sbom/infra/uuid-migration/frozen047-execution/w25_entry.py \
      --mode live --action unit_execute --manifest OPERATOR_APPROVED_PRIVATE_FILE \
      --manifest-sha256 OPERATOR_APPROVED_EXACT_RAW_HASH \
      --approval-reference OPERATOR_ISSUED_W25_WRITE_REFERENCE

Readback is a later separate invocation with unit_readback and its own approved
raw manifest/reference/evidence hash. No operator values are generated here.
No arbitrary revision argument exists. STOP after this source/package review.
