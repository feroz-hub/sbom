# W2.4C transaction compatibility proposal — OFFLINE ONLY

No runtime provider is wired; both CLIs deny live. These files neither replace
W2.4A nor apply W2.4B's patch. No guard, migration, old lock or approved package
is edited. Pending review is not execution authority.

## Confirmed conflict and selected model

All twelve pinned 080–091 transaction guards require DBAPI autocommit=False,
SQLAlchemy in_transaction()=True, isolation != AUTOCOMMIT and transactional DDL.
W2.4A Driver requires True, create_engine specifies AUTOCOMMIT, and its literal
BEGIN does not change those Python properties. Thus the existing combination
fails before a UUID body can execute. Merely flipping the boolean would also
introduce psycopg implicit BEGIN before literal BEGIN; normal SQLAlchemy engine
initialization has a finally/do_rollback that adds a transaction boundary.

The proposal uses a fresh dedicated connection with autocommit=False,
psycopg READ_COMMITTED (enum value 2), read_only=True initially. Preserve exact
F host/hostaddr/port/database/user/passfile/SSL/GSS/session options, clean
actual environment, five-second connection bound, authority/resource/secret
correlation and one connector attempt. No credential provider is implemented.
New client preparation policy prepare_threshold=None prevents automatic prepared
statement/cache maintenance commands. This is a proposed, separately reviewed
source change, not permission to alter old approved constructor semantics.

1. Construct a dedicated SQLAlchemy Engine + NullPool + Connection explicitly.
   No Engine.connect() automatic initialization/rollback hook is registered.
   NullPool has reset_on_return=None; its sole creator returns the one metered
   Driver once. _allow_revalidate=False refuses reconnection. on_connect adapter/
   notice setup occurs while IDLE with no SQL owner; SQL then fails closed.
2. Session.begin('ro') owns a genuine SQLAlchemy RootTransaction. begin() itself
   sends no wire BEGIN. The first reviewed driver query reserves its query and
   implicit BEGIN control before raw execution. Psycopg emits BEGIN ISOLATION
   LEVEL READ COMMITTED READ ONLY. Never send a second literal BEGIN.
3. Call the complete dialect.initialize() inside that transaction, under the
   W2.4B initialization phase (16-query ceiling), then full preflight under its
   own phase. Never fake dialect server version/schema/isolation discovery.
4. SQLAlchemy transaction.rollback() calls the owned DBAPI rollback exactly once.
   Confirm backend IDLE and logical transaction closed. Only now set native
   read_only=False while IDLE; default_transaction_read_only=on stays unchanged.
5. Own a new SQLAlchemy RootTransaction. First advisory SELECT starts explicit
   READ WRITE at psycopg's implicit boundary. Version EXCLUSIVE NOWAIT and all
   reviewed table locks, locked reinspection, exact frozen558/one isolated
   Operations upgrade, post-body checks and parameterized guarded marker remain
   in this same PostgreSQL transaction. Shared binding sees the real connection,
   autocommit=False, non-AUTOCOMMIT options and in_transaction=True.
6. Revalidate actual authority/source/target, durable COMMIT intent, then owned
   SQLAlchemy transaction.commit(). DBAPI call/IDLE return determines known ack.
   No acceptance until physical closure and a separately approved readback.

Write controls: implicit RO BEGIN + ROLLBACK + implicit RW BEGIN + COMMIT = 4.
On known precommit failure the last COMMIT slot is instead ROLLBACK. Separately
approved validate/readback has its own one-connection budget and two controls.
No quota increase or extra catalog query is needed by this transaction change.
Driver executions, not wire Parse/Bind protocol frames, are SQL budget units.

## Native discovery and conservative driver boundary

Installed psycopg TypeInfo.fetch requires a native Connection, opens
conn.transaction() (nested SAVEPOINT when already INTRANS) and constructs a
native Cursor outside the proxy. Unwrapping would defeat both budgets and
transaction ownership. `dialect.factory` proposes a new dedicated subtype,
without patching SQLAlchemy: its sole hstore discovery uses the same PG16
catalog projection/to_regtype predicate through the owned SQLAlchemy connection.
Zero rows remain None; one row builds actual TypeInfo; ambiguity/error refuses.
Native hstore adapters remain enabled and registered by the original initializer;
no extension is created. No SAVEPOINT, extra connection or native cursor bypass.
The exact new source/compiled driver SQL must receive independent allowlist and
source review; runtime PG16 semantic equivalence is NOT established offline.
Unknown native helper/type lookup/cursor factory/protocol still fails closed.

The installed complete PostgreSQL psycopg dialect initialization is exercised
with synthetic cursor results: four core SELECT/SHOW plus the one metered hstore
query, one implicit BEGIN, no intermediate rollback. This is not authentication
or PostgreSQL server acceptance. A second test uses real SQLAlchemy transaction
and Alembic Operations objects on a synthetic DBAPI connection. No migration
source upgrade() body is executed in this task.

## Metering, evidence and recovery

`metering.wrap` composes around the unchanged W2.4B ScopedMeter, which composes
around the pinned W2.4A Meter. SELECT/SHOW always charge query quota, phase and
global once. Reflection and dialect initialization cannot escape. Exact one-
statement framing and exact SQL hash/category allowlists remain mandatory;
materialized executemany reserves each execution, unknown/unbounded work refuses.
WITH (including modifying CTE), VALUES, TABLE, EXPLAIN (including ANALYZE), CALL,
COPY, literal transaction SQL, unknown families and multi-statements are refused
before raw execution even with an exact hash. None is silently charged as DDL.
CREATE/ALTER/DROP/COMMENT/DO/INSERT/UPDATE/DELETE/SET/LOCK still require their
exact approved non-query scope/hash and an owned RW transaction. Embedded SQL
inside one reviewed DO/DDL statement is one driver call, not extra client queries.

One durable journal is mandatory for meter + transaction kernel. Reserve/log
before driver operations; commit_sent is set only immediately before DBAPI
commit, commit_ack only after return and IDLE. Known precommit rollback failure
is unconfirmed/manual reconciliation; uncertain COMMIT never triggers another
COMMIT or guessed ROLLBACK. Known commit plus evidence failure stays committed/
evidence incomplete. Physical raw close precedes logical SQLAlchemy cleanup to
prevent wire SQL after uncertain commit; closed-driver rollback is a logical
no-op only, never a live idle rollback loophole. Close and dispose are attempted
independently. No downgrade, reset, cleanup, restore or marker repair exists.
Budgets/deadlines still allow bounded cleanup rollback after a failure.

## Transition and authority

`execution-transition.v3.proposed.json` and its complete unified diff target
future f-execution-v3 COPIES only, based on W2.4B's unapplied proposed copies.
Activation retains all original source/identity/lock/catalog/typed finalization/
marker/readback logic, substituting Session ownership for literal controls.
Old Engine initialization is removed from open(); Session initializes during RO.
No destination is created and no prior patch is applied. Kernel, dialect,
connection, recipe, strict meter and bridge must all be loaded from their new
pins by a new reviewed controlled loader. Never feed real adapters into W2.3's
mock-only functions or weaken their type checks.

`source-lock.v4.proposed.json` retains parent v3/source packages/pins and exact
unchanged v2 budget/phase proposal. A NEW reviewed source-specific loader,
wrapper schema, source-bundle/lock-v4 consumer and manifest builder are still
required. Existing budget_policy execution_bundle deliberately knows only v3
and absent v2 copies; do not pass v4 to it or silently repin it. The diff is a
complete transaction-interface proposal, not source-specific live activation.
Actual F identity/catalog/security/credential/network/reference/writer evidence,
raw manifest byte hash + repeated revalidation, distinct validate/execute/
readback approvals and accepted prefixes remain independent gates. Mock tokens
or bare approval flags are never adequate runtime evidence.

Pending template has accepted=false, no action references/approved hashes,
unknown F identity/expiry and all seven integrity attestations false. Review
package expiry is review metadata only; no old approval is renewed.

## Offline commands and remaining gates

    .venv/bin/python -B infra/uuid-migration/f-transaction-correction/test_transaction_offline.py
    .venv/bin/python -B infra/uuid-migration/f-transaction-correction/review.py --mode offline
    .venv/bin/python -B infra/uuid-migration/f-transaction-correction/lifecycle.py --mode offline

Rerun the unchanged 525 selected offline tests, static graph/source/SQL compiler
checks and Ruff. Mocks do not accept PG16 transaction/state/status behavior,
libpq/native dependency provenance, dialect subtype equivalence/adapter setup,
all reflection/driver SQL allowlists, lock/deadlock/timeout behavior, frozen047
PG14-to-PG16 semantics, rollback/recovery or actual independent readback.

Next separately authorizable stage: F infrastructure ONLY, after independent
source/package review and daemon/image/collision/capacity/network-risk/credential/
preservation review; stop before database authentication or schema installation.
Later fresh identity/auth/freshness and source-specific unit actions are separate.
F NOT CREATED; frozen047 NOT RUNTIME ACCEPTED; 193 live cases NOT EXECUTED.
