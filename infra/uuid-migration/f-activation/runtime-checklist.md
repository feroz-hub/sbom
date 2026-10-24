# Frozen047 and F runtime acceptance checklist — NOT EXECUTED

All values below are requirements/proposals, not observed F resources. No
existing A/B/D/E environment, storage or credential may be reused or modified.

## Gate0 — independent source and environment review

Review W2.4A full source/diffs/test results and the proposed transport change,
SQL allowlists, provider wiring, metering, installed/native driver dependencies,
durable worker ownership and per-unit budgets. Ordinary live mode stays denied
until a separately reviewed activation change. Do not activate W2.3 by weakening
its mock type checks. Approval flags and mock receipts alone are insufficient.

Review all45 source-pinned units and exact-next/read-back boundaries. Preserve
active head079; no active promotion is needed to execute the isolated loader.
Do not run historical001 or application metadata initialization.

## Gate1 — separately authorize F infrastructure only

Proposed project sbom-uuid-w2-f/service postgres_f, DB uuid_w2_f_fresh,
user uuid_w2_f_bootstrap, loopback127.0.0.1:56043, original new dedicated
volume sbom-uuid-w2-f_f_pgdata/network sbom-uuid-w2-f_f_access. Actual cluster,
container/image/network/volume identities, IP, DB OID and start time are UNKNOWN.

Before creation, independently inspect branch/HEAD/dirty files, exact local
Docker Desktop socket/daemon, approved locally present16.15 image ID, every
name/project/volume/network/credential-path/port collision, ≥2GiB host and Docker
storage and ≥1GiB host/Docker memory headroom. Snapshot existing resource ID
sets, selected configuration/start metadata and current processes/listeners;
compare unordered ID sets and selected properties afterwards. Do not demand
obsolete historical PIDs or start absent services. New F resources must be the
only expected set additions. No image pull/build, substitution, recreate, prune,
existing-resource lifecycle action or automatic cleanup.

Compose proposal:1CPU,512MiB memory,64MiB shm,128PIDs,max_connections12,
shared_buffers64MiB,work_mem4MiB,statement30s/lock1s/idle30s, restart=no,
no dependencies, dedicated ordinary NAT bridge/ICCfalse, only loopback publication.
Ordinary bridge outbound access remains possible; loopback/ICCfalse are not
zero-egress controls. Explicitly approve this risk or separately review a firewall.
Do not silently change topology to satisfy a claim of isolation.

Future authorized creation must generate a fresh F-only OS-random ASCII password,
no newline, outside repository: /Users/ferozebasha/.sbom-uuid-w2-f/postgres-password,
0700parent/0600file/ownerUID/regular/nonsymlink/single-link. No password exists
from this task. Verify host metadata, exact read-only /run/secrets/f_password
bind, sole data-volume/network attachments, image entrypoint OS ownership and
dedicated PGDATA ownership without chmod/chown repairs. Container read must
work in the reviewed initialization context. Correlate secret bytes only in
memory; permit only exact host or independently verified Desktop /host_mnt path.
Healthcheck is readiness, never identity/authentication acceptance.

Bootstrap POSTGRES_USER is initially a cluster bootstrap administrator under the
standard image; this is a security approval requirement, not an application role
or permission grant. Do not create arbitrary ownership roles. Approve actual
role attributes/memberships/ACLs after fresh observation. New F plpgsql metadata
must be reviewed on its own; historical D/E exceptions do not transfer.

## Gate2 — separately authorize first F read-only identity/freshness acceptance

A separate reviewed entrypoint/manifest is required for the first identity
observation, since exact F system identifier/DB OID/prefix are not yet known and
cannot be manufactured to satisfy a unit execution manifest. Limit scope to
one bounded authenticated read-only connection, rollback/physical close and
catalog/security evidence. Pin the new identity only after independent review.

Observe actual16.15, correct DB/current_user/session_user, non-recovery,
new system identifier different from all protected existing targets, actual
DB OID, internal interface:5432 correlated to host127.0.0.1:56043, PGDATA,
postmaster start and dedicated storage. Review actual SCRAM password metadata,
roles/memberships/owners/ACLs/default privileges, extensions and PostgreSQL/session
timeouts. HBA file rules report current file contents/parse status, not necessarily
last-loaded effective rules. Supplying a password and connecting does not prove
password authentication was required. Require separately reviewed effective
password-authentication evidence; otherwise UNKNOWN/BLOCKED. Do not silently
add an extra wrong-password connection or reload PostgreSQL.

Collect complete schemas, relations (including non-public), functions/types/
domains/operators and other objects, triggers/rules/events, sequences/indexes,
foreign objects, publications/subscriptions, role settings and Alembic absence;
allow only approved PG system/extension objects. Reject partially initialized
schemas, user objects, roles, reference/business data, RLS hiding data, competing
clients/writers/incompatible locks. Full fresh metadata must be independently
reviewed. No mutation follows first authentication automatically.

## Gate3 — independently approve first frozen047 unit

Verify original snapshot SHA256
e310421b5fea4ef93056be590756125726280671589b50d93aa85926b9833c09,
proposed representation6173c58cca7061483edd1b69e9edd0c431eee808f46ae1021293549d13e8c900
and transformation diff69d6a2bc019bbd991dcfe3b269938992be7d516e0cd9277381859f503ac63ce7.
558ordered statements:12session directives plus546object statements, including
45CREATE TABLE,34CREATE SEQUENCE,34OWNED BY,162ALTER TABLE,266CREATE INDEX,
5CREATE UNIQUE INDEX. These existing baseline indexes are unrelated to public
UUID finalization. Exact original object definitions/order are preserved in
source; runtime PG14.18→16.15 grammar/semantics are NOT established offline.
No old rows, sequence positions, passwords or customers are imported.

Review actual expected columns/types/defaults/nullability, every PK/FK/check/
unique constraint/index and sequence ownership against the full static inventory
and exact558 statements. No inferred B/D schema restore or drift repair. Plain
047 application schema should contain45tables/34sequences and its exact271
explicit indexes plus constraint-created indexes; do not assert that271 is total
physical indexes. Actual catalog acceptance must include constraint-created
indexes, functions/triggers/extension objects and owners/ACLs. No helper objects.

Review PG16 default tablespace/access method, UTF8/standard strings, xmloption,
plpgsql1.0/core gen_random_uuid availability, owner CREATE/schema privileges,
FK dependencies and necessary locks. Native UUID generation needs no uuid-ossp
or pgcrypto extension in PostgreSQL16. Do not install unapproved extensions.
SET LOCAL timeout30s/1s/30s, row_securityon, check_function_bodieson and
search_pathpg_catalog,public remain as reviewed; no timeout disablement.

Approve full driver SQL hashes (including compiler-generated reflection and
initialization), dependency provenance, exact source/target/prefix/reference/
security metadata, network risk, credential provenance and three distinct actions.
Original raw manifest byte hashes, duplicate rejection, current UTC expiry and
pre-auth/locked/prebody/premarker/precommit rechecks are mandatory. F identities
must come from Gate2, not proposed values or old D/E IDs.

## Gate4 — one actual047 transaction, then independent read-back

Require durable per-unit attempt claim before connection. One physical write
connection, readonly preflight/rollback, then one owned READ WRITE transaction;
reviewed advisory7160085085 and applicable locks/freshness recheck. Meter all558
statements once at driver boundary. Do not create the version table or INSERT047
until all schema statements acknowledge and exact post-schema acceptance passes.
Create version table with capacity128, bind one exact047 revision value, require
oneRETURNING row/sole marker. No direct stamp, no historical001 replay.

Known precommit failure: bounded rollback and physical close/dispose; independent
state reconciliation, no retry/repair. Before COMMIT, durable intent and source/
identity/authority/catalog checks; acknowledged COMMIT followed by physical close/
engine disposal. Lost acknowledgment is UNKNOWN; do not rollback/retry as repair.
Journal/disposal failure prevents acceptance even after a known commit.

Separately approved new readonly connection must verify exact047 sole marker,
full expected catalog/object/ownership/ACL/extension/dependency parity, no business
data/fixtures, source and other-resource preservation, then rollback/close/dispose.
Retain every earlier failure; never reuse an attempt claim or auto-clean resources.

## Gate5 — each later unit requires its own authority/commit/read-back

048 initializes required authorization catalog from frozen seed alternatives,
not old customer records. Review exact five system roles/scopes/status/version,
permissions, protected mappings and seed audit rows.064–068/075 modify platform/
tenant references; source-derived acceptance remains mandatory. Native Login
schema/bootstrap enrollment support is not permission to create an administrator,
tenant, password, membership or grant. Provider/config references and secure
runtime settings require explicit initialization acceptance; no application startup.

Every048–079 migration uses its original reviewed body and independent prefix/
revision/security/reference gates. Dedicated historical dialect binds public,
transaction-local public,pg_catalog path, restored pg_catalog before inspection.
080–085 preserve integer relationships and add six nullable UUID expansions;
086–091 final constraints are separate units. No backfill or imported business
records. Their correctness/lock/FK behavior requires real PostgreSQL acceptance.
Per-unit query/statement/time budget sufficiency and actual driver SQL shapes
remain blockers; in particular full three-pass mature catalog collection exceeds
256 queries. Review a new versioned budget or narrower proven observation plan;
never alter old source locks silently. No automatic remaining-unit progression.

All193 live integrity cases, application/native-login/tenant isolation/API/frontend,
SBOM workflows, DML/uniqueness/immutability/concurrency, recovery and performance
remain separately authorized future testing. No release acceptance is implied.
