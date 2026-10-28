# W2.4E — Dedicated F authenticated read-only acceptance preparation

Preparation only. No PostgreSQL connection is approved or performed by this
stage. Existing F infrastructure is accepted; database identity/authentication/
freshness are UNKNOWN. No migration coordinator or Alembic environment is used.
All imports are inert. Offline CLI imports no psycopg/runtime provider and makes
no Docker calls, credential reads or network connections. Tests use synthetic
credentials, catalog rows and injected connections only.

## Future authority and CLI

A separate operator must approve the exact source/package and candidate, the
five review flags and one distinct `read_only_execute` reference. Preserve the
original candidate; create a separate approved JSON changing only those issued
review/action fields and record its NEW exact raw byte SHA256. Do not renew
expiry, populate unknown database identity, self-approve or reuse D/E/unit refs.
All seven integrity attestations remain false and integrity actions empty.

    .venv/bin/python -B infra/uuid-migration/f-readonly-acceptance/entry.py --mode offline
    .venv/bin/python -B infra/uuid-migration/f-readonly-acceptance/entry.py --mode offline \
      --manifest /absolute/private/f-readonly-candidate.json --manifest-sha256 EXACT_RAW_CANDIDATE_HASH

Future live invocation contract (NOT AUTHORIZED NOW; no reference invented):

    env -i HOME=/Users/ferozebasha PATH=/usr/bin:/bin:/usr/local/bin \
      LC_ALL=C PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 \
      /Users/ferozebasha/sbom/.venv/bin/python -B \
      /Users/ferozebasha/sbom/infra/uuid-migration/f-readonly-acceptance/entry.py --mode live \
      --manifest /absolute/private/OPERATOR_APPROVED.json \
      --manifest-sha256 OPERATOR_APPROVED_EXACT_RAW_MANIFEST_HASH \
      --approval-reference SEPARATELY_ISSUED_W24E_F_READONLY_REFERENCE

Without exact raw manifest hash, fresh UTC expiry, reviewed source pins and
matching operator flags/action it refuses BEFORE runtime imports, Docker or
secret access. Private reader checks all nonsymlink path components, regular/
single-link/UID/0600/0700, descriptor before/after metadata, byte hash and unique
JSON keys; reopens exact original bytes before auth and subsequent observations.
Canonical JSON is not a byte-hash substitute. Historical W2.4C/W2.4D evidence
is verified from its actual private bytes and never treated as current DB facts.

## Resource, target and secret controls

Future live code first verifies installed Python/psycopg/psycopg-binary/Docker
CLI pins. Installed binary backend reports libpq18.0 with used_password API;
server target remains PG16.15. Bundled native-file pins/version are not full
provenance proof of every dynamically loaded OS library. Dependency drift
refuses; no dependency installation/update is performed here.

Metadata uses only exact Docker CLI/local Unix socket, pinned Desktop daemon,
F container/image/network/volume and original start/restart/health/publication/
limits/mount/configuration labels. Whole current container/network/volume sets
must equal the separately pinned current preparation baseline. Any unrelated
resource drift is a stop, not permission to waive or repair it. No mutation
commands, logs, startup, inspect formatting or general command runner allowed.
Exact permitted metadata argv forms are hardcoded, no arbitrary prefix matching.
Container inspection is projected server-side: Config.Env and healthcheck log
output are never fetched or recorded.

Host secret has fixed F path, regular/single-link/UID/0600/0700, exact inode/size/
mtime/ctime. Current preparation STATs metadata only. Only after future live
approval, O_NOFOLLOW descriptor reading and an exact bounded pinned-container
root-context head65 read correlate host/mount bytes in memory. Read-only bind
must be one exact host source or verified Desktop /host_mnt translation of it;
no suffix/path-prefix substitution. Only boolean correlation enters evidence;
no secret hash/content/command argument/environment/copy is persisted. Mutable
buffers are erased; Python/subprocess/driver internal immutable copies cannot
be guaranteed erased. Current stage does NOT perform correlation or prove
credential correctness.

One fixed connector call: host and hostaddr127.0.0.1, port56043, database
uuid_w2_f_fresh, useruuid_w2_f_bootstrap; passfile/dev/null; no service keyword,
no PG*/dotenv/application environment or socket fallback; SSL/GSS disable,
connect5s, application_namesbom_w24e_f_readonly, prepare_thresholdNone to avoid
automatic preparation maintenance. default_transaction_read_onlyon,
statement2s/lock250ms/idle5s,row_securityon,search_pathpg_catalog,
check_function_bodieson,stats_fetch_consistencynone set explicitly at startup.
AUTOCOMMIT is used ONLY for this dedicated read-only probe's literal owned
BEGIN READ ONLY/ROLLBACK. It does not change or activate the migration transport
or bypass the unchanged UUID guards.

## Budgets, lifecycle and failure

Exactly one constructor attempt and maximum one simultaneous connection; no
background worker, retry, fallback endpoint, wrong-password trial, independent
second connection or application initialization. Cooperative monotonic60s
window includes resource/secret/live observation work; checked before each
metadata call/query and before auth. This is not a guaranteed hard wall-clock
kill deadline: a bounded current call and cleanup may finish after it. Docker
metadata timeout8s, mounted-byte read5s, connection5s, statements2s and idle5s
are individually bounded. No PostgreSQL16 absolute transaction_timeout is
claimed. No cancellation process, server reload or uncertain-COMMIT injection.

33 planned catalog SELECT executions (30fixed templates plus final identity,
client and lock rechecks), hard ceiling40. No dynamic SQL/table rows, no SHOW
needed, no wildcard SQL, reflection, DDL/DML, SET, COPY, CALL, advisory locks,
marker query/INSERT, fixture or migration action. SQL source exact hashes are
bound to manifest and rechecked before cursor.execute. 1,024rows/query and8,192
rows overall; evidence frame524,288bytes maximum. Exceeding any allowance stops
and closes; no automatic expansion, query replacement or incomplete acceptance.

Server-enforced BEGIN READ ONLY; first identity verifies transaction_read_onlyon.
Catalog setting rechecks also require on. ROLLBACK is the only end control,
maximum2controls total; cleanup has reserved rollback capacity and may run after
deadline/evidence failure. Rollback send failure is not retried; physical close
still attempted. Failed BEGIN with an active backend is rolled back. UNKNOWN/
active status, query/permission error, resource drift, expiry, incomplete rollback/
close or failed durable evidence yields BLOCKED_OR_INCOMPLETE. No COMMIT exists.

Evidence is a pinned private O_EXCL0600 JSONL attempt claim under0700parent with
fsync/hash chain; duplicate claim refuses, even after approval renewal. Records
manifest BYTE hash, actual constructor attempts separately from reserved attempt
budget (durable preconnect evidence failure means zero actual calls), query
names/hashes, bounded catalog metadata, driver password-
use boolean, actual newly observed identity, sanitized diagnostics/SQLSTATE and
rollback/closure/resource disposition. Never full kwargs/DSN/password/hash/
function bodies/subscription conninfo/HBA options/process environments. Error
primary is bounded/redacted; unsafe material UNCLASSIFIED_REDACTED. After any
handle acquisition close is mandatory; after close fresh resource metadata must
match. Successful function result alone is insufficient if STOP/evidence fails.

## Acceptance matrix and limits

`acceptance-matrix.json` documents exact checks; `sql-review.json` contains all
30 full fixed catalog SQL definitions and hashes. Expected fresh PostgreSQL
objects are explicitly allowed: four standard schemas, plpgsql1.0 + three
extension handlers, builtin PG16 roles/memberships, default database/schema ACLs,
postgres/template databases and default tablespaces. No zero-cluster-object
heuristic or empty-public-only heuristic. All non-system user relations/columns/
functions/types/domains/operators/conversions/access methods/casts/text-search/
foreign/replication/event/rule/trigger/large objects/security labels/default ACLs/
role settings/competing clients/locks refuse. No application or seed row is read.
Alembic absence is checked by to_regclass; an existing table causes refusal, not
a version-row read or silent adoption.

Actual PG16.15/databaseOID/systemidentifier/internalIP:5432/PGDATA/postmaster/
encoding/collation/owner/roles/privileges must be observed. New systemidentifier
must differ from known historical D, while independent exclusive new F storage
and container correlation remain mandatory; unknown A/B/E database IDs are not
invented or queried. Bootstrap is expected to have the standard privileged
initial image role, confirmed by actual booleans/SCRAM-storage indication only.
No password value is selected. Unexpected role, privilege, membership, owner,
ACL, setting or extension fails; no historical plpgsql exception transfers.
Restricted application/runtime role is needed before app use; none is created.

A supplied password is not proof it was used. Require actual libpq
PGconn.used_password is True after success; missing/false yields UNKNOWN/BLOCKED.
This establishes password use for this one authenticated session, not the exact
SCRAM mechanism or complete effective loaded HBA rule set. HBA query reports
current file content/methods and boolean parse status only; stored SCRAM boolean
is a storage property. File parse success is never labelled loaded-policy proof.
The accepted observation, if later approved and successful, must retain those
explicit limitations; a requirement for independently proved complete loaded
HBA policy would remain a separate blocker, never silently waived.

## Offline verification and STOP

    .venv/bin/python -B infra/uuid-migration/f-readonly-acceptance/test_readonly_offline.py

Tests use only synthetic metadata/secrets/driver rows. Existing W2.1–W2.4C,
expand and integrity OFFLINE suites are rerun separately in their own processes
so similarly named modules cannot alias. No live193-case suite is run. Full
SQLAlchemy compilation is not PostgreSQL grammar/catalog runtime acceptance.
Preparation Docker snapshots/credential stat are separate from offline tests.

STOP independent exact source/package/candidate review. Operator must separately
approve the new raw-byte manifest and five specific reviews/distinct action.
Fdatabase identity/authentication/freshness NOT ACCEPTED; frozen047 NOT RUNTIME
ACCEPTED;193live integrity cases NOT EXECUTED. No migrations or role grants follow
a successful read-only probe without later independent authority.

## W2.4E.1 correction review

See `schema-privilege-review.md` for the version-tagged primary-source derivation
and exact eleven-row matrix for all four standard schemas. Missing non-public
grants, duplicates, additional grants, wrong owners/grantors/grantability and
incomplete/raw ACL representations refuse. Existing public-schema restrictions
remain. Only the existing schema_privileges SELECT gains a grantor projection;
SQL pins change explicitly, no new query or execution allowance. PostgreSQL
16.15 runtime compatibility remains unobserved and cannot be assumed.

Catalog assessment has CATALOG_OBSERVATIONS_ONLY scope and
overall_acceptance NOT_EVALUATED_HERE, without an ambiguous live_accepted=false.
The full probe separately records catalog, authentication, acknowledged rollback,
physical closure and infrastructure checks; only its complete lifecycle can
produce overall acceptance, with successful durable STOP recording required.
The future action, original raw-byte manifest, source/dependency/credential/
resource, read-only, rollback/closure and no-retry safeguards are unchanged.

Additional synthetic-only correction tests:

    .venv/bin/python -B infra/uuid-migration/f-readonly-acceptance/test_correction_offline.py

The new versioned candidate replaces no historical artifact, keeps the original
expiry and all five reviews false/actions empty/seven integrity reviews false.
No live session is approved. Resource observations in the candidate remain
historical W2.4E metadata, not a new Docker or PostgreSQL observation. Future
execution must reject any drift before authentication. STOP independent review.
