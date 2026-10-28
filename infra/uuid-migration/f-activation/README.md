# W2.4A — F activation preparation, offline only

This directory stages new dependency-injected resource, credential, catalog,
SQLAlchemy/DBAPI, isolated Operations and transaction-evidence adapters. No live
connector, Docker runner, secret provider or activated worker is wired to a CLI.
W2.1/W2.3 sources, mock-only checks, locks and migrations remain unchanged.

```sh
.venv/bin/python -B infra/uuid-migration/f-activation/activation.py --mode offline
.venv/bin/python -B infra/uuid-migration/f-activation/test_activation_offline.py
.venv/bin/python -B -m ruff check infra/uuid-migration/f-activation --no-cache
.venv/bin/python -B -m ruff format --check infra/uuid-migration/f-activation
```

`--mode live` always exits 2 before source/resource/credential access. There is
no force flag or CLI for constructing a live connector. Library lifecycle
functions are staged, injected integration recipes, exercised only with mocks.
This is not an executable provisioning or migration approval.

## Files and composition

- `reviewed.py`: pins/loads four inert W2.3 libraries into isolated namespaces;
  discovers the unchanged 113-input lock, 91-revision graph and 45 units. Does
  not call mock-only binding or coordinator functions with real objects.
- `security.py`: exact original-byte wrapper and original W2.3 unit authority,
  duplicate keys, private files, original expiry and repeated source/dependency/
  target/action rechecks; actual resource/byte correlation and HBA limitations.
- `resources.py`: pure normalization of independently collected Docker inspect
  metadata and descriptor-safe host-secret reading with injected OS/mount
  readers. No Docker command implementation or default secret reader exists.
- `transport.py`: one injected constructor, dedicated engine/NullPool, DBAPI
  cursor proxy (attached before dialect initialization), exactly-once metering,
  transaction ownership, bounded executemany and physical close/disposal.
- `catalog.py`: fixed full 27-category source-derived catalog, identity,
  client/lock, reference data, version and empty-business observations; complete
  W2.1 freshness and separate W2.2 17-category finalization formats preserved.
- `binding.py`: separate isolated individual-revision loader and injected
  MigrationContext/Operations factories. No env.py, historical001, ScriptDirectory,
  global Alembic proxy, app import or shared application engine. Exact reviewed
  048/064 seed alternatives; all44 eligible namespaces tested without upgrades.
- `activation.py`: explicit unit/preflight/lock/body/marker/commit/closure and
  independently authorized read-only lifecycle; ordinary live CLI denied.
- `journal.py`: private per-unit O_EXCL attempt claim, fsynced JSONL phase/hash
  chain, sanitized exception class/SQLSTATE, no SQL text/parameters/credentials.
- `compose.f.proposed.yml`: proposal only, not rendered with Docker.
- `approval.pending.json`: unusable template, not authority; approvals empty,
  accepted false, seven integrity flags false, actual identities/expiry unknown.
- `runtime-checklist.md`: mandatory future validation and separate approvals.
- `test_activation_offline.py`: synthetic/mocked regression tests only.

## Approval and transport contract

A future source-specific activation must review both the original W2.3 unit
manifest and a new `w24a-activation-review-v1` wrapper. Both require explicit
operator-approved original byte SHA256s; canonical digest is labeled separately.
Every boundary reopens the same private path, rejects changed bytes or an
in-memory plan differing from those bytes, rechecks source and installed-file
pins, actions and UTC expiry. Wrapper expiry cannot extend unit expiry.

Wrapper fields are exactly those in `approval.pending.json`. Its `w23_manifest`
is an original private path/hash; `activation_sources` pins every new source,
configuration, template and document; `dependency_sources` pins installed
SQLAlchemy/Alembic/psycopg Python/native distribution files and versions.
`sql_allowlist` requires separately reviewed **exact driver-statement byte hashes**
for each category, including reflection/initialization. No wildcard, automatic
learning or substitution is supported. An unexpected SQL shape refuses.

Distinct `unit_validate`, `unit_execute`, `unit_readback` references must match
both authorities. No old D/E references, test approvals or manifest flags alone
establish acceptance. Original unit checks require independently observed F
identity/resources/security/reference/catalog hashes and a separately protected
independent effective-authentication review. F identifiers cannot be guessed.

The new transport proposal is deliberately explicit: `autocommit=True` at the
DBAPI transport, dedicated SQLAlchemy AUTOCOMMIT engine with
`skip_autocommit_rollback=True`, no pool reset, and literal metered owned
`BEGIN READ ONLY`/`ROLLBACK` followed by one `BEGIN READ WRITE`/`COMMIT`.
The database unit remains atomic, never autocommitted statement-by-statement.
This differs from W2.3's mock constructor and **requires new independent review**;
W2.3's manifest/source was not edited or used alone to authorize this setting.

All other fixed endpoint/session options derive from the pinned unit contract:
127.0.0.1 host+hostaddr,56043,uuid_w2_f_fresh,uuid_w2_f_bootstrap,
passfile=/dev/null, no service, SSL/GSS disabled,connect5s,default READ ONLY,
row_security on, search_path pg_catalog, exact per-unit timeouts. New app names
are `sbom_w24a_f_unit` and `sbom_w24a_f_readback`. Future worker environment must
actually contain only HOME/PATH/LC_ALL/PYTHONDONTWRITEBYTECODE; returning a filtered
dictionary is not process-isolation evidence. No worker is started here.

## Meter and lifecycle

Only the driver cursor charges SQL. Logical query/DDL wrappers do not charge.
Dialect initialization and reflection are therefore included; SELECT/SHOW use
query quota even inside an upgrade. Executemany must be a bounded materialized
list/tuple and reserves one execution per row before driver submission. There
is one framed statement per call, exact SQL allowlists and no unowned transaction
control or mutations outside an owned transaction. Counts are conservative
reserved executions, not proof every reserved statement reached PostgreSQL.

Per-unit original budgets remain authoritative. Frozen047 uses its exact558
migration statements, separate marker/session/query/control quotas; no64-query
assumption. Deadline is cooperative120s, not a hard wall-clock bound on
connection/COMMIT/fsync. Rollback/close/disposal remain mandatory after deadline.

An O_EXCL claim in a dedicated private per-unit directory precedes connection.
It must survive interruption and cannot be reused by changing an action/hash.
Record/fsync failure before mutation prevents it; journal failure cannot inhibit
an emergency bounded rollback. Acknowledged COMMIT remains a committed fact even
if later evidence fails; failed COMMIT is UNKNOWN and never retried/rolled back
as a guessed recovery. Close/dispose failures prevent acceptance. One write
returns COMMITTED_UNVERIFIED; separate unit_readback obtains new actual catalog
state, rolls back and closes. State observations do not fabricate historical
execution provenance or automatically accept the installation.

## Known activation dependencies

A mature72-table prefix with71 business emptiness checks requires at least
3×(27catalog+71emptiness+identity+clients+locks+marker+4reference)=318 queries in
this three-observation write recipe, before reflection/initialization. Original
256-query rows cannot support that workload. The meter fails closed; original
budgets are unchanged. Independently review per-unit observer/query plans and
budget revisions under a new versioned contract before activating affected units.
512-query finalization rows also need measurement; no sufficiency claim.

Driver allowlists, actual PG16 dialect initialization/reflection, wrapped driver
compatibility and owned transaction/disposal behavior require future bounded
runtime acceptance. Native libpq/binary/backend provenance (including optional
psycopg-binary distribution and OS libraries), actual process environment,
Docker/OS reader wiring, anti-retry worker ownership and effective loaded HBA
proof require source-specific activation review. The distribution-file pinning
implemented here does not establish loaded native library provenance.

No live success, schema equivalence, application behavior, DML/concurrency,
recovery or performance acceptance follows from these mock/compiler tests.
F NOT CREATED; frozen047 NOT RUNTIME ACCEPTED; 193 live cases NOT EXECUTED.
