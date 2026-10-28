# W2.4B — Fresh F query-budget reconciliation, offline proposal

No PostgreSQL, Docker, credential, application or migration execution occurs in
this directory. Imports are inert. `budget_policy.py --mode live` always exits2;
original W2.1/W2.3/W2.4A live denials and sources remain unchanged. No source is
promoted or patched in place. F NOT CREATED, frozen047 NOT RUNTIME ACCEPTED and
all193live integrity cases NOT EXECUTED.

```sh
.venv/bin/python -B infra/uuid-migration/f-budget-reconciliation/budget_policy.py --mode offline
.venv/bin/python -B infra/uuid-migration/f-budget-reconciliation/test_budget_offline.py
.venv/bin/python -B -m ruff check infra/uuid-migration/f-budget-reconciliation --no-cache
.venv/bin/python -B -m ruff format --check infra/uuid-migration/f-budget-reconciliation
```

## Sources and data

- `review_inputs.py`: verifies the exact retained source map and four historical
  packages, then loads only pinned inert libraries/adapters in controlled
  namespaces. No historical migration or application module is imported.
- `accounting.py`: actual frozen047 token inventory, AST-reachable helpers/table
  additions in048–079, all45 before/after prefixes and query categories. Source
  functions are inspected, never invoked. Downgrades/raw ambiguous table SQL/
  unresolved table names fail closed. Intended successful-path prefixes are
  NOT runtime observations; conditional guards and reflection can still fail.
- `budget_policy.py`: deterministic proposal/CSV generation, comparison,
  exact original source-lock hash/reference checks and future copied-source
  gate. A selection is offline review metadata, never execution authority.
- `scoped_meter.py`: additional partitioned per-phase query ceilings around the
  unchanged, exact-pinned W2.4A driver meter. Logical wrappers do not charge SQL.
  Tested with real prior collector/cursor code and synthetic catalog results.
- `prior-sources.v1.json`: retained original hashes, not a replacement lock.
- `observation-plan.v2.json`: complete45-unit relation sets, each pass's query
  components, body/source-site inventory, reservations and non-query accounting.
- `query-budgets.v2.proposed.json`: three action-specific limits/phase caps per
  unit. All non-query limits equal the original immutable per-unit values.
- `query-accounting.v2.csv`: human-readable45-row comparison matrix.
- `driver-initialization-review.v1.json`: installed-source/version/hash evidence
  for SQLAlchemy/psycopg initialization paths; no connection was created.
- `integration.v2.proposed.diff`, `proposed-execution-sources.v2.json`: full
  minimal three-file integration proposal, original/output hashes and complete
  proposed sources. All output destinations are absent. Do not apply in place.
- `source-lock.v3.proposed.json`: new review lineage, retained sources, all new
  source/data hashes and proposed execution-copy hashes; no inherited authority.
- `budget-reference.schema.json`, `approval.pending.json`: reference-only schema
  and deliberately unapproved template. No target identity or action is invented.

## Exact accounting, without the uniform318 assumption

W2.4A collect() has30fixed queries per pass:27catalog +identity +clients +locks.
Add one EXISTS per non-reference ordinary public table, one version SELECT if
alembic_version exists and four reference queries once authorization_roles exists.
Frozen047 pre/locked each add the complete24-query freshness format; final086–091
pre/locked each add the separate17-query snapshot format. Those duplicates are
intentionally retained; no security/freshness data is omitted to save queries.

The model starts with0tables, installs45frozen application tables plus the version
table (46), and source048–079 add26tables to reach72. Five collector exclusions
are version+four authorization/seed-audit relations. Mature per-table emptiness
queries are67, not71. The historical D term71business tables included reference
relations; it is not this collector's fresh-install emptiness count. Reference
seed/audit contents retain their dedicated acceptance checks, not an empty check.

Write cost =preflight +locked reinspection +post-body +advisorySELECT +post-marker
SELECT +body read-shaped driver SQL +initialization/reflection. Marker RETURNING
is DML charged once to marker quota; it is not another catalog query. File/source
rechecks and pure acceptance/hash functions issue no SQL. Server-internal SELECTs
inside a DO/function do not create extra driver calls; time/DDL limits still apply.

- Frozen047:54+54+75+2=185 deterministic coordinator queries. Readback75.
- Mature080–085:102+102+102+2=308, body0driver SELECTs; readback102.
- Finalization086–091:119+119+102+2=342 outside the migration body. Body276,
  272,268,264,260,256 respectively; total618down to598 before initialization.
  All exceed old512, not just old256. The body includes two complete prefix,
  data-precondition, all-business/seed-audit and17-category snapshot traversals.
- Historical048–079:231to308 deterministic coordinator queries, plus unknown
  runtime body/reflection queries. First coordinator-only lower bound greater
  than256 is056(258). This is not a claim that earlier units fit256 in reality.

A finalization body at position p has6initialidentity/settings/advisory/marker/
client/event SELECTs; prefix43−2p then41−2p;12data checks; two relation-list plus
68per-relation business/seed-audit checks each (138);34snapshot queries; target
column1 and final predecessor marker1. Total276−4p. No source body is executed
by this analysis. Actual code guards require transactional driver autocommitfalse.

Independent validation/readback each owns one new connection/initialization
budget and one observation pass; no write-side pool or quota is reused. Readback
uses post-prefix, without old-state freshness24 or finalization-prefix17.

## Strategy evaluation and chosen correction

A: Set-based UNION/JSON/dynamic-SQL inspection could reduce round trips, but
requires new exact SQL shapes, result-format/mapping/privilege/RLS/locking review
and PostgreSQL semantic acceptance. Introducing helpers would also expand DDL
scope. It is not necessary to reconcile this source contract safely offline.

B (selected): keep every current observation and its format, introduce versioned
per-action/per-unit query limits and explicit phase budgets, add an exact prefix
relation-set guard before the variable table loop. Review the unavoidable raw
work instead of suppressing checks. No SQL optimization is claimed or applied.

C: possible later after independently testing semantic equivalence; do not mix
an unverified optimization with this budget correction.

Reservation policy is visible per unit, not a proven runtime worst case:

1.16initialization queries per connection/action. Installed code shows version,
   current_schema, transaction-isolation, standard-strings plus optional hstore/
   type lookup. Cache/backend/dialect differences remain uncertain; overflow stops.
2. Historical body hard reservation=max(8,16×read-capable AST sites +24×reflection
   sites +8×loop sites). A site can repeat many times; some execute sites are
   DML and some reflection constructors emit no SQL. This deliberately overcounts
   potential sites but does NOT bound arbitrary loop iterations. The8floor covers
   a small separately reviewable hidden compiler-read allowance. Exact SQL hashes
   still apply; this is not permission for an unknown statement.
3. Frozen/expansion body driver SELECT count0; finalization's exact source-path
   body counts above are explicit caps. Hidden additional calls refuse.
4. Sum exact observation costs and reservations, round up to a multiple of8
   (0–7unallocated rounding slots). Write ceiling=max(original,rounded); readonly
   actions use their own rounded ceiling. Per-phase caps cannot borrow dormant
   legacy/rounding headroom. The reservations contain the reviewable uncertainty
   margin; there is no blanket512/1024limit or automatic budget learning.

Proposed write limits range256–656, validation72–136, readback96–120. See each
row for exact reason and old/new values. Original migration, marker, session,
control, connection and time limits do not increase. Rounding/dormant headroom
cannot authorize extra checks; a cap change needs fresh source/plan review.

## Driver metering and failure behavior

The old DBAPI cursor remains the single global charging boundary; the new phase
ledger partitions those same queries, it is not an additional SQL execution.
Initialization, preflight, locked reinspection, body/reflection, post-body,
coordinator SELECTs and independent readback are attributed explicitly. Missing/
nested phase, unknown exact SQL, extra/missing same-count relations, phase/global
quota exhaustion or unbounded executemany refuses before the driver call.

The staged prefix guard runs after fixed catalog/identity/client/lock collection
and before per-table EXISTS. Full original fingerprint/owner/ACL/role/reference/
tenant/freshness/security/source checks still run; a relation count is not their
replacement. Scope/action/schema must match the new unit authority and its exact
budgets; old v1 approvals cannot activate the correction.

Original rollback, owned controls, deadline cleanup, physical closure/disposal,
no-retry, acknowledged versus uncertain COMMIT and separate read-back authority
are unchanged. Offline lifecycle tests inject budget failure into the proposed
copied coordinator and demonstrate rollback and transport closure. They do not
establish actual PostgreSQL transaction recovery.

## Versioned source-lock and consumption transition — not performed

Retain W2.1lock, W2.3lock/budgets, W2.4A source/package and all001–091sources.
The new v3PROPOSAL records those hashes as retained inputs and separately pins
new review artifacts and proposed output code. No original file is repinned.

Future separately reviewed steps:

1. Review v3original raw SHA, plan/budget original hashes, full diff and proposed
   output hashes. No approval is inherited from an earlier package or this task.
2. Prepare new `f-execution-v2` copies and apply only the reviewed diff there;
   originals remain at their original paths. Bind a NEW controlled loader/source
   bundle to those exact hashes and the budget_policy/scoped_meter definitions.
   Existing pinned loaders correctly reject changed authority sources.
3. Review a full v2manifest/schema (`w24b-f-unit-v2`) preserving all original
   exact-byte/duplicate/private-path/UTC/identity/target/source/role/security/
   credential/network/action/expiry checks. Add the six-field observation_budget
   reference, bind it to the exact requested unit/action, resolve current sources
   and plan to the exact action limits. The reference schema alone is not authority.
4. Actual copied-source presence/hashes are required by execution_bundle(); it
   fails now because no copies exist. Original source bundle plus v3new/copied
   hashes must match the operator-approved manifest. verify_contract recomputes
   the entire source-derived plan and compares the separate budget artifact.
5. A new separately reviewed adapter builder constructs the scoped meter using
   the pinned base class and verified unit/action selection, attributes the
   phases shown in the diff and preserves live CLI denial until source-specific
   activation. No builder or live connector is delivered/activated by W2.4B.
6. Only later fresh target-specific unit_validate/unit_execute/unit_readback
   operator references and manifests may authorize any operation. Seven integrity
   flags remainfalse/actions empty. No F identity/catalog value is manufactured.

The diff is a budget-interface proposal, not a complete activation patch: source
loader, full manifest schema and builder integration still need independent review.
No change to PostgreSQL/Docker/credentials/roles is part of applying a query plan.

## Separate execution-critical issues retained

Pinned080–091 bodies require driver autocommitfalse and refuse AUTOCOMMIT
isolation. W2.4A transport proposes autocommittrue/AUTOCOMMIT. This is a confirmed
source-contract conflict, not a runtime failure measured here; query-budget work
neither fixes nor waives it. Native psycopg proxy/type-info compatibility, exact
initialization/reflection SQL allowlists, native library provenance, effective
loaded authentication evidence, durable worker ownership, actual PG16/frozen047
semantics, timings and all DML/concurrency/recovery/performance remain unaccepted.

Historical runtime body counts cannot be proved bounded offline from AST call
sites. This proposal bounds permitted work and fails closed; it does not promise
that every migration completes within that allowance. Any real overflow is STOP
for review, never retry/automatic quota increase/cleanup. All prefix tables and
catalog hashes still need actual independently accepted F observations.

Next may be independent source/package review and then separately scoped
F-infrastructure-only collision/capacity/daemon/local-image/credential/network-risk
and preservation approval. Do not connect/create F or activate any migration from
this proposal. Resolve transaction/driver/loader/budget acceptance before migration
authority. Existing A/B/D/E/production/storage/services remain untouched.
