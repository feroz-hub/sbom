# W2.1 fresh PostgreSQL bootstrap adapter — staged, offline only

This build has no PostgreSQL driver, Docker wrapper, credential reader,
application import or live Alembic loader. `--mode live` always refuses before
reading configuration. Operator attestations in a future manifest cannot enable
it. Future connected integration and the exact target require separate source
review and explicit authorization.

From the repository root:

```sh
.venv/bin/python -B infra/uuid-migration/fresh-bootstrap/fresh_bootstrap.py --mode offline
.venv/bin/python -B infra/uuid-migration/fresh-bootstrap/test_fresh_bootstrap.py
.venv/bin/python -B -m ruff check --no-cache infra/uuid-migration/fresh-bootstrap/
.venv/bin/python -B -m ruff format --check --no-cache infra/uuid-migration/fresh-bootstrap/
```

`source-lock.json` pins93 historical inputs:79 active revisions, six staged
revisions, snapshot, two frozen seed modules, inert app package initializer,
existing Alembic config/environment and bootstrap helpers. Its byte hash is
hard-pinned by the adapter. Existing sources are never changed or imported.
The archived monolith is outside the exact six-file staged discovery set.

`pg_lex.py` is conservative statement framing, not a PostgreSQL SQL parser.
It handles standard/E strings, doubled identifier quotes, tagged dollar bodies,
line and nested block comments. Unsupported prefixes, ordinary backslash strings,
unterminated tokens and psql commands refuse. Generic framing support does not
make arbitrary SQL eligible: transformation requires the exact original047 hash,
558 statements, the12 exact directive token sequences and known object families.

`047-execution.proposed.sql` and `047-transformation.diff` are review artifacts.
They replace only12 session directives with transaction-local bounded settings,
row_security/check_function_bodies on and an explicit search_path. All546 object
statements and their order/comments are unchanged. The snapshot was produced by
PG14 tools; no PG16 grammar, semantic047 equivalence or actual DDL acceptance is
claimed. No data, sequence positions, old owners/ACLs or credentials are copied.

`fresh_catalog.py` defines24 fixed future SELECT templates and pure observation
validation. System schemas and the sole plpgsql extension are explicit; custom
relations/functions/types/domains/operators/access methods/text-search/casts/
transforms/large objects/security labels/triggers/rules/foreign/replication objects,
default ACLs, per-database role settings, other clients/locks and Alembic state
refuse. Complete role/ownership/ACL/shared-dependency/settings evidence must match
an independently approved fresh baseline. Privilege errors are not empty results.
Role passwords are exposed only as NULL/SCRAM booleans. HBA file rows/parse cannot
prove effective loaded authentication: a separate approved review reference is
mandatory. This is a catalog contract, not a live observer or baseline acceptance.

`fresh_bootstrap.py` derives39 scheduled units: frozen047,32 individual048–079,
six080–085. Each requires its exact predecessor, one owned transaction, a new
process, acknowledged commit, physical write close and separately authorized new
read-only read-back. The pure `UnitContract` consumes mocked ordered statement
receipts. Schema acknowledgments first require transaction-scoped advisory
serialization7160085085 and a fresh catalog recheck under that lock; unrelated
privileged DDL still requires an approved exclusive window. Only complete schema
installation permits the parameterized047 marker
instruction. It never stamps079/085. Precommit errors require rollback/closure;
unconfirmed rollback or COMMIT outcome stops for reconciliation without retry.
No receipt in this build certifies an actual database event.

Reference contracts derive048 frozen catalog data, final role-permission sets and
versions through079.048/064's two app seed imports have deterministic inert AST
alternatives with frozen literal values, complete diffs and preserved migration
bodies. These alternatives are not imported, executed or registered; future
Alembic binding/loader integration remains separately reviewed. No automatic
customer tenant, user, admin, password or membership is created.

`approval.schema.json` and `approval.pending.json` specify future authority.
The template deliberately fails execution validation: identity/resource/OID/
catalog/credential metadata/expiry are unknown, five source/target/credential/
role/egress attestations false, action approvals empty, accepted=false, seven
integrity attestations false and integrity approvals empty. No approvals exist.
The Python contract additionally requires an externally approved raw-file SHA256,
duplicate-key rejection, exact source map, unique action references, aware UTC
expiry, fixed F target and budgets, and private0700/0600 original bytes reread
immediately before any future authentication. Canonical digest is not byte SHA.

The F proposal is127.0.0.1:56043/uuid_w2_f_fresh/uuid_w2_f_bootstrap,
sbom-uuid-w2-f project,postgres_f service and new f_pgdata/f_access resources.
No resource availability or identity is inferred from these names. No D/E
password, volume, network or schema reuse. Ordinary-bridge outbound risk needs
its own approval. Proposed budgets: one attempt/concurrent connection,64catalog
SELECTs/four transaction controls,5sconnect/30sstatement/1slock/30sidle and120s
cooperative unit window.080–085 retain their stricter source caps. Cleanup must
still occur after a cooperative deadline; no hard network/COMMIT deadline is
claimed. The558 schema statements are a separate exact pinned DDL budget, not
catalog SELECTs. Read-only preflight and read-back use explicit READ ONLY/ROLLBACK;
the separately approved install unit needs BEGIN READ WRITE under the default
read-only connection policy. A future coordinator must enforce the contracts.

No staged migration promotion, final constraints, ORM/API/frontend changes,
legacy-data backfill, F provisioning or integrity case execution is included.
Review report28 and the protected package before authorizing further work.
