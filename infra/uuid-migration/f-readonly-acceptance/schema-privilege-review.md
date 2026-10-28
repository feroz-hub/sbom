# W2.4E.1 — PostgreSQL 16.15 schema privilege policy

This is a source-derived expected policy for later independently approved F
observations. It is not a PostgreSQL runtime measurement or acceptance receipt.
No database, Docker or real credential access occurred during this correction.

## Authoritative initialization evidence

Reviewed upstream PostgreSQL tag `REL_16_15`, not the moving development branch:

- [pg_namespace.dat](https://github.com/postgres/postgres/blob/REL_16_15/src/include/catalog/pg_namespace.dat), entries11/99/2200: initial catalog/toast schemas have NULL ACLs; public has pg_database_owner ownership.
- [pg_namespace.h](https://github.com/postgres/postgres/blob/REL_16_15/src/include/catalog/pg_namespace.h), nspowner declaration: omitted owner uses the bootstrap role.
- [initdb.c](https://github.com/postgres/postgres/blob/REL_16_15/src/bin/initdb/initdb.c), setup_privileges(): PUBLIC receives schema USAGE on pg_catalog and public. setup_schema() loads the information-schema definitions before template databases are copied.
- [information_schema.sql](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/catalog/information_schema.sql), schema initialization: bootstrap creates information_schema and grants PUBLIC USAGE.
- [acl.c](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/utils/adt/acl.c), acldefault(), aclitemout(), aclexplode(), select_best_grantor(): a NULL schema ACL expands to owner CREATE/USAGE, without stored grant options. Owner grants itself; superuser grants act as object owner. Exploded ACLs expose grantor, grantee, privilege and stored grantability.
- [acl.h](https://github.com/postgres/postgres/blob/REL_16_15/src/include/utils/acl.h), ACL codes/order and schema rights: owner rights serialize as UC; ACL updates append entries. The NULL representation means default protection, not no privileges.

The configured F bootstrap name substitutes for the initialization bootstrap
role; its actual ownership and privilege state must still be observed. The
policy expects an unmodified PostgreSQL 16.15 initialization and a database
copied from its clean template. An altered image/template/init script or catalog
representation is a STOP requiring review, never automatic normalization.

## Exact expected rows

B = uuid_w2_f_bootstrap; O = pg_database_owner. Every stored is_grantable is
boolean false. This does not claim owners lack implicit grant authority.

| Schema | Owner | Grantee | Grantor | Privilege |
|---|---|---|---|---|
| public | O | O | O | CREATE |
| public | O | O | O | USAGE |
| public | O | PUBLIC | O | USAGE |
| pg_catalog | B | B | B | CREATE |
| pg_catalog | B | B | B | USAGE |
| pg_catalog | B | PUBLIC | B | USAGE |
| information_schema | B | B | B | CREATE |
| information_schema | B | B | B | USAGE |
| information_schema | B | PUBLIC | B | USAGE |
| pg_toast | B | B | B | CREATE |
| pg_toast | B | B | B | USAGE |

The whole eleven-row sorted multiset must match, including schema and owner.
Duplicates are not collapsed. No absent row, additional allowed-looking grant,
wrong grantor/owner, grant option, extra field or numeric boolean is accepted.
Four complete schemas observations must independently match exact names,
owners and raw ACL representations. pg_toast retains NULL; each other schema
has exactly `{owner=UC/owner,=U/owner}`. A different raw ordering/representation
fails closed and needs independent runtime review, even if arguably equivalent.
No broad role/privilege allowlist substitutes for this matrix. Public CREATE
for PUBLIC remains forbidden. Query shape/row order does not excuse missing
observations. SQL changes only add grantor to the existing schema_privileges
SELECT; its allowlist hash is explicitly versioned in the new candidate.

## Acceptance scope

Catalog assessment: scope CATALOG_OBSERVATIONS_ONLY; catalog_observations PASS
and authentication_evidence PASS after those requirements validate;
overall_acceptance NOT_EVALUATED_HERE. It cannot independently accept a session.
The old ambiguous live_accepted field is removed.

Complete probe: scope COMPLETE_READ_ONLY_PROBE; separate checks for catalog,
authentication, acknowledged rollback, physical closure and infrastructure
preservation. Overall accepted/status is computed only from the complete
lifecycle and all checks; durable STOP recording must succeed before a result
can return. Catalog success cannot override failed cleanup or preservation.
Failed or incomplete checks remain explicit rather than being reported passed.

HBA file parse/content evidence remains distinct from loaded policy proof.
Password use for the one future session must be proved with libpq used_password;
stored SCRAM indication does not prove the exact wire mechanism. Actual F
identity, ACL serialization, initialization/template behavior and PostgreSQL
query compatibility remain runtime dependencies. No F identity or passing
runtime catalog value is supplied by this source policy.
