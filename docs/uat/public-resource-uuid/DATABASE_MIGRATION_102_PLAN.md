# Migration 102 and populated cutover

**POPULATED_DATABASE_MIGRATION_NOT_AUTHORIZED.** No 101/102 execution, backfill, marker update or service cutover on the populated database is included in this task.

The actual starting observation found `101_iam_user_public_uuid`, rather than the supplied historical revision 100. It contained 19 users, 19 provider links, 18 Native credentials, 21 memberships, 21 role assignments, 4 platform grants, 40 runs and 70 findings. A later explicit READ ONLY check matched those counts, the marker, existing public-column state and all 144 FK definitions. The operator independently stopped/restarted infrastructure during testing. This task did not start the original API/UI/worker or alter existing seeded identities.

## Forward-only unit

`100_greenfield_uuid_final → 101_iam_user_public_uuid → 102_public_membership_grant_analysis_uuid`

Frozen 100 and 101 remain byte-identical. Revision 102 requires exactly the sole 101 marker, PostgreSQL, a caller-owned SQLAlchemy transaction and DBAPI autocommit=False. It sets 30-second statement, 250-millisecond lock and 5-second idle-transaction limits; takes advisory key 7160085102; and acquires version/table NOWAIT locks. No retry is implemented.

Only `tenant_users`, `platform_user_roles` and `analysis_run` gain `public_id`. Each nullable native UUID column is allocated with `pg_catalog.gen_random_uuid()` only where NULL, then constrained NOT NULL and UNIQUE. The new validated CHECK restricts version 4/RFC4122 variant. An independent SECURITY INVOKER function, fixed pg_catalog search_path, revoked PUBLIC EXECUTE and per-table BEFORE INSERT allocator/AFTER UPDATE immutability triggers complete the unit. Existing integer PKs, FKs, credentials, provider links, roles and business values remain unchanged. The marker transition is atomic with the body.

The table locks serialize allocation and protect existing relationships; they can fail on contention. The limits are not approval to weaken or retry a failed run. An acknowledged precommit failure rolls back and physically closes. A lost/uncertain COMMIT stops for independent reconciliation. The migration downgrade refuses: recovery requires a separately approved, verified backup restoration plan.

## Fresh installation and synthetic upgrade evidence

The fresh installer constructs the reviewed previous metadata shape and original six-resource guards, then runs actual 101 and 102 in order. It records no final marker to hide an incomplete schema. Historical migration provenance is preserved. The fresh 100→101→102 path and the populated synthetic upgrade/rollback tests passed against PostgreSQL. Existing PostgreSQL bootstrap/migration compatibility tests in the complete inventory also passed; these results do not authorize a legacy-data transfer or populated installation.

Disposable populated 100→101→102 tests compare every original fixture value and FK definition for users, provider identities, Native credentials, memberships, platform grants, runs, findings and audit history. They verify one-to-one native UUID allocation, retained integer IDs, rollback of columns/backfill/guards/marker on injected failure, skipped-101 refusal and DBAPI-autocommit refusal. Concurrent creation, explicit NULL allocation, unique/NOT NULL/version/variant checks and immutable updates are tested against actual PostgreSQL.

Independent catalog checks on the restricted-runtime browser database find revision 102, ten UUID resources, zero metadata differences and an exact match to the populated baseline's 144 integer FK definitions. The SQLAlchemy cycle warning is recorded; explicit FK comparison supplements reflection. The frozen 100 guard retains its original default PUBLIC EXECUTE ACL, while 101 and 102 revoke it. No historical ACL was silently changed.

## Separately authorized cutover

1. Review the final source/hash manifest, SQL, current actual marker, table counts, ownership/ACLs, writer processes and resource identities.
2. Approve a maintenance window and stop incompatible writers under separate authority. Do not use ordinary development startup to infer migration approval.
3. Take an encrypted private full backup and verify a restore to another newly owned database. Record credential/provider/PK/FK/audit snapshots privately without publishing secrets or credential digests.
4. Independently approve the exact predecessor transition: 101→102 if the fresh observation still proves 101; 100→101→102 requires separate approval of both forward units if the observed target is actually 100. Never replay revision 100.
5. Run one reviewed bounded transaction per approved unit, with acknowledged COMMIT and physical closure. Stop on errors or unknown outcome; no automatic repair or marker stamping.
6. Perform independent read-only catalog, UUID, integer-graph and data-snapshot parity checks.
7. Only after acceptance, approve matching service restart and staging/browser/provider regression. Purge/reselect stale numeric resource selections and cached deep links. JWT/OIDC subjects and sessions retain their semantics; no credential rotation is required by this change.

The source-dependent populated launcher deliberately refuses revision 102 before credential/database access until a separate cutover integration is reviewed. There is no automatic 102 upgrade or deployment in this task.
