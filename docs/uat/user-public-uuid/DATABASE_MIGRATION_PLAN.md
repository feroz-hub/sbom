# IAM User UUID database migration and cutover plan

**Not authorized or applied to the populated application database.** The observed application target remains `127.0.0.1:56044/sbom_greenfield_uuid`, revision `100_greenfield_uuid_final`, cluster `7698349709013049382`. Initial read-only counts: 19 IAM users, 19 provider identities, 18 Native credentials, 21 memberships, 21 assignments, four platform grants. Refresh these observations before approving any upgrade.

## Proposed forward-only unit

`101_iam_user_public_uuid` follows frozen `100_greenfield_uuid_final`. Revision 100 and the original six-resource guard remain unchanged. One Alembic transaction acquires advisory key 7160085101, EXCLUSIVE NOWAIT version-table lock and ONLY iam_users ACCESS EXCLUSIVE NOWAIT lock. It requires exactly marker 100, adds nullable native UUID without an ADD COLUMN default, sets the separate random UUID default, assigns UUIDv4 only to NULL identities, establishes NOT NULL, a unique constraint and validated UUIDv4/variant CHECK, then installs independent IAM allocator and conditional AFTER UPDATE immutability triggers. Alembic establishes marker 101 in the same transaction. No integer PK, FK, provider identity, credential or authorization record is rewritten.

This is a deliberate small-table transactional backfill. It is not approved for arbitrary large installations. The main observed population is 19; an independently reviewed changed row count, writer load or lock dependency requires a revised window. Values are permanent after commit. No integer HTTP User compatibility period is implemented or authorized.

## Required operator review before populated execution

1. Review exact migration/helper/model/API/frontend diff and hashes, actual current row count, estimated storage and lock dependencies. Verify writer exclusion, owners, privileges, PostgreSQL 16.15 and marker 100. Confirm no prior public_id objects or collisions.
2. Quiesce the affected API, worker and enrollment writers using their supported supervisor. Do not leave old and new API/frontend contracts serving concurrently. Preserve process inventory and six seeded identities.
3. Create a protected, encrypted full application backup using existing dedicated setup credentials in memory/private passfile. Never put credentials on command lines or in reports. Preserve schema, data, ownership/ACLs and sequences. Record nonsecret archive digest and counts privately. Prove restoration on a newly authorized disposable target before relying on the backup. No backup/export/restore of the populated database was performed during this implementation.
4. Approve the one-target, one-attempt Alembic 100→101 unit, bounded statement/lock/idle timeouts and maintenance window. Do not invoke revision 100 on populated data. No generic deployment/start script should silently apply this upgrade.
5. Require acknowledged COMMIT and physical writer closure. Independently read back marker 101, UUID type/default, complete one-to-one mapping, version/variant, unique/NOT NULL/validated CHECK and enabled trigger definitions. Compare integer PK/FK definitions, provider links, credential metadata and role/membership rows to the protected pre-upgrade snapshot.
6. Start the matching backend/frontend only after independent schema acceptance. Refresh cached User API data and discard saved integer User selections. Existing Native/OIDC token subject semantics remain unchanged, but sign out/refetch is appropriate for stale UI contexts. Update external clients to UUID before cutover.

## Failure/recovery

Known precommit failure: rollback and physically close; independently establish marker 100 and absence of partial UUID schema. Do not retry automatically. Unknown COMMIT: stop all further mutation and reconcile with independent reads under separate authority. A committed identity must not be regenerated or overwritten. Downgrade fails closed. Recovery after committed failure requires a separately approved full backup restoration and matching prior application version in a controlled window, accounting for every record created after backup; this is not an automatic schema cleanup procedure.

## Fresh and disposable installation evidence

New code constructs a separate metadata copy representing revision 100 (excluding only the new IAM column/unique constraint), creates the existing six UUID guards, establishes the verified 100 schema, and executes the actual 101 body and marker update transactionally. The historical migration body is not rewritten or replayed. `scripts/greenfield_uuid.py` now expects 101 for a new installation and refuses an existing 100 marker rather than upgrading it silently.

Task-owned targets: `sbom_iam_public_uuid_test`, `sbom_iam_public_uuid_upgrade_test`, `sbom_iam_public_uuid_browser_test`. Only the upgrade-fixture database's public schema is reset by the migration tests. The browser runtime role is `iam_uuid_browser_app` (restricted), with separate `iam_uuid_browser_owner` NOLOGIN ownership and distinct private credentials/signing/session keys. No original Greenfield seeded account is used or modified.

Executed migration tests are recorded in TEST_RESULTS.md. Disposable success does not approve the populated database or establish release/UAT sign-off.

## Review source pins

- `alembic/versions/100_greenfield_uuid_final.py`: `365f64b4561c5475a9ebbc2162c49bb147beb3e3796ce942adb303fc5c8835fc`
- `alembic/versions/101_iam_user_public_uuid.py`: `8c97790e5341e10823933dc2372fe0c351b24c96f54328af10b2ec9992ae630d`
- `app/iam_public_identity.py`: `e834759cb556c91606ea00b647782cb877b2d71fb5328a7cfcf55d7da617fe64`
- `app/iam_schema.py`: `581a43b097df374c2518f813302abc3ea693bcbe83afe2bc03d1ca98653a6fda`
- `app/public_identity.py`: `2a82504499e5e362404a028300c0eb5cda6348c37ccdd46fd28e257338ca451c`
- `app/iam_public_api.py`: `aa661701f7d16610f99d2bbbf4bd6681a4f6c41c5b093fa7bb4dcbb44ad64cbe`
- `app/public_api.py`: `50021e40a29efeba5fa81005beebf12c5ac91e7c8104bcb17d4c8209663d5687`

These are review pins for this implementation, not an operator-approved populated migration manifest. Recheck exact bytes at the later approval gate.

## Ownership and execution choice

Before a populated upgrade, independently read and approve the actual IAM table/schema owner (the existing Greenfield installer intends `greenfield_owner`). The elevated setup connection must enter that exact reviewed owner role within its owned transaction before the migration body so the new guard function is not accidentally owned by the setup superuser. No role membership or grant change is implied. Reject an unexpected owner; do not substitute it automatically.

Use exactly one marker owner: ordinary Alembic can own its marker transition when its connection/role/transaction have been explicitly reviewed, or the existing tested apply_user_uuid_revision helper can execute the actual 101 body plus its guarded 100→101 marker update inside the caller-owned transaction. Do not run both marker mechanisms. The helper does not create its own connection, approve a target or grant authority; the future controlled caller must verify the exact main target, owner, backup, writer exclusion and timeout contract first. Validate table/function/index ownership before commit and on independent read-back.


## Setup credential incident boundary

The operator separately approved rotating only the Greenfield setup role after a legacy test failure exposed its URL. That rotation was committed and independently authenticated; application credentials and all user credentials/roles were unchanged. This approval does not authorize IAM schema migration. The public test evidence is sanitized and the exposed credential is revoked. Later migration tooling must reread the protected setup-password file rather than reuse an old environment value.


## Review evidence and exact proposed sources

The full changed-source register is evidence/implementation-source-sha256.json; implementation-source.patch includes new files as well as tracked changes. Review the exact 101 migration, app/iam_public_identity.py and app/iam_schema.py bytes from that register, rather than approving a floating branch. The active graph has exactly one head, 101→100→079; historical migration bytes remain unchanged. Historical fixture tests may bind an older copied/symlinked graph for their own test databases; this never changes active discovery.

The 204-case final affected regression includes a real populated synthetic upgrade with membership/provider/credential/grant snapshots. The upgraded Native account verifies its existing password twice, preserves JWT sub=internal integer string, and retains the same public UUID. The restricted browser role additionally performs explicit-NULL allocation and an independently verified rollback. These are disposable acceptance results, not execution authority for the 19 populated development accounts.

A task setup credential disclosure in a failed assertion was remediated through the separately recorded setup-only rotation; the private setup credential file is now current. No runtime/application credential or seeded identity was rotated. Use the private credential loader rather than any historical output or cached URL; never reuse a disclosed URL. The populated schema remains 100 and has no IAM UUID column.
