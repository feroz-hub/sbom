# Database bootstrap and upgrade

Authoritative database workflow entry. Source checked against e62951c2 on
28 October 2026: 83 revision files, one source head,
**103_tenant_admin_governance**. Historical revision numbers are not renumbered
to fill the 079-to-100 jump. A source head does not establish the revision,
physical schema or compatibility of a deployed database.

## Classify the target before any write

| Target | Repository behavior | Operator decision |
| --- | --- | --- |
| Fresh PostgreSQL installation | Empty-database paths use the frozen revision-047 snapshot and subsequent revisions; specialist Greenfield setup builds/validates its own final metadata baseline. | Confirm a separately named, empty target and the selected install mechanism. These paths are not interchangeable data-import procedures. |
| Existing compatible UUID installation | An accepted revision-100 baseline or descendant may have a reviewable next transition; schema, identity guards, source/target and privileges still require validation. | Approve the exact source-to-target transition and backup/restore evidence. A matching Alembic marker alone does not prove compatibility or production approval. |
| Populated pre-UUID installation | Revision 100_greenfield_uuid_final descends from 079 and refuses populated application tables. | **Unsupported crossing: stop before upgrade/start/deploy.** No approved populated pre-UUID upgrade is supplied here. Obtain a separately reviewed migration/recovery design. |
| Unknown, drifted, partial or ahead schema | General upgrade commands cannot establish a safe starting point. | Stop for target/schema reconciliation; do not stamp or repair history to force progress. |

[Revision 100](../alembic/versions/100_greenfield_uuid_final.py) checks the six
tables in [app/public_identity.py](../app/public_identity.py): tenants, projects,
products, logical_sbom, sbom_source and sbom_component. If any contains a row,
its upgrade refuses. The revision also deliberately refuses downgrade of public
identities. This is a safety boundary, not a guard to bypass.

**Production migrations must not cross unsupported revisions.** In particular,
do not run upgrade head, either directly or through a launcher/Compose, against
a populated pre-UUID target. No data deletion, marker stamping, historical
migration rewrite or generic downgrade is a substitute for an approved path.

## Fresh installation

Identify the PostgreSQL cluster/database and verify empty public schema using
approved operator tooling and protected connection configuration. Preserve
existing databases and keys.

The existing implementations are:

- [scripts/bootstrap_fresh_database.py](../scripts/bootstrap_fresh_database.py):
  PostgreSQL only, exact target-name confirmation, refusal of any public table,
  frozen 047 baseline, subsequent upgrade and final-head verification. Its CLI
  requires --database-url and --confirm-empty-database; use an approved secure
  invocation mechanism, accounting for command-line visibility. Never paste real
  URLs into history, tickets or documentation.
- [alembic/env.py](../alembic/env.py): an ordinary head upgrade on a provably empty
  PostgreSQL schema uses the same frozen 047 snapshot before later revisions.
- [scripts/docker_migrate.py](../scripts/docker_migrate.py): selects the guarded
  bootstrap for an empty server target, otherwise calls Alembic upgrade head.
  It does not supply a populated pre-UUID conversion.
- [scripts/dev.py setup](../scripts/dev.py): explicit isolated
  local setup, with final metadata validation, identity guards and its own
  reference/fixture process. Use a maintainer-reviewed, target-specific
  installation procedure. Historical acceptance records do not certify current
  setup or production support and are not newly indexed here.

Do not replay historical revision 001 as a fresh-install contract: it uses live
ORM metadata. Do not apply more than one installation mechanism to the same
partially initialized target.

## Existing compatible UUID installation

Before an approved upgrade, record source/image revision, nonsecret target
identity, physical schema/guard acceptance, current marker, exact destination,
required locks/privileges, writer-drain plan and a recoverable encrypted backup.
Rehearse restore and ensure keys needed for stored encrypted data are recoverable.

The existing Alembic interfaces are:

    python -m alembic heads
    python -m alembic current

heads reports source metadata; current accesses the configured database.
For an explicitly reviewed compatible transition only, the existing write
interface is:

    python -m alembic upgrade head

Do not run that command merely because it appears here. The server migration
service does not provide Greenfield's interactive per-unit confirmation or
backup/rehearsal contract. Use the
[production release gate](UBUNTU_DOCKER_DEPLOYMENT.md#8-upgrade) before server
deployment; Compose startup ordering does not drain old writers automatically.

## Greenfield startup

Ordinary Greenfield start performs a read-only current-schema gate through
[guarded migration selection](../scripts/greenfield_auto_migrations.py).
It can discover pending descendants of the accepted UUID baseline; it does not
replay pre-UUID history, bootstrap an existing installation or seed synthetic
users as an ordinary startup step.

Pending transitions require explicit scripts/dev.py setup --profile greenfield --migrate;
ordinary start supplies no confirmation and therefore cannot upgrade.
For each explicitly approved pending unit, the
[shared migration coordinator](../scripts/greenfield_migrations.py) requires:

1. Source pins/snapshots, resource identity, predecessor and physical schema
   preflight; no unresolved prior pending-upgrade marker.
2. A fresh explicit interactive confirmation for that unit. Non-interactive
   startup refuses when confirmation is required.
3. A full encrypted backup and restore verification into a new retained
   verification database; source/target parity is checked again afterward.
4. Locked, checked migration execution and acceptance before COMMIT.
5. Writer closure and independent read-back before application services start.

Cancellation leaves the migration unapplied. A backup/preflight failure blocks
continuation. Unknown COMMIT or incomplete committed acceptance requires manual
reconciliation: retain the private pending marker, backups and journal; do not
retry, downgrade or delete evidence automatically. Existing data containers may
already have been resumed before the migration gate stops application startup.

The local Greenfield contract is not approval for production upgrades or for
other operating systems. See [developer platform limits](development/README.md#profiles-and-platforms).

## History and recovery

Revision 049 validates legacy membership roles, creates primary assignments and
MIGRATED history, and refuses unknown role codes. These are historical
data-contract facts, not an instruction to replay migration 049 on a populated
modern database. Keep frozen authorization seeds and prior evidence unchanged.

[Tenant-role assignment operations](TENANT_ROLE_ASSIGNMENTS.md) describes its
downgrade restrictions. Application rollback requires a compatible schema and
configuration; irreversible identity transitions require the reviewed
restore/recovery plan and accounting for writes since backup. Never prescribe
Alembic downgrade as a universal production rollback.

This documentation phase executed no database commands and approves no deployed
source-to-target migration pair.
