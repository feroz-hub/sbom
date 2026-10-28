# W2.2 staged fresh-install UUID finalization

Offline implementation only. These six revisions are not in active Alembic
discovery, and no approved runtime coordinator supplies their required context.
Do not use the application Alembic environment, D/E manifests or the old expand
runner to execute them.

| Predecessor | New revision | Only DDL target |
| --- | --- | --- |
| 085_uuid_sbom_component_expand | 086_uuid_tenants_finalize | tenants |
| 086_uuid_tenants_finalize | 087_uuid_projects_finalize | projects |
| 087_uuid_projects_finalize | 088_uuid_products_finalize | products |
| 088_uuid_products_finalize | 089_uuid_logical_sbom_finalize | logical_sbom |
| 089_uuid_logical_sbom_finalize | 090_uuid_sbom_source_finalize | sbom_source |
| 090_uuid_sbom_source_finalize | 091_uuid_sbom_component_finalize | sbom_component |

Each unit creates `uq_<table>_public_id UNIQUE (public_id)` and its single full,
ordinary B-tree index, validates `ck_<table>_public_id_v4`, and sets the existing
UUID column NOT NULL. It preserves the default, shared guard, triggers and
integer graph. It never assigns an ID or repairs existing objects. Downgrade
always refuses.

Prerequisites include an independently accepted, quiescent fresh F installation,
exact predecessor, source/manifest/catalog pins, reviewed roles/ACLs and matching
six-table expanded/finalized prefix. NULLs, duplicates, invalid UUIDs, populated
business tables, extra UUID checks/indexes, trigger/rule collisions, unexpected
security changes and changed approvals refuse execution.

Essential authorization reference rows and their seed-audit action are allowed;
they must match independently accepted reference/catalog evidence. This is not
an upgrader for a populated installation and is not sufficient reference-data
acceptance by itself. Complete finalization before administrator enrollment,
business seeding or application startup.

The required `w22_f_finalization` context is a receipt from a future separately
reviewed coordinator, not an operator manifest or signature. No receipt is
created here. That coordinator must verify protected original manifest bytes,
action/expiry, all source hashes, actual F resources/credentials, complete
security/reference/catalog evidence and the exclusive writer window before
building the receipt. A bare boolean or arbitrary context supplied to Alembic
does not establish operator authority.

The revision additionally checks actual PostgreSQL 16.15/F identity, transaction,
security settings and catalog digest; takes advisory key 7160085085, version-table
EXCLUSIVE NOWAIT and target ACCESS EXCLUSIVE NOWAIT locks; and takes SHARE NOWAIT
locks on all ordinary public tables. This last lock scope is broader than its
one-table DDL scope and must be approved in the future F window. Source-local
timeout caps retain stricter caller settings. Snapshot hashes use this source's
17-category, OID-dependent format; they are not D Runner13 or Independent31.

The future coordinator must own the one transaction, update exactly the next
marker after successful upgrade checks, acknowledge COMMIT, physically close,
and use a new separately authorized read-only connection to verify the committed
prefix and full delta. Any SQL error must stop; known rollback must be verified.
An uncertain COMMIT requires manual reconciliation without retry or cleanup.
These physical lifecycle guarantees are not implemented by the revision body.

W2.1 retains its exact 79-active/six-expansion source lock. W2.3 must introduce a
separately approved, versioned discovery/lock/schedule/coordinator transition;
do not relax the old checks or silently repin historical evidence.

Run only the offline suite:

```sh
.venv/bin/python -B infra/uuid-migration/finalization-tests/test_finalization_offline.py
```

SQLAlchemy compilation and mocks are not PostgreSQL grammar, behavior, locking,
commit, concurrency, recovery or performance acceptance. The 193-case integrity
suite still targets a transitional schema; explicit-duplicate and NULL-update
expectations, final constraints and F-specific approvals need separate review.

See report29 for source hashes, full review-package evidence, compatibility
limitations and the proposed W2.3 promotion gates. No provisioning, promotion,
database operation, backfill or execution approval is included.
