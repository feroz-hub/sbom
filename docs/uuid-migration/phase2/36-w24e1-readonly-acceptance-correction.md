# W2.4E.1 — Complete schema privileges and acceptance evidence correction

**W2.4E.1 OFFLINE VERIFIED — STAGED; STOP for independent review.** 2026-10-19. No PostgreSQL connection, Docker command, real credential read, SQL execution, migration, database mutation, resource change or Git delivery occurred. Source review/tests used synthetic fixtures only. F database identity/authentication/freshness remains NOT ACCEPTED, frozen047 NOT RUNTIME ACCEPTED, all193live integrity cases NOT EXECUTED.

## Verified originals and scope

Required branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`; 2,207 existing file contents snapshotted before edits. Read report35/tracker/actual W2.4E source and original full package. Original package actual SHA256 `18b058d2b290b24ac29464ef2a8cca012aa6473ffb5778126ac7c563af683f9f` and candidatev2 actual SHA256 `3187eba1e6c7313005ec1d522f34cf022c36ec24b55eaadfd3febfa4f86d0ad2` verified, including all ten source bytes/diffs. Protected originals/expiry/previous reports and failures retained unchanged. Original source snapshots preserved separately. No historical migration, frozen047, source lock, W2.4C executor, application or deployment file edited.

## Confirmed defects and minimum corrections

Original `catalog.validate()` accepted only three public-schema rows; missing all non-public grants did not fail. [Offline defect reproduction](/Users/ferozebasha/.sbom-uuid-w2-review/w24e1-20261019T070747692248Z/defect-reproduction.json) confirms zero non-public privilege rows with original catalog_freshtrue, using original inert source and synthetic fixture AST, no database.

New schema validation requires exactly four complete name/owner/rawACL observations and an exact eleven-row privilege multiset. Each row binds schema, owner, grantee, grantor, privilege and actual boolean grantability; missing, duplicate, extra, wrong-owner/grantor, numeric boolean, unexpected field or rawACL representation refuses. SQL change adds only grantor to the existing schema_privileges SELECT; its hash explicitly changes. Other29query hashes,30template set,33planned executions/40ceiling, row/time/control budgets unchanged. No broad grantee/privilege allowlist or missing-observation default remains.

### Source-grounded expected PostgreSQL16.15 policy

The version-tagged [catalog entries](https://github.com/postgres/postgres/blob/REL_16_15/src/include/catalog/pg_namespace.dat) and [owner declaration](https://github.com/postgres/postgres/blob/REL_16_15/src/include/catalog/pg_namespace.h) establish initial public ownership versus bootstrap system-schema ownership. [initdb setup_privileges](https://github.com/postgres/postgres/blob/REL_16_15/src/bin/initdb/initdb.c) grants PUBLIC USAGE to catalog/public, and [information-schema initialization](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/catalog/information_schema.sql) grants its PUBLIC USAGE. [ACL implementation](https://github.com/postgres/postgres/blob/REL_16_15/src/backend/utils/adt/acl.c) supplies NULL owner defaults and owner grantors; [ACL definitions](https://github.com/postgres/postgres/blob/REL_16_15/src/include/utils/acl.h) define rights/serialization.

| Schema | Owner / grantor | Owner privileges | PUBLIC privileges | Stored grant options |
|---|---|---|---|---|
| public | pg_database_owner | CREATE, USAGE | USAGE | false |
| pg_catalog | uuid_w2_f_bootstrap | CREATE, USAGE | USAGE | false |
| information_schema | uuid_w2_f_bootstrap | CREATE, USAGE | USAGE | false |
| pg_toast | uuid_w2_f_bootstrap | CREATE, USAGE via NULL ACL default | none | false |

Each privilege is one exploded row (3+3+3+2=11). Implicit owner grant authority is distinct from stored grant-option bits. Exact rawACL is NULL for toast, otherwise `{owner=UC/owner,=U/owner}`; unknown ordering/representation requires independent review, no automatic normalization. [Complete policy derivation](/Users/ferozebasha/sbom/infra/uuid-migration/f-readonly-acceptance/schema-privilege-review.md) records source symbols and all eleven rows. These are source-derived expectations, **not invented F observations**. Actual image/template initialization, rawACL serialization and PostgreSQL query compatibility remain mandatory runtime dependencies; an unexpected observed representation is a STOP, not an assumed pass.

### Corrected evidence schema

Catalog assessment: `scope=CATALOG_OBSERVATIONS_ONLY`, `catalog_observations=PASS`, `authentication_evidence=PASS` after validation; `overall_acceptance=NOT_EVALUATED_HERE`. Removed ambiguous `live_accepted=false`. Catalog results do not certify lifecycle completion.

Complete probe: `scope=COMPLETE_READ_ONLY_PROBE`; separate checks for catalog observations, actual password-use evidence, transaction rollback acknowledgment, physical closure and infrastructure preservation. Overall accepted/status requires full successful probe, non-null assessment, authentication, known rollback, closure and preservation. Durable STOP recording must succeed before a result can return. Failed cleanup/preservation cannot be overridden by catalog success. Existing failure/secret/byte-hash/authority/rollback/closure controls unchanged.

HBA file parse/content remains file evidence; it does not prove effective last-loaded rules. libpq used_password is required for the future session; storedSCRAMboolean is not exact wire mechanism proof. No server setting/reload or extra connection added.

## Changed files, full diffs and pins

Six existing artifacts changed; two added (new focused tests and schema-policy review). All original ten sources remain preserved in the original package and new protected snapshot.

| Artifact | Original SHA256 | New SHA256 |
|---|---|---|
| README.md | `450085feb8df09d8a0c3883647b9de7ac4ff75b87e89c0cdfca730c0243a01b7` | `d777e7f7a8de16f6cc9b3446cbd4ad8d750685cb1053304d2c42e5e65d3f4870` |
| acceptance-matrix.json | `7ed47f6c6f51c94bac09479b77b71a43e0d1b5500d2bebeeaac38a50222f0d73` | `e1d7ffa68bc4a60e2a96ca988151cc129542cffbd7fa1a71702b46d4388adde4` |
| catalog.py | `f81d3986dea0c706b09cb937dbafde61ab0e2f72402bb106ef4f1869bd8b65c4` | `bb8d007b0a205507ad1a679b8cf27a49d83a6952fa4e60a68de6dde81166d2e7` |
| probe.py | `1a20a5621aca121d995814a7e1178571559fcaf698e757912217935155151e88` | `b292511293107bd53207f52e0530b9848a8829a0ae1c36427e55af11c0a51f12` |
| schema-privilege-review.md | `NEW` | `890acf0747e2c373b700ba7560759e3b3a97062cea27e7fe10584c7bfd74c63f` |
| sql-review.json | `7b4cbedb3edeb6b27bd6f936d642f364efffdf06c1a5274d45ba692be8e6cadf` | `26622cfb572cb227ec26e84bbc3a622cddb11949b4de6fda9b1021fa1d839385` |
| test_correction_offline.py | `NEW` | `93deac08f92dfb94849e5ce2b73a7bcbb299fbb054cae8769d70cf2f6b997ac2` |
| test_readonly_offline.py | `dcc07533ecf39b4317f868e2fe5a563c3404476cbf361d1865e7ad1970a58be8` | `8cc6fc4ec0513425fbc880179a5fd7ac81f6005c388e2a2be0968aaf087797d6` |

[Complete minimal unified source diffs](/Users/ferozebasha/.sbom-uuid-w2-review/w24e1-20261019T070747692248Z/w24e1-source-correction.diff) SHA256 `93bd322ff809642acbff029a376750cf7fa00bf0ddd880911c95911700978bf2`. `security.py`, `entry.py`, `runtime.py`, dependency-lock bytes unchanged. Probe Budget/Evidence/query/control/OPTIONS AST unchanged; only run() adds scoped check/overall evidence. Existing145 test names retained; fixture now independently lists the full eleven source-reviewed rows rather than copying policy output. No migration source edits or live-mode weakening.

## Actual offline test and static results

| Suite | PASS | FAIL | SKIP |
|---|---:|---:|---:|
| f-readonly-acceptance/test_readonly_offline.py | 145 | 0 | 0 |
| f-readonly-acceptance/test_correction_offline.py | 81 | 0 | 0 |
| f-transaction-correction/test_transaction_offline.py | 167 | 0 | 0 |
| f-budget-reconciliation/test_budget_offline.py | 99 | 0 | 0 |
| f-activation/test_activation_offline.py | 126 | 0 | 0 |
| fresh-coordinator/test_coordinator_offline.py | 71 | 0 | 0 |
| fresh-bootstrap/test_fresh_bootstrap.py | 102 | 0 | 0 |
| finalization-tests/test_finalization_offline.py | 53 | 0 | 0 |
| staged-runner/test_expand_one_step.py | 21 | 0 | 0 |
| staged-runner/test_uuid_integrity_offline.py | 53 | 0 | 0 |
| Total | 918 | 0 | 0 |

All837 applicable existing tests rerun, plus81focused tests. Every suite uses `.venv/bin/python -B infra/uuid-migration/<file>` in separate processes; commands/logs/hashes embedded in package. Original145tests also passed before correction. All81new tests passed first functional run and after formatting; no unit-test failures/skips. Focused matrix removes and duplicates every one of11privilege rows, changes everygrantor and schemaowner/ACL field, rejects extra grant/options/fields, and verifies catalog-only success cannot independently accept a probe. Authentication/rollback/close/preservation/error/evidence cases retain no-retry behavior.

SevenPython AST/in-memory compiles,30SQLAlchemy catalogtemplate compiles, exactSQLreview consistency, old42templates/14literal/18dynamic/6index compilation checks PASS. Graph active079/combined091/45units and W2.4C live denials remain unchanged. Rufflint/format sevenPythonfiles, source hashes, original/new candidate rawbyte/expiry/source/SQL/manifest-integrity checks and whitespace PASS. SQLAlchemy compilation and mocks are not PostgreSQL grammar/runtime acceptance.

Development tooling history preserved: first `.venv/bin/ruff` path absent, corrected to installed `/opt/anaconda3/bin/ruff`; initial one new-test I001 and three formatting findings corrected only in scoped files. First graph command named nonexistent entry.py, corrected to existing coordinator.py. These shell/tool failures were not counted as successful checks. Historical failures and six pinned migration import-order warnings remain untouched.

## New versioned candidate and source-review package

[New unapproved v3candidate](/Users/ferozebasha/.sbom-uuid-w2-review/w24e1-20261019T070747692248Z/f-readonly-approval-candidate.v3.json), exact original byte SHA256:

`e3eea378f7c6fcf77b5021d6027a8b5b9ac829e0faafaeb7bc8801e4d8766cd9`

Expiry: **`2026-10-20T06:48:30.897939+00:00`**, identical to originalv2; currently unexpired. No silent authorization renewal. Originalv2/package remain unchanged historical evidence; old source pins intentionally cannot authorize this corrected source. New candidate pins all12source artifacts and the single updated SQL hash. Exact F resource/credential/reference/target/budget fields retained; original protected metadata bytes reviewed offline, **no new infrastructure or secret observation**. Future drift must stop before authentication. Actual F systemID/databaseOID/version/catalog/marker remain null/UNKNOWN, not populated.

All five reviewsfalse (`source_reviewed`, `read_only_session_approved`, `credential_provenance_reviewed`, `privileged_bootstrap_read_reviewed`, `network_egress_reviewed`); actions{}, acceptedfalse, sevenintegrityattestationsfalse/actions{}. No approved manifest/action reference generated.

[Protected complete source-review package](/Users/ferozebasha/.sbom-uuid-w2-review/w24e1-20261019T070747692248Z/w24e1-source-review-package.json), actual byte SHA256:

`278a2bba320d4ae49626c1b2acc090327378fdd50374865829e6bdd4b8ca133e`

Same reviewexpiry;0700directory/0600files. Full12source texts/hashes/diffs, original hashes/snapshot, exact candidate JSON, exact privilege/evidence schema, unchanged dependency/resource/source restrictions,918testresults/tooling failures and runtime limits included. No secret contents/digest recorded.

Safe offline review command:

```sh
.venv/bin/python -B infra/uuid-migration/f-readonly-acceptance/entry.py --mode offline \
  --manifest /Users/ferozebasha/.sbom-uuid-w2-review/w24e1-20261019T070747692248Z/f-readonly-approval-candidate.v3.json \
  --manifest-sha256 e3eea378f7c6fcf77b5021d6027a8b5b9ac829e0faafaeb7bc8801e4d8766cd9
```

## Required next decision and STOP

Independent operator review of this exact source/package/v3candidate and expiry is pending. A later explicit F-only single-session approval must provide the five reviews, a distinct read_only_execute reference and separate approved manifest's exact original-byte SHA256. No source/candidate approval is inferred here or inherited. No PostgreSQL/Docker/credential work, migration, role, marker or integrity case follows automatically.

**F database identity/authentication/freshness NOT ACCEPTED. Frozen047 NOT RUNTIME ACCEPTED. All193live integrity cases NOT EXECUTED. STOP for independent source/package/candidate review.**
