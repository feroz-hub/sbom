# Phase 1 UUID migration: PostgreSQL schema comparison

Audit date: 2026-10-16 (Asia/Kolkata). Repository `feroz-hub/sbom`, branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`.

**Status: COMPLETED — both authorized local targets were accessible through enforced read-only transactions. Schema parity is not established.** No migrations, DML, DDL, business-record exports or business-table count scans were executed.

## Targets and query safeguards

Target **A** uses root `.env` DATABASE_URL (no shell override was present). Target **B** uses the distinct `.env.dev.local` DATABASE_URL. Both were explicitly configured loopback PostgreSQL targets; no other database was inferred or contacted. Neither configuration proves which target a running API/worker/deployment uses. Connection URLs, credentials, usernames and database names are intentionally omitted.

Each connection used startup `default_transaction_read_only=on`, `statement_timeout=3000`, `lock_timeout=1000`, `connect_timeout=3`, and `search_path=pg_catalog`. Inventory reads ran inside **REPEATABLE READ, READ ONLY**, verified with SHOW, and ended with explicit ROLLBACK. Different targets have separate snapshots, not one cross-database transaction. Queries read PostgreSQL catalogs/statistics plus bounded revision-marker rows from public.alembic_version. The initial availability probe counted catalog table entries only. No sequence was advanced, reset or asked for nextval/currval; sequence current/last values were not fetched.

## Observed inventory summary

| Metric | A: root .env | B: .env.dev.local |
| --- | --- | --- |
| Connection status | `ACCESSIBLE` | `ACCESSIBLE` |
| Read-only transaction | `on` | `on` |
| Isolation | `repeatable read` | `repeatable read` |
| Server version | `16.15 (Debian 16.15-1.pgdg13+2)` | `16.15 (Debian 16.15-1.pgdg13+2)` |
| Snapshot UTC | `2026-10-16T09:36:32.587863+00:00` | `2026-10-16T09:36:32.654498+00:00` |
| Alembic revision | `055_ai_model_registry` | `079_lifecycle_provider_verification` |
| Non-system tables | `60` | `72` |
| Columns | `909` | `1143` |
| Indexes, including constraint-backed | `404` | `512` |
| Sequences | `47` | `60` |
| PK constraints | `60` | `72` |
| FK constraints | `94` | `143` |
| UNIQUE constraints | `27` | `39` |
| CHECK constraints | `58` | `72` |
| Native uuid columns | `0` | `0` |
| Identity columns | `0` | `0` |
| Unvalidated catalog constraints | `0` | `0` |
| Invalid or unready indexes | `0` | `0` |
| Tables with unknown reltuples estimate | `46` | `59` |

Repository Alembic head remains `079_lifecycle_provider_verification` ([alembic/versions/079_lifecycle_provider_verification.py:9](../../../alembic/versions/079_lifecycle_provider_verification.py#L9)). A reports a recognized earlier revision, `055_ai_model_registry`; B reports head. Only public-schema objects were found by the non-system table filter. Ordinary/partitioned/foreign tables were included; views, materialized views and system/temp schemas are outside this table inventory.

## Findings that affect the UUID baseline

1. **B has all 71 shared-Base tables and matching PK column tuples**, plus operational `alembic_version`. It has **143 FKs against 144 declared in the ORM**. The missing edge is `vex_documents.superseded_by_id → vex_documents.id`, declared SET NULL at [app/models.py:1324](../../../app/models.py#L1324). The column exists but has no such catalog constraint. For matching FK edges, target tuples, delete/update actions, match type and deferrability agree; no catalog FK is marked unvalidated.
2. **A has 54 of the 71 ORM tables**. Seventeen are absent, and six database tables lie outside the shared Base (including Alembic/Celery/Kombu operational tables and legacy kev_entry). Its revision-related gaps include 39 missing columns and 11 missing FKs on tables that do exist. Missing tables are reported once rather than expanding all their absent columns/constraints/indexes as separate mismatches.
3. **No native uuid column or UUID-generating database default was found in either target.** B's UUID-shaped PKs are varchar(36) on validation sessions, repair jobs and AI fix batches, with no database default; A has validation sessions and AI fix batches, but no repair-jobs table. UUID validity/uniqueness beyond the declared PK and generation format were not tested against stored records.
4. **Both targets have a length difference**: report_subscription.deactivated_by is unbounded varchar in PostgreSQL versus String(128) inherited from [app/models_mixins.py:56](../../../app/models_mixins.py#L56). The migration declares an unbounded string ([alembic/versions/051_report_subscription.py:32](../../../alembic/versions/051_report_subscription.py#L32)). This is confirmed type drift, separate from key-type migration.
5. **B's named permission-code index is nonunique while ORM declares it unique**, but B also has a UNIQUE constraint on the same code column. Effective uniqueness is therefore still present; this is an index/constraint representation discrepancy, not evidence that duplicate codes are allowed. Migration 048 explicitly creates the constraint and a separate index ([alembic/versions/048_authorization_catalog.py:85](../../../alembic/versions/048_authorization_catalog.py#L85), line 102).
6. **Index names are not the same as coverage.** B lacks 14 exact ORM index names: 11 have same-signature indexes under other names, two have PK indexes covering the same key, and one has no exact same-signature counterpart. The last is the nonunique provider_key index on lifecycle_provider_configs; broader prefix/partial coverage was not assessed. Sixteen database-only standalone index names were found on common tables. Thirteen same-name definition differences normalize to equivalent simple predicates/rendering; these are not counted as confirmed semantic drift. A has two confirmed older AI default/fallback uniqueness predicates lacking the tenant_id IS NULL condition, detailed below. These are reported as index-expression differences, not rendering-only differences.
7. **Server defaults differ from model server-default declarations** on 27 B columns and 16 A columns. Most are database defaults beside ORM client-side defaults. This is a direct-SQL insert contract difference, not automatically a broken ORM insert. A's ai_settings.id also has no generation default even though the integer-PK model permits implicit generation; existing code explicitly assigns platform/tenant-derived IDs ([app/routers/ai_credentials.py:1185](../../../app/routers/ai_credentials.py#L1185)). No sequence repair is proposed or executed.
8. Both inspected kev_vulnerabilities tables use the main application's natural CVE primary key, not the separate KEV service's BIGINT Identity id mapping. The separate service was not connected independently. CVE IDs, package identifiers and bom-ref remain natural/document identities, not UUID-surrogate candidates.

A matching revision marker does not prove schema equivalence. This audit neither reconciles the differences nor establishes that A or B is the intended next migration target.

## Comparison method and limits

Expected schema was compiled from the same 71-table shared SQLAlchemy Base used in audits 02–03, with the repository naming convention from app/db.py. The module was substituted with an in-memory Base before importing models, avoiding application settings/engine/startup. PostgreSQL dialect compilation resolved type variants and identifier truncation. The separate KEV mapping is an alternative subsystem, not merged into this Base.

Comparison checks table/column presence, PostgreSQL type/length/timezone, nullability, PK columns, FK column/target tuples and actions/validation/deferrability, UNIQUE column tuples, server defaults versus implicit sequence generation, and named indexes including key order/expressions, uniqueness, method, INCLUDE fields, predicates, expected explicit operator classes and validity/readiness. Naming-convention truncation and ordinary serial defaults were normalized. Float versus PostgreSQL double precision and varchar spelling were normalized. Simple equivalent predicate parentheses/casts and literal IN versus PostgreSQL ANY-array rendering were checked separately with literal values retained in memory for comparison.

CHECK definitions are inventoried but not exhaustively compared to model expressions. Unique-constraint equivalence was compared by ordered column tuple; advanced NULLS NOT DISTINCT, exclusion/storage options, collation differences, privileges/RLS, triggers, partitions and business invariants are not certified by this comparison. Index access-path performance or broader prefix coverage was not measured. Server defaults are distinct from Python client defaults. All string literals in published catalog default/index/check expressions are redacted except nextval sequence identifiers; this does not imply the literals were equal. No application/UUID value samples were read.

## ORM versus database differences

Counts are observations on common tables except missing/extra-table rows. Name-only differences and equivalent rendering are listed separately from structural drift. The operational Alembic table and intentional migration-created indexes/defaults are still recorded so nothing is silently excluded.

### A — root .env DATABASE_URL

| Difference category | Count |
| --- | --- |
| Column generation | 1 |
| Column nullability | 2 |
| Column type | 1 |
| Extra database UNIQUE constraint | 7 |
| Extra database index | 7 |
| Extra database table | 6 |
| Index expression review | 2 |
| Index rendering equivalent | 6 |
| Index structure | 3 |
| Missing ORM FK | 11 |
| Missing ORM UNIQUE constraint | 8 |
| Missing ORM column | 39 |
| Missing ORM table | 17 |
| Missing named ORM index | 30 |
| Server default | 16 |

| Table | Difference | Detail | ORM source |
| --- | --- | --- | --- |
| `account_action_tokens` | Missing ORM table | `Absent from public schema` | [app/models.py:179](../../../app/models.py#L179) |
| `advisor_policy` | Missing ORM table | `Absent from public schema` | [app/models.py:2439](../../../app/models.py#L2439) |
| `advisor_policy_version` | Missing ORM table | `Absent from public schema` | [app/models.py:2473](../../../app/models.py#L2473) |
| `ai_credential_audit_log` | Missing ORM FK | `(('tenant_id',), 'public', 'tenants', ('id',))` | [app/models.py:2232](../../../app/models.py#L2232) |
| `ai_credential_audit_log` | Missing ORM column | `tenant_id: INTEGER` | [app/models.py:2244](../../../app/models.py#L2244) |
| `ai_provider_credential` | Extra database UNIQUE constraint | `uq_ai_provider_credential_provider_label ('provider_name', 'label')` | [app/models.py:2094](../../../app/models.py#L2094) |
| `ai_provider_credential` | Missing ORM FK | `(('tenant_id',), 'public', 'tenants', ('id',))` | [app/models.py:2094](../../../app/models.py#L2094) |
| `ai_provider_credential` | Missing ORM UNIQUE constraint | `('tenant_id', 'provider_name', 'label')` | [app/models.py:2094](../../../app/models.py#L2094) |
| `ai_provider_credential` | Missing ORM column | `tenant_id: INTEGER` | [app/models.py:2110](../../../app/models.py#L2110) |
| `ai_provider_model` | Server default | `discovery_source: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models.py:2180](../../../app/models.py#L2180) |
| `ai_provider_model` | Server default | `is_enabled: ORM —; DB true (client-side defaults excluded)` | [app/models.py:2170](../../../app/models.py#L2170) |
| `ai_provider_model` | Server default | `is_selected: ORM —; DB false (client-side defaults excluded)` | [app/models.py:2171](../../../app/models.py#L2171) |
| `ai_settings` | Column generation | `id: implicit ORM integer generation; DB has no sequence/identity default` | [app/models.py:2219](../../../app/models.py#L2219) |
| `ai_settings` | Missing ORM FK | `(('tenant_id',), 'public', 'tenants', ('id',))` | [app/models.py:2211](../../../app/models.py#L2211) |
| `ai_settings` | Missing ORM UNIQUE constraint | `('tenant_id',)` | [app/models.py:2211](../../../app/models.py#L2211) |
| `ai_settings` | Missing ORM column | `tenant_id: INTEGER` | [app/models.py:2220](../../../app/models.py#L2220) |
| `alembic_version` | Extra database table | `Operational Alembic table` | Outside shared Base |
| `analysis_finding` | Extra database UNIQUE constraint | `uq_analysis_finding_run_vuln_cpe ('analysis_run_id', 'vuln_id', 'cpe')` | [app/models.py:1628](../../../app/models.py#L1628) |
| `analysis_finding` | Missing ORM UNIQUE constraint | `('analysis_run_id', 'reconciliation_key')` | [app/models.py:1628](../../../app/models.py#L1628) |
| `analysis_finding` | Missing ORM column | `evidence_json: JSON` | [app/models.py:1677](../../../app/models.py#L1677) |
| `analysis_finding` | Missing ORM column | `reconciliation_key: VARCHAR(64)` | [app/models.py:1678](../../../app/models.py#L1678) |
| `analysis_run` | Missing ORM column | `analysis_input_fingerprint: JSON` | [app/models.py:1598](../../../app/models.py#L1598) |
| `analysis_run` | Missing ORM column | `is_current: BOOLEAN` | [app/models.py:1597](../../../app/models.py#L1597) |
| `authorization_permissions` | Extra database UNIQUE constraint | `uq_authorization_permissions_code ('code',)` | [app/models.py:395](../../../app/models.py#L395) |
| `celery_taskmeta` | Extra database table | `No shared-Base ORM table` | Outside shared Base |
| `celery_tasksetmeta` | Extra database table | `No shared-Base ORM table` | Outside shared Base |
| `component_lifecycle_cache` | Extra database UNIQUE constraint | `uq_component_lifecycle_cache_identity ('normalized_name', 'normalized_version', 'ecosystem', 'purl')` | [app/models.py:1148](../../../app/models.py#L1148) |
| `component_lifecycle_cache` | Missing ORM UNIQUE constraint | `('configuration_namespace', 'normalized_name', 'normalized_version', 'ecosystem', 'purl')` | [app/models.py:1148](../../../app/models.py#L1148) |
| `component_lifecycle_cache` | Missing ORM column | `configuration_namespace: VARCHAR(128)` | [app/models.py:1154](../../../app/models.py#L1154) |
| `component_purpose_metadata` | Missing ORM table | `Absent from public schema` | [app/models.py:2497](../../../app/models.py#L2497) |
| `component_recommendation` | Missing ORM table | `Absent from public schema` | [app/models.py:2532](../../../app/models.py#L2532) |
| `component_recommendation_candidate` | Missing ORM table | `Absent from public schema` | [app/models.py:2600](../../../app/models.py#L2600) |
| `component_recommendation_compatibility_check` | Missing ORM table | `Absent from public schema` | [app/models.py:2645](../../../app/models.py#L2645) |
| `component_recommendation_event` | Missing ORM table | `Absent from public schema` | [app/models.py:2699](../../../app/models.py#L2699) |
| `component_recommendation_factor` | Missing ORM table | `Absent from public schema` | [app/models.py:2670](../../../app/models.py#L2670) |
| `iam_users` | Column nullability | `external_iam_user_id: ORM NULL; DB NOT NULL` | [app/models.py:59](../../../app/models.py#L59) |
| `iam_users` | Missing ORM column | `first_name: VARCHAR(255)` | [app/models.py:67](../../../app/models.py#L67) |
| `iam_users` | Missing ORM column | `last_name: VARCHAR(255)` | [app/models.py:68](../../../app/models.py#L68) |
| `iam_users` | Missing ORM column | `normalized_email: VARCHAR(320)` | [app/models.py:72](../../../app/models.py#L72) |
| `iam_users` | Missing ORM column | `phone: VARCHAR(64)` | [app/models.py:69](../../../app/models.py#L69) |
| `kev_entry` | Extra database table | `No shared-Base ORM table` | Outside shared Base |
| `kombu_message` | Extra database table | `No shared-Base ORM table` | Outside shared Base |
| `kombu_queue` | Extra database table | `No shared-Base ORM table` | Outside shared Base |
| `lifecycle_provider_configs` | Missing ORM FK | `(('tenant_id',), 'public', 'tenants', ('id',))` | [app/models.py:1193](../../../app/models.py#L1193) |
| `lifecycle_provider_configs` | Missing ORM UNIQUE constraint | `('tenant_id', 'provider_key')` | [app/models.py:1193](../../../app/models.py#L1193) |
| `lifecycle_provider_configs` | Missing ORM column | `last_lookup_at: VARCHAR` | [app/models.py:1216](../../../app/models.py#L1216) |
| `lifecycle_provider_configs` | Missing ORM column | `last_probe_json: JSON` | [app/models.py:1215](../../../app/models.py#L1215) |
| `lifecycle_provider_configs` | Missing ORM column | `tenant_id: INTEGER` | [app/models.py:1199](../../../app/models.py#L1199) |
| `lifecycle_provider_secrets` | Extra database UNIQUE constraint | `uq_lifecycle_provider_secret_provider_name ('provider_key', 'secret_name')` | [app/models.py:1239](../../../app/models.py#L1239) |
| `lifecycle_provider_secrets` | Missing ORM FK | `(('tenant_id',), 'public', 'tenants', ('id',))` | [app/models.py:1239](../../../app/models.py#L1239) |
| `lifecycle_provider_secrets` | Missing ORM UNIQUE constraint | `('tenant_id', 'provider_key', 'secret_name')` | [app/models.py:1239](../../../app/models.py#L1239) |
| `lifecycle_provider_secrets` | Missing ORM column | `tenant_id: INTEGER` | [app/models.py:1245](../../../app/models.py#L1245) |
| `logical_sbom` | Missing ORM table | `Absent from public schema` | [app/models.py:732](../../../app/models.py#L732) |
| `native_platform_bootstrap` | Missing ORM table | `Absent from public schema` | [app/models.py:204](../../../app/models.py#L204) |
| `native_user_credentials` | Missing ORM table | `Absent from public schema` | [app/models.py:159](../../../app/models.py#L159) |
| `platform_user_roles` | Extra database UNIQUE constraint | `uq_platform_user_roles_user_id ('user_id',)` | [app/models.py:334](../../../app/models.py#L334) |
| `products` | Missing ORM UNIQUE constraint | `('id', 'tenant_id')` | [app/models.py:656](../../../app/models.py#L656) |
| `products` | Missing ORM column | `current_sbom_mode: VARCHAR(16)` | [app/models.py:685](../../../app/models.py#L685) |
| `report_delivery` | Server default | `attempt_count: ORM —; DB 0 (client-side defaults excluded)` | [app/models_reports.py:83](../../../app/models_reports.py#L83) |
| `report_delivery` | Server default | `run_count: ORM —; DB 0 (client-side defaults excluded)` | [app/models_reports.py:86](../../../app/models_reports.py#L86) |
| `report_delivery` | Server default | `sbom_count: ORM —; DB 0 (client-side defaults excluded)` | [app/models_reports.py:85](../../../app/models_reports.py#L85) |
| `report_delivery` | Server default | `status: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:81](../../../app/models_reports.py#L81) |
| `report_subscription` | Column type | `deactivated_by: ORM VARCHAR(128); DB character varying` | [app/models_mixins.py:56](../../../app/models_mixins.py#L56) |
| `report_subscription` | Server default | `baseline_mode: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:32](../../../app/models_reports.py#L32) |
| `report_subscription` | Server default | `cadence: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:28](../../../app/models_reports.py#L28) |
| `report_subscription` | Server default | `cross_version_target: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:33](../../../app/models_reports.py#L33) |
| `report_subscription` | Server default | `enabled: ORM —; DB true (client-side defaults excluded)` | [app/models_reports.py:36](../../../app/models_reports.py#L36) |
| `report_subscription` | Server default | `formats: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:30](../../../app/models_reports.py#L30) |
| `report_subscription` | Server default | `parts: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:29](../../../app/models_reports.py#L29) |
| `report_subscription` | Server default | `severity_floor: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:31](../../../app/models_reports.py#L31) |
| `report_subscription` | Server default | `suppress_when_unchanged: ORM —; DB false (client-side defaults excluded)` | [app/models_reports.py:35](../../../app/models_reports.py#L35) |
| `report_subscription` | Server default | `timezone: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:34](../../../app/models_reports.py#L34) |
| `sbom_component` | Missing ORM column | `description: TEXT` | [app/models.py:1101](../../../app/models.py#L1101) |
| `sbom_repair_jobs` | Missing ORM table | `Absent from public schema` | [app/models.py:1003](../../../app/models.py#L1003) |
| `sbom_source` | Extra database UNIQUE constraint | `uq_sbom_source_tenant_name_version ('tenant_id', 'sbom_name', 'sbom_version')` | [app/models.py:752](../../../app/models.py#L752) |
| `sbom_source` | Missing ORM FK | `(('logical_sbom_id', 'tenant_id'), 'public', 'logical_sbom', ('id', 'tenant_id'))` | [app/models.py:752](../../../app/models.py#L752) |
| `sbom_source` | Missing ORM FK | `(('logical_sbom_id', 'tenant_id', 'product_id'), 'public', 'logical_sbom', ('id', 'tenant_id', 'product_id'))` | [app/models.py:752](../../../app/models.py#L752) |
| `sbom_source` | Missing ORM FK | `(('logical_sbom_id',), 'public', 'logical_sbom', ('id',))` | [app/models.py:752](../../../app/models.py#L752) |
| `sbom_source` | Missing ORM UNIQUE constraint | `('logical_sbom_id', 'sbom_version')` | [app/models.py:752](../../../app/models.py#L752) |
| `sbom_source` | Missing ORM column | `analysis_requires_reanalysis: BOOLEAN` | [app/models.py:780](../../../app/models.py#L780) |
| `sbom_source` | Missing ORM column | `lifecycle_revision: INTEGER` | [app/models.py:779](../../../app/models.py#L779) |
| `sbom_source` | Missing ORM column | `lifecycle_status: VARCHAR(8)` | [app/models.py:778](../../../app/models.py#L778) |
| `sbom_source` | Missing ORM column | `logical_sbom_id: INTEGER` | [app/models.py:756](../../../app/models.py#L756) |
| `security_mail_outbox` | Missing ORM table | `Absent from public schema` | [app/models.py:220](../../../app/models.py#L220) |
| `user_identities` | Missing ORM table | `Absent from public schema` | [app/models.py:116](../../../app/models.py#L116) |
| `vex_documents` | Missing ORM FK | `(('superseded_by_id',), 'public', 'vex_documents', ('id',))` | [app/models.py:1296](../../../app/models.py#L1296) |
| `vex_documents` | Missing ORM column | `asserted_at: VARCHAR` | [app/models.py:1323](../../../app/models.py#L1323) |
| `vex_documents` | Missing ORM column | `source_document_id: VARCHAR` | [app/models.py:1320](../../../app/models.py#L1320) |
| `vex_documents` | Missing ORM column | `source_document_version: VARCHAR` | [app/models.py:1321](../../../app/models.py#L1321) |
| `vex_documents` | Missing ORM column | `source_hash: VARCHAR(64)` | [app/models.py:1322](../../../app/models.py#L1322) |
| `vex_documents` | Missing ORM column | `superseded_by_id: INTEGER` | [app/models.py:1324](../../../app/models.py#L1324) |
| `vex_investigation` | Missing ORM table | `Absent from public schema` | [app/models.py:1386](../../../app/models.py#L1386) |
| `vex_investigation_snapshot` | Missing ORM table | `Absent from public schema` | [app/models.py:1510](../../../app/models.py#L1510) |
| `vex_override_audit` | Column nullability | `component_id: ORM NULL; DB NOT NULL` | [app/models.py:1549](../../../app/models.py#L1549) |
| `vex_override_audit` | Missing ORM FK | `(('investigation_id',), 'public', 'vex_investigation', ('id',))` | [app/models.py:1522](../../../app/models.py#L1522) |
| `vex_override_audit` | Missing ORM FK | `(('sbom_id',), 'public', 'sbom_source', ('id',))` | [app/models.py:1522](../../../app/models.py#L1522) |
| `vex_override_audit` | Missing ORM column | `action: VARCHAR(32)` | [app/models.py:1555](../../../app/models.py#L1555) |
| `vex_override_audit` | Missing ORM column | `investigation_id: INTEGER` | [app/models.py:1551](../../../app/models.py#L1551) |
| `vex_override_audit` | Missing ORM column | `new_status: VARCHAR(32)` | [app/models.py:1557](../../../app/models.py#L1557) |
| `vex_override_audit` | Missing ORM column | `previous_status: VARCHAR(32)` | [app/models.py:1556](../../../app/models.py#L1556) |
| `vex_override_audit` | Missing ORM column | `sbom_id: INTEGER` | [app/models.py:1550](../../../app/models.py#L1550) |
| `vex_statements` | Missing ORM column | `asserted_at: VARCHAR` | [app/models.py:1368](../../../app/models.py#L1368) |
| `vex_statements` | Missing ORM column | `match_confidence: VARCHAR(16)` | [app/models.py:1372](../../../app/models.py#L1372) |
| `vex_statements` | Missing ORM column | `match_strategy: VARCHAR(32)` | [app/models.py:1371](../../../app/models.py#L1371) |
| `vex_statements` | Missing ORM column | `normalized_status: VARCHAR(32)` | [app/models.py:1367](../../../app/models.py#L1367) |
| `vex_statements` | Missing ORM column | `source_format: VARCHAR(32)` | [app/models.py:1365](../../../app/models.py#L1365) |
| `vex_statements` | Missing ORM column | `source_status: VARCHAR(64)` | [app/models.py:1366](../../../app/models.py#L1366) |
| `vex_statements` | Missing ORM column | `version_applicable: BOOLEAN` | [app/models.py:1375](../../../app/models.py#L1375) |

| Table / index | Comparison result | Detail |
| --- | --- | --- |
| `ai_credential_audit_log.ix_ai_credential_audit_log_tenant_id` | Missing named ORM index | `CREATE INDEX ix_ai_credential_audit_log_tenant_id ON ai_credential_audit_log (tenant_id); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `ai_provider_credential.ix_ai_only_one_default` | Index expression review | `ORM CREATE UNIQUE INDEX ix_ai_only_one_default ON ai_provider_credential (is_default) WHERE is_default = TRUE AND tenant_id IS NULL; DB CREATE UNIQUE INDEX ix_ai_only_one_default ON public.ai_provider_credential USING btree (is_default) WHERE (is_default = true)` |
| `ai_provider_credential.ix_ai_only_one_fallback` | Index expression review | `ORM CREATE UNIQUE INDEX ix_ai_only_one_fallback ON ai_provider_credential (is_fallback) WHERE is_fallback = TRUE AND tenant_id IS NULL; DB CREATE UNIQUE INDEX ix_ai_only_one_fallback ON public.ai_provider_credential USING btree (is_fallback) WHERE (is_fallback = true)` |
| `ai_provider_credential.ix_ai_provider_credential_tenant_id` | Missing named ORM index | `CREATE INDEX ix_ai_provider_credential_tenant_id ON ai_provider_credential (tenant_id); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `ai_provider_credential.ix_ai_tenant_default` | Missing named ORM index | `CREATE UNIQUE INDEX ix_ai_tenant_default ON ai_provider_credential (tenant_id) WHERE is_default = TRUE AND tenant_id IS NOT NULL; No exact same-signature index; broader prefix/partial coverage not assessed` |
| `ai_provider_credential.ix_ai_tenant_fallback` | Missing named ORM index | `CREATE UNIQUE INDEX ix_ai_tenant_fallback ON ai_provider_credential (tenant_id) WHERE is_fallback = TRUE AND tenant_id IS NOT NULL; No exact same-signature index; broader prefix/partial coverage not assessed` |
| `ai_provider_credential.uq_ai_credential_platform` | Missing named ORM index | `CREATE UNIQUE INDEX uq_ai_credential_platform ON ai_provider_credential (provider_name, label) WHERE tenant_id IS NULL; No exact same-signature index; broader prefix/partial coverage not assessed` |
| `ai_provider_model.ix_ai_provider_model_id` | Missing named ORM index | `CREATE INDEX ix_ai_provider_model_id ON ai_provider_model (id); PK index covers same key: pk_ai_provider_model` |
| `ai_settings.uq_ai_settings_platform` | Missing named ORM index | `CREATE UNIQUE INDEX uq_ai_settings_platform ON ai_settings ((1)) WHERE tenant_id IS NULL; No exact same-signature index; broader prefix/partial coverage not assessed` |
| `analysis_run.ix_analysis_run_is_current` | Missing named ORM index | `CREATE INDEX ix_analysis_run_is_current ON analysis_run (is_current); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `analysis_schedule.uq_analysis_schedule_tenant` | Extra database index | `CREATE UNIQUE INDEX uq_analysis_schedule_tenant ON public.analysis_schedule USING btree (tenant_id) WHERE (((scope)::text = '<literal redacted>'::text) AND is_active)` |
| `authorization_permissions.ix_authorization_permissions_code` | Index structure | `ORM (True, 'btree', []); DB (False, 'btree', [])` |
| `email_verification_tokens.uq_email_verification_tokens_active_user` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_email_verification_tokens_active_user ON email_verification_tokens (user_id) WHERE consumed_at IS NULL AND invalidated_at IS NULL; DB CREATE UNIQUE INDEX uq_email_verification_tokens_active_user ON public.email_verification_tokens USING btree (user_id) WHERE ((consumed_at IS NULL) AND (invalidated_at IS NULL))` |
| `iam_users.ix_iam_users_normalized_email` | Missing named ORM index | `CREATE INDEX ix_iam_users_normalized_email ON iam_users (normalized_email); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `lifecycle_provider_configs.ix_lifecycle_provider_configs_provider_key` | Index structure | `ORM (False, 'btree', []); DB (True, 'btree', [])` |
| `lifecycle_provider_configs.ix_lifecycle_provider_configs_tenant_id` | Missing named ORM index | `CREATE INDEX ix_lifecycle_provider_configs_tenant_id ON lifecycle_provider_configs (tenant_id); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `lifecycle_provider_configs.uq_lifecycle_provider_platform` | Missing named ORM index | `CREATE UNIQUE INDEX uq_lifecycle_provider_platform ON lifecycle_provider_configs (provider_key) WHERE tenant_id IS NULL; No exact same-signature index; broader prefix/partial coverage not assessed` |
| `lifecycle_provider_secrets.ix_lifecycle_provider_secrets_tenant_id` | Missing named ORM index | `CREATE INDEX ix_lifecycle_provider_secrets_tenant_id ON lifecycle_provider_secrets (tenant_id); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `lifecycle_provider_secrets.uq_lifecycle_secret_platform` | Missing named ORM index | `CREATE UNIQUE INDEX uq_lifecycle_secret_platform ON lifecycle_provider_secrets (provider_key, secret_name) WHERE tenant_id IS NULL; No exact same-signature index; broader prefix/partial coverage not assessed` |
| `platform_user_roles.ix_platform_user_roles_user_id` | Index structure | `ORM (True, 'btree', []); DB (False, 'btree', [])` |
| `report_subscription.uq_report_subscription_product` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_report_subscription_product ON report_subscription (tenant_id, iam_user_id, product_id) WHERE is_active AND scope = '<literal redacted>'; DB CREATE UNIQUE INDEX uq_report_subscription_product ON public.report_subscription USING btree (tenant_id, iam_user_id, product_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |
| `report_subscription.uq_report_subscription_project` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_report_subscription_project ON report_subscription (tenant_id, iam_user_id, project_id) WHERE is_active AND scope = '<literal redacted>'; DB CREATE UNIQUE INDEX uq_report_subscription_project ON public.report_subscription USING btree (tenant_id, iam_user_id, project_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |
| `report_subscription.uq_report_subscription_sbom` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_report_subscription_sbom ON report_subscription (tenant_id, iam_user_id, sbom_id) WHERE is_active AND scope = '<literal redacted>'; DB CREATE UNIQUE INDEX uq_report_subscription_sbom ON public.report_subscription USING btree (tenant_id, iam_user_id, sbom_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |
| `report_subscription.uq_report_subscription_tenant` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_report_subscription_tenant ON report_subscription (tenant_id, iam_user_id) WHERE is_active AND scope = '<literal redacted>'; DB CREATE UNIQUE INDEX uq_report_subscription_tenant ON public.report_subscription USING btree (tenant_id, iam_user_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |
| `sbom_component.ix_sbom_component_tenant_canonical` | Missing named ORM index | `CREATE INDEX ix_sbom_component_tenant_canonical ON sbom_component (tenant_id, dedupe_canonical_id); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `sbom_component.ix_sbom_component_tenant_package_key` | Missing named ORM index | `CREATE INDEX ix_sbom_component_tenant_package_key ON sbom_component (tenant_id, normalized_package_key); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `sbom_source.ix_sbom_source_lifecycle_status` | Missing named ORM index | `CREATE INDEX ix_sbom_source_lifecycle_status ON sbom_source (lifecycle_status); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `sbom_source.ix_sbom_source_logical_sbom_id` | Missing named ORM index | `CREATE INDEX ix_sbom_source_logical_sbom_id ON sbom_source (logical_sbom_id); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `sbom_source.uq_sbom_source_logical_unversioned` | Missing named ORM index | `CREATE UNIQUE INDEX uq_sbom_source_logical_unversioned ON sbom_source (logical_sbom_id) WHERE sbom_version IS NULL; No exact same-signature index; broader prefix/partial coverage not assessed` |
| `tenant_user_role_assignment_history.ix_tenant_role_assignment_history_assignment_id` | Extra database index | `CREATE INDEX ix_tenant_role_assignment_history_assignment_id ON public.tenant_user_role_assignment_history USING btree (assignment_id)` |
| `tenant_user_role_assignment_history.ix_tenant_role_assignment_history_occurred_at` | Extra database index | `CREATE INDEX ix_tenant_role_assignment_history_occurred_at ON public.tenant_user_role_assignment_history USING btree (occurred_at)` |
| `tenant_user_role_assignment_history.ix_tenant_role_assignment_history_tenant_id` | Extra database index | `CREATE INDEX ix_tenant_role_assignment_history_tenant_id ON public.tenant_user_role_assignment_history USING btree (tenant_id)` |
| `tenant_user_role_assignment_history.ix_tenant_role_assignment_history_tenant_user_id` | Extra database index | `CREATE INDEX ix_tenant_role_assignment_history_tenant_user_id ON public.tenant_user_role_assignment_history USING btree (tenant_user_id)` |
| `tenant_user_role_assignment_history.ix_tenant_user_role_assignment_history_assignment_id` | Missing named ORM index | `CREATE INDEX ix_tenant_user_role_assignment_history_assignment_id ON tenant_user_role_assignment_history (assignment_id); Same signature under: ix_tenant_role_assignment_history_assignment_id` |
| `tenant_user_role_assignment_history.ix_tenant_user_role_assignment_history_tenant_id` | Missing named ORM index | `CREATE INDEX ix_tenant_user_role_assignment_history_tenant_id ON tenant_user_role_assignment_history (tenant_id); Same signature under: ix_tenant_role_assignment_history_tenant_id` |
| `tenant_user_role_assignment_history.ix_tenant_user_role_assignment_history_tenant_user_id` | Missing named ORM index | `CREATE INDEX ix_tenant_user_role_assignment_history_tenant_user_id ON tenant_user_role_assignment_history (tenant_user_id); Same signature under: ix_tenant_role_assignment_history_tenant_user_id` |
| `tenant_user_role_assignments.ix_tenant_user_role_assignments_membership_status` | Extra database index | `CREATE INDEX ix_tenant_user_role_assignments_membership_status ON public.tenant_user_role_assignments USING btree (tenant_user_id, status)` |
| `tenant_user_role_assignments.ix_tenant_user_role_assignments_status` | Extra database index | `CREATE INDEX ix_tenant_user_role_assignments_status ON public.tenant_user_role_assignments USING btree (status)` |
| `tenant_user_role_assignments.uq_tenant_user_role_assignments_active_primary` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_tenant_user_role_assignments_active_primary ON tenant_user_role_assignments (tenant_user_id) WHERE status = '<literal redacted>' AND is_primary; DB CREATE UNIQUE INDEX uq_tenant_user_role_assignments_active_primary ON public.tenant_user_role_assignments USING btree (tenant_user_id) WHERE (((status)::text = '<literal redacted>'::text) AND is_primary)` |
| `vex_documents.ix_vex_documents_asserted_at` | Missing named ORM index | `CREATE INDEX ix_vex_documents_asserted_at ON vex_documents (asserted_at); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `vex_documents.ix_vex_documents_source_document_id` | Missing named ORM index | `CREATE INDEX ix_vex_documents_source_document_id ON vex_documents (source_document_id); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `vex_documents.ix_vex_documents_source_hash` | Missing named ORM index | `CREATE INDEX ix_vex_documents_source_hash ON vex_documents (source_hash); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `vex_documents.ix_vex_documents_superseded_by_id` | Missing named ORM index | `CREATE INDEX ix_vex_documents_superseded_by_id ON vex_documents (superseded_by_id); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `vex_override_audit.ix_vex_override_audit_action` | Missing named ORM index | `CREATE INDEX ix_vex_override_audit_action ON vex_override_audit (action); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `vex_override_audit.ix_vex_override_audit_investigation_id` | Missing named ORM index | `CREATE INDEX ix_vex_override_audit_investigation_id ON vex_override_audit (investigation_id); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `vex_override_audit.ix_vex_override_audit_sbom_id` | Missing named ORM index | `CREATE INDEX ix_vex_override_audit_sbom_id ON vex_override_audit (sbom_id); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `vex_statements.ix_vex_statements_normalized_status` | Missing named ORM index | `CREATE INDEX ix_vex_statements_normalized_status ON vex_statements (normalized_status); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `vex_statements.ix_vex_statements_source_format` | Missing named ORM index | `CREATE INDEX ix_vex_statements_source_format ON vex_statements (source_format); No exact same-signature index; broader prefix/partial coverage not assessed` |

### B — .env.dev.local DATABASE_URL

| Difference category | Count |
| --- | --- |
| Column type | 1 |
| Constraint name only | 13 |
| Extra database UNIQUE constraint | 1 |
| Extra database index | 16 |
| Extra database table | 1 |
| Index rendering equivalent | 13 |
| Index structure | 1 |
| Missing ORM FK | 1 |
| Missing named ORM index | 14 |
| Server default | 27 |

| Table | Difference | Detail | ORM source |
| --- | --- | --- | --- |
| `ai_credential_audit_log` | Constraint name only | `FK ('tenant_id',): ORM fk_ai_credential_audit_log_tenant_id_tenants; DB fk_ai_credential_audit_log_configuration_tenant` | [app/models.py:2232](../../../app/models.py#L2232) |
| `ai_provider_credential` | Constraint name only | `FK ('tenant_id',): ORM fk_ai_provider_credential_tenant_id_tenants; DB fk_ai_provider_credential_configuration_tenant` | [app/models.py:2094](../../../app/models.py#L2094) |
| `ai_provider_credential` | Constraint name only | `UNIQUE ('tenant_id', 'provider_name', 'label'): ORM uq_ai_credential_tenant; DB uq_ai_provider_credential_tenant_slot` | [app/models.py:2094](../../../app/models.py#L2094) |
| `ai_provider_model` | Server default | `discovery_source: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models.py:2180](../../../app/models.py#L2180) |
| `ai_provider_model` | Server default | `is_enabled: ORM —; DB true (client-side defaults excluded)` | [app/models.py:2170](../../../app/models.py#L2170) |
| `ai_provider_model` | Server default | `is_selected: ORM —; DB false (client-side defaults excluded)` | [app/models.py:2171](../../../app/models.py#L2171) |
| `ai_settings` | Constraint name only | `FK ('tenant_id',): ORM fk_ai_settings_tenant_id_tenants; DB fk_ai_settings_configuration_tenant` | [app/models.py:2211](../../../app/models.py#L2211) |
| `ai_settings` | Constraint name only | `UNIQUE ('tenant_id',): ORM uq_ai_settings_tenant_id; DB uq_ai_settings_tenant` | [app/models.py:2211](../../../app/models.py#L2211) |
| `alembic_version` | Extra database table | `Operational Alembic table` | Outside shared Base |
| `authorization_permissions` | Extra database UNIQUE constraint | `uq_authorization_permissions_code ('code',)` | [app/models.py:395](../../../app/models.py#L395) |
| `cves` | Constraint name only | `PK ORM pk_cves; DB cves_pkey` | [app/nvd_mirror/db/models.py:82](../../../app/nvd_mirror/db/models.py#L82) |
| `cves` | Server default | `aliases: ORM —; DB '<literal redacted>'::jsonb (client-side defaults excluded)` | [app/nvd_mirror/db/models.py:112](../../../app/nvd_mirror/db/models.py#L112) |
| `cves` | Server default | `cpe_match: ORM —; DB '<literal redacted>'::jsonb (client-side defaults excluded)` | [app/nvd_mirror/db/models.py:113](../../../app/nvd_mirror/db/models.py#L113) |
| `cves` | Server default | `references: ORM —; DB '<literal redacted>'::jsonb (client-side defaults excluded)` | [app/nvd_mirror/db/models.py:114](../../../app/nvd_mirror/db/models.py#L114) |
| `lifecycle_provider_configs` | Constraint name only | `FK ('tenant_id',): ORM fk_lifecycle_provider_configs_tenant_id_tenants; DB fk_lifecycle_provider_configs_configuration_tenant` | [app/models.py:1193](../../../app/models.py#L1193) |
| `lifecycle_provider_configs` | Constraint name only | `UNIQUE ('tenant_id', 'provider_key'): ORM uq_lifecycle_provider_tenant; DB uq_lifecycle_provider_configs_tenant_slot` | [app/models.py:1193](../../../app/models.py#L1193) |
| `lifecycle_provider_secrets` | Constraint name only | `FK ('tenant_id',): ORM fk_lifecycle_provider_secrets_tenant_id_tenants; DB fk_lifecycle_provider_secrets_configuration_tenant` | [app/models.py:1239](../../../app/models.py#L1239) |
| `lifecycle_provider_secrets` | Constraint name only | `UNIQUE ('tenant_id', 'provider_key', 'secret_name'): ORM uq_lifecycle_secret_tenant; DB uq_lifecycle_provider_secrets_tenant_slot` | [app/models.py:1239](../../../app/models.py#L1239) |
| `nvd_settings` | Constraint name only | `PK ORM pk_nvd_settings; DB nvd_settings_pkey` | [app/nvd_mirror/db/models.py:45](../../../app/nvd_mirror/db/models.py#L45) |
| `nvd_settings` | Server default | `api_endpoint: ORM —; DB '<literal redacted>'::text (client-side defaults excluded)` | [app/nvd_mirror/db/models.py:62](../../../app/nvd_mirror/db/models.py#L62) |
| `nvd_settings` | Server default | `download_feeds_enabled: ORM —; DB false (client-side defaults excluded)` | [app/nvd_mirror/db/models.py:68](../../../app/nvd_mirror/db/models.py#L68) |
| `nvd_settings` | Server default | `enabled: ORM —; DB false (client-side defaults excluded)` | [app/nvd_mirror/db/models.py:61](../../../app/nvd_mirror/db/models.py#L61) |
| `nvd_settings` | Server default | `min_freshness_hours: ORM —; DB 24 (client-side defaults excluded)` | [app/nvd_mirror/db/models.py:71](../../../app/nvd_mirror/db/models.py#L71) |
| `nvd_settings` | Server default | `page_size: ORM —; DB 2000 (client-side defaults excluded)` | [app/nvd_mirror/db/models.py:69](../../../app/nvd_mirror/db/models.py#L69) |
| `nvd_settings` | Server default | `window_days: ORM —; DB 119 (client-side defaults excluded)` | [app/nvd_mirror/db/models.py:70](../../../app/nvd_mirror/db/models.py#L70) |
| `nvd_sync_runs` | Constraint name only | `PK ORM pk_nvd_sync_runs; DB nvd_sync_runs_pkey` | [app/nvd_mirror/db/models.py:123](../../../app/nvd_mirror/db/models.py#L123) |
| `nvd_sync_runs` | Server default | `status: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/nvd_mirror/db/models.py:155](../../../app/nvd_mirror/db/models.py#L155) |
| `nvd_sync_runs` | Server default | `upserted_count: ORM —; DB 0 (client-side defaults excluded)` | [app/nvd_mirror/db/models.py:156](../../../app/nvd_mirror/db/models.py#L156) |
| `report_delivery` | Server default | `attempt_count: ORM —; DB 0 (client-side defaults excluded)` | [app/models_reports.py:83](../../../app/models_reports.py#L83) |
| `report_delivery` | Server default | `run_count: ORM —; DB 0 (client-side defaults excluded)` | [app/models_reports.py:86](../../../app/models_reports.py#L86) |
| `report_delivery` | Server default | `sbom_count: ORM —; DB 0 (client-side defaults excluded)` | [app/models_reports.py:85](../../../app/models_reports.py#L85) |
| `report_delivery` | Server default | `status: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:81](../../../app/models_reports.py#L81) |
| `report_subscription` | Column type | `deactivated_by: ORM VARCHAR(128); DB character varying` | [app/models_mixins.py:56](../../../app/models_mixins.py#L56) |
| `report_subscription` | Server default | `baseline_mode: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:32](../../../app/models_reports.py#L32) |
| `report_subscription` | Server default | `cadence: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:28](../../../app/models_reports.py#L28) |
| `report_subscription` | Server default | `cross_version_target: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:33](../../../app/models_reports.py#L33) |
| `report_subscription` | Server default | `enabled: ORM —; DB true (client-side defaults excluded)` | [app/models_reports.py:36](../../../app/models_reports.py#L36) |
| `report_subscription` | Server default | `formats: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:30](../../../app/models_reports.py#L30) |
| `report_subscription` | Server default | `parts: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:29](../../../app/models_reports.py#L29) |
| `report_subscription` | Server default | `severity_floor: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:31](../../../app/models_reports.py#L31) |
| `report_subscription` | Server default | `suppress_when_unchanged: ORM —; DB false (client-side defaults excluded)` | [app/models_reports.py:35](../../../app/models_reports.py#L35) |
| `report_subscription` | Server default | `timezone: ORM —; DB '<literal redacted>'::character varying (client-side defaults excluded)` | [app/models_reports.py:34](../../../app/models_reports.py#L34) |
| `sbom_source` | Constraint name only | `FK ('logical_sbom_id',): ORM fk_sbom_source_logical_sbom_id_logical_sbom; DB fk_sbom_source_logical` | [app/models.py:752](../../../app/models.py#L752) |
| `vex_documents` | Missing ORM FK | `(('superseded_by_id',), 'public', 'vex_documents', ('id',))` | [app/models.py:1296](../../../app/models.py#L1296) |

| Table / index | Comparison result | Detail |
| --- | --- | --- |
| `account_action_tokens.uq_account_action_tokens_active` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_account_action_tokens_active ON account_action_tokens (user_id, purpose) WHERE consumed_at IS NULL AND invalidated_at IS NULL; DB CREATE UNIQUE INDEX uq_account_action_tokens_active ON public.account_action_tokens USING btree (user_id, purpose) WHERE ((consumed_at IS NULL) AND (invalidated_at IS NULL))` |
| `ai_credential_audit_log.ix_ai_credential_audit_log_configuration_tenant` | Extra database index | `CREATE INDEX ix_ai_credential_audit_log_configuration_tenant ON public.ai_credential_audit_log USING btree (tenant_id)` |
| `ai_credential_audit_log.ix_ai_credential_audit_log_tenant_id` | Missing named ORM index | `CREATE INDEX ix_ai_credential_audit_log_tenant_id ON ai_credential_audit_log (tenant_id); Same signature under: ix_ai_credential_audit_log_configuration_tenant` |
| `ai_provider_credential.ix_ai_only_one_default` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX ix_ai_only_one_default ON ai_provider_credential (is_default) WHERE is_default = TRUE AND tenant_id IS NULL; DB CREATE UNIQUE INDEX ix_ai_only_one_default ON public.ai_provider_credential USING btree (is_default) WHERE ((is_default = true) AND (tenant_id IS NULL))` |
| `ai_provider_credential.ix_ai_only_one_fallback` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX ix_ai_only_one_fallback ON ai_provider_credential (is_fallback) WHERE is_fallback = TRUE AND tenant_id IS NULL; DB CREATE UNIQUE INDEX ix_ai_only_one_fallback ON public.ai_provider_credential USING btree (is_fallback) WHERE ((is_fallback = true) AND (tenant_id IS NULL))` |
| `ai_provider_credential.ix_ai_provider_credential_configuration_tenant` | Extra database index | `CREATE INDEX ix_ai_provider_credential_configuration_tenant ON public.ai_provider_credential USING btree (tenant_id)` |
| `ai_provider_credential.ix_ai_provider_credential_tenant_id` | Missing named ORM index | `CREATE INDEX ix_ai_provider_credential_tenant_id ON ai_provider_credential (tenant_id); Same signature under: ix_ai_provider_credential_configuration_tenant` |
| `ai_provider_credential.ix_ai_tenant_default` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX ix_ai_tenant_default ON ai_provider_credential (tenant_id) WHERE is_default = TRUE AND tenant_id IS NOT NULL; DB CREATE UNIQUE INDEX ix_ai_tenant_default ON public.ai_provider_credential USING btree (tenant_id) WHERE ((is_default = true) AND (tenant_id IS NOT NULL))` |
| `ai_provider_credential.ix_ai_tenant_fallback` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX ix_ai_tenant_fallback ON ai_provider_credential (tenant_id) WHERE is_fallback = TRUE AND tenant_id IS NOT NULL; DB CREATE UNIQUE INDEX ix_ai_tenant_fallback ON public.ai_provider_credential USING btree (tenant_id) WHERE ((is_fallback = true) AND (tenant_id IS NOT NULL))` |
| `ai_provider_credential.uq_ai_credential_platform` | Missing named ORM index | `CREATE UNIQUE INDEX uq_ai_credential_platform ON ai_provider_credential (provider_name, label) WHERE tenant_id IS NULL; Same signature under: uq_ai_provider_credential_platform_slot` |
| `ai_provider_credential.uq_ai_provider_credential_platform_slot` | Extra database index | `CREATE UNIQUE INDEX uq_ai_provider_credential_platform_slot ON public.ai_provider_credential USING btree (provider_name, label) WHERE (tenant_id IS NULL)` |
| `ai_provider_model.ix_ai_provider_model_id` | Missing named ORM index | `CREATE INDEX ix_ai_provider_model_id ON ai_provider_model (id); PK index covers same key: pk_ai_provider_model` |
| `ai_settings.ix_ai_settings_configuration_tenant` | Extra database index | `CREATE INDEX ix_ai_settings_configuration_tenant ON public.ai_settings USING btree (tenant_id)` |
| `ai_settings.uq_ai_settings_platform` | Missing named ORM index | `CREATE UNIQUE INDEX uq_ai_settings_platform ON ai_settings ((1)) WHERE tenant_id IS NULL; Same signature under: uq_ai_settings_platform_slot` |
| `ai_settings.uq_ai_settings_platform_slot` | Extra database index | `CREATE UNIQUE INDEX uq_ai_settings_platform_slot ON public.ai_settings USING btree ((1)) WHERE (tenant_id IS NULL)` |
| `analysis_schedule.uq_analysis_schedule_tenant` | Extra database index | `CREATE UNIQUE INDEX uq_analysis_schedule_tenant ON public.analysis_schedule USING btree (tenant_id) WHERE (((scope)::text = '<literal redacted>'::text) AND is_active)` |
| `authorization_permissions.ix_authorization_permissions_code` | Index structure | `ORM (True, 'btree', []); DB (False, 'btree', [])` |
| `component_recommendation.uq_component_recommendation_open` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_component_recommendation_open ON component_recommendation (tenant_id, source_canonical_key, scope_key, trigger_type) WHERE status IN ('<literal redacted>','<literal redacted>','<literal redacted>','<literal redacted>'); DB CREATE UNIQUE INDEX uq_component_recommendation_open ON public.component_recommendation USING btree (tenant_id, source_canonical_key, scope_key, trigger_type) WHERE ((status)::text = ANY ((ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying])::text[]))` |
| `email_verification_tokens.uq_email_verification_tokens_active_user` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_email_verification_tokens_active_user ON email_verification_tokens (user_id) WHERE consumed_at IS NULL AND invalidated_at IS NULL; DB CREATE UNIQUE INDEX uq_email_verification_tokens_active_user ON public.email_verification_tokens USING btree (user_id) WHERE ((consumed_at IS NULL) AND (invalidated_at IS NULL))` |
| `lifecycle_provider_configs.ix_lifecycle_provider_configs_configuration_tenant` | Extra database index | `CREATE INDEX ix_lifecycle_provider_configs_configuration_tenant ON public.lifecycle_provider_configs USING btree (tenant_id)` |
| `lifecycle_provider_configs.ix_lifecycle_provider_configs_provider_key` | Missing named ORM index | `CREATE INDEX ix_lifecycle_provider_configs_provider_key ON lifecycle_provider_configs (provider_key); No exact same-signature index; broader prefix/partial coverage not assessed` |
| `lifecycle_provider_configs.ix_lifecycle_provider_configs_tenant_id` | Missing named ORM index | `CREATE INDEX ix_lifecycle_provider_configs_tenant_id ON lifecycle_provider_configs (tenant_id); Same signature under: ix_lifecycle_provider_configs_configuration_tenant` |
| `lifecycle_provider_configs.uq_lifecycle_provider_configs_platform_slot` | Extra database index | `CREATE UNIQUE INDEX uq_lifecycle_provider_configs_platform_slot ON public.lifecycle_provider_configs USING btree (provider_key) WHERE (tenant_id IS NULL)` |
| `lifecycle_provider_configs.uq_lifecycle_provider_platform` | Missing named ORM index | `CREATE UNIQUE INDEX uq_lifecycle_provider_platform ON lifecycle_provider_configs (provider_key) WHERE tenant_id IS NULL; Same signature under: uq_lifecycle_provider_configs_platform_slot` |
| `lifecycle_provider_secrets.ix_lifecycle_provider_secrets_configuration_tenant` | Extra database index | `CREATE INDEX ix_lifecycle_provider_secrets_configuration_tenant ON public.lifecycle_provider_secrets USING btree (tenant_id)` |
| `lifecycle_provider_secrets.ix_lifecycle_provider_secrets_tenant_id` | Missing named ORM index | `CREATE INDEX ix_lifecycle_provider_secrets_tenant_id ON lifecycle_provider_secrets (tenant_id); Same signature under: ix_lifecycle_provider_secrets_configuration_tenant` |
| `lifecycle_provider_secrets.uq_lifecycle_provider_secrets_platform_slot` | Extra database index | `CREATE UNIQUE INDEX uq_lifecycle_provider_secrets_platform_slot ON public.lifecycle_provider_secrets USING btree (provider_key, secret_name) WHERE (tenant_id IS NULL)` |
| `lifecycle_provider_secrets.uq_lifecycle_secret_platform` | Missing named ORM index | `CREATE UNIQUE INDEX uq_lifecycle_secret_platform ON lifecycle_provider_secrets (provider_key, secret_name) WHERE tenant_id IS NULL; Same signature under: uq_lifecycle_provider_secrets_platform_slot` |
| `report_subscription.uq_report_subscription_product` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_report_subscription_product ON report_subscription (tenant_id, iam_user_id, product_id) WHERE is_active AND scope = '<literal redacted>'; DB CREATE UNIQUE INDEX uq_report_subscription_product ON public.report_subscription USING btree (tenant_id, iam_user_id, product_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |
| `report_subscription.uq_report_subscription_project` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_report_subscription_project ON report_subscription (tenant_id, iam_user_id, project_id) WHERE is_active AND scope = '<literal redacted>'; DB CREATE UNIQUE INDEX uq_report_subscription_project ON public.report_subscription USING btree (tenant_id, iam_user_id, project_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |
| `report_subscription.uq_report_subscription_sbom` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_report_subscription_sbom ON report_subscription (tenant_id, iam_user_id, sbom_id) WHERE is_active AND scope = '<literal redacted>'; DB CREATE UNIQUE INDEX uq_report_subscription_sbom ON public.report_subscription USING btree (tenant_id, iam_user_id, sbom_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |
| `report_subscription.uq_report_subscription_tenant` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_report_subscription_tenant ON report_subscription (tenant_id, iam_user_id) WHERE is_active AND scope = '<literal redacted>'; DB CREATE UNIQUE INDEX uq_report_subscription_tenant ON public.report_subscription USING btree (tenant_id, iam_user_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |
| `tenant_user_role_assignment_history.ix_tenant_role_assignment_history_assignment_id` | Extra database index | `CREATE INDEX ix_tenant_role_assignment_history_assignment_id ON public.tenant_user_role_assignment_history USING btree (assignment_id)` |
| `tenant_user_role_assignment_history.ix_tenant_role_assignment_history_occurred_at` | Extra database index | `CREATE INDEX ix_tenant_role_assignment_history_occurred_at ON public.tenant_user_role_assignment_history USING btree (occurred_at)` |
| `tenant_user_role_assignment_history.ix_tenant_role_assignment_history_tenant_id` | Extra database index | `CREATE INDEX ix_tenant_role_assignment_history_tenant_id ON public.tenant_user_role_assignment_history USING btree (tenant_id)` |
| `tenant_user_role_assignment_history.ix_tenant_role_assignment_history_tenant_user_id` | Extra database index | `CREATE INDEX ix_tenant_role_assignment_history_tenant_user_id ON public.tenant_user_role_assignment_history USING btree (tenant_user_id)` |
| `tenant_user_role_assignment_history.ix_tenant_user_role_assignment_history_assignment_id` | Missing named ORM index | `CREATE INDEX ix_tenant_user_role_assignment_history_assignment_id ON tenant_user_role_assignment_history (assignment_id); Same signature under: ix_tenant_role_assignment_history_assignment_id` |
| `tenant_user_role_assignment_history.ix_tenant_user_role_assignment_history_tenant_id` | Missing named ORM index | `CREATE INDEX ix_tenant_user_role_assignment_history_tenant_id ON tenant_user_role_assignment_history (tenant_id); Same signature under: ix_tenant_role_assignment_history_tenant_id` |
| `tenant_user_role_assignment_history.ix_tenant_user_role_assignment_history_tenant_user_id` | Missing named ORM index | `CREATE INDEX ix_tenant_user_role_assignment_history_tenant_user_id ON tenant_user_role_assignment_history (tenant_user_id); Same signature under: ix_tenant_role_assignment_history_tenant_user_id` |
| `tenant_user_role_assignments.ix_tenant_user_role_assignments_membership_status` | Extra database index | `CREATE INDEX ix_tenant_user_role_assignments_membership_status ON public.tenant_user_role_assignments USING btree (tenant_user_id, status)` |
| `tenant_user_role_assignments.ix_tenant_user_role_assignments_status` | Extra database index | `CREATE INDEX ix_tenant_user_role_assignments_status ON public.tenant_user_role_assignments USING btree (status)` |
| `tenant_user_role_assignments.uq_tenant_user_role_assignments_active_primary` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_tenant_user_role_assignments_active_primary ON tenant_user_role_assignments (tenant_user_id) WHERE status = '<literal redacted>' AND is_primary; DB CREATE UNIQUE INDEX uq_tenant_user_role_assignments_active_primary ON public.tenant_user_role_assignments USING btree (tenant_user_id) WHERE (((status)::text = '<literal redacted>'::text) AND is_primary)` |
| `user_identities.uq_user_identities_native_email` | Index rendering equivalent | `ORM CREATE UNIQUE INDEX uq_user_identities_native_email ON user_identities (provider_identifier) WHERE provider_type = '<literal redacted>'; DB CREATE UNIQUE INDEX uq_user_identities_native_email ON public.user_identities USING btree (provider_identifier) WHERE ((provider_type)::text = '<literal redacted>'::text)` |
| `vex_investigation.ix_vex_investigation_id` | Missing named ORM index | `CREATE INDEX ix_vex_investigation_id ON vex_investigation (id); PK index covers same key: pk_vex_investigation` |

## Tables, primary keys and estimated row counts

Each row below is a catalog table entry, not exported application data. reltuples is an approximate planner estimate, normally refreshed by ANALYZE/VACUUM. **Unknown (-1) does not mean empty.** n_live_tup is a second asynchronous statistics estimate; zero with no analyze timestamp does not prove no rows. No exact COUNT on a business table, sampling, ANALYZE, size scan or query plan was performed.

### A — root .env DATABASE_URL

| Table | Kind | ORM model source | PK constraint / columns and live types | Columns / FKs / indexes | Estimated rows (reltuples) | Stats n_live_tup | Last analyze / autoanalyze |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `public.ai_credential_audit_log` | `r` | [app/models.py:2232](../../../app/models.py#L2232) | `pk_ai_credential_audit_log (id:integer)` | 8 / 0 / 3 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.ai_fix_batch` | `r` | [app/models.py:2048](../../../app/models.py#L2048) | `pk_ai_fix_batch (id:character varying(36))` | 20 / 2 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.ai_fix_cache` | `r` | [app/models.py:1995](../../../app/models.py#L1995) | `pk_ai_fix_cache (cache_key:character varying(64))` | 16 / 0 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.ai_provider_config` | `r` | [app/models.py:1973](../../../app/models.py#L1973) | `pk_ai_provider_config (provider_name:character varying(32))` | 9 / 0 / 1 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.ai_provider_credential` | `r` | [app/models.py:2094](../../../app/models.py#L2094) | `pk_ai_provider_credential (id:integer)` | 20 / 0 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.ai_provider_model` | `r` | [app/models.py:2141](../../../app/models.py#L2141) | `pk_ai_provider_model (id:integer)` | 24 / 1 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.ai_settings` | `r` | [app/models.py:2211](../../../app/models.py#L2211) | `pk_ai_settings (id:integer)` | 8 / 0 / 1 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.ai_usage_log` | `r` | [app/models.py:1946](../../../app/models.py#L1946) | `pk_ai_usage_log (id:integer)` | 14 / 1 / 10 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.alembic_version` | `r` | Outside shared Base | `alembic_version_pkc (version_num:character varying(128))` | 1 / 0 / 1 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.analysis_finding` | `r` | [app/models.py:1628](../../../app/models.py#L1628) | `pk_analysis_finding (id:integer)` | 28 / 3 / 14 | 440.0 | 0 | `unknown / unknown` |
| `public.analysis_run` | `r` | [app/models.py:1566](../../../app/models.py#L1566) | `pk_analysis_run (id:integer)` | 25 / 4 / 10 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.analysis_schedule` | `r` | [app/models.py:1740](../../../app/models.py#L1740) | `pk_analysis_schedule (id:integer)` | 28 / 5 / 11 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.audit_log` | `r` | [app/models.py:2254](../../../app/models.py#L2254) | `pk_audit_log (id:integer)` | 16 / 2 / 11 | 1893.0 | 0 | `unknown / unknown` |
| `public.authorization_audit_log` | `r` | [app/models.py:2295](../../../app/models.py#L2295) | `pk_authorization_audit_log (id:integer)` | 12 / 4 / 9 | 372.0 | 0 | `unknown / unknown` |
| `public.authorization_permissions` | `r` | [app/models.py:395](../../../app/models.py#L395) | `pk_authorization_permissions (id:integer)` | 11 / 0 / 7 | 55.0 | 0 | `unknown / unknown` |
| `public.authorization_role_permissions` | `r` | [app/models.py:433](../../../app/models.py#L433) | `pk_authorization_role_permissions (id:integer)` | 7 / 3 / 4 | 157.0 | 0 | `unknown / unknown` |
| `public.authorization_roles` | `r` | [app/models.py:356](../../../app/models.py#L356) | `pk_authorization_roles (id:integer)` | 13 / 2 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.celery_taskmeta` | `r` | Outside shared Base | `celery_taskmeta_pkey (id:integer)` | 12 / 0 / 3 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.celery_tasksetmeta` | `r` | Outside shared Base | `celery_tasksetmeta_pkey (id:integer)` | 4 / 0 / 3 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.compare_cache` | `r` | [app/models.py:1925](../../../app/models.py#L1925) | `pk_compare_cache (cache_key:character varying(64))` | 8 / 1 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.component_lifecycle_cache` | `r` | [app/models.py:1148](../../../app/models.py#L1148) | `pk_component_lifecycle_cache (id:integer)` | 25 / 0 / 12 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.component_lifecycle_override_audit` | `r` | [app/models.py:1495](../../../app/models.py#L1495) | `pk_component_lifecycle_override_audit (id:integer)` | 9 / 2 / 7 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.cve_cache` | `r` | [app/models.py:1845](../../../app/models.py#L1845) | `pk_cve_cache (cve_id:character varying(32))` | 7 / 0 / 3 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.cves` | `r` | [app/nvd_mirror/db/models.py:82](../../../app/nvd_mirror/db/models.py#L82) | `pk_cves (cve_id:text)` | 15 / 0 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.email_verification_tokens` | `r` | [app/models.py:243](../../../app/models.py#L243) | `pk_email_verification_tokens (id:integer)` | 15 / 1 / 7 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.epss_score` | `r` | [app/models.py:1824](../../../app/models.py#L1824) | `pk_epss_score (cve_id:character varying)` | 5 / 0 / 2 | 81.0 | 0 | `unknown / unknown` |
| `public.iam_users` | `r` | [app/models.py:52](../../../app/models.py#L52) | `pk_iam_users (id:integer)` | 17 / 0 / 8 | 3.0 | 0 | `unknown / unknown` |
| `public.kev_entry` | `r` | Outside shared Base | `pk_kev_entry (cve_id:character varying)` | 10 / 0 / 2 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.kev_vulnerabilities` | `r` | [app/models.py:1705](../../../app/models.py#L1705) | `pk_kev_vulnerabilities (cve_id:character varying(32))` | 16 / 0 / 4 | 1716.0 | 0 | `unknown / unknown` |
| `public.kombu_message` | `r` | Outside shared Base | `kombu_message_pkey (id:integer)` | 6 / 1 / 4 | 160.0 | 0 | `unknown / unknown` |
| `public.kombu_queue` | `r` | Outside shared Base | `kombu_queue_pkey (id:integer)` | 2 / 0 / 2 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.lifecycle_provider_configs` | `r` | [app/models.py:1193](../../../app/models.py#L1193) | `pk_lifecycle_provider_configs (id:integer)` | 23 / 1 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.lifecycle_provider_secrets` | `r` | [app/models.py:1239](../../../app/models.py#L1239) | `pk_lifecycle_provider_secrets (id:integer)` | 8 / 1 / 5 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.lifecycle_vendor_records` | `r` | [app/models.py:1261](../../../app/models.py#L1261) | `pk_lifecycle_vendor_records (id:integer)` | 24 / 1 / 7 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.nvd_lookup_cache` | `r` | [app/models.py:1899](../../../app/models.py#L1899) | `pk_nvd_lookup_cache (id:integer)` | 12 / 0 / 5 | 35.0 | 0 | `unknown / unknown` |
| `public.nvd_settings` | `r` | [app/nvd_mirror/db/models.py:45](../../../app/nvd_mirror/db/models.py#L45) | `pk_nvd_settings (id:integer)` | 12 / 0 / 1 | 0.0 | 0 | `unknown / unknown` |
| `public.nvd_sync_runs` | `r` | [app/nvd_mirror/db/models.py:123](../../../app/nvd_mirror/db/models.py#L123) | `pk_nvd_sync_runs (id:bigint)` | 9 / 0 / 2 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.platform_user_roles` | `r` | [app/models.py:334](../../../app/models.py#L334) | `pk_platform_user_roles (id:integer)` | 7 / 2 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.products` | `r` | [app/models.py:656](../../../app/models.py#L656) | `pk_products (id:integer)` | 21 / 3 / 13 | 1.0 | 0 | `unknown / unknown` |
| `public.projects` | `r` | [app/models.py:609](../../../app/models.py#L609) | `pk_projects (id:integer)` | 12 / 1 / 9 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.report_artifact` | `r` | [app/models_reports.py:103](../../../app/models_reports.py#L103) | `pk_report_artifact (id:integer)` | 11 / 2 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.report_delivery` | `r` | [app/models_reports.py:73](../../../app/models_reports.py#L73) | `pk_report_delivery (id:integer)` | 19 / 2 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.report_subscription` | `r` | [app/models_reports.py:20](../../../app/models_reports.py#L20) | `pk_report_subscription (id:integer)` | 24 / 5 / 7 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.run_cache` | `r` | [app/models.py:1689](../../../app/models.py#L1689) | `pk_run_cache (id:integer)` | 6 / 1 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.sbom_analysis_report` | `r` | [app/models.py:1025](../../../app/models.py#L1025) | `pk_sbom_analysis_report (id:integer)` | 12 / 2 / 5 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.sbom_component` | `r` | [app/models.py:1040](../../../app/models.py#L1040) | `pk_sbom_component (id:integer)` | 67 / 3 / 29 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.sbom_source` | `r` | [app/models.py:752](../../../app/models.py#L752) | `pk_sbom_source (id:integer)` | 50 / 7 / 22 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.sbom_type` | `r` | [app/models.py:718](../../../app/models.py#L718) | `pk_sbom_type (id:integer)` | 7 / 0 / 3 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.sbom_validation_session_events` | `r` | [app/models.py:980](../../../app/models.py#L980) | `pk_sbom_validation_session_events (id:integer)` | 10 / 2 / 8 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.sbom_validation_sessions` | `r` | [app/models.py:919](../../../app/models.py#L919) | `pk_sbom_validation_sessions (id:character varying(36))` | 42 / 4 / 14 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.source_response_cache` | `r` | [app/models.py:1867](../../../app/models.py#L1867) | `pk_source_response_cache (source:character varying(32), component_key:character varying(512))` | 5 / 0 / 2 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.tenant_user_role_assignment_history` | `r` | [app/models.py:543](../../../app/models.py#L543) | `pk_tenant_user_role_assignment_history (id:integer)` | 19 / 5 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.tenant_user_role_assignments` | `r` | [app/models.py:468](../../../app/models.py#L468) | `pk_tenant_user_role_assignments (id:integer)` | 15 / 5 / 9 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.tenant_users` | `r` | [app/models.py:298](../../../app/models.py#L298) | `pk_tenant_users (id:integer)` | 8 / 2 / 6 | 4.0 | 0 | `unknown / unknown` |
| `public.tenants` | `r` | [app/models.py:32](../../../app/models.py#L32) | `pk_tenants (id:integer)` | 7 / 0 / 5 | 2.0 | 0 | `unknown / unknown` |
| `public.vex_documents` | `r` | [app/models.py:1296](../../../app/models.py#L1296) | `pk_vex_documents (id:integer)` | 14 / 2 / 10 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.vex_override_audit` | `r` | [app/models.py:1522](../../../app/models.py#L1522) | `pk_vex_override_audit (id:integer)` | 10 / 2 / 8 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.vex_statements` | `r` | [app/models.py:1337](../../../app/models.py#L1337) | `pk_vex_statements (id:integer)` | 18 / 4 / 13 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.vulnerability_remediation` | `r` | [app/models.py:2323](../../../app/models.py#L2323) | `pk_vulnerability_remediation (id:integer)` | 14 / 2 / 7 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.vulnerability_remediation_audit` | `r` | [app/models.py:2352](../../../app/models.py#L2352) | `pk_vulnerability_remediation_audit (id:integer)` | 12 / 3 / 9 | UNKNOWN (-1) | 0 | `unknown / unknown` |

### B — .env.dev.local DATABASE_URL

| Table | Kind | ORM model source | PK constraint / columns and live types | Columns / FKs / indexes | Estimated rows (reltuples) | Stats n_live_tup | Last analyze / autoanalyze |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `public.account_action_tokens` | `r` | [app/models.py:179](../../../app/models.py#L179) | `pk_account_action_tokens (id:integer)` | 9 / 1 / 5 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.advisor_policy` | `r` | [app/models.py:2439](../../../app/models.py#L2439) | `pk_advisor_policy (id:integer)` | 8 / 1 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.advisor_policy_version` | `r` | [app/models.py:2473](../../../app/models.py#L2473) | `pk_advisor_policy_version (id:integer)` | 11 / 2 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.ai_credential_audit_log` | `r` | [app/models.py:2232](../../../app/models.py#L2232) | `pk_ai_credential_audit_log (id:integer)` | 9 / 1 / 4 | UNKNOWN (-1) | 1 | `unknown / unknown` |
| `public.ai_fix_batch` | `r` | [app/models.py:2048](../../../app/models.py#L2048) | `pk_ai_fix_batch (id:character varying(36))` | 20 / 2 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.ai_fix_cache` | `r` | [app/models.py:1995](../../../app/models.py#L1995) | `pk_ai_fix_cache (cache_key:character varying(64))` | 16 / 0 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.ai_provider_config` | `r` | [app/models.py:1973](../../../app/models.py#L1973) | `pk_ai_provider_config (provider_name:character varying(32))` | 9 / 0 / 1 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.ai_provider_credential` | `r` | [app/models.py:2094](../../../app/models.py#L2094) | `pk_ai_provider_credential (id:integer)` | 21 / 1 / 10 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.ai_provider_model` | `r` | [app/models.py:2141](../../../app/models.py#L2141) | `pk_ai_provider_model (id:integer)` | 24 / 1 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.ai_settings` | `r` | [app/models.py:2211](../../../app/models.py#L2211) | `pk_ai_settings (id:integer)` | 9 / 1 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.ai_usage_log` | `r` | [app/models.py:1946](../../../app/models.py#L1946) | `pk_ai_usage_log (id:integer)` | 14 / 1 / 10 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.alembic_version` | `r` | Outside shared Base | `alembic_version_pkc (version_num:character varying(128))` | 1 / 0 / 1 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.analysis_finding` | `r` | [app/models.py:1628](../../../app/models.py#L1628) | `pk_analysis_finding (id:integer)` | 30 / 3 / 14 | 108.0 | 0 | `unknown / unknown` |
| `public.analysis_run` | `r` | [app/models.py:1566](../../../app/models.py#L1566) | `pk_analysis_run (id:integer)` | 27 / 4 / 11 | 1.0 | 0 | `unknown / unknown` |
| `public.analysis_schedule` | `r` | [app/models.py:1740](../../../app/models.py#L1740) | `pk_analysis_schedule (id:integer)` | 28 / 5 / 11 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.audit_log` | `r` | [app/models.py:2254](../../../app/models.py#L2254) | `pk_audit_log (id:integer)` | 16 / 2 / 11 | 590.0 | 52 | `unknown / unknown` |
| `public.authorization_audit_log` | `r` | [app/models.py:2295](../../../app/models.py#L2295) | `pk_authorization_audit_log (id:integer)` | 12 / 4 / 9 | 297.0 | 353 | `unknown / 2026-10-16 08:02:09.935755+00:00` |
| `public.authorization_permissions` | `r` | [app/models.py:395](../../../app/models.py#L395) | `pk_authorization_permissions (id:integer)` | 11 / 0 / 7 | 55.0 | 0 | `unknown / unknown` |
| `public.authorization_role_permissions` | `r` | [app/models.py:433](../../../app/models.py#L433) | `pk_authorization_role_permissions (id:integer)` | 7 / 3 / 4 | 143.0 | 0 | `unknown / unknown` |
| `public.authorization_roles` | `r` | [app/models.py:356](../../../app/models.py#L356) | `pk_authorization_roles (id:integer)` | 13 / 2 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.compare_cache` | `r` | [app/models.py:1925](../../../app/models.py#L1925) | `pk_compare_cache (cache_key:character varying(64))` | 8 / 1 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.component_lifecycle_cache` | `r` | [app/models.py:1148](../../../app/models.py#L1148) | `pk_component_lifecycle_cache (id:integer)` | 26 / 0 / 12 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.component_lifecycle_override_audit` | `r` | [app/models.py:1495](../../../app/models.py#L1495) | `pk_component_lifecycle_override_audit (id:integer)` | 9 / 2 / 7 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.component_purpose_metadata` | `r` | [app/models.py:2497](../../../app/models.py#L2497) | `pk_component_purpose_metadata (id:integer)` | 14 / 1 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.component_recommendation` | `r` | [app/models.py:2532](../../../app/models.py#L2532) | `pk_component_recommendation (id:integer)` | 29 / 5 / 12 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.component_recommendation_candidate` | `r` | [app/models.py:2600](../../../app/models.py#L2600) | `pk_component_recommendation_candidate (id:integer)` | 19 / 2 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.component_recommendation_compatibility_check` | `r` | [app/models.py:2645](../../../app/models.py#L2645) | `pk_component_recommendation_compatibility_check (id:integer)` | 10 / 2 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.component_recommendation_event` | `r` | [app/models.py:2699](../../../app/models.py#L2699) | `pk_component_recommendation_event (id:integer)` | 20 / 2 / 7 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.component_recommendation_factor` | `r` | [app/models.py:2670](../../../app/models.py#L2670) | `pk_component_recommendation_factor (id:integer)` | 13 / 3 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.cve_cache` | `r` | [app/models.py:1845](../../../app/models.py#L1845) | `pk_cve_cache (cve_id:character varying(32))` | 7 / 0 / 3 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.cves` | `r` | [app/nvd_mirror/db/models.py:82](../../../app/nvd_mirror/db/models.py#L82) | `cves_pkey (cve_id:text)` | 15 / 0 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.email_verification_tokens` | `r` | [app/models.py:243](../../../app/models.py#L243) | `pk_email_verification_tokens (id:integer)` | 15 / 1 / 7 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.epss_score` | `r` | [app/models.py:1824](../../../app/models.py#L1824) | `pk_epss_score (cve_id:character varying)` | 5 / 0 / 2 | 103.0 | 0 | `unknown / unknown` |
| `public.iam_users` | `r` | [app/models.py:52](../../../app/models.py#L52) | `pk_iam_users (id:integer)` | 21 / 0 / 9 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.kev_vulnerabilities` | `r` | [app/models.py:1705](../../../app/models.py#L1705) | `pk_kev_vulnerabilities (cve_id:character varying(32))` | 16 / 0 / 4 | 1746.0 | 1746 | `unknown / 2026-10-16 07:16:19.608717+00:00` |
| `public.lifecycle_provider_configs` | `r` | [app/models.py:1193](../../../app/models.py#L1193) | `pk_lifecycle_provider_configs (id:integer)` | 26 / 2 / 8 | 11.0 | 0 | `unknown / unknown` |
| `public.lifecycle_provider_secrets` | `r` | [app/models.py:1239](../../../app/models.py#L1239) | `pk_lifecycle_provider_secrets (id:integer)` | 9 / 2 / 7 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.lifecycle_vendor_records` | `r` | [app/models.py:1261](../../../app/models.py#L1261) | `pk_lifecycle_vendor_records (id:integer)` | 24 / 1 / 7 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.logical_sbom` | `r` | [app/models.py:732](../../../app/models.py#L732) | `pk_logical_sbom (id:integer)` | 8 / 3 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.native_platform_bootstrap` | `r` | [app/models.py:204](../../../app/models.py#L204) | `pk_native_platform_bootstrap (id:integer)` | 6 / 1 / 2 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.native_user_credentials` | `r` | [app/models.py:159](../../../app/models.py#L159) | `pk_native_user_credentials (id:integer)` | 11 / 1 / 2 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.nvd_lookup_cache` | `r` | [app/models.py:1899](../../../app/models.py#L1899) | `pk_nvd_lookup_cache (id:integer)` | 12 / 0 / 5 | 77.0 | 0 | `unknown / unknown` |
| `public.nvd_settings` | `r` | [app/nvd_mirror/db/models.py:45](../../../app/nvd_mirror/db/models.py#L45) | `nvd_settings_pkey (id:integer)` | 12 / 0 / 1 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.nvd_sync_runs` | `r` | [app/nvd_mirror/db/models.py:123](../../../app/nvd_mirror/db/models.py#L123) | `nvd_sync_runs_pkey (id:bigint)` | 9 / 0 / 2 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.platform_user_roles` | `r` | [app/models.py:334](../../../app/models.py#L334) | `pk_platform_user_roles (id:integer)` | 7 / 2 / 3 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.products` | `r` | [app/models.py:656](../../../app/models.py#L656) | `pk_products (id:integer)` | 22 / 3 / 14 | 5.0 | 0 | `unknown / unknown` |
| `public.projects` | `r` | [app/models.py:609](../../../app/models.py#L609) | `pk_projects (id:integer)` | 12 / 1 / 9 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.report_artifact` | `r` | [app/models_reports.py:103](../../../app/models_reports.py#L103) | `pk_report_artifact (id:integer)` | 11 / 2 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.report_delivery` | `r` | [app/models_reports.py:73](../../../app/models_reports.py#L73) | `pk_report_delivery (id:integer)` | 19 / 2 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.report_subscription` | `r` | [app/models_reports.py:20](../../../app/models_reports.py#L20) | `pk_report_subscription (id:integer)` | 24 / 5 / 7 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.run_cache` | `r` | [app/models.py:1689](../../../app/models.py#L1689) | `pk_run_cache (id:integer)` | 6 / 1 / 4 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.sbom_analysis_report` | `r` | [app/models.py:1025](../../../app/models.py#L1025) | `pk_sbom_analysis_report (id:integer)` | 12 / 2 / 5 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.sbom_component` | `r` | [app/models.py:1040](../../../app/models.py#L1040) | `pk_sbom_component (id:integer)` | 68 / 3 / 31 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.sbom_repair_jobs` | `r` | [app/models.py:1003](../../../app/models.py#L1003) | `pk_sbom_repair_jobs (id:character varying(36))` | 18 / 4 / 3 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.sbom_source` | `r` | [app/models.py:752](../../../app/models.py#L752) | `pk_sbom_source (id:integer)` | 54 / 10 / 25 | 2.0 | 0 | `unknown / unknown` |
| `public.sbom_type` | `r` | [app/models.py:718](../../../app/models.py#L718) | `pk_sbom_type (id:integer)` | 7 / 0 / 3 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.sbom_validation_session_events` | `r` | [app/models.py:980](../../../app/models.py#L980) | `pk_sbom_validation_session_events (id:integer)` | 10 / 2 / 8 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.sbom_validation_sessions` | `r` | [app/models.py:919](../../../app/models.py#L919) | `pk_sbom_validation_sessions (id:character varying(36))` | 42 / 4 / 14 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.security_mail_outbox` | `r` | [app/models.py:220](../../../app/models.py#L220) | `pk_security_mail_outbox (id:integer)` | 13 / 2 / 3 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.source_response_cache` | `r` | [app/models.py:1867](../../../app/models.py#L1867) | `pk_source_response_cache (source:character varying(32), component_key:character varying(512))` | 5 / 0 / 2 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.tenant_user_role_assignment_history` | `r` | [app/models.py:543](../../../app/models.py#L543) | `pk_tenant_user_role_assignment_history (id:integer)` | 19 / 5 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.tenant_user_role_assignments` | `r` | [app/models.py:468](../../../app/models.py#L468) | `pk_tenant_user_role_assignments (id:integer)` | 15 / 5 / 9 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.tenant_users` | `r` | [app/models.py:298](../../../app/models.py#L298) | `pk_tenant_users (id:integer)` | 8 / 2 / 6 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.tenants` | `r` | [app/models.py:32](../../../app/models.py#L32) | `pk_tenants (id:integer)` | 7 / 0 / 5 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.user_identities` | `r` | [app/models.py:116](../../../app/models.py#L116) | `pk_user_identities (id:integer)` | 10 / 1 / 5 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.vex_documents` | `r` | [app/models.py:1296](../../../app/models.py#L1296) | `pk_vex_documents (id:integer)` | 19 / 2 / 14 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.vex_investigation` | `r` | [app/models.py:1386](../../../app/models.py#L1386) | `pk_vex_investigation (id:integer)` | 23 / 5 / 18 | 111.0 | 0 | `unknown / unknown` |
| `public.vex_investigation_snapshot` | `r` | [app/models.py:1510](../../../app/models.py#L1510) | `pk_vex_investigation_snapshot (id:integer)` | 7 / 4 / 5 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.vex_override_audit` | `r` | [app/models.py:1522](../../../app/models.py#L1522) | `pk_vex_override_audit (id:integer)` | 15 / 4 / 11 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.vex_statements` | `r` | [app/models.py:1337](../../../app/models.py#L1337) | `pk_vex_statements (id:integer)` | 25 / 4 / 15 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.vulnerability_remediation` | `r` | [app/models.py:2323](../../../app/models.py#L2323) | `pk_vulnerability_remediation (id:integer)` | 14 / 2 / 7 | UNKNOWN (-1) | 0 | `unknown / unknown` |
| `public.vulnerability_remediation_audit` | `r` | [app/models.py:2352](../../../app/models.py#L2352) | `pk_vulnerability_remediation_audit (id:integer)` | 12 / 3 / 9 | UNKNOWN (-1) | 0 | `unknown / unknown` |

## UUID-like keys and database generation

| Target | Table.column | Live type | Default / identity | Interpretation |
| --- | --- | --- | --- | --- |
| A | `ai_fix_batch.id` | `character varying(36)` | `—` / identity `none` | UUID4 generated in application services; no native uuid/default observed |
| A | `sbom_validation_sessions.id` | `character varying(36)` | `—` / identity `none` | UUID4 generated in application services; no native uuid/default observed |
| B | `ai_fix_batch.id` | `character varying(36)` | `—` / identity `none` | UUID4 generated in application services; no native uuid/default observed |
| B | `sbom_repair_jobs.id` | `character varying(36)` | `—` / identity `none` | UUID4 generated in application services; no native uuid/default observed |
| B | `sbom_validation_sessions.id` | `character varying(36)` | `—` / identity `none` | UUID4 generated in application services; no native uuid/default observed |

All observed columns had empty identity and generated-column flags. Sequence-backed integer columns use defaults/ownership recorded below; the sequences are not native IDENTITY columns. Absence of a UUID default does not validate every existing varchar(36) value as a UUID. Generation call sites are documented in [02-primary-keys.md](02-primary-keys.md).

## Sequence inventory

Configuration/ownership only: no last/current/next value was fetched. `a` ownership is an automatic serial dependency, `i` would indicate internal identity ownership, and no owner means no such catalog ownership dependency was found (not proof that nothing uses it). All observed sequences start at 1, increment by 1, cache 1 and have cycle=false; types/bounds and owner columns are listed for each target.

### A — root .env DATABASE_URL

| Sequence | Type | Owner column | Dependency | Start / increment / min / max / cache / cycle |
| --- | --- | --- | --- | --- |
| `public.ai_credential_audit_log_id_seq` | `integer` | `public.ai_credential_audit_log.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.ai_provider_credential_id_seq` | `integer` | `public.ai_provider_credential.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.ai_provider_model_id_seq` | `integer` | `public.ai_provider_model.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.ai_usage_log_id_seq` | `integer` | `public.ai_usage_log.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.analysis_finding_id_seq` | `integer` | `public.analysis_finding.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.analysis_run_id_seq` | `integer` | `public.analysis_run.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.analysis_schedule_id_seq` | `integer` | `public.analysis_schedule.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.audit_log_id_seq` | `integer` | `public.audit_log.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.authorization_audit_log_id_seq` | `integer` | `public.authorization_audit_log.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.authorization_permissions_id_seq` | `integer` | `public.authorization_permissions.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.authorization_role_permissions_id_seq` | `integer` | `public.authorization_role_permissions.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.authorization_roles_id_seq` | `integer` | `public.authorization_roles.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.component_lifecycle_cache_id_seq` | `integer` | `public.component_lifecycle_cache.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.component_lifecycle_override_audit_id_seq` | `integer` | `public.component_lifecycle_override_audit.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.email_verification_tokens_id_seq` | `integer` | `public.email_verification_tokens.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.iam_users_id_seq` | `integer` | `public.iam_users.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.lifecycle_provider_configs_id_seq` | `integer` | `public.lifecycle_provider_configs.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.lifecycle_provider_secrets_id_seq` | `integer` | `public.lifecycle_provider_secrets.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.lifecycle_vendor_records_id_seq` | `integer` | `public.lifecycle_vendor_records.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.message_id_sequence` | `bigint` | `no catalog owner` | — | `1 / 1 / 1 / 9223372036854775807 / 1 / False` |
| `public.nvd_lookup_cache_id_seq` | `integer` | `public.nvd_lookup_cache.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.nvd_settings_id_seq` | `integer` | `public.nvd_settings.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.nvd_sync_runs_id_seq` | `bigint` | `public.nvd_sync_runs.id` | a | `1 / 1 / 1 / 9223372036854775807 / 1 / False` |
| `public.platform_user_roles_id_seq` | `integer` | `public.platform_user_roles.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.products_id_seq` | `integer` | `public.products.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.projects_id_seq` | `integer` | `public.projects.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.queue_id_sequence` | `bigint` | `no catalog owner` | — | `1 / 1 / 1 / 9223372036854775807 / 1 / False` |
| `public.report_artifact_id_seq` | `integer` | `public.report_artifact.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.report_delivery_id_seq` | `integer` | `public.report_delivery.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.report_subscription_id_seq` | `integer` | `public.report_subscription.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.run_cache_id_seq` | `integer` | `public.run_cache.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.sbom_analysis_report_id_seq` | `integer` | `public.sbom_analysis_report.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.sbom_component_id_seq` | `integer` | `public.sbom_component.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.sbom_source_id_seq` | `integer` | `public.sbom_source.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.sbom_type_id_seq` | `integer` | `public.sbom_type.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.sbom_validation_session_events_id_seq` | `integer` | `public.sbom_validation_session_events.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.task_id_sequence` | `bigint` | `no catalog owner` | — | `1 / 1 / 1 / 9223372036854775807 / 1 / False` |
| `public.taskset_id_sequence` | `bigint` | `no catalog owner` | — | `1 / 1 / 1 / 9223372036854775807 / 1 / False` |
| `public.tenant_user_role_assignment_history_id_seq` | `integer` | `public.tenant_user_role_assignment_history.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.tenant_user_role_assignments_id_seq` | `integer` | `public.tenant_user_role_assignments.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.tenant_users_id_seq` | `integer` | `public.tenant_users.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.tenants_id_seq` | `integer` | `public.tenants.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.vex_documents_id_seq` | `integer` | `public.vex_documents.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.vex_override_audit_id_seq` | `integer` | `public.vex_override_audit.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.vex_statements_id_seq` | `integer` | `public.vex_statements.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.vulnerability_remediation_audit_id_seq` | `integer` | `public.vulnerability_remediation_audit.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.vulnerability_remediation_id_seq` | `integer` | `public.vulnerability_remediation.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |

### B — .env.dev.local DATABASE_URL

| Sequence | Type | Owner column | Dependency | Start / increment / min / max / cache / cycle |
| --- | --- | --- | --- | --- |
| `public.account_action_tokens_id_seq` | `integer` | `public.account_action_tokens.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.advisor_policy_id_seq` | `integer` | `public.advisor_policy.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.advisor_policy_version_id_seq` | `integer` | `public.advisor_policy_version.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.ai_credential_audit_log_id_seq` | `integer` | `public.ai_credential_audit_log.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.ai_provider_credential_id_seq` | `integer` | `public.ai_provider_credential.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.ai_provider_model_id_seq` | `integer` | `public.ai_provider_model.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.ai_settings_scope_id_seq` | `bigint` | `public.ai_settings.id` | a | `1 / 1 / 1 / 9223372036854775807 / 1 / False` |
| `public.ai_usage_log_id_seq` | `integer` | `public.ai_usage_log.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.analysis_finding_id_seq` | `integer` | `public.analysis_finding.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.analysis_run_id_seq` | `integer` | `public.analysis_run.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.analysis_schedule_id_seq` | `integer` | `public.analysis_schedule.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.audit_log_id_seq` | `integer` | `public.audit_log.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.authorization_audit_log_id_seq` | `integer` | `public.authorization_audit_log.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.authorization_permissions_id_seq` | `integer` | `public.authorization_permissions.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.authorization_role_permissions_id_seq` | `integer` | `public.authorization_role_permissions.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.authorization_roles_id_seq` | `integer` | `public.authorization_roles.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.component_lifecycle_cache_id_seq` | `integer` | `public.component_lifecycle_cache.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.component_lifecycle_override_audit_id_seq` | `integer` | `public.component_lifecycle_override_audit.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.component_purpose_metadata_id_seq` | `integer` | `public.component_purpose_metadata.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.component_recommendation_candidate_id_seq` | `integer` | `public.component_recommendation_candidate.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.component_recommendation_compatibility_check_id_seq` | `integer` | `public.component_recommendation_compatibility_check.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.component_recommendation_event_id_seq` | `integer` | `public.component_recommendation_event.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.component_recommendation_factor_id_seq` | `integer` | `public.component_recommendation_factor.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.component_recommendation_id_seq` | `integer` | `public.component_recommendation.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.email_verification_tokens_id_seq` | `integer` | `public.email_verification_tokens.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.iam_users_id_seq` | `integer` | `public.iam_users.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.lifecycle_provider_configs_id_seq` | `integer` | `public.lifecycle_provider_configs.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.lifecycle_provider_secrets_id_seq` | `integer` | `public.lifecycle_provider_secrets.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.lifecycle_vendor_records_id_seq` | `integer` | `public.lifecycle_vendor_records.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.logical_sbom_id_seq` | `integer` | `public.logical_sbom.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.native_platform_bootstrap_id_seq` | `integer` | `public.native_platform_bootstrap.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.native_user_credentials_id_seq` | `integer` | `public.native_user_credentials.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.nvd_lookup_cache_id_seq` | `integer` | `public.nvd_lookup_cache.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.nvd_settings_id_seq` | `integer` | `public.nvd_settings.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.nvd_sync_runs_id_seq` | `bigint` | `public.nvd_sync_runs.id` | a | `1 / 1 / 1 / 9223372036854775807 / 1 / False` |
| `public.platform_user_roles_id_seq` | `integer` | `public.platform_user_roles.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.products_id_seq` | `integer` | `public.products.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.projects_id_seq` | `integer` | `public.projects.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.report_artifact_id_seq` | `integer` | `public.report_artifact.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.report_delivery_id_seq` | `integer` | `public.report_delivery.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.report_subscription_id_seq` | `integer` | `public.report_subscription.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.run_cache_id_seq` | `integer` | `public.run_cache.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.sbom_analysis_report_id_seq` | `integer` | `public.sbom_analysis_report.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.sbom_component_id_seq` | `integer` | `public.sbom_component.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.sbom_source_id_seq` | `integer` | `public.sbom_source.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.sbom_type_id_seq` | `integer` | `public.sbom_type.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.sbom_validation_session_events_id_seq` | `integer` | `public.sbom_validation_session_events.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.security_mail_outbox_id_seq` | `integer` | `public.security_mail_outbox.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.tenant_user_role_assignment_history_id_seq` | `integer` | `public.tenant_user_role_assignment_history.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.tenant_user_role_assignments_id_seq` | `integer` | `public.tenant_user_role_assignments.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.tenant_users_id_seq` | `integer` | `public.tenant_users.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.tenants_id_seq` | `integer` | `public.tenants.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.user_identities_id_seq` | `integer` | `public.user_identities.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.vex_documents_id_seq` | `integer` | `public.vex_documents.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.vex_investigation_id_seq` | `integer` | `public.vex_investigation.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.vex_investigation_snapshot_id_seq` | `integer` | `public.vex_investigation_snapshot.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.vex_override_audit_id_seq` | `integer` | `public.vex_override_audit.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.vex_statements_id_seq` | `integer` | `public.vex_statements.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.vulnerability_remediation_audit_id_seq` | `integer` | `public.vulnerability_remediation_audit.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |
| `public.vulnerability_remediation_id_seq` | `integer` | `public.vulnerability_remediation.id` | a | `1 / 1 / 1 / 2147483647 / 1 / False` |

## Complete live column, constraint and index inventory

The expandable per-target sections retain all catalog rows used for comparison, including operational/non-ORM tables. Defaults and expression literals are redacted. PK/FK/UNIQUE/CHECK constraints are included; indexes include their backing constraint, validity/readiness and PostgreSQL deparsed definition. This metadata inventory contains no business records.

<details>
<summary>A — root .env DATABASE_URL — full live metadata</summary>


### `public.ai_credential_audit_log`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.ai_credential_audit_log_id_seq'::regclass)` | `none / none` |
| `user_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `action` | `character varying(48)` | NOT NULL | `—` | `none / none` |
| `target_kind` | `character varying(24)` | NOT NULL | `—` | `none / none` |
| `target_id` | `integer` | NULL | `—` | `none / none` |
| `provider_name` | `character varying(32)` | NULL | `—` | `none / none` |
| `detail` | `character varying(240)` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_ai_credential_audit_log` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_ai_credential_audit_log_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_credential_audit_log_created_at ON public.ai_credential_audit_log USING btree (created_at)` |
| `ix_ai_credential_audit_log_id` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_credential_audit_log_id ON public.ai_credential_audit_log USING btree (id)` |
| `pk_ai_credential_audit_log` | btree / True | `pk_ai_credential_audit_log` | True / True | `CREATE UNIQUE INDEX pk_ai_credential_audit_log ON public.ai_credential_audit_log USING btree (id)` |

### `public.ai_fix_batch`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `character varying(36)` | NOT NULL | `—` | `none / none` |
| `run_id` | `integer` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(24)` | NOT NULL | `—` | `none / none` |
| `scope_label` | `character varying(120)` | NULL | `—` | `none / none` |
| `scope_json` | `json` | NULL | `—` | `none / none` |
| `finding_ids_json` | `json` | NOT NULL | `—` | `none / none` |
| `provider_name` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `total` | `integer` | NOT NULL | `—` | `none / none` |
| `cached_count` | `integer` | NOT NULL | `—` | `none / none` |
| `generated_count` | `integer` | NOT NULL | `—` | `none / none` |
| `failed_count` | `integer` | NOT NULL | `—` | `none / none` |
| `cost_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `started_at` | `character varying` | NULL | `—` | `none / none` |
| `completed_at` | `character varying` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `last_error` | `character varying(240)` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_ai_fix_batch_run_id_analysis_run` | f | `FOREIGN KEY (run_id) REFERENCES public.analysis_run(id) ON DELETE CASCADE` | True / False / False |
| `fk_ai_fix_batch_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_ai_fix_batch` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_ai_fix_batch_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_batch_created_at ON public.ai_fix_batch USING btree (created_at)` |
| `ix_ai_fix_batch_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_batch_deactivated ON public.ai_fix_batch USING btree (is_active) WHERE (is_active = false)` |
| `ix_ai_fix_batch_run_status` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_batch_run_status ON public.ai_fix_batch USING btree (run_id, status)` |
| `ix_ai_fix_batch_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_batch_tenant_id ON public.ai_fix_batch USING btree (tenant_id)` |
| `ix_ai_fix_batch_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_batch_tenant_identity ON public.ai_fix_batch USING btree (tenant_id, id)` |
| `pk_ai_fix_batch` | btree / True | `pk_ai_fix_batch` | True / True | `CREATE UNIQUE INDEX pk_ai_fix_batch ON public.ai_fix_batch USING btree (id)` |

### `public.ai_fix_cache`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `cache_key` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `vuln_id` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `component_name` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `component_version` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `prompt_version` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `schema_version` | `integer` | NOT NULL | `—` | `none / none` |
| `remediation_prose` | `json` | NOT NULL | `—` | `none / none` |
| `upgrade_command` | `json` | NOT NULL | `—` | `none / none` |
| `decision_recommendation` | `json` | NOT NULL | `—` | `none / none` |
| `overall_confidence` | `character varying(16)` | NULL | `—` | `none / none` |
| `provider_used` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `model_used` | `character varying(256)` | NOT NULL | `—` | `none / none` |
| `total_cost_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `generated_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `last_accessed_at` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_ai_fix_cache` | p | `PRIMARY KEY (cache_key)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_ai_fix_cache_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_cache_expires_at ON public.ai_fix_cache USING btree (expires_at)` |
| `ix_ai_fix_cache_vuln_component` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_cache_vuln_component ON public.ai_fix_cache USING btree (vuln_id, component_name, component_version)` |
| `ix_ai_fix_cache_vuln_id` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_cache_vuln_id ON public.ai_fix_cache USING btree (vuln_id)` |
| `pk_ai_fix_cache` | btree / True | `pk_ai_fix_cache` | True / True | `CREATE UNIQUE INDEX pk_ai_fix_cache ON public.ai_fix_cache USING btree (cache_key)` |

### `public.ai_provider_config`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `provider_name` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `enabled` | `boolean` | NULL | `—` | `none / none` |
| `default_model` | `character varying(256)` | NULL | `—` | `none / none` |
| `base_url` | `character varying(256)` | NULL | `—` | `none / none` |
| `max_concurrent` | `integer` | NULL | `—` | `none / none` |
| `rate_per_minute` | `double precision` | NULL | `—` | `none / none` |
| `notes` | `text` | NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NULL | `—` | `none / none` |
| `updated_by` | `character varying` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_ai_provider_config` | p | `PRIMARY KEY (provider_name)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `pk_ai_provider_config` | btree / True | `pk_ai_provider_config` | True / True | `CREATE UNIQUE INDEX pk_ai_provider_config ON public.ai_provider_config USING btree (provider_name)` |

### `public.ai_provider_credential`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.ai_provider_credential_id_seq'::regclass)` | `none / none` |
| `provider_name` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `label` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `api_key_encrypted` | `text` | NULL | `—` | `none / none` |
| `base_url` | `character varying(512)` | NULL | `—` | `none / none` |
| `default_model` | `character varying(256)` | NULL | `—` | `none / none` |
| `tier` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `is_default` | `boolean` | NOT NULL | `—` | `none / none` |
| `is_fallback` | `boolean` | NOT NULL | `—` | `none / none` |
| `enabled` | `boolean` | NOT NULL | `—` | `none / none` |
| `cost_per_1k_input_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `cost_per_1k_output_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `is_local` | `boolean` | NOT NULL | `—` | `none / none` |
| `max_concurrent` | `integer` | NULL | `—` | `none / none` |
| `rate_per_minute` | `double precision` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `last_test_at` | `character varying` | NULL | `—` | `none / none` |
| `last_test_success` | `boolean` | NULL | `—` | `none / none` |
| `last_test_error` | `text` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_ai_provider_credential` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_ai_provider_credential_provider_label` | u | `UNIQUE (provider_name, label)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_ai_only_one_default` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX ix_ai_only_one_default ON public.ai_provider_credential USING btree (is_default) WHERE (is_default = true)` |
| `ix_ai_only_one_fallback` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX ix_ai_only_one_fallback ON public.ai_provider_credential USING btree (is_fallback) WHERE (is_fallback = true)` |
| `ix_ai_provider_credential_id` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_provider_credential_id ON public.ai_provider_credential USING btree (id)` |
| `ix_ai_provider_credential_provider_name` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_provider_credential_provider_name ON public.ai_provider_credential USING btree (provider_name)` |
| `pk_ai_provider_credential` | btree / True | `pk_ai_provider_credential` | True / True | `CREATE UNIQUE INDEX pk_ai_provider_credential ON public.ai_provider_credential USING btree (id)` |
| `uq_ai_provider_credential_provider_label` | btree / True | `uq_ai_provider_credential_provider_label` | True / True | `CREATE UNIQUE INDEX uq_ai_provider_credential_provider_label ON public.ai_provider_credential USING btree (provider_name, label)` |

### `public.ai_provider_model`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.ai_provider_model_id_seq'::regclass)` | `none / none` |
| `provider_credential_id` | `integer` | NOT NULL | `—` | `none / none` |
| `provider_name` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `provider_model_id` | `character varying(256)` | NOT NULL | `—` | `none / none` |
| `runtime_model_id` | `character varying(256)` | NOT NULL | `—` | `none / none` |
| `display_name` | `character varying(256)` | NULL | `—` | `none / none` |
| `is_available` | `boolean` | NULL | `—` | `none / none` |
| `is_enabled` | `boolean` | NOT NULL | `true` | `none / none` |
| `is_selected` | `boolean` | NOT NULL | `false` | `none / none` |
| `supports_chat` | `boolean` | NULL | `—` | `none / none` |
| `supports_structured_output` | `boolean` | NULL | `—` | `none / none` |
| `supports_streaming` | `boolean` | NULL | `—` | `none / none` |
| `supports_tools` | `boolean` | NULL | `—` | `none / none` |
| `context_window` | `integer` | NULL | `—` | `none / none` |
| `max_output_tokens` | `integer` | NULL | `—` | `none / none` |
| `discovery_source` | `character varying(24)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `first_discovered_at` | `character varying` | NULL | `—` | `none / none` |
| `last_discovered_at` | `character varying` | NULL | `—` | `none / none` |
| `last_verified_at` | `character varying` | NULL | `—` | `none / none` |
| `last_test_success` | `boolean` | NULL | `—` | `none / none` |
| `last_test_error` | `character varying(240)` | NULL | `—` | `none / none` |
| `raw_metadata` | `json` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_ai_provider_model_provider_credential_id_ai_provider_97cb` | f | `FOREIGN KEY (provider_credential_id) REFERENCES public.ai_provider_credential(id) ON DELETE CASCADE` | True / False / False |
| `pk_ai_provider_model` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_ai_provider_model_credential_provider_model` | u | `UNIQUE (provider_credential_id, provider_model_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_ai_provider_model_credential_available` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_provider_model_credential_available ON public.ai_provider_model USING btree (provider_credential_id, is_available)` |
| `ix_ai_provider_model_only_one_selected` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX ix_ai_provider_model_only_one_selected ON public.ai_provider_model USING btree (provider_credential_id) WHERE (is_selected = true)` |
| `ix_ai_provider_model_provider_credential_id` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_provider_model_provider_credential_id ON public.ai_provider_model USING btree (provider_credential_id)` |
| `ix_ai_provider_model_provider_name` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_provider_model_provider_name ON public.ai_provider_model USING btree (provider_name)` |
| `pk_ai_provider_model` | btree / True | `pk_ai_provider_model` | True / True | `CREATE UNIQUE INDEX pk_ai_provider_model ON public.ai_provider_model USING btree (id)` |
| `uq_ai_provider_model_credential_provider_model` | btree / True | `uq_ai_provider_model_credential_provider_model` | True / True | `CREATE UNIQUE INDEX uq_ai_provider_model_credential_provider_model ON public.ai_provider_model USING btree (provider_credential_id, provider_model_id)` |

### `public.ai_settings`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `—` | `none / none` |
| `feature_enabled` | `boolean` | NOT NULL | `—` | `none / none` |
| `kill_switch_active` | `boolean` | NOT NULL | `—` | `none / none` |
| `budget_per_request_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `budget_per_scan_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `budget_daily_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_by_user_id` | `character varying` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_ai_settings_ck_ai_settings_singleton` | c | `CHECK (id = 1)` | True / False / False |
| `pk_ai_settings` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `pk_ai_settings` | btree / True | `pk_ai_settings` | True / True | `CREATE UNIQUE INDEX pk_ai_settings ON public.ai_settings USING btree (id)` |

### `public.ai_usage_log`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.ai_usage_log_id_seq'::regclass)` | `none / none` |
| `request_id` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `provider` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `model` | `character varying(256)` | NOT NULL | `—` | `none / none` |
| `purpose` | `character varying(48)` | NOT NULL | `—` | `none / none` |
| `finding_cache_key` | `character varying(64)` | NULL | `—` | `none / none` |
| `input_tokens` | `integer` | NOT NULL | `—` | `none / none` |
| `output_tokens` | `integer` | NOT NULL | `—` | `none / none` |
| `cost_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `latency_ms` | `integer` | NOT NULL | `—` | `none / none` |
| `cache_hit` | `boolean` | NOT NULL | `—` | `none / none` |
| `error` | `text` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_ai_usage_log_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_ai_usage_log` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_ai_usage_log_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_created_at ON public.ai_usage_log USING btree (created_at)` |
| `ix_ai_usage_log_finding_cache_key` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_finding_cache_key ON public.ai_usage_log USING btree (finding_cache_key)` |
| `ix_ai_usage_log_id` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_id ON public.ai_usage_log USING btree (id)` |
| `ix_ai_usage_log_provider` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_provider ON public.ai_usage_log USING btree (provider)` |
| `ix_ai_usage_log_provider_created` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_provider_created ON public.ai_usage_log USING btree (provider, created_at)` |
| `ix_ai_usage_log_purpose` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_purpose ON public.ai_usage_log USING btree (purpose)` |
| `ix_ai_usage_log_purpose_created` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_purpose_created ON public.ai_usage_log USING btree (purpose, created_at)` |
| `ix_ai_usage_log_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_tenant_id ON public.ai_usage_log USING btree (tenant_id)` |
| `ix_ai_usage_log_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_tenant_identity ON public.ai_usage_log USING btree (tenant_id, id)` |
| `pk_ai_usage_log` | btree / True | `pk_ai_usage_log` | True / True | `CREATE UNIQUE INDEX pk_ai_usage_log ON public.ai_usage_log USING btree (id)` |

### `public.alembic_version`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `version_num` | `character varying(128)` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `alembic_version_pkc` | p | `PRIMARY KEY (version_num)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `alembic_version_pkc` | btree / True | `alembic_version_pkc` | True / True | `CREATE UNIQUE INDEX alembic_version_pkc ON public.alembic_version USING btree (version_num)` |

### `public.analysis_finding`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.analysis_finding_id_seq'::regclass)` | `none / none` |
| `analysis_run_id` | `integer` | NOT NULL | `—` | `none / none` |
| `component_id` | `integer` | NULL | `—` | `none / none` |
| `vuln_id` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `source` | `character varying(128)` | NULL | `—` | `none / none` |
| `title` | `character varying` | NULL | `—` | `none / none` |
| `description` | `text` | NULL | `—` | `none / none` |
| `severity` | `character varying(16)` | NULL | `—` | `none / none` |
| `score` | `double precision` | NULL | `—` | `none / none` |
| `vector` | `text` | NULL | `—` | `none / none` |
| `published_on` | `character varying` | NULL | `—` | `none / none` |
| `reference_url` | `text` | NULL | `—` | `none / none` |
| `cwe` | `text` | NULL | `—` | `none / none` |
| `cpe` | `character varying` | NULL | `—` | `none / none` |
| `component_name` | `text` | NULL | `—` | `none / none` |
| `component_version` | `text` | NULL | `—` | `none / none` |
| `fixed_versions` | `text` | NULL | `—` | `none / none` |
| `attack_vector` | `character varying(64)` | NULL | `—` | `none / none` |
| `cvss_version` | `character varying(16)` | NULL | `—` | `none / none` |
| `aliases` | `text` | NULL | `—` | `none / none` |
| `match_reason` | `character varying(255)` | NULL | `—` | `none / none` |
| `matched_range` | `text` | NULL | `—` | `none / none` |
| `match_confidence` | `double precision` | NULL | `—` | `none / none` |
| `match_strategy` | `character varying(64)` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_analysis_finding_analysis_run_id_analysis_run` | f | `FOREIGN KEY (analysis_run_id) REFERENCES public.analysis_run(id)` | True / False / False |
| `fk_analysis_finding_component_id_sbom_component` | f | `FOREIGN KEY (component_id) REFERENCES public.sbom_component(id)` | True / False / False |
| `fk_analysis_finding_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_analysis_finding` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_analysis_finding_run_vuln_cpe` | u | `UNIQUE (analysis_run_id, vuln_id, cpe)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_analysis_finding_analysis_run_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_analysis_run_id ON public.analysis_finding USING btree (analysis_run_id)` |
| `ix_analysis_finding_component_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_component_id ON public.analysis_finding USING btree (component_id)` |
| `ix_analysis_finding_cpe` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_cpe ON public.analysis_finding USING btree (cpe)` |
| `ix_analysis_finding_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_deactivated ON public.analysis_finding USING btree (is_active) WHERE (is_active = false)` |
| `ix_analysis_finding_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_id ON public.analysis_finding USING btree (id)` |
| `ix_analysis_finding_match_reason` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_match_reason ON public.analysis_finding USING btree (match_reason)` |
| `ix_analysis_finding_match_strategy` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_match_strategy ON public.analysis_finding USING btree (match_strategy)` |
| `ix_analysis_finding_run_severity` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_run_severity ON public.analysis_finding USING btree (analysis_run_id, severity)` |
| `ix_analysis_finding_severity` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_severity ON public.analysis_finding USING btree (severity)` |
| `ix_analysis_finding_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_tenant_id ON public.analysis_finding USING btree (tenant_id)` |
| `ix_analysis_finding_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_tenant_identity ON public.analysis_finding USING btree (tenant_id, id)` |
| `ix_analysis_finding_vuln_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_vuln_id ON public.analysis_finding USING btree (vuln_id)` |
| `pk_analysis_finding` | btree / True | `pk_analysis_finding` | True / True | `CREATE UNIQUE INDEX pk_analysis_finding ON public.analysis_finding USING btree (id)` |
| `uq_analysis_finding_run_vuln_cpe` | btree / True | `uq_analysis_finding_run_vuln_cpe` | True / True | `CREATE UNIQUE INDEX uq_analysis_finding_run_vuln_cpe ON public.analysis_finding USING btree (analysis_run_id, vuln_id, cpe)` |

### `public.analysis_run`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.analysis_run_id_seq'::regclass)` | `none / none` |
| `sbom_id` | `integer` | NOT NULL | `—` | `none / none` |
| `project_id` | `integer` | NULL | `—` | `none / none` |
| `product_id` | `integer` | NULL | `—` | `none / none` |
| `run_status` | `character varying` | NOT NULL | `—` | `none / none` |
| `sbom_name` | `character varying` | NULL | `—` | `none / none` |
| `source` | `character varying` | NOT NULL | `—` | `none / none` |
| `trigger_source` | `character varying(32)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `started_on` | `character varying` | NOT NULL | `—` | `none / none` |
| `completed_on` | `character varying` | NOT NULL | `—` | `none / none` |
| `duration_ms` | `integer` | NOT NULL | `—` | `none / none` |
| `total_components` | `integer` | NOT NULL | `—` | `none / none` |
| `components_with_cpe` | `integer` | NOT NULL | `—` | `none / none` |
| `total_findings` | `integer` | NOT NULL | `—` | `none / none` |
| `critical_count` | `integer` | NOT NULL | `—` | `none / none` |
| `high_count` | `integer` | NOT NULL | `—` | `none / none` |
| `medium_count` | `integer` | NOT NULL | `—` | `none / none` |
| `low_count` | `integer` | NOT NULL | `—` | `none / none` |
| `unknown_count` | `integer` | NOT NULL | `—` | `none / none` |
| `query_error_count` | `integer` | NOT NULL | `—` | `none / none` |
| `raw_report` | `text` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_analysis_run_product_id_products` | f | `FOREIGN KEY (product_id) REFERENCES public.products(id)` | True / False / False |
| `fk_analysis_run_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id)` | True / False / False |
| `fk_analysis_run_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_analysis_run_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_analysis_run` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_analysis_run_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_deactivated ON public.analysis_run USING btree (is_active) WHERE (is_active = false)` |
| `ix_analysis_run_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_id ON public.analysis_run USING btree (id)` |
| `ix_analysis_run_product_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_product_id ON public.analysis_run USING btree (product_id)` |
| `ix_analysis_run_project_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_project_id ON public.analysis_run USING btree (project_id)` |
| `ix_analysis_run_run_status` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_run_status ON public.analysis_run USING btree (run_status)` |
| `ix_analysis_run_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_sbom_id ON public.analysis_run USING btree (sbom_id)` |
| `ix_analysis_run_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_tenant_id ON public.analysis_run USING btree (tenant_id)` |
| `ix_analysis_run_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_tenant_identity ON public.analysis_run USING btree (tenant_id, id)` |
| `ix_analysis_run_trigger_source` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_trigger_source ON public.analysis_run USING btree (trigger_source)` |
| `pk_analysis_run` | btree / True | `pk_analysis_run` | True / True | `CREATE UNIQUE INDEX pk_analysis_run ON public.analysis_run USING btree (id)` |

### `public.analysis_schedule`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.analysis_schedule_id_seq'::regclass)` | `none / none` |
| `scope` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `project_id` | `integer` | NULL | `—` | `none / none` |
| `product_id` | `integer` | NULL | `—` | `none / none` |
| `sbom_id` | `integer` | NULL | `—` | `none / none` |
| `cadence` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `cron_expression` | `character varying(128)` | NULL | `—` | `none / none` |
| `day_of_week` | `integer` | NULL | `—` | `none / none` |
| `day_of_month` | `integer` | NULL | `—` | `none / none` |
| `hour_utc` | `integer` | NOT NULL | `—` | `none / none` |
| `timezone` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `enabled` | `boolean` | NOT NULL | `—` | `none / none` |
| `next_run_at` | `character varying` | NULL | `—` | `none / none` |
| `last_run_at` | `character varying` | NULL | `—` | `none / none` |
| `last_run_status` | `character varying(16)` | NULL | `—` | `none / none` |
| `last_run_id` | `integer` | NULL | `—` | `none / none` |
| `consecutive_failures` | `integer` | NOT NULL | `—` | `none / none` |
| `min_gap_minutes` | `integer` | NOT NULL | `—` | `none / none` |
| `created_on` | `character varying` | NULL | `—` | `none / none` |
| `created_by` | `character varying` | NULL | `—` | `none / none` |
| `modified_on` | `character varying` | NULL | `—` | `none / none` |
| `modified_by` | `character varying` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `mode` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `target_version_policy` | `character varying(32)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_analysis_schedule_ck_analysis_schedule_cadence` | c | `CHECK (cadence::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_analysis_schedule_ck_analysis_schedule_dom_range` | c | `CHECK (day_of_month IS NULL OR day_of_month >= 1 AND day_of_month <= 28)` | True / False / False |
| `ck_analysis_schedule_ck_analysis_schedule_dow_range` | c | `CHECK (day_of_week IS NULL OR day_of_week >= 0 AND day_of_week <= 6)` | True / False / False |
| `ck_analysis_schedule_ck_analysis_schedule_hour_range` | c | `CHECK (hour_utc >= 0 AND hour_utc <= 23)` | True / False / False |
| `ck_analysis_schedule_ck_analysis_schedule_mode` | c | `CHECK (mode::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_analysis_schedule_ck_analysis_schedule_scope` | c | `CHECK (scope::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_analysis_schedule_ck_analysis_schedule_target` | c | `CHECK (scope::text = '<literal redacted>'::text AND project_id IS NOT NULL AND product_id IS NULL AND sbom_id IS NULL OR scope::text = '<literal redacted>'::text AND product_id IS NOT NULL AND project_id IS NULL AND sbom_id IS NULL OR scope::text = '<literal redacted>'::text AND sbom_id IS NOT NULL AND project_id IS NULL AND product_id IS NULL OR scope::text = '<literal redacted>'::text AND project_id IS NULL AND product_id IS NULL AND sbom_id IS NULL)` | True / False / False |
| `ck_analysis_schedule_ck_analysis_schedule_target_version_policy` | c | `CHECK (target_version_policy::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `fk_analysis_schedule_last_run_id_analysis_run` | f | `FOREIGN KEY (last_run_id) REFERENCES public.analysis_run(id) ON DELETE SET NULL` | True / False / False |
| `fk_analysis_schedule_product_id_products` | f | `FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE CASCADE` | True / False / False |
| `fk_analysis_schedule_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE` | True / False / False |
| `fk_analysis_schedule_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE CASCADE` | True / False / False |
| `fk_analysis_schedule_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_analysis_schedule` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_analysis_schedule_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_deactivated ON public.analysis_schedule USING btree (is_active) WHERE (is_active = false)` |
| `ix_analysis_schedule_due` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_due ON public.analysis_schedule USING btree (enabled, next_run_at)` |
| `ix_analysis_schedule_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_id ON public.analysis_schedule USING btree (id)` |
| `ix_analysis_schedule_next_run_at` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_next_run_at ON public.analysis_schedule USING btree (next_run_at)` |
| `ix_analysis_schedule_product_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_product_id ON public.analysis_schedule USING btree (product_id)` |
| `ix_analysis_schedule_project_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_project_id ON public.analysis_schedule USING btree (project_id)` |
| `ix_analysis_schedule_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_sbom_id ON public.analysis_schedule USING btree (sbom_id)` |
| `ix_analysis_schedule_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_tenant_id ON public.analysis_schedule USING btree (tenant_id)` |
| `ix_analysis_schedule_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_tenant_identity ON public.analysis_schedule USING btree (tenant_id, id)` |
| `pk_analysis_schedule` | btree / True | `pk_analysis_schedule` | True / True | `CREATE UNIQUE INDEX pk_analysis_schedule ON public.analysis_schedule USING btree (id)` |
| `uq_analysis_schedule_tenant` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_analysis_schedule_tenant ON public.analysis_schedule USING btree (tenant_id) WHERE (((scope)::text = '<literal redacted>'::text) AND is_active)` |

### `public.audit_log`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.audit_log_id_seq'::regclass)` | `none / none` |
| `user_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `action` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `target_kind` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `target_id` | `integer` | NULL | `—` | `none / none` |
| `detail` | `text` | NULL | `—` | `none / none` |
| `metadata_json` | `json` | NULL | `—` | `none / none` |
| `user_ref_id` | `integer` | NULL | `—` | `none / none` |
| `entity_type` | `character varying(128)` | NULL | `—` | `none / none` |
| `entity_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `old_value` | `json` | NULL | `—` | `none / none` |
| `new_value` | `json` | NULL | `—` | `none / none` |
| `ip_address` | `character varying(64)` | NULL | `—` | `none / none` |
| `user_agent` | `text` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_audit_log_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `fk_audit_log_user_ref_id_iam_users` | f | `FOREIGN KEY (user_ref_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `pk_audit_log` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_audit_log_action` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_action ON public.audit_log USING btree (action)` |
| `ix_audit_log_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_created_at ON public.audit_log USING btree (created_at)` |
| `ix_audit_log_entity_id` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_entity_id ON public.audit_log USING btree (entity_id)` |
| `ix_audit_log_entity_type` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_entity_type ON public.audit_log USING btree (entity_type)` |
| `ix_audit_log_id` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_id ON public.audit_log USING btree (id)` |
| `ix_audit_log_target_id` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_target_id ON public.audit_log USING btree (target_id)` |
| `ix_audit_log_target_kind` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_target_kind ON public.audit_log USING btree (target_kind)` |
| `ix_audit_log_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_tenant_id ON public.audit_log USING btree (tenant_id)` |
| `ix_audit_log_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_tenant_identity ON public.audit_log USING btree (tenant_id, id)` |
| `ix_audit_log_user_ref_id` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_user_ref_id ON public.audit_log USING btree (user_ref_id)` |
| `pk_audit_log` | btree / True | `pk_audit_log` | True / True | `CREATE UNIQUE INDEX pk_audit_log ON public.audit_log USING btree (id)` |

### `public.authorization_audit_log`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.authorization_audit_log_id_seq'::regclass)` | `none / none` |
| `actor_user_id` | `integer` | NULL | `—` | `none / none` |
| `target_user_id` | `integer` | NULL | `—` | `none / none` |
| `target_membership_id` | `integer` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NULL | `—` | `none / none` |
| `action` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `outcome` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `old_value` | `json` | NULL | `—` | `none / none` |
| `new_value` | `json` | NULL | `—` | `none / none` |
| `correlation_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `detail` | `character varying(240)` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_authorization_audit_log_ck_authorization_audit_log_a_b862` | c | `CHECK (outcome::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `fk_authorization_audit_log_actor_user_id_iam_users` | f | `FOREIGN KEY (actor_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_authorization_audit_log_target_membership_id_tenant_users` | f | `FOREIGN KEY (target_membership_id) REFERENCES public.tenant_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_authorization_audit_log_target_user_id_iam_users` | f | `FOREIGN KEY (target_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_authorization_audit_log_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL` | True / False / False |
| `pk_authorization_audit_log` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_authorization_audit_log_action` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_action ON public.authorization_audit_log USING btree (action)` |
| `ix_authorization_audit_log_actor_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_actor_user_id ON public.authorization_audit_log USING btree (actor_user_id)` |
| `ix_authorization_audit_log_correlation_id` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_correlation_id ON public.authorization_audit_log USING btree (correlation_id)` |
| `ix_authorization_audit_log_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_created_at ON public.authorization_audit_log USING btree (created_at)` |
| `ix_authorization_audit_log_outcome` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_outcome ON public.authorization_audit_log USING btree (outcome)` |
| `ix_authorization_audit_log_target_membership_id` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_target_membership_id ON public.authorization_audit_log USING btree (target_membership_id)` |
| `ix_authorization_audit_log_target_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_target_user_id ON public.authorization_audit_log USING btree (target_user_id)` |
| `ix_authorization_audit_log_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_tenant_id ON public.authorization_audit_log USING btree (tenant_id)` |
| `pk_authorization_audit_log` | btree / True | `pk_authorization_audit_log` | True / True | `CREATE UNIQUE INDEX pk_authorization_audit_log ON public.authorization_audit_log USING btree (id)` |

### `public.authorization_permissions`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.authorization_permissions_id_seq'::regclass)` | `none / none` |
| `code` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `name` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `description` | `text` | NULL | `—` | `none / none` |
| `scope` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `resource` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `action` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `is_system` | `boolean` | NOT NULL | `true` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_authorization_permissions_authorization_permission_c_6755` | c | `CHECK (length(TRIM(BOTH FROM code)) > 0)` | True / False / False |
| `ck_authorization_permissions_authorization_permission_c_d702` | c | `CHECK (code::text = lower(code::text) AND code::text !~~ '<literal redacted>'::text)` | True / False / False |
| `ck_authorization_permissions_authorization_permission_n_fa1b` | c | `CHECK (length(TRIM(BOTH FROM name)) > 0)` | True / False / False |
| `ck_authorization_permissions_authorization_permission_scope` | c | `CHECK (scope::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_authorization_permissions_authorization_permission_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `pk_authorization_permissions` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_authorization_permissions_code` | u | `UNIQUE (code)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_authorization_permissions_action` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_permissions_action ON public.authorization_permissions USING btree (action)` |
| `ix_authorization_permissions_code` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_permissions_code ON public.authorization_permissions USING btree (code)` |
| `ix_authorization_permissions_resource` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_permissions_resource ON public.authorization_permissions USING btree (resource)` |
| `ix_authorization_permissions_scope` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_permissions_scope ON public.authorization_permissions USING btree (scope)` |
| `ix_authorization_permissions_status` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_permissions_status ON public.authorization_permissions USING btree (status)` |
| `pk_authorization_permissions` | btree / True | `pk_authorization_permissions` | True / True | `CREATE UNIQUE INDEX pk_authorization_permissions ON public.authorization_permissions USING btree (id)` |
| `uq_authorization_permissions_code` | btree / True | `uq_authorization_permissions_code` | True / True | `CREATE UNIQUE INDEX uq_authorization_permissions_code ON public.authorization_permissions USING btree (code)` |

### `public.authorization_role_permissions`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.authorization_role_permissions_id_seq'::regclass)` | `none / none` |
| `role_id` | `integer` | NOT NULL | `—` | `none / none` |
| `permission_id` | `integer` | NOT NULL | `—` | `none / none` |
| `is_protected` | `boolean` | NOT NULL | `false` | `none / none` |
| `created_by_user_id` | `integer` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_authorization_role_permissions_created_by_user_id_iam_users` | f | `FOREIGN KEY (created_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_authorization_role_permissions_permission_id_authori_8d82` | f | `FOREIGN KEY (permission_id) REFERENCES public.authorization_permissions(id) ON DELETE RESTRICT` | True / False / False |
| `fk_authorization_role_permissions_role_id_authorization_roles` | f | `FOREIGN KEY (role_id) REFERENCES public.authorization_roles(id) ON DELETE RESTRICT` | True / False / False |
| `pk_authorization_role_permissions` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_authorization_role_permissions_role_permission` | u | `UNIQUE (role_id, permission_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_authorization_role_permissions_permission_id` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_role_permissions_permission_id ON public.authorization_role_permissions USING btree (permission_id)` |
| `ix_authorization_role_permissions_role_id` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_role_permissions_role_id ON public.authorization_role_permissions USING btree (role_id)` |
| `pk_authorization_role_permissions` | btree / True | `pk_authorization_role_permissions` | True / True | `CREATE UNIQUE INDEX pk_authorization_role_permissions ON public.authorization_role_permissions USING btree (id)` |
| `uq_authorization_role_permissions_role_permission` | btree / True | `uq_authorization_role_permissions_role_permission` | True / True | `CREATE UNIQUE INDEX uq_authorization_role_permissions_role_permission ON public.authorization_role_permissions USING btree (role_id, permission_id)` |

### `public.authorization_roles`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.authorization_roles_id_seq'::regclass)` | `none / none` |
| `code` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `name` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `description` | `text` | NULL | `—` | `none / none` |
| `scope` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `is_system` | `boolean` | NOT NULL | `true` | `none / none` |
| `is_assignable` | `boolean` | NOT NULL | `true` | `none / none` |
| `version` | `integer` | NOT NULL | `1` | `none / none` |
| `created_by_user_id` | `integer` | NULL | `—` | `none / none` |
| `updated_by_user_id` | `integer` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_authorization_roles_authorization_role_code_normalized` | c | `CHECK (code::text = upper(code::text))` | True / False / False |
| `ck_authorization_roles_authorization_role_code_not_blank` | c | `CHECK (length(TRIM(BOTH FROM code)) > 0)` | True / False / False |
| `ck_authorization_roles_authorization_role_name_not_blank` | c | `CHECK (length(TRIM(BOTH FROM name)) > 0)` | True / False / False |
| `ck_authorization_roles_authorization_role_scope` | c | `CHECK (scope::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_authorization_roles_authorization_role_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_authorization_roles_authorization_role_version` | c | `CHECK (version >= 1)` | True / False / False |
| `fk_authorization_roles_created_by_user_id_iam_users` | f | `FOREIGN KEY (created_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_authorization_roles_updated_by_user_id_iam_users` | f | `FOREIGN KEY (updated_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `pk_authorization_roles` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_authorization_roles_scope_code` | u | `UNIQUE (scope, code)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_authorization_roles_scope` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_roles_scope ON public.authorization_roles USING btree (scope)` |
| `ix_authorization_roles_status` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_roles_status ON public.authorization_roles USING btree (status)` |
| `pk_authorization_roles` | btree / True | `pk_authorization_roles` | True / True | `CREATE UNIQUE INDEX pk_authorization_roles ON public.authorization_roles USING btree (id)` |
| `uq_authorization_roles_scope_code` | btree / True | `uq_authorization_roles_scope_code` | True / True | `CREATE UNIQUE INDEX uq_authorization_roles_scope_code ON public.authorization_roles USING btree (scope, code)` |

### `public.celery_taskmeta`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `—` | `none / none` |
| `task_id` | `character varying(155)` | NULL | `—` | `none / none` |
| `status` | `character varying(50)` | NULL | `—` | `none / none` |
| `result` | `bytea` | NULL | `—` | `none / none` |
| `date_done` | `timestamp without time zone` | NULL | `—` | `none / none` |
| `traceback` | `text` | NULL | `—` | `none / none` |
| `name` | `character varying(155)` | NULL | `—` | `none / none` |
| `args` | `bytea` | NULL | `—` | `none / none` |
| `kwargs` | `bytea` | NULL | `—` | `none / none` |
| `worker` | `character varying(155)` | NULL | `—` | `none / none` |
| `retries` | `integer` | NULL | `—` | `none / none` |
| `queue` | `character varying(155)` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `celery_taskmeta_pkey` | p | `PRIMARY KEY (id)` | True / False / False |
| `celery_taskmeta_task_id_key` | u | `UNIQUE (task_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `celery_taskmeta_pkey` | btree / True | `celery_taskmeta_pkey` | True / True | `CREATE UNIQUE INDEX celery_taskmeta_pkey ON public.celery_taskmeta USING btree (id)` |
| `celery_taskmeta_task_id_key` | btree / True | `celery_taskmeta_task_id_key` | True / True | `CREATE UNIQUE INDEX celery_taskmeta_task_id_key ON public.celery_taskmeta USING btree (task_id)` |
| `ix_celery_taskmeta_date_done` | btree / False | `none` | True / True | `CREATE INDEX ix_celery_taskmeta_date_done ON public.celery_taskmeta USING btree (date_done)` |

### `public.celery_tasksetmeta`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `—` | `none / none` |
| `taskset_id` | `character varying(155)` | NULL | `—` | `none / none` |
| `result` | `bytea` | NULL | `—` | `none / none` |
| `date_done` | `timestamp without time zone` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `celery_tasksetmeta_pkey` | p | `PRIMARY KEY (id)` | True / False / False |
| `celery_tasksetmeta_taskset_id_key` | u | `UNIQUE (taskset_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `celery_tasksetmeta_pkey` | btree / True | `celery_tasksetmeta_pkey` | True / True | `CREATE UNIQUE INDEX celery_tasksetmeta_pkey ON public.celery_tasksetmeta USING btree (id)` |
| `celery_tasksetmeta_taskset_id_key` | btree / True | `celery_tasksetmeta_taskset_id_key` | True / True | `CREATE UNIQUE INDEX celery_tasksetmeta_taskset_id_key ON public.celery_tasksetmeta USING btree (taskset_id)` |
| `ix_celery_tasksetmeta_date_done` | btree / False | `none` | True / True | `CREATE INDEX ix_celery_tasksetmeta_date_done ON public.celery_tasksetmeta USING btree (date_done)` |

### `public.compare_cache`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `cache_key` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `run_a_id` | `integer` | NOT NULL | `—` | `none / none` |
| `run_b_id` | `integer` | NOT NULL | `—` | `none / none` |
| `payload` | `json` | NOT NULL | `—` | `none / none` |
| `computed_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `schema_version` | `integer` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_compare_cache_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_compare_cache` | p | `PRIMARY KEY (cache_key)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_compare_cache_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_compare_cache_expires_at ON public.compare_cache USING btree (expires_at)` |
| `ix_compare_cache_run_a_id` | btree / False | `none` | True / True | `CREATE INDEX ix_compare_cache_run_a_id ON public.compare_cache USING btree (run_a_id)` |
| `ix_compare_cache_run_b_id` | btree / False | `none` | True / True | `CREATE INDEX ix_compare_cache_run_b_id ON public.compare_cache USING btree (run_b_id)` |
| `ix_compare_cache_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_compare_cache_tenant_id ON public.compare_cache USING btree (tenant_id)` |
| `ix_compare_cache_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_compare_cache_tenant_identity ON public.compare_cache USING btree (tenant_id, cache_key)` |
| `pk_compare_cache` | btree / True | `pk_compare_cache` | True / True | `CREATE UNIQUE INDEX pk_compare_cache ON public.compare_cache USING btree (cache_key)` |

### `public.component_lifecycle_cache`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.component_lifecycle_cache_id_seq'::regclass)` | `none / none` |
| `lookup_key` | `character varying` | NULL | `—` | `none / none` |
| `normalized_name` | `character varying` | NOT NULL | `—` | `none / none` |
| `normalized_version` | `character varying` | NULL | `—` | `none / none` |
| `ecosystem` | `character varying` | NULL | `—` | `none / none` |
| `purl` | `character varying` | NULL | `—` | `none / none` |
| `cpe` | `character varying` | NULL | `—` | `none / none` |
| `lifecycle_status` | `character varying` | NULL | `—` | `none / none` |
| `eos_date` | `character varying` | NULL | `—` | `none / none` |
| `eol_date` | `character varying` | NULL | `—` | `none / none` |
| `eof_date` | `character varying` | NULL | `—` | `none / none` |
| `deprecated` | `boolean` | NULL | `—` | `none / none` |
| `unsupported` | `boolean` | NULL | `—` | `none / none` |
| `maintenance_status` | `character varying` | NULL | `—` | `none / none` |
| `latest_version` | `character varying` | NULL | `—` | `none / none` |
| `latest_supported_version` | `character varying` | NULL | `—` | `none / none` |
| `recommended_version` | `character varying` | NULL | `—` | `none / none` |
| `recommendation` | `text` | NULL | `—` | `none / none` |
| `source_name` | `character varying` | NULL | `—` | `none / none` |
| `source_url` | `character varying` | NULL | `—` | `none / none` |
| `evidence_json` | `json` | NULL | `—` | `none / none` |
| `confidence` | `character varying` | NULL | `—` | `none / none` |
| `checked_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `is_stale` | `boolean` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_component_lifecycle_cache` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_component_lifecycle_cache_identity` | u | `UNIQUE (normalized_name, normalized_version, ecosystem, purl)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_component_lifecycle_cache_checked_at` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_checked_at ON public.component_lifecycle_cache USING btree (checked_at)` |
| `ix_component_lifecycle_cache_cpe` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_cpe ON public.component_lifecycle_cache USING btree (cpe)` |
| `ix_component_lifecycle_cache_ecosystem` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_ecosystem ON public.component_lifecycle_cache USING btree (ecosystem)` |
| `ix_component_lifecycle_cache_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_expires_at ON public.component_lifecycle_cache USING btree (expires_at)` |
| `ix_component_lifecycle_cache_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_id ON public.component_lifecycle_cache USING btree (id)` |
| `ix_component_lifecycle_cache_lookup` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_lookup ON public.component_lifecycle_cache USING btree (ecosystem, normalized_name, normalized_version)` |
| `ix_component_lifecycle_cache_lookup_key` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_lookup_key ON public.component_lifecycle_cache USING btree (lookup_key)` |
| `ix_component_lifecycle_cache_normalized_name` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_normalized_name ON public.component_lifecycle_cache USING btree (normalized_name)` |
| `ix_component_lifecycle_cache_normalized_version` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_normalized_version ON public.component_lifecycle_cache USING btree (normalized_version)` |
| `ix_component_lifecycle_cache_purl` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_purl ON public.component_lifecycle_cache USING btree (purl)` |
| `pk_component_lifecycle_cache` | btree / True | `pk_component_lifecycle_cache` | True / True | `CREATE UNIQUE INDEX pk_component_lifecycle_cache ON public.component_lifecycle_cache USING btree (id)` |
| `uq_component_lifecycle_cache_identity` | btree / True | `uq_component_lifecycle_cache_identity` | True / True | `CREATE UNIQUE INDEX uq_component_lifecycle_cache_identity ON public.component_lifecycle_cache USING btree (normalized_name, normalized_version, ecosystem, purl)` |

### `public.component_lifecycle_override_audit`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.component_lifecycle_override_audit_id_seq'::regclass)` | `none / none` |
| `component_id` | `integer` | NOT NULL | `—` | `none / none` |
| `old_value_json` | `json` | NULL | `—` | `none / none` |
| `new_value_json` | `json` | NULL | `—` | `none / none` |
| `reason` | `text` | NOT NULL | `—` | `none / none` |
| `evidence_url` | `character varying` | NULL | `—` | `none / none` |
| `changed_by` | `character varying` | NULL | `—` | `none / none` |
| `changed_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_component_lifecycle_override_audit_component_id_sbom_794b` | f | `FOREIGN KEY (component_id) REFERENCES public.sbom_component(id) ON DELETE CASCADE` | True / False / False |
| `fk_component_lifecycle_override_audit_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_component_lifecycle_override_audit` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_component_lifecycle_override_audit_changed_at` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_override_audit_changed_at ON public.component_lifecycle_override_audit USING btree (changed_at)` |
| `ix_component_lifecycle_override_audit_changed_by` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_override_audit_changed_by ON public.component_lifecycle_override_audit USING btree (changed_by)` |
| `ix_component_lifecycle_override_audit_component_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_override_audit_component_id ON public.component_lifecycle_override_audit USING btree (component_id)` |
| `ix_component_lifecycle_override_audit_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_override_audit_id ON public.component_lifecycle_override_audit USING btree (id)` |
| `ix_component_lifecycle_override_audit_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_override_audit_tenant_id ON public.component_lifecycle_override_audit USING btree (tenant_id)` |
| `ix_component_lifecycle_override_audit_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_override_audit_tenant_identity ON public.component_lifecycle_override_audit USING btree (tenant_id, id)` |
| `pk_component_lifecycle_override_audit` | btree / True | `pk_component_lifecycle_override_audit` | True / True | `CREATE UNIQUE INDEX pk_component_lifecycle_override_audit ON public.component_lifecycle_override_audit USING btree (id)` |

### `public.cve_cache`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `cve_id` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `payload` | `json` | NOT NULL | `—` | `none / none` |
| `sources_used` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `fetched_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `fetch_error` | `text` | NULL | `—` | `none / none` |
| `schema_version` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_cve_cache` | p | `PRIMARY KEY (cve_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_cve_cache_cve_id` | btree / False | `none` | True / True | `CREATE INDEX ix_cve_cache_cve_id ON public.cve_cache USING btree (cve_id)` |
| `ix_cve_cache_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_cve_cache_expires_at ON public.cve_cache USING btree (expires_at)` |
| `pk_cve_cache` | btree / True | `pk_cve_cache` | True / True | `CREATE UNIQUE INDEX pk_cve_cache ON public.cve_cache USING btree (cve_id)` |

### `public.cves`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `cve_id` | `text` | NOT NULL | `—` | `none / none` |
| `last_modified` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `published` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `vuln_status` | `text` | NOT NULL | `—` | `none / none` |
| `description_en` | `text` | NULL | `—` | `none / none` |
| `score_v40` | `double precision` | NULL | `—` | `none / none` |
| `score_v31` | `double precision` | NULL | `—` | `none / none` |
| `score_v2` | `double precision` | NULL | `—` | `none / none` |
| `severity_text` | `character varying(32)` | NULL | `—` | `none / none` |
| `vector_string` | `text` | NULL | `—` | `none / none` |
| `aliases` | `jsonb` | NOT NULL | `—` | `none / none` |
| `cpe_match` | `jsonb` | NOT NULL | `—` | `none / none` |
| `references` | `jsonb` | NOT NULL | `—` | `none / none` |
| `data` | `jsonb` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `now()` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_cves` | p | `PRIMARY KEY (cve_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_cves_cpe_match_gin` | gin / False | `none` | True / True | `CREATE INDEX ix_cves_cpe_match_gin ON public.cves USING gin (cpe_match jsonb_path_ops)` |
| `ix_cves_last_modified` | btree / False | `none` | True / True | `CREATE INDEX ix_cves_last_modified ON public.cves USING btree (last_modified)` |
| `ix_cves_vuln_status` | btree / False | `none` | True / True | `CREATE INDEX ix_cves_vuln_status ON public.cves USING btree (vuln_status)` |
| `pk_cves` | btree / True | `pk_cves` | True / True | `CREATE UNIQUE INDEX pk_cves ON public.cves USING btree (cve_id)` |

### `public.email_verification_tokens`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.email_verification_tokens_id_seq'::regclass)` | `none / none` |
| `user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `token_hash` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `email_snapshot` | `character varying(320)` | NOT NULL | `—` | `none / none` |
| `expires_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `consumed_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `invalidated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `invalidation_reason` | `character varying(64)` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `created_by_ip_hash` | `character varying(64)` | NULL | `—` | `none / none` |
| `consumed_by_ip_hash` | `character varying(64)` | NULL | `—` | `none / none` |
| `correlation_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `delivery_status` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `delivery_attempted_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `delivery_error_code` | `character varying(64)` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_email_verification_tokens_ck_email_verification_toke_1c56` | c | `CHECK (consumed_at IS NULL OR consumed_at >= created_at)` | True / False / False |
| `ck_email_verification_tokens_ck_email_verification_toke_39e0` | c | `CHECK (delivery_status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_email_verification_tokens_ck_email_verification_toke_46d4` | c | `CHECK (expires_at > created_at)` | True / False / False |
| `ck_email_verification_tokens_ck_email_verification_toke_d99d` | c | `CHECK (invalidated_at IS NULL OR invalidated_at >= created_at)` | True / False / False |
| `fk_email_verification_tokens_user_id_iam_users` | f | `FOREIGN KEY (user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE` | True / False / False |
| `pk_email_verification_tokens` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_email_verification_tokens_token_hash` | u | `UNIQUE (token_hash)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_email_verification_tokens_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_email_verification_tokens_expires_at ON public.email_verification_tokens USING btree (expires_at)` |
| `ix_email_verification_tokens_user_consumed` | btree / False | `none` | True / True | `CREATE INDEX ix_email_verification_tokens_user_consumed ON public.email_verification_tokens USING btree (user_id, consumed_at)` |
| `ix_email_verification_tokens_user_created` | btree / False | `none` | True / True | `CREATE INDEX ix_email_verification_tokens_user_created ON public.email_verification_tokens USING btree (user_id, created_at)` |
| `ix_email_verification_tokens_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_email_verification_tokens_user_id ON public.email_verification_tokens USING btree (user_id)` |
| `pk_email_verification_tokens` | btree / True | `pk_email_verification_tokens` | True / True | `CREATE UNIQUE INDEX pk_email_verification_tokens ON public.email_verification_tokens USING btree (id)` |
| `uq_email_verification_tokens_active_user` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_email_verification_tokens_active_user ON public.email_verification_tokens USING btree (user_id) WHERE ((consumed_at IS NULL) AND (invalidated_at IS NULL))` |
| `uq_email_verification_tokens_token_hash` | btree / True | `uq_email_verification_tokens_token_hash` | True / True | `CREATE UNIQUE INDEX uq_email_verification_tokens_token_hash ON public.email_verification_tokens USING btree (token_hash)` |

### `public.epss_score`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `cve_id` | `character varying` | NOT NULL | `—` | `none / none` |
| `epss` | `double precision` | NOT NULL | `—` | `none / none` |
| `percentile` | `double precision` | NULL | `—` | `none / none` |
| `score_date` | `character varying` | NULL | `—` | `none / none` |
| `refreshed_at` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_epss_score` | p | `PRIMARY KEY (cve_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_epss_score_cve_id` | btree / False | `none` | True / True | `CREATE INDEX ix_epss_score_cve_id ON public.epss_score USING btree (cve_id)` |
| `pk_epss_score` | btree / True | `pk_epss_score` | True / True | `CREATE UNIQUE INDEX pk_epss_score ON public.epss_score USING btree (cve_id)` |

### `public.iam_users`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.iam_users_id_seq'::regclass)` | `none / none` |
| `external_iam_user_id` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `email` | `character varying(320)` | NULL | `—` | `none / none` |
| `display_name` | `character varying(255)` | NULL | `—` | `none / none` |
| `status` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `last_login_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `external_issuer` | `character varying(512)` | NULL | `—` | `none / none` |
| `external_subject` | `character varying(255)` | NULL | `—` | `none / none` |
| `employee_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `user_principal_name` | `character varying(320)` | NULL | `—` | `none / none` |
| `department` | `character varying(255)` | NULL | `—` | `none / none` |
| `email_verified` | `boolean` | NOT NULL | `false` | `none / none` |
| `email_verified_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `verification_required` | `boolean` | NOT NULL | `true` | `none / none` |
| `last_claim_sync_at` | `timestamp with time zone` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_iam_users_email_verification_timestamp` | c | `CHECK (email_verified = false OR email_verified_at IS NOT NULL)` | True / False / False |
| `ck_iam_users_external_issuer_not_blank` | c | `CHECK (external_issuer IS NULL OR length(TRIM(BOTH FROM external_issuer)) > 0)` | True / False / False |
| `ck_iam_users_external_subject_not_blank` | c | `CHECK (external_subject IS NULL OR length(TRIM(BOTH FROM external_subject)) > 0)` | True / False / False |
| `ck_iam_users_iam_user_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `pk_iam_users` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_iam_users_external_iam_user_id` | u | `UNIQUE (external_iam_user_id)` | True / False / False |
| `uq_iam_users_external_identity` | u | `UNIQUE (external_issuer, external_subject)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_iam_users_email` | btree / False | `none` | True / True | `CREATE INDEX ix_iam_users_email ON public.iam_users USING btree (email)` |
| `ix_iam_users_employee_id` | btree / False | `none` | True / True | `CREATE INDEX ix_iam_users_employee_id ON public.iam_users USING btree (employee_id)` |
| `ix_iam_users_external_iam_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_iam_users_external_iam_user_id ON public.iam_users USING btree (external_iam_user_id)` |
| `ix_iam_users_user_principal_name` | btree / False | `none` | True / True | `CREATE INDEX ix_iam_users_user_principal_name ON public.iam_users USING btree (user_principal_name)` |
| `ix_iam_users_verification_status` | btree / False | `none` | True / True | `CREATE INDEX ix_iam_users_verification_status ON public.iam_users USING btree (verification_required, status)` |
| `pk_iam_users` | btree / True | `pk_iam_users` | True / True | `CREATE UNIQUE INDEX pk_iam_users ON public.iam_users USING btree (id)` |
| `uq_iam_users_external_iam_user_id` | btree / True | `uq_iam_users_external_iam_user_id` | True / True | `CREATE UNIQUE INDEX uq_iam_users_external_iam_user_id ON public.iam_users USING btree (external_iam_user_id)` |
| `uq_iam_users_external_identity` | btree / True | `uq_iam_users_external_identity` | True / True | `CREATE UNIQUE INDEX uq_iam_users_external_identity ON public.iam_users USING btree (external_issuer, external_subject)` |

### `public.kev_entry`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `cve_id` | `character varying` | NOT NULL | `—` | `none / none` |
| `vendor_project` | `character varying` | NULL | `—` | `none / none` |
| `product` | `character varying` | NULL | `—` | `none / none` |
| `vulnerability_name` | `character varying` | NULL | `—` | `none / none` |
| `date_added` | `character varying` | NULL | `—` | `none / none` |
| `short_description` | `text` | NULL | `—` | `none / none` |
| `required_action` | `text` | NULL | `—` | `none / none` |
| `due_date` | `character varying` | NULL | `—` | `none / none` |
| `known_ransomware_use` | `character varying` | NULL | `—` | `none / none` |
| `refreshed_at` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_kev_entry` | p | `PRIMARY KEY (cve_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_kev_entry_cve_id` | btree / False | `none` | True / True | `CREATE INDEX ix_kev_entry_cve_id ON public.kev_entry USING btree (cve_id)` |
| `pk_kev_entry` | btree / True | `pk_kev_entry` | True / True | `CREATE UNIQUE INDEX pk_kev_entry ON public.kev_entry USING btree (cve_id)` |

### `public.kev_vulnerabilities`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `cve_id` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `vendor_project` | `character varying(255)` | NULL | `—` | `none / none` |
| `product` | `character varying(255)` | NULL | `—` | `none / none` |
| `vulnerability_name` | `text` | NULL | `—` | `none / none` |
| `date_added` | `character varying(10)` | NULL | `—` | `none / none` |
| `short_description` | `text` | NULL | `—` | `none / none` |
| `required_action` | `text` | NULL | `—` | `none / none` |
| `due_date` | `character varying(10)` | NULL | `—` | `none / none` |
| `known_ransomware_campaign_use` | `character varying(32)` | NULL | `—` | `none / none` |
| `notes` | `text` | NULL | `—` | `none / none` |
| `cwes` | `json` | NULL | `—` | `none / none` |
| `catalog_version` | `character varying(32)` | NULL | `—` | `none / none` |
| `catalog_date_released` | `character varying(64)` | NULL | `—` | `none / none` |
| `refreshed_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `first_seen_at` | `character varying` | NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_kev_vulnerabilities` | p | `PRIMARY KEY (cve_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_kev_vulnerabilities_cve_id` | btree / False | `none` | True / True | `CREATE INDEX ix_kev_vulnerabilities_cve_id ON public.kev_vulnerabilities USING btree (cve_id)` |
| `ix_kev_vulnerabilities_date_added` | btree / False | `none` | True / True | `CREATE INDEX ix_kev_vulnerabilities_date_added ON public.kev_vulnerabilities USING btree (date_added)` |
| `ix_kev_vulnerabilities_ransomware` | btree / False | `none` | True / True | `CREATE INDEX ix_kev_vulnerabilities_ransomware ON public.kev_vulnerabilities USING btree (known_ransomware_campaign_use)` |
| `pk_kev_vulnerabilities` | btree / True | `pk_kev_vulnerabilities` | True / True | `CREATE UNIQUE INDEX pk_kev_vulnerabilities ON public.kev_vulnerabilities USING btree (cve_id)` |

### `public.kombu_message`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `—` | `none / none` |
| `visible` | `boolean` | NULL | `—` | `none / none` |
| `timestamp` | `timestamp without time zone` | NULL | `—` | `none / none` |
| `payload` | `text` | NOT NULL | `—` | `none / none` |
| `version` | `smallint` | NOT NULL | `—` | `none / none` |
| `queue_id` | `integer` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `FK_kombu_message_queue` | f | `FOREIGN KEY (queue_id) REFERENCES public.kombu_queue(id)` | True / False / False |
| `kombu_message_pkey` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_kombu_message_timestamp` | btree / False | `none` | True / True | `CREATE INDEX ix_kombu_message_timestamp ON public.kombu_message USING btree ("timestamp")` |
| `ix_kombu_message_timestamp_id` | btree / False | `none` | True / True | `CREATE INDEX ix_kombu_message_timestamp_id ON public.kombu_message USING btree ("timestamp", id)` |
| `ix_kombu_message_visible` | btree / False | `none` | True / True | `CREATE INDEX ix_kombu_message_visible ON public.kombu_message USING btree (visible)` |
| `kombu_message_pkey` | btree / True | `kombu_message_pkey` | True / True | `CREATE UNIQUE INDEX kombu_message_pkey ON public.kombu_message USING btree (id)` |

### `public.kombu_queue`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `—` | `none / none` |
| `name` | `character varying(200)` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `kombu_queue_pkey` | p | `PRIMARY KEY (id)` | True / False / False |
| `kombu_queue_name_key` | u | `UNIQUE (name)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `kombu_queue_name_key` | btree / True | `kombu_queue_name_key` | True / True | `CREATE UNIQUE INDEX kombu_queue_name_key ON public.kombu_queue USING btree (name)` |
| `kombu_queue_pkey` | btree / True | `kombu_queue_pkey` | True / True | `CREATE UNIQUE INDEX kombu_queue_pkey ON public.kombu_queue USING btree (id)` |

### `public.lifecycle_provider_configs`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.lifecycle_provider_configs_id_seq'::regclass)` | `none / none` |
| `provider_key` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `display_name` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `provider_type` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `enabled` | `boolean` | NOT NULL | `—` | `none / none` |
| `priority` | `integer` | NOT NULL | `—` | `none / none` |
| `base_url` | `character varying(512)` | NULL | `—` | `none / none` |
| `feed_urls_json` | `json` | NULL | `—` | `none / none` |
| `config_json` | `json` | NULL | `—` | `none / none` |
| `timeout_seconds` | `integer` | NOT NULL | `—` | `none / none` |
| `max_retries` | `integer` | NOT NULL | `—` | `none / none` |
| `circuit_breaker_enabled` | `boolean` | NOT NULL | `—` | `none / none` |
| `cache_ttl_known_days` | `integer` | NULL | `—` | `none / none` |
| `cache_ttl_unknown_hours` | `integer` | NULL | `—` | `none / none` |
| `cache_ttl_failure_minutes` | `integer` | NULL | `—` | `none / none` |
| `cache_ttl_deprecated_days` | `integer` | NULL | `—` | `none / none` |
| `last_success_at` | `character varying` | NULL | `—` | `none / none` |
| `last_failure_at` | `character varying` | NULL | `—` | `none / none` |
| `last_failure_message` | `text` | NULL | `—` | `none / none` |
| `health_status` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_by_user_id` | `integer` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_lifecycle_provider_configs_ck_lifecycle_provider_con_1000` | c | `CHECK (max_retries >= 0 AND max_retries <= 10)` | True / False / False |
| `ck_lifecycle_provider_configs_ck_lifecycle_provider_con_5331` | c | `CHECK (timeout_seconds >= 1 AND timeout_seconds <= 60)` | True / False / False |
| `ck_lifecycle_provider_configs_ck_lifecycle_provider_con_a0a3` | c | `CHECK (health_status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_lifecycle_provider_configs_ck_lifecycle_provider_con_ef01` | c | `CHECK (priority >= 1 AND priority <= 1000)` | True / False / False |
| `fk_lifecycle_provider_configs_updated_by_user_id_iam_users` | f | `FOREIGN KEY (updated_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `pk_lifecycle_provider_configs` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_lifecycle_provider_configs_enabled_priority` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_configs_enabled_priority ON public.lifecycle_provider_configs USING btree (enabled, priority)` |
| `ix_lifecycle_provider_configs_health_status` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_configs_health_status ON public.lifecycle_provider_configs USING btree (health_status)` |
| `ix_lifecycle_provider_configs_id` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_configs_id ON public.lifecycle_provider_configs USING btree (id)` |
| `ix_lifecycle_provider_configs_provider_key` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX ix_lifecycle_provider_configs_provider_key ON public.lifecycle_provider_configs USING btree (provider_key)` |
| `ix_lifecycle_provider_configs_provider_type` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_configs_provider_type ON public.lifecycle_provider_configs USING btree (provider_type)` |
| `pk_lifecycle_provider_configs` | btree / True | `pk_lifecycle_provider_configs` | True / True | `CREATE UNIQUE INDEX pk_lifecycle_provider_configs ON public.lifecycle_provider_configs USING btree (id)` |

### `public.lifecycle_provider_secrets`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.lifecycle_provider_secrets_id_seq'::regclass)` | `none / none` |
| `provider_key` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `secret_name` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `encrypted_value` | `text` | NOT NULL | `—` | `none / none` |
| `value_preview` | `character varying(64)` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_by_user_id` | `integer` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_lifecycle_provider_secrets_updated_by_user_id_iam_users` | f | `FOREIGN KEY (updated_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `pk_lifecycle_provider_secrets` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_lifecycle_provider_secret_provider_name` | u | `UNIQUE (provider_key, secret_name)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_lifecycle_provider_secrets_id` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_secrets_id ON public.lifecycle_provider_secrets USING btree (id)` |
| `ix_lifecycle_provider_secrets_provider` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_secrets_provider ON public.lifecycle_provider_secrets USING btree (provider_key)` |
| `ix_lifecycle_provider_secrets_provider_key` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_secrets_provider_key ON public.lifecycle_provider_secrets USING btree (provider_key)` |
| `pk_lifecycle_provider_secrets` | btree / True | `pk_lifecycle_provider_secrets` | True / True | `CREATE UNIQUE INDEX pk_lifecycle_provider_secrets ON public.lifecycle_provider_secrets USING btree (id)` |
| `uq_lifecycle_provider_secret_provider_name` | btree / True | `uq_lifecycle_provider_secret_provider_name` | True / True | `CREATE UNIQUE INDEX uq_lifecycle_provider_secret_provider_name ON public.lifecycle_provider_secrets USING btree (provider_key, secret_name)` |

### `public.lifecycle_vendor_records`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.lifecycle_vendor_records_id_seq'::regclass)` | `none / none` |
| `vendor_name` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `product_name` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `product_aliases_json` | `json` | NULL | `—` | `none / none` |
| `ecosystem` | `character varying(64)` | NULL | `—` | `none / none` |
| `version_pattern` | `character varying(128)` | NULL | `—` | `none / none` |
| `version_start` | `character varying(64)` | NULL | `—` | `none / none` |
| `version_end` | `character varying(64)` | NULL | `—` | `none / none` |
| `lifecycle_status` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `maintenance_status` | `character varying(128)` | NULL | `—` | `none / none` |
| `eol_date` | `character varying` | NULL | `—` | `none / none` |
| `eos_date` | `character varying` | NULL | `—` | `none / none` |
| `eof_date` | `character varying` | NULL | `—` | `none / none` |
| `deprecated` | `boolean` | NOT NULL | `—` | `none / none` |
| `unsupported` | `boolean` | NOT NULL | `—` | `none / none` |
| `latest_supported_version` | `character varying(128)` | NULL | `—` | `none / none` |
| `recommended_version` | `character varying(128)` | NULL | `—` | `none / none` |
| `evidence_url` | `character varying(512)` | NULL | `—` | `none / none` |
| `evidence_json` | `json` | NULL | `—` | `none / none` |
| `confidence` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `enabled` | `boolean` | NOT NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_by_user_id` | `integer` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_lifecycle_vendor_records_updated_by_user_id_iam_users` | f | `FOREIGN KEY (updated_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `pk_lifecycle_vendor_records` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_lifecycle_vendor_records_ecosystem` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_vendor_records_ecosystem ON public.lifecycle_vendor_records USING btree (ecosystem)` |
| `ix_lifecycle_vendor_records_enabled` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_vendor_records_enabled ON public.lifecycle_vendor_records USING btree (enabled)` |
| `ix_lifecycle_vendor_records_id` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_vendor_records_id ON public.lifecycle_vendor_records USING btree (id)` |
| `ix_lifecycle_vendor_records_lookup` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_vendor_records_lookup ON public.lifecycle_vendor_records USING btree (enabled, ecosystem, product_name)` |
| `ix_lifecycle_vendor_records_product_name` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_vendor_records_product_name ON public.lifecycle_vendor_records USING btree (product_name)` |
| `ix_lifecycle_vendor_records_vendor_name` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_vendor_records_vendor_name ON public.lifecycle_vendor_records USING btree (vendor_name)` |
| `pk_lifecycle_vendor_records` | btree / True | `pk_lifecycle_vendor_records` | True / True | `CREATE UNIQUE INDEX pk_lifecycle_vendor_records ON public.lifecycle_vendor_records USING btree (id)` |

### `public.nvd_lookup_cache`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.nvd_lookup_cache_id_seq'::regclass)` | `none / none` |
| `lookup_type` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `identifier` | `character varying(2048)` | NOT NULL | `—` | `none / none` |
| `identifier_hash` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `response_json` | `json` | NULL | `—` | `none / none` |
| `http_status` | `integer` | NULL | `—` | `none / none` |
| `error_message` | `text` | NULL | `—` | `none / none` |
| `checked_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_nvd_lookup_cache` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_nvd_lookup_cache_type_hash` | u | `UNIQUE (lookup_type, identifier_hash)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_nvd_lookup_cache_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_nvd_lookup_cache_expires_at ON public.nvd_lookup_cache USING btree (expires_at)` |
| `ix_nvd_lookup_cache_identifier` | btree / False | `none` | True / True | `CREATE INDEX ix_nvd_lookup_cache_identifier ON public.nvd_lookup_cache USING btree (identifier)` |
| `ix_nvd_lookup_cache_status` | btree / False | `none` | True / True | `CREATE INDEX ix_nvd_lookup_cache_status ON public.nvd_lookup_cache USING btree (status)` |
| `pk_nvd_lookup_cache` | btree / True | `pk_nvd_lookup_cache` | True / True | `CREATE UNIQUE INDEX pk_nvd_lookup_cache ON public.nvd_lookup_cache USING btree (id)` |
| `uq_nvd_lookup_cache_type_hash` | btree / True | `uq_nvd_lookup_cache_type_hash` | True / True | `CREATE UNIQUE INDEX uq_nvd_lookup_cache_type_hash ON public.nvd_lookup_cache USING btree (lookup_type, identifier_hash)` |

### `public.nvd_settings`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.nvd_settings_id_seq'::regclass)` | `none / none` |
| `enabled` | `boolean` | NOT NULL | `—` | `none / none` |
| `api_endpoint` | `text` | NOT NULL | `—` | `none / none` |
| `api_key_ciphertext` | `bytea` | NULL | `—` | `none / none` |
| `download_feeds_enabled` | `boolean` | NOT NULL | `—` | `none / none` |
| `page_size` | `integer` | NOT NULL | `—` | `none / none` |
| `window_days` | `integer` | NOT NULL | `—` | `none / none` |
| `min_freshness_hours` | `integer` | NOT NULL | `—` | `none / none` |
| `last_modified_utc` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `last_successful_sync_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `now()` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `now()` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_nvd_settings_ck_nvd_settings_min_freshness_nonneg` | c | `CHECK (min_freshness_hours >= 0)` | True / False / False |
| `ck_nvd_settings_ck_nvd_settings_page_size_range` | c | `CHECK (page_size >= 1 AND page_size <= 2000)` | True / False / False |
| `ck_nvd_settings_ck_nvd_settings_singleton` | c | `CHECK (id = 1)` | True / False / False |
| `ck_nvd_settings_ck_nvd_settings_window_days_range` | c | `CHECK (window_days >= 1 AND window_days <= 119)` | True / False / False |
| `pk_nvd_settings` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `pk_nvd_settings` | btree / True | `pk_nvd_settings` | True / True | `CREATE UNIQUE INDEX pk_nvd_settings ON public.nvd_settings USING btree (id)` |

### `public.nvd_sync_runs`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `bigint` | NOT NULL | `nextval('public.nvd_sync_runs_id_seq'::regclass)` | `none / none` |
| `run_kind` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `window_start` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `window_end` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `started_at` | `timestamp with time zone` | NOT NULL | `now()` | `none / none` |
| `finished_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `status` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `upserted_count` | `integer` | NOT NULL | `—` | `none / none` |
| `error_message` | `text` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_nvd_sync_runs_ck_nvd_sync_runs_kind` | c | `CHECK (run_kind::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_nvd_sync_runs_ck_nvd_sync_runs_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `pk_nvd_sync_runs` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_nvd_sync_runs_started_at` | btree / False | `none` | True / True | `CREATE INDEX ix_nvd_sync_runs_started_at ON public.nvd_sync_runs USING btree (started_at)` |
| `pk_nvd_sync_runs` | btree / True | `pk_nvd_sync_runs` | True / True | `CREATE UNIQUE INDEX pk_nvd_sync_runs ON public.nvd_sync_runs USING btree (id)` |

### `public.platform_user_roles`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.platform_user_roles_id_seq'::regclass)` | `none / none` |
| `user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `role` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `created_by_user_id` | `integer` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_platform_user_roles_ck_platform_user_roles_platform__3fb3` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_platform_user_roles_ck_platform_user_roles_platform__984b` | c | `CHECK (role::text = '<literal redacted>'::text)` | True / False / False |
| `fk_platform_user_roles_created_by_user_id_iam_users` | f | `FOREIGN KEY (created_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_platform_user_roles_user_id_iam_users` | f | `FOREIGN KEY (user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE` | True / False / False |
| `pk_platform_user_roles` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_platform_user_roles_user_id` | u | `UNIQUE (user_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_platform_user_roles_status` | btree / False | `none` | True / True | `CREATE INDEX ix_platform_user_roles_status ON public.platform_user_roles USING btree (status)` |
| `ix_platform_user_roles_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_platform_user_roles_user_id ON public.platform_user_roles USING btree (user_id)` |
| `pk_platform_user_roles` | btree / True | `pk_platform_user_roles` | True / True | `CREATE UNIQUE INDEX pk_platform_user_roles ON public.platform_user_roles USING btree (id)` |
| `uq_platform_user_roles_user_id` | btree / True | `uq_platform_user_roles_user_id` | True / True | `CREATE UNIQUE INDEX uq_platform_user_roles_user_id ON public.platform_user_roles USING btree (user_id)` |

### `public.products`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.products_id_seq'::regclass)` | `none / none` |
| `project_id` | `integer` | NOT NULL | `—` | `none / none` |
| `name` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `normalized_name` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `slug` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `description` | `text` | NULL | `—` | `none / none` |
| `product_key` | `character varying(128)` | NULL | `—` | `none / none` |
| `vendor` | `character varying(255)` | NULL | `—` | `none / none` |
| `category` | `character varying(128)` | NULL | `—` | `none / none` |
| `status` | `character varying(32)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `latest_version` | `character varying(128)` | NULL | `—` | `none / none` |
| `metadata_json` | `json` | NULL | `—` | `none / none` |
| `created_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NULL | `—` | `none / none` |
| `deleted_at` | `character varying` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `current_sbom_id` | `integer` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_products_current_sbom_id_sbom_source` | f | `FOREIGN KEY (current_sbom_id) REFERENCES public.sbom_source(id) ON DELETE SET NULL` | True / False / False |
| `fk_products_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE` | True / False / False |
| `fk_products_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_products` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_products_tenant_project_slug` | u | `UNIQUE (tenant_id, project_id, slug)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_products_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_products_created_at ON public.products USING btree (created_at)` |
| `ix_products_created_by` | btree / False | `none` | True / True | `CREATE INDEX ix_products_created_by ON public.products USING btree (created_by)` |
| `ix_products_current_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_products_current_sbom_id ON public.products USING btree (current_sbom_id)` |
| `ix_products_deleted_at` | btree / False | `none` | True / True | `CREATE INDEX ix_products_deleted_at ON public.products USING btree (deleted_at)` |
| `ix_products_id` | btree / False | `none` | True / True | `CREATE INDEX ix_products_id ON public.products USING btree (id)` |
| `ix_products_product_key` | btree / False | `none` | True / True | `CREATE INDEX ix_products_product_key ON public.products USING btree (product_key)` |
| `ix_products_project_id` | btree / False | `none` | True / True | `CREATE INDEX ix_products_project_id ON public.products USING btree (project_id)` |
| `ix_products_status` | btree / False | `none` | True / True | `CREATE INDEX ix_products_status ON public.products USING btree (status)` |
| `ix_products_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_products_tenant_id ON public.products USING btree (tenant_id)` |
| `ix_products_tenant_project` | btree / False | `none` | True / True | `CREATE INDEX ix_products_tenant_project ON public.products USING btree (tenant_id, project_id)` |
| `ix_products_tenant_project_name` | btree / False | `none` | True / True | `CREATE INDEX ix_products_tenant_project_name ON public.products USING btree (tenant_id, project_id, normalized_name)` |
| `pk_products` | btree / True | `pk_products` | True / True | `CREATE UNIQUE INDEX pk_products ON public.products USING btree (id)` |
| `uq_products_tenant_project_slug` | btree / True | `uq_products_tenant_project_slug` | True / True | `CREATE UNIQUE INDEX uq_products_tenant_project_slug ON public.products USING btree (tenant_id, project_id, slug)` |

### `public.projects`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.projects_id_seq'::regclass)` | `none / none` |
| `project_name` | `character varying` | NOT NULL | `—` | `none / none` |
| `project_details` | `character varying` | NULL | `—` | `none / none` |
| `project_status` | `integer` | NOT NULL | `—` | `none / none` |
| `created_on` | `character varying` | NULL | `—` | `none / none` |
| `created_by` | `character varying` | NULL | `—` | `none / none` |
| `modified_on` | `character varying` | NULL | `—` | `none / none` |
| `modified_by` | `character varying` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_projects_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_projects` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_projects_tenant_name` | u | `UNIQUE (tenant_id, project_name)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_projects_created_by` | btree / False | `none` | True / True | `CREATE INDEX ix_projects_created_by ON public.projects USING btree (created_by)` |
| `ix_projects_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_projects_deactivated ON public.projects USING btree (is_active) WHERE (is_active = false)` |
| `ix_projects_id` | btree / False | `none` | True / True | `CREATE INDEX ix_projects_id ON public.projects USING btree (id)` |
| `ix_projects_project_name` | btree / False | `none` | True / True | `CREATE INDEX ix_projects_project_name ON public.projects USING btree (project_name)` |
| `ix_projects_tenant_created` | btree / False | `none` | True / True | `CREATE INDEX ix_projects_tenant_created ON public.projects USING btree (tenant_id, created_on)` |
| `ix_projects_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_projects_tenant_id ON public.projects USING btree (tenant_id)` |
| `ix_projects_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_projects_tenant_identity ON public.projects USING btree (tenant_id, id)` |
| `pk_projects` | btree / True | `pk_projects` | True / True | `CREATE UNIQUE INDEX pk_projects ON public.projects USING btree (id)` |
| `uq_projects_tenant_name` | btree / True | `uq_projects_tenant_name` | True / True | `CREATE UNIQUE INDEX uq_projects_tenant_name ON public.projects USING btree (tenant_id, project_name)` |

### `public.report_artifact`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.report_artifact_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `delivery_id` | `integer` | NOT NULL | `—` | `none / none` |
| `kind` | `character varying(8)` | NOT NULL | `—` | `none / none` |
| `filename` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `media_type` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `size_bytes` | `integer` | NOT NULL | `—` | `none / none` |
| `sha256` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `storage_path` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `created_on` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_report_artifact_report_artifact_kind` | c | `CHECK (kind::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `fk_report_artifact_delivery_id_report_delivery` | f | `FOREIGN KEY (delivery_id) REFERENCES public.report_delivery(id) ON DELETE CASCADE` | True / False / False |
| `fk_report_artifact_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_report_artifact` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_report_artifact_delivery_id` | btree / False | `none` | True / True | `CREATE INDEX ix_report_artifact_delivery_id ON public.report_artifact USING btree (delivery_id)` |
| `ix_report_artifact_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_report_artifact_expires_at ON public.report_artifact USING btree (expires_at)` |
| `ix_report_artifact_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_report_artifact_tenant_id ON public.report_artifact USING btree (tenant_id)` |
| `pk_report_artifact` | btree / True | `pk_report_artifact` | True / True | `CREATE UNIQUE INDEX pk_report_artifact ON public.report_artifact USING btree (id)` |

### `public.report_delivery`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.report_delivery_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `subscription_id` | `integer` | NOT NULL | `—` | `none / none` |
| `cycle_start` | `character varying` | NOT NULL | `—` | `none / none` |
| `cycle_end` | `character varying` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `error_code` | `character varying(64)` | NULL | `—` | `none / none` |
| `attempt_count` | `integer` | NOT NULL | `0` | `none / none` |
| `recipient_email` | `character varying(320)` | NULL | `—` | `none / none` |
| `sbom_count` | `integer` | NOT NULL | `0` | `none / none` |
| `run_count` | `integer` | NOT NULL | `0` | `none / none` |
| `artifact_ids` | `json` | NOT NULL | `—` | `none / none` |
| `payload` | `json` | NOT NULL | `—` | `none / none` |
| `attempts` | `json` | NOT NULL | `—` | `none / none` |
| `next_attempt_at` | `character varying` | NULL | `—` | `none / none` |
| `claimed_at` | `character varying` | NULL | `—` | `none / none` |
| `dispatch_started_at` | `character varying` | NULL | `—` | `none / none` |
| `sent_at` | `character varying` | NULL | `—` | `none / none` |
| `created_on` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_report_delivery_report_delivery_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `fk_report_delivery_subscription_id_report_subscription` | f | `FOREIGN KEY (subscription_id) REFERENCES public.report_subscription(id) ON DELETE CASCADE` | True / False / False |
| `fk_report_delivery_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_report_delivery` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_report_delivery_cycle` | u | `UNIQUE (subscription_id, cycle_start, cycle_end)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_report_delivery_status` | btree / False | `none` | True / True | `CREATE INDEX ix_report_delivery_status ON public.report_delivery USING btree (status)` |
| `ix_report_delivery_subscription_id` | btree / False | `none` | True / True | `CREATE INDEX ix_report_delivery_subscription_id ON public.report_delivery USING btree (subscription_id)` |
| `ix_report_delivery_tenant_dispatch` | btree / False | `none` | True / True | `CREATE INDEX ix_report_delivery_tenant_dispatch ON public.report_delivery USING btree (tenant_id, dispatch_started_at)` |
| `ix_report_delivery_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_report_delivery_tenant_id ON public.report_delivery USING btree (tenant_id)` |
| `pk_report_delivery` | btree / True | `pk_report_delivery` | True / True | `CREATE UNIQUE INDEX pk_report_delivery ON public.report_delivery USING btree (id)` |
| `uq_report_delivery_cycle` | btree / True | `uq_report_delivery_cycle` | True / True | `CREATE UNIQUE INDEX uq_report_delivery_cycle ON public.report_delivery USING btree (subscription_id, cycle_start, cycle_end)` |

### `public.report_subscription`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.report_subscription_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `iam_user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `scope` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `project_id` | `integer` | NULL | `—` | `none / none` |
| `product_id` | `integer` | NULL | `—` | `none / none` |
| `sbom_id` | `integer` | NULL | `—` | `none / none` |
| `cadence` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `parts` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `formats` | `character varying(32)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `severity_floor` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `baseline_mode` | `character varying(32)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `cross_version_target` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `timezone` | `character varying(64)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `suppress_when_unchanged` | `boolean` | NOT NULL | `false` | `none / none` |
| `enabled` | `boolean` | NOT NULL | `true` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying` | NULL | `—` | `none / none` |
| `last_delivered_at` | `character varying` | NULL | `—` | `none / none` |
| `created_on` | `character varying` | NOT NULL | `—` | `none / none` |
| `created_by` | `character varying` | NULL | `—` | `none / none` |
| `modified_on` | `character varying` | NULL | `—` | `none / none` |
| `modified_by` | `character varying` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_report_subscription_report_cadence` | c | `CHECK (cadence::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_report_subscription_report_scope` | c | `CHECK (scope::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_report_subscription_report_severity` | c | `CHECK (severity_floor::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_report_subscription_report_target` | c | `CHECK (scope::text = '<literal redacted>'::text AND project_id IS NULL AND product_id IS NULL AND sbom_id IS NULL OR scope::text = '<literal redacted>'::text AND project_id IS NOT NULL AND product_id IS NULL AND sbom_id IS NULL OR scope::text = '<literal redacted>'::text AND product_id IS NOT NULL AND project_id IS NULL AND sbom_id IS NULL OR scope::text = '<literal redacted>'::text AND sbom_id IS NOT NULL AND project_id IS NULL AND product_id IS NULL)` | True / False / False |
| `fk_report_subscription_iam_user_id_iam_users` | f | `FOREIGN KEY (iam_user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE` | True / False / False |
| `fk_report_subscription_product_id_products` | f | `FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE CASCADE` | True / False / False |
| `fk_report_subscription_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE` | True / False / False |
| `fk_report_subscription_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE CASCADE` | True / False / False |
| `fk_report_subscription_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_report_subscription` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_report_subscription_iam_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_report_subscription_iam_user_id ON public.report_subscription USING btree (iam_user_id)` |
| `ix_report_subscription_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_report_subscription_tenant_id ON public.report_subscription USING btree (tenant_id)` |
| `pk_report_subscription` | btree / True | `pk_report_subscription` | True / True | `CREATE UNIQUE INDEX pk_report_subscription ON public.report_subscription USING btree (id)` |
| `uq_report_subscription_product` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_report_subscription_product ON public.report_subscription USING btree (tenant_id, iam_user_id, product_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |
| `uq_report_subscription_project` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_report_subscription_project ON public.report_subscription USING btree (tenant_id, iam_user_id, project_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |
| `uq_report_subscription_sbom` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_report_subscription_sbom ON public.report_subscription USING btree (tenant_id, iam_user_id, sbom_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |
| `uq_report_subscription_tenant` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_report_subscription_tenant ON public.report_subscription USING btree (tenant_id, iam_user_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |

### `public.run_cache`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.run_cache_id_seq'::regclass)` | `none / none` |
| `run_json` | `text` | NOT NULL | `—` | `none / none` |
| `created_on` | `character varying` | NULL | `—` | `none / none` |
| `source` | `character varying` | NULL | `—` | `none / none` |
| `sbom_id` | `integer` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_run_cache_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_run_cache` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_run_cache_id` | btree / False | `none` | True / True | `CREATE INDEX ix_run_cache_id ON public.run_cache USING btree (id)` |
| `ix_run_cache_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_run_cache_tenant_id ON public.run_cache USING btree (tenant_id)` |
| `ix_run_cache_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_run_cache_tenant_identity ON public.run_cache USING btree (tenant_id, id)` |
| `pk_run_cache` | btree / True | `pk_run_cache` | True / True | `CREATE UNIQUE INDEX pk_run_cache ON public.run_cache USING btree (id)` |

### `public.sbom_analysis_report`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.sbom_analysis_report_id_seq'::regclass)` | `none / none` |
| `sbom_ref_id` | `integer` | NULL | `—` | `none / none` |
| `sbom_result` | `character varying` | NULL | `—` | `none / none` |
| `project_id` | `character varying` | NULL | `—` | `none / none` |
| `created_on` | `character varying` | NULL | `—` | `none / none` |
| `analysis_details` | `text` | NULL | `—` | `none / none` |
| `reference_source` | `character varying` | NULL | `—` | `none / none` |
| `sbom_analysis_level` | `integer` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_sbom_analysis_report_sbom_ref_id_sbom_source` | f | `FOREIGN KEY (sbom_ref_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_sbom_analysis_report_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_sbom_analysis_report` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_sbom_analysis_report_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_analysis_report_deactivated ON public.sbom_analysis_report USING btree (is_active) WHERE (is_active = false)` |
| `ix_sbom_analysis_report_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_analysis_report_id ON public.sbom_analysis_report USING btree (id)` |
| `ix_sbom_analysis_report_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_analysis_report_tenant_id ON public.sbom_analysis_report USING btree (tenant_id)` |
| `ix_sbom_analysis_report_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_analysis_report_tenant_identity ON public.sbom_analysis_report USING btree (tenant_id, id)` |
| `pk_sbom_analysis_report` | btree / True | `pk_sbom_analysis_report` | True / True | `CREATE UNIQUE INDEX pk_sbom_analysis_report ON public.sbom_analysis_report USING btree (id)` |

### `public.sbom_component`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.sbom_component_id_seq'::regclass)` | `none / none` |
| `sbom_id` | `integer` | NOT NULL | `—` | `none / none` |
| `bom_ref` | `character varying` | NULL | `—` | `none / none` |
| `component_type` | `character varying` | NULL | `—` | `none / none` |
| `component_group` | `character varying` | NULL | `—` | `none / none` |
| `name` | `character varying` | NOT NULL | `—` | `none / none` |
| `version` | `character varying` | NULL | `—` | `none / none` |
| `purl` | `character varying` | NULL | `—` | `none / none` |
| `cpe` | `character varying` | NULL | `—` | `none / none` |
| `cpe_source` | `character varying(32)` | NULL | `—` | `none / none` |
| `supplier` | `character varying` | NULL | `—` | `none / none` |
| `scope` | `character varying` | NULL | `—` | `none / none` |
| `created_on` | `character varying` | NULL | `—` | `none / none` |
| `ecosystem` | `character varying` | NULL | `—` | `none / none` |
| `original_name` | `character varying` | NULL | `—` | `none / none` |
| `normalized_name` | `character varying` | NULL | `—` | `none / none` |
| `original_version` | `character varying` | NULL | `—` | `none / none` |
| `normalized_version` | `character varying` | NULL | `—` | `none / none` |
| `normalized_ecosystem` | `character varying` | NULL | `—` | `none / none` |
| `original_purl` | `character varying` | NULL | `—` | `none / none` |
| `normalized_purl` | `character varying` | NULL | `—` | `none / none` |
| `purl_type` | `character varying` | NULL | `—` | `none / none` |
| `purl_namespace` | `character varying` | NULL | `—` | `none / none` |
| `purl_name` | `character varying` | NULL | `—` | `none / none` |
| `purl_version` | `character varying` | NULL | `—` | `none / none` |
| `purl_qualifiers_json` | `json` | NULL | `—` | `none / none` |
| `purl_subpath` | `character varying` | NULL | `—` | `none / none` |
| `normalized_cpes` | `json` | NULL | `—` | `none / none` |
| `primary_cpe` | `character varying` | NULL | `—` | `none / none` |
| `cpe_evidence_json` | `json` | NULL | `—` | `none / none` |
| `normalized_supplier` | `character varying` | NULL | `—` | `none / none` |
| `normalized_package_key` | `character varying` | NULL | `—` | `none / none` |
| `canonical_identity_confidence` | `character varying` | NULL | `—` | `none / none` |
| `license` | `character varying` | NULL | `—` | `none / none` |
| `hashes` | `text` | NULL | `—` | `none / none` |
| `lifecycle_status` | `character varying` | NULL | `—` | `none / none` |
| `eos_date` | `character varying` | NULL | `—` | `none / none` |
| `eol_date` | `character varying` | NULL | `—` | `none / none` |
| `eof_date` | `character varying` | NULL | `—` | `none / none` |
| `is_deprecated` | `boolean` | NULL | `—` | `none / none` |
| `deprecated` | `boolean` | NULL | `—` | `none / none` |
| `unsupported` | `boolean` | NULL | `—` | `none / none` |
| `maintenance_status` | `character varying` | NULL | `—` | `none / none` |
| `latest_version` | `character varying` | NULL | `—` | `none / none` |
| `latest_supported_version` | `character varying` | NULL | `—` | `none / none` |
| `recommended_version` | `character varying` | NULL | `—` | `none / none` |
| `lifecycle_recommendation` | `text` | NULL | `—` | `none / none` |
| `lifecycle_source` | `character varying` | NULL | `—` | `none / none` |
| `lifecycle_source_url` | `character varying` | NULL | `—` | `none / none` |
| `lifecycle_confidence` | `character varying` | NULL | `—` | `none / none` |
| `lifecycle_checked_at` | `character varying` | NULL | `—` | `none / none` |
| `lifecycle_evidence_json` | `json` | NULL | `—` | `none / none` |
| `lifecycle_is_stale` | `boolean` | NOT NULL | `—` | `none / none` |
| `lifecycle_manual_override` | `boolean` | NOT NULL | `—` | `none / none` |
| `normalized_component_key` | `character varying` | NULL | `—` | `none / none` |
| `dedupe_canonical_id` | `character varying` | NULL | `—` | `none / none` |
| `dedupe_group_id` | `character varying` | NULL | `—` | `none / none` |
| `is_duplicate` | `boolean` | NOT NULL | `—` | `none / none` |
| `duplicate_of_component_id` | `integer` | NULL | `—` | `none / none` |
| `dedupe_reason` | `character varying` | NULL | `—` | `none / none` |
| `dedupe_confidence` | `character varying` | NULL | `—` | `none / none` |
| `normalization_notes_json` | `json` | NULL | `—` | `none / none` |
| `dedupe_evidence_json` | `json` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_sbom_component_duplicate_of_component_id_sbom_component` | f | `FOREIGN KEY (duplicate_of_component_id) REFERENCES public.sbom_component(id) ON DELETE CASCADE` | True / False / False |
| `fk_sbom_component_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_sbom_component_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_sbom_component` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_sbom_component_fingerprint` | u | `UNIQUE (tenant_id, sbom_id, bom_ref, name, version, cpe)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_sbom_component_bom_ref` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_bom_ref ON public.sbom_component USING btree (bom_ref)` |
| `ix_sbom_component_cpe` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_cpe ON public.sbom_component USING btree (cpe)` |
| `ix_sbom_component_cpe_source` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_cpe_source ON public.sbom_component USING btree (cpe_source)` |
| `ix_sbom_component_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_deactivated ON public.sbom_component USING btree (is_active) WHERE (is_active = false)` |
| `ix_sbom_component_dedupe_canonical_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_dedupe_canonical_id ON public.sbom_component USING btree (dedupe_canonical_id)` |
| `ix_sbom_component_dedupe_group_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_dedupe_group_id ON public.sbom_component USING btree (dedupe_group_id)` |
| `ix_sbom_component_duplicate_of_component_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_duplicate_of_component_id ON public.sbom_component USING btree (duplicate_of_component_id)` |
| `ix_sbom_component_ecosystem` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_ecosystem ON public.sbom_component USING btree (ecosystem)` |
| `ix_sbom_component_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_id ON public.sbom_component USING btree (id)` |
| `ix_sbom_component_lifecycle` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_lifecycle ON public.sbom_component USING btree (lifecycle_status, ecosystem)` |
| `ix_sbom_component_lifecycle_checked_at` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_lifecycle_checked_at ON public.sbom_component USING btree (lifecycle_checked_at)` |
| `ix_sbom_component_name` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_name ON public.sbom_component USING btree (name)` |
| `ix_sbom_component_normalized_component_key` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_normalized_component_key ON public.sbom_component USING btree (normalized_component_key)` |
| `ix_sbom_component_normalized_ecosystem` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_normalized_ecosystem ON public.sbom_component USING btree (normalized_ecosystem)` |
| `ix_sbom_component_normalized_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_normalized_identity ON public.sbom_component USING btree (normalized_ecosystem, normalized_name, normalized_version)` |
| `ix_sbom_component_normalized_name` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_normalized_name ON public.sbom_component USING btree (normalized_name)` |
| `ix_sbom_component_normalized_package_key` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_normalized_package_key ON public.sbom_component USING btree (normalized_package_key)` |
| `ix_sbom_component_normalized_purl` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_normalized_purl ON public.sbom_component USING btree (normalized_purl)` |
| `ix_sbom_component_normalized_version` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_normalized_version ON public.sbom_component USING btree (normalized_version)` |
| `ix_sbom_component_primary_cpe` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_primary_cpe ON public.sbom_component USING btree (primary_cpe)` |
| `ix_sbom_component_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_sbom_id ON public.sbom_component USING btree (sbom_id)` |
| `ix_sbom_component_sbom_is_duplicate` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_sbom_is_duplicate ON public.sbom_component USING btree (sbom_id, is_duplicate)` |
| `ix_sbom_component_sbom_name` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_sbom_name ON public.sbom_component USING btree (sbom_id, name)` |
| `ix_sbom_component_sbom_normalized_key` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_sbom_normalized_key ON public.sbom_component USING btree (sbom_id, normalized_component_key)` |
| `ix_sbom_component_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_tenant_id ON public.sbom_component USING btree (tenant_id)` |
| `ix_sbom_component_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_tenant_identity ON public.sbom_component USING btree (tenant_id, id)` |
| `ix_sbom_component_version` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_version ON public.sbom_component USING btree (version)` |
| `pk_sbom_component` | btree / True | `pk_sbom_component` | True / True | `CREATE UNIQUE INDEX pk_sbom_component ON public.sbom_component USING btree (id)` |
| `uq_sbom_component_fingerprint` | btree / True | `uq_sbom_component_fingerprint` | True / True | `CREATE UNIQUE INDEX uq_sbom_component_fingerprint ON public.sbom_component USING btree (tenant_id, sbom_id, bom_ref, name, version, cpe)` |

### `public.sbom_source`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.sbom_source_id_seq'::regclass)` | `none / none` |
| `sbom_name` | `character varying` | NOT NULL | `—` | `none / none` |
| `sbom_data` | `text` | NULL | `—` | `none / none` |
| `sbom_type` | `integer` | NULL | `—` | `none / none` |
| `projectid` | `integer` | NULL | `—` | `none / none` |
| `product_id` | `integer` | NULL | `—` | `none / none` |
| `created_on` | `character varying` | NULL | `—` | `none / none` |
| `sbom_version` | `character varying` | NULL | `—` | `none / none` |
| `created_by` | `character varying` | NULL | `—` | `none / none` |
| `productver` | `character varying` | NULL | `—` | `none / none` |
| `modified_on` | `character varying` | NULL | `—` | `none / none` |
| `modified_by` | `character varying` | NULL | `—` | `none / none` |
| `parent_id` | `integer` | NULL | `—` | `none / none` |
| `change_summary` | `character varying` | NULL | `—` | `none / none` |
| `completeness_score` | `double precision` | NULL | `—` | `none / none` |
| `completeness_report` | `json` | NULL | `—` | `none / none` |
| `dedupe_report_json` | `json` | NULL | `—` | `none / none` |
| `product_name` | `character varying` | NULL | `—` | `none / none` |
| `description` | `character varying` | NULL | `—` | `none / none` |
| `status` | `character varying(24)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `failed_stage` | `character varying(32)` | NULL | `—` | `none / none` |
| `validation_errors` | `json` | NULL | `—` | `none / none` |
| `error_count` | `integer` | NOT NULL | `0` | `none / none` |
| `warning_count` | `integer` | NOT NULL | `0` | `none / none` |
| `validated_at` | `character varying` | NULL | `—` | `none / none` |
| `original_format` | `character varying(32)` | NULL | `—` | `none / none` |
| `current_format` | `character varying(32)` | NULL | `—` | `none / none` |
| `converted_from_format` | `character varying(32)` | NULL | `—` | `none / none` |
| `source_sbom_id` | `integer` | NULL | `—` | `none / none` |
| `converted_sbom_id` | `integer` | NULL | `—` | `none / none` |
| `conversion_status` | `character varying(32)` | NULL | `—` | `none / none` |
| `conversion_warnings_json` | `json` | NULL | `—` | `none / none` |
| `conversion_report_json` | `json` | NULL | `—` | `none / none` |
| `converted_at` | `character varying` | NULL | `—` | `none / none` |
| `converted_by` | `character varying` | NULL | `—` | `none / none` |
| `enrichment_status` | `character varying(32)` | NULL | `—` | `none / none` |
| `conversion_started_at` | `character varying` | NULL | `—` | `none / none` |
| `conversion_completed_at` | `character varying` | NULL | `—` | `none / none` |
| `enrichment_started_at` | `character varying` | NULL | `—` | `none / none` |
| `enrichment_completed_at` | `character varying` | NULL | `—` | `none / none` |
| `conversion_error` | `text` | NULL | `—` | `none / none` |
| `enrichment_error` | `text` | NULL | `—` | `none / none` |
| `component_extraction_status` | `character varying(32)` | NULL | `—` | `none / none` |
| `component_extraction_error` | `text` | NULL | `—` | `none / none` |
| `component_extraction_attempted_at` | `character varying` | NULL | `—` | `none / none` |
| `component_extraction_completed_at` | `character varying` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_sbom_source_converted_sbom_id_sbom_source` | f | `FOREIGN KEY (converted_sbom_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_sbom_source_parent_id_sbom_source` | f | `FOREIGN KEY (parent_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_sbom_source_product_id_products` | f | `FOREIGN KEY (product_id) REFERENCES public.products(id)` | True / False / False |
| `fk_sbom_source_projectid_projects` | f | `FOREIGN KEY (projectid) REFERENCES public.projects(id)` | True / False / False |
| `fk_sbom_source_sbom_type_sbom_type` | f | `FOREIGN KEY (sbom_type) REFERENCES public.sbom_type(id)` | True / False / False |
| `fk_sbom_source_source_sbom_id_sbom_source` | f | `FOREIGN KEY (source_sbom_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_sbom_source_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_sbom_source` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_sbom_source_tenant_name_version` | u | `UNIQUE (tenant_id, sbom_name, sbom_version)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_sbom_source_component_extraction_status` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_component_extraction_status ON public.sbom_source USING btree (component_extraction_status)` |
| `ix_sbom_source_conversion_status` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_conversion_status ON public.sbom_source USING btree (conversion_status)` |
| `ix_sbom_source_converted_from_format` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_converted_from_format ON public.sbom_source USING btree (converted_from_format)` |
| `ix_sbom_source_converted_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_converted_sbom_id ON public.sbom_source USING btree (converted_sbom_id)` |
| `ix_sbom_source_created_by` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_created_by ON public.sbom_source USING btree (created_by)` |
| `ix_sbom_source_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_deactivated ON public.sbom_source USING btree (is_active) WHERE (is_active = false)` |
| `ix_sbom_source_enrichment_status` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_enrichment_status ON public.sbom_source USING btree (enrichment_status)` |
| `ix_sbom_source_failed_stage` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_failed_stage ON public.sbom_source USING btree (failed_stage)` |
| `ix_sbom_source_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_id ON public.sbom_source USING btree (id)` |
| `ix_sbom_source_parent_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_parent_id ON public.sbom_source USING btree (parent_id)` |
| `ix_sbom_source_product_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_product_id ON public.sbom_source USING btree (product_id)` |
| `ix_sbom_source_sbom_name` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_sbom_name ON public.sbom_source USING btree (sbom_name)` |
| `ix_sbom_source_sbom_type` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_sbom_type ON public.sbom_source USING btree (sbom_type)` |
| `ix_sbom_source_source_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_source_sbom_id ON public.sbom_source USING btree (source_sbom_id)` |
| `ix_sbom_source_status` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_status ON public.sbom_source USING btree (status)` |
| `ix_sbom_source_tenant_created` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_tenant_created ON public.sbom_source USING btree (tenant_id, created_on)` |
| `ix_sbom_source_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_tenant_id ON public.sbom_source USING btree (tenant_id)` |
| `ix_sbom_source_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_tenant_identity ON public.sbom_source USING btree (tenant_id, id)` |
| `ix_sbom_source_tenant_product` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_tenant_product ON public.sbom_source USING btree (tenant_id, product_id)` |
| `ix_sbom_source_tenant_project` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_tenant_project ON public.sbom_source USING btree (tenant_id, projectid)` |
| `pk_sbom_source` | btree / True | `pk_sbom_source` | True / True | `CREATE UNIQUE INDEX pk_sbom_source ON public.sbom_source USING btree (id)` |
| `uq_sbom_source_tenant_name_version` | btree / True | `uq_sbom_source_tenant_name_version` | True / True | `CREATE UNIQUE INDEX uq_sbom_source_tenant_name_version ON public.sbom_source USING btree (tenant_id, sbom_name, sbom_version)` |

### `public.sbom_type`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.sbom_type_id_seq'::regclass)` | `none / none` |
| `typename` | `character varying` | NOT NULL | `—` | `none / none` |
| `type_details` | `character varying` | NULL | `—` | `none / none` |
| `created_on` | `character varying` | NULL | `—` | `none / none` |
| `created_by` | `character varying` | NULL | `—` | `none / none` |
| `modified_on` | `character varying` | NULL | `—` | `none / none` |
| `modified_by` | `character varying` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_sbom_type` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_sbom_type_typename` | u | `UNIQUE (typename)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_sbom_type_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_type_id ON public.sbom_type USING btree (id)` |
| `pk_sbom_type` | btree / True | `pk_sbom_type` | True / True | `CREATE UNIQUE INDEX pk_sbom_type ON public.sbom_type USING btree (id)` |
| `uq_sbom_type_typename` | btree / True | `uq_sbom_type_typename` | True / True | `CREATE UNIQUE INDEX uq_sbom_type_typename ON public.sbom_type USING btree (typename)` |

### `public.sbom_validation_session_events`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.sbom_validation_session_events_id_seq'::regclass)` | `none / none` |
| `session_id` | `character varying(36)` | NOT NULL | `—` | `none / none` |
| `event_type` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `actor_user_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `timestamp` | `character varying` | NOT NULL | `—` | `none / none` |
| `summary` | `text` | NULL | `—` | `none / none` |
| `before_hash` | `character varying(64)` | NULL | `—` | `none / none` |
| `after_hash` | `character varying(64)` | NULL | `—` | `none / none` |
| `metadata_json` | `json` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_sbom_validation_session_events_session_id_sbom_valid_ca0d` | f | `FOREIGN KEY (session_id) REFERENCES public.sbom_validation_sessions(id) ON DELETE CASCADE` | True / False / False |
| `fk_sbom_validation_session_events_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_sbom_validation_session_events` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_sbom_validation_session_events_actor_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_session_events_actor_user_id ON public.sbom_validation_session_events USING btree (actor_user_id)` |
| `ix_sbom_validation_session_events_event_type` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_session_events_event_type ON public.sbom_validation_session_events USING btree (event_type)` |
| `ix_sbom_validation_session_events_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_session_events_id ON public.sbom_validation_session_events USING btree (id)` |
| `ix_sbom_validation_session_events_session_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_session_events_session_id ON public.sbom_validation_session_events USING btree (session_id)` |
| `ix_sbom_validation_session_events_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_session_events_tenant_id ON public.sbom_validation_session_events USING btree (tenant_id)` |
| `ix_sbom_validation_session_events_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_session_events_tenant_identity ON public.sbom_validation_session_events USING btree (tenant_id, id)` |
| `ix_sbom_validation_session_events_timestamp` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_session_events_timestamp ON public.sbom_validation_session_events USING btree ("timestamp")` |
| `pk_sbom_validation_session_events` | btree / True | `pk_sbom_validation_session_events` | True / True | `CREATE UNIQUE INDEX pk_sbom_validation_session_events ON public.sbom_validation_session_events USING btree (id)` |

### `public.sbom_validation_sessions`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `character varying(36)` | NOT NULL | `—` | `none / none` |
| `project_id` | `integer` | NULL | `—` | `none / none` |
| `user_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `original_filename` | `character varying(255)` | NULL | `—` | `none / none` |
| `sbom_name` | `character varying(255)` | NULL | `—` | `none / none` |
| `sbom_type` | `integer` | NULL | `—` | `none / none` |
| `content_type` | `character varying(255)` | NULL | `—` | `none / none` |
| `file_size_bytes` | `integer` | NULL | `—` | `none / none` |
| `sha256` | `character varying(64)` | NULL | `—` | `none / none` |
| `original_size_bytes` | `integer` | NULL | `—` | `none / none` |
| `original_sha256` | `character varying(64)` | NULL | `—` | `none / none` |
| `stored_size_bytes` | `integer` | NULL | `—` | `none / none` |
| `stored_sha256` | `character varying(64)` | NULL | `—` | `none / none` |
| `storage_backend` | `character varying(32)` | NULL | `—` | `none / none` |
| `detected_format` | `character varying(64)` | NULL | `—` | `none / none` |
| `detected_version` | `character varying(64)` | NULL | `—` | `none / none` |
| `detection_confidence` | `double precision` | NULL | `—` | `none / none` |
| `detection_evidence_json` | `json` | NULL | `—` | `none / none` |
| `raw_content_text` | `text` | NULL | `—` | `none / none` |
| `raw_content_blob` | `bytea` | NULL | `—` | `none / none` |
| `raw_storage_path` | `character varying(1024)` | NULL | `—` | `none / none` |
| `sanitized_content` | `text` | NULL | `—` | `none / none` |
| `current_content` | `text` | NULL | `—` | `none / none` |
| `repair_content_text` | `text` | NULL | `—` | `none / none` |
| `repair_content_blob` | `bytea` | NULL | `—` | `none / none` |
| `repair_storage_path` | `character varying(1024)` | NULL | `—` | `none / none` |
| `validation_status` | `character varying(32)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `validation_errors_json` | `json` | NULL | `—` | `none / none` |
| `stage_results_json` | `json` | NULL | `—` | `none / none` |
| `latest_error_report_json` | `json` | NULL | `—` | `none / none` |
| `total_lines` | `integer` | NULL | `—` | `none / none` |
| `is_large_file` | `boolean` | NOT NULL | `false` | `none / none` |
| `full_editor_allowed` | `boolean` | NOT NULL | `true` | `none / none` |
| `can_edit` | `boolean` | NOT NULL | `true` | `none / none` |
| `can_ai_fix` | `boolean` | NOT NULL | `true` | `none / none` |
| `security_blocked_reason` | `text` | NULL | `—` | `none / none` |
| `content_sha256` | `character varying(64)` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `imported_sbom_id` | `integer` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_sbom_validation_sessions_imported_sbom_id_sbom_source` | f | `FOREIGN KEY (imported_sbom_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_sbom_validation_sessions_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id)` | True / False / False |
| `fk_sbom_validation_sessions_sbom_type_sbom_type` | f | `FOREIGN KEY (sbom_type) REFERENCES public.sbom_type(id)` | True / False / False |
| `fk_sbom_validation_sessions_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_sbom_validation_sessions` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_sbom_validation_sessions_content_sha256` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_content_sha256 ON public.sbom_validation_sessions USING btree (content_sha256)` |
| `ix_sbom_validation_sessions_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_created_at ON public.sbom_validation_sessions USING btree (created_at)` |
| `ix_sbom_validation_sessions_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_expires_at ON public.sbom_validation_sessions USING btree (expires_at)` |
| `ix_sbom_validation_sessions_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_id ON public.sbom_validation_sessions USING btree (id)` |
| `ix_sbom_validation_sessions_imported_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_imported_sbom_id ON public.sbom_validation_sessions USING btree (imported_sbom_id)` |
| `ix_sbom_validation_sessions_original_sha256` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_original_sha256 ON public.sbom_validation_sessions USING btree (original_sha256)` |
| `ix_sbom_validation_sessions_project_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_project_id ON public.sbom_validation_sessions USING btree (project_id)` |
| `ix_sbom_validation_sessions_sha256` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_sha256 ON public.sbom_validation_sessions USING btree (sha256)` |
| `ix_sbom_validation_sessions_stored_sha256` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_stored_sha256 ON public.sbom_validation_sessions USING btree (stored_sha256)` |
| `ix_sbom_validation_sessions_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_tenant_id ON public.sbom_validation_sessions USING btree (tenant_id)` |
| `ix_sbom_validation_sessions_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_tenant_identity ON public.sbom_validation_sessions USING btree (tenant_id, id)` |
| `ix_sbom_validation_sessions_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_user_id ON public.sbom_validation_sessions USING btree (user_id)` |
| `ix_sbom_validation_sessions_validation_status` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_validation_status ON public.sbom_validation_sessions USING btree (validation_status)` |
| `pk_sbom_validation_sessions` | btree / True | `pk_sbom_validation_sessions` | True / True | `CREATE UNIQUE INDEX pk_sbom_validation_sessions ON public.sbom_validation_sessions USING btree (id)` |

### `public.source_response_cache`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `source` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `component_key` | `character varying(512)` | NOT NULL | `—` | `none / none` |
| `payload` | `json` | NOT NULL | `—` | `none / none` |
| `fetched_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_source_response_cache` | p | `PRIMARY KEY (source, component_key)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_source_response_cache_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_source_response_cache_expires_at ON public.source_response_cache USING btree (expires_at)` |
| `pk_source_response_cache` | btree / True | `pk_source_response_cache` | True / True | `CREATE UNIQUE INDEX pk_source_response_cache ON public.source_response_cache USING btree (source, component_key)` |

### `public.tenant_user_role_assignment_history`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.tenant_user_role_assignment_history_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `tenant_user_id` | `integer` | NULL | `—` | `none / none` |
| `assignment_id` | `integer` | NULL | `—` | `none / none` |
| `role_id` | `integer` | NULL | `—` | `none / none` |
| `role_code_snapshot` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `event_type` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `previous_status` | `character varying(16)` | NULL | `—` | `none / none` |
| `new_status` | `character varying(16)` | NULL | `—` | `none / none` |
| `previous_primary` | `boolean` | NULL | `—` | `none / none` |
| `new_primary` | `boolean` | NULL | `—` | `none / none` |
| `actor_user_id` | `integer` | NULL | `—` | `none / none` |
| `assignment_source` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `reason` | `character varying(512)` | NULL | `—` | `none / none` |
| `before_membership_version` | `integer` | NOT NULL | `—` | `none / none` |
| `after_membership_version` | `integer` | NOT NULL | `—` | `none / none` |
| `correlation_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `occurred_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `metadata_json` | `json` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_tenant_user_role_assignment_history_tenant_role_assi_3223` | c | `CHECK (assignment_source::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_tenant_user_role_assignment_history_tenant_role_assi_902f` | c | `CHECK (event_type::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_tenant_user_role_assignment_history_tenant_role_assi_f6d5` | c | `CHECK (before_membership_version >= 1 AND after_membership_version >= before_membership_version)` | True / False / False |
| `fk_tenant_user_role_assignment_history_actor_user_id_iam_users` | f | `FOREIGN KEY (actor_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_tenant_user_role_assignment_history_assignment_id_te_89a9` | f | `FOREIGN KEY (assignment_id) REFERENCES public.tenant_user_role_assignments(id) ON DELETE SET NULL` | True / False / False |
| `fk_tenant_user_role_assignment_history_role_id_authoriz_9a90` | f | `FOREIGN KEY (role_id) REFERENCES public.authorization_roles(id) ON DELETE SET NULL` | True / False / False |
| `fk_tenant_user_role_assignment_history_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT` | True / False / False |
| `fk_tenant_user_role_assignment_history_tenant_user_id_t_b1b5` | f | `FOREIGN KEY (tenant_user_id) REFERENCES public.tenant_users(id) ON DELETE SET NULL` | True / False / False |
| `pk_tenant_user_role_assignment_history` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_tenant_role_assignment_history_assignment_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_role_assignment_history_assignment_id ON public.tenant_user_role_assignment_history USING btree (assignment_id)` |
| `ix_tenant_role_assignment_history_membership_time` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_role_assignment_history_membership_time ON public.tenant_user_role_assignment_history USING btree (tenant_id, tenant_user_id, occurred_at)` |
| `ix_tenant_role_assignment_history_occurred_at` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_role_assignment_history_occurred_at ON public.tenant_user_role_assignment_history USING btree (occurred_at)` |
| `ix_tenant_role_assignment_history_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_role_assignment_history_tenant_id ON public.tenant_user_role_assignment_history USING btree (tenant_id)` |
| `ix_tenant_role_assignment_history_tenant_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_role_assignment_history_tenant_user_id ON public.tenant_user_role_assignment_history USING btree (tenant_user_id)` |
| `pk_tenant_user_role_assignment_history` | btree / True | `pk_tenant_user_role_assignment_history` | True / True | `CREATE UNIQUE INDEX pk_tenant_user_role_assignment_history ON public.tenant_user_role_assignment_history USING btree (id)` |

### `public.tenant_user_role_assignments`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.tenant_user_role_assignments_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `tenant_user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `role_id` | `integer` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `is_primary` | `boolean` | NOT NULL | `false` | `none / none` |
| `assignment_source` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `assigned_by_user_id` | `integer` | NULL | `—` | `none / none` |
| `assigned_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `revoked_by_user_id` | `integer` | NULL | `—` | `none / none` |
| `revoked_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `revocation_reason` | `character varying(512)` | NULL | `—` | `none / none` |
| `version` | `integer` | NOT NULL | `1` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_tenant_user_role_assignments_tenant_role_assignment__f1b0` | c | `CHECK (status::text = '<literal redacted>'::text AND revoked_at IS NULL AND revoked_by_user_id IS NULL OR status::text = '<literal redacted>'::text AND revoked_at IS NOT NULL AND is_primary = false)` | True / False / False |
| `ck_tenant_user_role_assignments_tenant_role_assignment_source` | c | `CHECK (assignment_source::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_tenant_user_role_assignments_tenant_role_assignment_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_tenant_user_role_assignments_tenant_role_assignment_version` | c | `CHECK (version >= 1)` | True / False / False |
| `fk_tenant_role_assignment_membership_tenant` | f | `FOREIGN KEY (tenant_user_id, tenant_id) REFERENCES public.tenant_users(id, tenant_id) ON DELETE CASCADE` | True / False / False |
| `fk_tenant_user_role_assignments_assigned_by_user_id_iam_users` | f | `FOREIGN KEY (assigned_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_tenant_user_role_assignments_revoked_by_user_id_iam_users` | f | `FOREIGN KEY (revoked_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_tenant_user_role_assignments_role_id_authorization_roles` | f | `FOREIGN KEY (role_id) REFERENCES public.authorization_roles(id) ON DELETE RESTRICT` | True / False / False |
| `fk_tenant_user_role_assignments_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE` | True / False / False |
| `pk_tenant_user_role_assignments` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_tenant_user_role_assignments_membership_role` | u | `UNIQUE (tenant_user_id, role_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_tenant_user_role_assignments_membership_status` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_user_role_assignments_membership_status ON public.tenant_user_role_assignments USING btree (tenant_user_id, status)` |
| `ix_tenant_user_role_assignments_role_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_user_role_assignments_role_id ON public.tenant_user_role_assignments USING btree (role_id)` |
| `ix_tenant_user_role_assignments_status` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_user_role_assignments_status ON public.tenant_user_role_assignments USING btree (status)` |
| `ix_tenant_user_role_assignments_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_user_role_assignments_tenant_id ON public.tenant_user_role_assignments USING btree (tenant_id)` |
| `ix_tenant_user_role_assignments_tenant_status` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_user_role_assignments_tenant_status ON public.tenant_user_role_assignments USING btree (tenant_id, status)` |
| `ix_tenant_user_role_assignments_tenant_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_user_role_assignments_tenant_user_id ON public.tenant_user_role_assignments USING btree (tenant_user_id)` |
| `pk_tenant_user_role_assignments` | btree / True | `pk_tenant_user_role_assignments` | True / True | `CREATE UNIQUE INDEX pk_tenant_user_role_assignments ON public.tenant_user_role_assignments USING btree (id)` |
| `uq_tenant_user_role_assignments_active_primary` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_tenant_user_role_assignments_active_primary ON public.tenant_user_role_assignments USING btree (tenant_user_id) WHERE (((status)::text = '<literal redacted>'::text) AND is_primary)` |
| `uq_tenant_user_role_assignments_membership_role` | btree / True | `uq_tenant_user_role_assignments_membership_role` | True / True | `CREATE UNIQUE INDEX uq_tenant_user_role_assignments_membership_role ON public.tenant_user_role_assignments USING btree (tenant_user_id, role_id)` |

### `public.tenant_users`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.tenant_users_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `role` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `role_assignment_version` | `integer` | NOT NULL | `1` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_tenant_users_tenant_user_role_assignment_version` | c | `CHECK (role_assignment_version >= 1)` | True / False / False |
| `ck_tenant_users_tenant_user_role_normalized` | c | `CHECK (length(TRIM(BOTH FROM role)) > 0 AND role::text = upper(role::text))` | True / False / False |
| `ck_tenant_users_tenant_user_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `fk_tenant_users_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE` | True / False / False |
| `fk_tenant_users_user_id_iam_users` | f | `FOREIGN KEY (user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE` | True / False / False |
| `pk_tenant_users` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_tenant_users_id_tenant` | u | `UNIQUE (id, tenant_id)` | True / False / False |
| `uq_tenant_users_tenant_user` | u | `UNIQUE (tenant_id, user_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_tenant_users_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_users_tenant_id ON public.tenant_users USING btree (tenant_id)` |
| `ix_tenant_users_tenant_status` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_users_tenant_status ON public.tenant_users USING btree (tenant_id, status)` |
| `ix_tenant_users_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_users_user_id ON public.tenant_users USING btree (user_id)` |
| `pk_tenant_users` | btree / True | `pk_tenant_users` | True / True | `CREATE UNIQUE INDEX pk_tenant_users ON public.tenant_users USING btree (id)` |
| `uq_tenant_users_id_tenant` | btree / True | `uq_tenant_users_id_tenant` | True / True | `CREATE UNIQUE INDEX uq_tenant_users_id_tenant ON public.tenant_users USING btree (id, tenant_id)` |
| `uq_tenant_users_tenant_user` | btree / True | `uq_tenant_users_tenant_user` | True / True | `CREATE UNIQUE INDEX uq_tenant_users_tenant_user ON public.tenant_users USING btree (tenant_id, user_id)` |

### `public.tenants`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.tenants_id_seq'::regclass)` | `none / none` |
| `name` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `slug` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `external_iam_tenant_id` | `character varying(255)` | NULL | `—` | `none / none` |
| `status` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_tenants_tenant_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `pk_tenants` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_tenants_external_iam_tenant_id` | u | `UNIQUE (external_iam_tenant_id)` | True / False / False |
| `uq_tenants_slug` | u | `UNIQUE (slug)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_tenants_external_iam_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenants_external_iam_tenant_id ON public.tenants USING btree (external_iam_tenant_id)` |
| `ix_tenants_slug` | btree / False | `none` | True / True | `CREATE INDEX ix_tenants_slug ON public.tenants USING btree (slug)` |
| `pk_tenants` | btree / True | `pk_tenants` | True / True | `CREATE UNIQUE INDEX pk_tenants ON public.tenants USING btree (id)` |
| `uq_tenants_external_iam_tenant_id` | btree / True | `uq_tenants_external_iam_tenant_id` | True / True | `CREATE UNIQUE INDEX uq_tenants_external_iam_tenant_id ON public.tenants USING btree (external_iam_tenant_id)` |
| `uq_tenants_slug` | btree / True | `uq_tenants_slug` | True / True | `CREATE UNIQUE INDEX uq_tenants_slug ON public.tenants USING btree (slug)` |

### `public.vex_documents`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.vex_documents_id_seq'::regclass)` | `none / none` |
| `sbom_id` | `integer` | NOT NULL | `—` | `none / none` |
| `source_type` | `character varying` | NOT NULL | `—` | `none / none` |
| `format` | `character varying` | NULL | `—` | `none / none` |
| `author` | `character varying` | NULL | `—` | `none / none` |
| `source_url` | `character varying` | NULL | `—` | `none / none` |
| `discovery_evidence_json` | `json` | NULL | `—` | `none / none` |
| `last_refresh_status` | `character varying` | NULL | `—` | `none / none` |
| `provider_errors_json` | `json` | NULL | `—` | `none / none` |
| `uploaded_by` | `character varying` | NULL | `—` | `none / none` |
| `uploaded_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `raw_document_json` | `json` | NULL | `—` | `none / none` |
| `validation_status` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_vex_documents_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE CASCADE` | True / False / False |
| `fk_vex_documents_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_vex_documents` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_vex_documents_format` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_format ON public.vex_documents USING btree (format)` |
| `ix_vex_documents_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_id ON public.vex_documents USING btree (id)` |
| `ix_vex_documents_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_sbom_id ON public.vex_documents USING btree (sbom_id)` |
| `ix_vex_documents_source_type` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_source_type ON public.vex_documents USING btree (source_type)` |
| `ix_vex_documents_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_tenant_id ON public.vex_documents USING btree (tenant_id)` |
| `ix_vex_documents_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_tenant_identity ON public.vex_documents USING btree (tenant_id, id)` |
| `ix_vex_documents_uploaded_at` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_uploaded_at ON public.vex_documents USING btree (uploaded_at)` |
| `ix_vex_documents_uploaded_by` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_uploaded_by ON public.vex_documents USING btree (uploaded_by)` |
| `ix_vex_documents_validation_status` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_validation_status ON public.vex_documents USING btree (validation_status)` |
| `pk_vex_documents` | btree / True | `pk_vex_documents` | True / True | `CREATE UNIQUE INDEX pk_vex_documents ON public.vex_documents USING btree (id)` |

### `public.vex_override_audit`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.vex_override_audit_id_seq'::regclass)` | `none / none` |
| `component_id` | `integer` | NOT NULL | `—` | `none / none` |
| `vulnerability_id` | `character varying` | NOT NULL | `—` | `none / none` |
| `old_value_json` | `json` | NULL | `—` | `none / none` |
| `new_value_json` | `json` | NULL | `—` | `none / none` |
| `reason` | `text` | NOT NULL | `—` | `none / none` |
| `evidence_url` | `character varying` | NULL | `—` | `none / none` |
| `changed_by` | `character varying` | NULL | `—` | `none / none` |
| `changed_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_vex_override_audit_component_id_sbom_component` | f | `FOREIGN KEY (component_id) REFERENCES public.sbom_component(id) ON DELETE CASCADE` | True / False / False |
| `fk_vex_override_audit_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_vex_override_audit` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_vex_override_audit_changed_at` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_changed_at ON public.vex_override_audit USING btree (changed_at)` |
| `ix_vex_override_audit_changed_by` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_changed_by ON public.vex_override_audit USING btree (changed_by)` |
| `ix_vex_override_audit_component_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_component_id ON public.vex_override_audit USING btree (component_id)` |
| `ix_vex_override_audit_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_id ON public.vex_override_audit USING btree (id)` |
| `ix_vex_override_audit_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_tenant_id ON public.vex_override_audit USING btree (tenant_id)` |
| `ix_vex_override_audit_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_tenant_identity ON public.vex_override_audit USING btree (tenant_id, id)` |
| `ix_vex_override_audit_vulnerability_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_vulnerability_id ON public.vex_override_audit USING btree (vulnerability_id)` |
| `pk_vex_override_audit` | btree / True | `pk_vex_override_audit` | True / True | `CREATE UNIQUE INDEX pk_vex_override_audit ON public.vex_override_audit USING btree (id)` |

### `public.vex_statements`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.vex_statements_id_seq'::regclass)` | `none / none` |
| `vex_document_id` | `integer` | NULL | `—` | `none / none` |
| `sbom_id` | `integer` | NOT NULL | `—` | `none / none` |
| `component_id` | `integer` | NULL | `—` | `none / none` |
| `vulnerability_id` | `character varying` | NOT NULL | `—` | `none / none` |
| `cve_id` | `character varying` | NULL | `—` | `none / none` |
| `status` | `character varying` | NOT NULL | `—` | `none / none` |
| `justification` | `text` | NULL | `—` | `none / none` |
| `impact_statement` | `text` | NULL | `—` | `none / none` |
| `action_statement` | `text` | NULL | `—` | `none / none` |
| `fixed_version` | `character varying` | NULL | `—` | `none / none` |
| `mitigation` | `text` | NULL | `—` | `none / none` |
| `source_name` | `character varying` | NULL | `—` | `none / none` |
| `source_url` | `character varying` | NULL | `—` | `none / none` |
| `confidence` | `character varying` | NULL | `—` | `none / none` |
| `evidence_json` | `json` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_vex_statements_component_id_sbom_component` | f | `FOREIGN KEY (component_id) REFERENCES public.sbom_component(id) ON DELETE SET NULL` | True / False / False |
| `fk_vex_statements_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE CASCADE` | True / False / False |
| `fk_vex_statements_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `fk_vex_statements_vex_document_id_vex_documents` | f | `FOREIGN KEY (vex_document_id) REFERENCES public.vex_documents(id) ON DELETE CASCADE` | True / False / False |
| `pk_vex_statements` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_vex_statement_component_vuln` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statement_component_vuln ON public.vex_statements USING btree (component_id, vulnerability_id)` |
| `ix_vex_statement_sbom_status` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statement_sbom_status ON public.vex_statements USING btree (sbom_id, status)` |
| `ix_vex_statements_component_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_component_id ON public.vex_statements USING btree (component_id)` |
| `ix_vex_statements_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_created_at ON public.vex_statements USING btree (created_at)` |
| `ix_vex_statements_cve_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_cve_id ON public.vex_statements USING btree (cve_id)` |
| `ix_vex_statements_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_id ON public.vex_statements USING btree (id)` |
| `ix_vex_statements_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_sbom_id ON public.vex_statements USING btree (sbom_id)` |
| `ix_vex_statements_status` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_status ON public.vex_statements USING btree (status)` |
| `ix_vex_statements_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_tenant_id ON public.vex_statements USING btree (tenant_id)` |
| `ix_vex_statements_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_tenant_identity ON public.vex_statements USING btree (tenant_id, id)` |
| `ix_vex_statements_vex_document_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_vex_document_id ON public.vex_statements USING btree (vex_document_id)` |
| `ix_vex_statements_vulnerability_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_vulnerability_id ON public.vex_statements USING btree (vulnerability_id)` |
| `pk_vex_statements` | btree / True | `pk_vex_statements` | True / True | `CREATE UNIQUE INDEX pk_vex_statements ON public.vex_statements USING btree (id)` |

### `public.vulnerability_remediation`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.vulnerability_remediation_id_seq'::regclass)` | `none / none` |
| `project_id` | `integer` | NOT NULL | `—` | `none / none` |
| `vuln_id` | `character varying` | NOT NULL | `—` | `none / none` |
| `component_name` | `character varying` | NOT NULL | `—` | `none / none` |
| `component_version` | `character varying` | NOT NULL | `—` | `none / none` |
| `fixed_version` | `character varying` | NULL | `—` | `none / none` |
| `status` | `character varying` | NOT NULL | `—` | `none / none` |
| `owner` | `character varying` | NULL | `—` | `none / none` |
| `due_date` | `character varying` | NULL | `—` | `none / none` |
| `resolution_date` | `character varying` | NULL | `—` | `none / none` |
| `fix_notes` | `text` | NULL | `—` | `none / none` |
| `created_on` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_on` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_vulnerability_remediation_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE` | True / False / False |
| `fk_vulnerability_remediation_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_vulnerability_remediation` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_vulnerability_remediation_component_name` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_component_name ON public.vulnerability_remediation USING btree (component_name)` |
| `ix_vulnerability_remediation_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_id ON public.vulnerability_remediation USING btree (id)` |
| `ix_vulnerability_remediation_project_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_project_id ON public.vulnerability_remediation USING btree (project_id)` |
| `ix_vulnerability_remediation_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_tenant_id ON public.vulnerability_remediation USING btree (tenant_id)` |
| `ix_vulnerability_remediation_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_tenant_identity ON public.vulnerability_remediation USING btree (tenant_id, id)` |
| `ix_vulnerability_remediation_vuln_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_vuln_id ON public.vulnerability_remediation USING btree (vuln_id)` |
| `pk_vulnerability_remediation` | btree / True | `pk_vulnerability_remediation` | True / True | `CREATE UNIQUE INDEX pk_vulnerability_remediation ON public.vulnerability_remediation USING btree (id)` |

### `public.vulnerability_remediation_audit`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.vulnerability_remediation_audit_id_seq'::regclass)` | `none / none` |
| `remediation_id` | `integer` | NOT NULL | `—` | `none / none` |
| `project_id` | `integer` | NOT NULL | `—` | `none / none` |
| `vuln_id` | `character varying` | NOT NULL | `—` | `none / none` |
| `component_name` | `character varying` | NOT NULL | `—` | `none / none` |
| `component_version` | `character varying` | NOT NULL | `—` | `none / none` |
| `old_status` | `character varying` | NULL | `—` | `none / none` |
| `new_status` | `character varying` | NOT NULL | `—` | `none / none` |
| `changed_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `changed_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `note` | `text` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_vulnerability_remediation_audit_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE` | True / False / False |
| `fk_vulnerability_remediation_audit_remediation_id_vulne_f9a9` | f | `FOREIGN KEY (remediation_id) REFERENCES public.vulnerability_remediation(id) ON DELETE CASCADE` | True / False / False |
| `fk_vulnerability_remediation_audit_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_vulnerability_remediation_audit` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_vulnerability_remediation_audit_changed_at` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_changed_at ON public.vulnerability_remediation_audit USING btree (changed_at)` |
| `ix_vulnerability_remediation_audit_component_name` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_component_name ON public.vulnerability_remediation_audit USING btree (component_name)` |
| `ix_vulnerability_remediation_audit_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_id ON public.vulnerability_remediation_audit USING btree (id)` |
| `ix_vulnerability_remediation_audit_project_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_project_id ON public.vulnerability_remediation_audit USING btree (project_id)` |
| `ix_vulnerability_remediation_audit_remediation_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_remediation_id ON public.vulnerability_remediation_audit USING btree (remediation_id)` |
| `ix_vulnerability_remediation_audit_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_tenant_id ON public.vulnerability_remediation_audit USING btree (tenant_id)` |
| `ix_vulnerability_remediation_audit_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_tenant_identity ON public.vulnerability_remediation_audit USING btree (tenant_id, id)` |
| `ix_vulnerability_remediation_audit_vuln_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_vuln_id ON public.vulnerability_remediation_audit USING btree (vuln_id)` |
| `pk_vulnerability_remediation_audit` | btree / True | `pk_vulnerability_remediation_audit` | True / True | `CREATE UNIQUE INDEX pk_vulnerability_remediation_audit ON public.vulnerability_remediation_audit USING btree (id)` |

</details>

<details>
<summary>B — .env.dev.local DATABASE_URL — full live metadata</summary>


### `public.account_action_tokens`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.account_action_tokens_id_seq'::regclass)` | `none / none` |
| `user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `purpose` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `token_hash` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `email_snapshot` | `character varying(320)` | NOT NULL | `—` | `none / none` |
| `expires_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `consumed_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `invalidated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_account_action_tokens_account_action_consumed_time` | c | `CHECK (consumed_at IS NULL OR consumed_at >= created_at)` | True / False / False |
| `ck_account_action_tokens_account_action_expiry` | c | `CHECK (expires_at > created_at)` | True / False / False |
| `ck_account_action_tokens_account_action_invalidated_time` | c | `CHECK (invalidated_at IS NULL OR invalidated_at >= created_at)` | True / False / False |
| `ck_account_action_tokens_account_action_purpose` | c | `CHECK (purpose::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `fk_account_action_tokens_user_id_iam_users` | f | `FOREIGN KEY (user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE` | True / False / False |
| `pk_account_action_tokens` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_account_action_tokens_token_hash` | u | `UNIQUE (token_hash)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_account_action_tokens_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_account_action_tokens_expires_at ON public.account_action_tokens USING btree (expires_at)` |
| `ix_account_action_tokens_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_account_action_tokens_user_id ON public.account_action_tokens USING btree (user_id)` |
| `pk_account_action_tokens` | btree / True | `pk_account_action_tokens` | True / True | `CREATE UNIQUE INDEX pk_account_action_tokens ON public.account_action_tokens USING btree (id)` |
| `uq_account_action_tokens_active` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_account_action_tokens_active ON public.account_action_tokens USING btree (user_id, purpose) WHERE ((consumed_at IS NULL) AND (invalidated_at IS NULL))` |
| `uq_account_action_tokens_token_hash` | btree / True | `uq_account_action_tokens_token_hash` | True / True | `CREATE UNIQUE INDEX uq_account_action_tokens_token_hash ON public.account_action_tokens USING btree (token_hash)` |

### `public.advisor_policy`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.advisor_policy_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NULL | `—` | `none / none` |
| `kind` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `row_version` | `integer` | NOT NULL | `1` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `created_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `updated_by` | `character varying(128)` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_advisor_policy_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE` | True / False / False |
| `pk_advisor_policy` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_advisor_policy_tenant_kind` | u | `UNIQUE (tenant_id, kind)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_advisor_policy_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_advisor_policy_tenant_id ON public.advisor_policy USING btree (tenant_id)` |
| `pk_advisor_policy` | btree / True | `pk_advisor_policy` | True / True | `CREATE UNIQUE INDEX pk_advisor_policy ON public.advisor_policy USING btree (id)` |
| `uq_advisor_policy_platform_kind` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_advisor_policy_platform_kind ON public.advisor_policy USING btree (kind) WHERE (tenant_id IS NULL)` |
| `uq_advisor_policy_tenant_kind` | btree / True | `uq_advisor_policy_tenant_kind` | True / True | `CREATE UNIQUE INDEX uq_advisor_policy_tenant_kind ON public.advisor_policy USING btree (tenant_id, kind)` |

### `public.advisor_policy_version`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.advisor_policy_version_id_seq'::regclass)` | `none / none` |
| `policy_id` | `integer` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NULL | `—` | `none / none` |
| `kind` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `version` | `integer` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `rules_json` | `json` | NOT NULL | `—` | `none / none` |
| `reason` | `text` | NOT NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `created_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `correlation_id` | `character varying(128)` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_advisor_policy_version_policy_id_advisor_policy` | f | `FOREIGN KEY (policy_id) REFERENCES public.advisor_policy(id)` | True / False / False |
| `fk_advisor_policy_version_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE` | True / False / False |
| `pk_advisor_policy_version` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_advisor_policy_version_number` | u | `UNIQUE (policy_id, version)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_advisor_policy_version_policy_id` | btree / False | `none` | True / True | `CREATE INDEX ix_advisor_policy_version_policy_id ON public.advisor_policy_version USING btree (policy_id)` |
| `ix_advisor_policy_version_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_advisor_policy_version_tenant_id ON public.advisor_policy_version USING btree (tenant_id)` |
| `pk_advisor_policy_version` | btree / True | `pk_advisor_policy_version` | True / True | `CREATE UNIQUE INDEX pk_advisor_policy_version ON public.advisor_policy_version USING btree (id)` |
| `uq_advisor_policy_version_number` | btree / True | `uq_advisor_policy_version_number` | True / True | `CREATE UNIQUE INDEX uq_advisor_policy_version_number ON public.advisor_policy_version USING btree (policy_id, version)` |

### `public.ai_credential_audit_log`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.ai_credential_audit_log_id_seq'::regclass)` | `none / none` |
| `user_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `action` | `character varying(48)` | NOT NULL | `—` | `none / none` |
| `target_kind` | `character varying(24)` | NOT NULL | `—` | `none / none` |
| `target_id` | `integer` | NULL | `—` | `none / none` |
| `provider_name` | `character varying(32)` | NULL | `—` | `none / none` |
| `detail` | `character varying(240)` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_ai_credential_audit_log_configuration_tenant` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL` | True / False / False |
| `pk_ai_credential_audit_log` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_ai_credential_audit_log_configuration_tenant` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_credential_audit_log_configuration_tenant ON public.ai_credential_audit_log USING btree (tenant_id)` |
| `ix_ai_credential_audit_log_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_credential_audit_log_created_at ON public.ai_credential_audit_log USING btree (created_at)` |
| `ix_ai_credential_audit_log_id` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_credential_audit_log_id ON public.ai_credential_audit_log USING btree (id)` |
| `pk_ai_credential_audit_log` | btree / True | `pk_ai_credential_audit_log` | True / True | `CREATE UNIQUE INDEX pk_ai_credential_audit_log ON public.ai_credential_audit_log USING btree (id)` |

### `public.ai_fix_batch`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `character varying(36)` | NOT NULL | `—` | `none / none` |
| `run_id` | `integer` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(24)` | NOT NULL | `—` | `none / none` |
| `scope_label` | `character varying(120)` | NULL | `—` | `none / none` |
| `scope_json` | `json` | NULL | `—` | `none / none` |
| `finding_ids_json` | `json` | NOT NULL | `—` | `none / none` |
| `provider_name` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `total` | `integer` | NOT NULL | `—` | `none / none` |
| `cached_count` | `integer` | NOT NULL | `—` | `none / none` |
| `generated_count` | `integer` | NOT NULL | `—` | `none / none` |
| `failed_count` | `integer` | NOT NULL | `—` | `none / none` |
| `cost_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `started_at` | `character varying` | NULL | `—` | `none / none` |
| `completed_at` | `character varying` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `last_error` | `character varying(240)` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_ai_fix_batch_run_id_analysis_run` | f | `FOREIGN KEY (run_id) REFERENCES public.analysis_run(id) ON DELETE CASCADE` | True / False / False |
| `fk_ai_fix_batch_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_ai_fix_batch` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_ai_fix_batch_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_batch_created_at ON public.ai_fix_batch USING btree (created_at)` |
| `ix_ai_fix_batch_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_batch_deactivated ON public.ai_fix_batch USING btree (is_active) WHERE (is_active = false)` |
| `ix_ai_fix_batch_run_status` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_batch_run_status ON public.ai_fix_batch USING btree (run_id, status)` |
| `ix_ai_fix_batch_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_batch_tenant_id ON public.ai_fix_batch USING btree (tenant_id)` |
| `ix_ai_fix_batch_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_batch_tenant_identity ON public.ai_fix_batch USING btree (tenant_id, id)` |
| `pk_ai_fix_batch` | btree / True | `pk_ai_fix_batch` | True / True | `CREATE UNIQUE INDEX pk_ai_fix_batch ON public.ai_fix_batch USING btree (id)` |

### `public.ai_fix_cache`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `cache_key` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `vuln_id` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `component_name` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `component_version` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `prompt_version` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `schema_version` | `integer` | NOT NULL | `—` | `none / none` |
| `remediation_prose` | `json` | NOT NULL | `—` | `none / none` |
| `upgrade_command` | `json` | NOT NULL | `—` | `none / none` |
| `decision_recommendation` | `json` | NOT NULL | `—` | `none / none` |
| `overall_confidence` | `character varying(16)` | NULL | `—` | `none / none` |
| `provider_used` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `model_used` | `character varying(256)` | NOT NULL | `—` | `none / none` |
| `total_cost_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `generated_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `last_accessed_at` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_ai_fix_cache` | p | `PRIMARY KEY (cache_key)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_ai_fix_cache_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_cache_expires_at ON public.ai_fix_cache USING btree (expires_at)` |
| `ix_ai_fix_cache_vuln_component` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_cache_vuln_component ON public.ai_fix_cache USING btree (vuln_id, component_name, component_version)` |
| `ix_ai_fix_cache_vuln_id` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_fix_cache_vuln_id ON public.ai_fix_cache USING btree (vuln_id)` |
| `pk_ai_fix_cache` | btree / True | `pk_ai_fix_cache` | True / True | `CREATE UNIQUE INDEX pk_ai_fix_cache ON public.ai_fix_cache USING btree (cache_key)` |

### `public.ai_provider_config`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `provider_name` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `enabled` | `boolean` | NULL | `—` | `none / none` |
| `default_model` | `character varying(256)` | NULL | `—` | `none / none` |
| `base_url` | `character varying(256)` | NULL | `—` | `none / none` |
| `max_concurrent` | `integer` | NULL | `—` | `none / none` |
| `rate_per_minute` | `double precision` | NULL | `—` | `none / none` |
| `notes` | `text` | NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NULL | `—` | `none / none` |
| `updated_by` | `character varying` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_ai_provider_config` | p | `PRIMARY KEY (provider_name)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `pk_ai_provider_config` | btree / True | `pk_ai_provider_config` | True / True | `CREATE UNIQUE INDEX pk_ai_provider_config ON public.ai_provider_config USING btree (provider_name)` |

### `public.ai_provider_credential`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.ai_provider_credential_id_seq'::regclass)` | `none / none` |
| `provider_name` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `label` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `api_key_encrypted` | `text` | NULL | `—` | `none / none` |
| `base_url` | `character varying(512)` | NULL | `—` | `none / none` |
| `default_model` | `character varying(256)` | NULL | `—` | `none / none` |
| `tier` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `is_default` | `boolean` | NOT NULL | `—` | `none / none` |
| `is_fallback` | `boolean` | NOT NULL | `—` | `none / none` |
| `enabled` | `boolean` | NOT NULL | `—` | `none / none` |
| `cost_per_1k_input_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `cost_per_1k_output_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `is_local` | `boolean` | NOT NULL | `—` | `none / none` |
| `max_concurrent` | `integer` | NULL | `—` | `none / none` |
| `rate_per_minute` | `double precision` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `last_test_at` | `character varying` | NULL | `—` | `none / none` |
| `last_test_success` | `boolean` | NULL | `—` | `none / none` |
| `last_test_error` | `text` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_ai_provider_credential_configuration_tenant` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE` | True / False / False |
| `pk_ai_provider_credential` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_ai_provider_credential_tenant_slot` | u | `UNIQUE (tenant_id, provider_name, label)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_ai_only_one_default` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX ix_ai_only_one_default ON public.ai_provider_credential USING btree (is_default) WHERE ((is_default = true) AND (tenant_id IS NULL))` |
| `ix_ai_only_one_fallback` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX ix_ai_only_one_fallback ON public.ai_provider_credential USING btree (is_fallback) WHERE ((is_fallback = true) AND (tenant_id IS NULL))` |
| `ix_ai_provider_credential_configuration_tenant` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_provider_credential_configuration_tenant ON public.ai_provider_credential USING btree (tenant_id)` |
| `ix_ai_provider_credential_id` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_provider_credential_id ON public.ai_provider_credential USING btree (id)` |
| `ix_ai_provider_credential_provider_name` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_provider_credential_provider_name ON public.ai_provider_credential USING btree (provider_name)` |
| `ix_ai_tenant_default` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX ix_ai_tenant_default ON public.ai_provider_credential USING btree (tenant_id) WHERE ((is_default = true) AND (tenant_id IS NOT NULL))` |
| `ix_ai_tenant_fallback` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX ix_ai_tenant_fallback ON public.ai_provider_credential USING btree (tenant_id) WHERE ((is_fallback = true) AND (tenant_id IS NOT NULL))` |
| `pk_ai_provider_credential` | btree / True | `pk_ai_provider_credential` | True / True | `CREATE UNIQUE INDEX pk_ai_provider_credential ON public.ai_provider_credential USING btree (id)` |
| `uq_ai_provider_credential_platform_slot` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_ai_provider_credential_platform_slot ON public.ai_provider_credential USING btree (provider_name, label) WHERE (tenant_id IS NULL)` |
| `uq_ai_provider_credential_tenant_slot` | btree / True | `uq_ai_provider_credential_tenant_slot` | True / True | `CREATE UNIQUE INDEX uq_ai_provider_credential_tenant_slot ON public.ai_provider_credential USING btree (tenant_id, provider_name, label)` |

### `public.ai_provider_model`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.ai_provider_model_id_seq'::regclass)` | `none / none` |
| `provider_credential_id` | `integer` | NOT NULL | `—` | `none / none` |
| `provider_name` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `provider_model_id` | `character varying(256)` | NOT NULL | `—` | `none / none` |
| `runtime_model_id` | `character varying(256)` | NOT NULL | `—` | `none / none` |
| `display_name` | `character varying(256)` | NULL | `—` | `none / none` |
| `is_available` | `boolean` | NULL | `—` | `none / none` |
| `is_enabled` | `boolean` | NOT NULL | `true` | `none / none` |
| `is_selected` | `boolean` | NOT NULL | `false` | `none / none` |
| `supports_chat` | `boolean` | NULL | `—` | `none / none` |
| `supports_structured_output` | `boolean` | NULL | `—` | `none / none` |
| `supports_streaming` | `boolean` | NULL | `—` | `none / none` |
| `supports_tools` | `boolean` | NULL | `—` | `none / none` |
| `context_window` | `integer` | NULL | `—` | `none / none` |
| `max_output_tokens` | `integer` | NULL | `—` | `none / none` |
| `discovery_source` | `character varying(24)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `first_discovered_at` | `character varying` | NULL | `—` | `none / none` |
| `last_discovered_at` | `character varying` | NULL | `—` | `none / none` |
| `last_verified_at` | `character varying` | NULL | `—` | `none / none` |
| `last_test_success` | `boolean` | NULL | `—` | `none / none` |
| `last_test_error` | `character varying(240)` | NULL | `—` | `none / none` |
| `raw_metadata` | `json` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_ai_provider_model_provider_credential_id_ai_provider_97cb` | f | `FOREIGN KEY (provider_credential_id) REFERENCES public.ai_provider_credential(id) ON DELETE CASCADE` | True / False / False |
| `pk_ai_provider_model` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_ai_provider_model_credential_provider_model` | u | `UNIQUE (provider_credential_id, provider_model_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_ai_provider_model_credential_available` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_provider_model_credential_available ON public.ai_provider_model USING btree (provider_credential_id, is_available)` |
| `ix_ai_provider_model_only_one_selected` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX ix_ai_provider_model_only_one_selected ON public.ai_provider_model USING btree (provider_credential_id) WHERE (is_selected = true)` |
| `ix_ai_provider_model_provider_credential_id` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_provider_model_provider_credential_id ON public.ai_provider_model USING btree (provider_credential_id)` |
| `ix_ai_provider_model_provider_name` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_provider_model_provider_name ON public.ai_provider_model USING btree (provider_name)` |
| `pk_ai_provider_model` | btree / True | `pk_ai_provider_model` | True / True | `CREATE UNIQUE INDEX pk_ai_provider_model ON public.ai_provider_model USING btree (id)` |
| `uq_ai_provider_model_credential_provider_model` | btree / True | `uq_ai_provider_model_credential_provider_model` | True / True | `CREATE UNIQUE INDEX uq_ai_provider_model_credential_provider_model ON public.ai_provider_model USING btree (provider_credential_id, provider_model_id)` |

### `public.ai_settings`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.ai_settings_scope_id_seq'::regclass)` | `none / none` |
| `feature_enabled` | `boolean` | NOT NULL | `—` | `none / none` |
| `kill_switch_active` | `boolean` | NOT NULL | `—` | `none / none` |
| `budget_per_request_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `budget_per_scan_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `budget_daily_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_by_user_id` | `character varying` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_ai_settings_configuration_tenant` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE` | True / False / False |
| `pk_ai_settings` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_ai_settings_tenant` | u | `UNIQUE (tenant_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_ai_settings_configuration_tenant` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_settings_configuration_tenant ON public.ai_settings USING btree (tenant_id)` |
| `pk_ai_settings` | btree / True | `pk_ai_settings` | True / True | `CREATE UNIQUE INDEX pk_ai_settings ON public.ai_settings USING btree (id)` |
| `uq_ai_settings_platform_slot` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_ai_settings_platform_slot ON public.ai_settings USING btree ((1)) WHERE (tenant_id IS NULL)` |
| `uq_ai_settings_tenant` | btree / True | `uq_ai_settings_tenant` | True / True | `CREATE UNIQUE INDEX uq_ai_settings_tenant ON public.ai_settings USING btree (tenant_id)` |

### `public.ai_usage_log`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.ai_usage_log_id_seq'::regclass)` | `none / none` |
| `request_id` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `provider` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `model` | `character varying(256)` | NOT NULL | `—` | `none / none` |
| `purpose` | `character varying(48)` | NOT NULL | `—` | `none / none` |
| `finding_cache_key` | `character varying(64)` | NULL | `—` | `none / none` |
| `input_tokens` | `integer` | NOT NULL | `—` | `none / none` |
| `output_tokens` | `integer` | NOT NULL | `—` | `none / none` |
| `cost_usd` | `double precision` | NOT NULL | `—` | `none / none` |
| `latency_ms` | `integer` | NOT NULL | `—` | `none / none` |
| `cache_hit` | `boolean` | NOT NULL | `—` | `none / none` |
| `error` | `text` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_ai_usage_log_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_ai_usage_log` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_ai_usage_log_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_created_at ON public.ai_usage_log USING btree (created_at)` |
| `ix_ai_usage_log_finding_cache_key` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_finding_cache_key ON public.ai_usage_log USING btree (finding_cache_key)` |
| `ix_ai_usage_log_id` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_id ON public.ai_usage_log USING btree (id)` |
| `ix_ai_usage_log_provider` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_provider ON public.ai_usage_log USING btree (provider)` |
| `ix_ai_usage_log_provider_created` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_provider_created ON public.ai_usage_log USING btree (provider, created_at)` |
| `ix_ai_usage_log_purpose` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_purpose ON public.ai_usage_log USING btree (purpose)` |
| `ix_ai_usage_log_purpose_created` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_purpose_created ON public.ai_usage_log USING btree (purpose, created_at)` |
| `ix_ai_usage_log_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_tenant_id ON public.ai_usage_log USING btree (tenant_id)` |
| `ix_ai_usage_log_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_ai_usage_log_tenant_identity ON public.ai_usage_log USING btree (tenant_id, id)` |
| `pk_ai_usage_log` | btree / True | `pk_ai_usage_log` | True / True | `CREATE UNIQUE INDEX pk_ai_usage_log ON public.ai_usage_log USING btree (id)` |

### `public.alembic_version`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `version_num` | `character varying(128)` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `alembic_version_pkc` | p | `PRIMARY KEY (version_num)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `alembic_version_pkc` | btree / True | `alembic_version_pkc` | True / True | `CREATE UNIQUE INDEX alembic_version_pkc ON public.alembic_version USING btree (version_num)` |

### `public.analysis_finding`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.analysis_finding_id_seq'::regclass)` | `none / none` |
| `analysis_run_id` | `integer` | NOT NULL | `—` | `none / none` |
| `component_id` | `integer` | NULL | `—` | `none / none` |
| `vuln_id` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `source` | `character varying(128)` | NULL | `—` | `none / none` |
| `title` | `character varying` | NULL | `—` | `none / none` |
| `description` | `text` | NULL | `—` | `none / none` |
| `severity` | `character varying(16)` | NULL | `—` | `none / none` |
| `score` | `double precision` | NULL | `—` | `none / none` |
| `vector` | `text` | NULL | `—` | `none / none` |
| `published_on` | `character varying` | NULL | `—` | `none / none` |
| `reference_url` | `text` | NULL | `—` | `none / none` |
| `cwe` | `text` | NULL | `—` | `none / none` |
| `cpe` | `character varying` | NULL | `—` | `none / none` |
| `component_name` | `text` | NULL | `—` | `none / none` |
| `component_version` | `text` | NULL | `—` | `none / none` |
| `fixed_versions` | `text` | NULL | `—` | `none / none` |
| `attack_vector` | `character varying(64)` | NULL | `—` | `none / none` |
| `cvss_version` | `character varying(16)` | NULL | `—` | `none / none` |
| `aliases` | `text` | NULL | `—` | `none / none` |
| `match_reason` | `character varying(255)` | NULL | `—` | `none / none` |
| `matched_range` | `text` | NULL | `—` | `none / none` |
| `match_confidence` | `double precision` | NULL | `—` | `none / none` |
| `match_strategy` | `character varying(64)` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `evidence_json` | `json` | NULL | `—` | `none / none` |
| `reconciliation_key` | `character varying(64)` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_analysis_finding_analysis_run_id_analysis_run` | f | `FOREIGN KEY (analysis_run_id) REFERENCES public.analysis_run(id)` | True / False / False |
| `fk_analysis_finding_component_id_sbom_component` | f | `FOREIGN KEY (component_id) REFERENCES public.sbom_component(id)` | True / False / False |
| `fk_analysis_finding_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_analysis_finding` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_analysis_finding_run_reconciliation` | u | `UNIQUE (analysis_run_id, reconciliation_key)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_analysis_finding_analysis_run_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_analysis_run_id ON public.analysis_finding USING btree (analysis_run_id)` |
| `ix_analysis_finding_component_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_component_id ON public.analysis_finding USING btree (component_id)` |
| `ix_analysis_finding_cpe` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_cpe ON public.analysis_finding USING btree (cpe)` |
| `ix_analysis_finding_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_deactivated ON public.analysis_finding USING btree (is_active) WHERE (is_active = false)` |
| `ix_analysis_finding_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_id ON public.analysis_finding USING btree (id)` |
| `ix_analysis_finding_match_reason` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_match_reason ON public.analysis_finding USING btree (match_reason)` |
| `ix_analysis_finding_match_strategy` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_match_strategy ON public.analysis_finding USING btree (match_strategy)` |
| `ix_analysis_finding_run_severity` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_run_severity ON public.analysis_finding USING btree (analysis_run_id, severity)` |
| `ix_analysis_finding_severity` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_severity ON public.analysis_finding USING btree (severity)` |
| `ix_analysis_finding_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_tenant_id ON public.analysis_finding USING btree (tenant_id)` |
| `ix_analysis_finding_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_tenant_identity ON public.analysis_finding USING btree (tenant_id, id)` |
| `ix_analysis_finding_vuln_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_finding_vuln_id ON public.analysis_finding USING btree (vuln_id)` |
| `pk_analysis_finding` | btree / True | `pk_analysis_finding` | True / True | `CREATE UNIQUE INDEX pk_analysis_finding ON public.analysis_finding USING btree (id)` |
| `uq_analysis_finding_run_reconciliation` | btree / True | `uq_analysis_finding_run_reconciliation` | True / True | `CREATE UNIQUE INDEX uq_analysis_finding_run_reconciliation ON public.analysis_finding USING btree (analysis_run_id, reconciliation_key)` |

### `public.analysis_run`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.analysis_run_id_seq'::regclass)` | `none / none` |
| `sbom_id` | `integer` | NOT NULL | `—` | `none / none` |
| `project_id` | `integer` | NULL | `—` | `none / none` |
| `product_id` | `integer` | NULL | `—` | `none / none` |
| `run_status` | `character varying` | NOT NULL | `—` | `none / none` |
| `sbom_name` | `character varying` | NULL | `—` | `none / none` |
| `source` | `character varying` | NOT NULL | `—` | `none / none` |
| `trigger_source` | `character varying(32)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `started_on` | `character varying` | NOT NULL | `—` | `none / none` |
| `completed_on` | `character varying` | NOT NULL | `—` | `none / none` |
| `duration_ms` | `integer` | NOT NULL | `—` | `none / none` |
| `total_components` | `integer` | NOT NULL | `—` | `none / none` |
| `components_with_cpe` | `integer` | NOT NULL | `—` | `none / none` |
| `total_findings` | `integer` | NOT NULL | `—` | `none / none` |
| `critical_count` | `integer` | NOT NULL | `—` | `none / none` |
| `high_count` | `integer` | NOT NULL | `—` | `none / none` |
| `medium_count` | `integer` | NOT NULL | `—` | `none / none` |
| `low_count` | `integer` | NOT NULL | `—` | `none / none` |
| `unknown_count` | `integer` | NOT NULL | `—` | `none / none` |
| `query_error_count` | `integer` | NOT NULL | `—` | `none / none` |
| `raw_report` | `text` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `is_current` | `boolean` | NOT NULL | `true` | `none / none` |
| `analysis_input_fingerprint` | `json` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_analysis_run_product_id_products` | f | `FOREIGN KEY (product_id) REFERENCES public.products(id)` | True / False / False |
| `fk_analysis_run_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id)` | True / False / False |
| `fk_analysis_run_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_analysis_run_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_analysis_run` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_analysis_run_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_deactivated ON public.analysis_run USING btree (is_active) WHERE (is_active = false)` |
| `ix_analysis_run_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_id ON public.analysis_run USING btree (id)` |
| `ix_analysis_run_is_current` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_is_current ON public.analysis_run USING btree (is_current)` |
| `ix_analysis_run_product_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_product_id ON public.analysis_run USING btree (product_id)` |
| `ix_analysis_run_project_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_project_id ON public.analysis_run USING btree (project_id)` |
| `ix_analysis_run_run_status` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_run_status ON public.analysis_run USING btree (run_status)` |
| `ix_analysis_run_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_sbom_id ON public.analysis_run USING btree (sbom_id)` |
| `ix_analysis_run_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_tenant_id ON public.analysis_run USING btree (tenant_id)` |
| `ix_analysis_run_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_tenant_identity ON public.analysis_run USING btree (tenant_id, id)` |
| `ix_analysis_run_trigger_source` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_run_trigger_source ON public.analysis_run USING btree (trigger_source)` |
| `pk_analysis_run` | btree / True | `pk_analysis_run` | True / True | `CREATE UNIQUE INDEX pk_analysis_run ON public.analysis_run USING btree (id)` |

### `public.analysis_schedule`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.analysis_schedule_id_seq'::regclass)` | `none / none` |
| `scope` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `project_id` | `integer` | NULL | `—` | `none / none` |
| `product_id` | `integer` | NULL | `—` | `none / none` |
| `sbom_id` | `integer` | NULL | `—` | `none / none` |
| `cadence` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `cron_expression` | `character varying(128)` | NULL | `—` | `none / none` |
| `day_of_week` | `integer` | NULL | `—` | `none / none` |
| `day_of_month` | `integer` | NULL | `—` | `none / none` |
| `hour_utc` | `integer` | NOT NULL | `—` | `none / none` |
| `timezone` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `enabled` | `boolean` | NOT NULL | `—` | `none / none` |
| `next_run_at` | `character varying` | NULL | `—` | `none / none` |
| `last_run_at` | `character varying` | NULL | `—` | `none / none` |
| `last_run_status` | `character varying(16)` | NULL | `—` | `none / none` |
| `last_run_id` | `integer` | NULL | `—` | `none / none` |
| `consecutive_failures` | `integer` | NOT NULL | `—` | `none / none` |
| `min_gap_minutes` | `integer` | NOT NULL | `—` | `none / none` |
| `created_on` | `character varying` | NULL | `—` | `none / none` |
| `created_by` | `character varying` | NULL | `—` | `none / none` |
| `modified_on` | `character varying` | NULL | `—` | `none / none` |
| `modified_by` | `character varying` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `mode` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `target_version_policy` | `character varying(32)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_analysis_schedule_ck_analysis_schedule_cadence` | c | `CHECK (cadence::text = ANY (ARRAY['<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text]))` | True / False / False |
| `ck_analysis_schedule_ck_analysis_schedule_dom_range` | c | `CHECK (day_of_month IS NULL OR day_of_month >= 1 AND day_of_month <= 28)` | True / False / False |
| `ck_analysis_schedule_ck_analysis_schedule_dow_range` | c | `CHECK (day_of_week IS NULL OR day_of_week >= 0 AND day_of_week <= 6)` | True / False / False |
| `ck_analysis_schedule_ck_analysis_schedule_hour_range` | c | `CHECK (hour_utc >= 0 AND hour_utc <= 23)` | True / False / False |
| `ck_analysis_schedule_ck_analysis_schedule_mode` | c | `CHECK (mode::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_analysis_schedule_ck_analysis_schedule_scope` | c | `CHECK (scope::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_analysis_schedule_ck_analysis_schedule_target` | c | `CHECK (scope::text = '<literal redacted>'::text AND project_id IS NOT NULL AND product_id IS NULL AND sbom_id IS NULL OR scope::text = '<literal redacted>'::text AND product_id IS NOT NULL AND project_id IS NULL AND sbom_id IS NULL OR scope::text = '<literal redacted>'::text AND sbom_id IS NOT NULL AND project_id IS NULL AND product_id IS NULL OR scope::text = '<literal redacted>'::text AND project_id IS NULL AND product_id IS NULL AND sbom_id IS NULL)` | True / False / False |
| `ck_analysis_schedule_ck_analysis_schedule_target_version_policy` | c | `CHECK (target_version_policy::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `fk_analysis_schedule_last_run_id_analysis_run` | f | `FOREIGN KEY (last_run_id) REFERENCES public.analysis_run(id) ON DELETE SET NULL` | True / False / False |
| `fk_analysis_schedule_product_id_products` | f | `FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE CASCADE` | True / False / False |
| `fk_analysis_schedule_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE` | True / False / False |
| `fk_analysis_schedule_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE CASCADE` | True / False / False |
| `fk_analysis_schedule_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_analysis_schedule` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_analysis_schedule_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_deactivated ON public.analysis_schedule USING btree (is_active) WHERE (is_active = false)` |
| `ix_analysis_schedule_due` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_due ON public.analysis_schedule USING btree (enabled, next_run_at)` |
| `ix_analysis_schedule_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_id ON public.analysis_schedule USING btree (id)` |
| `ix_analysis_schedule_next_run_at` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_next_run_at ON public.analysis_schedule USING btree (next_run_at)` |
| `ix_analysis_schedule_product_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_product_id ON public.analysis_schedule USING btree (product_id)` |
| `ix_analysis_schedule_project_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_project_id ON public.analysis_schedule USING btree (project_id)` |
| `ix_analysis_schedule_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_sbom_id ON public.analysis_schedule USING btree (sbom_id)` |
| `ix_analysis_schedule_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_tenant_id ON public.analysis_schedule USING btree (tenant_id)` |
| `ix_analysis_schedule_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_analysis_schedule_tenant_identity ON public.analysis_schedule USING btree (tenant_id, id)` |
| `pk_analysis_schedule` | btree / True | `pk_analysis_schedule` | True / True | `CREATE UNIQUE INDEX pk_analysis_schedule ON public.analysis_schedule USING btree (id)` |
| `uq_analysis_schedule_tenant` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_analysis_schedule_tenant ON public.analysis_schedule USING btree (tenant_id) WHERE (((scope)::text = '<literal redacted>'::text) AND is_active)` |

### `public.audit_log`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.audit_log_id_seq'::regclass)` | `none / none` |
| `user_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `action` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `target_kind` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `target_id` | `integer` | NULL | `—` | `none / none` |
| `detail` | `text` | NULL | `—` | `none / none` |
| `metadata_json` | `json` | NULL | `—` | `none / none` |
| `user_ref_id` | `integer` | NULL | `—` | `none / none` |
| `entity_type` | `character varying(128)` | NULL | `—` | `none / none` |
| `entity_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `old_value` | `json` | NULL | `—` | `none / none` |
| `new_value` | `json` | NULL | `—` | `none / none` |
| `ip_address` | `character varying(64)` | NULL | `—` | `none / none` |
| `user_agent` | `text` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_audit_log_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `fk_audit_log_user_ref_id_iam_users` | f | `FOREIGN KEY (user_ref_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `pk_audit_log` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_audit_log_action` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_action ON public.audit_log USING btree (action)` |
| `ix_audit_log_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_created_at ON public.audit_log USING btree (created_at)` |
| `ix_audit_log_entity_id` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_entity_id ON public.audit_log USING btree (entity_id)` |
| `ix_audit_log_entity_type` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_entity_type ON public.audit_log USING btree (entity_type)` |
| `ix_audit_log_id` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_id ON public.audit_log USING btree (id)` |
| `ix_audit_log_target_id` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_target_id ON public.audit_log USING btree (target_id)` |
| `ix_audit_log_target_kind` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_target_kind ON public.audit_log USING btree (target_kind)` |
| `ix_audit_log_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_tenant_id ON public.audit_log USING btree (tenant_id)` |
| `ix_audit_log_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_tenant_identity ON public.audit_log USING btree (tenant_id, id)` |
| `ix_audit_log_user_ref_id` | btree / False | `none` | True / True | `CREATE INDEX ix_audit_log_user_ref_id ON public.audit_log USING btree (user_ref_id)` |
| `pk_audit_log` | btree / True | `pk_audit_log` | True / True | `CREATE UNIQUE INDEX pk_audit_log ON public.audit_log USING btree (id)` |

### `public.authorization_audit_log`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.authorization_audit_log_id_seq'::regclass)` | `none / none` |
| `actor_user_id` | `integer` | NULL | `—` | `none / none` |
| `target_user_id` | `integer` | NULL | `—` | `none / none` |
| `target_membership_id` | `integer` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NULL | `—` | `none / none` |
| `action` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `outcome` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `old_value` | `json` | NULL | `—` | `none / none` |
| `new_value` | `json` | NULL | `—` | `none / none` |
| `correlation_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `detail` | `character varying(240)` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_authorization_audit_log_authorization_audit_outcome` | c | `CHECK (outcome::text = ANY (ARRAY['<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text]))` | True / False / False |
| `fk_authorization_audit_log_actor_user_id_iam_users` | f | `FOREIGN KEY (actor_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_authorization_audit_log_target_membership_id_tenant_users` | f | `FOREIGN KEY (target_membership_id) REFERENCES public.tenant_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_authorization_audit_log_target_user_id_iam_users` | f | `FOREIGN KEY (target_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_authorization_audit_log_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL` | True / False / False |
| `pk_authorization_audit_log` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_authorization_audit_log_action` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_action ON public.authorization_audit_log USING btree (action)` |
| `ix_authorization_audit_log_actor_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_actor_user_id ON public.authorization_audit_log USING btree (actor_user_id)` |
| `ix_authorization_audit_log_correlation_id` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_correlation_id ON public.authorization_audit_log USING btree (correlation_id)` |
| `ix_authorization_audit_log_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_created_at ON public.authorization_audit_log USING btree (created_at)` |
| `ix_authorization_audit_log_outcome` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_outcome ON public.authorization_audit_log USING btree (outcome)` |
| `ix_authorization_audit_log_target_membership_id` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_target_membership_id ON public.authorization_audit_log USING btree (target_membership_id)` |
| `ix_authorization_audit_log_target_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_target_user_id ON public.authorization_audit_log USING btree (target_user_id)` |
| `ix_authorization_audit_log_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_audit_log_tenant_id ON public.authorization_audit_log USING btree (tenant_id)` |
| `pk_authorization_audit_log` | btree / True | `pk_authorization_audit_log` | True / True | `CREATE UNIQUE INDEX pk_authorization_audit_log ON public.authorization_audit_log USING btree (id)` |

### `public.authorization_permissions`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.authorization_permissions_id_seq'::regclass)` | `none / none` |
| `code` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `name` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `description` | `text` | NULL | `—` | `none / none` |
| `scope` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `resource` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `action` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `is_system` | `boolean` | NOT NULL | `true` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_authorization_permissions_authorization_permission_c_6755` | c | `CHECK (length(TRIM(BOTH FROM code)) > 0)` | True / False / False |
| `ck_authorization_permissions_authorization_permission_c_d702` | c | `CHECK (code::text = lower(code::text) AND code::text !~~ '<literal redacted>'::text)` | True / False / False |
| `ck_authorization_permissions_authorization_permission_n_fa1b` | c | `CHECK (length(TRIM(BOTH FROM name)) > 0)` | True / False / False |
| `ck_authorization_permissions_authorization_permission_scope` | c | `CHECK (scope::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_authorization_permissions_authorization_permission_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `pk_authorization_permissions` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_authorization_permissions_code` | u | `UNIQUE (code)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_authorization_permissions_action` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_permissions_action ON public.authorization_permissions USING btree (action)` |
| `ix_authorization_permissions_code` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_permissions_code ON public.authorization_permissions USING btree (code)` |
| `ix_authorization_permissions_resource` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_permissions_resource ON public.authorization_permissions USING btree (resource)` |
| `ix_authorization_permissions_scope` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_permissions_scope ON public.authorization_permissions USING btree (scope)` |
| `ix_authorization_permissions_status` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_permissions_status ON public.authorization_permissions USING btree (status)` |
| `pk_authorization_permissions` | btree / True | `pk_authorization_permissions` | True / True | `CREATE UNIQUE INDEX pk_authorization_permissions ON public.authorization_permissions USING btree (id)` |
| `uq_authorization_permissions_code` | btree / True | `uq_authorization_permissions_code` | True / True | `CREATE UNIQUE INDEX uq_authorization_permissions_code ON public.authorization_permissions USING btree (code)` |

### `public.authorization_role_permissions`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.authorization_role_permissions_id_seq'::regclass)` | `none / none` |
| `role_id` | `integer` | NOT NULL | `—` | `none / none` |
| `permission_id` | `integer` | NOT NULL | `—` | `none / none` |
| `is_protected` | `boolean` | NOT NULL | `false` | `none / none` |
| `created_by_user_id` | `integer` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_authorization_role_permissions_created_by_user_id_iam_users` | f | `FOREIGN KEY (created_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_authorization_role_permissions_permission_id_authori_8d82` | f | `FOREIGN KEY (permission_id) REFERENCES public.authorization_permissions(id) ON DELETE RESTRICT` | True / False / False |
| `fk_authorization_role_permissions_role_id_authorization_roles` | f | `FOREIGN KEY (role_id) REFERENCES public.authorization_roles(id) ON DELETE RESTRICT` | True / False / False |
| `pk_authorization_role_permissions` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_authorization_role_permissions_role_permission` | u | `UNIQUE (role_id, permission_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_authorization_role_permissions_permission_id` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_role_permissions_permission_id ON public.authorization_role_permissions USING btree (permission_id)` |
| `ix_authorization_role_permissions_role_id` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_role_permissions_role_id ON public.authorization_role_permissions USING btree (role_id)` |
| `pk_authorization_role_permissions` | btree / True | `pk_authorization_role_permissions` | True / True | `CREATE UNIQUE INDEX pk_authorization_role_permissions ON public.authorization_role_permissions USING btree (id)` |
| `uq_authorization_role_permissions_role_permission` | btree / True | `uq_authorization_role_permissions_role_permission` | True / True | `CREATE UNIQUE INDEX uq_authorization_role_permissions_role_permission ON public.authorization_role_permissions USING btree (role_id, permission_id)` |

### `public.authorization_roles`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.authorization_roles_id_seq'::regclass)` | `none / none` |
| `code` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `name` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `description` | `text` | NULL | `—` | `none / none` |
| `scope` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `is_system` | `boolean` | NOT NULL | `true` | `none / none` |
| `is_assignable` | `boolean` | NOT NULL | `true` | `none / none` |
| `version` | `integer` | NOT NULL | `1` | `none / none` |
| `created_by_user_id` | `integer` | NULL | `—` | `none / none` |
| `updated_by_user_id` | `integer` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_authorization_roles_authorization_role_code_normalized` | c | `CHECK (code::text = upper(code::text))` | True / False / False |
| `ck_authorization_roles_authorization_role_code_not_blank` | c | `CHECK (length(TRIM(BOTH FROM code)) > 0)` | True / False / False |
| `ck_authorization_roles_authorization_role_name_not_blank` | c | `CHECK (length(TRIM(BOTH FROM name)) > 0)` | True / False / False |
| `ck_authorization_roles_authorization_role_scope` | c | `CHECK (scope::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_authorization_roles_authorization_role_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_authorization_roles_authorization_role_version` | c | `CHECK (version >= 1)` | True / False / False |
| `fk_authorization_roles_created_by_user_id_iam_users` | f | `FOREIGN KEY (created_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_authorization_roles_updated_by_user_id_iam_users` | f | `FOREIGN KEY (updated_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `pk_authorization_roles` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_authorization_roles_scope_code` | u | `UNIQUE (scope, code)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_authorization_roles_scope` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_roles_scope ON public.authorization_roles USING btree (scope)` |
| `ix_authorization_roles_status` | btree / False | `none` | True / True | `CREATE INDEX ix_authorization_roles_status ON public.authorization_roles USING btree (status)` |
| `pk_authorization_roles` | btree / True | `pk_authorization_roles` | True / True | `CREATE UNIQUE INDEX pk_authorization_roles ON public.authorization_roles USING btree (id)` |
| `uq_authorization_roles_scope_code` | btree / True | `uq_authorization_roles_scope_code` | True / True | `CREATE UNIQUE INDEX uq_authorization_roles_scope_code ON public.authorization_roles USING btree (scope, code)` |

### `public.compare_cache`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `cache_key` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `run_a_id` | `integer` | NOT NULL | `—` | `none / none` |
| `run_b_id` | `integer` | NOT NULL | `—` | `none / none` |
| `payload` | `json` | NOT NULL | `—` | `none / none` |
| `computed_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `schema_version` | `integer` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_compare_cache_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_compare_cache` | p | `PRIMARY KEY (cache_key)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_compare_cache_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_compare_cache_expires_at ON public.compare_cache USING btree (expires_at)` |
| `ix_compare_cache_run_a_id` | btree / False | `none` | True / True | `CREATE INDEX ix_compare_cache_run_a_id ON public.compare_cache USING btree (run_a_id)` |
| `ix_compare_cache_run_b_id` | btree / False | `none` | True / True | `CREATE INDEX ix_compare_cache_run_b_id ON public.compare_cache USING btree (run_b_id)` |
| `ix_compare_cache_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_compare_cache_tenant_id ON public.compare_cache USING btree (tenant_id)` |
| `ix_compare_cache_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_compare_cache_tenant_identity ON public.compare_cache USING btree (tenant_id, cache_key)` |
| `pk_compare_cache` | btree / True | `pk_compare_cache` | True / True | `CREATE UNIQUE INDEX pk_compare_cache ON public.compare_cache USING btree (cache_key)` |

### `public.component_lifecycle_cache`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.component_lifecycle_cache_id_seq'::regclass)` | `none / none` |
| `lookup_key` | `character varying` | NULL | `—` | `none / none` |
| `normalized_name` | `character varying` | NOT NULL | `—` | `none / none` |
| `normalized_version` | `character varying` | NULL | `—` | `none / none` |
| `ecosystem` | `character varying` | NULL | `—` | `none / none` |
| `purl` | `character varying` | NULL | `—` | `none / none` |
| `cpe` | `character varying` | NULL | `—` | `none / none` |
| `lifecycle_status` | `character varying` | NULL | `—` | `none / none` |
| `eos_date` | `character varying` | NULL | `—` | `none / none` |
| `eol_date` | `character varying` | NULL | `—` | `none / none` |
| `eof_date` | `character varying` | NULL | `—` | `none / none` |
| `deprecated` | `boolean` | NULL | `—` | `none / none` |
| `unsupported` | `boolean` | NULL | `—` | `none / none` |
| `maintenance_status` | `character varying` | NULL | `—` | `none / none` |
| `latest_version` | `character varying` | NULL | `—` | `none / none` |
| `latest_supported_version` | `character varying` | NULL | `—` | `none / none` |
| `recommended_version` | `character varying` | NULL | `—` | `none / none` |
| `recommendation` | `text` | NULL | `—` | `none / none` |
| `source_name` | `character varying` | NULL | `—` | `none / none` |
| `source_url` | `character varying` | NULL | `—` | `none / none` |
| `evidence_json` | `json` | NULL | `—` | `none / none` |
| `confidence` | `character varying` | NULL | `—` | `none / none` |
| `checked_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `is_stale` | `boolean` | NOT NULL | `—` | `none / none` |
| `configuration_namespace` | `character varying(128)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_component_lifecycle_cache` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_component_lifecycle_cache_identity` | u | `UNIQUE (configuration_namespace, normalized_name, normalized_version, ecosystem, purl)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_component_lifecycle_cache_checked_at` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_checked_at ON public.component_lifecycle_cache USING btree (checked_at)` |
| `ix_component_lifecycle_cache_cpe` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_cpe ON public.component_lifecycle_cache USING btree (cpe)` |
| `ix_component_lifecycle_cache_ecosystem` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_ecosystem ON public.component_lifecycle_cache USING btree (ecosystem)` |
| `ix_component_lifecycle_cache_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_expires_at ON public.component_lifecycle_cache USING btree (expires_at)` |
| `ix_component_lifecycle_cache_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_id ON public.component_lifecycle_cache USING btree (id)` |
| `ix_component_lifecycle_cache_lookup` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_lookup ON public.component_lifecycle_cache USING btree (ecosystem, normalized_name, normalized_version)` |
| `ix_component_lifecycle_cache_lookup_key` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_lookup_key ON public.component_lifecycle_cache USING btree (lookup_key)` |
| `ix_component_lifecycle_cache_normalized_name` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_normalized_name ON public.component_lifecycle_cache USING btree (normalized_name)` |
| `ix_component_lifecycle_cache_normalized_version` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_normalized_version ON public.component_lifecycle_cache USING btree (normalized_version)` |
| `ix_component_lifecycle_cache_purl` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_cache_purl ON public.component_lifecycle_cache USING btree (purl)` |
| `pk_component_lifecycle_cache` | btree / True | `pk_component_lifecycle_cache` | True / True | `CREATE UNIQUE INDEX pk_component_lifecycle_cache ON public.component_lifecycle_cache USING btree (id)` |
| `uq_component_lifecycle_cache_identity` | btree / True | `uq_component_lifecycle_cache_identity` | True / True | `CREATE UNIQUE INDEX uq_component_lifecycle_cache_identity ON public.component_lifecycle_cache USING btree (configuration_namespace, normalized_name, normalized_version, ecosystem, purl)` |

### `public.component_lifecycle_override_audit`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.component_lifecycle_override_audit_id_seq'::regclass)` | `none / none` |
| `component_id` | `integer` | NOT NULL | `—` | `none / none` |
| `old_value_json` | `json` | NULL | `—` | `none / none` |
| `new_value_json` | `json` | NULL | `—` | `none / none` |
| `reason` | `text` | NOT NULL | `—` | `none / none` |
| `evidence_url` | `character varying` | NULL | `—` | `none / none` |
| `changed_by` | `character varying` | NULL | `—` | `none / none` |
| `changed_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_component_lifecycle_override_audit_component_id_sbom_794b` | f | `FOREIGN KEY (component_id) REFERENCES public.sbom_component(id) ON DELETE CASCADE` | True / False / False |
| `fk_component_lifecycle_override_audit_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_component_lifecycle_override_audit` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_component_lifecycle_override_audit_changed_at` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_override_audit_changed_at ON public.component_lifecycle_override_audit USING btree (changed_at)` |
| `ix_component_lifecycle_override_audit_changed_by` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_override_audit_changed_by ON public.component_lifecycle_override_audit USING btree (changed_by)` |
| `ix_component_lifecycle_override_audit_component_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_override_audit_component_id ON public.component_lifecycle_override_audit USING btree (component_id)` |
| `ix_component_lifecycle_override_audit_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_override_audit_id ON public.component_lifecycle_override_audit USING btree (id)` |
| `ix_component_lifecycle_override_audit_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_override_audit_tenant_id ON public.component_lifecycle_override_audit USING btree (tenant_id)` |
| `ix_component_lifecycle_override_audit_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_component_lifecycle_override_audit_tenant_identity ON public.component_lifecycle_override_audit USING btree (tenant_id, id)` |
| `pk_component_lifecycle_override_audit` | btree / True | `pk_component_lifecycle_override_audit` | True / True | `CREATE UNIQUE INDEX pk_component_lifecycle_override_audit ON public.component_lifecycle_override_audit USING btree (id)` |

### `public.component_purpose_metadata`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.component_purpose_metadata_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NULL | `—` | `none / none` |
| `family_key` | `character varying(512)` | NOT NULL | `—` | `none / none` |
| `source` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `purpose` | `text` | NULL | `—` | `none / none` |
| `primary_use_case` | `character varying(255)` | NULL | `—` | `none / none` |
| `category` | `character varying(128)` | NULL | `—` | `none / none` |
| `confidence` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `provenance_json` | `json` | NULL | `—` | `none / none` |
| `row_version` | `integer` | NOT NULL | `1` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `created_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `updated_by` | `character varying(128)` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_component_purpose_metadata_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE` | True / False / False |
| `pk_component_purpose_metadata` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_component_purpose_tenant_family_source` | u | `UNIQUE (tenant_id, family_key, source)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_component_purpose_metadata_category` | btree / False | `none` | True / True | `CREATE INDEX ix_component_purpose_metadata_category ON public.component_purpose_metadata USING btree (category)` |
| `ix_component_purpose_metadata_family_key` | btree / False | `none` | True / True | `CREATE INDEX ix_component_purpose_metadata_family_key ON public.component_purpose_metadata USING btree (family_key)` |
| `ix_component_purpose_metadata_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_purpose_metadata_tenant_id ON public.component_purpose_metadata USING btree (tenant_id)` |
| `pk_component_purpose_metadata` | btree / True | `pk_component_purpose_metadata` | True / True | `CREATE UNIQUE INDEX pk_component_purpose_metadata ON public.component_purpose_metadata USING btree (id)` |
| `uq_component_purpose_platform_family_source` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_component_purpose_platform_family_source ON public.component_purpose_metadata USING btree (family_key, source) WHERE (tenant_id IS NULL)` |
| `uq_component_purpose_tenant_family_source` | btree / True | `uq_component_purpose_tenant_family_source` | True / True | `CREATE UNIQUE INDEX uq_component_purpose_tenant_family_source ON public.component_purpose_metadata USING btree (tenant_id, family_key, source)` |

### `public.component_recommendation`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.component_recommendation_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `project_id` | `integer` | NULL | `—` | `none / none` |
| `product_id` | `integer` | NULL | `—` | `none / none` |
| `sbom_id` | `integer` | NULL | `—` | `none / none` |
| `scope_key` | `integer` | NOT NULL | `0` | `none / none` |
| `source_component_id` | `integer` | NULL | `—` | `none / none` |
| `source_canonical_key` | `character varying(80)` | NOT NULL | `—` | `none / none` |
| `source_family_key` | `character varying(512)` | NULL | `—` | `none / none` |
| `source_name` | `character varying(512)` | NOT NULL | `—` | `none / none` |
| `source_version` | `character varying(255)` | NULL | `—` | `none / none` |
| `source_ecosystem` | `character varying(64)` | NULL | `—` | `none / none` |
| `trigger_type` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `trigger_evidence_json` | `json` | NULL | `—` | `none / none` |
| `status` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `discovery_summary_json` | `json` | NULL | `—` | `none / none` |
| `evaluation_error` | `text` | NULL | `—` | `none / none` |
| `correlation_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `created_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `evaluated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `row_version` | `integer` | NOT NULL | `1` | `none / none` |
| `recommended_candidate_id` | `integer` | NULL | `—` | `none / none` |
| `accepted_candidate_id` | `integer` | NULL | `—` | `none / none` |
| `last_decision` | `character varying(32)` | NULL | `—` | `none / none` |
| `last_decision_reason` | `text` | NULL | `—` | `none / none` |
| `decided_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `decided_at` | `timestamp with time zone` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_component_recommendation_product_id_products` | f | `FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE SET NULL` | True / False / False |
| `fk_component_recommendation_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE SET NULL` | True / False / False |
| `fk_component_recommendation_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE SET NULL` | True / False / False |
| `fk_component_recommendation_source_component_id_sbom_component` | f | `FOREIGN KEY (source_component_id) REFERENCES public.sbom_component(id) ON DELETE SET NULL` | True / False / False |
| `fk_component_recommendation_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_component_recommendation` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_component_recommendation_correlation_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_correlation_id ON public.component_recommendation USING btree (correlation_id)` |
| `ix_component_recommendation_product_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_product_id ON public.component_recommendation USING btree (product_id)` |
| `ix_component_recommendation_project_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_project_id ON public.component_recommendation USING btree (project_id)` |
| `ix_component_recommendation_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_sbom_id ON public.component_recommendation USING btree (sbom_id)` |
| `ix_component_recommendation_source_canonical_key` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_source_canonical_key ON public.component_recommendation USING btree (source_canonical_key)` |
| `ix_component_recommendation_source_family_key` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_source_family_key ON public.component_recommendation USING btree (source_family_key)` |
| `ix_component_recommendation_status` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_status ON public.component_recommendation USING btree (status)` |
| `ix_component_recommendation_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_tenant_id ON public.component_recommendation USING btree (tenant_id)` |
| `ix_component_recommendation_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_tenant_identity ON public.component_recommendation USING btree (tenant_id, id)` |
| `ix_component_recommendation_tenant_status` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_tenant_status ON public.component_recommendation USING btree (tenant_id, status)` |
| `pk_component_recommendation` | btree / True | `pk_component_recommendation` | True / True | `CREATE UNIQUE INDEX pk_component_recommendation ON public.component_recommendation USING btree (id)` |
| `uq_component_recommendation_open` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_component_recommendation_open ON public.component_recommendation USING btree (tenant_id, source_canonical_key, scope_key, trigger_type) WHERE ((status)::text = ANY ((ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying])::text[]))` |

### `public.component_recommendation_candidate`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.component_recommendation_candidate_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `recommendation_id` | `integer` | NOT NULL | `—` | `none / none` |
| `candidate_kind` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `source_type` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `candidate_canonical_key` | `character varying(80)` | NULL | `—` | `none / none` |
| `name` | `character varying(512)` | NOT NULL | `—` | `none / none` |
| `version` | `character varying(255)` | NULL | `—` | `none / none` |
| `purl` | `character varying(1024)` | NULL | `—` | `none / none` |
| `ecosystem` | `character varying(64)` | NULL | `—` | `none / none` |
| `rank` | `integer` | NOT NULL | `—` | `none / none` |
| `evidence_sources_json` | `json` | NOT NULL | `—` | `none / none` |
| `reasons_json` | `json` | NOT NULL | `—` | `none / none` |
| `limitations_json` | `json` | NOT NULL | `—` | `none / none` |
| `evaluation_json` | `json` | NOT NULL | `—` | `none / none` |
| `score` | `double precision` | NULL | `—` | `none / none` |
| `confidence` | `character varying(32)` | NULL | `—` | `none / none` |
| `blocked` | `boolean` | NOT NULL | `false` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_component_recommendation_candidate_recommendation_id_4ea3` | f | `FOREIGN KEY (recommendation_id) REFERENCES public.component_recommendation(id) ON DELETE CASCADE` | True / False / False |
| `fk_component_recommendation_candidate_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_component_recommendation_candidate` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_component_recommendation_candidate_recommendation_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_candidate_recommendation_id ON public.component_recommendation_candidate USING btree (recommendation_id)` |
| `ix_component_recommendation_candidate_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_candidate_tenant_id ON public.component_recommendation_candidate USING btree (tenant_id)` |
| `ix_component_recommendation_candidate_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_candidate_tenant_identity ON public.component_recommendation_candidate USING btree (tenant_id, id)` |
| `pk_component_recommendation_candidate` | btree / True | `pk_component_recommendation_candidate` | True / True | `CREATE UNIQUE INDEX pk_component_recommendation_candidate ON public.component_recommendation_candidate USING btree (id)` |

### `public.component_recommendation_compatibility_check`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.component_recommendation_compatibility_check_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `candidate_id` | `integer` | NOT NULL | `—` | `none / none` |
| `check_type` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `result` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `blocking` | `boolean` | NOT NULL | `false` | `none / none` |
| `reason` | `text` | NOT NULL | `—` | `none / none` |
| `limitation` | `character varying(64)` | NULL | `—` | `none / none` |
| `evidence_json` | `json` | NOT NULL | `—` | `none / none` |
| `evaluated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_component_recommendation_compatibility_check_candida_e9cc` | f | `FOREIGN KEY (candidate_id) REFERENCES public.component_recommendation_candidate(id) ON DELETE CASCADE` | True / False / False |
| `fk_component_recommendation_compatibility_check_tenant__39ac` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_component_recommendation_compatibility_check` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_component_recommendation_compatibility_check_candidate_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_compatibility_check_candidate_id ON public.component_recommendation_compatibility_check USING btree (candidate_id)` |
| `ix_component_recommendation_compatibility_check_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_compatibility_check_tenant_id ON public.component_recommendation_compatibility_check USING btree (tenant_id)` |
| `ix_component_recommendation_compatibility_check_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_compatibility_check_tenant_identity ON public.component_recommendation_compatibility_check USING btree (tenant_id, id)` |
| `pk_component_recommendation_compatibility_check` | btree / True | `pk_component_recommendation_compatibility_check` | True / True | `CREATE UNIQUE INDEX pk_component_recommendation_compatibility_check ON public.component_recommendation_compatibility_check USING btree (id)` |

### `public.component_recommendation_event`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.component_recommendation_event_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `recommendation_id` | `integer` | NULL | `—` | `none / none` |
| `candidate_id` | `integer` | NULL | `—` | `none / none` |
| `candidate_json` | `json` | NULL | `—` | `none / none` |
| `action` | `character varying(48)` | NOT NULL | `—` | `none / none` |
| `decision` | `character varying(32)` | NULL | `—` | `none / none` |
| `actor` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `actor_user_id` | `integer` | NULL | `—` | `none / none` |
| `reason` | `text` | NULL | `—` | `none / none` |
| `old_status` | `character varying(32)` | NULL | `—` | `none / none` |
| `new_status` | `character varying(32)` | NULL | `—` | `none / none` |
| `policy_versions_json` | `json` | NULL | `—` | `none / none` |
| `score` | `double precision` | NULL | `—` | `none / none` |
| `confidence` | `character varying(32)` | NULL | `—` | `none / none` |
| `evidence_refs_json` | `json` | NULL | `—` | `none / none` |
| `details_json` | `json` | NULL | `—` | `none / none` |
| `correlation_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `source` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_component_recommendation_event_recommendation_id_com_f423` | f | `FOREIGN KEY (recommendation_id) REFERENCES public.component_recommendation(id)` | True / False / False |
| `fk_component_recommendation_event_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_component_recommendation_event` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_component_recommendation_event_action` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_event_action ON public.component_recommendation_event USING btree (action)` |
| `ix_component_recommendation_event_correlation_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_event_correlation_id ON public.component_recommendation_event USING btree (correlation_id)` |
| `ix_component_recommendation_event_recommendation_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_event_recommendation_id ON public.component_recommendation_event USING btree (recommendation_id)` |
| `ix_component_recommendation_event_tenant_created` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_event_tenant_created ON public.component_recommendation_event USING btree (tenant_id, created_at)` |
| `ix_component_recommendation_event_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_event_tenant_id ON public.component_recommendation_event USING btree (tenant_id)` |
| `ix_component_recommendation_event_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_event_tenant_identity ON public.component_recommendation_event USING btree (tenant_id, id)` |
| `pk_component_recommendation_event` | btree / True | `pk_component_recommendation_event` | True / True | `CREATE UNIQUE INDEX pk_component_recommendation_event ON public.component_recommendation_event USING btree (id)` |

### `public.component_recommendation_factor`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.component_recommendation_factor_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `candidate_id` | `integer` | NOT NULL | `—` | `none / none` |
| `factor` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `raw_value_json` | `json` | NULL | `—` | `none / none` |
| `normalized_value` | `double precision` | NULL | `—` | `none / none` |
| `weight` | `double precision` | NOT NULL | `—` | `none / none` |
| `contribution` | `double precision` | NOT NULL | `—` | `none / none` |
| `missing_data_treatment` | `character varying(16)` | NULL | `—` | `none / none` |
| `evidence_source` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `evidence_at` | `character varying(64)` | NULL | `—` | `none / none` |
| `policy_version_id` | `integer` | NULL | `—` | `none / none` |
| `policy_version_label` | `character varying(64)` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_component_recommendation_factor_candidate_id_compone_6850` | f | `FOREIGN KEY (candidate_id) REFERENCES public.component_recommendation_candidate(id) ON DELETE CASCADE` | True / False / False |
| `fk_component_recommendation_factor_policy_version_id_ad_151c` | f | `FOREIGN KEY (policy_version_id) REFERENCES public.advisor_policy_version(id)` | True / False / False |
| `fk_component_recommendation_factor_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_component_recommendation_factor` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_component_recommendation_factor_candidate_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_factor_candidate_id ON public.component_recommendation_factor USING btree (candidate_id)` |
| `ix_component_recommendation_factor_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_factor_tenant_id ON public.component_recommendation_factor USING btree (tenant_id)` |
| `ix_component_recommendation_factor_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_component_recommendation_factor_tenant_identity ON public.component_recommendation_factor USING btree (tenant_id, id)` |
| `pk_component_recommendation_factor` | btree / True | `pk_component_recommendation_factor` | True / True | `CREATE UNIQUE INDEX pk_component_recommendation_factor ON public.component_recommendation_factor USING btree (id)` |

### `public.cve_cache`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `cve_id` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `payload` | `json` | NOT NULL | `—` | `none / none` |
| `sources_used` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `fetched_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `fetch_error` | `text` | NULL | `—` | `none / none` |
| `schema_version` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_cve_cache` | p | `PRIMARY KEY (cve_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_cve_cache_cve_id` | btree / False | `none` | True / True | `CREATE INDEX ix_cve_cache_cve_id ON public.cve_cache USING btree (cve_id)` |
| `ix_cve_cache_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_cve_cache_expires_at ON public.cve_cache USING btree (expires_at)` |
| `pk_cve_cache` | btree / True | `pk_cve_cache` | True / True | `CREATE UNIQUE INDEX pk_cve_cache ON public.cve_cache USING btree (cve_id)` |

### `public.cves`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `cve_id` | `text` | NOT NULL | `—` | `none / none` |
| `last_modified` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `published` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `vuln_status` | `text` | NOT NULL | `—` | `none / none` |
| `description_en` | `text` | NULL | `—` | `none / none` |
| `score_v40` | `double precision` | NULL | `—` | `none / none` |
| `score_v31` | `double precision` | NULL | `—` | `none / none` |
| `score_v2` | `double precision` | NULL | `—` | `none / none` |
| `severity_text` | `character varying(32)` | NULL | `—` | `none / none` |
| `vector_string` | `text` | NULL | `—` | `none / none` |
| `aliases` | `jsonb` | NOT NULL | `'<literal redacted>'::jsonb` | `none / none` |
| `cpe_match` | `jsonb` | NOT NULL | `'<literal redacted>'::jsonb` | `none / none` |
| `references` | `jsonb` | NOT NULL | `'<literal redacted>'::jsonb` | `none / none` |
| `data` | `jsonb` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `now()` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `cves_pkey` | p | `PRIMARY KEY (cve_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `cves_pkey` | btree / True | `cves_pkey` | True / True | `CREATE UNIQUE INDEX cves_pkey ON public.cves USING btree (cve_id)` |
| `ix_cves_cpe_match_gin` | gin / False | `none` | True / True | `CREATE INDEX ix_cves_cpe_match_gin ON public.cves USING gin (cpe_match jsonb_path_ops)` |
| `ix_cves_last_modified` | btree / False | `none` | True / True | `CREATE INDEX ix_cves_last_modified ON public.cves USING btree (last_modified)` |
| `ix_cves_vuln_status` | btree / False | `none` | True / True | `CREATE INDEX ix_cves_vuln_status ON public.cves USING btree (vuln_status)` |

### `public.email_verification_tokens`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.email_verification_tokens_id_seq'::regclass)` | `none / none` |
| `user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `token_hash` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `email_snapshot` | `character varying(320)` | NOT NULL | `—` | `none / none` |
| `expires_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `consumed_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `invalidated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `invalidation_reason` | `character varying(64)` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `created_by_ip_hash` | `character varying(64)` | NULL | `—` | `none / none` |
| `consumed_by_ip_hash` | `character varying(64)` | NULL | `—` | `none / none` |
| `correlation_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `delivery_status` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `delivery_attempted_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `delivery_error_code` | `character varying(64)` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_email_verification_tokens_ck_email_verification_toke_1c56` | c | `CHECK (consumed_at IS NULL OR consumed_at >= created_at)` | True / False / False |
| `ck_email_verification_tokens_ck_email_verification_toke_39e0` | c | `CHECK (delivery_status::text = ANY (ARRAY['<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text]))` | True / False / False |
| `ck_email_verification_tokens_ck_email_verification_toke_46d4` | c | `CHECK (expires_at > created_at)` | True / False / False |
| `ck_email_verification_tokens_ck_email_verification_toke_d99d` | c | `CHECK (invalidated_at IS NULL OR invalidated_at >= created_at)` | True / False / False |
| `fk_email_verification_tokens_user_id_iam_users` | f | `FOREIGN KEY (user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE` | True / False / False |
| `pk_email_verification_tokens` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_email_verification_tokens_token_hash` | u | `UNIQUE (token_hash)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_email_verification_tokens_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_email_verification_tokens_expires_at ON public.email_verification_tokens USING btree (expires_at)` |
| `ix_email_verification_tokens_user_consumed` | btree / False | `none` | True / True | `CREATE INDEX ix_email_verification_tokens_user_consumed ON public.email_verification_tokens USING btree (user_id, consumed_at)` |
| `ix_email_verification_tokens_user_created` | btree / False | `none` | True / True | `CREATE INDEX ix_email_verification_tokens_user_created ON public.email_verification_tokens USING btree (user_id, created_at)` |
| `ix_email_verification_tokens_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_email_verification_tokens_user_id ON public.email_verification_tokens USING btree (user_id)` |
| `pk_email_verification_tokens` | btree / True | `pk_email_verification_tokens` | True / True | `CREATE UNIQUE INDEX pk_email_verification_tokens ON public.email_verification_tokens USING btree (id)` |
| `uq_email_verification_tokens_active_user` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_email_verification_tokens_active_user ON public.email_verification_tokens USING btree (user_id) WHERE ((consumed_at IS NULL) AND (invalidated_at IS NULL))` |
| `uq_email_verification_tokens_token_hash` | btree / True | `uq_email_verification_tokens_token_hash` | True / True | `CREATE UNIQUE INDEX uq_email_verification_tokens_token_hash ON public.email_verification_tokens USING btree (token_hash)` |

### `public.epss_score`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `cve_id` | `character varying` | NOT NULL | `—` | `none / none` |
| `epss` | `double precision` | NOT NULL | `—` | `none / none` |
| `percentile` | `double precision` | NULL | `—` | `none / none` |
| `score_date` | `character varying` | NULL | `—` | `none / none` |
| `refreshed_at` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_epss_score` | p | `PRIMARY KEY (cve_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_epss_score_cve_id` | btree / False | `none` | True / True | `CREATE INDEX ix_epss_score_cve_id ON public.epss_score USING btree (cve_id)` |
| `pk_epss_score` | btree / True | `pk_epss_score` | True / True | `CREATE UNIQUE INDEX pk_epss_score ON public.epss_score USING btree (cve_id)` |

### `public.iam_users`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.iam_users_id_seq'::regclass)` | `none / none` |
| `external_iam_user_id` | `character varying(255)` | NULL | `—` | `none / none` |
| `email` | `character varying(320)` | NULL | `—` | `none / none` |
| `display_name` | `character varying(255)` | NULL | `—` | `none / none` |
| `status` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `last_login_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `external_issuer` | `character varying(512)` | NULL | `—` | `none / none` |
| `external_subject` | `character varying(255)` | NULL | `—` | `none / none` |
| `employee_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `user_principal_name` | `character varying(320)` | NULL | `—` | `none / none` |
| `department` | `character varying(255)` | NULL | `—` | `none / none` |
| `email_verified` | `boolean` | NOT NULL | `false` | `none / none` |
| `email_verified_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `verification_required` | `boolean` | NOT NULL | `true` | `none / none` |
| `last_claim_sync_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `first_name` | `character varying(255)` | NULL | `—` | `none / none` |
| `last_name` | `character varying(255)` | NULL | `—` | `none / none` |
| `phone` | `character varying(64)` | NULL | `—` | `none / none` |
| `normalized_email` | `character varying(320)` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_iam_users_email_verification_timestamp` | c | `CHECK (email_verified = false OR email_verified_at IS NOT NULL)` | True / False / False |
| `ck_iam_users_external_issuer_not_blank` | c | `CHECK (external_issuer IS NULL OR length(TRIM(BOTH FROM external_issuer)) > 0)` | True / False / False |
| `ck_iam_users_external_subject_not_blank` | c | `CHECK (external_subject IS NULL OR length(TRIM(BOTH FROM external_subject)) > 0)` | True / False / False |
| `ck_iam_users_iam_user_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `pk_iam_users` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_iam_users_external_iam_user_id` | u | `UNIQUE (external_iam_user_id)` | True / False / False |
| `uq_iam_users_external_identity` | u | `UNIQUE (external_issuer, external_subject)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_iam_users_email` | btree / False | `none` | True / True | `CREATE INDEX ix_iam_users_email ON public.iam_users USING btree (email)` |
| `ix_iam_users_employee_id` | btree / False | `none` | True / True | `CREATE INDEX ix_iam_users_employee_id ON public.iam_users USING btree (employee_id)` |
| `ix_iam_users_external_iam_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_iam_users_external_iam_user_id ON public.iam_users USING btree (external_iam_user_id)` |
| `ix_iam_users_normalized_email` | btree / False | `none` | True / True | `CREATE INDEX ix_iam_users_normalized_email ON public.iam_users USING btree (normalized_email)` |
| `ix_iam_users_user_principal_name` | btree / False | `none` | True / True | `CREATE INDEX ix_iam_users_user_principal_name ON public.iam_users USING btree (user_principal_name)` |
| `ix_iam_users_verification_status` | btree / False | `none` | True / True | `CREATE INDEX ix_iam_users_verification_status ON public.iam_users USING btree (verification_required, status)` |
| `pk_iam_users` | btree / True | `pk_iam_users` | True / True | `CREATE UNIQUE INDEX pk_iam_users ON public.iam_users USING btree (id)` |
| `uq_iam_users_external_iam_user_id` | btree / True | `uq_iam_users_external_iam_user_id` | True / True | `CREATE UNIQUE INDEX uq_iam_users_external_iam_user_id ON public.iam_users USING btree (external_iam_user_id)` |
| `uq_iam_users_external_identity` | btree / True | `uq_iam_users_external_identity` | True / True | `CREATE UNIQUE INDEX uq_iam_users_external_identity ON public.iam_users USING btree (external_issuer, external_subject)` |

### `public.kev_vulnerabilities`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `cve_id` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `vendor_project` | `character varying(255)` | NULL | `—` | `none / none` |
| `product` | `character varying(255)` | NULL | `—` | `none / none` |
| `vulnerability_name` | `text` | NULL | `—` | `none / none` |
| `date_added` | `character varying(10)` | NULL | `—` | `none / none` |
| `short_description` | `text` | NULL | `—` | `none / none` |
| `required_action` | `text` | NULL | `—` | `none / none` |
| `due_date` | `character varying(10)` | NULL | `—` | `none / none` |
| `known_ransomware_campaign_use` | `character varying(32)` | NULL | `—` | `none / none` |
| `notes` | `text` | NULL | `—` | `none / none` |
| `cwes` | `json` | NULL | `—` | `none / none` |
| `catalog_version` | `character varying(32)` | NULL | `—` | `none / none` |
| `catalog_date_released` | `character varying(64)` | NULL | `—` | `none / none` |
| `refreshed_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `first_seen_at` | `character varying` | NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_kev_vulnerabilities` | p | `PRIMARY KEY (cve_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_kev_vulnerabilities_cve_id` | btree / False | `none` | True / True | `CREATE INDEX ix_kev_vulnerabilities_cve_id ON public.kev_vulnerabilities USING btree (cve_id)` |
| `ix_kev_vulnerabilities_date_added` | btree / False | `none` | True / True | `CREATE INDEX ix_kev_vulnerabilities_date_added ON public.kev_vulnerabilities USING btree (date_added)` |
| `ix_kev_vulnerabilities_ransomware` | btree / False | `none` | True / True | `CREATE INDEX ix_kev_vulnerabilities_ransomware ON public.kev_vulnerabilities USING btree (known_ransomware_campaign_use)` |
| `pk_kev_vulnerabilities` | btree / True | `pk_kev_vulnerabilities` | True / True | `CREATE UNIQUE INDEX pk_kev_vulnerabilities ON public.kev_vulnerabilities USING btree (cve_id)` |

### `public.lifecycle_provider_configs`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.lifecycle_provider_configs_id_seq'::regclass)` | `none / none` |
| `provider_key` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `display_name` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `provider_type` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `enabled` | `boolean` | NOT NULL | `—` | `none / none` |
| `priority` | `integer` | NOT NULL | `—` | `none / none` |
| `base_url` | `character varying(512)` | NULL | `—` | `none / none` |
| `feed_urls_json` | `json` | NULL | `—` | `none / none` |
| `config_json` | `json` | NULL | `—` | `none / none` |
| `timeout_seconds` | `integer` | NOT NULL | `—` | `none / none` |
| `max_retries` | `integer` | NOT NULL | `—` | `none / none` |
| `circuit_breaker_enabled` | `boolean` | NOT NULL | `—` | `none / none` |
| `cache_ttl_known_days` | `integer` | NULL | `—` | `none / none` |
| `cache_ttl_unknown_hours` | `integer` | NULL | `—` | `none / none` |
| `cache_ttl_failure_minutes` | `integer` | NULL | `—` | `none / none` |
| `cache_ttl_deprecated_days` | `integer` | NULL | `—` | `none / none` |
| `last_success_at` | `character varying` | NULL | `—` | `none / none` |
| `last_failure_at` | `character varying` | NULL | `—` | `none / none` |
| `last_failure_message` | `text` | NULL | `—` | `none / none` |
| `health_status` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_by_user_id` | `integer` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NULL | `—` | `none / none` |
| `last_probe_json` | `json` | NULL | `—` | `none / none` |
| `last_lookup_at` | `character varying` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_lifecycle_provider_configs_ck_lifecycle_provider_con_1000` | c | `CHECK (max_retries >= 0 AND max_retries <= 10)` | True / False / False |
| `ck_lifecycle_provider_configs_ck_lifecycle_provider_con_5331` | c | `CHECK (timeout_seconds >= 1 AND timeout_seconds <= 60)` | True / False / False |
| `ck_lifecycle_provider_configs_ck_lifecycle_provider_con_a0a3` | c | `CHECK (health_status::text = ANY (ARRAY['<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text]))` | True / False / False |
| `ck_lifecycle_provider_configs_ck_lifecycle_provider_con_ef01` | c | `CHECK (priority >= 1 AND priority <= 1000)` | True / False / False |
| `fk_lifecycle_provider_configs_configuration_tenant` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE` | True / False / False |
| `fk_lifecycle_provider_configs_updated_by_user_id_iam_users` | f | `FOREIGN KEY (updated_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `pk_lifecycle_provider_configs` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_lifecycle_provider_configs_tenant_slot` | u | `UNIQUE (tenant_id, provider_key)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_lifecycle_provider_configs_configuration_tenant` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_configs_configuration_tenant ON public.lifecycle_provider_configs USING btree (tenant_id)` |
| `ix_lifecycle_provider_configs_enabled_priority` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_configs_enabled_priority ON public.lifecycle_provider_configs USING btree (enabled, priority)` |
| `ix_lifecycle_provider_configs_health_status` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_configs_health_status ON public.lifecycle_provider_configs USING btree (health_status)` |
| `ix_lifecycle_provider_configs_id` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_configs_id ON public.lifecycle_provider_configs USING btree (id)` |
| `ix_lifecycle_provider_configs_provider_type` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_configs_provider_type ON public.lifecycle_provider_configs USING btree (provider_type)` |
| `pk_lifecycle_provider_configs` | btree / True | `pk_lifecycle_provider_configs` | True / True | `CREATE UNIQUE INDEX pk_lifecycle_provider_configs ON public.lifecycle_provider_configs USING btree (id)` |
| `uq_lifecycle_provider_configs_platform_slot` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_lifecycle_provider_configs_platform_slot ON public.lifecycle_provider_configs USING btree (provider_key) WHERE (tenant_id IS NULL)` |
| `uq_lifecycle_provider_configs_tenant_slot` | btree / True | `uq_lifecycle_provider_configs_tenant_slot` | True / True | `CREATE UNIQUE INDEX uq_lifecycle_provider_configs_tenant_slot ON public.lifecycle_provider_configs USING btree (tenant_id, provider_key)` |

### `public.lifecycle_provider_secrets`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.lifecycle_provider_secrets_id_seq'::regclass)` | `none / none` |
| `provider_key` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `secret_name` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `encrypted_value` | `text` | NOT NULL | `—` | `none / none` |
| `value_preview` | `character varying(64)` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_by_user_id` | `integer` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_lifecycle_provider_secrets_configuration_tenant` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE` | True / False / False |
| `fk_lifecycle_provider_secrets_updated_by_user_id_iam_users` | f | `FOREIGN KEY (updated_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `pk_lifecycle_provider_secrets` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_lifecycle_provider_secrets_tenant_slot` | u | `UNIQUE (tenant_id, provider_key, secret_name)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_lifecycle_provider_secrets_configuration_tenant` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_secrets_configuration_tenant ON public.lifecycle_provider_secrets USING btree (tenant_id)` |
| `ix_lifecycle_provider_secrets_id` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_secrets_id ON public.lifecycle_provider_secrets USING btree (id)` |
| `ix_lifecycle_provider_secrets_provider` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_secrets_provider ON public.lifecycle_provider_secrets USING btree (provider_key)` |
| `ix_lifecycle_provider_secrets_provider_key` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_provider_secrets_provider_key ON public.lifecycle_provider_secrets USING btree (provider_key)` |
| `pk_lifecycle_provider_secrets` | btree / True | `pk_lifecycle_provider_secrets` | True / True | `CREATE UNIQUE INDEX pk_lifecycle_provider_secrets ON public.lifecycle_provider_secrets USING btree (id)` |
| `uq_lifecycle_provider_secrets_platform_slot` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_lifecycle_provider_secrets_platform_slot ON public.lifecycle_provider_secrets USING btree (provider_key, secret_name) WHERE (tenant_id IS NULL)` |
| `uq_lifecycle_provider_secrets_tenant_slot` | btree / True | `uq_lifecycle_provider_secrets_tenant_slot` | True / True | `CREATE UNIQUE INDEX uq_lifecycle_provider_secrets_tenant_slot ON public.lifecycle_provider_secrets USING btree (tenant_id, provider_key, secret_name)` |

### `public.lifecycle_vendor_records`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.lifecycle_vendor_records_id_seq'::regclass)` | `none / none` |
| `vendor_name` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `product_name` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `product_aliases_json` | `json` | NULL | `—` | `none / none` |
| `ecosystem` | `character varying(64)` | NULL | `—` | `none / none` |
| `version_pattern` | `character varying(128)` | NULL | `—` | `none / none` |
| `version_start` | `character varying(64)` | NULL | `—` | `none / none` |
| `version_end` | `character varying(64)` | NULL | `—` | `none / none` |
| `lifecycle_status` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `maintenance_status` | `character varying(128)` | NULL | `—` | `none / none` |
| `eol_date` | `character varying` | NULL | `—` | `none / none` |
| `eos_date` | `character varying` | NULL | `—` | `none / none` |
| `eof_date` | `character varying` | NULL | `—` | `none / none` |
| `deprecated` | `boolean` | NOT NULL | `—` | `none / none` |
| `unsupported` | `boolean` | NOT NULL | `—` | `none / none` |
| `latest_supported_version` | `character varying(128)` | NULL | `—` | `none / none` |
| `recommended_version` | `character varying(128)` | NULL | `—` | `none / none` |
| `evidence_url` | `character varying(512)` | NULL | `—` | `none / none` |
| `evidence_json` | `json` | NULL | `—` | `none / none` |
| `confidence` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `enabled` | `boolean` | NOT NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_by_user_id` | `integer` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_lifecycle_vendor_records_updated_by_user_id_iam_users` | f | `FOREIGN KEY (updated_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `pk_lifecycle_vendor_records` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_lifecycle_vendor_records_ecosystem` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_vendor_records_ecosystem ON public.lifecycle_vendor_records USING btree (ecosystem)` |
| `ix_lifecycle_vendor_records_enabled` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_vendor_records_enabled ON public.lifecycle_vendor_records USING btree (enabled)` |
| `ix_lifecycle_vendor_records_id` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_vendor_records_id ON public.lifecycle_vendor_records USING btree (id)` |
| `ix_lifecycle_vendor_records_lookup` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_vendor_records_lookup ON public.lifecycle_vendor_records USING btree (enabled, ecosystem, product_name)` |
| `ix_lifecycle_vendor_records_product_name` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_vendor_records_product_name ON public.lifecycle_vendor_records USING btree (product_name)` |
| `ix_lifecycle_vendor_records_vendor_name` | btree / False | `none` | True / True | `CREATE INDEX ix_lifecycle_vendor_records_vendor_name ON public.lifecycle_vendor_records USING btree (vendor_name)` |
| `pk_lifecycle_vendor_records` | btree / True | `pk_lifecycle_vendor_records` | True / True | `CREATE UNIQUE INDEX pk_lifecycle_vendor_records ON public.lifecycle_vendor_records USING btree (id)` |

### `public.logical_sbom`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.logical_sbom_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `product_id` | `integer` | NULL | `—` | `none / none` |
| `name` | `character varying` | NOT NULL | `—` | `none / none` |
| `description` | `text` | NULL | `—` | `none / none` |
| `created_by` | `character varying` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_logical_sbom_product_id_products` | f | `FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE CASCADE` | True / False / False |
| `fk_logical_sbom_product_tenant` | f | `FOREIGN KEY (product_id, tenant_id) REFERENCES public.products(id, tenant_id) ON DELETE CASCADE` | True / False / False |
| `fk_logical_sbom_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_logical_sbom` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_logical_sbom_id_tenant` | u | `UNIQUE (id, tenant_id)` | True / False / False |
| `uq_logical_sbom_id_tenant_product` | u | `UNIQUE (id, tenant_id, product_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_logical_sbom_product_id` | btree / False | `none` | True / True | `CREATE INDEX ix_logical_sbom_product_id ON public.logical_sbom USING btree (product_id)` |
| `ix_logical_sbom_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_logical_sbom_tenant_id ON public.logical_sbom USING btree (tenant_id)` |
| `ix_logical_sbom_tenant_product` | btree / False | `none` | True / True | `CREATE INDEX ix_logical_sbom_tenant_product ON public.logical_sbom USING btree (tenant_id, product_id)` |
| `pk_logical_sbom` | btree / True | `pk_logical_sbom` | True / True | `CREATE UNIQUE INDEX pk_logical_sbom ON public.logical_sbom USING btree (id)` |
| `uq_logical_sbom_id_tenant` | btree / True | `uq_logical_sbom_id_tenant` | True / True | `CREATE UNIQUE INDEX uq_logical_sbom_id_tenant ON public.logical_sbom USING btree (id, tenant_id)` |
| `uq_logical_sbom_id_tenant_product` | btree / True | `uq_logical_sbom_id_tenant_product` | True / True | `CREATE UNIQUE INDEX uq_logical_sbom_id_tenant_product ON public.logical_sbom USING btree (id, tenant_id, product_id)` |

### `public.native_platform_bootstrap`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.native_platform_bootstrap_id_seq'::regclass)` | `none / none` |
| `user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `state` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `completed_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `operator_reference` | `character varying(128)` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_native_platform_bootstrap_native_bootstrap_completion` | c | `CHECK (state::text = '<literal redacted>'::text AND completed_at IS NULL OR state::text = '<literal redacted>'::text AND completed_at IS NOT NULL)` | True / False / False |
| `ck_native_platform_bootstrap_native_bootstrap_singleton` | c | `CHECK (id = 1)` | True / False / False |
| `ck_native_platform_bootstrap_native_bootstrap_state` | c | `CHECK (state::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `fk_native_platform_bootstrap_user_id_iam_users` | f | `FOREIGN KEY (user_id) REFERENCES public.iam_users(id) ON DELETE RESTRICT` | True / False / False |
| `pk_native_platform_bootstrap` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_native_platform_bootstrap_user_id` | u | `UNIQUE (user_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `pk_native_platform_bootstrap` | btree / True | `pk_native_platform_bootstrap` | True / True | `CREATE UNIQUE INDEX pk_native_platform_bootstrap ON public.native_platform_bootstrap USING btree (id)` |
| `uq_native_platform_bootstrap_user_id` | btree / True | `uq_native_platform_bootstrap_user_id` | True / True | `CREATE UNIQUE INDEX uq_native_platform_bootstrap_user_id ON public.native_platform_bootstrap USING btree (user_id)` |

### `public.native_user_credentials`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.native_user_credentials_id_seq'::regclass)` | `none / none` |
| `user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `password_hash` | `character varying(512)` | NOT NULL | `—` | `none / none` |
| `password_hash_scheme` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `password_changed_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `failed_login_count` | `integer` | NOT NULL | `0` | `none / none` |
| `locked_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `locked_until` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `security_version` | `integer` | NOT NULL | `1` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_native_user_credentials_native_password_scheme` | c | `CHECK (password_hash_scheme::text = '<literal redacted>'::text AND password_hash::text ~~ '<literal redacted>'::text)` | True / False / False |
| `ck_native_user_credentials_native_security_counters` | c | `CHECK (failed_login_count >= 0 AND security_version >= 1)` | True / False / False |
| `fk_native_user_credentials_user_id_iam_users` | f | `FOREIGN KEY (user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE` | True / False / False |
| `pk_native_user_credentials` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_native_user_credentials_user_id` | u | `UNIQUE (user_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `pk_native_user_credentials` | btree / True | `pk_native_user_credentials` | True / True | `CREATE UNIQUE INDEX pk_native_user_credentials ON public.native_user_credentials USING btree (id)` |
| `uq_native_user_credentials_user_id` | btree / True | `uq_native_user_credentials_user_id` | True / True | `CREATE UNIQUE INDEX uq_native_user_credentials_user_id ON public.native_user_credentials USING btree (user_id)` |

### `public.nvd_lookup_cache`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.nvd_lookup_cache_id_seq'::regclass)` | `none / none` |
| `lookup_type` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `identifier` | `character varying(2048)` | NOT NULL | `—` | `none / none` |
| `identifier_hash` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `response_json` | `json` | NULL | `—` | `none / none` |
| `http_status` | `integer` | NULL | `—` | `none / none` |
| `error_message` | `text` | NULL | `—` | `none / none` |
| `checked_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_nvd_lookup_cache` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_nvd_lookup_cache_type_hash` | u | `UNIQUE (lookup_type, identifier_hash)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_nvd_lookup_cache_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_nvd_lookup_cache_expires_at ON public.nvd_lookup_cache USING btree (expires_at)` |
| `ix_nvd_lookup_cache_identifier` | btree / False | `none` | True / True | `CREATE INDEX ix_nvd_lookup_cache_identifier ON public.nvd_lookup_cache USING btree (identifier)` |
| `ix_nvd_lookup_cache_status` | btree / False | `none` | True / True | `CREATE INDEX ix_nvd_lookup_cache_status ON public.nvd_lookup_cache USING btree (status)` |
| `pk_nvd_lookup_cache` | btree / True | `pk_nvd_lookup_cache` | True / True | `CREATE UNIQUE INDEX pk_nvd_lookup_cache ON public.nvd_lookup_cache USING btree (id)` |
| `uq_nvd_lookup_cache_type_hash` | btree / True | `uq_nvd_lookup_cache_type_hash` | True / True | `CREATE UNIQUE INDEX uq_nvd_lookup_cache_type_hash ON public.nvd_lookup_cache USING btree (lookup_type, identifier_hash)` |

### `public.nvd_settings`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.nvd_settings_id_seq'::regclass)` | `none / none` |
| `enabled` | `boolean` | NOT NULL | `false` | `none / none` |
| `api_endpoint` | `text` | NOT NULL | `'<literal redacted>'::text` | `none / none` |
| `api_key_ciphertext` | `bytea` | NULL | `—` | `none / none` |
| `download_feeds_enabled` | `boolean` | NOT NULL | `false` | `none / none` |
| `page_size` | `integer` | NOT NULL | `2000` | `none / none` |
| `window_days` | `integer` | NOT NULL | `119` | `none / none` |
| `min_freshness_hours` | `integer` | NOT NULL | `24` | `none / none` |
| `last_modified_utc` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `last_successful_sync_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `now()` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `now()` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_nvd_settings_min_freshness_nonneg` | c | `CHECK (min_freshness_hours >= 0)` | True / False / False |
| `ck_nvd_settings_page_size_range` | c | `CHECK (page_size >= 1 AND page_size <= 2000)` | True / False / False |
| `ck_nvd_settings_singleton` | c | `CHECK (id = 1)` | True / False / False |
| `ck_nvd_settings_window_days_range` | c | `CHECK (window_days >= 1 AND window_days <= 119)` | True / False / False |
| `nvd_settings_pkey` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `nvd_settings_pkey` | btree / True | `nvd_settings_pkey` | True / True | `CREATE UNIQUE INDEX nvd_settings_pkey ON public.nvd_settings USING btree (id)` |

### `public.nvd_sync_runs`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `bigint` | NOT NULL | `nextval('public.nvd_sync_runs_id_seq'::regclass)` | `none / none` |
| `run_kind` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `window_start` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `window_end` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `started_at` | `timestamp with time zone` | NOT NULL | `now()` | `none / none` |
| `finished_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `status` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `upserted_count` | `integer` | NOT NULL | `0` | `none / none` |
| `error_message` | `text` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_nvd_sync_runs_kind` | c | `CHECK (run_kind::text = ANY (ARRAY['<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text]))` | True / False / False |
| `ck_nvd_sync_runs_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text]))` | True / False / False |
| `nvd_sync_runs_pkey` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_nvd_sync_runs_started_at` | btree / False | `none` | True / True | `CREATE INDEX ix_nvd_sync_runs_started_at ON public.nvd_sync_runs USING btree (started_at)` |
| `nvd_sync_runs_pkey` | btree / True | `nvd_sync_runs_pkey` | True / True | `CREATE UNIQUE INDEX nvd_sync_runs_pkey ON public.nvd_sync_runs USING btree (id)` |

### `public.platform_user_roles`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.platform_user_roles_id_seq'::regclass)` | `none / none` |
| `user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `role` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `created_by_user_id` | `integer` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_platform_user_roles_platform_user_role` | c | `CHECK (role::text = '<literal redacted>'::text)` | True / False / False |
| `ck_platform_user_roles_platform_user_role_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text]))` | True / False / False |
| `fk_platform_user_roles_created_by_user_id_iam_users` | f | `FOREIGN KEY (created_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_platform_user_roles_user_id_iam_users` | f | `FOREIGN KEY (user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE` | True / False / False |
| `pk_platform_user_roles` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_platform_user_roles_status` | btree / False | `none` | True / True | `CREATE INDEX ix_platform_user_roles_status ON public.platform_user_roles USING btree (status)` |
| `ix_platform_user_roles_user_id` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX ix_platform_user_roles_user_id ON public.platform_user_roles USING btree (user_id)` |
| `pk_platform_user_roles` | btree / True | `pk_platform_user_roles` | True / True | `CREATE UNIQUE INDEX pk_platform_user_roles ON public.platform_user_roles USING btree (id)` |

### `public.products`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.products_id_seq'::regclass)` | `none / none` |
| `project_id` | `integer` | NOT NULL | `—` | `none / none` |
| `name` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `normalized_name` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `slug` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `description` | `text` | NULL | `—` | `none / none` |
| `product_key` | `character varying(128)` | NULL | `—` | `none / none` |
| `vendor` | `character varying(255)` | NULL | `—` | `none / none` |
| `category` | `character varying(128)` | NULL | `—` | `none / none` |
| `status` | `character varying(32)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `latest_version` | `character varying(128)` | NULL | `—` | `none / none` |
| `metadata_json` | `json` | NULL | `—` | `none / none` |
| `created_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NULL | `—` | `none / none` |
| `deleted_at` | `character varying` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `current_sbom_id` | `integer` | NULL | `—` | `none / none` |
| `current_sbom_mode` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_products_ck_products_current_sbom_mode` | c | `CHECK (current_sbom_mode::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `fk_products_current_sbom_id_sbom_source` | f | `FOREIGN KEY (current_sbom_id) REFERENCES public.sbom_source(id) ON DELETE SET NULL` | True / False / False |
| `fk_products_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE` | True / False / False |
| `fk_products_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_products` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_products_id_tenant` | u | `UNIQUE (id, tenant_id)` | True / False / False |
| `uq_products_tenant_project_slug` | u | `UNIQUE (tenant_id, project_id, slug)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_products_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_products_created_at ON public.products USING btree (created_at)` |
| `ix_products_created_by` | btree / False | `none` | True / True | `CREATE INDEX ix_products_created_by ON public.products USING btree (created_by)` |
| `ix_products_current_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_products_current_sbom_id ON public.products USING btree (current_sbom_id)` |
| `ix_products_deleted_at` | btree / False | `none` | True / True | `CREATE INDEX ix_products_deleted_at ON public.products USING btree (deleted_at)` |
| `ix_products_id` | btree / False | `none` | True / True | `CREATE INDEX ix_products_id ON public.products USING btree (id)` |
| `ix_products_product_key` | btree / False | `none` | True / True | `CREATE INDEX ix_products_product_key ON public.products USING btree (product_key)` |
| `ix_products_project_id` | btree / False | `none` | True / True | `CREATE INDEX ix_products_project_id ON public.products USING btree (project_id)` |
| `ix_products_status` | btree / False | `none` | True / True | `CREATE INDEX ix_products_status ON public.products USING btree (status)` |
| `ix_products_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_products_tenant_id ON public.products USING btree (tenant_id)` |
| `ix_products_tenant_project` | btree / False | `none` | True / True | `CREATE INDEX ix_products_tenant_project ON public.products USING btree (tenant_id, project_id)` |
| `ix_products_tenant_project_name` | btree / False | `none` | True / True | `CREATE INDEX ix_products_tenant_project_name ON public.products USING btree (tenant_id, project_id, normalized_name)` |
| `pk_products` | btree / True | `pk_products` | True / True | `CREATE UNIQUE INDEX pk_products ON public.products USING btree (id)` |
| `uq_products_id_tenant` | btree / True | `uq_products_id_tenant` | True / True | `CREATE UNIQUE INDEX uq_products_id_tenant ON public.products USING btree (id, tenant_id)` |
| `uq_products_tenant_project_slug` | btree / True | `uq_products_tenant_project_slug` | True / True | `CREATE UNIQUE INDEX uq_products_tenant_project_slug ON public.products USING btree (tenant_id, project_id, slug)` |

### `public.projects`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.projects_id_seq'::regclass)` | `none / none` |
| `project_name` | `character varying` | NOT NULL | `—` | `none / none` |
| `project_details` | `character varying` | NULL | `—` | `none / none` |
| `project_status` | `integer` | NOT NULL | `—` | `none / none` |
| `created_on` | `character varying` | NULL | `—` | `none / none` |
| `created_by` | `character varying` | NULL | `—` | `none / none` |
| `modified_on` | `character varying` | NULL | `—` | `none / none` |
| `modified_by` | `character varying` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_projects_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_projects` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_projects_tenant_name` | u | `UNIQUE (tenant_id, project_name)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_projects_created_by` | btree / False | `none` | True / True | `CREATE INDEX ix_projects_created_by ON public.projects USING btree (created_by)` |
| `ix_projects_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_projects_deactivated ON public.projects USING btree (is_active) WHERE (is_active = false)` |
| `ix_projects_id` | btree / False | `none` | True / True | `CREATE INDEX ix_projects_id ON public.projects USING btree (id)` |
| `ix_projects_project_name` | btree / False | `none` | True / True | `CREATE INDEX ix_projects_project_name ON public.projects USING btree (project_name)` |
| `ix_projects_tenant_created` | btree / False | `none` | True / True | `CREATE INDEX ix_projects_tenant_created ON public.projects USING btree (tenant_id, created_on)` |
| `ix_projects_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_projects_tenant_id ON public.projects USING btree (tenant_id)` |
| `ix_projects_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_projects_tenant_identity ON public.projects USING btree (tenant_id, id)` |
| `pk_projects` | btree / True | `pk_projects` | True / True | `CREATE UNIQUE INDEX pk_projects ON public.projects USING btree (id)` |
| `uq_projects_tenant_name` | btree / True | `uq_projects_tenant_name` | True / True | `CREATE UNIQUE INDEX uq_projects_tenant_name ON public.projects USING btree (tenant_id, project_name)` |

### `public.report_artifact`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.report_artifact_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `delivery_id` | `integer` | NOT NULL | `—` | `none / none` |
| `kind` | `character varying(8)` | NOT NULL | `—` | `none / none` |
| `filename` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `media_type` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `size_bytes` | `integer` | NOT NULL | `—` | `none / none` |
| `sha256` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `storage_path` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `created_on` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_report_artifact_report_artifact_kind` | c | `CHECK (kind::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `fk_report_artifact_delivery_id_report_delivery` | f | `FOREIGN KEY (delivery_id) REFERENCES public.report_delivery(id) ON DELETE CASCADE` | True / False / False |
| `fk_report_artifact_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_report_artifact` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_report_artifact_delivery_id` | btree / False | `none` | True / True | `CREATE INDEX ix_report_artifact_delivery_id ON public.report_artifact USING btree (delivery_id)` |
| `ix_report_artifact_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_report_artifact_expires_at ON public.report_artifact USING btree (expires_at)` |
| `ix_report_artifact_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_report_artifact_tenant_id ON public.report_artifact USING btree (tenant_id)` |
| `pk_report_artifact` | btree / True | `pk_report_artifact` | True / True | `CREATE UNIQUE INDEX pk_report_artifact ON public.report_artifact USING btree (id)` |

### `public.report_delivery`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.report_delivery_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `subscription_id` | `integer` | NOT NULL | `—` | `none / none` |
| `cycle_start` | `character varying` | NOT NULL | `—` | `none / none` |
| `cycle_end` | `character varying` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `error_code` | `character varying(64)` | NULL | `—` | `none / none` |
| `attempt_count` | `integer` | NOT NULL | `0` | `none / none` |
| `recipient_email` | `character varying(320)` | NULL | `—` | `none / none` |
| `sbom_count` | `integer` | NOT NULL | `0` | `none / none` |
| `run_count` | `integer` | NOT NULL | `0` | `none / none` |
| `artifact_ids` | `json` | NOT NULL | `—` | `none / none` |
| `payload` | `json` | NOT NULL | `—` | `none / none` |
| `attempts` | `json` | NOT NULL | `—` | `none / none` |
| `next_attempt_at` | `character varying` | NULL | `—` | `none / none` |
| `claimed_at` | `character varying` | NULL | `—` | `none / none` |
| `dispatch_started_at` | `character varying` | NULL | `—` | `none / none` |
| `sent_at` | `character varying` | NULL | `—` | `none / none` |
| `created_on` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_report_delivery_report_delivery_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `fk_report_delivery_subscription_id_report_subscription` | f | `FOREIGN KEY (subscription_id) REFERENCES public.report_subscription(id) ON DELETE CASCADE` | True / False / False |
| `fk_report_delivery_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_report_delivery` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_report_delivery_cycle` | u | `UNIQUE (subscription_id, cycle_start, cycle_end)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_report_delivery_status` | btree / False | `none` | True / True | `CREATE INDEX ix_report_delivery_status ON public.report_delivery USING btree (status)` |
| `ix_report_delivery_subscription_id` | btree / False | `none` | True / True | `CREATE INDEX ix_report_delivery_subscription_id ON public.report_delivery USING btree (subscription_id)` |
| `ix_report_delivery_tenant_dispatch` | btree / False | `none` | True / True | `CREATE INDEX ix_report_delivery_tenant_dispatch ON public.report_delivery USING btree (tenant_id, dispatch_started_at)` |
| `ix_report_delivery_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_report_delivery_tenant_id ON public.report_delivery USING btree (tenant_id)` |
| `pk_report_delivery` | btree / True | `pk_report_delivery` | True / True | `CREATE UNIQUE INDEX pk_report_delivery ON public.report_delivery USING btree (id)` |
| `uq_report_delivery_cycle` | btree / True | `uq_report_delivery_cycle` | True / True | `CREATE UNIQUE INDEX uq_report_delivery_cycle ON public.report_delivery USING btree (subscription_id, cycle_start, cycle_end)` |

### `public.report_subscription`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.report_subscription_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `iam_user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `scope` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `project_id` | `integer` | NULL | `—` | `none / none` |
| `product_id` | `integer` | NULL | `—` | `none / none` |
| `sbom_id` | `integer` | NULL | `—` | `none / none` |
| `cadence` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `parts` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `formats` | `character varying(32)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `severity_floor` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `baseline_mode` | `character varying(32)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `cross_version_target` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `timezone` | `character varying(64)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `suppress_when_unchanged` | `boolean` | NOT NULL | `false` | `none / none` |
| `enabled` | `boolean` | NOT NULL | `true` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying` | NULL | `—` | `none / none` |
| `last_delivered_at` | `character varying` | NULL | `—` | `none / none` |
| `created_on` | `character varying` | NOT NULL | `—` | `none / none` |
| `created_by` | `character varying` | NULL | `—` | `none / none` |
| `modified_on` | `character varying` | NULL | `—` | `none / none` |
| `modified_by` | `character varying` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_report_subscription_report_cadence` | c | `CHECK (cadence::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_report_subscription_report_scope` | c | `CHECK (scope::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_report_subscription_report_severity` | c | `CHECK (severity_floor::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_report_subscription_report_target` | c | `CHECK (scope::text = '<literal redacted>'::text AND project_id IS NULL AND product_id IS NULL AND sbom_id IS NULL OR scope::text = '<literal redacted>'::text AND project_id IS NOT NULL AND product_id IS NULL AND sbom_id IS NULL OR scope::text = '<literal redacted>'::text AND product_id IS NOT NULL AND project_id IS NULL AND sbom_id IS NULL OR scope::text = '<literal redacted>'::text AND sbom_id IS NOT NULL AND project_id IS NULL AND product_id IS NULL)` | True / False / False |
| `fk_report_subscription_iam_user_id_iam_users` | f | `FOREIGN KEY (iam_user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE` | True / False / False |
| `fk_report_subscription_product_id_products` | f | `FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE CASCADE` | True / False / False |
| `fk_report_subscription_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE` | True / False / False |
| `fk_report_subscription_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE CASCADE` | True / False / False |
| `fk_report_subscription_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_report_subscription` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_report_subscription_iam_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_report_subscription_iam_user_id ON public.report_subscription USING btree (iam_user_id)` |
| `ix_report_subscription_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_report_subscription_tenant_id ON public.report_subscription USING btree (tenant_id)` |
| `pk_report_subscription` | btree / True | `pk_report_subscription` | True / True | `CREATE UNIQUE INDEX pk_report_subscription ON public.report_subscription USING btree (id)` |
| `uq_report_subscription_product` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_report_subscription_product ON public.report_subscription USING btree (tenant_id, iam_user_id, product_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |
| `uq_report_subscription_project` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_report_subscription_project ON public.report_subscription USING btree (tenant_id, iam_user_id, project_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |
| `uq_report_subscription_sbom` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_report_subscription_sbom ON public.report_subscription USING btree (tenant_id, iam_user_id, sbom_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |
| `uq_report_subscription_tenant` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_report_subscription_tenant ON public.report_subscription USING btree (tenant_id, iam_user_id) WHERE (is_active AND ((scope)::text = '<literal redacted>'::text))` |

### `public.run_cache`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.run_cache_id_seq'::regclass)` | `none / none` |
| `run_json` | `text` | NOT NULL | `—` | `none / none` |
| `created_on` | `character varying` | NULL | `—` | `none / none` |
| `source` | `character varying` | NULL | `—` | `none / none` |
| `sbom_id` | `integer` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_run_cache_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_run_cache` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_run_cache_id` | btree / False | `none` | True / True | `CREATE INDEX ix_run_cache_id ON public.run_cache USING btree (id)` |
| `ix_run_cache_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_run_cache_tenant_id ON public.run_cache USING btree (tenant_id)` |
| `ix_run_cache_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_run_cache_tenant_identity ON public.run_cache USING btree (tenant_id, id)` |
| `pk_run_cache` | btree / True | `pk_run_cache` | True / True | `CREATE UNIQUE INDEX pk_run_cache ON public.run_cache USING btree (id)` |

### `public.sbom_analysis_report`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.sbom_analysis_report_id_seq'::regclass)` | `none / none` |
| `sbom_ref_id` | `integer` | NULL | `—` | `none / none` |
| `sbom_result` | `character varying` | NULL | `—` | `none / none` |
| `project_id` | `character varying` | NULL | `—` | `none / none` |
| `created_on` | `character varying` | NULL | `—` | `none / none` |
| `analysis_details` | `text` | NULL | `—` | `none / none` |
| `reference_source` | `character varying` | NULL | `—` | `none / none` |
| `sbom_analysis_level` | `integer` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_sbom_analysis_report_sbom_ref_id_sbom_source` | f | `FOREIGN KEY (sbom_ref_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_sbom_analysis_report_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_sbom_analysis_report` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_sbom_analysis_report_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_analysis_report_deactivated ON public.sbom_analysis_report USING btree (is_active) WHERE (is_active = false)` |
| `ix_sbom_analysis_report_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_analysis_report_id ON public.sbom_analysis_report USING btree (id)` |
| `ix_sbom_analysis_report_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_analysis_report_tenant_id ON public.sbom_analysis_report USING btree (tenant_id)` |
| `ix_sbom_analysis_report_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_analysis_report_tenant_identity ON public.sbom_analysis_report USING btree (tenant_id, id)` |
| `pk_sbom_analysis_report` | btree / True | `pk_sbom_analysis_report` | True / True | `CREATE UNIQUE INDEX pk_sbom_analysis_report ON public.sbom_analysis_report USING btree (id)` |

### `public.sbom_component`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.sbom_component_id_seq'::regclass)` | `none / none` |
| `sbom_id` | `integer` | NOT NULL | `—` | `none / none` |
| `bom_ref` | `character varying` | NULL | `—` | `none / none` |
| `component_type` | `character varying` | NULL | `—` | `none / none` |
| `component_group` | `character varying` | NULL | `—` | `none / none` |
| `name` | `character varying` | NOT NULL | `—` | `none / none` |
| `version` | `character varying` | NULL | `—` | `none / none` |
| `purl` | `character varying` | NULL | `—` | `none / none` |
| `cpe` | `character varying` | NULL | `—` | `none / none` |
| `cpe_source` | `character varying(32)` | NULL | `—` | `none / none` |
| `supplier` | `character varying` | NULL | `—` | `none / none` |
| `scope` | `character varying` | NULL | `—` | `none / none` |
| `created_on` | `character varying` | NULL | `—` | `none / none` |
| `ecosystem` | `character varying` | NULL | `—` | `none / none` |
| `original_name` | `character varying` | NULL | `—` | `none / none` |
| `normalized_name` | `character varying` | NULL | `—` | `none / none` |
| `original_version` | `character varying` | NULL | `—` | `none / none` |
| `normalized_version` | `character varying` | NULL | `—` | `none / none` |
| `normalized_ecosystem` | `character varying` | NULL | `—` | `none / none` |
| `original_purl` | `character varying` | NULL | `—` | `none / none` |
| `normalized_purl` | `character varying` | NULL | `—` | `none / none` |
| `purl_type` | `character varying` | NULL | `—` | `none / none` |
| `purl_namespace` | `character varying` | NULL | `—` | `none / none` |
| `purl_name` | `character varying` | NULL | `—` | `none / none` |
| `purl_version` | `character varying` | NULL | `—` | `none / none` |
| `purl_qualifiers_json` | `json` | NULL | `—` | `none / none` |
| `purl_subpath` | `character varying` | NULL | `—` | `none / none` |
| `normalized_cpes` | `json` | NULL | `—` | `none / none` |
| `primary_cpe` | `character varying` | NULL | `—` | `none / none` |
| `cpe_evidence_json` | `json` | NULL | `—` | `none / none` |
| `normalized_supplier` | `character varying` | NULL | `—` | `none / none` |
| `normalized_package_key` | `character varying` | NULL | `—` | `none / none` |
| `canonical_identity_confidence` | `character varying` | NULL | `—` | `none / none` |
| `license` | `character varying` | NULL | `—` | `none / none` |
| `hashes` | `text` | NULL | `—` | `none / none` |
| `lifecycle_status` | `character varying` | NULL | `—` | `none / none` |
| `eos_date` | `character varying` | NULL | `—` | `none / none` |
| `eol_date` | `character varying` | NULL | `—` | `none / none` |
| `eof_date` | `character varying` | NULL | `—` | `none / none` |
| `is_deprecated` | `boolean` | NULL | `—` | `none / none` |
| `deprecated` | `boolean` | NULL | `—` | `none / none` |
| `unsupported` | `boolean` | NULL | `—` | `none / none` |
| `maintenance_status` | `character varying` | NULL | `—` | `none / none` |
| `latest_version` | `character varying` | NULL | `—` | `none / none` |
| `latest_supported_version` | `character varying` | NULL | `—` | `none / none` |
| `recommended_version` | `character varying` | NULL | `—` | `none / none` |
| `lifecycle_recommendation` | `text` | NULL | `—` | `none / none` |
| `lifecycle_source` | `character varying` | NULL | `—` | `none / none` |
| `lifecycle_source_url` | `character varying` | NULL | `—` | `none / none` |
| `lifecycle_confidence` | `character varying` | NULL | `—` | `none / none` |
| `lifecycle_checked_at` | `character varying` | NULL | `—` | `none / none` |
| `lifecycle_evidence_json` | `json` | NULL | `—` | `none / none` |
| `lifecycle_is_stale` | `boolean` | NOT NULL | `—` | `none / none` |
| `lifecycle_manual_override` | `boolean` | NOT NULL | `—` | `none / none` |
| `normalized_component_key` | `character varying` | NULL | `—` | `none / none` |
| `dedupe_canonical_id` | `character varying` | NULL | `—` | `none / none` |
| `dedupe_group_id` | `character varying` | NULL | `—` | `none / none` |
| `is_duplicate` | `boolean` | NOT NULL | `—` | `none / none` |
| `duplicate_of_component_id` | `integer` | NULL | `—` | `none / none` |
| `dedupe_reason` | `character varying` | NULL | `—` | `none / none` |
| `dedupe_confidence` | `character varying` | NULL | `—` | `none / none` |
| `normalization_notes_json` | `json` | NULL | `—` | `none / none` |
| `dedupe_evidence_json` | `json` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `description` | `text` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_sbom_component_duplicate_of_component_id_sbom_component` | f | `FOREIGN KEY (duplicate_of_component_id) REFERENCES public.sbom_component(id) ON DELETE CASCADE` | True / False / False |
| `fk_sbom_component_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_sbom_component_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_sbom_component` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_sbom_component_fingerprint` | u | `UNIQUE (tenant_id, sbom_id, bom_ref, name, version, cpe)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_sbom_component_bom_ref` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_bom_ref ON public.sbom_component USING btree (bom_ref)` |
| `ix_sbom_component_cpe` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_cpe ON public.sbom_component USING btree (cpe)` |
| `ix_sbom_component_cpe_source` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_cpe_source ON public.sbom_component USING btree (cpe_source)` |
| `ix_sbom_component_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_deactivated ON public.sbom_component USING btree (is_active) WHERE (is_active = false)` |
| `ix_sbom_component_dedupe_canonical_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_dedupe_canonical_id ON public.sbom_component USING btree (dedupe_canonical_id)` |
| `ix_sbom_component_dedupe_group_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_dedupe_group_id ON public.sbom_component USING btree (dedupe_group_id)` |
| `ix_sbom_component_duplicate_of_component_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_duplicate_of_component_id ON public.sbom_component USING btree (duplicate_of_component_id)` |
| `ix_sbom_component_ecosystem` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_ecosystem ON public.sbom_component USING btree (ecosystem)` |
| `ix_sbom_component_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_id ON public.sbom_component USING btree (id)` |
| `ix_sbom_component_lifecycle` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_lifecycle ON public.sbom_component USING btree (lifecycle_status, ecosystem)` |
| `ix_sbom_component_lifecycle_checked_at` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_lifecycle_checked_at ON public.sbom_component USING btree (lifecycle_checked_at)` |
| `ix_sbom_component_name` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_name ON public.sbom_component USING btree (name)` |
| `ix_sbom_component_normalized_component_key` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_normalized_component_key ON public.sbom_component USING btree (normalized_component_key)` |
| `ix_sbom_component_normalized_ecosystem` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_normalized_ecosystem ON public.sbom_component USING btree (normalized_ecosystem)` |
| `ix_sbom_component_normalized_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_normalized_identity ON public.sbom_component USING btree (normalized_ecosystem, normalized_name, normalized_version)` |
| `ix_sbom_component_normalized_name` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_normalized_name ON public.sbom_component USING btree (normalized_name)` |
| `ix_sbom_component_normalized_package_key` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_normalized_package_key ON public.sbom_component USING btree (normalized_package_key)` |
| `ix_sbom_component_normalized_purl` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_normalized_purl ON public.sbom_component USING btree (normalized_purl)` |
| `ix_sbom_component_normalized_version` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_normalized_version ON public.sbom_component USING btree (normalized_version)` |
| `ix_sbom_component_primary_cpe` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_primary_cpe ON public.sbom_component USING btree (primary_cpe)` |
| `ix_sbom_component_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_sbom_id ON public.sbom_component USING btree (sbom_id)` |
| `ix_sbom_component_sbom_is_duplicate` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_sbom_is_duplicate ON public.sbom_component USING btree (sbom_id, is_duplicate)` |
| `ix_sbom_component_sbom_name` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_sbom_name ON public.sbom_component USING btree (sbom_id, name)` |
| `ix_sbom_component_sbom_normalized_key` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_sbom_normalized_key ON public.sbom_component USING btree (sbom_id, normalized_component_key)` |
| `ix_sbom_component_tenant_canonical` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_tenant_canonical ON public.sbom_component USING btree (tenant_id, dedupe_canonical_id)` |
| `ix_sbom_component_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_tenant_id ON public.sbom_component USING btree (tenant_id)` |
| `ix_sbom_component_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_tenant_identity ON public.sbom_component USING btree (tenant_id, id)` |
| `ix_sbom_component_tenant_package_key` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_tenant_package_key ON public.sbom_component USING btree (tenant_id, normalized_package_key)` |
| `ix_sbom_component_version` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_component_version ON public.sbom_component USING btree (version)` |
| `pk_sbom_component` | btree / True | `pk_sbom_component` | True / True | `CREATE UNIQUE INDEX pk_sbom_component ON public.sbom_component USING btree (id)` |
| `uq_sbom_component_fingerprint` | btree / True | `uq_sbom_component_fingerprint` | True / True | `CREATE UNIQUE INDEX uq_sbom_component_fingerprint ON public.sbom_component USING btree (tenant_id, sbom_id, bom_ref, name, version, cpe)` |

### `public.sbom_repair_jobs`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `character varying(36)` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `session_id` | `character varying(36)` | NOT NULL | `—` | `none / none` |
| `source_sha256` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `original_sha256` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `source_sbom_sha256` | `character varying(64)` | NULL | `—` | `none / none` |
| `source_sbom_id` | `integer` | NULL | `—` | `none / none` |
| `candidate_sha256` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `candidate_content` | `text` | NOT NULL | `—` | `none / none` |
| `report_json` | `json` | NOT NULL | `—` | `none / none` |
| `validation_options_json` | `json` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `approval_status` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `decided_at` | `character varying` | NULL | `—` | `none / none` |
| `actor_user_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `decided_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `imported_sbom_id` | `integer` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_sbom_repair_jobs_imported_sbom_id_sbom_source` | f | `FOREIGN KEY (imported_sbom_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_sbom_repair_jobs_session_id_sbom_validation_sessions` | f | `FOREIGN KEY (session_id) REFERENCES public.sbom_validation_sessions(id) ON DELETE CASCADE` | True / False / False |
| `fk_sbom_repair_jobs_source_sbom_id_sbom_source` | f | `FOREIGN KEY (source_sbom_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_sbom_repair_jobs_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_sbom_repair_jobs` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_sbom_repair_jobs_session_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_repair_jobs_session_id ON public.sbom_repair_jobs USING btree (session_id)` |
| `ix_sbom_repair_jobs_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_repair_jobs_tenant_id ON public.sbom_repair_jobs USING btree (tenant_id)` |
| `pk_sbom_repair_jobs` | btree / True | `pk_sbom_repair_jobs` | True / True | `CREATE UNIQUE INDEX pk_sbom_repair_jobs ON public.sbom_repair_jobs USING btree (id)` |

### `public.sbom_source`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.sbom_source_id_seq'::regclass)` | `none / none` |
| `sbom_name` | `character varying` | NOT NULL | `—` | `none / none` |
| `sbom_data` | `text` | NULL | `—` | `none / none` |
| `sbom_type` | `integer` | NULL | `—` | `none / none` |
| `projectid` | `integer` | NULL | `—` | `none / none` |
| `product_id` | `integer` | NULL | `—` | `none / none` |
| `created_on` | `character varying` | NULL | `—` | `none / none` |
| `sbom_version` | `character varying` | NULL | `—` | `none / none` |
| `created_by` | `character varying` | NULL | `—` | `none / none` |
| `productver` | `character varying` | NULL | `—` | `none / none` |
| `modified_on` | `character varying` | NULL | `—` | `none / none` |
| `modified_by` | `character varying` | NULL | `—` | `none / none` |
| `parent_id` | `integer` | NULL | `—` | `none / none` |
| `change_summary` | `character varying` | NULL | `—` | `none / none` |
| `completeness_score` | `double precision` | NULL | `—` | `none / none` |
| `completeness_report` | `json` | NULL | `—` | `none / none` |
| `dedupe_report_json` | `json` | NULL | `—` | `none / none` |
| `product_name` | `character varying` | NULL | `—` | `none / none` |
| `description` | `character varying` | NULL | `—` | `none / none` |
| `status` | `character varying(24)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `failed_stage` | `character varying(32)` | NULL | `—` | `none / none` |
| `validation_errors` | `json` | NULL | `—` | `none / none` |
| `error_count` | `integer` | NOT NULL | `0` | `none / none` |
| `warning_count` | `integer` | NOT NULL | `0` | `none / none` |
| `validated_at` | `character varying` | NULL | `—` | `none / none` |
| `original_format` | `character varying(32)` | NULL | `—` | `none / none` |
| `current_format` | `character varying(32)` | NULL | `—` | `none / none` |
| `converted_from_format` | `character varying(32)` | NULL | `—` | `none / none` |
| `source_sbom_id` | `integer` | NULL | `—` | `none / none` |
| `converted_sbom_id` | `integer` | NULL | `—` | `none / none` |
| `conversion_status` | `character varying(32)` | NULL | `—` | `none / none` |
| `conversion_warnings_json` | `json` | NULL | `—` | `none / none` |
| `conversion_report_json` | `json` | NULL | `—` | `none / none` |
| `converted_at` | `character varying` | NULL | `—` | `none / none` |
| `converted_by` | `character varying` | NULL | `—` | `none / none` |
| `enrichment_status` | `character varying(32)` | NULL | `—` | `none / none` |
| `conversion_started_at` | `character varying` | NULL | `—` | `none / none` |
| `conversion_completed_at` | `character varying` | NULL | `—` | `none / none` |
| `enrichment_started_at` | `character varying` | NULL | `—` | `none / none` |
| `enrichment_completed_at` | `character varying` | NULL | `—` | `none / none` |
| `conversion_error` | `text` | NULL | `—` | `none / none` |
| `enrichment_error` | `text` | NULL | `—` | `none / none` |
| `component_extraction_status` | `character varying(32)` | NULL | `—` | `none / none` |
| `component_extraction_error` | `text` | NULL | `—` | `none / none` |
| `component_extraction_attempted_at` | `character varying` | NULL | `—` | `none / none` |
| `component_extraction_completed_at` | `character varying` | NULL | `—` | `none / none` |
| `is_active` | `boolean` | NOT NULL | `true` | `none / none` |
| `deactivated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `deactivated_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `lifecycle_status` | `character varying(8)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `lifecycle_revision` | `integer` | NOT NULL | `0` | `none / none` |
| `analysis_requires_reanalysis` | `boolean` | NOT NULL | `false` | `none / none` |
| `logical_sbom_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_sbom_source_sbom_operational_lifecycle` | c | `CHECK (lifecycle_status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `fk_sbom_source_converted_sbom_id_sbom_source` | f | `FOREIGN KEY (converted_sbom_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_sbom_source_logical` | f | `FOREIGN KEY (logical_sbom_id) REFERENCES public.logical_sbom(id)` | True / False / False |
| `fk_sbom_source_logical_product` | f | `FOREIGN KEY (logical_sbom_id, tenant_id, product_id) REFERENCES public.logical_sbom(id, tenant_id, product_id)` | True / False / False |
| `fk_sbom_source_logical_tenant` | f | `FOREIGN KEY (logical_sbom_id, tenant_id) REFERENCES public.logical_sbom(id, tenant_id)` | True / False / False |
| `fk_sbom_source_parent_id_sbom_source` | f | `FOREIGN KEY (parent_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_sbom_source_product_id_products` | f | `FOREIGN KEY (product_id) REFERENCES public.products(id)` | True / False / False |
| `fk_sbom_source_projectid_projects` | f | `FOREIGN KEY (projectid) REFERENCES public.projects(id)` | True / False / False |
| `fk_sbom_source_sbom_type_sbom_type` | f | `FOREIGN KEY (sbom_type) REFERENCES public.sbom_type(id)` | True / False / False |
| `fk_sbom_source_source_sbom_id_sbom_source` | f | `FOREIGN KEY (source_sbom_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_sbom_source_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_sbom_source` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_sbom_source_logical_version` | u | `UNIQUE (logical_sbom_id, sbom_version)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_sbom_source_component_extraction_status` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_component_extraction_status ON public.sbom_source USING btree (component_extraction_status)` |
| `ix_sbom_source_conversion_status` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_conversion_status ON public.sbom_source USING btree (conversion_status)` |
| `ix_sbom_source_converted_from_format` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_converted_from_format ON public.sbom_source USING btree (converted_from_format)` |
| `ix_sbom_source_converted_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_converted_sbom_id ON public.sbom_source USING btree (converted_sbom_id)` |
| `ix_sbom_source_created_by` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_created_by ON public.sbom_source USING btree (created_by)` |
| `ix_sbom_source_deactivated` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_deactivated ON public.sbom_source USING btree (is_active) WHERE (is_active = false)` |
| `ix_sbom_source_enrichment_status` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_enrichment_status ON public.sbom_source USING btree (enrichment_status)` |
| `ix_sbom_source_failed_stage` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_failed_stage ON public.sbom_source USING btree (failed_stage)` |
| `ix_sbom_source_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_id ON public.sbom_source USING btree (id)` |
| `ix_sbom_source_lifecycle_status` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_lifecycle_status ON public.sbom_source USING btree (lifecycle_status)` |
| `ix_sbom_source_logical_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_logical_sbom_id ON public.sbom_source USING btree (logical_sbom_id)` |
| `ix_sbom_source_parent_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_parent_id ON public.sbom_source USING btree (parent_id)` |
| `ix_sbom_source_product_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_product_id ON public.sbom_source USING btree (product_id)` |
| `ix_sbom_source_sbom_name` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_sbom_name ON public.sbom_source USING btree (sbom_name)` |
| `ix_sbom_source_sbom_type` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_sbom_type ON public.sbom_source USING btree (sbom_type)` |
| `ix_sbom_source_source_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_source_sbom_id ON public.sbom_source USING btree (source_sbom_id)` |
| `ix_sbom_source_status` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_status ON public.sbom_source USING btree (status)` |
| `ix_sbom_source_tenant_created` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_tenant_created ON public.sbom_source USING btree (tenant_id, created_on)` |
| `ix_sbom_source_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_tenant_id ON public.sbom_source USING btree (tenant_id)` |
| `ix_sbom_source_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_tenant_identity ON public.sbom_source USING btree (tenant_id, id)` |
| `ix_sbom_source_tenant_product` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_tenant_product ON public.sbom_source USING btree (tenant_id, product_id)` |
| `ix_sbom_source_tenant_project` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_source_tenant_project ON public.sbom_source USING btree (tenant_id, projectid)` |
| `pk_sbom_source` | btree / True | `pk_sbom_source` | True / True | `CREATE UNIQUE INDEX pk_sbom_source ON public.sbom_source USING btree (id)` |
| `uq_sbom_source_logical_unversioned` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_sbom_source_logical_unversioned ON public.sbom_source USING btree (logical_sbom_id) WHERE (sbom_version IS NULL)` |
| `uq_sbom_source_logical_version` | btree / True | `uq_sbom_source_logical_version` | True / True | `CREATE UNIQUE INDEX uq_sbom_source_logical_version ON public.sbom_source USING btree (logical_sbom_id, sbom_version)` |

### `public.sbom_type`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.sbom_type_id_seq'::regclass)` | `none / none` |
| `typename` | `character varying` | NOT NULL | `—` | `none / none` |
| `type_details` | `character varying` | NULL | `—` | `none / none` |
| `created_on` | `character varying` | NULL | `—` | `none / none` |
| `created_by` | `character varying` | NULL | `—` | `none / none` |
| `modified_on` | `character varying` | NULL | `—` | `none / none` |
| `modified_by` | `character varying` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_sbom_type` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_sbom_type_typename` | u | `UNIQUE (typename)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_sbom_type_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_type_id ON public.sbom_type USING btree (id)` |
| `pk_sbom_type` | btree / True | `pk_sbom_type` | True / True | `CREATE UNIQUE INDEX pk_sbom_type ON public.sbom_type USING btree (id)` |
| `uq_sbom_type_typename` | btree / True | `uq_sbom_type_typename` | True / True | `CREATE UNIQUE INDEX uq_sbom_type_typename ON public.sbom_type USING btree (typename)` |

### `public.sbom_validation_session_events`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.sbom_validation_session_events_id_seq'::regclass)` | `none / none` |
| `session_id` | `character varying(36)` | NOT NULL | `—` | `none / none` |
| `event_type` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `actor_user_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `timestamp` | `character varying` | NOT NULL | `—` | `none / none` |
| `summary` | `text` | NULL | `—` | `none / none` |
| `before_hash` | `character varying(64)` | NULL | `—` | `none / none` |
| `after_hash` | `character varying(64)` | NULL | `—` | `none / none` |
| `metadata_json` | `json` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_sbom_validation_session_events_session_id_sbom_valid_ca0d` | f | `FOREIGN KEY (session_id) REFERENCES public.sbom_validation_sessions(id) ON DELETE CASCADE` | True / False / False |
| `fk_sbom_validation_session_events_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_sbom_validation_session_events` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_sbom_validation_session_events_actor_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_session_events_actor_user_id ON public.sbom_validation_session_events USING btree (actor_user_id)` |
| `ix_sbom_validation_session_events_event_type` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_session_events_event_type ON public.sbom_validation_session_events USING btree (event_type)` |
| `ix_sbom_validation_session_events_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_session_events_id ON public.sbom_validation_session_events USING btree (id)` |
| `ix_sbom_validation_session_events_session_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_session_events_session_id ON public.sbom_validation_session_events USING btree (session_id)` |
| `ix_sbom_validation_session_events_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_session_events_tenant_id ON public.sbom_validation_session_events USING btree (tenant_id)` |
| `ix_sbom_validation_session_events_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_session_events_tenant_identity ON public.sbom_validation_session_events USING btree (tenant_id, id)` |
| `ix_sbom_validation_session_events_timestamp` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_session_events_timestamp ON public.sbom_validation_session_events USING btree ("timestamp")` |
| `pk_sbom_validation_session_events` | btree / True | `pk_sbom_validation_session_events` | True / True | `CREATE UNIQUE INDEX pk_sbom_validation_session_events ON public.sbom_validation_session_events USING btree (id)` |

### `public.sbom_validation_sessions`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `character varying(36)` | NOT NULL | `—` | `none / none` |
| `project_id` | `integer` | NULL | `—` | `none / none` |
| `user_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `original_filename` | `character varying(255)` | NULL | `—` | `none / none` |
| `sbom_name` | `character varying(255)` | NULL | `—` | `none / none` |
| `sbom_type` | `integer` | NULL | `—` | `none / none` |
| `content_type` | `character varying(255)` | NULL | `—` | `none / none` |
| `file_size_bytes` | `integer` | NULL | `—` | `none / none` |
| `sha256` | `character varying(64)` | NULL | `—` | `none / none` |
| `original_size_bytes` | `integer` | NULL | `—` | `none / none` |
| `original_sha256` | `character varying(64)` | NULL | `—` | `none / none` |
| `stored_size_bytes` | `integer` | NULL | `—` | `none / none` |
| `stored_sha256` | `character varying(64)` | NULL | `—` | `none / none` |
| `storage_backend` | `character varying(32)` | NULL | `—` | `none / none` |
| `detected_format` | `character varying(64)` | NULL | `—` | `none / none` |
| `detected_version` | `character varying(64)` | NULL | `—` | `none / none` |
| `detection_confidence` | `double precision` | NULL | `—` | `none / none` |
| `detection_evidence_json` | `json` | NULL | `—` | `none / none` |
| `raw_content_text` | `text` | NULL | `—` | `none / none` |
| `raw_content_blob` | `bytea` | NULL | `—` | `none / none` |
| `raw_storage_path` | `character varying(1024)` | NULL | `—` | `none / none` |
| `sanitized_content` | `text` | NULL | `—` | `none / none` |
| `current_content` | `text` | NULL | `—` | `none / none` |
| `repair_content_text` | `text` | NULL | `—` | `none / none` |
| `repair_content_blob` | `bytea` | NULL | `—` | `none / none` |
| `repair_storage_path` | `character varying(1024)` | NULL | `—` | `none / none` |
| `validation_status` | `character varying(32)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `validation_errors_json` | `json` | NULL | `—` | `none / none` |
| `stage_results_json` | `json` | NULL | `—` | `none / none` |
| `latest_error_report_json` | `json` | NULL | `—` | `none / none` |
| `total_lines` | `integer` | NULL | `—` | `none / none` |
| `is_large_file` | `boolean` | NOT NULL | `false` | `none / none` |
| `full_editor_allowed` | `boolean` | NOT NULL | `true` | `none / none` |
| `can_edit` | `boolean` | NOT NULL | `true` | `none / none` |
| `can_ai_fix` | `boolean` | NOT NULL | `true` | `none / none` |
| `security_blocked_reason` | `text` | NULL | `—` | `none / none` |
| `content_sha256` | `character varying(64)` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `imported_sbom_id` | `integer` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_sbom_validation_sessions_imported_sbom_id_sbom_source` | f | `FOREIGN KEY (imported_sbom_id) REFERENCES public.sbom_source(id)` | True / False / False |
| `fk_sbom_validation_sessions_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id)` | True / False / False |
| `fk_sbom_validation_sessions_sbom_type_sbom_type` | f | `FOREIGN KEY (sbom_type) REFERENCES public.sbom_type(id)` | True / False / False |
| `fk_sbom_validation_sessions_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_sbom_validation_sessions` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_sbom_validation_sessions_content_sha256` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_content_sha256 ON public.sbom_validation_sessions USING btree (content_sha256)` |
| `ix_sbom_validation_sessions_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_created_at ON public.sbom_validation_sessions USING btree (created_at)` |
| `ix_sbom_validation_sessions_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_expires_at ON public.sbom_validation_sessions USING btree (expires_at)` |
| `ix_sbom_validation_sessions_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_id ON public.sbom_validation_sessions USING btree (id)` |
| `ix_sbom_validation_sessions_imported_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_imported_sbom_id ON public.sbom_validation_sessions USING btree (imported_sbom_id)` |
| `ix_sbom_validation_sessions_original_sha256` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_original_sha256 ON public.sbom_validation_sessions USING btree (original_sha256)` |
| `ix_sbom_validation_sessions_project_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_project_id ON public.sbom_validation_sessions USING btree (project_id)` |
| `ix_sbom_validation_sessions_sha256` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_sha256 ON public.sbom_validation_sessions USING btree (sha256)` |
| `ix_sbom_validation_sessions_stored_sha256` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_stored_sha256 ON public.sbom_validation_sessions USING btree (stored_sha256)` |
| `ix_sbom_validation_sessions_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_tenant_id ON public.sbom_validation_sessions USING btree (tenant_id)` |
| `ix_sbom_validation_sessions_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_tenant_identity ON public.sbom_validation_sessions USING btree (tenant_id, id)` |
| `ix_sbom_validation_sessions_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_user_id ON public.sbom_validation_sessions USING btree (user_id)` |
| `ix_sbom_validation_sessions_validation_status` | btree / False | `none` | True / True | `CREATE INDEX ix_sbom_validation_sessions_validation_status ON public.sbom_validation_sessions USING btree (validation_status)` |
| `pk_sbom_validation_sessions` | btree / True | `pk_sbom_validation_sessions` | True / True | `CREATE UNIQUE INDEX pk_sbom_validation_sessions ON public.sbom_validation_sessions USING btree (id)` |

### `public.security_mail_outbox`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.security_mail_outbox_id_seq'::regclass)` | `none / none` |
| `token_id` | `integer` | NOT NULL | `—` | `none / none` |
| `user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `purpose` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `recipient` | `character varying(320)` | NOT NULL | `—` | `none / none` |
| `payload` | `bytea` | NULL | `—` | `none / none` |
| `status` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `attempts` | `integer` | NOT NULL | `—` | `none / none` |
| `next_attempt_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `expires_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `sent_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `failed_at` | `timestamp with time zone` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_security_mail_outbox_security_mail_attempts` | c | `CHECK (attempts >= 0)` | True / False / False |
| `ck_security_mail_outbox_security_mail_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `fk_security_mail_outbox_token_id_account_action_tokens` | f | `FOREIGN KEY (token_id) REFERENCES public.account_action_tokens(id) ON DELETE CASCADE` | True / False / False |
| `fk_security_mail_outbox_user_id_iam_users` | f | `FOREIGN KEY (user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE` | True / False / False |
| `pk_security_mail_outbox` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_security_mail_outbox_token_id` | u | `UNIQUE (token_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_security_mail_due` | btree / False | `none` | True / True | `CREATE INDEX ix_security_mail_due ON public.security_mail_outbox USING btree (status, next_attempt_at)` |
| `pk_security_mail_outbox` | btree / True | `pk_security_mail_outbox` | True / True | `CREATE UNIQUE INDEX pk_security_mail_outbox ON public.security_mail_outbox USING btree (id)` |
| `uq_security_mail_outbox_token_id` | btree / True | `uq_security_mail_outbox_token_id` | True / True | `CREATE UNIQUE INDEX uq_security_mail_outbox_token_id ON public.security_mail_outbox USING btree (token_id)` |

### `public.source_response_cache`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `source` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `component_key` | `character varying(512)` | NOT NULL | `—` | `none / none` |
| `payload` | `json` | NOT NULL | `—` | `none / none` |
| `fetched_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `expires_at` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `pk_source_response_cache` | p | `PRIMARY KEY (source, component_key)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_source_response_cache_expires_at` | btree / False | `none` | True / True | `CREATE INDEX ix_source_response_cache_expires_at ON public.source_response_cache USING btree (expires_at)` |
| `pk_source_response_cache` | btree / True | `pk_source_response_cache` | True / True | `CREATE UNIQUE INDEX pk_source_response_cache ON public.source_response_cache USING btree (source, component_key)` |

### `public.tenant_user_role_assignment_history`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.tenant_user_role_assignment_history_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `tenant_user_id` | `integer` | NULL | `—` | `none / none` |
| `assignment_id` | `integer` | NULL | `—` | `none / none` |
| `role_id` | `integer` | NULL | `—` | `none / none` |
| `role_code_snapshot` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `event_type` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `previous_status` | `character varying(16)` | NULL | `—` | `none / none` |
| `new_status` | `character varying(16)` | NULL | `—` | `none / none` |
| `previous_primary` | `boolean` | NULL | `—` | `none / none` |
| `new_primary` | `boolean` | NULL | `—` | `none / none` |
| `actor_user_id` | `integer` | NULL | `—` | `none / none` |
| `assignment_source` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `reason` | `character varying(512)` | NULL | `—` | `none / none` |
| `before_membership_version` | `integer` | NOT NULL | `—` | `none / none` |
| `after_membership_version` | `integer` | NOT NULL | `—` | `none / none` |
| `correlation_id` | `character varying(128)` | NULL | `—` | `none / none` |
| `occurred_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `metadata_json` | `json` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_tenant_user_role_assignment_history_tenant_role_assi_3223` | c | `CHECK (assignment_source::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_tenant_user_role_assignment_history_tenant_role_assi_902f` | c | `CHECK (event_type::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_tenant_user_role_assignment_history_tenant_role_assi_f6d5` | c | `CHECK (before_membership_version >= 1 AND after_membership_version >= before_membership_version)` | True / False / False |
| `fk_tenant_user_role_assignment_history_actor_user_id_iam_users` | f | `FOREIGN KEY (actor_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_tenant_user_role_assignment_history_assignment_id_te_89a9` | f | `FOREIGN KEY (assignment_id) REFERENCES public.tenant_user_role_assignments(id) ON DELETE SET NULL` | True / False / False |
| `fk_tenant_user_role_assignment_history_role_id_authoriz_9a90` | f | `FOREIGN KEY (role_id) REFERENCES public.authorization_roles(id) ON DELETE SET NULL` | True / False / False |
| `fk_tenant_user_role_assignment_history_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE RESTRICT` | True / False / False |
| `fk_tenant_user_role_assignment_history_tenant_user_id_t_b1b5` | f | `FOREIGN KEY (tenant_user_id) REFERENCES public.tenant_users(id) ON DELETE SET NULL` | True / False / False |
| `pk_tenant_user_role_assignment_history` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_tenant_role_assignment_history_assignment_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_role_assignment_history_assignment_id ON public.tenant_user_role_assignment_history USING btree (assignment_id)` |
| `ix_tenant_role_assignment_history_membership_time` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_role_assignment_history_membership_time ON public.tenant_user_role_assignment_history USING btree (tenant_id, tenant_user_id, occurred_at)` |
| `ix_tenant_role_assignment_history_occurred_at` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_role_assignment_history_occurred_at ON public.tenant_user_role_assignment_history USING btree (occurred_at)` |
| `ix_tenant_role_assignment_history_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_role_assignment_history_tenant_id ON public.tenant_user_role_assignment_history USING btree (tenant_id)` |
| `ix_tenant_role_assignment_history_tenant_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_role_assignment_history_tenant_user_id ON public.tenant_user_role_assignment_history USING btree (tenant_user_id)` |
| `pk_tenant_user_role_assignment_history` | btree / True | `pk_tenant_user_role_assignment_history` | True / True | `CREATE UNIQUE INDEX pk_tenant_user_role_assignment_history ON public.tenant_user_role_assignment_history USING btree (id)` |

### `public.tenant_user_role_assignments`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.tenant_user_role_assignments_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `tenant_user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `role_id` | `integer` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(16)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `is_primary` | `boolean` | NOT NULL | `false` | `none / none` |
| `assignment_source` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `assigned_by_user_id` | `integer` | NULL | `—` | `none / none` |
| `assigned_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `revoked_by_user_id` | `integer` | NULL | `—` | `none / none` |
| `revoked_at` | `timestamp with time zone` | NULL | `—` | `none / none` |
| `revocation_reason` | `character varying(512)` | NULL | `—` | `none / none` |
| `version` | `integer` | NOT NULL | `1` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_tenant_user_role_assignments_tenant_role_assignment__f1b0` | c | `CHECK (status::text = '<literal redacted>'::text AND revoked_at IS NULL AND revoked_by_user_id IS NULL OR status::text = '<literal redacted>'::text AND revoked_at IS NOT NULL AND is_primary = false)` | True / False / False |
| `ck_tenant_user_role_assignments_tenant_role_assignment_source` | c | `CHECK (assignment_source::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_tenant_user_role_assignments_tenant_role_assignment_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_tenant_user_role_assignments_tenant_role_assignment_version` | c | `CHECK (version >= 1)` | True / False / False |
| `fk_tenant_role_assignment_membership_tenant` | f | `FOREIGN KEY (tenant_user_id, tenant_id) REFERENCES public.tenant_users(id, tenant_id) ON DELETE CASCADE` | True / False / False |
| `fk_tenant_user_role_assignments_assigned_by_user_id_iam_users` | f | `FOREIGN KEY (assigned_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_tenant_user_role_assignments_revoked_by_user_id_iam_users` | f | `FOREIGN KEY (revoked_by_user_id) REFERENCES public.iam_users(id) ON DELETE SET NULL` | True / False / False |
| `fk_tenant_user_role_assignments_role_id_authorization_roles` | f | `FOREIGN KEY (role_id) REFERENCES public.authorization_roles(id) ON DELETE RESTRICT` | True / False / False |
| `fk_tenant_user_role_assignments_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE` | True / False / False |
| `pk_tenant_user_role_assignments` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_tenant_user_role_assignments_membership_role` | u | `UNIQUE (tenant_user_id, role_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_tenant_user_role_assignments_membership_status` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_user_role_assignments_membership_status ON public.tenant_user_role_assignments USING btree (tenant_user_id, status)` |
| `ix_tenant_user_role_assignments_role_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_user_role_assignments_role_id ON public.tenant_user_role_assignments USING btree (role_id)` |
| `ix_tenant_user_role_assignments_status` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_user_role_assignments_status ON public.tenant_user_role_assignments USING btree (status)` |
| `ix_tenant_user_role_assignments_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_user_role_assignments_tenant_id ON public.tenant_user_role_assignments USING btree (tenant_id)` |
| `ix_tenant_user_role_assignments_tenant_status` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_user_role_assignments_tenant_status ON public.tenant_user_role_assignments USING btree (tenant_id, status)` |
| `ix_tenant_user_role_assignments_tenant_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_user_role_assignments_tenant_user_id ON public.tenant_user_role_assignments USING btree (tenant_user_id)` |
| `pk_tenant_user_role_assignments` | btree / True | `pk_tenant_user_role_assignments` | True / True | `CREATE UNIQUE INDEX pk_tenant_user_role_assignments ON public.tenant_user_role_assignments USING btree (id)` |
| `uq_tenant_user_role_assignments_active_primary` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_tenant_user_role_assignments_active_primary ON public.tenant_user_role_assignments USING btree (tenant_user_id) WHERE (((status)::text = '<literal redacted>'::text) AND is_primary)` |
| `uq_tenant_user_role_assignments_membership_role` | btree / True | `uq_tenant_user_role_assignments_membership_role` | True / True | `CREATE UNIQUE INDEX uq_tenant_user_role_assignments_membership_role ON public.tenant_user_role_assignments USING btree (tenant_user_id, role_id)` |

### `public.tenant_users`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.tenant_users_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `role` | `character varying(64)` | NOT NULL | `—` | `none / none` |
| `status` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `role_assignment_version` | `integer` | NOT NULL | `1` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_tenant_users_tenant_user_role_assignment_version` | c | `CHECK (role_assignment_version >= 1)` | True / False / False |
| `ck_tenant_users_tenant_user_role_normalized` | c | `CHECK (length(TRIM(BOTH FROM role)) > 0 AND role::text = upper(role::text))` | True / False / False |
| `ck_tenant_users_tenant_user_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text]))` | True / False / False |
| `fk_tenant_users_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE` | True / False / False |
| `fk_tenant_users_user_id_iam_users` | f | `FOREIGN KEY (user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE` | True / False / False |
| `pk_tenant_users` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_tenant_users_id_tenant` | u | `UNIQUE (id, tenant_id)` | True / False / False |
| `uq_tenant_users_tenant_user` | u | `UNIQUE (tenant_id, user_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_tenant_users_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_users_tenant_id ON public.tenant_users USING btree (tenant_id)` |
| `ix_tenant_users_tenant_status` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_users_tenant_status ON public.tenant_users USING btree (tenant_id, status)` |
| `ix_tenant_users_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenant_users_user_id ON public.tenant_users USING btree (user_id)` |
| `pk_tenant_users` | btree / True | `pk_tenant_users` | True / True | `CREATE UNIQUE INDEX pk_tenant_users ON public.tenant_users USING btree (id)` |
| `uq_tenant_users_id_tenant` | btree / True | `uq_tenant_users_id_tenant` | True / True | `CREATE UNIQUE INDEX uq_tenant_users_id_tenant ON public.tenant_users USING btree (id, tenant_id)` |
| `uq_tenant_users_tenant_user` | btree / True | `uq_tenant_users_tenant_user` | True / True | `CREATE UNIQUE INDEX uq_tenant_users_tenant_user ON public.tenant_users USING btree (tenant_id, user_id)` |

### `public.tenants`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.tenants_id_seq'::regclass)` | `none / none` |
| `name` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `slug` | `character varying(128)` | NOT NULL | `—` | `none / none` |
| `external_iam_tenant_id` | `character varying(255)` | NULL | `—` | `none / none` |
| `status` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_tenants_tenant_status` | c | `CHECK (status::text = ANY (ARRAY['<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text, '<literal redacted>'::character varying::text]))` | True / False / False |
| `pk_tenants` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_tenants_external_iam_tenant_id` | u | `UNIQUE (external_iam_tenant_id)` | True / False / False |
| `uq_tenants_slug` | u | `UNIQUE (slug)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_tenants_external_iam_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_tenants_external_iam_tenant_id ON public.tenants USING btree (external_iam_tenant_id)` |
| `ix_tenants_slug` | btree / False | `none` | True / True | `CREATE INDEX ix_tenants_slug ON public.tenants USING btree (slug)` |
| `pk_tenants` | btree / True | `pk_tenants` | True / True | `CREATE UNIQUE INDEX pk_tenants ON public.tenants USING btree (id)` |
| `uq_tenants_external_iam_tenant_id` | btree / True | `uq_tenants_external_iam_tenant_id` | True / True | `CREATE UNIQUE INDEX uq_tenants_external_iam_tenant_id ON public.tenants USING btree (external_iam_tenant_id)` |
| `uq_tenants_slug` | btree / True | `uq_tenants_slug` | True / True | `CREATE UNIQUE INDEX uq_tenants_slug ON public.tenants USING btree (slug)` |

### `public.user_identities`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.user_identities_id_seq'::regclass)` | `none / none` |
| `user_id` | `integer` | NOT NULL | `—` | `none / none` |
| `provider_type` | `character varying(16)` | NOT NULL | `—` | `none / none` |
| `issuer` | `character varying(512)` | NULL | `—` | `none / none` |
| `subject` | `character varying(255)` | NULL | `—` | `none / none` |
| `provider_identifier` | `character varying(320)` | NULL | `—` | `none / none` |
| `provider_email` | `character varying(320)` | NULL | `—` | `none / none` |
| `created_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `updated_at` | `timestamp with time zone` | NOT NULL | `—` | `none / none` |
| `last_authenticated_at` | `timestamp with time zone` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `ck_user_identities_identity_provider` | c | `CHECK (provider_type::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[]))` | True / False / False |
| `ck_user_identities_identity_provider_fields` | c | `CHECK ((provider_type::text = ANY (ARRAY['<literal redacted>'::character varying, '<literal redacted>'::character varying]::text[])) AND issuer IS NOT NULL AND length(TRIM(BOTH FROM issuer)) > 0 AND subject IS NOT NULL AND length(TRIM(BOTH FROM subject)) > 0 OR provider_type::text = '<literal redacted>'::text AND issuer IS NULL AND subject IS NULL AND provider_identifier IS NOT NULL AND length(TRIM(BOTH FROM provider_identifier)) > 0 AND provider_identifier::text = lower(TRIM(BOTH FROM provider_identifier)))` | True / False / False |
| `fk_user_identities_user_id_iam_users` | f | `FOREIGN KEY (user_id) REFERENCES public.iam_users(id) ON DELETE CASCADE` | True / False / False |
| `pk_user_identities` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_user_identities_external` | u | `UNIQUE (provider_type, issuer, subject)` | True / False / False |
| `uq_user_identities_user_provider` | u | `UNIQUE (user_id, provider_type)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_user_identities_user_id` | btree / False | `none` | True / True | `CREATE INDEX ix_user_identities_user_id ON public.user_identities USING btree (user_id)` |
| `pk_user_identities` | btree / True | `pk_user_identities` | True / True | `CREATE UNIQUE INDEX pk_user_identities ON public.user_identities USING btree (id)` |
| `uq_user_identities_external` | btree / True | `uq_user_identities_external` | True / True | `CREATE UNIQUE INDEX uq_user_identities_external ON public.user_identities USING btree (provider_type, issuer, subject)` |
| `uq_user_identities_native_email` | btree / True | `none` | True / True | `CREATE UNIQUE INDEX uq_user_identities_native_email ON public.user_identities USING btree (provider_identifier) WHERE ((provider_type)::text = '<literal redacted>'::text)` |
| `uq_user_identities_user_provider` | btree / True | `uq_user_identities_user_provider` | True / True | `CREATE UNIQUE INDEX uq_user_identities_user_provider ON public.user_identities USING btree (user_id, provider_type)` |

### `public.vex_documents`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.vex_documents_id_seq'::regclass)` | `none / none` |
| `sbom_id` | `integer` | NOT NULL | `—` | `none / none` |
| `source_type` | `character varying` | NOT NULL | `—` | `none / none` |
| `format` | `character varying` | NULL | `—` | `none / none` |
| `author` | `character varying` | NULL | `—` | `none / none` |
| `source_url` | `character varying` | NULL | `—` | `none / none` |
| `discovery_evidence_json` | `json` | NULL | `—` | `none / none` |
| `last_refresh_status` | `character varying` | NULL | `—` | `none / none` |
| `provider_errors_json` | `json` | NULL | `—` | `none / none` |
| `uploaded_by` | `character varying` | NULL | `—` | `none / none` |
| `uploaded_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `raw_document_json` | `json` | NULL | `—` | `none / none` |
| `validation_status` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `source_document_id` | `character varying` | NULL | `—` | `none / none` |
| `source_document_version` | `character varying` | NULL | `—` | `none / none` |
| `source_hash` | `character varying(64)` | NULL | `—` | `none / none` |
| `asserted_at` | `character varying` | NULL | `—` | `none / none` |
| `superseded_by_id` | `integer` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_vex_documents_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE CASCADE` | True / False / False |
| `fk_vex_documents_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_vex_documents` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_vex_documents_asserted_at` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_asserted_at ON public.vex_documents USING btree (asserted_at)` |
| `ix_vex_documents_format` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_format ON public.vex_documents USING btree (format)` |
| `ix_vex_documents_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_id ON public.vex_documents USING btree (id)` |
| `ix_vex_documents_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_sbom_id ON public.vex_documents USING btree (sbom_id)` |
| `ix_vex_documents_source_document_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_source_document_id ON public.vex_documents USING btree (source_document_id)` |
| `ix_vex_documents_source_hash` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_source_hash ON public.vex_documents USING btree (source_hash)` |
| `ix_vex_documents_source_type` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_source_type ON public.vex_documents USING btree (source_type)` |
| `ix_vex_documents_superseded_by_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_superseded_by_id ON public.vex_documents USING btree (superseded_by_id)` |
| `ix_vex_documents_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_tenant_id ON public.vex_documents USING btree (tenant_id)` |
| `ix_vex_documents_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_tenant_identity ON public.vex_documents USING btree (tenant_id, id)` |
| `ix_vex_documents_uploaded_at` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_uploaded_at ON public.vex_documents USING btree (uploaded_at)` |
| `ix_vex_documents_uploaded_by` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_uploaded_by ON public.vex_documents USING btree (uploaded_by)` |
| `ix_vex_documents_validation_status` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_documents_validation_status ON public.vex_documents USING btree (validation_status)` |
| `pk_vex_documents` | btree / True | `pk_vex_documents` | True / True | `CREATE UNIQUE INDEX pk_vex_documents ON public.vex_documents USING btree (id)` |

### `public.vex_investigation`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.vex_investigation_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `sbom_id` | `integer` | NOT NULL | `—` | `none / none` |
| `component_id` | `integer` | NULL | `—` | `none / none` |
| `component_key` | `integer` | NOT NULL | `0` | `none / none` |
| `canonical_vulnerability_id` | `character varying(255)` | NOT NULL | `—` | `none / none` |
| `aliases_json` | `text` | NULL | `—` | `none / none` |
| `effective_status` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `reconciliation_status` | `character varying(32)` | NOT NULL | `—` | `none / none` |
| `analyzer_detection_state` | `character varying(32)` | NULL | `—` | `none / none` |
| `effective_vex_statement_id` | `integer` | NULL | `—` | `none / none` |
| `unresolved_discriminator` | `character varying(64)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `is_current` | `boolean` | NOT NULL | `true` | `none / none` |
| `first_seen_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `last_seen_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `last_analysis_run_id` | `integer` | NULL | `—` | `none / none` |
| `assigned_to` | `character varying` | NULL | `—` | `none / none` |
| `reviewed_by` | `character varying` | NULL | `—` | `none / none` |
| `reviewed_at` | `character varying` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_at` | `character varying` | NULL | `—` | `none / none` |
| `row_version` | `integer` | NOT NULL | `1` | `none / none` |
| `analyzer_sources_json` | `text` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_vex_investigation_component_id_sbom_component` | f | `FOREIGN KEY (component_id) REFERENCES public.sbom_component(id) ON DELETE SET NULL` | True / False / False |
| `fk_vex_investigation_effective_vex_statement_id_vex_statements` | f | `FOREIGN KEY (effective_vex_statement_id) REFERENCES public.vex_statements(id) ON DELETE SET NULL` | True / False / False |
| `fk_vex_investigation_last_analysis_run_id_analysis_run` | f | `FOREIGN KEY (last_analysis_run_id) REFERENCES public.analysis_run(id) ON DELETE SET NULL` | True / False / False |
| `fk_vex_investigation_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE CASCADE` | True / False / False |
| `fk_vex_investigation_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_vex_investigation` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_vex_investigation_context` | u | `UNIQUE (tenant_id, sbom_id, component_key, canonical_vulnerability_id, unresolved_discriminator)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_vex_investigation_analyzer_detection_state` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_analyzer_detection_state ON public.vex_investigation USING btree (analyzer_detection_state)` |
| `ix_vex_investigation_assigned_to` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_assigned_to ON public.vex_investigation USING btree (assigned_to)` |
| `ix_vex_investigation_canonical_vulnerability_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_canonical_vulnerability_id ON public.vex_investigation USING btree (canonical_vulnerability_id)` |
| `ix_vex_investigation_component_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_component_id ON public.vex_investigation USING btree (component_id)` |
| `ix_vex_investigation_effective_status` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_effective_status ON public.vex_investigation USING btree (effective_status)` |
| `ix_vex_investigation_effective_vex_statement_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_effective_vex_statement_id ON public.vex_investigation USING btree (effective_vex_statement_id)` |
| `ix_vex_investigation_first_seen_at` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_first_seen_at ON public.vex_investigation USING btree (first_seen_at)` |
| `ix_vex_investigation_is_current` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_is_current ON public.vex_investigation USING btree (is_current)` |
| `ix_vex_investigation_last_analysis_run_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_last_analysis_run_id ON public.vex_investigation USING btree (last_analysis_run_id)` |
| `ix_vex_investigation_last_seen_at` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_last_seen_at ON public.vex_investigation USING btree (last_seen_at)` |
| `ix_vex_investigation_queue` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_queue ON public.vex_investigation USING btree (tenant_id, is_current, reconciliation_status)` |
| `ix_vex_investigation_reconciliation_status` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_reconciliation_status ON public.vex_investigation USING btree (reconciliation_status)` |
| `ix_vex_investigation_sbom_current` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_sbom_current ON public.vex_investigation USING btree (sbom_id, is_current)` |
| `ix_vex_investigation_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_sbom_id ON public.vex_investigation USING btree (sbom_id)` |
| `ix_vex_investigation_status` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_status ON public.vex_investigation USING btree (tenant_id, is_current, effective_status)` |
| `ix_vex_investigation_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_tenant_id ON public.vex_investigation USING btree (tenant_id)` |
| `pk_vex_investigation` | btree / True | `pk_vex_investigation` | True / True | `CREATE UNIQUE INDEX pk_vex_investigation ON public.vex_investigation USING btree (id)` |
| `uq_vex_investigation_context` | btree / True | `uq_vex_investigation_context` | True / True | `CREATE UNIQUE INDEX uq_vex_investigation_context ON public.vex_investigation USING btree (tenant_id, sbom_id, component_key, canonical_vulnerability_id, unresolved_discriminator)` |

### `public.vex_investigation_snapshot`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.vex_investigation_snapshot_id_seq'::regclass)` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `sbom_id` | `integer` | NOT NULL | `—` | `none / none` |
| `analysis_run_id` | `integer` | NOT NULL | `—` | `none / none` |
| `investigation_id` | `integer` | NOT NULL | `—` | `none / none` |
| `payload_json` | `json` | NOT NULL | `—` | `none / none` |
| `captured_at` | `character varying` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_vex_investigation_snapshot_analysis_run_id_analysis_run` | f | `FOREIGN KEY (analysis_run_id) REFERENCES public.analysis_run(id) ON DELETE CASCADE` | True / False / False |
| `fk_vex_investigation_snapshot_investigation_id_vex_inve_284e` | f | `FOREIGN KEY (investigation_id) REFERENCES public.vex_investigation(id) ON DELETE CASCADE` | True / False / False |
| `fk_vex_investigation_snapshot_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE CASCADE` | True / False / False |
| `fk_vex_investigation_snapshot_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_vex_investigation_snapshot` | p | `PRIMARY KEY (id)` | True / False / False |
| `uq_vex_run_context_snapshot` | u | `UNIQUE (analysis_run_id, investigation_id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_vex_investigation_snapshot_analysis_run_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_snapshot_analysis_run_id ON public.vex_investigation_snapshot USING btree (analysis_run_id)` |
| `ix_vex_investigation_snapshot_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_snapshot_sbom_id ON public.vex_investigation_snapshot USING btree (sbom_id)` |
| `ix_vex_investigation_snapshot_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_investigation_snapshot_tenant_id ON public.vex_investigation_snapshot USING btree (tenant_id)` |
| `pk_vex_investigation_snapshot` | btree / True | `pk_vex_investigation_snapshot` | True / True | `CREATE UNIQUE INDEX pk_vex_investigation_snapshot ON public.vex_investigation_snapshot USING btree (id)` |
| `uq_vex_run_context_snapshot` | btree / True | `uq_vex_run_context_snapshot` | True / True | `CREATE UNIQUE INDEX uq_vex_run_context_snapshot ON public.vex_investigation_snapshot USING btree (analysis_run_id, investigation_id)` |

### `public.vex_override_audit`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.vex_override_audit_id_seq'::regclass)` | `none / none` |
| `component_id` | `integer` | NULL | `—` | `none / none` |
| `vulnerability_id` | `character varying` | NOT NULL | `—` | `none / none` |
| `old_value_json` | `json` | NULL | `—` | `none / none` |
| `new_value_json` | `json` | NULL | `—` | `none / none` |
| `reason` | `text` | NOT NULL | `—` | `none / none` |
| `evidence_url` | `character varying` | NULL | `—` | `none / none` |
| `changed_by` | `character varying` | NULL | `—` | `none / none` |
| `changed_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `sbom_id` | `integer` | NULL | `—` | `none / none` |
| `investigation_id` | `integer` | NULL | `—` | `none / none` |
| `action` | `character varying(32)` | NOT NULL | `'<literal redacted>'::character varying` | `none / none` |
| `previous_status` | `character varying(32)` | NULL | `—` | `none / none` |
| `new_status` | `character varying(32)` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_vex_override_audit_component_id_sbom_component` | f | `FOREIGN KEY (component_id) REFERENCES public.sbom_component(id) ON DELETE CASCADE` | True / False / False |
| `fk_vex_override_audit_investigation_id_vex_investigation` | f | `FOREIGN KEY (investigation_id) REFERENCES public.vex_investigation(id) ON DELETE SET NULL` | True / False / False |
| `fk_vex_override_audit_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE CASCADE` | True / False / False |
| `fk_vex_override_audit_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_vex_override_audit` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_vex_override_audit_action` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_action ON public.vex_override_audit USING btree (action)` |
| `ix_vex_override_audit_changed_at` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_changed_at ON public.vex_override_audit USING btree (changed_at)` |
| `ix_vex_override_audit_changed_by` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_changed_by ON public.vex_override_audit USING btree (changed_by)` |
| `ix_vex_override_audit_component_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_component_id ON public.vex_override_audit USING btree (component_id)` |
| `ix_vex_override_audit_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_id ON public.vex_override_audit USING btree (id)` |
| `ix_vex_override_audit_investigation_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_investigation_id ON public.vex_override_audit USING btree (investigation_id)` |
| `ix_vex_override_audit_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_sbom_id ON public.vex_override_audit USING btree (sbom_id)` |
| `ix_vex_override_audit_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_tenant_id ON public.vex_override_audit USING btree (tenant_id)` |
| `ix_vex_override_audit_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_tenant_identity ON public.vex_override_audit USING btree (tenant_id, id)` |
| `ix_vex_override_audit_vulnerability_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_override_audit_vulnerability_id ON public.vex_override_audit USING btree (vulnerability_id)` |
| `pk_vex_override_audit` | btree / True | `pk_vex_override_audit` | True / True | `CREATE UNIQUE INDEX pk_vex_override_audit ON public.vex_override_audit USING btree (id)` |

### `public.vex_statements`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.vex_statements_id_seq'::regclass)` | `none / none` |
| `vex_document_id` | `integer` | NULL | `—` | `none / none` |
| `sbom_id` | `integer` | NOT NULL | `—` | `none / none` |
| `component_id` | `integer` | NULL | `—` | `none / none` |
| `vulnerability_id` | `character varying` | NOT NULL | `—` | `none / none` |
| `cve_id` | `character varying` | NULL | `—` | `none / none` |
| `status` | `character varying` | NOT NULL | `—` | `none / none` |
| `justification` | `text` | NULL | `—` | `none / none` |
| `impact_statement` | `text` | NULL | `—` | `none / none` |
| `action_statement` | `text` | NULL | `—` | `none / none` |
| `fixed_version` | `character varying` | NULL | `—` | `none / none` |
| `mitigation` | `text` | NULL | `—` | `none / none` |
| `source_name` | `character varying` | NULL | `—` | `none / none` |
| `source_url` | `character varying` | NULL | `—` | `none / none` |
| `confidence` | `character varying` | NULL | `—` | `none / none` |
| `evidence_json` | `json` | NULL | `—` | `none / none` |
| `created_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |
| `source_format` | `character varying(32)` | NULL | `—` | `none / none` |
| `source_status` | `character varying(64)` | NULL | `—` | `none / none` |
| `normalized_status` | `character varying(32)` | NULL | `—` | `none / none` |
| `asserted_at` | `character varying` | NULL | `—` | `none / none` |
| `match_strategy` | `character varying(32)` | NULL | `—` | `none / none` |
| `match_confidence` | `character varying(16)` | NULL | `—` | `none / none` |
| `version_applicable` | `boolean` | NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_vex_statements_component_id_sbom_component` | f | `FOREIGN KEY (component_id) REFERENCES public.sbom_component(id) ON DELETE SET NULL` | True / False / False |
| `fk_vex_statements_sbom_id_sbom_source` | f | `FOREIGN KEY (sbom_id) REFERENCES public.sbom_source(id) ON DELETE CASCADE` | True / False / False |
| `fk_vex_statements_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `fk_vex_statements_vex_document_id_vex_documents` | f | `FOREIGN KEY (vex_document_id) REFERENCES public.vex_documents(id) ON DELETE CASCADE` | True / False / False |
| `pk_vex_statements` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_vex_statement_component_vuln` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statement_component_vuln ON public.vex_statements USING btree (component_id, vulnerability_id)` |
| `ix_vex_statement_sbom_status` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statement_sbom_status ON public.vex_statements USING btree (sbom_id, status)` |
| `ix_vex_statements_component_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_component_id ON public.vex_statements USING btree (component_id)` |
| `ix_vex_statements_created_at` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_created_at ON public.vex_statements USING btree (created_at)` |
| `ix_vex_statements_cve_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_cve_id ON public.vex_statements USING btree (cve_id)` |
| `ix_vex_statements_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_id ON public.vex_statements USING btree (id)` |
| `ix_vex_statements_normalized_status` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_normalized_status ON public.vex_statements USING btree (normalized_status)` |
| `ix_vex_statements_sbom_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_sbom_id ON public.vex_statements USING btree (sbom_id)` |
| `ix_vex_statements_source_format` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_source_format ON public.vex_statements USING btree (source_format)` |
| `ix_vex_statements_status` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_status ON public.vex_statements USING btree (status)` |
| `ix_vex_statements_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_tenant_id ON public.vex_statements USING btree (tenant_id)` |
| `ix_vex_statements_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_tenant_identity ON public.vex_statements USING btree (tenant_id, id)` |
| `ix_vex_statements_vex_document_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_vex_document_id ON public.vex_statements USING btree (vex_document_id)` |
| `ix_vex_statements_vulnerability_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vex_statements_vulnerability_id ON public.vex_statements USING btree (vulnerability_id)` |
| `pk_vex_statements` | btree / True | `pk_vex_statements` | True / True | `CREATE UNIQUE INDEX pk_vex_statements ON public.vex_statements USING btree (id)` |

### `public.vulnerability_remediation`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.vulnerability_remediation_id_seq'::regclass)` | `none / none` |
| `project_id` | `integer` | NOT NULL | `—` | `none / none` |
| `vuln_id` | `character varying` | NOT NULL | `—` | `none / none` |
| `component_name` | `character varying` | NOT NULL | `—` | `none / none` |
| `component_version` | `character varying` | NOT NULL | `—` | `none / none` |
| `fixed_version` | `character varying` | NULL | `—` | `none / none` |
| `status` | `character varying` | NOT NULL | `—` | `none / none` |
| `owner` | `character varying` | NULL | `—` | `none / none` |
| `due_date` | `character varying` | NULL | `—` | `none / none` |
| `resolution_date` | `character varying` | NULL | `—` | `none / none` |
| `fix_notes` | `text` | NULL | `—` | `none / none` |
| `created_on` | `character varying` | NOT NULL | `—` | `none / none` |
| `updated_on` | `character varying` | NOT NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_vulnerability_remediation_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE` | True / False / False |
| `fk_vulnerability_remediation_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_vulnerability_remediation` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_vulnerability_remediation_component_name` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_component_name ON public.vulnerability_remediation USING btree (component_name)` |
| `ix_vulnerability_remediation_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_id ON public.vulnerability_remediation USING btree (id)` |
| `ix_vulnerability_remediation_project_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_project_id ON public.vulnerability_remediation USING btree (project_id)` |
| `ix_vulnerability_remediation_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_tenant_id ON public.vulnerability_remediation USING btree (tenant_id)` |
| `ix_vulnerability_remediation_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_tenant_identity ON public.vulnerability_remediation USING btree (tenant_id, id)` |
| `ix_vulnerability_remediation_vuln_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_vuln_id ON public.vulnerability_remediation USING btree (vuln_id)` |
| `pk_vulnerability_remediation` | btree / True | `pk_vulnerability_remediation` | True / True | `CREATE UNIQUE INDEX pk_vulnerability_remediation ON public.vulnerability_remediation USING btree (id)` |

### `public.vulnerability_remediation_audit`

| Column | PostgreSQL type | Nullability | Default | Identity / generated |
| --- | --- | --- | --- | --- |
| `id` | `integer` | NOT NULL | `nextval('public.vulnerability_remediation_audit_id_seq'::regclass)` | `none / none` |
| `remediation_id` | `integer` | NOT NULL | `—` | `none / none` |
| `project_id` | `integer` | NOT NULL | `—` | `none / none` |
| `vuln_id` | `character varying` | NOT NULL | `—` | `none / none` |
| `component_name` | `character varying` | NOT NULL | `—` | `none / none` |
| `component_version` | `character varying` | NOT NULL | `—` | `none / none` |
| `old_status` | `character varying` | NULL | `—` | `none / none` |
| `new_status` | `character varying` | NOT NULL | `—` | `none / none` |
| `changed_by` | `character varying(128)` | NULL | `—` | `none / none` |
| `changed_at` | `character varying` | NOT NULL | `—` | `none / none` |
| `note` | `text` | NULL | `—` | `none / none` |
| `tenant_id` | `integer` | NOT NULL | `—` | `none / none` |

| Constraint | Kind | Definition | Validated / deferrable / initially deferred |
| --- | --- | --- | --- |
| `fk_vulnerability_remediation_audit_project_id_projects` | f | `FOREIGN KEY (project_id) REFERENCES public.projects(id) ON DELETE CASCADE` | True / False / False |
| `fk_vulnerability_remediation_audit_remediation_id_vulne_f9a9` | f | `FOREIGN KEY (remediation_id) REFERENCES public.vulnerability_remediation(id) ON DELETE CASCADE` | True / False / False |
| `fk_vulnerability_remediation_audit_tenant_id_tenants` | f | `FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)` | True / False / False |
| `pk_vulnerability_remediation_audit` | p | `PRIMARY KEY (id)` | True / False / False |

| Index | Method / unique | Backing constraint | Valid / ready | Definition |
| --- | --- | --- | --- | --- |
| `ix_vulnerability_remediation_audit_changed_at` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_changed_at ON public.vulnerability_remediation_audit USING btree (changed_at)` |
| `ix_vulnerability_remediation_audit_component_name` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_component_name ON public.vulnerability_remediation_audit USING btree (component_name)` |
| `ix_vulnerability_remediation_audit_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_id ON public.vulnerability_remediation_audit USING btree (id)` |
| `ix_vulnerability_remediation_audit_project_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_project_id ON public.vulnerability_remediation_audit USING btree (project_id)` |
| `ix_vulnerability_remediation_audit_remediation_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_remediation_id ON public.vulnerability_remediation_audit USING btree (remediation_id)` |
| `ix_vulnerability_remediation_audit_tenant_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_tenant_id ON public.vulnerability_remediation_audit USING btree (tenant_id)` |
| `ix_vulnerability_remediation_audit_tenant_identity` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_tenant_identity ON public.vulnerability_remediation_audit USING btree (tenant_id, id)` |
| `ix_vulnerability_remediation_audit_vuln_id` | btree / False | `none` | True / True | `CREATE INDEX ix_vulnerability_remediation_audit_vuln_id ON public.vulnerability_remediation_audit USING btree (vuln_id)` |
| `pk_vulnerability_remediation_audit` | btree / True | `pk_vulnerability_remediation_audit` | True / True | `CREATE UNIQUE INDEX pk_vulnerability_remediation_audit ON public.vulnerability_remediation_audit USING btree (id)` |

</details>

## Reusable read-only SQL inventory

Access was available, so this is a reproducibility aid rather than a BLOCKED fallback. Connect through an already authorized connection without embedding a URL or password in this document. Run once per intended target. The statements read catalogs/statistics and the known public Alembic marker only; expression literals are redacted. The exact included script was also executed successfully against B in an enforced read-only connection, with read-only/isolation results checked and ROLLBACK confirmed by the final statement. A missing revision table can make the revision query fail; end with ROLLBACK and report that limitation rather than creating/stamping it.

```sql
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '3s';
SET LOCAL lock_timeout = '1s';
SET LOCAL search_path = pg_catalog;
SHOW transaction_read_only;
SHOW transaction_isolation;
SHOW server_version;
SELECT transaction_timestamp() AS observed_utc;
SELECT version_num FROM public.alembic_version ORDER BY version_num LIMIT 20;

-- tables
SELECT n.nspname AS schema, c.relname AS name, c.relkind AS kind,
      c.reltuples::double precision AS estimated_rows, c.relispartition AS is_partition,
      s.n_live_tup AS stats_live_rows, s.last_analyze, s.last_autoanalyze
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      LEFT JOIN pg_catalog.pg_stat_all_tables s ON s.relid=c.oid
      WHERE c.relkind IN ('r','p','f') AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
      ORDER BY n.nspname,c.relname;

-- columns
SELECT n.nspname AS schema,c.relname AS table_name,a.attname AS name,
      a.attnum AS ordinal,pg_catalog.format_type(a.atttypid,a.atttypmod) AS type,
      a.attnotnull AS not_null,a.attidentity AS identity,a.attgenerated AS generated,
      pg_catalog.regexp_replace(pg_catalog.pg_get_expr(d.adbin,d.adrelid), $rx$'([^']|'')*'$rx$, $rep$'<literal redacted>'$rep$, 'g') AS default_expr
      FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
      WHERE a.attnum>0 AND NOT a.attisdropped AND c.relkind IN ('r','p','f')
      AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
      ORDER BY n.nspname,c.relname,a.attnum;

-- constraints
SELECT n.nspname AS schema,c.relname AS table_name,k.conname AS name,
      k.contype AS kind,k.convalidated AS validated,k.condeferrable AS deferrable,k.condeferred AS deferred,
      ARRAY(SELECT a.attname FROM unnest(k.conkey) WITH ORDINALITY x(attnum,ord)
        JOIN pg_catalog.pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=x.attnum ORDER BY x.ord) AS columns,
      pn.nspname AS parent_schema,pc.relname AS parent_table,
      ARRAY(SELECT a.attname FROM unnest(k.confkey) WITH ORDINALITY x(attnum,ord)
        JOIN pg_catalog.pg_attribute a ON a.attrelid=k.confrelid AND a.attnum=x.attnum ORDER BY x.ord) AS parent_columns,
      k.confdeltype AS delete_code,k.confupdtype AS update_code,k.confmatchtype AS match_code,
      pg_catalog.regexp_replace(pg_catalog.pg_get_constraintdef(k.oid,true), $rx$'([^']|'')*'$rx$, $rep$'<literal redacted>'$rep$, 'g') AS definition
      FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      LEFT JOIN pg_catalog.pg_class pc ON pc.oid=k.confrelid
      LEFT JOIN pg_catalog.pg_namespace pn ON pn.oid=pc.relnamespace
      WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
      AND c.relkind IN ('r','p','f') ORDER BY n.nspname,c.relname,k.contype,k.conname;

-- indexes
SELECT n.nspname AS schema,c.relname AS table_name,ic.relname AS name,
      am.amname AS method,i.indisunique AS unique,i.indisprimary AS primary,i.indisvalid AS valid,
      i.indisready AS ready,k.conname AS constraint_name,
      ARRAY(SELECT pg_catalog.regexp_replace(pg_catalog.pg_get_indexdef(i.indexrelid,x,true), $rx$'([^']|'')*'$rx$, $rep$'<literal redacted>'$rep$, 'g')
        FROM generate_series(1,i.indnkeyatts) x) AS keys,
      ARRAY(SELECT pg_catalog.regexp_replace(pg_catalog.pg_get_indexdef(i.indexrelid,x,true), $rx$'([^']|'')*'$rx$, $rep$'<literal redacted>'$rep$, 'g')
        FROM generate_series(i.indnkeyatts+1,i.indnatts) x) AS include,
      pg_catalog.regexp_replace(pg_catalog.pg_get_expr(i.indpred,i.indrelid), $rx$'([^']|'')*'$rx$, $rep$'<literal redacted>'$rep$, 'g') AS predicate,
      pg_catalog.regexp_replace(pg_catalog.pg_get_indexdef(i.indexrelid), $rx$'([^']|'')*'$rx$, $rep$'<literal redacted>'$rep$, 'g') AS definition
      FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      JOIN pg_catalog.pg_class ic ON ic.oid=i.indexrelid JOIN pg_catalog.pg_am am ON am.oid=ic.relam
      LEFT JOIN pg_catalog.pg_constraint k ON k.conindid=i.indexrelid AND k.contype IN ('p','u','x')
      WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
      AND c.relkind IN ('r','p','f') ORDER BY n.nspname,c.relname,ic.relname;

-- sequences
SELECT n.nspname AS schema,c.relname AS name,
      pg_catalog.format_type(s.seqtypid,NULL) AS type,s.seqstart AS start,s.seqincrement AS increment,
      s.seqmin AS min,s.seqmax AS max,s.seqcache AS cache,s.seqcycle AS cycle,
      tn.nspname AS owner_schema,tc.relname AS owner_table,a.attname AS owner_column,d.deptype AS dependency
      FROM pg_catalog.pg_sequence s JOIN pg_catalog.pg_class c ON c.oid=s.seqrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      LEFT JOIN pg_catalog.pg_depend d ON d.classid='pg_catalog.pg_class'::regclass
        AND d.objid=c.oid AND d.refclassid='pg_catalog.pg_class'::regclass AND d.deptype IN ('a','i')
      LEFT JOIN pg_catalog.pg_class tc ON tc.oid=d.refobjid
      LEFT JOIN pg_catalog.pg_namespace tn ON tn.oid=tc.relnamespace
      LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=tc.oid AND a.attnum=d.refobjsubid
      WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' ORDER BY n.nspname,c.relname;

ROLLBACK;
```

## Completion and boundaries

Read-only catalog access succeeded for both targets; neither is marked BLOCKED. The comparison found the differences above and does not certify migration readiness, sequence alignment with maximum IDs, referential integrity of untyped JSON/strings, or absence of orphan records. Those checks were deliberately outside the authorized light inventory. The live-schema comparison has not modified or reconciled either database.

Only `docs/uuid-migration/phase1/04-postgresql.md` was added to the repository. Existing tracked changes, prior audit documents and the untracked frontend test were preserved. No application startup, dependency installation, migration, DML, DDL, checkout, pull, reset, stash, commit or push was performed.
