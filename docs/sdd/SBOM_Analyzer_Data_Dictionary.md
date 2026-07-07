# SBOM Analyzer — Data Dictionary

| | |
|---|---|
| **Doc ID** | SBOM-DOC-002-DD (companion to SBOM-DOC-002 Rev 0.1) |
| **Release Date** | 07-Jul-2026 |
| **Baseline** | Alembic head `041_project_product_hierarchy` · 42 tables (39 in `app/models.py`, 3 in `app/nvd_mirror/db/models.py`) |
| **Prepared By** | Feroze |

Database entity and field-level documentation: every SQLAlchemy model with field name, DB type, nullability, default, key status (PK/FK), description, plus unique constraints, indexes, JSON column shapes, relationship map, engine/session configuration, the full Alembic migration chain (001–041) and startup schema-verification behaviour. Line references are to the audited working tree (2026-07-06). Open items are tracked in SBOM_Analyzer_Open_Questions (OQ-038, OQ-039).


## 1. Where the models live

| File | Contents | Style |
|---|---|---|
| `app/models.py` (1,500 lines) | 39 application tables (SBOM, analysis, schedules, VEX, lifecycle, AI, audit, tenancy) | Legacy `Column(...)` declarative |
| `app/models_mixins.py` | `SoftDeleteMixin`, `TenantOwnedMixin` | mixins |
| `app/nvd_mirror/db/models.py` | 3 NVD-mirror tables (`nvd_settings`, `cves`, `nvd_sync_runs`) | SQLAlchemy 2.0 `Mapped`/`mapped_column` (deliberate local divergence, docstring lines 1–16) |
| `app/db.py:137` | `Base = declarative_base(metadata=MetaData(naming_convention=...))` — single metadata for everything | |

Total: **42 tables**. No other `__tablename__` declarations exist in the repo (grep over all files; other `models.py`-like files are Pydantic schemas).

**Naming convention** (`app/db.py:21-27`): `ix_%(column_0_label)s`, `uq_%(table_name)s_%(column_0_name)s`, `ck_%(table_name)s_%(constraint_name)s`, `fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s`, `pk_%(table_name)s`.

### 1.1 Mixins (field-level, apply to tables as flagged below)

`app/models_mixins.py`:

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| `is_active` | Boolean | NO | Python `True`; server_default `sa.true()` | — | Soft-delete flag (`True` = live). Naming rationale in module docstring (lines 6–13) |
| `deactivated_at` | DateTime(timezone=True) | YES | — | — | Soft-delete timestamp (tz-aware) |
| `deactivated_by` | String(128) | YES | — | — | Actor string (no users FK by design, docstring lines 15–22) |
| `tenant_id` | Integer | NO | — | FK→`tenants.id` (indexed) | `TenantOwnedMixin` — tenant isolation column |

- **SoftDeleteMixin applied to (9):** `projects`, `products`, `sbom_source`, `sbom_analysis_report`, `sbom_component`, `analysis_run`, `analysis_finding`, `analysis_schedule`, `ai_fix_batch`.
- **TenantOwnedMixin applied to (21):** `projects`, `products`, `sbom_source`, `sbom_validation_sessions`, `sbom_validation_session_events`, `sbom_analysis_report`, `sbom_component`, `vex_documents`, `vex_statements`, `component_lifecycle_override_audit`, `vex_override_audit`, `analysis_run`, `analysis_finding`, `run_cache`, `analysis_schedule`, `compare_cache`, `ai_usage_log`, `ai_fix_batch`, `audit_log`, `vulnerability_remediation`, `vulnerability_remediation_audit`.
- **Transparent enforcement** (`app/db.py:177-240`): a `do_orm_execute` listener injects `WHERE is_active = TRUE` into every ORM SELECT (bypass: `execution_options(include_deleted=True)`) and a tenant predicate when a tenant context is bound; a `before_flush` listener stamps `tenant_id` on new rows and raises on cross-tenant mutation.
- **Module-level generated indexes** (`app/models.py:1433-1477`):
  - `ix_<table>_deactivated` — partial index on `is_active` `WHERE is_active = false` (`sqlite_where is_active = 0`) for 8 tables (all SoftDelete tables **except `products`**).
  - `ix_<table>_tenant_identity` — `(tenant_id, <pk>)` for 20 tenant tables (**`products` again excluded**; migration 041 instead creates `ix_products_tenant_project` etc.).

**Timestamp convention warning:** outside `tenants`/`iam_users`/`tenant_users`, `deactivated_at`, and the NVD-mirror tables, *all* timestamps (`created_on`, `created_at`, `expires_at`, `started_on`, …) are **String columns holding ISO-8601 text**, not `DateTime`. tz-aware `DateTime(timezone=True)` is used only where noted below.

---

## 2. Field-level data dictionary

Legend: PK = primary key; FK→x = foreign key; "idx" in Key = single-column index (`index=True`). Mixin columns are listed once in §1.1 and flagged per table as `[+SoftDelete]` / `[+Tenant]`.

### 2.1 Identity & tenancy

#### `tenants` — class `Tenant` (`app/models.py:28`)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK | |
| name | String(255) | NO | — | — | Display name |
| slug | String(128) | NO | — | idx | URL-safe id |
| external_iam_tenant_id | String(255) | NO | — | idx | HCL IAM tenant mapping |
| status | String(32) | NO | `ACTIVE` (py) | — | |
| created_at / updated_at | DateTime(timezone=True) | NO | — | — | tz-aware |

Unique: `uq_tenants_slug` (slug), `uq_tenants_external_iam_tenant_id`.

#### `iam_users` — class `IAMUser` (`app/models.py:45`)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK | |
| external_iam_user_id | String(255) | NO | — | idx | HCL IAM subject id |
| email | String(320) | YES | — | idx | |
| display_name | String(255) | YES | — | — | |
| status | String(32) | NO | `ACTIVE` (py) | — | |
| last_login_at | DateTime(timezone=True) | YES | — | — | |
| created_at / updated_at | DateTime(timezone=True) | NO | — | — | |

Unique: `uq_iam_users_external_iam_user_id`. No password/credential columns — auth is external (HCL IAM); dev seed user id=1 created at startup (`app/main.py:488-505`).

#### `tenant_users` — class `TenantUser` (`app/models.py:60`)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK | |
| tenant_id | Integer | NO | — | FK→tenants.id `ondelete=CASCADE`, idx | |
| user_id | Integer | NO | — | FK→iam_users.id `ondelete=CASCADE`, idx | |
| role | String(64) | NO | — | — | e.g. `TENANT_ADMIN`, `PLATFORM_ADMIN` (seeded in main.py/migration 033) |
| status | String(32) | NO | `ACTIVE` (py) | — | |
| created_at / updated_at | DateTime(timezone=True) | NO | — | — | |

Unique: `uq_tenant_users_tenant_user` (tenant_id, user_id). Index: `ix_tenant_users_tenant_status` (tenant_id, status).

### 2.2 Project / product / SBOM hierarchy

#### `projects` — class `Projects` (`app/models.py:80`) `[+SoftDelete] [+Tenant]`

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| project_name | String | NO | — | idx | |
| project_details | String | YES | — | — | |
| project_status | Integer | NO | `1` (py) | — | 1=Active, 0=Inactive (pre-mixin legacy flag) |
| created_on | String | YES | — | — | ISO text |
| created_by | String | YES | — | idx | |
| modified_on / modified_by | String | YES | — | — | |

Unique: `uq_projects_tenant_name` (tenant_id, project_name). Index: `ix_projects_tenant_created` (tenant_id, created_on). Python-only helper properties `sbom_count`, `latest_sbom_id`, `latest_sbom_version` (lines 106-123).

#### `products` — class `Product` (`app/models.py:127`) `[+SoftDelete] [+Tenant]` (added by migration 041)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| project_id | Integer | NO | — | FK→projects.id `ondelete=CASCADE`, idx | |
| name | String(255) | NO | — | — | |
| normalized_name | String(255) | NO | — | — | lowercase match key |
| slug | String(255) | NO | — | — | |
| description | Text | YES | — | — | |
| product_key | String(128) | YES | — | idx | |
| vendor | String(255) | YES | — | — | |
| category | String(128) | YES | — | — | |
| status | String(32) | NO | `active` (py + server_default) | idx | |
| latest_version | String(128) | YES | — | — | |
| metadata_json | JSON | YES | — | — | free-form product metadata |
| created_by | String(128) | YES | — | idx | |
| created_at | String | NO | — | idx | ISO text |
| updated_at | String | YES | — | — | |
| deleted_at | String | YES | — | idx | **extra soft-delete string column in addition to the mixin's `is_active`** |

Unique: `uq_products_tenant_project_slug` (tenant_id, project_id, slug). Indexes: `ix_products_tenant_project_name` (tenant_id, project_id, normalized_name), `ix_products_tenant_project` (tenant_id, project_id); migration 041 also creates `ix_products_status/created_by/created_at/deleted_at/...` (041:83-94).

#### `sbom_type` — class `SBOMType` (`app/models.py:167`)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| typename | String | NO | — | unique | Seeded: `CycloneDX`, `SPDX` (`app/main.py:527-551`) |
| type_details | String | YES | — | — | |
| created_on / created_by / modified_on / modified_by | String | YES | — | — | |

#### `sbom_source` — class `SBOMSource` (`app/models.py:181`) `[+SoftDelete] [+Tenant]`

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| sbom_name | String | NO | — | idx | |
| sbom_data | Text | YES | — | — | full SBOM JSON document as text |
| sbom_type | Integer | YES | — | FK→sbom_type.id (module idx `ix_sbom_source_sbom_type`) | |
| projectid | Integer | YES | — | FK→projects.id | legacy spelling; property `project_id` aliases it |
| product_id | Integer | YES | — | FK→products.id, idx | |
| created_on | String | YES | — | — | |
| sbom_version | String | YES | — | — | |
| created_by | String | YES | — | idx | |
| productver | String | YES | — | — | legacy product version |
| modified_on / modified_by | String | YES | — | — | |
| parent_id | Integer | YES | — | FK→sbom_source.id (self), module idx | version lineage |
| change_summary | String | YES | — | — | |
| completeness_score | Float | YES | `100.0` (py) | — | NTIA completeness % |
| completeness_report | JSON | YES | — | — | per-field completeness breakdown |
| dedupe_report_json | JSON | YES | — | — | Stage-9 dedup report |
| product_name | String | YES | — | — | denormalized display name (mig 028) |
| description | String | YES | — | — | |
| status | String(24) | NO | `validated` (py + server_default) | idx | 8-stage validation outcome (mig 012); `pending` for legacy rows (mig 013) |
| failed_stage | String(32) | YES | — | idx | |
| validation_errors | JSON | YES | — | — | error list from validation pipeline |
| error_count / warning_count | Integer | NO | `0` (py + server_default `"0"`) | — | |
| validated_at | String | YES | — | — | |
| original_format / current_format / converted_from_format | String(32) | YES | — | (module idx on converted_from_format) | SPDX→CDX conversion tracking (mig 029) |
| source_sbom_id / converted_sbom_id | Integer | YES | — | FK→sbom_source.id (self), idx | conversion links |
| conversion_status | String(32) | YES | — | idx | |
| conversion_warnings_json / conversion_report_json | JSON | YES | — | — | |
| converted_at / converted_by | String | YES | — | — | |
| enrichment_status | String(32) | YES | — | idx | (mig 030) |
| conversion_started_at / conversion_completed_at / enrichment_started_at / enrichment_completed_at | String | YES | — | — | |
| conversion_error / enrichment_error | Text | YES | — | — | |
| component_extraction_status | String(32) | YES | — | idx | (mig 036) |
| component_extraction_error | Text | YES | — | — | |
| component_extraction_attempted_at / component_extraction_completed_at | String | YES | — | — | |

Unique: `uq_sbom_source_tenant_name_version` (tenant_id, sbom_name, sbom_version). Indexes: `ix_sbom_source_tenant_project`, `ix_sbom_source_tenant_product`, `ix_sbom_source_tenant_created` (+ module-level `parent_id`, `sbom_type`, `converted_from_format`). Read-only properties compute `format` / `spec_version` by parsing `sbom_data` (lines 301-333).

#### `sbom_validation_sessions` — class `SBOMValidationSession` (`app/models.py:336`) `[+Tenant]`
Repair workspace for SBOMs that failed validation (not trusted SBOM records).

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | String(36) | NO | — | PK, idx | UUID |
| project_id | Integer | YES | — | FK→projects.id, idx | |
| user_id | String(128) | YES | — | idx | |
| original_filename / sbom_name | String(255) | YES | — | — | |
| sbom_type | Integer | YES | — | FK→sbom_type.id | |
| content_type | String(255) | YES | — | — | |
| file_size_bytes / original_size_bytes / stored_size_bytes / total_lines | Integer | YES | — | — | |
| sha256 / original_sha256 / stored_sha256 / content_sha256 | String(64) | YES | — | idx each | integrity hashes (migs 038/039) |
| storage_backend | String(32) | YES | — | — | |
| detected_format / detected_version | String(64) | YES | — | — | |
| detection_confidence | Float | YES | — | — | |
| detection_evidence_json | JSON | YES | — | — | |
| raw_content_text / sanitized_content / current_content / repair_content_text | Text | YES | — | — | staged SBOM content |
| raw_content_blob / repair_content_blob | LargeBinary | YES | — | — | large-file path |
| raw_storage_path / repair_storage_path | String(1024) | YES | — | — | |
| validation_status | String(32) | NO | `failed` (py + server_default) | idx | |
| validation_errors_json / stage_results_json / latest_error_report_json | JSON | YES | — | — | |
| is_large_file | Boolean | NO | `False` (py) + server_default `sa.false()` | — | (mig 039) |
| full_editor_allowed / can_edit / can_ai_fix | Boolean | NO | `True` (py) + server_default `sa.true()` | — | |
| security_blocked_reason | Text | YES | — | — | |
| created_at | String | NO | — | idx | |
| updated_at | String | NO | — | — | |
| expires_at | String | NO | — | idx | session TTL |
| imported_sbom_id | Integer | YES | — | FK→sbom_source.id, idx | set once repaired SBOM is imported |

Relationship: `events` → `SBOMValidationSessionEvent`, `cascade="all, delete-orphan"`, plus FK `ondelete=CASCADE`.

#### `sbom_validation_session_events` — class `SBOMValidationSessionEvent` (`app/models.py:397`) `[+Tenant]` — append-only audit for repair sessions

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| session_id | String(36) | NO | — | FK→sbom_validation_sessions.id `ondelete=CASCADE`, idx | |
| event_type | String(64) | NO | — | idx | |
| actor_user_id | String(128) | YES | — | idx | |
| timestamp | String | NO | — | idx | |
| summary | Text | YES | — | — | |
| before_hash / after_hash | String(64) | YES | — | — | content hashes around an edit |
| metadata_json | JSON | YES | — | — | |

#### `sbom_analysis_report` — class `SBOMAnalysisReport` (`app/models.py:420`) `[+SoftDelete] [+Tenant]` (legacy report rows)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| sbom_ref_id | Integer | YES | — | FK→sbom_source.id | |
| sbom_result | String | YES | — | — | |
| project_id | String | YES | — | — | *String*, kept for backward compat (comment line 426) |
| created_on | String | YES | — | — | |
| analysis_details | Text | YES | — | — | |
| reference_source | String | YES | — | — | |
| sbom_analysis_level | Integer | YES | — | — | |

#### `sbom_component` — class `SBOMComponent` (`app/models.py:435`) `[+SoftDelete] [+Tenant]`

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| sbom_id | Integer | NO | — | FK→sbom_source.id, idx | |
| bom_ref | String | YES | — | module idx | CycloneDX bom-ref |
| component_type / component_group | String | YES | — | — | |
| name | String | NO | — | idx | |
| version | String | YES | — | idx | |
| purl | String | YES | — | — | |
| cpe | String | YES | — | idx | |
| cpe_source | String(32) | YES | — | idx | provenance of CPE (mig 031) |
| supplier / scope | String | YES | — | — | |
| created_on | String | YES | — | — | |
| ecosystem | String | YES | — | idx | |
| original_name / original_version / original_purl | String | YES | — | — | Stage-9 normalization originals (mig 037) |
| normalized_name / normalized_version / normalized_ecosystem / normalized_purl | String | YES | — | idx each | |
| purl_type / purl_namespace / purl_name / purl_version / purl_subpath | String | YES | — | — | parsed PURL parts |
| purl_qualifiers_json | JSON | YES | — | — | PURL qualifiers map |
| normalized_cpes | JSON | YES | — | — | list of normalized CPE strings |
| primary_cpe | String | YES | — | idx | |
| cpe_evidence_json | JSON | YES | — | — | |
| normalized_supplier | String | YES | — | — | |
| normalized_package_key | String | YES | — | idx | |
| canonical_identity_confidence | String | YES | — | — | |
| license | String | YES | — | — | |
| hashes | Text | YES | — | — | |
| lifecycle_status | String | YES | — | — | e.g. EOL/active (provider-enriched) |
| eos_date / eol_date / eof_date | String | YES | — | — | end-of-support/life/fix dates |
| is_deprecated | Boolean | YES* | `False` (py) | — | *no explicit nullable → nullable |
| deprecated / unsupported | Boolean | YES | `False` (py) | — | |
| maintenance_status | String | YES | — | — | |
| latest_version / latest_supported_version / recommended_version | String | YES | — | — | |
| lifecycle_recommendation | Text | YES | — | — | |
| lifecycle_source / lifecycle_source_url / lifecycle_confidence | String | YES | — | — | |
| lifecycle_checked_at | String | YES | — | idx | |
| lifecycle_evidence_json | JSON | YES | — | — | |
| lifecycle_is_stale / lifecycle_manual_override | Boolean | NO | `False` (py) | — | |
| normalized_component_key | String | YES | — | idx | dedup identity key |
| dedupe_canonical_id / dedupe_group_id | String | YES | — | idx each | |
| is_duplicate | Boolean | NO | `False` (py) | — | |
| duplicate_of_component_id | Integer | YES | — | FK→sbom_component.id (self) `ondelete=CASCADE`, module idx | |
| dedupe_reason / dedupe_confidence | String | YES | — | — | |
| normalization_notes_json / dedupe_evidence_json | JSON | YES | — | — | |

Unique: `uq_sbom_component_fingerprint` (tenant_id, sbom_id, bom_ref, name, version, cpe) — component dedup within an SBOM. Indexes: `ix_sbom_component_sbom_name` (sbom_id, name), `ix_sbom_component_lifecycle` (lifecycle_status, ecosystem), `ix_sbom_component_sbom_normalized_key`, `ix_sbom_component_sbom_is_duplicate`, `ix_sbom_component_normalized_identity` (normalized_ecosystem, normalized_name, normalized_version).

### 2.3 Analysis runs, findings, schedules

#### `analysis_run` — class `AnalysisRun` (`app/models.py:767`) `[+SoftDelete] [+Tenant]`

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| sbom_id | Integer | NO | — | FK→sbom_source.id, idx | |
| project_id | Integer | YES | — | FK→projects.id, idx | |
| product_id | Integer | YES | — | FK→products.id, idx | |
| run_status | String | NO | — | idx | Canonical: `OK` `FINDINGS` `PARTIAL` `ERROR` `RUNNING` `PENDING` `NO_DATA` (`app/services/analysis_service.py:114-120`, ADR-0001). **No CHECK constraint** — string column, Python-enforced. Legacy `PASS`/`FAIL` renamed by migration 005 |
| sbom_name | String | YES | — | — | denormalized snapshot |
| source | String | NO | `NVD` (py) | — | analysis source label |
| trigger_source | String(32) | NO | `unknown` (py + server_default) | idx | `api` / `manual` / `schedule` / `unknown` (mig 040; values from `app/routers/analyze_endpoints.py:205`, `sboms_crud.py:1555`, `workers/scheduled_analysis.py:193`) |
| started_on / completed_on | String | NO | — | — | ISO text |
| duration_ms | Integer | NO | `0` (py) | — | |
| total_components | Integer | NO | `0` (py) | — | counter |
| components_with_cpe | Integer | NO | `0` (py) | — | counter |
| total_findings | Integer | NO | `0` (py) | — | counter |
| critical_count / high_count / medium_count / low_count / unknown_count | Integer | NO | `0` (py) | — | severity counters |
| query_error_count | Integer | NO | `0` (py) | — | upstream feed errors → drives `PARTIAL` |
| raw_report | Text | YES | — | — | full run JSON |

No table-level unique constraints. Counters are written after findings persist via `calculate_run_finding_metrics`/`apply_metrics_to_run` (`app/services/analysis_service.py:345-355`).

#### `analysis_finding` — class `AnalysisFinding` (`app/models.py:812`) `[+SoftDelete] [+Tenant]`

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| analysis_run_id | Integer | NO | — | FK→analysis_run.id, idx | |
| component_id | Integer | YES | — | FK→sbom_component.id, idx | |
| vuln_id | String | NO | — | idx | CVE/GHSA id; fallback `UNKNOWN-CVE` (`analysis_service.py:260`) |
| source | String | YES | — | — | comma-joined source list |
| title | String | YES | — | — | |
| description | Text | YES | — | — | |
| severity | String | YES | — | idx | Uppercased; `UNKNOWN` fallback (`analysis_service.py:309`). No CHECK |
| score | Float | YES | — | — | CVSS score |
| vector | String | YES | — | — | CVSS vector string |
| published_on | String | YES | — | — | |
| reference_url | String | YES | — | — | |
| cwe | Text | YES | — | — | JSON-encoded sorted list OR legacy scalar string |
| cpe | String | YES | — | idx | matched CPE |
| component_name / component_version | String | YES | — | — | denormalized |
| fixed_versions | Text | YES | — | — | JSON array stored as string |
| attack_vector | String | YES | — | — | |
| cvss_version | String | YES | — | — | |
| aliases | Text | YES | — | — | JSON array as string |
| match_reason | String(32) | YES | — | idx | version-range verdict (mig 016); Python `Literal`, no CHECK |
| matched_range | String(128) | YES | — | — | |
| match_confidence | Float | YES | — | — | token-overlap score in [0,1] (mig 017); no DB CHECK by design (comment lines 848-853) |
| match_strategy | String(32) | YES | — | idx | `cpe_name` / `virtual_match_string` / `keyword_search` / `purl_direct` / `ghsa_alias` (comment lines 855-861) |

**Dedup uniqueness guarantee:** `uq_analysis_finding_run_vuln_cpe` UNIQUE(`analysis_run_id`, `vuln_id`, `cpe`) (`app/models.py:868`) — at most one row per (run, vulnerability, CPE). Re-analysis of an existing run first `DELETE`s all its findings and rewrites them (`app/services/analysis_service.py:242-244`), so the constraint guards within-run duplicates from multi-source merge. Index: `ix_analysis_finding_run_severity` (analysis_run_id, severity). **EPSS/KEV/lifecycle values are NOT columns here** — they are joined at read time from `epss_score`, `kev_entry`, and `sbom_component` lifecycle fields.

#### `analysis_schedule` — class `AnalysisSchedule` (`app/models.py:913`) `[+SoftDelete] [+Tenant]`

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| scope | String(16) | NO | — | — | `PROJECT` / `PRODUCT` / `SBOM` |
| project_id | Integer | YES | — | FK→projects.id `ondelete=CASCADE`, idx | |
| product_id | Integer | YES | — | FK→products.id `ondelete=CASCADE`, idx | |
| sbom_id | Integer | YES | — | FK→sbom_source.id `ondelete=CASCADE`, idx | |
| cadence | String(16) | NO | — | — | `DAILY|WEEKLY|BIWEEKLY|MONTHLY|QUARTERLY|CUSTOM` |
| cron_expression | String(128) | YES | — | — | only when cadence=`CUSTOM` |
| day_of_week | Integer | YES | — | — | 0=Mon..6=Sun |
| day_of_month | Integer | YES | — | — | 1..28 |
| hour_utc | Integer | NO | `2` (py) | — | |
| timezone | String(64) | NO | `UTC` (py) | — | |
| enabled | Boolean | NO | `True` (py) | — | |
| next_run_at | String | YES | — | idx | |
| last_run_at | String | YES | — | — | |
| last_run_status | String(16) | YES | — | — | same vocabulary as run_status (renamed in mig 005) |
| last_run_id | Integer | YES | — | FK→analysis_run.id `ondelete=SET NULL` | |
| consecutive_failures | Integer | NO | `0` (py) | — | |
| min_gap_minutes | Integer | NO | `60` (py) | — | debounce |
| created_on / created_by / modified_on / modified_by | String | YES | — | — | |

CHECK constraints (lines 956-976): `ck_analysis_schedule_scope` (scope in 3 values), `ck_analysis_schedule_cadence`, `ck_analysis_schedule_target` (exactly one of project_id/product_id/sbom_id set matching scope), `ck_analysis_schedule_hour_range` (0-23), `..._dow_range` (0-6/NULL), `..._dom_range` (1-28/NULL). Index: `ix_analysis_schedule_due` (enabled, next_run_at).

#### `run_cache` — class `RunCache` (`app/models.py:873`) `[+Tenant]` — ad-hoc analysis payloads for PDF export

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | doubles as the client-facing runId |
| run_json | Text | NO | — | — | whole run JSON |
| created_on | String | YES | — | — | |
| source | String | YES | — | — | `consolidated|nvd|osv|ghsa` |
| sbom_id | Integer | YES | — | — (**no FK, intentional**) | for cache invalidation |

### 2.4 VEX & lifecycle-override audit

#### `vex_documents` — class `VexDocument` (`app/models.py:676`) `[+Tenant]`

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| sbom_id | Integer | NO | — | FK→sbom_source.id `ondelete=CASCADE`, idx | |
| source_type | String | NO | `uploaded` (py) | idx | uploaded vs discovered |
| format | String | YES | — | idx | CSAF/CycloneDX-VEX/OpenVEX etc. |
| author / source_url | String | YES | — | — | |
| discovery_evidence_json / provider_errors_json | JSON | YES | — | — | (mig 027) |
| last_refresh_status | String | YES | — | — | |
| uploaded_by | String | YES | — | idx | |
| uploaded_at | String | NO | — | idx | |
| raw_document_json | JSON | YES | — | — | full VEX document |
| validation_status | String | NO | `accepted` (py) | idx | |

Relationship: `statements` `cascade="all, delete-orphan"` + FK CASCADE.

#### `vex_statements` — class `VexStatement` (`app/models.py:704`) `[+Tenant]`

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| vex_document_id | Integer | YES | — | FK→vex_documents.id `ondelete=CASCADE`, idx | NULL for manual overrides |
| sbom_id | Integer | NO | — | FK→sbom_source.id `ondelete=CASCADE`, idx | |
| component_id | Integer | YES | — | FK→sbom_component.id `ondelete=SET NULL`, idx | |
| vulnerability_id | String | NO | — | idx | |
| cve_id | String | YES | — | idx | |
| status | String | NO | — | idx | VEX status (affected / not_affected / fixed / under_investigation) |
| justification / impact_statement / action_statement / mitigation | Text | YES | — | — | |
| fixed_version | String | YES | — | — | |
| source_name / source_url / confidence | String | YES | — | — | |
| evidence_json | JSON | YES | — | — | |
| created_at | String | NO | — | idx | |

Indexes: `ix_vex_statement_sbom_status` (sbom_id, status), `ix_vex_statement_component_vuln` (component_id, vulnerability_id).

#### `component_lifecycle_override_audit` — class `ComponentLifecycleOverrideAudit` (`app/models.py:736`) `[+Tenant]`

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| component_id | Integer | NO | — | FK→sbom_component.id `ondelete=CASCADE`, idx | |
| old_value_json / new_value_json | JSON | YES | — | — | before/after lifecycle values |
| reason | Text | NO | — | — | |
| evidence_url | String | YES | — | — | |
| changed_by | String | YES | — | idx | |
| changed_at | String | NO | — | idx | |

#### `vex_override_audit` — class `VexOverrideAudit` (`app/models.py:751`) `[+Tenant]` — same shape plus:

| Field | DB type | Nullable | Default | Key |
|---|---|---|---|---|
| vulnerability_id | String | NO | — | idx |

(other columns identical to `component_lifecycle_override_audit`).

### 2.5 External-data caches (CVE / KEV / EPSS / lifecycle / NVD)

#### `kev_entry` — class `KevEntry` (`app/models.py:889`) — CISA KEV catalog cache (24h refresh)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| cve_id | String | NO | — | PK, idx | presence ⇒ on KEV list |
| vendor_project / product / vulnerability_name | String | YES | — | — | |
| date_added | String | YES | — | — | |
| short_description / required_action | Text | YES | — | — | |
| due_date | String | YES | — | — | |
| known_ransomware_use | String | YES | — | — | `Known`/`Unknown` |
| refreshed_at | String | NO | — | — | ISO timestamp |

Upserted via `INSERT ... ON CONFLICT` with dialect fallback (`app/sources/kev.py:189-200`).

#### `epss_score` — class `EpssScore` (`app/models.py:981`) — FIRST.org EPSS cache (per-CVE, 24h TTL, on-demand)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| cve_id | String | NO | — | PK, idx | |
| epss | Float | NO | `0.0` (py) | — | probability 0..1 |
| percentile | Float | YES | — | — | 0..1 |
| score_date | String | YES | — | — | date EPSS published |
| refreshed_at | String | NO | — | — | |

#### `cve_cache` — class `CveCache` (`app/models.py:1002`) — merged CVE detail (OSV+GHSA+NVD+EPSS+KEV)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| cve_id | String(32) | NO | — | PK, idx | canonical `CVE-YYYY-NNNN+` |
| payload | JSON | NO | — | — | full `CveDetail` JSON for the modal |
| sources_used | String(128) | NO | — | — | comma-joined |
| fetched_at | String | NO | — | — | |
| expires_at | String | NO | — | idx | TTL enforced at upsert by `CveDetailService`; readers compare to now() |
| fetch_error | Text | YES | — | — | non-null ⇒ negative cache entry (~15 min) |
| schema_version | Integer | NO | `1` (py) | — | |

#### `source_response_cache` — class `SourceResponseCache` (`app/models.py:1024`) — per-(source, component) raw response

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| source | String(32) | NO | — | PK (composite) | NVD/OSV/GHSA |
| component_key | String(512) | NO | — | PK (composite) | canonical PURL — shared across SBOMs |
| payload | JSON | NO | — | — | opaque raw source response |
| fetched_at / expires_at | String | NO | — | — | TTL enforced at read time |

Index: `ix_source_response_cache_expires_at`. Docstring (lines 1040-1042) explicitly distinguishes it from `cve_cache` and `run_cache`.

#### `nvd_lookup_cache` — class `NvdLookupCache` (`app/models.py:1056`)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK | |
| lookup_type | String(16) | NO | — | — | e.g. cpe/keyword |
| identifier | String(2048) | NO | — | idx `ix_nvd_lookup_cache_identifier` | |
| identifier_hash | String(64) | NO | — | — | |
| status | String(16) | NO | — | idx | success/failure marker |
| response_json | JSON | YES | — | — | |
| http_status | Integer | YES | — | — | |
| error_message | Text | YES | — | — | |
| checked_at / expires_at / created_at / updated_at | String | NO | — | idx on expires_at | |

Unique: `uq_nvd_lookup_cache_type_hash` (lookup_type, identifier_hash).

#### `compare_cache` — class `CompareCache` (`app/models.py:1082`) `[+Tenant]` — ADR-0008 compare-runs result cache

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| cache_key | String(64) | NO | — | PK | `sha256(f"{min(a,b)}:{max(a,b)}")` — order-independent |
| run_a_id / run_b_id | Integer | NO | — | idx each (**no FK, intentional** — O(1) invalidation on re-analysis) | |
| payload | JSON | NO | — | — | `CompareResult` |
| computed_at | String | NO | — | — | |
| expires_at | String | NO | — | idx | |
| schema_version | Integer | NO | `1` (py) | — | |

#### `component_lifecycle_cache` — class `ComponentLifecycleCache` (`app/models.py:537`) — shared lifecycle/EOL enrichment cache

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| lookup_key | String | YES | — | idx | |
| normalized_name | String | NO | — | idx | |
| normalized_version / ecosystem / purl / cpe | String | YES | — | idx each | |
| lifecycle_status / maintenance_status | String | YES | — | — | |
| eos_date / eol_date / eof_date | String | YES | — | — | |
| deprecated / unsupported | Boolean | YES | `False` (py) | — | |
| latest_version / latest_supported_version / recommended_version | String | YES | — | — | |
| recommendation | Text | YES | — | — | |
| source_name / source_url / confidence | String | YES | — | — | |
| evidence_json | JSON | YES | — | — | |
| checked_at / expires_at | String | NO | — | idx each | TTL |
| is_stale | Boolean | NO | `False` (py) | — | |

Unique: `uq_component_lifecycle_cache_identity` (normalized_name, normalized_version, ecosystem, purl). Index: `ix_component_lifecycle_cache_lookup` (ecosystem, normalized_name, normalized_version). Upsert via `ON CONFLICT` with non-supporting-dialect fallback (`app/services/lifecycle/lifecycle_cache_repository.py:139-170`).

### 2.6 Lifecycle provider administration

#### `lifecycle_provider_configs` — class `LifecycleProviderConfig` (`app/models.py:580`)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| provider_key | String(64) | NO | — | unique, idx | |
| display_name | String(128) | NO | — | — | |
| provider_type | String(64) | NO | — | idx | |
| enabled | Boolean | NO | `True` (py) | — | |
| priority | Integer | NO | `100` (py) | — | CHECK 1–1000 |
| base_url | String(512) | YES | — | — | |
| feed_urls_json / config_json | JSON | YES | — | — | |
| timeout_seconds | Integer | NO | `5` (py) | — | CHECK 1–60 |
| max_retries | Integer | NO | `0` (py) | — | CHECK 0–10 |
| circuit_breaker_enabled | Boolean | NO | `True` (py) | — | |
| cache_ttl_known_days / cache_ttl_unknown_hours / cache_ttl_failure_minutes / cache_ttl_deprecated_days | Integer | YES | — | — | per-state TTLs |
| last_success_at / last_failure_at | String | YES | — | — | |
| last_failure_message | Text | YES | — | — | |
| health_status | String(32) | NO | `unknown` (py) | idx | CHECK in (healthy, degraded, disabled, unknown) |
| created_at / updated_at | String | NO | — | — | |
| updated_by_user_id | Integer | YES | — | FK→iam_users.id `ondelete=SET NULL` | |

Index: `ix_lifecycle_provider_configs_enabled_priority` (enabled, priority). Defaults seeded at startup (`app/main.py:554-556`) and in migration 034.

#### `lifecycle_provider_secrets` — class `LifecycleProviderSecret` (`app/models.py:621`)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| provider_key | String(64) | NO | — | idx | |
| secret_name | String(64) | NO | — | — | name only; value `<REDACTED>` |
| encrypted_value | Text | NO | — | — | encrypted at rest; never leaves server (docstring line 622) |
| value_preview | String(64) | YES | — | — | masked preview |
| created_at / updated_at | String | NO | — | — | |
| updated_by_user_id | Integer | YES | — | FK→iam_users.id `ondelete=SET NULL` | |

Unique: `uq_lifecycle_provider_secret_provider_name` (provider_key, secret_name). Index `ix_lifecycle_provider_secrets_provider`.

#### `lifecycle_vendor_records` — class `LifecycleVendorRecord` (`app/models.py:641`)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| vendor_name | String(128) | NO | — | idx | |
| product_name | String(255) | NO | — | idx | |
| product_aliases_json | JSON | YES | — | — | alias list |
| ecosystem | String(64) | YES | — | idx | |
| version_pattern | String(128) | YES | — | — | |
| version_start / version_end | String(64) | YES | — | — | |
| lifecycle_status | String(64) | NO | — | — | |
| maintenance_status | String(128) | YES | — | — | |
| eol_date / eos_date / eof_date | String | YES | — | — | |
| deprecated / unsupported | Boolean | NO | `False` (py) | — | |
| latest_supported_version / recommended_version | String(128) | YES | — | — | |
| evidence_url | String(512) | YES | — | — | |
| evidence_json | JSON | YES | — | — | |
| confidence | String(32) | NO | `High` (py) | — | |
| enabled | Boolean | NO | `True` (py) | idx | |
| created_at / updated_at | String | NO | — | — | |
| updated_by_user_id | Integer | YES | — | FK→iam_users.id `ondelete=SET NULL` | |

Index: `ix_lifecycle_vendor_records_lookup` (enabled, ecosystem, product_name).

### 2.7 AI subsystem

#### `ai_usage_log` — class `AiUsageLog` (`app/models.py:1103`) `[+Tenant]` — append-only LLM call ledger

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| request_id | String(64) | NO | — | — | |
| provider | String(32) | NO | — | idx | |
| model | String(96) | NO | — | — | |
| purpose | String(48) | NO | — | idx | |
| finding_cache_key | String(64) | YES | — | idx | joins to ai_fix_cache.cache_key |
| input_tokens / output_tokens | Integer | NO | `0` (py) | — | |
| cost_usd | Float | NO | `0.0` (py) | — | |
| latency_ms | Integer | NO | `0` (py) | — | |
| cache_hit | Boolean | NO | `False` (py) | — | |
| error | Text | YES | — | — | |
| created_at | String | NO | — | idx | |

Module indexes: `ix_ai_usage_log_provider_created`, `ix_ai_usage_log_purpose_created` (models.py:1479-1480).

#### `ai_provider_config` — class `AiProviderConfig` (`app/models.py:1130`) — per-provider runtime overrides (no secrets)

| Field | DB type | Nullable | Default | Key |
|---|---|---|---|---|
| provider_name | String(32) | NO | — | PK |
| enabled | Boolean | YES | — | — |
| default_model | String(96) | YES | — | — |
| base_url | String(256) | YES | — | — |
| max_concurrent | Integer | YES | — | — |
| rate_per_minute | Float | YES | — | — |
| notes | Text | YES | — | — |
| updated_at / updated_by | String | YES | — | — |

#### `ai_fix_cache` — class `AiFixCache` (`app/models.py:1153`) — tenant-shared fix bundles; TTL: KEV 7d / non-KEV 30d / negative 1h (docstring lines 1163-1168)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| cache_key | String(64) | NO | — | PK | hash of (vuln_id, component, version, prompt_version) |
| vuln_id | String(64) | NO | — | idx | |
| component_name | String(255) | NO | — | — | |
| component_version | String(128) | NO | — | — | |
| prompt_version | String(32) | NO | — | — | |
| schema_version | Integer | NO | `1` (py) | — | |
| remediation_prose / upgrade_command / decision_recommendation | JSON | NO | — | — | structured AI outputs |
| overall_confidence | String(16) | YES | — | — | high/medium/low; nullable for pre-019 rows |
| provider_used | String(32) | NO | — | — | |
| model_used | String(96) | NO | — | — | |
| total_cost_usd | Float | NO | `0.0` (py) | — | |
| generated_at / expires_at / last_accessed_at | String | NO | — | idx on expires_at | |

Index: `ix_ai_fix_cache_vuln_component` (vuln_id, component_name, component_version).

#### `ai_fix_batch` — class `AiFixBatch` (`app/models.py:1206`) `[+SoftDelete] [+Tenant]`

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | String(36) | NO | — | PK | app-generated UUID |
| run_id | Integer | NO | — | FK→analysis_run.id `ondelete=CASCADE` | ≤3 active batches/run (router-enforced) |
| status | String(24) | NO | — | — | Python-enforced vocabulary |
| scope_label | String(120) | YES | — | — | |
| scope_json | JSON | YES | — | — | scope filter used |
| finding_ids_json | JSON | NO | — | — | denormalized resolved finding-id list (immutable record) |
| provider_name | String(64) | NO | — | — | |
| total / cached_count / generated_count / failed_count | Integer | NO | `0` (py) | — | outcome counters |
| cost_usd | Float | NO | `0.0` (py) | — | |
| started_at / completed_at | String | YES | — | — | |
| created_at | String | NO | — | — | |
| last_error | String(240) | YES | — | — | |

Indexes: `ix_ai_fix_batch_run_status` (run_id, status), `ix_ai_fix_batch_created_at`.

#### `ai_provider_credential` — class `AiProviderCredential` (`app/models.py:1252`)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| provider_name | String(32) | NO | — | idx | |
| label | String(64) | NO | `default` (py) | — | multi-key scaffold |
| api_key_encrypted | Text | YES | — | — | AES-GCM ciphertext; **never returned by any endpoint** (docstring lines 1260-1262); value `<REDACTED>` |
| base_url | String(512) | YES | — | — | |
| default_model | String(128) | YES | — | — | |
| tier | String(16) | NO | `paid` (py) | — | |
| is_default / is_fallback | Boolean | NO | `False` (py) | unique partial idx | |
| enabled | Boolean | NO | `True` (py) | — | |
| cost_per_1k_input_usd / cost_per_1k_output_usd | Float | NO | `0.0` (py) | — | |
| is_local | Boolean | NO | `False` (py) | — | ollama/vllm style |
| max_concurrent | Integer | YES | — | — | |
| rate_per_minute | Float | YES | — | — | |
| created_at / updated_at | String | NO | — | — | |
| last_test_at | String | YES | — | — | |
| last_test_success | Boolean | YES | — | — | |
| last_test_error | Text | YES | — | — | |

Unique: `uq_ai_provider_credential_provider_label` (provider_name, label). **Unique partial indexes** `ix_ai_only_one_default` / `ix_ai_only_one_fallback` (`WHERE is_default = true` / `is_fallback = true`, SQLite variants `= 1`) enforce a single default/fallback credential globally (models.py:1486-1499).

#### `ai_settings` — class `AiSettings` (`app/models.py:1291`) — singleton

| Field | DB type | Nullable | Default | Key |
|---|---|---|---|---|
| id | Integer | NO | `1` (py) | PK; CHECK `id = 1` (`ck_ai_settings_singleton`) |
| feature_enabled | Boolean | NO | `True` (py) | — |
| kill_switch_active | Boolean | NO | `False` (py) | — |
| budget_per_request_usd | Float | NO | `0.10` (py) | — |
| budget_per_scan_usd / budget_daily_usd | Float | NO | `5.00` (py) | — |
| updated_at | String | NO | — | — |
| updated_by_user_id | String | YES | — | — (string, not FK) |

Seed row inserted by migration 010.

#### `ai_credential_audit_log` — class `AiCredentialAuditLog` (`app/models.py:1314`) — append-only; never stores credential payloads (docstring)

| Field | DB type | Nullable | Default | Key |
|---|---|---|---|---|
| id | Integer | NO | — | PK, idx |
| user_id | String(128) | YES | — | — |
| action | String(48) | NO | — | — |
| target_kind | String(24) | NO | — | — (`credential` \| `settings`) |
| target_id | Integer | YES | — | — |
| provider_name | String(32) | YES | — | — |
| detail | String(240) | YES | — | — |
| created_at | String | NO | — | idx |

### 2.8 General audit & remediation

#### `audit_log` — class `AuditLog` (`app/models.py:1335`) `[+Tenant]` — append-only lifecycle audit (soft-delete / permanent delete / restore vocabulary in docstring lines 1345-1351)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| user_id | String(128) | YES | — | — | header-trusted actor string |
| action | String(128) | NO | — | idx | e.g. `project.soft_delete`, `lifecycle.provider_config.update` (widened by mig 035) |
| target_kind | String(128) | NO | — | idx | |
| target_id | Integer | YES | — | idx | |
| detail | Text | YES | — | — | |
| metadata_json | JSON | YES | — | — | e.g. cascade row counts |
| user_ref_id | Integer | YES | — | FK→iam_users.id `ondelete=SET NULL`, idx | (mig 033) |
| entity_type | String(128) | YES | — | idx | |
| entity_id | String(128) | YES | — | idx | |
| old_value / new_value | JSON | YES | — | — | |
| ip_address | String(64) | YES | — | — | |
| user_agent | Text | YES | — | — | (widened 512→Text by mig 035) |
| created_at | String | NO | — | idx | |

#### `vulnerability_remediation` — class `VulnerabilityRemediation` (`app/models.py:1376`) `[+Tenant]`

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK, idx | |
| project_id | Integer | NO | — | FK→projects.id `ondelete=CASCADE`, idx | |
| vuln_id | String | NO | — | idx | |
| component_name | String | NO | — | idx | |
| component_version | String | NO | — | — | |
| fixed_version | String | YES | — | — | |
| status | String | NO | `Open` (py) | — | Open / In Progress / Fixed / Accepted Risk / Closed (comment) |
| owner | String | YES | — | — | |
| due_date / resolution_date | String | YES | — | — | YYYY-MM-DD |
| fix_notes | Text | YES | — | — | |
| created_on / updated_on | String | NO | — | — | |

Relationship: `history` → audit rows, `cascade="all, delete-orphan"`.

#### `vulnerability_remediation_audit` — class `VulnerabilityRemediationAudit` (`app/models.py:1405`) `[+Tenant]`

| Field | DB type | Nullable | Default | Key |
|---|---|---|---|---|
| id | Integer | NO | — | PK, idx |
| remediation_id | Integer | NO | — | FK→vulnerability_remediation.id `ondelete=CASCADE`, idx |
| project_id | Integer | NO | — | FK→projects.id `ondelete=CASCADE`, idx |
| vuln_id | String | NO | — | idx |
| component_name | String | NO | — | idx |
| component_version | String | NO | — | — |
| old_status | String | YES | — | — |
| new_status | String | NO | — | — |
| changed_by | String(128) | YES | — | — |
| changed_at | String | NO | — | idx |
| note | Text | YES | — | — |

### 2.9 NVD mirror package (`app/nvd_mirror/db/models.py`)

JSON columns use `JSON().with_variant(JSONB(), "postgresql")` (line 42) — JSONB on PG, TEXT-backed JSON on SQLite. All timestamps here are tz-aware `DateTime(timezone=True)`; several have `server_default=func.now()`.

#### `nvd_settings` — class `NvdSettingsRow` (line 45) — singleton (CHECK `id = 1`, `ck_nvd_settings_singleton`)

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | Integer | NO | — | PK | must be 1 |
| enabled | Boolean | NO | `False` (py) | — | mirror on/off |
| api_endpoint | Text | NO | NVD v2 URL (py) | — | |
| api_key_ciphertext | LargeBinary | YES | — | — | encrypted NVD API key `<REDACTED>` |
| download_feeds_enabled | Boolean | NO | `False` (py) | — | |
| page_size | Integer | NO | `2000` (py) | — | CHECK 1–2000 |
| window_days | Integer | NO | `119` (py) | — | CHECK 1–119 |
| min_freshness_hours | Integer | NO | `24` (py) | — | CHECK ≥ 0 |
| last_modified_utc / last_successful_sync_at | DateTime(tz) | YES | — | — | |
| created_at / updated_at | DateTime(tz) | NO | server_default `now()` | — | |

#### `cves` — class `CveRow` (line 82) — one row per mirrored CVE

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| cve_id | Text | NO | — | PK | |
| last_modified | DateTime(tz) | NO | — | idx `ix_cves_last_modified` | |
| published | DateTime(tz) | NO | — | — | |
| vuln_status | Text | NO | — | idx `ix_cves_vuln_status` | |
| description_en | Text | YES | — | — | |
| score_v40 / score_v31 / score_v2 | Float | YES | — | — | CVSS 4.0 / 3.1 / 2 |
| severity_text | String(32) | YES | — | — | |
| vector_string | Text | YES | — | — | |
| aliases | JSON/JSONB | NO | `list` (py) | — | list[str] |
| cpe_match | JSON/JSONB | NO | `list` (py) | **GIN idx `ix_cves_cpe_match_gin` (`jsonb_path_ops`), PostgreSQL-only via `.ddl_if(dialect="postgresql")`** | denormalized flat array of `CpeCriterion`-shaped objects |
| references | JSON/JSONB | NO | `list` (py) | — | list[str] |
| data | JSON/JSONB | NO | — | — | verbatim NVD JSON |
| updated_at | DateTime(tz) | NO | server_default `now()` | — | |

Upsert: `INSERT ... ON CONFLICT (cve_id) DO UPDATE ... WHERE excluded.last_modified > cves.last_modified` (`app/nvd_mirror/adapters/cve_repository.py:4-9,76,101`).

#### `nvd_sync_runs` — class `NvdSyncRunRow` (line 123) — mirror sync audit

| Field | DB type | Nullable | Default | Key | Description |
|---|---|---|---|---|---|
| id | BigInteger (Integer on SQLite via `.with_variant`) | NO | autoincrement | PK | |
| run_kind | String(16) | NO | — | — | CHECK in (`bootstrap`,`incremental`) |
| window_start / window_end | DateTime(tz) | NO | — | — | |
| started_at | DateTime(tz) | NO | server_default `now()` | idx | |
| finished_at | DateTime(tz) | YES | — | — | |
| status | String(16) | NO | `running` (py) | — | CHECK in (`running`,`success`,`failed`,`aborted`) |
| upserted_count | Integer | NO | `0` (py) | — | |
| error_message | Text | YES | — | — | |

---

## 3. Relationship map (for Mermaid erDiagram)

FK-backed (cardinality 1--*; ondelete noted where declared):

```
tenants                 1--* tenant_users                       (tenant_users.tenant_id, CASCADE)
iam_users               1--* tenant_users                       (tenant_users.user_id, CASCADE)
tenants                 1--* <all 21 TenantOwned tables>        (<table>.tenant_id)
iam_users               1--* lifecycle_provider_configs         (updated_by_user_id, SET NULL)
iam_users               1--* lifecycle_provider_secrets         (updated_by_user_id, SET NULL)
iam_users               1--* lifecycle_vendor_records           (updated_by_user_id, SET NULL)
iam_users               1--* audit_log                          (user_ref_id, SET NULL)
projects                1--* products                           (products.project_id, CASCADE)
projects                1--* sbom_source                        (sbom_source.projectid)
projects                1--* sbom_validation_sessions           (project_id)
projects                1--* analysis_run                       (analysis_run.project_id)
projects                1--* analysis_schedule                  (project_id, CASCADE)
projects                1--* vulnerability_remediation          (project_id, CASCADE)
projects                1--* vulnerability_remediation_audit    (project_id, CASCADE)
products                1--* sbom_source                        (sbom_source.product_id)
products                1--* analysis_run                       (analysis_run.product_id)
products                1--* analysis_schedule                  (product_id, CASCADE)
sbom_type               1--* sbom_source                        (sbom_source.sbom_type)
sbom_type               1--* sbom_validation_sessions           (sbom_type)
sbom_source             1--* sbom_source                        (parent_id — version lineage, self-ref)
sbom_source             1--1 sbom_source                        (source_sbom_id / converted_sbom_id — conversion pair, self-ref)
sbom_source             1--* sbom_analysis_report               (sbom_ref_id)
sbom_source             1--* sbom_component                     (sbom_id)
sbom_source             1--* vex_documents                      (sbom_id, CASCADE)
sbom_source             1--* vex_statements                     (sbom_id, CASCADE)
sbom_source             1--* analysis_run                       (sbom_id)
sbom_source             1--* analysis_schedule                  (sbom_id, CASCADE)
sbom_source             1--* sbom_validation_sessions           (imported_sbom_id)
sbom_validation_sessions 1--* sbom_validation_session_events    (session_id, CASCADE + ORM delete-orphan)
sbom_component          1--* analysis_finding                   (component_id)
sbom_component          1--* vex_statements                     (component_id, SET NULL)
sbom_component          1--* component_lifecycle_override_audit (component_id, CASCADE)
sbom_component          1--* vex_override_audit                 (component_id, CASCADE)
sbom_component          1--* sbom_component                     (duplicate_of_component_id, CASCADE, self-ref)
vex_documents           1--* vex_statements                     (vex_document_id, CASCADE + ORM delete-orphan)
analysis_run            1--* analysis_finding                   (analysis_run_id)
analysis_run            1--* ai_fix_batch                       (run_id, CASCADE)
analysis_run            1--* analysis_schedule                  (last_run_id, SET NULL)
vulnerability_remediation 1--* vulnerability_remediation_audit  (remediation_id, CASCADE + ORM delete-orphan)
```

Logical (no FK — join by value; intentional loose coupling):

```
analysis_run  1--* compare_cache      (run_a_id / run_b_id — cache invalidation by id)
sbom_source   1--* run_cache          (run_cache.sbom_id, plain Integer)
kev_entry     1--1 analysis_finding   (by cve_id/vuln_id at read time)
epss_score    1--1 analysis_finding   (by cve_id/vuln_id at read time)
cve_cache     1--1 analysis_finding   (by vuln_id)
ai_fix_cache  *--* analysis_finding   (cache_key derived from vuln+component+version)
cves (mirror) standalone; nvd_settings, nvd_sync_runs, ai_settings, ai_provider_config,
ai_provider_credential, ai_credential_audit_log, source_response_cache, nvd_lookup_cache,
component_lifecycle_cache, lifecycle_* standalone
```

ORM `cascade="all, delete-orphan"` exists only on: validation-session events, VEX document statements, remediation history. Other deletes are handled by FK `ondelete` or service code (`app/services/sbom_delete_service.py`).

---

## 4. Engine & session setup (`app/db.py`)

| Aspect | Evidence |
|---|---|
| Sync vs async | **Synchronous only**: `create_engine` + `sessionmaker` (`db.py:124,136`); no `create_async_engine` anywhere (grep over `app/` = 0 hits) |
| URL resolution | `DATABASE_URL` env var first, then `Settings.database_url` (pydantic BaseSettings; `.env` file, case-insensitive; `app/settings.py:76-79,558-560`); both paths loaded after `dotenv.load_dotenv()` (`db.py:10-15`) |
| SQLite fallback | Only if `ALLOW_SQLITE=true`; otherwise `RuntimeError` "DATABASE_URL is not configured…" (`db.py:64-71`). Default SQLite path = `sbom_api.db` beside the project root (`db.py:30-32`). `sbom_api.db` exists in the repo root (9,265,152 bytes) — SQLite is the dev/test engine; README §19: "PostgreSQL is the normal development database" and example URL `postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser` (README lines ~648-693) |
| PG guard | PostgreSQL URL without a password raises `RuntimeError` (`db.py:41-42,55-56`) |
| PG pool settings | `pool_pre_ping` (default True), `pool_size` (`db_pool_size` default 20; legacy `database_pool_size` default 5), `max_overflow` (20 / legacy 10), `pool_timeout` 30 s, `pool_recycle` 1800 s — new `db_pool_*` names take precedence over legacy `database_pool_*` (`db.py:93-120`, `settings.py:80-95`) |
| SQLite options | `check_same_thread=False`; `PRAGMA foreign_keys=ON` on every connect (`db.py:86,127-133`) |
| Session | `SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)`; FastAPI dependency `get_db()` with rollback-on-exception (`db.py:136-148`) |
| Global query filters | Soft-delete + tenant filters and tenant write-stamping via session event listeners (§1.1; `db.py:151-240`). When auth disabled and no context: writes default to `tenant_id = 1` (`db.py:218-223`) |
| Dialect support | Explicitly SQLite + PostgreSQL; any other dialect → `RuntimeError` at startup (`app/main.py:334-335`) |

---

## 5. Alembic

### 5.1 Configuration

- `alembic.ini` (repo root): `script_location = alembic`; `sqlalchemy.url = driver://user:pass@localhost/dbname` is a **placeholder — never used** (env.py overrides). Standard logging config.
- `alembic/env.py`: loads `.env`; imports `app.models` **and** `app.nvd_mirror.db.models` to register all tables on `Base.metadata` (lines 16-17); `target_metadata = Base.metadata` → **autogenerate-capable**; `get_url()` = `DATABASE_URL` env or `app.db.DATABASE_URL` (line 29-30); online mode creates a `NullPool` engine (line 46). No `compare_type`/`render_as_batch` options set.
- `alembic/` contains only `env.py`, `script.py.mako`, `versions/` — **no alembic README**.

### 5.2 Migration chain (strictly linear, single head)

Order verified from `revision`/`down_revision` headers of all 41 files in `alembic/versions/`. **Head = `041_project_product_hierarchy`. No branch labels, no merge revisions.** Revision ids are human-readable slugs, not hashes.

| # | Revision id | Revises | Description (from docstring) | Date |
|---|---|---|---|---|
| 001 | `001_initial_schema` | — | Initial schema — **bootstrap via `Base.metadata.create_all`** (not a frozen DDL snapshot) | 2026-04-13 |
| 002 | `002_nvd_mirror_tables` | 001 | NVD mirror tables (Phase 2) | 2026-04-28 |
| 003 | `003_kev_epss_cache` | 002 | KEV + EPSS cache tables | 2026-04-29 |
| 004 | `004_analysis_schedule` | 003 | Periodic analysis scheduling | 2026-04-29 |
| 005 | `005_rename_run_status` | 004 | **Data migration**: `FAIL→FINDINGS`, `PASS→OK` on `analysis_run.run_status` + `analysis_schedule.last_run_status` (ADR-0001) | 2026-04-30 |
| 006 | `006_cve_cache` | 005 | Merged CVE detail cache | 2026-04-30 |
| 007 | `007_compare_cache` | 006 | Compare-runs result cache (ADR-0008) | 2026-05-01 |
| 008 | `008_ai_usage_log` | 007 | ai_usage_log + ai_provider_config | 2026-05-03 |
| 009 | `009_ai_fix_cache` | 008 | Cached AI fix bundles | 2026-05-03 |
| 010 | `010_ai_credentials` | 009 | ai_provider_credential + ai_settings (+ **seed singleton row**) + ai_credential_audit_log | 2026-05-04 |
| 011 | `011_ai_fix_batch` | 010 | Multi-batch AI fix tracking | 2026-05-04 |
| 012 | `012_sbom_validation_columns` | 011 | sbom_source 8-stage validation columns | 2026-05-07 |
| 013 | `013_reclassify_unvalidated_sbom_source` | 012 | **Data migration**: legacy rows → `status='pending'`; downgrade = intentional no-op | 2026-05-07 |
| 014 | `014_add_soft_delete_columns` | 013 | Soft-delete columns on 8 tables | 2026-05-07 |
| 015 | `015_audit_log_table` | 014 | General-purpose audit_log | 2026-05-07 |
| 016 | `016_analysis_finding_match_reason` | 015 | match_reason + matched_range | 2026-05-27 |
| 017 | `017_analysis_finding_confidence_and_strategy` | 016 | match_confidence + match_strategy | 2026-06-02 |
| 018 | `018_source_response_cache` | 017 | Raw per-source response cache | 2026-06-03 |
| 019 | `019_ai_fix_cache_overall_confidence` | 018 | overall_confidence column | 2026-06-09 |
| 020 | `020_lifecycle_management_platform` | 019 | Lifecycle/completeness/versioning/remediation schema | 2026-06-11 |
| 021 | `021_remediation_audit_history` | 020 | Remediation audit history | 2026-06-11 |
| 022 | `022_component_lifecycle_enrichment` | 021 | Provider-based lifecycle enrichment fields | 2026-06-11 |
| 023 | `023_component_deduplication` | 022 | Component dedup support | 2026-06-12 |
| 024 | `024_validation_repair_sessions` | 023 | Validation repair session tables | 2026-06-12 |
| 025 | `025_lifecycle_advanced_fields` | 024 | Advanced lifecycle fields | 2026-06-12 |
| 026 | `026_vex_lifecycle_enrichment` | 025 | VEX enrichment + override audit tables | 2026-06-12 |
| 027 | `027_vex_discovery_metadata` | 026 | Document-level VEX discovery metadata | 2026-06-12 |
| 028 | `028_add_sbom_product_name_description` | 027 | product_name + description on sbom_source | 2026-06-12 |
| 029 | `029_sbom_spdx_cyclonedx_conversion` | 028 | SPDX→CycloneDX conversion columns | 2026-06-17 |
| 030 | `030_sbom_conversion_enrichment_status` | 029 | Conversion enrichment status | 2026-06-17 |
| 031 | `031_nvd_lookup_cache` | 030 | NVD lookup cache + CPE provenance | 2026-06-20 |
| 032 | `032_postgres_compat` | 031 | **PostgreSQL-only**: widen `alembic_version.version_num` to String(128); fix `server_default sa.true()` on can_edit/can_ai_fix; downgrade intentionally returns | 2026-06-22 |
| 033 | `033_hcl_iam_multitenancy` | 032 | **Data migration**: tenants/iam_users/tenant_users tables; seed Default Tenant id=1 + local-dev-admin; add NOT NULL `tenant_id` (backfilled `=1`) + FK + `(tenant_id, pk)` indexes to 20 tables; audit_log identity columns; tenant-scoped unique constraints. **Downgrade raises RuntimeError (intentionally unsupported — "Restore from a pre-migration backup instead")** | 2026-06-22 |
| 034 | `034_lifecycle_provider_admin` | 033 | Lifecycle provider admin tables + **seed provider defaults** | 2026-06-27 |
| 035 | `035_widen_audit_log_fields` | 034 | Widen audit_log fields for namespaced actions | 2026-06-27 |
| 036 | `036_component_extraction_status` | 035 | Component-extraction reconciliation status | 2026-06-27 |
| 037 | `037_stage9_normalization_dedup` | 036 | Stage-9 normalization/dedup fields | 2026-06-29 |
| 038 | `038_validation_session_full_content` | 037 | Full invalid-SBOM content + integrity metadata (contains `op.execute` backfill) | 2026-06-29 |
| 039 | `039_validation_workspace_large_file` | 038 | Large-file workspace metadata | 2026-06-29 |
| 040 | `040_analysis_run_trigger_source` | 039 | analysis_run.trigger_source | 2026-07-01 |
| 041 | `041_project_product_hierarchy` | 040 | **Head.** products table; product_id FKs on sbom_source/analysis_run/analysis_schedule; **data migration** creating "Legacy / Unassigned Product" per project and "Unassigned Project" per tenant, backfilling `sbom_source.product_id`/`projectid` and `analysis_run.product_id`; replaces schedule scope CHECK to include `PRODUCT` (041:123-345) | 2026-07-03 |

### 5.3 Migration characteristics

- **Downgrades:** real implementations in ~38/41 revisions (guarded drops). Exceptions: 013 (`pass`, documented no-op), 032 (`return`, keeps widened alembic_version), 033 (**raises `RuntimeError` — downgrade intentionally unsupported**). 001's downgrade is `Base.metadata.drop_all`.
- **Idempotency:** every migration guards with `_table_exists` / `_column_exists` / `_index_exists` inspector helpers (visible in all downgrade/upgrade bodies) — reflects README rule "keep migrations idempotent where practical" (README line 993).
- **`sa.true()/sa.false()` server defaults:** used in 002, 004, 020, 022, 023, 024, 025, 032, 034, 039, 041 (grep). Mirrored in models via `expression.true()/false()` (e.g. `models_mixins.py:49-54`, `models.py:377-380`).
- **Data migrations:** 005, 010 (seed ai_settings), 013, 033 (identity seed + tenant backfill), 034 (provider seed), 038 (content backfill), 041 (product/project backfill). SQLite-specific handling via `op.batch_alter_table` (e.g. 033, 035, 041).
- **Dialect-gated DDL:** PG-only GIN index in 002/mirror models (`.ddl_if(dialect="postgresql")`); 032 entirely PG-only; 041 skips CHECK-constraint swap on SQLite (041:315-320).
- **Orphan artifact:** `alembic/versions/__pycache__/e241e4c5d91e_tmp_frozen_snapshot.cpython-312.pyc` — compiled remnant of a deleted hash-named "tmp frozen snapshot" migration; the `.py` no longer exists (no effect on the chain, but shows a frozen-snapshot attempt was made and removed).

### 5.4 Operating rules found in docs

| Rule | Source |
|---|---|
| Run Alembic through the project venv: `python -m alembic current / heads / upgrade head` | README §19 (lines ~659-668) |
| "Add a new Alembic revision for schema changes; do not silently mutate already-applied production migrations" | README line 951 |
| "Use Alembic for schema changes and keep migrations idempotent where practical" | README line 993 |
| If `DATABASE_URL` missing, app fails unless `ALLOW_SQLITE=true`; PostgreSQL is the normal dev DB | README §19 |
| PostgreSQL schema DDL "belongs exclusively to Alembic"; SQLite legacy files get compat DDL at startup | `app/main.py:466-469` |
| Take a DB backup before risky credential-table operations | `docs/runbook-ai-credentials.md:48,216` |
| De-facto forward-only at 033: downgrade raises; "Restore from a pre-migration backup instead" | `alembic/versions/033_hcl_iam_multitenancy.py` downgrade |
| Explicit "forward-only" policy or `alembic stamp` guidance | **Not documented — no evidence found** (searched "forward-only", "forward only", "alembic stamp", "backup" in README.md, docs/, CLAUDE.md, alembic/) |

---

## 6. Startup schema-revision check (`app/main.py`)

`_ensure_seed_data()` (main.py:324) runs at app startup and calls `_verify_schema_is_current()` (main.py:562-621):

1. Inspect table names; a **completely empty DB passes** (SQLite awaiting `create_all`, or PG awaiting migrations) (line 585-587).
2. If `alembic_version` exists: load `alembic.ini`, compute `ScriptDirectory.get_heads()`, compare against `SELECT version_num FROM alembic_version`. **Mismatch → `RuntimeError` "Database schema is not at Alembic head; run 'alembic upgrade head'…"** listing expected vs found (lines 589-615).
3. If `alembic_version` missing but `sbom_source` exists: require the `tenant_id` column, else `RuntimeError` "Run alembic upgrade head" (lines 616-621).
4. PG auth failures are rewritten into a friendly "password authentication failed for user 'sbom'" error (lines 571-583, 596-607).

Then, **SQLite only**: `Base.metadata.create_all` plus a long ladder of idempotent `_ensure_column`/`_ensure_*_table` "lightweight migrations" replaying columns from migrations 012→041 for pre-Alembic dev DBs (main.py:329-462), the 013 reclassification UPDATE (line 361-362), and index DDL for validation sessions (main.py:305-321). PostgreSQL gets **no** DDL here — Alembic is authoritative. Finally seeds: Tenant id=1 / IAMUser id=1 / TenantUser admin membership, SBOMType rows, lifecycle provider defaults (main.py:471-557), with PG sequence resync helpers (`_sync_postgres_sequence`, lines 506-507).

---

## 7. Model ↔ migration drift notes (time-boxed check)

- **001 is `create_all` from live models**, so the "initial schema" changes retroactively as models evolve; fresh installs and long-upgraded DBs converge only because later migrations are idempotent (`IF NOT EXISTS`-style guards). This is a deliberate but unusual design; it masks missing-migration errors on fresh DBs.
- **README §19 is stale**: "latest inspected migration is `035_widen_audit_log_fields`" vs actual head `041`.
- **`products` inconsistencies**: excluded from both module-level index loops (`ix_*_deactivated`, `ix_*_tenant_identity`, models.py:1433-1477) although it carries both mixins; it also has a redundant `deleted_at` String column alongside `is_active`. Model and migration 041 agree with each other, but the table diverges from the conventions of the other 20 tenant tables.
- **`audit_log.entity_type`**: model String(128) (models.py:1367) vs migration 033 creating String(64) (033:~172) — migration 035 widens fields, reconciling; not re-verified column-by-column.
- Every model table is covered by the chain (mirror tables in 002; lifecycle admin in 034; products in 041). No model without a migration was found, with the caveat that 001's `create_all` would silently absorb one.
- SQLite dev DBs additionally rely on the `_ensure_column` ladder in `app/main.py` rather than Alembic — two parallel schema-maintenance mechanisms that must be kept in sync by hand.

---
