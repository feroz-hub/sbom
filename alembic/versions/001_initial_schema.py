"""Initial schema — frozen literal snapshot.

Revision ID: 001_initial_schema
Revises:
Create Date: 2026-04-13

Phase 2 of the DB schema-management consolidation froze this migration. It
previously imported the live application models and bulk-built every table
from their metadata, so the migration silently changed whenever the models
changed — but a migration must be an immutable snapshot. It is now an explicit
``op.create_table`` /
``op.create_index`` snapshot rendered from the model metadata at head, so a
fresh ``alembic upgrade head`` produces the identical final schema (migrations
002-039 stay existence-guarded no-ops on a fresh DB, exactly as before).

Do NOT add new schema changes here — create a new migration instead.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('ai_credential_audit_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.String(length=128), nullable=True),
    sa.Column('action', sa.String(length=48), nullable=False),
    sa.Column('target_kind', sa.String(length=24), nullable=False),
    sa.Column('target_id', sa.Integer(), nullable=True),
    sa.Column('provider_name', sa.String(length=32), nullable=True),
    sa.Column('detail', sa.String(length=240), nullable=True),
    sa.Column('created_at', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ai_credential_audit_log'))
    )
    op.create_index(op.f('ix_ai_credential_audit_log_created_at'), 'ai_credential_audit_log', ['created_at'], unique=False)
    op.create_index(op.f('ix_ai_credential_audit_log_id'), 'ai_credential_audit_log', ['id'], unique=False)
    op.create_table('ai_fix_cache',
    sa.Column('cache_key', sa.String(length=64), nullable=False),
    sa.Column('vuln_id', sa.String(length=64), nullable=False),
    sa.Column('component_name', sa.String(length=255), nullable=False),
    sa.Column('component_version', sa.String(length=128), nullable=False),
    sa.Column('prompt_version', sa.String(length=32), nullable=False),
    sa.Column('schema_version', sa.Integer(), nullable=False),
    sa.Column('remediation_prose', sa.JSON(), nullable=False),
    sa.Column('upgrade_command', sa.JSON(), nullable=False),
    sa.Column('decision_recommendation', sa.JSON(), nullable=False),
    sa.Column('overall_confidence', sa.String(length=16), nullable=True),
    sa.Column('provider_used', sa.String(length=32), nullable=False),
    sa.Column('model_used', sa.String(length=96), nullable=False),
    sa.Column('total_cost_usd', sa.Float(), nullable=False),
    sa.Column('generated_at', sa.String(), nullable=False),
    sa.Column('expires_at', sa.String(), nullable=False),
    sa.Column('last_accessed_at', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('cache_key', name=op.f('pk_ai_fix_cache'))
    )
    op.create_index(op.f('ix_ai_fix_cache_expires_at'), 'ai_fix_cache', ['expires_at'], unique=False)
    op.create_index('ix_ai_fix_cache_vuln_component', 'ai_fix_cache', ['vuln_id', 'component_name', 'component_version'], unique=False)
    op.create_index(op.f('ix_ai_fix_cache_vuln_id'), 'ai_fix_cache', ['vuln_id'], unique=False)
    op.create_table('ai_provider_config',
    sa.Column('provider_name', sa.String(length=32), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=True),
    sa.Column('default_model', sa.String(length=96), nullable=True),
    sa.Column('base_url', sa.String(length=256), nullable=True),
    sa.Column('max_concurrent', sa.Integer(), nullable=True),
    sa.Column('rate_per_minute', sa.Float(), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('updated_at', sa.String(), nullable=True),
    sa.Column('updated_by', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('provider_name', name=op.f('pk_ai_provider_config'))
    )
    op.create_table('ai_provider_credential',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('provider_name', sa.String(length=32), nullable=False),
    sa.Column('label', sa.String(length=64), nullable=False),
    sa.Column('api_key_encrypted', sa.Text(), nullable=True),
    sa.Column('base_url', sa.String(length=512), nullable=True),
    sa.Column('default_model', sa.String(length=128), nullable=True),
    sa.Column('tier', sa.String(length=16), nullable=False),
    sa.Column('is_default', sa.Boolean(), nullable=False),
    sa.Column('is_fallback', sa.Boolean(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('cost_per_1k_input_usd', sa.Float(), nullable=False),
    sa.Column('cost_per_1k_output_usd', sa.Float(), nullable=False),
    sa.Column('is_local', sa.Boolean(), nullable=False),
    sa.Column('max_concurrent', sa.Integer(), nullable=True),
    sa.Column('rate_per_minute', sa.Float(), nullable=True),
    sa.Column('created_at', sa.String(), nullable=False),
    sa.Column('updated_at', sa.String(), nullable=False),
    sa.Column('last_test_at', sa.String(), nullable=True),
    sa.Column('last_test_success', sa.Boolean(), nullable=True),
    sa.Column('last_test_error', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ai_provider_credential')),
    sa.UniqueConstraint('provider_name', 'label', name='uq_ai_provider_credential_provider_label')
    )
    op.create_index('ix_ai_only_one_default', 'ai_provider_credential', ['is_default'], unique=True, postgresql_where=sa.text('is_default = true'), sqlite_where=sa.text('is_default = 1'))
    op.create_index('ix_ai_only_one_fallback', 'ai_provider_credential', ['is_fallback'], unique=True, postgresql_where=sa.text('is_fallback = true'), sqlite_where=sa.text('is_fallback = 1'))
    op.create_index(op.f('ix_ai_provider_credential_id'), 'ai_provider_credential', ['id'], unique=False)
    op.create_index(op.f('ix_ai_provider_credential_provider_name'), 'ai_provider_credential', ['provider_name'], unique=False)
    op.create_table('ai_settings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('feature_enabled', sa.Boolean(), nullable=False),
    sa.Column('kill_switch_active', sa.Boolean(), nullable=False),
    sa.Column('budget_per_request_usd', sa.Float(), nullable=False),
    sa.Column('budget_per_scan_usd', sa.Float(), nullable=False),
    sa.Column('budget_daily_usd', sa.Float(), nullable=False),
    sa.Column('updated_at', sa.String(), nullable=False),
    sa.Column('updated_by_user_id', sa.String(), nullable=True),
    sa.CheckConstraint('id = 1', name=op.f('ck_ai_settings_ck_ai_settings_singleton')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ai_settings'))
    )
    op.create_table('component_lifecycle_cache',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('lookup_key', sa.String(), nullable=True),
    sa.Column('normalized_name', sa.String(), nullable=False),
    sa.Column('normalized_version', sa.String(), nullable=True),
    sa.Column('ecosystem', sa.String(), nullable=True),
    sa.Column('purl', sa.String(), nullable=True),
    sa.Column('cpe', sa.String(), nullable=True),
    sa.Column('lifecycle_status', sa.String(), nullable=True),
    sa.Column('eos_date', sa.String(), nullable=True),
    sa.Column('eol_date', sa.String(), nullable=True),
    sa.Column('eof_date', sa.String(), nullable=True),
    sa.Column('deprecated', sa.Boolean(), nullable=True),
    sa.Column('unsupported', sa.Boolean(), nullable=True),
    sa.Column('maintenance_status', sa.String(), nullable=True),
    sa.Column('latest_version', sa.String(), nullable=True),
    sa.Column('latest_supported_version', sa.String(), nullable=True),
    sa.Column('recommended_version', sa.String(), nullable=True),
    sa.Column('recommendation', sa.Text(), nullable=True),
    sa.Column('source_name', sa.String(), nullable=True),
    sa.Column('source_url', sa.String(), nullable=True),
    sa.Column('evidence_json', sa.JSON(), nullable=True),
    sa.Column('confidence', sa.String(), nullable=True),
    sa.Column('checked_at', sa.String(), nullable=False),
    sa.Column('expires_at', sa.String(), nullable=False),
    sa.Column('is_stale', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_component_lifecycle_cache')),
    sa.UniqueConstraint('normalized_name', 'normalized_version', 'ecosystem', 'purl', name='uq_component_lifecycle_cache_identity')
    )
    op.create_index(op.f('ix_component_lifecycle_cache_checked_at'), 'component_lifecycle_cache', ['checked_at'], unique=False)
    op.create_index(op.f('ix_component_lifecycle_cache_cpe'), 'component_lifecycle_cache', ['cpe'], unique=False)
    op.create_index(op.f('ix_component_lifecycle_cache_ecosystem'), 'component_lifecycle_cache', ['ecosystem'], unique=False)
    op.create_index(op.f('ix_component_lifecycle_cache_expires_at'), 'component_lifecycle_cache', ['expires_at'], unique=False)
    op.create_index(op.f('ix_component_lifecycle_cache_id'), 'component_lifecycle_cache', ['id'], unique=False)
    op.create_index('ix_component_lifecycle_cache_lookup', 'component_lifecycle_cache', ['ecosystem', 'normalized_name', 'normalized_version'], unique=False)
    op.create_index(op.f('ix_component_lifecycle_cache_lookup_key'), 'component_lifecycle_cache', ['lookup_key'], unique=False)
    op.create_index(op.f('ix_component_lifecycle_cache_normalized_name'), 'component_lifecycle_cache', ['normalized_name'], unique=False)
    op.create_index(op.f('ix_component_lifecycle_cache_normalized_version'), 'component_lifecycle_cache', ['normalized_version'], unique=False)
    op.create_index(op.f('ix_component_lifecycle_cache_purl'), 'component_lifecycle_cache', ['purl'], unique=False)
    op.create_table('cve_cache',
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('payload', sa.JSON(), nullable=False),
    sa.Column('sources_used', sa.String(length=128), nullable=False),
    sa.Column('fetched_at', sa.String(), nullable=False),
    sa.Column('expires_at', sa.String(), nullable=False),
    sa.Column('fetch_error', sa.Text(), nullable=True),
    sa.Column('schema_version', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('cve_id', name=op.f('pk_cve_cache'))
    )
    op.create_index(op.f('ix_cve_cache_cve_id'), 'cve_cache', ['cve_id'], unique=False)
    op.create_index(op.f('ix_cve_cache_expires_at'), 'cve_cache', ['expires_at'], unique=False)
    op.create_table('cves',
    sa.Column('cve_id', sa.Text(), nullable=False),
    sa.Column('last_modified', sa.DateTime(timezone=True), nullable=False),
    sa.Column('published', sa.DateTime(timezone=True), nullable=False),
    sa.Column('vuln_status', sa.Text(), nullable=False),
    sa.Column('description_en', sa.Text(), nullable=True),
    sa.Column('score_v40', sa.Float(), nullable=True),
    sa.Column('score_v31', sa.Float(), nullable=True),
    sa.Column('score_v2', sa.Float(), nullable=True),
    sa.Column('severity_text', sa.String(length=32), nullable=True),
    sa.Column('vector_string', sa.Text(), nullable=True),
    sa.Column('aliases', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('cpe_match', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('references', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('data', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.PrimaryKeyConstraint('cve_id', name=op.f('pk_cves'))
    )
    # GIN index is PostgreSQL-only. Migration 002 guards it the same way, and
    # SQLAlchemy skips a ``postgresql_using`` index on SQLite, so this guard
    # keeps a fresh SQLite build identical to the historical schema.
    if op.get_bind().dialect.name == 'postgresql':
        op.create_index('ix_cves_cpe_match_gin', 'cves', ['cpe_match'], unique=False, postgresql_using='gin', postgresql_ops={'cpe_match': 'jsonb_path_ops'})
    op.create_index('ix_cves_last_modified', 'cves', ['last_modified'], unique=False)
    op.create_index('ix_cves_vuln_status', 'cves', ['vuln_status'], unique=False)
    op.create_table('epss_score',
    sa.Column('cve_id', sa.String(), nullable=False),
    sa.Column('epss', sa.Float(), nullable=False),
    sa.Column('percentile', sa.Float(), nullable=True),
    sa.Column('score_date', sa.String(), nullable=True),
    sa.Column('refreshed_at', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('cve_id', name=op.f('pk_epss_score'))
    )
    op.create_index(op.f('ix_epss_score_cve_id'), 'epss_score', ['cve_id'], unique=False)
    op.create_table('iam_users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('external_iam_user_id', sa.String(length=255), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=True),
    sa.Column('display_name', sa.String(length=255), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_iam_users')),
    sa.UniqueConstraint('external_iam_user_id', name='uq_iam_users_external_iam_user_id')
    )
    op.create_index(op.f('ix_iam_users_email'), 'iam_users', ['email'], unique=False)
    op.create_index(op.f('ix_iam_users_external_iam_user_id'), 'iam_users', ['external_iam_user_id'], unique=False)
    op.create_table('kev_entry',
    sa.Column('cve_id', sa.String(), nullable=False),
    sa.Column('vendor_project', sa.String(), nullable=True),
    sa.Column('product', sa.String(), nullable=True),
    sa.Column('vulnerability_name', sa.String(), nullable=True),
    sa.Column('date_added', sa.String(), nullable=True),
    sa.Column('short_description', sa.Text(), nullable=True),
    sa.Column('required_action', sa.Text(), nullable=True),
    sa.Column('due_date', sa.String(), nullable=True),
    sa.Column('known_ransomware_use', sa.String(), nullable=True),
    sa.Column('refreshed_at', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('cve_id', name=op.f('pk_kev_entry'))
    )
    op.create_index(op.f('ix_kev_entry_cve_id'), 'kev_entry', ['cve_id'], unique=False)
    op.create_table('nvd_lookup_cache',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('lookup_type', sa.String(length=16), nullable=False),
    sa.Column('identifier', sa.String(length=2048), nullable=False),
    sa.Column('identifier_hash', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('response_json', sa.JSON(), nullable=True),
    sa.Column('http_status', sa.Integer(), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('checked_at', sa.String(), nullable=False),
    sa.Column('expires_at', sa.String(), nullable=False),
    sa.Column('created_at', sa.String(), nullable=False),
    sa.Column('updated_at', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_nvd_lookup_cache')),
    sa.UniqueConstraint('lookup_type', 'identifier_hash', name='uq_nvd_lookup_cache_type_hash')
    )
    op.create_index('ix_nvd_lookup_cache_expires_at', 'nvd_lookup_cache', ['expires_at'], unique=False)
    op.create_index('ix_nvd_lookup_cache_identifier', 'nvd_lookup_cache', ['identifier'], unique=False)
    op.create_index('ix_nvd_lookup_cache_status', 'nvd_lookup_cache', ['status'], unique=False)
    op.create_table('nvd_settings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('api_endpoint', sa.Text(), nullable=False),
    sa.Column('api_key_ciphertext', sa.LargeBinary(), nullable=True),
    sa.Column('download_feeds_enabled', sa.Boolean(), nullable=False),
    sa.Column('page_size', sa.Integer(), nullable=False),
    sa.Column('window_days', sa.Integer(), nullable=False),
    sa.Column('min_freshness_hours', sa.Integer(), nullable=False),
    sa.Column('last_modified_utc', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_successful_sync_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.CheckConstraint('id = 1', name=op.f('ck_nvd_settings_ck_nvd_settings_singleton')),
    sa.CheckConstraint('min_freshness_hours >= 0', name=op.f('ck_nvd_settings_ck_nvd_settings_min_freshness_nonneg')),
    sa.CheckConstraint('page_size BETWEEN 1 AND 2000', name=op.f('ck_nvd_settings_ck_nvd_settings_page_size_range')),
    sa.CheckConstraint('window_days BETWEEN 1 AND 119', name=op.f('ck_nvd_settings_ck_nvd_settings_window_days_range')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_nvd_settings'))
    )
    op.create_table('nvd_sync_runs',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('run_kind', sa.String(length=16), nullable=False),
    sa.Column('window_start', sa.DateTime(timezone=True), nullable=False),
    sa.Column('window_end', sa.DateTime(timezone=True), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('upserted_count', sa.Integer(), nullable=False),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.CheckConstraint("run_kind IN ('bootstrap','incremental')", name=op.f('ck_nvd_sync_runs_ck_nvd_sync_runs_kind')),
    sa.CheckConstraint("status IN ('running','success','failed','aborted')", name=op.f('ck_nvd_sync_runs_ck_nvd_sync_runs_status')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_nvd_sync_runs'))
    )
    op.create_index('ix_nvd_sync_runs_started_at', 'nvd_sync_runs', ['started_at'], unique=False)
    op.create_table('sbom_type',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('typename', sa.String(), nullable=False),
    sa.Column('type_details', sa.String(), nullable=True),
    sa.Column('created_on', sa.String(), nullable=True),
    sa.Column('created_by', sa.String(), nullable=True),
    sa.Column('modified_on', sa.String(), nullable=True),
    sa.Column('modified_by', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sbom_type')),
    sa.UniqueConstraint('typename', name=op.f('uq_sbom_type_typename'))
    )
    op.create_index(op.f('ix_sbom_type_id'), 'sbom_type', ['id'], unique=False)
    op.create_table('source_response_cache',
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('component_key', sa.String(length=512), nullable=False),
    sa.Column('payload', sa.JSON(), nullable=False),
    sa.Column('fetched_at', sa.String(), nullable=False),
    sa.Column('expires_at', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('source', 'component_key', name=op.f('pk_source_response_cache'))
    )
    op.create_index('ix_source_response_cache_expires_at', 'source_response_cache', ['expires_at'], unique=False)
    op.create_table('tenants',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('slug', sa.String(length=128), nullable=False),
    sa.Column('external_iam_tenant_id', sa.String(length=255), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_tenants')),
    sa.UniqueConstraint('external_iam_tenant_id', name='uq_tenants_external_iam_tenant_id'),
    sa.UniqueConstraint('slug', name='uq_tenants_slug')
    )
    op.create_index(op.f('ix_tenants_external_iam_tenant_id'), 'tenants', ['external_iam_tenant_id'], unique=False)
    op.create_index(op.f('ix_tenants_slug'), 'tenants', ['slug'], unique=False)
    op.create_table('ai_usage_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('request_id', sa.String(length=64), nullable=False),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('model', sa.String(length=96), nullable=False),
    sa.Column('purpose', sa.String(length=48), nullable=False),
    sa.Column('finding_cache_key', sa.String(length=64), nullable=True),
    sa.Column('input_tokens', sa.Integer(), nullable=False),
    sa.Column('output_tokens', sa.Integer(), nullable=False),
    sa.Column('cost_usd', sa.Float(), nullable=False),
    sa.Column('latency_ms', sa.Integer(), nullable=False),
    sa.Column('cache_hit', sa.Boolean(), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('created_at', sa.String(), nullable=False),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_ai_usage_log_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ai_usage_log'))
    )
    op.create_index(op.f('ix_ai_usage_log_created_at'), 'ai_usage_log', ['created_at'], unique=False)
    op.create_index(op.f('ix_ai_usage_log_finding_cache_key'), 'ai_usage_log', ['finding_cache_key'], unique=False)
    op.create_index(op.f('ix_ai_usage_log_id'), 'ai_usage_log', ['id'], unique=False)
    op.create_index(op.f('ix_ai_usage_log_provider'), 'ai_usage_log', ['provider'], unique=False)
    op.create_index('ix_ai_usage_log_provider_created', 'ai_usage_log', ['provider', 'created_at'], unique=False)
    op.create_index(op.f('ix_ai_usage_log_purpose'), 'ai_usage_log', ['purpose'], unique=False)
    op.create_index('ix_ai_usage_log_purpose_created', 'ai_usage_log', ['purpose', 'created_at'], unique=False)
    op.create_index(op.f('ix_ai_usage_log_tenant_id'), 'ai_usage_log', ['tenant_id'], unique=False)
    op.create_index('ix_ai_usage_log_tenant_identity', 'ai_usage_log', ['tenant_id', 'id'], unique=False)
    op.create_table('audit_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.String(length=128), nullable=True),
    sa.Column('action', sa.String(length=128), nullable=False),
    sa.Column('target_kind', sa.String(length=128), nullable=False),
    sa.Column('target_id', sa.Integer(), nullable=True),
    sa.Column('detail', sa.Text(), nullable=True),
    sa.Column('metadata_json', sa.JSON(), nullable=True),
    sa.Column('user_ref_id', sa.Integer(), nullable=True),
    sa.Column('entity_type', sa.String(length=128), nullable=True),
    sa.Column('entity_id', sa.String(length=128), nullable=True),
    sa.Column('old_value', sa.JSON(), nullable=True),
    sa.Column('new_value', sa.JSON(), nullable=True),
    sa.Column('ip_address', sa.String(length=64), nullable=True),
    sa.Column('user_agent', sa.Text(), nullable=True),
    sa.Column('created_at', sa.String(), nullable=False),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_audit_log_tenant_id_tenants')),
    sa.ForeignKeyConstraint(['user_ref_id'], ['iam_users.id'], name=op.f('fk_audit_log_user_ref_id_iam_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_log'))
    )
    op.create_index(op.f('ix_audit_log_action'), 'audit_log', ['action'], unique=False)
    op.create_index(op.f('ix_audit_log_created_at'), 'audit_log', ['created_at'], unique=False)
    op.create_index(op.f('ix_audit_log_entity_id'), 'audit_log', ['entity_id'], unique=False)
    op.create_index(op.f('ix_audit_log_entity_type'), 'audit_log', ['entity_type'], unique=False)
    op.create_index(op.f('ix_audit_log_id'), 'audit_log', ['id'], unique=False)
    op.create_index(op.f('ix_audit_log_target_id'), 'audit_log', ['target_id'], unique=False)
    op.create_index(op.f('ix_audit_log_target_kind'), 'audit_log', ['target_kind'], unique=False)
    op.create_index(op.f('ix_audit_log_tenant_id'), 'audit_log', ['tenant_id'], unique=False)
    op.create_index('ix_audit_log_tenant_identity', 'audit_log', ['tenant_id', 'id'], unique=False)
    op.create_index(op.f('ix_audit_log_user_ref_id'), 'audit_log', ['user_ref_id'], unique=False)
    op.create_table('compare_cache',
    sa.Column('cache_key', sa.String(length=64), nullable=False),
    sa.Column('run_a_id', sa.Integer(), nullable=False),
    sa.Column('run_b_id', sa.Integer(), nullable=False),
    sa.Column('payload', sa.JSON(), nullable=False),
    sa.Column('computed_at', sa.String(), nullable=False),
    sa.Column('expires_at', sa.String(), nullable=False),
    sa.Column('schema_version', sa.Integer(), nullable=False),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_compare_cache_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('cache_key', name=op.f('pk_compare_cache'))
    )
    op.create_index(op.f('ix_compare_cache_expires_at'), 'compare_cache', ['expires_at'], unique=False)
    op.create_index(op.f('ix_compare_cache_run_a_id'), 'compare_cache', ['run_a_id'], unique=False)
    op.create_index(op.f('ix_compare_cache_run_b_id'), 'compare_cache', ['run_b_id'], unique=False)
    op.create_index(op.f('ix_compare_cache_tenant_id'), 'compare_cache', ['tenant_id'], unique=False)
    op.create_index('ix_compare_cache_tenant_identity', 'compare_cache', ['tenant_id', 'cache_key'], unique=False)
    op.create_table('lifecycle_provider_configs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('provider_key', sa.String(length=64), nullable=False),
    sa.Column('display_name', sa.String(length=128), nullable=False),
    sa.Column('provider_type', sa.String(length=64), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('priority', sa.Integer(), nullable=False),
    sa.Column('base_url', sa.String(length=512), nullable=True),
    sa.Column('feed_urls_json', sa.JSON(), nullable=True),
    sa.Column('config_json', sa.JSON(), nullable=True),
    sa.Column('timeout_seconds', sa.Integer(), nullable=False),
    sa.Column('max_retries', sa.Integer(), nullable=False),
    sa.Column('circuit_breaker_enabled', sa.Boolean(), nullable=False),
    sa.Column('cache_ttl_known_days', sa.Integer(), nullable=True),
    sa.Column('cache_ttl_unknown_hours', sa.Integer(), nullable=True),
    sa.Column('cache_ttl_failure_minutes', sa.Integer(), nullable=True),
    sa.Column('cache_ttl_deprecated_days', sa.Integer(), nullable=True),
    sa.Column('last_success_at', sa.String(), nullable=True),
    sa.Column('last_failure_at', sa.String(), nullable=True),
    sa.Column('last_failure_message', sa.Text(), nullable=True),
    sa.Column('health_status', sa.String(length=32), nullable=False),
    sa.Column('created_at', sa.String(), nullable=False),
    sa.Column('updated_at', sa.String(), nullable=False),
    sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
    sa.CheckConstraint("health_status IN ('healthy','degraded','disabled','unknown')", name=op.f('ck_lifecycle_provider_configs_ck_lifecycle_provider_config_health')),
    sa.CheckConstraint('max_retries BETWEEN 0 AND 10', name=op.f('ck_lifecycle_provider_configs_ck_lifecycle_provider_config_retries')),
    sa.CheckConstraint('priority BETWEEN 1 AND 1000', name=op.f('ck_lifecycle_provider_configs_ck_lifecycle_provider_config_priority')),
    sa.CheckConstraint('timeout_seconds BETWEEN 1 AND 60', name=op.f('ck_lifecycle_provider_configs_ck_lifecycle_provider_config_timeout')),
    sa.ForeignKeyConstraint(['updated_by_user_id'], ['iam_users.id'], name=op.f('fk_lifecycle_provider_configs_updated_by_user_id_iam_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_lifecycle_provider_configs'))
    )
    op.create_index('ix_lifecycle_provider_configs_enabled_priority', 'lifecycle_provider_configs', ['enabled', 'priority'], unique=False)
    op.create_index(op.f('ix_lifecycle_provider_configs_health_status'), 'lifecycle_provider_configs', ['health_status'], unique=False)
    op.create_index(op.f('ix_lifecycle_provider_configs_id'), 'lifecycle_provider_configs', ['id'], unique=False)
    op.create_index(op.f('ix_lifecycle_provider_configs_provider_key'), 'lifecycle_provider_configs', ['provider_key'], unique=True)
    op.create_index(op.f('ix_lifecycle_provider_configs_provider_type'), 'lifecycle_provider_configs', ['provider_type'], unique=False)
    op.create_table('lifecycle_provider_secrets',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('provider_key', sa.String(length=64), nullable=False),
    sa.Column('secret_name', sa.String(length=64), nullable=False),
    sa.Column('encrypted_value', sa.Text(), nullable=False),
    sa.Column('value_preview', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.String(), nullable=False),
    sa.Column('updated_at', sa.String(), nullable=False),
    sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['updated_by_user_id'], ['iam_users.id'], name=op.f('fk_lifecycle_provider_secrets_updated_by_user_id_iam_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_lifecycle_provider_secrets')),
    sa.UniqueConstraint('provider_key', 'secret_name', name='uq_lifecycle_provider_secret_provider_name')
    )
    op.create_index(op.f('ix_lifecycle_provider_secrets_id'), 'lifecycle_provider_secrets', ['id'], unique=False)
    op.create_index('ix_lifecycle_provider_secrets_provider', 'lifecycle_provider_secrets', ['provider_key'], unique=False)
    op.create_index(op.f('ix_lifecycle_provider_secrets_provider_key'), 'lifecycle_provider_secrets', ['provider_key'], unique=False)
    op.create_table('lifecycle_vendor_records',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('vendor_name', sa.String(length=128), nullable=False),
    sa.Column('product_name', sa.String(length=255), nullable=False),
    sa.Column('product_aliases_json', sa.JSON(), nullable=True),
    sa.Column('ecosystem', sa.String(length=64), nullable=True),
    sa.Column('version_pattern', sa.String(length=128), nullable=True),
    sa.Column('version_start', sa.String(length=64), nullable=True),
    sa.Column('version_end', sa.String(length=64), nullable=True),
    sa.Column('lifecycle_status', sa.String(length=64), nullable=False),
    sa.Column('maintenance_status', sa.String(length=128), nullable=True),
    sa.Column('eol_date', sa.String(), nullable=True),
    sa.Column('eos_date', sa.String(), nullable=True),
    sa.Column('eof_date', sa.String(), nullable=True),
    sa.Column('deprecated', sa.Boolean(), nullable=False),
    sa.Column('unsupported', sa.Boolean(), nullable=False),
    sa.Column('latest_supported_version', sa.String(length=128), nullable=True),
    sa.Column('recommended_version', sa.String(length=128), nullable=True),
    sa.Column('evidence_url', sa.String(length=512), nullable=True),
    sa.Column('evidence_json', sa.JSON(), nullable=True),
    sa.Column('confidence', sa.String(length=32), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.String(), nullable=False),
    sa.Column('updated_at', sa.String(), nullable=False),
    sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['updated_by_user_id'], ['iam_users.id'], name=op.f('fk_lifecycle_vendor_records_updated_by_user_id_iam_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_lifecycle_vendor_records'))
    )
    op.create_index(op.f('ix_lifecycle_vendor_records_ecosystem'), 'lifecycle_vendor_records', ['ecosystem'], unique=False)
    op.create_index(op.f('ix_lifecycle_vendor_records_enabled'), 'lifecycle_vendor_records', ['enabled'], unique=False)
    op.create_index(op.f('ix_lifecycle_vendor_records_id'), 'lifecycle_vendor_records', ['id'], unique=False)
    op.create_index('ix_lifecycle_vendor_records_lookup', 'lifecycle_vendor_records', ['enabled', 'ecosystem', 'product_name'], unique=False)
    op.create_index(op.f('ix_lifecycle_vendor_records_product_name'), 'lifecycle_vendor_records', ['product_name'], unique=False)
    op.create_index(op.f('ix_lifecycle_vendor_records_vendor_name'), 'lifecycle_vendor_records', ['vendor_name'], unique=False)
    op.create_table('projects',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('project_name', sa.String(), nullable=False),
    sa.Column('project_details', sa.String(), nullable=True),
    sa.Column('project_status', sa.Integer(), nullable=False),
    sa.Column('created_on', sa.String(), nullable=True),
    sa.Column('created_by', sa.String(), nullable=True),
    sa.Column('modified_on', sa.String(), nullable=True),
    sa.Column('modified_by', sa.String(), nullable=True),
    sa.Column('is_active', sa.Boolean(), server_default=sa.text('1'), nullable=False),
    sa.Column('deactivated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('deactivated_by', sa.String(length=128), nullable=True),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_projects_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_projects')),
    sa.UniqueConstraint('tenant_id', 'project_name', name='uq_projects_tenant_name')
    )
    op.create_index(op.f('ix_projects_created_by'), 'projects', ['created_by'], unique=False)
    op.create_index('ix_projects_deactivated', 'projects', ['is_active'], unique=False, postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.create_index(op.f('ix_projects_id'), 'projects', ['id'], unique=False)
    op.create_index(op.f('ix_projects_project_name'), 'projects', ['project_name'], unique=False)
    op.create_index('ix_projects_tenant_created', 'projects', ['tenant_id', 'created_on'], unique=False)
    op.create_index(op.f('ix_projects_tenant_id'), 'projects', ['tenant_id'], unique=False)
    op.create_index('ix_projects_tenant_identity', 'projects', ['tenant_id', 'id'], unique=False)
    op.create_table('run_cache',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('run_json', sa.Text(), nullable=False),
    sa.Column('created_on', sa.String(), nullable=True),
    sa.Column('source', sa.String(), nullable=True),
    sa.Column('sbom_id', sa.Integer(), nullable=True),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_run_cache_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_run_cache'))
    )
    op.create_index(op.f('ix_run_cache_id'), 'run_cache', ['id'], unique=False)
    op.create_index(op.f('ix_run_cache_tenant_id'), 'run_cache', ['tenant_id'], unique=False)
    op.create_index('ix_run_cache_tenant_identity', 'run_cache', ['tenant_id', 'id'], unique=False)
    op.create_table('tenant_users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('role', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_tenant_users_tenant_id_tenants'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['iam_users.id'], name=op.f('fk_tenant_users_user_id_iam_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_tenant_users')),
    sa.UniqueConstraint('tenant_id', 'user_id', name='uq_tenant_users_tenant_user')
    )
    op.create_index(op.f('ix_tenant_users_tenant_id'), 'tenant_users', ['tenant_id'], unique=False)
    op.create_index('ix_tenant_users_tenant_status', 'tenant_users', ['tenant_id', 'status'], unique=False)
    op.create_index(op.f('ix_tenant_users_user_id'), 'tenant_users', ['user_id'], unique=False)
    op.create_table('sbom_source',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('sbom_name', sa.String(), nullable=False),
    sa.Column('sbom_data', sa.Text(), nullable=True),
    sa.Column('sbom_type', sa.Integer(), nullable=True),
    sa.Column('projectid', sa.Integer(), nullable=True),
    sa.Column('created_on', sa.String(), nullable=True),
    sa.Column('sbom_version', sa.String(), nullable=True),
    sa.Column('created_by', sa.String(), nullable=True),
    sa.Column('productver', sa.String(), nullable=True),
    sa.Column('modified_on', sa.String(), nullable=True),
    sa.Column('modified_by', sa.String(), nullable=True),
    sa.Column('parent_id', sa.Integer(), nullable=True),
    sa.Column('change_summary', sa.String(), nullable=True),
    sa.Column('completeness_score', sa.Float(), nullable=True),
    sa.Column('completeness_report', sa.JSON(), nullable=True),
    sa.Column('dedupe_report_json', sa.JSON(), nullable=True),
    sa.Column('product_name', sa.String(), nullable=True),
    sa.Column('description', sa.String(), nullable=True),
    sa.Column('status', sa.String(length=24), server_default='validated', nullable=False),
    sa.Column('failed_stage', sa.String(length=32), nullable=True),
    sa.Column('validation_errors', sa.JSON(), nullable=True),
    sa.Column('error_count', sa.Integer(), server_default='0', nullable=False),
    sa.Column('warning_count', sa.Integer(), server_default='0', nullable=False),
    sa.Column('validated_at', sa.String(), nullable=True),
    sa.Column('original_format', sa.String(length=32), nullable=True),
    sa.Column('current_format', sa.String(length=32), nullable=True),
    sa.Column('converted_from_format', sa.String(length=32), nullable=True),
    sa.Column('source_sbom_id', sa.Integer(), nullable=True),
    sa.Column('converted_sbom_id', sa.Integer(), nullable=True),
    sa.Column('conversion_status', sa.String(length=32), nullable=True),
    sa.Column('conversion_warnings_json', sa.JSON(), nullable=True),
    sa.Column('conversion_report_json', sa.JSON(), nullable=True),
    sa.Column('converted_at', sa.String(), nullable=True),
    sa.Column('converted_by', sa.String(), nullable=True),
    sa.Column('enrichment_status', sa.String(length=32), nullable=True),
    sa.Column('conversion_started_at', sa.String(), nullable=True),
    sa.Column('conversion_completed_at', sa.String(), nullable=True),
    sa.Column('enrichment_started_at', sa.String(), nullable=True),
    sa.Column('enrichment_completed_at', sa.String(), nullable=True),
    sa.Column('conversion_error', sa.Text(), nullable=True),
    sa.Column('enrichment_error', sa.Text(), nullable=True),
    sa.Column('component_extraction_status', sa.String(length=32), nullable=True),
    sa.Column('component_extraction_error', sa.Text(), nullable=True),
    sa.Column('component_extraction_attempted_at', sa.String(), nullable=True),
    sa.Column('component_extraction_completed_at', sa.String(), nullable=True),
    sa.Column('is_active', sa.Boolean(), server_default=sa.text('1'), nullable=False),
    sa.Column('deactivated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('deactivated_by', sa.String(length=128), nullable=True),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['converted_sbom_id'], ['sbom_source.id'], name=op.f('fk_sbom_source_converted_sbom_id_sbom_source')),
    sa.ForeignKeyConstraint(['parent_id'], ['sbom_source.id'], name=op.f('fk_sbom_source_parent_id_sbom_source')),
    sa.ForeignKeyConstraint(['projectid'], ['projects.id'], name=op.f('fk_sbom_source_projectid_projects')),
    sa.ForeignKeyConstraint(['sbom_type'], ['sbom_type.id'], name=op.f('fk_sbom_source_sbom_type_sbom_type')),
    sa.ForeignKeyConstraint(['source_sbom_id'], ['sbom_source.id'], name=op.f('fk_sbom_source_source_sbom_id_sbom_source')),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_sbom_source_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sbom_source')),
    sa.UniqueConstraint('tenant_id', 'sbom_name', 'sbom_version', name='uq_sbom_source_tenant_name_version')
    )
    op.create_index(op.f('ix_sbom_source_component_extraction_status'), 'sbom_source', ['component_extraction_status'], unique=False)
    op.create_index(op.f('ix_sbom_source_conversion_status'), 'sbom_source', ['conversion_status'], unique=False)
    op.create_index('ix_sbom_source_converted_from_format', 'sbom_source', ['converted_from_format'], unique=False)
    op.create_index(op.f('ix_sbom_source_converted_sbom_id'), 'sbom_source', ['converted_sbom_id'], unique=False)
    op.create_index(op.f('ix_sbom_source_created_by'), 'sbom_source', ['created_by'], unique=False)
    op.create_index('ix_sbom_source_deactivated', 'sbom_source', ['is_active'], unique=False, postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.create_index(op.f('ix_sbom_source_enrichment_status'), 'sbom_source', ['enrichment_status'], unique=False)
    op.create_index(op.f('ix_sbom_source_failed_stage'), 'sbom_source', ['failed_stage'], unique=False)
    op.create_index(op.f('ix_sbom_source_id'), 'sbom_source', ['id'], unique=False)
    op.create_index('ix_sbom_source_parent_id', 'sbom_source', ['parent_id'], unique=False)
    op.create_index(op.f('ix_sbom_source_sbom_name'), 'sbom_source', ['sbom_name'], unique=False)
    op.create_index('ix_sbom_source_sbom_type', 'sbom_source', ['sbom_type'], unique=False)
    op.create_index(op.f('ix_sbom_source_source_sbom_id'), 'sbom_source', ['source_sbom_id'], unique=False)
    op.create_index(op.f('ix_sbom_source_status'), 'sbom_source', ['status'], unique=False)
    op.create_index('ix_sbom_source_tenant_created', 'sbom_source', ['tenant_id', 'created_on'], unique=False)
    op.create_index(op.f('ix_sbom_source_tenant_id'), 'sbom_source', ['tenant_id'], unique=False)
    op.create_index('ix_sbom_source_tenant_identity', 'sbom_source', ['tenant_id', 'id'], unique=False)
    op.create_index('ix_sbom_source_tenant_project', 'sbom_source', ['tenant_id', 'projectid'], unique=False)
    op.create_table('vulnerability_remediation',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=False),
    sa.Column('vuln_id', sa.String(), nullable=False),
    sa.Column('component_name', sa.String(), nullable=False),
    sa.Column('component_version', sa.String(), nullable=False),
    sa.Column('fixed_version', sa.String(), nullable=True),
    sa.Column('status', sa.String(), nullable=False),
    sa.Column('owner', sa.String(), nullable=True),
    sa.Column('due_date', sa.String(), nullable=True),
    sa.Column('resolution_date', sa.String(), nullable=True),
    sa.Column('fix_notes', sa.Text(), nullable=True),
    sa.Column('created_on', sa.String(), nullable=False),
    sa.Column('updated_on', sa.String(), nullable=False),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_vulnerability_remediation_project_id_projects'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_vulnerability_remediation_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_vulnerability_remediation'))
    )
    op.create_index(op.f('ix_vulnerability_remediation_component_name'), 'vulnerability_remediation', ['component_name'], unique=False)
    op.create_index(op.f('ix_vulnerability_remediation_id'), 'vulnerability_remediation', ['id'], unique=False)
    op.create_index(op.f('ix_vulnerability_remediation_project_id'), 'vulnerability_remediation', ['project_id'], unique=False)
    op.create_index(op.f('ix_vulnerability_remediation_tenant_id'), 'vulnerability_remediation', ['tenant_id'], unique=False)
    op.create_index('ix_vulnerability_remediation_tenant_identity', 'vulnerability_remediation', ['tenant_id', 'id'], unique=False)
    op.create_index(op.f('ix_vulnerability_remediation_vuln_id'), 'vulnerability_remediation', ['vuln_id'], unique=False)
    op.create_table('analysis_run',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('sbom_id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=True),
    sa.Column('run_status', sa.String(), nullable=False),
    sa.Column('sbom_name', sa.String(), nullable=True),
    sa.Column('source', sa.String(), nullable=False),
    sa.Column('started_on', sa.String(), nullable=False),
    sa.Column('completed_on', sa.String(), nullable=False),
    sa.Column('duration_ms', sa.Integer(), nullable=False),
    sa.Column('total_components', sa.Integer(), nullable=False),
    sa.Column('components_with_cpe', sa.Integer(), nullable=False),
    sa.Column('total_findings', sa.Integer(), nullable=False),
    sa.Column('critical_count', sa.Integer(), nullable=False),
    sa.Column('high_count', sa.Integer(), nullable=False),
    sa.Column('medium_count', sa.Integer(), nullable=False),
    sa.Column('low_count', sa.Integer(), nullable=False),
    sa.Column('unknown_count', sa.Integer(), nullable=False),
    sa.Column('query_error_count', sa.Integer(), nullable=False),
    sa.Column('raw_report', sa.Text(), nullable=True),
    sa.Column('is_active', sa.Boolean(), server_default=sa.text('1'), nullable=False),
    sa.Column('deactivated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('deactivated_by', sa.String(length=128), nullable=True),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_analysis_run_project_id_projects')),
    sa.ForeignKeyConstraint(['sbom_id'], ['sbom_source.id'], name=op.f('fk_analysis_run_sbom_id_sbom_source')),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_analysis_run_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_analysis_run'))
    )
    op.create_index('ix_analysis_run_deactivated', 'analysis_run', ['is_active'], unique=False, postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.create_index(op.f('ix_analysis_run_id'), 'analysis_run', ['id'], unique=False)
    op.create_index(op.f('ix_analysis_run_project_id'), 'analysis_run', ['project_id'], unique=False)
    op.create_index(op.f('ix_analysis_run_run_status'), 'analysis_run', ['run_status'], unique=False)
    op.create_index(op.f('ix_analysis_run_sbom_id'), 'analysis_run', ['sbom_id'], unique=False)
    op.create_index(op.f('ix_analysis_run_tenant_id'), 'analysis_run', ['tenant_id'], unique=False)
    op.create_index('ix_analysis_run_tenant_identity', 'analysis_run', ['tenant_id', 'id'], unique=False)
    op.create_table('sbom_analysis_report',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('sbom_ref_id', sa.Integer(), nullable=True),
    sa.Column('sbom_result', sa.String(), nullable=True),
    sa.Column('project_id', sa.String(), nullable=True),
    sa.Column('created_on', sa.String(), nullable=True),
    sa.Column('analysis_details', sa.Text(), nullable=True),
    sa.Column('reference_source', sa.String(), nullable=True),
    sa.Column('sbom_analysis_level', sa.Integer(), nullable=True),
    sa.Column('is_active', sa.Boolean(), server_default=sa.text('1'), nullable=False),
    sa.Column('deactivated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('deactivated_by', sa.String(length=128), nullable=True),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['sbom_ref_id'], ['sbom_source.id'], name=op.f('fk_sbom_analysis_report_sbom_ref_id_sbom_source')),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_sbom_analysis_report_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sbom_analysis_report'))
    )
    op.create_index('ix_sbom_analysis_report_deactivated', 'sbom_analysis_report', ['is_active'], unique=False, postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.create_index(op.f('ix_sbom_analysis_report_id'), 'sbom_analysis_report', ['id'], unique=False)
    op.create_index(op.f('ix_sbom_analysis_report_tenant_id'), 'sbom_analysis_report', ['tenant_id'], unique=False)
    op.create_index('ix_sbom_analysis_report_tenant_identity', 'sbom_analysis_report', ['tenant_id', 'id'], unique=False)
    op.create_table('sbom_component',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('sbom_id', sa.Integer(), nullable=False),
    sa.Column('bom_ref', sa.String(), nullable=True),
    sa.Column('component_type', sa.String(), nullable=True),
    sa.Column('component_group', sa.String(), nullable=True),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('version', sa.String(), nullable=True),
    sa.Column('purl', sa.String(), nullable=True),
    sa.Column('cpe', sa.String(), nullable=True),
    sa.Column('cpe_source', sa.String(length=32), nullable=True),
    sa.Column('supplier', sa.String(), nullable=True),
    sa.Column('scope', sa.String(), nullable=True),
    sa.Column('created_on', sa.String(), nullable=True),
    sa.Column('ecosystem', sa.String(), nullable=True),
    sa.Column('original_name', sa.String(), nullable=True),
    sa.Column('normalized_name', sa.String(), nullable=True),
    sa.Column('original_version', sa.String(), nullable=True),
    sa.Column('normalized_version', sa.String(), nullable=True),
    sa.Column('normalized_ecosystem', sa.String(), nullable=True),
    sa.Column('original_purl', sa.String(), nullable=True),
    sa.Column('normalized_purl', sa.String(), nullable=True),
    sa.Column('purl_type', sa.String(), nullable=True),
    sa.Column('purl_namespace', sa.String(), nullable=True),
    sa.Column('purl_name', sa.String(), nullable=True),
    sa.Column('purl_version', sa.String(), nullable=True),
    sa.Column('purl_qualifiers_json', sa.JSON(), nullable=True),
    sa.Column('purl_subpath', sa.String(), nullable=True),
    sa.Column('normalized_cpes', sa.JSON(), nullable=True),
    sa.Column('primary_cpe', sa.String(), nullable=True),
    sa.Column('cpe_evidence_json', sa.JSON(), nullable=True),
    sa.Column('normalized_supplier', sa.String(), nullable=True),
    sa.Column('normalized_package_key', sa.String(), nullable=True),
    sa.Column('canonical_identity_confidence', sa.String(), nullable=True),
    sa.Column('license', sa.String(), nullable=True),
    sa.Column('hashes', sa.Text(), nullable=True),
    sa.Column('lifecycle_status', sa.String(), nullable=True),
    sa.Column('eos_date', sa.String(), nullable=True),
    sa.Column('eol_date', sa.String(), nullable=True),
    sa.Column('eof_date', sa.String(), nullable=True),
    sa.Column('is_deprecated', sa.Boolean(), nullable=True),
    sa.Column('deprecated', sa.Boolean(), nullable=True),
    sa.Column('unsupported', sa.Boolean(), nullable=True),
    sa.Column('maintenance_status', sa.String(), nullable=True),
    sa.Column('latest_version', sa.String(), nullable=True),
    sa.Column('latest_supported_version', sa.String(), nullable=True),
    sa.Column('recommended_version', sa.String(), nullable=True),
    sa.Column('lifecycle_recommendation', sa.Text(), nullable=True),
    sa.Column('lifecycle_source', sa.String(), nullable=True),
    sa.Column('lifecycle_source_url', sa.String(), nullable=True),
    sa.Column('lifecycle_confidence', sa.String(), nullable=True),
    sa.Column('lifecycle_checked_at', sa.String(), nullable=True),
    sa.Column('lifecycle_evidence_json', sa.JSON(), nullable=True),
    sa.Column('lifecycle_is_stale', sa.Boolean(), nullable=False),
    sa.Column('lifecycle_manual_override', sa.Boolean(), nullable=False),
    sa.Column('normalized_component_key', sa.String(), nullable=True),
    sa.Column('dedupe_canonical_id', sa.String(), nullable=True),
    sa.Column('dedupe_group_id', sa.String(), nullable=True),
    sa.Column('is_duplicate', sa.Boolean(), nullable=False),
    sa.Column('duplicate_of_component_id', sa.Integer(), nullable=True),
    sa.Column('dedupe_reason', sa.String(), nullable=True),
    sa.Column('dedupe_confidence', sa.String(), nullable=True),
    sa.Column('normalization_notes_json', sa.JSON(), nullable=True),
    sa.Column('dedupe_evidence_json', sa.JSON(), nullable=True),
    sa.Column('is_active', sa.Boolean(), server_default=sa.text('1'), nullable=False),
    sa.Column('deactivated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('deactivated_by', sa.String(length=128), nullable=True),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['duplicate_of_component_id'], ['sbom_component.id'], name=op.f('fk_sbom_component_duplicate_of_component_id_sbom_component'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['sbom_id'], ['sbom_source.id'], name=op.f('fk_sbom_component_sbom_id_sbom_source')),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_sbom_component_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sbom_component')),
    sa.UniqueConstraint('tenant_id', 'sbom_id', 'bom_ref', 'name', 'version', 'cpe', name='uq_sbom_component_fingerprint')
    )
    op.create_index('ix_sbom_component_bom_ref', 'sbom_component', ['bom_ref'], unique=False)
    op.create_index(op.f('ix_sbom_component_cpe'), 'sbom_component', ['cpe'], unique=False)
    op.create_index(op.f('ix_sbom_component_cpe_source'), 'sbom_component', ['cpe_source'], unique=False)
    op.create_index('ix_sbom_component_deactivated', 'sbom_component', ['is_active'], unique=False, postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.create_index(op.f('ix_sbom_component_dedupe_canonical_id'), 'sbom_component', ['dedupe_canonical_id'], unique=False)
    op.create_index(op.f('ix_sbom_component_dedupe_group_id'), 'sbom_component', ['dedupe_group_id'], unique=False)
    op.create_index('ix_sbom_component_duplicate_of_component_id', 'sbom_component', ['duplicate_of_component_id'], unique=False)
    op.create_index(op.f('ix_sbom_component_ecosystem'), 'sbom_component', ['ecosystem'], unique=False)
    op.create_index(op.f('ix_sbom_component_id'), 'sbom_component', ['id'], unique=False)
    op.create_index('ix_sbom_component_lifecycle', 'sbom_component', ['lifecycle_status', 'ecosystem'], unique=False)
    op.create_index(op.f('ix_sbom_component_lifecycle_checked_at'), 'sbom_component', ['lifecycle_checked_at'], unique=False)
    op.create_index(op.f('ix_sbom_component_name'), 'sbom_component', ['name'], unique=False)
    op.create_index(op.f('ix_sbom_component_normalized_component_key'), 'sbom_component', ['normalized_component_key'], unique=False)
    op.create_index(op.f('ix_sbom_component_normalized_ecosystem'), 'sbom_component', ['normalized_ecosystem'], unique=False)
    op.create_index('ix_sbom_component_normalized_identity', 'sbom_component', ['normalized_ecosystem', 'normalized_name', 'normalized_version'], unique=False)
    op.create_index(op.f('ix_sbom_component_normalized_name'), 'sbom_component', ['normalized_name'], unique=False)
    op.create_index(op.f('ix_sbom_component_normalized_package_key'), 'sbom_component', ['normalized_package_key'], unique=False)
    op.create_index(op.f('ix_sbom_component_normalized_purl'), 'sbom_component', ['normalized_purl'], unique=False)
    op.create_index(op.f('ix_sbom_component_normalized_version'), 'sbom_component', ['normalized_version'], unique=False)
    op.create_index(op.f('ix_sbom_component_primary_cpe'), 'sbom_component', ['primary_cpe'], unique=False)
    op.create_index(op.f('ix_sbom_component_sbom_id'), 'sbom_component', ['sbom_id'], unique=False)
    op.create_index('ix_sbom_component_sbom_is_duplicate', 'sbom_component', ['sbom_id', 'is_duplicate'], unique=False)
    op.create_index('ix_sbom_component_sbom_name', 'sbom_component', ['sbom_id', 'name'], unique=False)
    op.create_index('ix_sbom_component_sbom_normalized_key', 'sbom_component', ['sbom_id', 'normalized_component_key'], unique=False)
    op.create_index(op.f('ix_sbom_component_tenant_id'), 'sbom_component', ['tenant_id'], unique=False)
    op.create_index('ix_sbom_component_tenant_identity', 'sbom_component', ['tenant_id', 'id'], unique=False)
    op.create_index(op.f('ix_sbom_component_version'), 'sbom_component', ['version'], unique=False)
    op.create_table('sbom_validation_sessions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=True),
    sa.Column('user_id', sa.String(length=128), nullable=True),
    sa.Column('original_filename', sa.String(length=255), nullable=True),
    sa.Column('sbom_name', sa.String(length=255), nullable=True),
    sa.Column('sbom_type', sa.Integer(), nullable=True),
    sa.Column('content_type', sa.String(length=255), nullable=True),
    sa.Column('file_size_bytes', sa.Integer(), nullable=True),
    sa.Column('sha256', sa.String(length=64), nullable=True),
    sa.Column('original_size_bytes', sa.Integer(), nullable=True),
    sa.Column('original_sha256', sa.String(length=64), nullable=True),
    sa.Column('stored_size_bytes', sa.Integer(), nullable=True),
    sa.Column('stored_sha256', sa.String(length=64), nullable=True),
    sa.Column('storage_backend', sa.String(length=32), nullable=True),
    sa.Column('detected_format', sa.String(length=64), nullable=True),
    sa.Column('detected_version', sa.String(length=64), nullable=True),
    sa.Column('detection_confidence', sa.Float(), nullable=True),
    sa.Column('detection_evidence_json', sa.JSON(), nullable=True),
    sa.Column('raw_content_text', sa.Text(), nullable=True),
    sa.Column('raw_content_blob', sa.LargeBinary(), nullable=True),
    sa.Column('raw_storage_path', sa.String(length=1024), nullable=True),
    sa.Column('sanitized_content', sa.Text(), nullable=True),
    sa.Column('current_content', sa.Text(), nullable=True),
    sa.Column('repair_content_text', sa.Text(), nullable=True),
    sa.Column('repair_content_blob', sa.LargeBinary(), nullable=True),
    sa.Column('repair_storage_path', sa.String(length=1024), nullable=True),
    sa.Column('validation_status', sa.String(length=32), server_default='failed', nullable=False),
    sa.Column('validation_errors_json', sa.JSON(), nullable=True),
    sa.Column('stage_results_json', sa.JSON(), nullable=True),
    sa.Column('latest_error_report_json', sa.JSON(), nullable=True),
    sa.Column('total_lines', sa.Integer(), nullable=True),
    sa.Column('is_large_file', sa.Boolean(), server_default=sa.text('0'), nullable=False),
    sa.Column('full_editor_allowed', sa.Boolean(), server_default=sa.text('1'), nullable=False),
    sa.Column('can_edit', sa.Boolean(), server_default=sa.text('1'), nullable=False),
    sa.Column('can_ai_fix', sa.Boolean(), server_default=sa.text('1'), nullable=False),
    sa.Column('security_blocked_reason', sa.Text(), nullable=True),
    sa.Column('content_sha256', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.String(), nullable=False),
    sa.Column('updated_at', sa.String(), nullable=False),
    sa.Column('expires_at', sa.String(), nullable=False),
    sa.Column('imported_sbom_id', sa.Integer(), nullable=True),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['imported_sbom_id'], ['sbom_source.id'], name=op.f('fk_sbom_validation_sessions_imported_sbom_id_sbom_source')),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_sbom_validation_sessions_project_id_projects')),
    sa.ForeignKeyConstraint(['sbom_type'], ['sbom_type.id'], name=op.f('fk_sbom_validation_sessions_sbom_type_sbom_type')),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_sbom_validation_sessions_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sbom_validation_sessions'))
    )
    op.create_index(op.f('ix_sbom_validation_sessions_content_sha256'), 'sbom_validation_sessions', ['content_sha256'], unique=False)
    op.create_index(op.f('ix_sbom_validation_sessions_created_at'), 'sbom_validation_sessions', ['created_at'], unique=False)
    op.create_index(op.f('ix_sbom_validation_sessions_expires_at'), 'sbom_validation_sessions', ['expires_at'], unique=False)
    op.create_index(op.f('ix_sbom_validation_sessions_id'), 'sbom_validation_sessions', ['id'], unique=False)
    op.create_index(op.f('ix_sbom_validation_sessions_imported_sbom_id'), 'sbom_validation_sessions', ['imported_sbom_id'], unique=False)
    op.create_index(op.f('ix_sbom_validation_sessions_original_sha256'), 'sbom_validation_sessions', ['original_sha256'], unique=False)
    op.create_index(op.f('ix_sbom_validation_sessions_project_id'), 'sbom_validation_sessions', ['project_id'], unique=False)
    op.create_index(op.f('ix_sbom_validation_sessions_sha256'), 'sbom_validation_sessions', ['sha256'], unique=False)
    op.create_index(op.f('ix_sbom_validation_sessions_stored_sha256'), 'sbom_validation_sessions', ['stored_sha256'], unique=False)
    op.create_index(op.f('ix_sbom_validation_sessions_tenant_id'), 'sbom_validation_sessions', ['tenant_id'], unique=False)
    op.create_index('ix_sbom_validation_sessions_tenant_identity', 'sbom_validation_sessions', ['tenant_id', 'id'], unique=False)
    op.create_index(op.f('ix_sbom_validation_sessions_user_id'), 'sbom_validation_sessions', ['user_id'], unique=False)
    op.create_index(op.f('ix_sbom_validation_sessions_validation_status'), 'sbom_validation_sessions', ['validation_status'], unique=False)
    op.create_table('vex_documents',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('sbom_id', sa.Integer(), nullable=False),
    sa.Column('source_type', sa.String(), nullable=False),
    sa.Column('format', sa.String(), nullable=True),
    sa.Column('author', sa.String(), nullable=True),
    sa.Column('source_url', sa.String(), nullable=True),
    sa.Column('discovery_evidence_json', sa.JSON(), nullable=True),
    sa.Column('last_refresh_status', sa.String(), nullable=True),
    sa.Column('provider_errors_json', sa.JSON(), nullable=True),
    sa.Column('uploaded_by', sa.String(), nullable=True),
    sa.Column('uploaded_at', sa.String(), nullable=False),
    sa.Column('raw_document_json', sa.JSON(), nullable=True),
    sa.Column('validation_status', sa.String(), nullable=False),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['sbom_id'], ['sbom_source.id'], name=op.f('fk_vex_documents_sbom_id_sbom_source'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_vex_documents_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_vex_documents'))
    )
    op.create_index(op.f('ix_vex_documents_format'), 'vex_documents', ['format'], unique=False)
    op.create_index(op.f('ix_vex_documents_id'), 'vex_documents', ['id'], unique=False)
    op.create_index(op.f('ix_vex_documents_sbom_id'), 'vex_documents', ['sbom_id'], unique=False)
    op.create_index(op.f('ix_vex_documents_source_type'), 'vex_documents', ['source_type'], unique=False)
    op.create_index(op.f('ix_vex_documents_tenant_id'), 'vex_documents', ['tenant_id'], unique=False)
    op.create_index('ix_vex_documents_tenant_identity', 'vex_documents', ['tenant_id', 'id'], unique=False)
    op.create_index(op.f('ix_vex_documents_uploaded_at'), 'vex_documents', ['uploaded_at'], unique=False)
    op.create_index(op.f('ix_vex_documents_uploaded_by'), 'vex_documents', ['uploaded_by'], unique=False)
    op.create_index(op.f('ix_vex_documents_validation_status'), 'vex_documents', ['validation_status'], unique=False)
    op.create_table('vulnerability_remediation_audit',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('remediation_id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=False),
    sa.Column('vuln_id', sa.String(), nullable=False),
    sa.Column('component_name', sa.String(), nullable=False),
    sa.Column('component_version', sa.String(), nullable=False),
    sa.Column('old_status', sa.String(), nullable=True),
    sa.Column('new_status', sa.String(), nullable=False),
    sa.Column('changed_by', sa.String(length=128), nullable=True),
    sa.Column('changed_at', sa.String(), nullable=False),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_vulnerability_remediation_audit_project_id_projects'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['remediation_id'], ['vulnerability_remediation.id'], name=op.f('fk_vulnerability_remediation_audit_remediation_id_vulnerability_remediation'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_vulnerability_remediation_audit_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_vulnerability_remediation_audit'))
    )
    op.create_index(op.f('ix_vulnerability_remediation_audit_changed_at'), 'vulnerability_remediation_audit', ['changed_at'], unique=False)
    op.create_index(op.f('ix_vulnerability_remediation_audit_component_name'), 'vulnerability_remediation_audit', ['component_name'], unique=False)
    op.create_index(op.f('ix_vulnerability_remediation_audit_id'), 'vulnerability_remediation_audit', ['id'], unique=False)
    op.create_index(op.f('ix_vulnerability_remediation_audit_project_id'), 'vulnerability_remediation_audit', ['project_id'], unique=False)
    op.create_index(op.f('ix_vulnerability_remediation_audit_remediation_id'), 'vulnerability_remediation_audit', ['remediation_id'], unique=False)
    op.create_index(op.f('ix_vulnerability_remediation_audit_tenant_id'), 'vulnerability_remediation_audit', ['tenant_id'], unique=False)
    op.create_index('ix_vulnerability_remediation_audit_tenant_identity', 'vulnerability_remediation_audit', ['tenant_id', 'id'], unique=False)
    op.create_index(op.f('ix_vulnerability_remediation_audit_vuln_id'), 'vulnerability_remediation_audit', ['vuln_id'], unique=False)
    op.create_table('ai_fix_batch',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('run_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.Column('scope_label', sa.String(length=120), nullable=True),
    sa.Column('scope_json', sa.JSON(), nullable=True),
    sa.Column('finding_ids_json', sa.JSON(), nullable=False),
    sa.Column('provider_name', sa.String(length=64), nullable=False),
    sa.Column('total', sa.Integer(), nullable=False),
    sa.Column('cached_count', sa.Integer(), nullable=False),
    sa.Column('generated_count', sa.Integer(), nullable=False),
    sa.Column('failed_count', sa.Integer(), nullable=False),
    sa.Column('cost_usd', sa.Float(), nullable=False),
    sa.Column('started_at', sa.String(), nullable=True),
    sa.Column('completed_at', sa.String(), nullable=True),
    sa.Column('created_at', sa.String(), nullable=False),
    sa.Column('last_error', sa.String(length=240), nullable=True),
    sa.Column('is_active', sa.Boolean(), server_default=sa.text('1'), nullable=False),
    sa.Column('deactivated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('deactivated_by', sa.String(length=128), nullable=True),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['run_id'], ['analysis_run.id'], name=op.f('fk_ai_fix_batch_run_id_analysis_run'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_ai_fix_batch_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_ai_fix_batch'))
    )
    op.create_index('ix_ai_fix_batch_created_at', 'ai_fix_batch', ['created_at'], unique=False)
    op.create_index('ix_ai_fix_batch_deactivated', 'ai_fix_batch', ['is_active'], unique=False, postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.create_index('ix_ai_fix_batch_run_status', 'ai_fix_batch', ['run_id', 'status'], unique=False)
    op.create_index(op.f('ix_ai_fix_batch_tenant_id'), 'ai_fix_batch', ['tenant_id'], unique=False)
    op.create_index('ix_ai_fix_batch_tenant_identity', 'ai_fix_batch', ['tenant_id', 'id'], unique=False)
    op.create_table('analysis_finding',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('analysis_run_id', sa.Integer(), nullable=False),
    sa.Column('component_id', sa.Integer(), nullable=True),
    sa.Column('vuln_id', sa.String(), nullable=False),
    sa.Column('source', sa.String(), nullable=True),
    sa.Column('title', sa.String(), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('severity', sa.String(), nullable=True),
    sa.Column('score', sa.Float(), nullable=True),
    sa.Column('vector', sa.String(), nullable=True),
    sa.Column('published_on', sa.String(), nullable=True),
    sa.Column('reference_url', sa.String(), nullable=True),
    sa.Column('cwe', sa.Text(), nullable=True),
    sa.Column('cpe', sa.String(), nullable=True),
    sa.Column('component_name', sa.String(), nullable=True),
    sa.Column('component_version', sa.String(), nullable=True),
    sa.Column('fixed_versions', sa.Text(), nullable=True),
    sa.Column('attack_vector', sa.String(), nullable=True),
    sa.Column('cvss_version', sa.String(), nullable=True),
    sa.Column('aliases', sa.Text(), nullable=True),
    sa.Column('match_reason', sa.String(length=32), nullable=True),
    sa.Column('matched_range', sa.String(length=128), nullable=True),
    sa.Column('match_confidence', sa.Float(), nullable=True),
    sa.Column('match_strategy', sa.String(length=32), nullable=True),
    sa.Column('is_active', sa.Boolean(), server_default=sa.text('1'), nullable=False),
    sa.Column('deactivated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('deactivated_by', sa.String(length=128), nullable=True),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['analysis_run_id'], ['analysis_run.id'], name=op.f('fk_analysis_finding_analysis_run_id_analysis_run')),
    sa.ForeignKeyConstraint(['component_id'], ['sbom_component.id'], name=op.f('fk_analysis_finding_component_id_sbom_component')),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_analysis_finding_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_analysis_finding')),
    sa.UniqueConstraint('analysis_run_id', 'vuln_id', 'cpe', name='uq_analysis_finding_run_vuln_cpe')
    )
    op.create_index(op.f('ix_analysis_finding_analysis_run_id'), 'analysis_finding', ['analysis_run_id'], unique=False)
    op.create_index(op.f('ix_analysis_finding_component_id'), 'analysis_finding', ['component_id'], unique=False)
    op.create_index(op.f('ix_analysis_finding_cpe'), 'analysis_finding', ['cpe'], unique=False)
    op.create_index('ix_analysis_finding_deactivated', 'analysis_finding', ['is_active'], unique=False, postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.create_index(op.f('ix_analysis_finding_id'), 'analysis_finding', ['id'], unique=False)
    op.create_index(op.f('ix_analysis_finding_match_reason'), 'analysis_finding', ['match_reason'], unique=False)
    op.create_index(op.f('ix_analysis_finding_match_strategy'), 'analysis_finding', ['match_strategy'], unique=False)
    op.create_index('ix_analysis_finding_run_severity', 'analysis_finding', ['analysis_run_id', 'severity'], unique=False)
    op.create_index(op.f('ix_analysis_finding_severity'), 'analysis_finding', ['severity'], unique=False)
    op.create_index(op.f('ix_analysis_finding_tenant_id'), 'analysis_finding', ['tenant_id'], unique=False)
    op.create_index('ix_analysis_finding_tenant_identity', 'analysis_finding', ['tenant_id', 'id'], unique=False)
    op.create_index(op.f('ix_analysis_finding_vuln_id'), 'analysis_finding', ['vuln_id'], unique=False)
    op.create_table('analysis_schedule',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('scope', sa.String(length=16), nullable=False),
    sa.Column('project_id', sa.Integer(), nullable=True),
    sa.Column('sbom_id', sa.Integer(), nullable=True),
    sa.Column('cadence', sa.String(length=16), nullable=False),
    sa.Column('cron_expression', sa.String(length=128), nullable=True),
    sa.Column('day_of_week', sa.Integer(), nullable=True),
    sa.Column('day_of_month', sa.Integer(), nullable=True),
    sa.Column('hour_utc', sa.Integer(), nullable=False),
    sa.Column('timezone', sa.String(length=64), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('next_run_at', sa.String(), nullable=True),
    sa.Column('last_run_at', sa.String(), nullable=True),
    sa.Column('last_run_status', sa.String(length=16), nullable=True),
    sa.Column('last_run_id', sa.Integer(), nullable=True),
    sa.Column('consecutive_failures', sa.Integer(), nullable=False),
    sa.Column('min_gap_minutes', sa.Integer(), nullable=False),
    sa.Column('created_on', sa.String(), nullable=True),
    sa.Column('created_by', sa.String(), nullable=True),
    sa.Column('modified_on', sa.String(), nullable=True),
    sa.Column('modified_by', sa.String(), nullable=True),
    sa.Column('is_active', sa.Boolean(), server_default=sa.text('1'), nullable=False),
    sa.Column('deactivated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('deactivated_by', sa.String(length=128), nullable=True),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.CheckConstraint("(scope = 'PROJECT' AND project_id IS NOT NULL AND sbom_id IS NULL) OR (scope = 'SBOM' AND sbom_id IS NOT NULL AND project_id IS NULL)", name=op.f('ck_analysis_schedule_ck_analysis_schedule_target')),
    sa.CheckConstraint("cadence IN ('DAILY','WEEKLY','BIWEEKLY','MONTHLY','QUARTERLY','CUSTOM')", name=op.f('ck_analysis_schedule_ck_analysis_schedule_cadence')),
    sa.CheckConstraint("scope IN ('PROJECT','SBOM')", name=op.f('ck_analysis_schedule_ck_analysis_schedule_scope')),
    sa.CheckConstraint('day_of_month IS NULL OR day_of_month BETWEEN 1 AND 28', name=op.f('ck_analysis_schedule_ck_analysis_schedule_dom_range')),
    sa.CheckConstraint('day_of_week IS NULL OR day_of_week BETWEEN 0 AND 6', name=op.f('ck_analysis_schedule_ck_analysis_schedule_dow_range')),
    sa.CheckConstraint('hour_utc BETWEEN 0 AND 23', name=op.f('ck_analysis_schedule_ck_analysis_schedule_hour_range')),
    sa.ForeignKeyConstraint(['last_run_id'], ['analysis_run.id'], name=op.f('fk_analysis_schedule_last_run_id_analysis_run'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_analysis_schedule_project_id_projects'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['sbom_id'], ['sbom_source.id'], name=op.f('fk_analysis_schedule_sbom_id_sbom_source'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_analysis_schedule_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_analysis_schedule'))
    )
    op.create_index('ix_analysis_schedule_deactivated', 'analysis_schedule', ['is_active'], unique=False, postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.create_index('ix_analysis_schedule_due', 'analysis_schedule', ['enabled', 'next_run_at'], unique=False)
    op.create_index(op.f('ix_analysis_schedule_id'), 'analysis_schedule', ['id'], unique=False)
    op.create_index(op.f('ix_analysis_schedule_next_run_at'), 'analysis_schedule', ['next_run_at'], unique=False)
    op.create_index(op.f('ix_analysis_schedule_project_id'), 'analysis_schedule', ['project_id'], unique=False)
    op.create_index(op.f('ix_analysis_schedule_sbom_id'), 'analysis_schedule', ['sbom_id'], unique=False)
    op.create_index(op.f('ix_analysis_schedule_tenant_id'), 'analysis_schedule', ['tenant_id'], unique=False)
    op.create_index('ix_analysis_schedule_tenant_identity', 'analysis_schedule', ['tenant_id', 'id'], unique=False)
    op.create_table('component_lifecycle_override_audit',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('component_id', sa.Integer(), nullable=False),
    sa.Column('old_value_json', sa.JSON(), nullable=True),
    sa.Column('new_value_json', sa.JSON(), nullable=True),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('evidence_url', sa.String(), nullable=True),
    sa.Column('changed_by', sa.String(), nullable=True),
    sa.Column('changed_at', sa.String(), nullable=False),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['component_id'], ['sbom_component.id'], name=op.f('fk_component_lifecycle_override_audit_component_id_sbom_component'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_component_lifecycle_override_audit_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_component_lifecycle_override_audit'))
    )
    op.create_index(op.f('ix_component_lifecycle_override_audit_changed_at'), 'component_lifecycle_override_audit', ['changed_at'], unique=False)
    op.create_index(op.f('ix_component_lifecycle_override_audit_changed_by'), 'component_lifecycle_override_audit', ['changed_by'], unique=False)
    op.create_index(op.f('ix_component_lifecycle_override_audit_component_id'), 'component_lifecycle_override_audit', ['component_id'], unique=False)
    op.create_index(op.f('ix_component_lifecycle_override_audit_id'), 'component_lifecycle_override_audit', ['id'], unique=False)
    op.create_index(op.f('ix_component_lifecycle_override_audit_tenant_id'), 'component_lifecycle_override_audit', ['tenant_id'], unique=False)
    op.create_index('ix_component_lifecycle_override_audit_tenant_identity', 'component_lifecycle_override_audit', ['tenant_id', 'id'], unique=False)
    op.create_table('sbom_validation_session_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('session_id', sa.String(length=36), nullable=False),
    sa.Column('event_type', sa.String(length=64), nullable=False),
    sa.Column('actor_user_id', sa.String(length=128), nullable=True),
    sa.Column('timestamp', sa.String(), nullable=False),
    sa.Column('summary', sa.Text(), nullable=True),
    sa.Column('before_hash', sa.String(length=64), nullable=True),
    sa.Column('after_hash', sa.String(length=64), nullable=True),
    sa.Column('metadata_json', sa.JSON(), nullable=True),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['session_id'], ['sbom_validation_sessions.id'], name=op.f('fk_sbom_validation_session_events_session_id_sbom_validation_sessions'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_sbom_validation_session_events_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sbom_validation_session_events'))
    )
    op.create_index(op.f('ix_sbom_validation_session_events_actor_user_id'), 'sbom_validation_session_events', ['actor_user_id'], unique=False)
    op.create_index(op.f('ix_sbom_validation_session_events_event_type'), 'sbom_validation_session_events', ['event_type'], unique=False)
    op.create_index(op.f('ix_sbom_validation_session_events_id'), 'sbom_validation_session_events', ['id'], unique=False)
    op.create_index(op.f('ix_sbom_validation_session_events_session_id'), 'sbom_validation_session_events', ['session_id'], unique=False)
    op.create_index(op.f('ix_sbom_validation_session_events_tenant_id'), 'sbom_validation_session_events', ['tenant_id'], unique=False)
    op.create_index('ix_sbom_validation_session_events_tenant_identity', 'sbom_validation_session_events', ['tenant_id', 'id'], unique=False)
    op.create_index(op.f('ix_sbom_validation_session_events_timestamp'), 'sbom_validation_session_events', ['timestamp'], unique=False)
    op.create_table('vex_override_audit',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('component_id', sa.Integer(), nullable=False),
    sa.Column('vulnerability_id', sa.String(), nullable=False),
    sa.Column('old_value_json', sa.JSON(), nullable=True),
    sa.Column('new_value_json', sa.JSON(), nullable=True),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('evidence_url', sa.String(), nullable=True),
    sa.Column('changed_by', sa.String(), nullable=True),
    sa.Column('changed_at', sa.String(), nullable=False),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['component_id'], ['sbom_component.id'], name=op.f('fk_vex_override_audit_component_id_sbom_component'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_vex_override_audit_tenant_id_tenants')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_vex_override_audit'))
    )
    op.create_index(op.f('ix_vex_override_audit_changed_at'), 'vex_override_audit', ['changed_at'], unique=False)
    op.create_index(op.f('ix_vex_override_audit_changed_by'), 'vex_override_audit', ['changed_by'], unique=False)
    op.create_index(op.f('ix_vex_override_audit_component_id'), 'vex_override_audit', ['component_id'], unique=False)
    op.create_index(op.f('ix_vex_override_audit_id'), 'vex_override_audit', ['id'], unique=False)
    op.create_index(op.f('ix_vex_override_audit_tenant_id'), 'vex_override_audit', ['tenant_id'], unique=False)
    op.create_index('ix_vex_override_audit_tenant_identity', 'vex_override_audit', ['tenant_id', 'id'], unique=False)
    op.create_index(op.f('ix_vex_override_audit_vulnerability_id'), 'vex_override_audit', ['vulnerability_id'], unique=False)
    op.create_table('vex_statements',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('vex_document_id', sa.Integer(), nullable=True),
    sa.Column('sbom_id', sa.Integer(), nullable=False),
    sa.Column('component_id', sa.Integer(), nullable=True),
    sa.Column('vulnerability_id', sa.String(), nullable=False),
    sa.Column('cve_id', sa.String(), nullable=True),
    sa.Column('status', sa.String(), nullable=False),
    sa.Column('justification', sa.Text(), nullable=True),
    sa.Column('impact_statement', sa.Text(), nullable=True),
    sa.Column('action_statement', sa.Text(), nullable=True),
    sa.Column('fixed_version', sa.String(), nullable=True),
    sa.Column('mitigation', sa.Text(), nullable=True),
    sa.Column('source_name', sa.String(), nullable=True),
    sa.Column('source_url', sa.String(), nullable=True),
    sa.Column('confidence', sa.String(), nullable=True),
    sa.Column('evidence_json', sa.JSON(), nullable=True),
    sa.Column('created_at', sa.String(), nullable=False),
    sa.Column('tenant_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['component_id'], ['sbom_component.id'], name=op.f('fk_vex_statements_component_id_sbom_component'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['sbom_id'], ['sbom_source.id'], name=op.f('fk_vex_statements_sbom_id_sbom_source'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], name=op.f('fk_vex_statements_tenant_id_tenants')),
    sa.ForeignKeyConstraint(['vex_document_id'], ['vex_documents.id'], name=op.f('fk_vex_statements_vex_document_id_vex_documents'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_vex_statements'))
    )
    op.create_index('ix_vex_statement_component_vuln', 'vex_statements', ['component_id', 'vulnerability_id'], unique=False)
    op.create_index('ix_vex_statement_sbom_status', 'vex_statements', ['sbom_id', 'status'], unique=False)
    op.create_index(op.f('ix_vex_statements_component_id'), 'vex_statements', ['component_id'], unique=False)
    op.create_index(op.f('ix_vex_statements_created_at'), 'vex_statements', ['created_at'], unique=False)
    op.create_index(op.f('ix_vex_statements_cve_id'), 'vex_statements', ['cve_id'], unique=False)
    op.create_index(op.f('ix_vex_statements_id'), 'vex_statements', ['id'], unique=False)
    op.create_index(op.f('ix_vex_statements_sbom_id'), 'vex_statements', ['sbom_id'], unique=False)
    op.create_index(op.f('ix_vex_statements_status'), 'vex_statements', ['status'], unique=False)
    op.create_index(op.f('ix_vex_statements_tenant_id'), 'vex_statements', ['tenant_id'], unique=False)
    op.create_index('ix_vex_statements_tenant_identity', 'vex_statements', ['tenant_id', 'id'], unique=False)
    op.create_index(op.f('ix_vex_statements_vex_document_id'), 'vex_statements', ['vex_document_id'], unique=False)
    op.create_index(op.f('ix_vex_statements_vulnerability_id'), 'vex_statements', ['vulnerability_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_vex_statements_vulnerability_id'), table_name='vex_statements')
    op.drop_index(op.f('ix_vex_statements_vex_document_id'), table_name='vex_statements')
    op.drop_index('ix_vex_statements_tenant_identity', table_name='vex_statements')
    op.drop_index(op.f('ix_vex_statements_tenant_id'), table_name='vex_statements')
    op.drop_index(op.f('ix_vex_statements_status'), table_name='vex_statements')
    op.drop_index(op.f('ix_vex_statements_sbom_id'), table_name='vex_statements')
    op.drop_index(op.f('ix_vex_statements_id'), table_name='vex_statements')
    op.drop_index(op.f('ix_vex_statements_cve_id'), table_name='vex_statements')
    op.drop_index(op.f('ix_vex_statements_created_at'), table_name='vex_statements')
    op.drop_index(op.f('ix_vex_statements_component_id'), table_name='vex_statements')
    op.drop_index('ix_vex_statement_sbom_status', table_name='vex_statements')
    op.drop_index('ix_vex_statement_component_vuln', table_name='vex_statements')
    op.drop_table('vex_statements')
    op.drop_index(op.f('ix_vex_override_audit_vulnerability_id'), table_name='vex_override_audit')
    op.drop_index('ix_vex_override_audit_tenant_identity', table_name='vex_override_audit')
    op.drop_index(op.f('ix_vex_override_audit_tenant_id'), table_name='vex_override_audit')
    op.drop_index(op.f('ix_vex_override_audit_id'), table_name='vex_override_audit')
    op.drop_index(op.f('ix_vex_override_audit_component_id'), table_name='vex_override_audit')
    op.drop_index(op.f('ix_vex_override_audit_changed_by'), table_name='vex_override_audit')
    op.drop_index(op.f('ix_vex_override_audit_changed_at'), table_name='vex_override_audit')
    op.drop_table('vex_override_audit')
    op.drop_index(op.f('ix_sbom_validation_session_events_timestamp'), table_name='sbom_validation_session_events')
    op.drop_index('ix_sbom_validation_session_events_tenant_identity', table_name='sbom_validation_session_events')
    op.drop_index(op.f('ix_sbom_validation_session_events_tenant_id'), table_name='sbom_validation_session_events')
    op.drop_index(op.f('ix_sbom_validation_session_events_session_id'), table_name='sbom_validation_session_events')
    op.drop_index(op.f('ix_sbom_validation_session_events_id'), table_name='sbom_validation_session_events')
    op.drop_index(op.f('ix_sbom_validation_session_events_event_type'), table_name='sbom_validation_session_events')
    op.drop_index(op.f('ix_sbom_validation_session_events_actor_user_id'), table_name='sbom_validation_session_events')
    op.drop_table('sbom_validation_session_events')
    op.drop_index('ix_component_lifecycle_override_audit_tenant_identity', table_name='component_lifecycle_override_audit')
    op.drop_index(op.f('ix_component_lifecycle_override_audit_tenant_id'), table_name='component_lifecycle_override_audit')
    op.drop_index(op.f('ix_component_lifecycle_override_audit_id'), table_name='component_lifecycle_override_audit')
    op.drop_index(op.f('ix_component_lifecycle_override_audit_component_id'), table_name='component_lifecycle_override_audit')
    op.drop_index(op.f('ix_component_lifecycle_override_audit_changed_by'), table_name='component_lifecycle_override_audit')
    op.drop_index(op.f('ix_component_lifecycle_override_audit_changed_at'), table_name='component_lifecycle_override_audit')
    op.drop_table('component_lifecycle_override_audit')
    op.drop_index('ix_analysis_schedule_tenant_identity', table_name='analysis_schedule')
    op.drop_index(op.f('ix_analysis_schedule_tenant_id'), table_name='analysis_schedule')
    op.drop_index(op.f('ix_analysis_schedule_sbom_id'), table_name='analysis_schedule')
    op.drop_index(op.f('ix_analysis_schedule_project_id'), table_name='analysis_schedule')
    op.drop_index(op.f('ix_analysis_schedule_next_run_at'), table_name='analysis_schedule')
    op.drop_index(op.f('ix_analysis_schedule_id'), table_name='analysis_schedule')
    op.drop_index('ix_analysis_schedule_due', table_name='analysis_schedule')
    op.drop_index('ix_analysis_schedule_deactivated', table_name='analysis_schedule', postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.drop_table('analysis_schedule')
    op.drop_index(op.f('ix_analysis_finding_vuln_id'), table_name='analysis_finding')
    op.drop_index('ix_analysis_finding_tenant_identity', table_name='analysis_finding')
    op.drop_index(op.f('ix_analysis_finding_tenant_id'), table_name='analysis_finding')
    op.drop_index(op.f('ix_analysis_finding_severity'), table_name='analysis_finding')
    op.drop_index('ix_analysis_finding_run_severity', table_name='analysis_finding')
    op.drop_index(op.f('ix_analysis_finding_match_strategy'), table_name='analysis_finding')
    op.drop_index(op.f('ix_analysis_finding_match_reason'), table_name='analysis_finding')
    op.drop_index(op.f('ix_analysis_finding_id'), table_name='analysis_finding')
    op.drop_index('ix_analysis_finding_deactivated', table_name='analysis_finding', postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.drop_index(op.f('ix_analysis_finding_cpe'), table_name='analysis_finding')
    op.drop_index(op.f('ix_analysis_finding_component_id'), table_name='analysis_finding')
    op.drop_index(op.f('ix_analysis_finding_analysis_run_id'), table_name='analysis_finding')
    op.drop_table('analysis_finding')
    op.drop_index('ix_ai_fix_batch_tenant_identity', table_name='ai_fix_batch')
    op.drop_index(op.f('ix_ai_fix_batch_tenant_id'), table_name='ai_fix_batch')
    op.drop_index('ix_ai_fix_batch_run_status', table_name='ai_fix_batch')
    op.drop_index('ix_ai_fix_batch_deactivated', table_name='ai_fix_batch', postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.drop_index('ix_ai_fix_batch_created_at', table_name='ai_fix_batch')
    op.drop_table('ai_fix_batch')
    op.drop_index(op.f('ix_vulnerability_remediation_audit_vuln_id'), table_name='vulnerability_remediation_audit')
    op.drop_index('ix_vulnerability_remediation_audit_tenant_identity', table_name='vulnerability_remediation_audit')
    op.drop_index(op.f('ix_vulnerability_remediation_audit_tenant_id'), table_name='vulnerability_remediation_audit')
    op.drop_index(op.f('ix_vulnerability_remediation_audit_remediation_id'), table_name='vulnerability_remediation_audit')
    op.drop_index(op.f('ix_vulnerability_remediation_audit_project_id'), table_name='vulnerability_remediation_audit')
    op.drop_index(op.f('ix_vulnerability_remediation_audit_id'), table_name='vulnerability_remediation_audit')
    op.drop_index(op.f('ix_vulnerability_remediation_audit_component_name'), table_name='vulnerability_remediation_audit')
    op.drop_index(op.f('ix_vulnerability_remediation_audit_changed_at'), table_name='vulnerability_remediation_audit')
    op.drop_table('vulnerability_remediation_audit')
    op.drop_index(op.f('ix_vex_documents_validation_status'), table_name='vex_documents')
    op.drop_index(op.f('ix_vex_documents_uploaded_by'), table_name='vex_documents')
    op.drop_index(op.f('ix_vex_documents_uploaded_at'), table_name='vex_documents')
    op.drop_index('ix_vex_documents_tenant_identity', table_name='vex_documents')
    op.drop_index(op.f('ix_vex_documents_tenant_id'), table_name='vex_documents')
    op.drop_index(op.f('ix_vex_documents_source_type'), table_name='vex_documents')
    op.drop_index(op.f('ix_vex_documents_sbom_id'), table_name='vex_documents')
    op.drop_index(op.f('ix_vex_documents_id'), table_name='vex_documents')
    op.drop_index(op.f('ix_vex_documents_format'), table_name='vex_documents')
    op.drop_table('vex_documents')
    op.drop_index(op.f('ix_sbom_validation_sessions_validation_status'), table_name='sbom_validation_sessions')
    op.drop_index(op.f('ix_sbom_validation_sessions_user_id'), table_name='sbom_validation_sessions')
    op.drop_index('ix_sbom_validation_sessions_tenant_identity', table_name='sbom_validation_sessions')
    op.drop_index(op.f('ix_sbom_validation_sessions_tenant_id'), table_name='sbom_validation_sessions')
    op.drop_index(op.f('ix_sbom_validation_sessions_stored_sha256'), table_name='sbom_validation_sessions')
    op.drop_index(op.f('ix_sbom_validation_sessions_sha256'), table_name='sbom_validation_sessions')
    op.drop_index(op.f('ix_sbom_validation_sessions_project_id'), table_name='sbom_validation_sessions')
    op.drop_index(op.f('ix_sbom_validation_sessions_original_sha256'), table_name='sbom_validation_sessions')
    op.drop_index(op.f('ix_sbom_validation_sessions_imported_sbom_id'), table_name='sbom_validation_sessions')
    op.drop_index(op.f('ix_sbom_validation_sessions_id'), table_name='sbom_validation_sessions')
    op.drop_index(op.f('ix_sbom_validation_sessions_expires_at'), table_name='sbom_validation_sessions')
    op.drop_index(op.f('ix_sbom_validation_sessions_created_at'), table_name='sbom_validation_sessions')
    op.drop_index(op.f('ix_sbom_validation_sessions_content_sha256'), table_name='sbom_validation_sessions')
    op.drop_table('sbom_validation_sessions')
    op.drop_index(op.f('ix_sbom_component_version'), table_name='sbom_component')
    op.drop_index('ix_sbom_component_tenant_identity', table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_tenant_id'), table_name='sbom_component')
    op.drop_index('ix_sbom_component_sbom_normalized_key', table_name='sbom_component')
    op.drop_index('ix_sbom_component_sbom_name', table_name='sbom_component')
    op.drop_index('ix_sbom_component_sbom_is_duplicate', table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_sbom_id'), table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_primary_cpe'), table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_normalized_version'), table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_normalized_purl'), table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_normalized_package_key'), table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_normalized_name'), table_name='sbom_component')
    op.drop_index('ix_sbom_component_normalized_identity', table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_normalized_ecosystem'), table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_normalized_component_key'), table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_name'), table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_lifecycle_checked_at'), table_name='sbom_component')
    op.drop_index('ix_sbom_component_lifecycle', table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_id'), table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_ecosystem'), table_name='sbom_component')
    op.drop_index('ix_sbom_component_duplicate_of_component_id', table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_dedupe_group_id'), table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_dedupe_canonical_id'), table_name='sbom_component')
    op.drop_index('ix_sbom_component_deactivated', table_name='sbom_component', postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.drop_index(op.f('ix_sbom_component_cpe_source'), table_name='sbom_component')
    op.drop_index(op.f('ix_sbom_component_cpe'), table_name='sbom_component')
    op.drop_index('ix_sbom_component_bom_ref', table_name='sbom_component')
    op.drop_table('sbom_component')
    op.drop_index('ix_sbom_analysis_report_tenant_identity', table_name='sbom_analysis_report')
    op.drop_index(op.f('ix_sbom_analysis_report_tenant_id'), table_name='sbom_analysis_report')
    op.drop_index(op.f('ix_sbom_analysis_report_id'), table_name='sbom_analysis_report')
    op.drop_index('ix_sbom_analysis_report_deactivated', table_name='sbom_analysis_report', postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.drop_table('sbom_analysis_report')
    op.drop_index('ix_analysis_run_tenant_identity', table_name='analysis_run')
    op.drop_index(op.f('ix_analysis_run_tenant_id'), table_name='analysis_run')
    op.drop_index(op.f('ix_analysis_run_sbom_id'), table_name='analysis_run')
    op.drop_index(op.f('ix_analysis_run_run_status'), table_name='analysis_run')
    op.drop_index(op.f('ix_analysis_run_project_id'), table_name='analysis_run')
    op.drop_index(op.f('ix_analysis_run_id'), table_name='analysis_run')
    op.drop_index('ix_analysis_run_deactivated', table_name='analysis_run', postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.drop_table('analysis_run')
    op.drop_index(op.f('ix_vulnerability_remediation_vuln_id'), table_name='vulnerability_remediation')
    op.drop_index('ix_vulnerability_remediation_tenant_identity', table_name='vulnerability_remediation')
    op.drop_index(op.f('ix_vulnerability_remediation_tenant_id'), table_name='vulnerability_remediation')
    op.drop_index(op.f('ix_vulnerability_remediation_project_id'), table_name='vulnerability_remediation')
    op.drop_index(op.f('ix_vulnerability_remediation_id'), table_name='vulnerability_remediation')
    op.drop_index(op.f('ix_vulnerability_remediation_component_name'), table_name='vulnerability_remediation')
    op.drop_table('vulnerability_remediation')
    op.drop_index('ix_sbom_source_tenant_project', table_name='sbom_source')
    op.drop_index('ix_sbom_source_tenant_identity', table_name='sbom_source')
    op.drop_index(op.f('ix_sbom_source_tenant_id'), table_name='sbom_source')
    op.drop_index('ix_sbom_source_tenant_created', table_name='sbom_source')
    op.drop_index(op.f('ix_sbom_source_status'), table_name='sbom_source')
    op.drop_index(op.f('ix_sbom_source_source_sbom_id'), table_name='sbom_source')
    op.drop_index('ix_sbom_source_sbom_type', table_name='sbom_source')
    op.drop_index(op.f('ix_sbom_source_sbom_name'), table_name='sbom_source')
    op.drop_index('ix_sbom_source_parent_id', table_name='sbom_source')
    op.drop_index(op.f('ix_sbom_source_id'), table_name='sbom_source')
    op.drop_index(op.f('ix_sbom_source_failed_stage'), table_name='sbom_source')
    op.drop_index(op.f('ix_sbom_source_enrichment_status'), table_name='sbom_source')
    op.drop_index('ix_sbom_source_deactivated', table_name='sbom_source', postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.drop_index(op.f('ix_sbom_source_created_by'), table_name='sbom_source')
    op.drop_index(op.f('ix_sbom_source_converted_sbom_id'), table_name='sbom_source')
    op.drop_index('ix_sbom_source_converted_from_format', table_name='sbom_source')
    op.drop_index(op.f('ix_sbom_source_conversion_status'), table_name='sbom_source')
    op.drop_index(op.f('ix_sbom_source_component_extraction_status'), table_name='sbom_source')
    op.drop_table('sbom_source')
    op.drop_index(op.f('ix_tenant_users_user_id'), table_name='tenant_users')
    op.drop_index('ix_tenant_users_tenant_status', table_name='tenant_users')
    op.drop_index(op.f('ix_tenant_users_tenant_id'), table_name='tenant_users')
    op.drop_table('tenant_users')
    op.drop_index('ix_run_cache_tenant_identity', table_name='run_cache')
    op.drop_index(op.f('ix_run_cache_tenant_id'), table_name='run_cache')
    op.drop_index(op.f('ix_run_cache_id'), table_name='run_cache')
    op.drop_table('run_cache')
    op.drop_index('ix_projects_tenant_identity', table_name='projects')
    op.drop_index(op.f('ix_projects_tenant_id'), table_name='projects')
    op.drop_index('ix_projects_tenant_created', table_name='projects')
    op.drop_index(op.f('ix_projects_project_name'), table_name='projects')
    op.drop_index(op.f('ix_projects_id'), table_name='projects')
    op.drop_index('ix_projects_deactivated', table_name='projects', postgresql_where=sa.text('is_active = false'), sqlite_where=sa.text('is_active = 0'))
    op.drop_index(op.f('ix_projects_created_by'), table_name='projects')
    op.drop_table('projects')
    op.drop_index(op.f('ix_lifecycle_vendor_records_vendor_name'), table_name='lifecycle_vendor_records')
    op.drop_index(op.f('ix_lifecycle_vendor_records_product_name'), table_name='lifecycle_vendor_records')
    op.drop_index('ix_lifecycle_vendor_records_lookup', table_name='lifecycle_vendor_records')
    op.drop_index(op.f('ix_lifecycle_vendor_records_id'), table_name='lifecycle_vendor_records')
    op.drop_index(op.f('ix_lifecycle_vendor_records_enabled'), table_name='lifecycle_vendor_records')
    op.drop_index(op.f('ix_lifecycle_vendor_records_ecosystem'), table_name='lifecycle_vendor_records')
    op.drop_table('lifecycle_vendor_records')
    op.drop_index(op.f('ix_lifecycle_provider_secrets_provider_key'), table_name='lifecycle_provider_secrets')
    op.drop_index('ix_lifecycle_provider_secrets_provider', table_name='lifecycle_provider_secrets')
    op.drop_index(op.f('ix_lifecycle_provider_secrets_id'), table_name='lifecycle_provider_secrets')
    op.drop_table('lifecycle_provider_secrets')
    op.drop_index(op.f('ix_lifecycle_provider_configs_provider_type'), table_name='lifecycle_provider_configs')
    op.drop_index(op.f('ix_lifecycle_provider_configs_provider_key'), table_name='lifecycle_provider_configs')
    op.drop_index(op.f('ix_lifecycle_provider_configs_id'), table_name='lifecycle_provider_configs')
    op.drop_index(op.f('ix_lifecycle_provider_configs_health_status'), table_name='lifecycle_provider_configs')
    op.drop_index('ix_lifecycle_provider_configs_enabled_priority', table_name='lifecycle_provider_configs')
    op.drop_table('lifecycle_provider_configs')
    op.drop_index('ix_compare_cache_tenant_identity', table_name='compare_cache')
    op.drop_index(op.f('ix_compare_cache_tenant_id'), table_name='compare_cache')
    op.drop_index(op.f('ix_compare_cache_run_b_id'), table_name='compare_cache')
    op.drop_index(op.f('ix_compare_cache_run_a_id'), table_name='compare_cache')
    op.drop_index(op.f('ix_compare_cache_expires_at'), table_name='compare_cache')
    op.drop_table('compare_cache')
    op.drop_index(op.f('ix_audit_log_user_ref_id'), table_name='audit_log')
    op.drop_index('ix_audit_log_tenant_identity', table_name='audit_log')
    op.drop_index(op.f('ix_audit_log_tenant_id'), table_name='audit_log')
    op.drop_index(op.f('ix_audit_log_target_kind'), table_name='audit_log')
    op.drop_index(op.f('ix_audit_log_target_id'), table_name='audit_log')
    op.drop_index(op.f('ix_audit_log_id'), table_name='audit_log')
    op.drop_index(op.f('ix_audit_log_entity_type'), table_name='audit_log')
    op.drop_index(op.f('ix_audit_log_entity_id'), table_name='audit_log')
    op.drop_index(op.f('ix_audit_log_created_at'), table_name='audit_log')
    op.drop_index(op.f('ix_audit_log_action'), table_name='audit_log')
    op.drop_table('audit_log')
    op.drop_index('ix_ai_usage_log_tenant_identity', table_name='ai_usage_log')
    op.drop_index(op.f('ix_ai_usage_log_tenant_id'), table_name='ai_usage_log')
    op.drop_index('ix_ai_usage_log_purpose_created', table_name='ai_usage_log')
    op.drop_index(op.f('ix_ai_usage_log_purpose'), table_name='ai_usage_log')
    op.drop_index('ix_ai_usage_log_provider_created', table_name='ai_usage_log')
    op.drop_index(op.f('ix_ai_usage_log_provider'), table_name='ai_usage_log')
    op.drop_index(op.f('ix_ai_usage_log_id'), table_name='ai_usage_log')
    op.drop_index(op.f('ix_ai_usage_log_finding_cache_key'), table_name='ai_usage_log')
    op.drop_index(op.f('ix_ai_usage_log_created_at'), table_name='ai_usage_log')
    op.drop_table('ai_usage_log')
    op.drop_index(op.f('ix_tenants_slug'), table_name='tenants')
    op.drop_index(op.f('ix_tenants_external_iam_tenant_id'), table_name='tenants')
    op.drop_table('tenants')
    op.drop_index('ix_source_response_cache_expires_at', table_name='source_response_cache')
    op.drop_table('source_response_cache')
    op.drop_index(op.f('ix_sbom_type_id'), table_name='sbom_type')
    op.drop_table('sbom_type')
    op.drop_index('ix_nvd_sync_runs_started_at', table_name='nvd_sync_runs')
    op.drop_table('nvd_sync_runs')
    op.drop_table('nvd_settings')
    op.drop_index('ix_nvd_lookup_cache_status', table_name='nvd_lookup_cache')
    op.drop_index('ix_nvd_lookup_cache_identifier', table_name='nvd_lookup_cache')
    op.drop_index('ix_nvd_lookup_cache_expires_at', table_name='nvd_lookup_cache')
    op.drop_table('nvd_lookup_cache')
    op.drop_index(op.f('ix_kev_entry_cve_id'), table_name='kev_entry')
    op.drop_table('kev_entry')
    op.drop_index(op.f('ix_iam_users_external_iam_user_id'), table_name='iam_users')
    op.drop_index(op.f('ix_iam_users_email'), table_name='iam_users')
    op.drop_table('iam_users')
    op.drop_index(op.f('ix_epss_score_cve_id'), table_name='epss_score')
    op.drop_table('epss_score')
    op.drop_index('ix_cves_vuln_status', table_name='cves')
    op.drop_index('ix_cves_last_modified', table_name='cves')
    # GIN index only exists on PostgreSQL (see upgrade guard above).
    if op.get_bind().dialect.name == 'postgresql':
        op.drop_index('ix_cves_cpe_match_gin', table_name='cves', postgresql_using='gin', postgresql_ops={'cpe_match': 'jsonb_path_ops'})
    op.drop_table('cves')
    op.drop_index(op.f('ix_cve_cache_expires_at'), table_name='cve_cache')
    op.drop_index(op.f('ix_cve_cache_cve_id'), table_name='cve_cache')
    op.drop_table('cve_cache')
    op.drop_index(op.f('ix_component_lifecycle_cache_purl'), table_name='component_lifecycle_cache')
    op.drop_index(op.f('ix_component_lifecycle_cache_normalized_version'), table_name='component_lifecycle_cache')
    op.drop_index(op.f('ix_component_lifecycle_cache_normalized_name'), table_name='component_lifecycle_cache')
    op.drop_index(op.f('ix_component_lifecycle_cache_lookup_key'), table_name='component_lifecycle_cache')
    op.drop_index('ix_component_lifecycle_cache_lookup', table_name='component_lifecycle_cache')
    op.drop_index(op.f('ix_component_lifecycle_cache_id'), table_name='component_lifecycle_cache')
    op.drop_index(op.f('ix_component_lifecycle_cache_expires_at'), table_name='component_lifecycle_cache')
    op.drop_index(op.f('ix_component_lifecycle_cache_ecosystem'), table_name='component_lifecycle_cache')
    op.drop_index(op.f('ix_component_lifecycle_cache_cpe'), table_name='component_lifecycle_cache')
    op.drop_index(op.f('ix_component_lifecycle_cache_checked_at'), table_name='component_lifecycle_cache')
    op.drop_table('component_lifecycle_cache')
    op.drop_table('ai_settings')
    op.drop_index(op.f('ix_ai_provider_credential_provider_name'), table_name='ai_provider_credential')
    op.drop_index(op.f('ix_ai_provider_credential_id'), table_name='ai_provider_credential')
    op.drop_index('ix_ai_only_one_fallback', table_name='ai_provider_credential', postgresql_where=sa.text('is_fallback = true'), sqlite_where=sa.text('is_fallback = 1'))
    op.drop_index('ix_ai_only_one_default', table_name='ai_provider_credential', postgresql_where=sa.text('is_default = true'), sqlite_where=sa.text('is_default = 1'))
    op.drop_table('ai_provider_credential')
    op.drop_table('ai_provider_config')
    op.drop_index(op.f('ix_ai_fix_cache_vuln_id'), table_name='ai_fix_cache')
    op.drop_index('ix_ai_fix_cache_vuln_component', table_name='ai_fix_cache')
    op.drop_index(op.f('ix_ai_fix_cache_expires_at'), table_name='ai_fix_cache')
    op.drop_table('ai_fix_cache')
    op.drop_index(op.f('ix_ai_credential_audit_log_id'), table_name='ai_credential_audit_log')
    op.drop_index(op.f('ix_ai_credential_audit_log_created_at'), table_name='ai_credential_audit_log')
    op.drop_table('ai_credential_audit_log')
