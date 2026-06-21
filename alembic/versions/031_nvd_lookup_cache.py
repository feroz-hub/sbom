"""Add production-safe NVD lookup cache and CPE provenance.

Revision ID: 031_nvd_lookup_cache
Revises: 030_sbom_conversion_enrichment_status
Create Date: 2026-06-20
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "031_nvd_lookup_cache"
down_revision = "030_sbom_conversion_enrichment_status"
branch_labels = None
depends_on = None


def _table_exists(bind, name: str) -> bool:
    return name in sa.inspect(bind).get_table_names()


def _column_exists(bind, table: str, column: str) -> bool:
    return column in {c["name"] for c in sa.inspect(bind).get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    if not _column_exists(bind, "sbom_component", "cpe_source"):
        op.add_column("sbom_component", sa.Column("cpe_source", sa.String(32), nullable=True))
        op.create_index("ix_sbom_component_cpe_source", "sbom_component", ["cpe_source"])

    if not _table_exists(bind, "nvd_lookup_cache"):
        op.create_table(
            "nvd_lookup_cache",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("lookup_type", sa.String(16), nullable=False),
            sa.Column("identifier", sa.String(2048), nullable=False),
            sa.Column("identifier_hash", sa.String(64), nullable=False),
            sa.Column("status", sa.String(16), nullable=False),
            sa.Column("response_json", sa.JSON(), nullable=True),
            sa.Column("http_status", sa.Integer(), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("checked_at", sa.String(), nullable=False),
            sa.Column("expires_at", sa.String(), nullable=False),
            sa.Column("created_at", sa.String(), nullable=False),
            sa.Column("updated_at", sa.String(), nullable=False),
            sa.UniqueConstraint("lookup_type", "identifier_hash", name="uq_nvd_lookup_cache_type_hash"),
        )
        op.create_index("ix_nvd_lookup_cache_expires_at", "nvd_lookup_cache", ["expires_at"])
        op.create_index("ix_nvd_lookup_cache_status", "nvd_lookup_cache", ["status"])
        op.create_index("ix_nvd_lookup_cache_identifier", "nvd_lookup_cache", ["identifier"])


def downgrade() -> None:
    bind = op.get_bind()
    if _table_exists(bind, "nvd_lookup_cache"):
        op.drop_table("nvd_lookup_cache")
    if _column_exists(bind, "sbom_component", "cpe_source"):
        op.drop_index("ix_sbom_component_cpe_source", table_name="sbom_component")
        op.drop_column("sbom_component", "cpe_source")
