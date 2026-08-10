"""kev + epss cache tables — risk scoring v2.

Revision ID: 003_kev_epss_cache
Revises: 002_nvd_mirror_tables
Create Date: 2026-04-29

Adds two cache tables backing the new CVSS+KEV+EPSS risk scorer:

    kev_entry  — CISA Known Exploited Vulnerabilities catalog mirror
    epss_score — FIRST.org EPSS per-CVE probabilities

Both tables are refreshed on a TTL (24h) — never block scoring on
external feed availability.

Idempotency: each create is guarded by an inspector existence check so
this migration is safe against fresh databases where Base.metadata.create_all
has already created the tables.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "003_kev_epss_cache"
down_revision = "002_nvd_mirror_tables"
branch_labels = None
depends_on = None


def _table_exists(bind: sa.engine.Connection, name: str) -> bool:
    return name in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    bind = op.get_bind()

    if not _table_exists(bind, "kev_entry"):
        op.create_table(
            "kev_entry",
            sa.Column("cve_id", sa.String(), primary_key=True, index=True),
            sa.Column("vendor_project", sa.String(), nullable=True),
            sa.Column("product", sa.String(), nullable=True),
            sa.Column("vulnerability_name", sa.String(), nullable=True),
            sa.Column("date_added", sa.String(), nullable=True),
            sa.Column("short_description", sa.Text(), nullable=True),
            sa.Column("required_action", sa.Text(), nullable=True),
            sa.Column("due_date", sa.String(), nullable=True),
            sa.Column("known_ransomware_use", sa.String(), nullable=True),
            sa.Column("refreshed_at", sa.String(), nullable=False),
        )

    if not _table_exists(bind, "epss_score"):
        op.create_table(
            "epss_score",
            sa.Column("cve_id", sa.String(), primary_key=True, index=True),
            sa.Column(
                "epss",
                sa.Float(),
                nullable=False,
                server_default=sa.text("0.0"),
            ),
            sa.Column("percentile", sa.Float(), nullable=True),
            sa.Column("score_date", sa.String(), nullable=True),
            sa.Column("refreshed_at", sa.String(), nullable=False),
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _table_exists(bind, "epss_score"):
        op.drop_table("epss_score")
    if _table_exists(bind, "kev_entry"):
        op.drop_table("kev_entry")
