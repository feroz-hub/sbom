"""SQLAlchemy 2.0 typed ORM models for the NVD mirror tables.

These models intentionally use the modern ``Mapped`` / ``mapped_column``
syntax, diverging from the legacy ``Column(...)`` style used elsewhere
in the repo. The divergence is local to this package and accepted —
new tables get the modern form.

Type variants:
  * ``JSON().with_variant(JSONB(), 'postgresql')`` — PostgreSQL gets the
    indexable JSONB type; SQLite falls back to JSON (TEXT-backed). The
    PG-only GIN indexes live in the Alembic migration, gated on dialect.
  * ``LargeBinary`` — BYTEA on PG, BLOB on SQLite.
  * ``DateTime(timezone=True)`` — TIMESTAMPTZ on PG, TEXT-with-tz-suffix
    on SQLite (round-trip works, native ordering does not — but this
    package only runs in production on PG).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base

# JSON column type — JSONB on PostgreSQL, plain JSON on SQLite.
_JsonType = JSON().with_variant(JSONB(), "postgresql")


class NvdSettingsRow(Base):
    """Singleton row holding the live mirror configuration.

    The CHECK (id = 1) constraint enforces single-row semantics at the
    DB layer. Application code addresses this row by id=1 unconditionally.
    """

    __tablename__ = "nvd_settings"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_nvd_settings_singleton"),
        CheckConstraint(
            "page_size BETWEEN 1 AND 2000", name="ck_nvd_settings_page_size_range"
        ),
        CheckConstraint(
            "window_days BETWEEN 1 AND 119", name="ck_nvd_settings_window_days_range"
        ),
        CheckConstraint(
            "min_freshness_hours >= 0", name="ck_nvd_settings_min_freshness_nonneg"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    api_endpoint: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
    )
    api_key_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    download_feeds_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    page_size: Mapped[int] = mapped_column(Integer, nullable=False, default=2000)
    window_days: Mapped[int] = mapped_column(Integer, nullable=False, default=119)
    min_freshness_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    last_modified_utc: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_successful_sync_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class CveRow(Base):
    """One row per mirrored CVE.

    ``data`` holds the verbatim NVD JSON; ``cpe_match`` is a denormalised
    flat array of ``CpeCriterion``-shaped objects to support the GIN
    candidate-selection query in the repository.
    """

    __tablename__ = "cves"
    __table_args__ = (
        Index("ix_cves_last_modified", "last_modified"),
        Index("ix_cves_vuln_status", "vuln_status"),
        # Note: GIN indexes for cpe_match (and aliases on PG) are added by
        # the Alembic migration in a dialect-conditional block. They are
        # not declared here because SQLAlchemy cannot express GIN
        # generically and the repo runs against SQLite in the dev/test path.
    )

    cve_id: Mapped[str] = mapped_column(Text, primary_key=True)
    last_modified: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    published: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    vuln_status: Mapped[str] = mapped_column(Text, nullable=False)
    description_en: Mapped[str | None] = mapped_column(Text, nullable=True)
    score_v40: Mapped[float | None] = mapped_column(nullable=True)
    score_v31: Mapped[float | None] = mapped_column(nullable=True)
    score_v2: Mapped[float | None] = mapped_column(nullable=True)
    severity_text: Mapped[str | None] = mapped_column(String(32), nullable=True)
    vector_string: Mapped[str | None] = mapped_column(Text, nullable=True)
    aliases: Mapped[list[str]] = mapped_column(_JsonType, nullable=False, default=list)
    cpe_match: Mapped[list[dict[str, Any]]] = mapped_column(
        _JsonType, nullable=False, default=list
    )
    references: Mapped[list[str]] = mapped_column(_JsonType, nullable=False, default=list)
    data: Mapped[dict[str, Any]] = mapped_column(_JsonType, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class NvdSyncRunRow(Base):
    """Audit row for one bootstrap or incremental run."""

    __tablename__ = "nvd_sync_runs"
    __table_args__ = (
        CheckConstraint(
            "run_kind IN ('bootstrap','incremental')",
            name="ck_nvd_sync_runs_kind",
        ),
        CheckConstraint(
            "status IN ('running','success','failed','aborted')",
            name="ck_nvd_sync_runs_status",
        ),
        Index("ix_nvd_sync_runs_started_at", "started_at"),
    )

    # BigInteger on PostgreSQL; SQLite needs plain Integer for the
    # `INTEGER PRIMARY KEY = rowid alias` rule that enables autoincrement.
    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer(), "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    run_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    upserted_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
