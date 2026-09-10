"""Tenant-owned report subscriptions, durable outbox and private artifacts."""

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
)

from .db import Base
from .models_mixins import SoftDeleteMixin, TenantOwnedMixin


class ReportSubscription(Base, SoftDeleteMixin, TenantOwnedMixin):
    __tablename__ = "report_subscription"
    id = Column(Integer, primary_key=True)
    iam_user_id = Column(Integer, ForeignKey("iam_users.id", ondelete="CASCADE"), nullable=False, index=True)
    scope = Column(String(16), nullable=False)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"))
    product_id = Column(Integer, ForeignKey("products.id", ondelete="CASCADE"))
    sbom_id = Column(Integer, ForeignKey("sbom_source.id", ondelete="CASCADE"))
    cadence = Column(String(16), nullable=False, default="DAILY")
    parts = Column(String(16), nullable=False, default="A,B")
    formats = Column(String(32), nullable=False, default="PDF,XLSX")
    severity_floor = Column(String(16), nullable=False, default="ALL")
    baseline_mode = Column(String(32), nullable=False, default="FIRST_RUN_OF_SBOM")
    cross_version_target = Column(String(16), nullable=False, default="PARENT")
    timezone = Column(String(64), nullable=False, default="UTC")
    suppress_when_unchanged = Column(Boolean, nullable=False, default=False)
    enabled = Column(Boolean, nullable=False, default=True)
    last_delivered_at = Column(String)
    created_on = Column(String, nullable=False)
    created_by = Column(String)
    modified_on = Column(String)
    modified_by = Column(String)
    __table_args__ = (
        CheckConstraint("scope IN ('TENANT','PROJECT','PRODUCT','SBOM')", name="report_scope"),
        CheckConstraint(
            "(scope='TENANT' AND project_id IS NULL AND product_id IS NULL AND sbom_id IS NULL) OR "
            "(scope='PROJECT' AND project_id IS NOT NULL AND product_id IS NULL AND sbom_id IS NULL) OR "
            "(scope='PRODUCT' AND product_id IS NOT NULL AND project_id IS NULL AND sbom_id IS NULL) OR "
            "(scope='SBOM' AND sbom_id IS NOT NULL AND project_id IS NULL AND product_id IS NULL)",
            name="report_target",
        ),
        CheckConstraint("cadence IN ('ON_EVERY_RUN','DAILY','WEEKLY','MONTHLY')", name="report_cadence"),
        CheckConstraint("severity_floor IN ('ALL','LOW','MEDIUM','HIGH','CRITICAL')", name="report_severity"),
        *[
            Index(
                f"uq_report_subscription_{scope.lower()}",
                "tenant_id",
                "iam_user_id",
                *columns,
                unique=True,
                postgresql_where=text(f"is_active AND scope = '{scope}'"),
                sqlite_where=text(f"is_active = 1 AND scope = '{scope}'"),
            )
            for scope, columns in [
                ("TENANT", []),
                ("PROJECT", ["project_id"]),
                ("PRODUCT", ["product_id"]),
                ("SBOM", ["sbom_id"]),
            ]
        ],
    )


class ReportDelivery(Base, TenantOwnedMixin):
    __tablename__ = "report_delivery"
    id = Column(Integer, primary_key=True)
    subscription_id = Column(
        Integer, ForeignKey("report_subscription.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cycle_start = Column(String, nullable=False)
    cycle_end = Column(String, nullable=False)
    status = Column(String(16), nullable=False, default="PENDING", index=True)
    error_code = Column(String(64))
    attempt_count = Column(Integer, nullable=False, default=0)
    recipient_email = Column(String(320))
    sbom_count = Column(Integer, nullable=False, default=0)
    run_count = Column(Integer, nullable=False, default=0)
    artifact_ids = Column(JSON, nullable=False, default=list)
    # Transactional outbox: immutable scope snapshot and expected scheduled completions.
    payload = Column(JSON, nullable=False, default=dict)
    attempts = Column(JSON, nullable=False, default=list)
    next_attempt_at = Column(String)
    claimed_at = Column(String)
    dispatch_started_at = Column(String)
    sent_at = Column(String)
    created_on = Column(String, nullable=False)
    __table_args__ = (
        UniqueConstraint("subscription_id", "cycle_start", "cycle_end", name="uq_report_delivery_cycle"),
        CheckConstraint("status IN ('PENDING','SENT','FAILED','SKIPPED','SUPPRESSED')", name="report_delivery_status"),
        Index("ix_report_delivery_tenant_dispatch", "tenant_id", "dispatch_started_at"),
    )


class ReportArtifact(Base, TenantOwnedMixin):
    __tablename__ = "report_artifact"
    id = Column(Integer, primary_key=True)
    delivery_id = Column(Integer, ForeignKey("report_delivery.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(8), nullable=False)
    filename = Column(String(255), nullable=False)
    media_type = Column(String(128), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False)
    storage_path = Column(String(255), nullable=False)
    expires_at = Column(String, nullable=False, index=True)
    created_on = Column(String, nullable=False)
    __table_args__ = (CheckConstraint("kind IN ('PDF','XLSX','JSON')", name="report_artifact_kind"),)
