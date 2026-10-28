"""Narrow internal maintenance entry points; never expose these as HTTP inputs."""

from contextlib import contextmanager

from sqlalchemy import select

from ..core.context import get_bound_context, minimal_background_context, tenant_scope
from ..db import SessionLocal, engine
from ..models import AnalysisSchedule, ReportArtifact, SBOMSource, Tenant
from .audit_service import write_authorization_audit


def _internal_only():
    if get_bound_context() is not None:
        raise RuntimeError("Maintenance discovery is unavailable to request contexts")


def _audit_discovery(kind, count):
    with SessionLocal() as db:
        write_authorization_audit(db, action="maintenance.discovery", new_value={"kind": kind, "count": count})
        db.commit()


def active_tenant_ids():
    """Discover active tenant identifiers, without loading business records."""
    _internal_only()
    with SessionLocal() as db:
        identifiers = tuple(db.scalars(select(Tenant.id).where(Tenant.status == "ACTIVE").order_by(Tenant.id)))
    _audit_discovery("active_tenant_ids", len(identifiers))
    return identifiers


def schedule_tenant_id(schedule_id, *, sbom_id=None):
    """Resolve a queued schedule's owner from trusted DB metadata only."""
    _internal_only()
    schedule = AnalysisSchedule.__table__
    # A dedicated fixed-shape Core query avoids loading an unscoped ORM entity.
    # Do not generalize this into an arbitrary statement execution capability.
    statement = (
        select(schedule.c.tenant_id)
        .join(Tenant.__table__, Tenant.id == schedule.c.tenant_id)
        .where(schedule.c.id == schedule_id, schedule.c.is_active.is_(True), Tenant.status == "ACTIVE")
    )
    if sbom_id is not None:
        sbom = SBOMSource.__table__
        statement = statement.where(
            select(sbom.c.id).where(sbom.c.id == sbom_id, sbom.c.tenant_id == schedule.c.tenant_id).exists()
        )
    with engine.connect() as connection:
        identifier = connection.scalar(statement)
    _audit_discovery("schedule_owner", int(identifier is not None))
    return identifier


def report_artifact_owner(storage_identifier):
    """Metadata-only existence check for internal orphan-file cleanup."""
    _internal_only()
    artifact = ReportArtifact.__table__
    with engine.connect() as connection:
        return connection.execute(
            select(artifact.c.id, artifact.c.tenant_id).where(artifact.c.storage_path == storage_identifier)
        ).first()


@contextmanager
def maintenance_tenant(tenant_id, operation):
    """Validate an active owner, bind execution, and clear scope on all exits."""
    _internal_only()
    if type(tenant_id) is not int or tenant_id <= 0:
        raise RuntimeError("Invalid maintenance tenant")
    with SessionLocal() as db:
        if not db.scalar(select(Tenant.id).where(Tenant.id == tenant_id, Tenant.status == "ACTIVE")):
            raise RuntimeError("Inactive maintenance tenant")
        write_authorization_audit(
            db, action="maintenance.started", tenant_id=tenant_id, new_value={"operation": operation}
        )
        db.commit()
    with tenant_scope(minimal_background_context(tenant_id)):
        outcome = "SUCCESS"
        try:
            yield
        except BaseException:
            outcome = "FAILED"
            raise
        finally:
            with SessionLocal() as db:
                write_authorization_audit(
                    db,
                    action="maintenance.finished",
                    outcome=outcome,
                    tenant_id=tenant_id,
                    new_value={"operation": operation},
                )
                db.commit()


@contextmanager
def background_tenant(tenant_id=None):
    """Bind an explicit job owner; a request context cannot select another owner."""
    context = get_bound_context()
    selected = tenant_id if tenant_id is not None else context.tenant_id if context else None
    if type(selected) is not int or selected <= 0:
        raise RuntimeError("Tenant context is required for background work")
    if context is not None and context.tenant_id != selected:
        raise RuntimeError("Cross-tenant background context rejected")
    with SessionLocal() as db:
        if not db.scalar(select(Tenant.id).where(Tenant.id == selected, Tenant.status == "ACTIVE")):
            raise RuntimeError("Inactive background tenant")
    with tenant_scope(minimal_background_context(selected)):
        yield selected
