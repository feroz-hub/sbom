"""Logical SBOM ownership and revision selection without moving version evidence."""

from datetime import UTC, datetime
from functools import cmp_to_key

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import LogicalSBOM, SBOMSource
from .sbom_version_lineage import _compare, parse_version


def now_iso():
    return datetime.now(UTC).isoformat()


def get_logical_sbom(db: Session, logical_id: int, tenant_id: int, *, product_id=None, lock=False):
    stmt = select(LogicalSBOM).where(LogicalSBOM.id == logical_id, LogicalSBOM.tenant_id == tenant_id)
    if product_id is not None:
        stmt = stmt.where(LogicalSBOM.product_id == product_id)
    if lock:
        stmt = stmt.with_for_update()
    master = db.scalar(stmt)
    if master is None:
        raise HTTPException(404, detail="Logical SBOM not found")
    return master


def assign_logical_identity(db: Session, row: SBOMSource):
    """Give every writer a parent, with explicit tenant and Product ownership."""
    from ..core.context import get_bound_context
    from ..settings import get_settings

    context = get_bound_context()
    tenant_id = row.tenant_id or (context.tenant_id if context else None)
    if tenant_id is None and not get_settings().auth_enabled:
        tenant_id = 1
    if tenant_id is None:
        raise RuntimeError("Tenant context is required for SBOM versions")
    row.tenant_id = tenant_id
    master = row.logical_sbom
    if master is None and row.logical_sbom_id is not None:
        master = db.scalar(
            select(LogicalSBOM).where(LogicalSBOM.id == row.logical_sbom_id, LogicalSBOM.tenant_id == tenant_id)
        )
        if master is None:
            raise HTTPException(404, detail="Logical SBOM not found")
    # A legacy single-version assignment preserves the other versions in place.
    if master is not None and master.product_id != row.product_id:
        if row in db.new:
            raise HTTPException(422, detail="Logical SBOM belongs to a different application")
        row.logical_sbom_id = None
        row.logical_sbom = None
        master = None
    if master is None and row.parent_id is not None and row in db.new and row.source_sbom_id is None:
        parent = db.get(SBOMSource, row.parent_id)
        if (
            parent
            and parent.tenant_id == tenant_id
            and parent.product_id == row.product_id
            and parent.projectid == row.projectid
        ):
            master = parent.logical_sbom
            # Legacy unversioned clone chains are ambiguous identities. Preserve
            # each record in its own master, just as migration backfill does.
            if row.sbom_version is None and master is not None:
                exists = db.scalar(select(SBOMSource.id).where(
                    SBOMSource.logical_sbom_id == master.id, SBOMSource.sbom_version.is_(None)
                ).execution_options(include_deleted=True))
                if exists is not None:
                    master = None
    if master is None:
        master = LogicalSBOM(
            tenant_id=tenant_id,
            product_id=row.product_id,
            name=row.sbom_name,
            description=row.description,
            created_by=row.created_by,
            created_at=row.created_on or now_iso(),
            updated_at=now_iso(),
        )
        db.add(master)
    if master.tenant_id != tenant_id:
        raise HTTPException(404, detail="Logical SBOM not found")
    if row in db.new:
        master.updated_at = now_iso()
    row.logical_sbom = master


def ordered_versions(rows):
    """Highest dotted numeric revision first; arbitrary labels use upload order."""
    if rows and all(parse_version(row.sbom_version) is not None for row in rows):

        def compare(a, b):
            numeric = _compare(parse_version(a.sbom_version), parse_version(b.sbom_version))
            return numeric or ((a.id > b.id) - (a.id < b.id))

        return sorted(rows, key=cmp_to_key(compare), reverse=True)
    return sorted(rows, key=lambda row: row.id or 0, reverse=True)


def versions_for(db, master):
    return list(
        db.scalars(
            select(SBOMSource).where(SBOMSource.logical_sbom_id == master.id, SBOMSource.tenant_id == master.tenant_id)
        )
    )


def ensure_version_available(db, master, version, *, exclude_id=None):
    version = (version or "").strip() or None
    stmt = (
        select(SBOMSource.id)
        .where(
            SBOMSource.logical_sbom_id == master.id,
            SBOMSource.tenant_id == master.tenant_id,
            SBOMSource.sbom_version == version,
        )
        .execution_options(include_deleted=True)
    )
    if exclude_id is not None:
        stmt = stmt.where(SBOMSource.id != exclude_id)
    with db.no_autoflush:
        exists = db.scalar(stmt)
    if exists is not None:
        raise HTTPException(
            409,
            detail={
                "code": "duplicate_sbom_version",
                "message": f"SBOM version {version or '(unversioned)'} already exists in this logical SBOM.",
            },
        )


def next_revision(db, parent):
    master = parent.logical_sbom
    rows = versions_for(db, master)
    latest = ordered_versions(rows)[0] if rows else parent
    text = latest.sbom_version or "1.0.0"
    parts = parse_version(text)
    candidate = ".".join(str(v) for v in (*parts[:-1], parts[-1] + 1)) if parts else f"{text}-revised"
    used = set(
        db.scalars(
            select(SBOMSource.sbom_version)
            .where(SBOMSource.logical_sbom_id == master.id)
            .execution_options(include_deleted=True)
        )
    )
    base = candidate
    i = 1
    while candidate in used:
        candidate = f"{base}.{i}"
        i += 1
    return candidate
