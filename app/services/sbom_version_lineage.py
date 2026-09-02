"""Linking an uploaded SBOM to the version it supersedes.

Editing an SBOM in-app has always produced a parent/child version chain
(``app/services/version_control_service.py``), but uploading never did: every
upload landed with ``parent_id = NULL``, so re-uploading "the same SBOM, next
version" produced two unrelated rows. Version History, ``compare-versions`` and
``restore`` all read the chain, so none of them worked for the path a real
build pipeline actually uses.

Lineage here is **declared, not inferred**. The uploader names the SBOM the new
file supersedes. Guessing from a matching name would silently merge two
genuinely different SBOMs that happen to share one, and a wrong merge is much
harder to notice than a missing link.
"""

from __future__ import annotations

import logging
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import SBOMSource

log = logging.getLogger("sbom.version_lineage")

_NUMERIC_VERSION = re.compile(r"^\d+(\.\d+)*$")


class VersionLineageError(Exception):
    """Raised when a requested parent cannot be used. Carries an HTTP status."""

    def __init__(self, message: str, *, status_code: int = 422) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def parse_version(value: str | None) -> tuple[int, ...] | None:
    """Return a comparable tuple for a dotted-numeric version, else ``None``.

    Deliberately narrow. Only ``1``, ``1.2``, ``1.2.3``-shaped strings compare;
    anything with a suffix (``2.0.0-rc1``, ``2024.09-build7``) returns ``None``
    so the caller skips ordering rather than guessing at pre-release precedence.
    """
    if not value:
        return None
    text = value.strip()
    if not _NUMERIC_VERSION.match(text):
        return None
    try:
        return tuple(int(part) for part in text.split("."))
    except ValueError:  # pragma: no cover - regex already guarantees digits
        return None


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    """Compare two version tuples, zero-padding so 1.2 == 1.2.0."""
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def resolve_parent_sbom(
    db: Session,
    *,
    parent_sbom_id: int,
    tenant_id: int,
    project_id: int | None,
    product_id: int | None,
    new_version: str | None,
) -> SBOMSource:
    """Validate that ``parent_sbom_id`` may be superseded by this upload.

    Returns the parent row. Raises :class:`VersionLineageError` when the parent
    is missing, belongs elsewhere, or the declared version would move backwards.
    """
    parent = db.execute(
        select(SBOMSource).where(
            SBOMSource.id == parent_sbom_id,
            SBOMSource.tenant_id == tenant_id,
        )
    ).scalar_one_or_none()
    if parent is None:
        raise VersionLineageError(
            f"Previous version SBOM {parent_sbom_id} was not found in this tenant.",
            status_code=404,
        )

    # A version chain that jumps between products would make "all versions of
    # this SBOM" meaningless on the product screen.
    if project_id is not None and parent.projectid is not None and parent.projectid != project_id:
        raise VersionLineageError(
            "The previous version belongs to a different project. "
            "Move it first, or upload without linking a previous version."
        )
    if product_id is not None and parent.product_id is not None and parent.product_id != product_id:
        raise VersionLineageError(
            "The previous version belongs to a different product. "
            "Move it first, or upload without linking a previous version."
        )

    parent_version = parse_version(parent.sbom_version)
    next_version = parse_version(new_version)
    if parent_version is not None and next_version is not None and _compare(next_version, parent_version) <= 0:
        raise VersionLineageError(
            f"SBOM version {new_version} does not come after {parent.sbom_version}. "
            "Use a higher version, or upload without linking a previous version."
        )

    return parent


def head_of_lineage(db: Session, parent: SBOMSource) -> SBOMSource:
    """Return the newest descendant of ``parent``, or ``parent`` itself.

    Uploading "a new version of 1.0.0" when 1.1.0 already exists should extend
    the chain rather than fork it — a fork would make ``/versions`` show two
    competing tips with no way to tell which is current.
    """
    current = parent
    seen = {current.id}
    while True:
        child = db.execute(
            select(SBOMSource)
            .where(SBOMSource.parent_id == current.id, SBOMSource.tenant_id == current.tenant_id)
            .order_by(SBOMSource.id.desc())
        ).scalars().first()
        if child is None or child.id in seen:
            return current
        current = child
        seen.add(current.id)
