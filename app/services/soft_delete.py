"""Cascading soft-delete service.

Walks the SQLAlchemy relationship graph from a parent record and marks
every reachable child as soft-deleted (``is_active=False``,
``deactivated_at=<now>``, ``deactivated_by=<user>``).

Hard rules
----------
* The cascade STOPS at tables in ``CASCADE_EXCLUDED_TABLES``: the AI
  fix cache, the audit logs, the credential / settings surfaces, and
  every TTL-managed cache. Tombstoning these would either lose
  retention data (audit/usage log), or silently regenerate paid
  content (ai_fix_cache), or be a security bug (credentials).
* The walker only follows ``ONETOMANY`` / ``ONETOONE`` relationships
  (parent → child), never ``MANYTOONE`` (child → parent). Otherwise a
  soft-delete on an SBOM would walk back up to the project.
* Already-soft-deleted records are no-ops; the walker doesn't touch
  them again. This makes the operation idempotent — re-issuing
  ``soft_delete(project)`` after a partial failure is safe.
* The walker is cycle-safe via a ``(table, id)`` visited set, even
  though the current ownership tree has no cycles. Cheap insurance.

Side-effects beyond the walker
------------------------------
When an ``AnalysisRun`` is soft-deleted we additionally hard-delete
its rows in ``compare_cache`` (via ``CompareService.invalidate_for_run``
semantics). Compare cache is a TTL-bounded derived cache keyed by
SHA of the run-id pair; tombstoning it would create cache poisoning
where a stale comparison persists past a re-run. The hard-delete
mirrors the existing re-run invalidation hook.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import inspect, or_, select
from sqlalchemy.orm import Session

from ..models import CompareCache
from ..models_mixins import SoftDeleteMixin

log = logging.getLogger("sbom.soft_delete")


# Tables that the cascade NEVER touches.
#
# Rationale per table is captured in docs/soft-delete-audit.md §1.1.
CASCADE_EXCLUDED_TABLES: frozenset[str] = frozenset(
    {
        # Append-only audit / retention surfaces
        "audit_log",
        "ai_credential_audit_log",
        "ai_usage_log",
        # Caches (TTL-managed, recomputable)
        "ai_fix_cache",
        "compare_cache",  # special-cased to hard-delete; see _post_run_hooks
        "cve_cache",
        "epss_score",
        "kev_entry",
        "run_cache",
        # Reference / settings / security
        "sbom_type",
        "ai_provider_config",
        "ai_provider_credential",
        "ai_settings",
    }
)


class SoftDeleteService:
    """Cascades soft-delete through the SQLAlchemy relationship graph."""

    def __init__(self, db: Session):
        self._db = db
        self._visited: set[tuple[str, Any]] = set()

    # ------------------------------------------------------------------
    # Soft delete
    # ------------------------------------------------------------------

    def soft_delete(
        self,
        record: object,
        *,
        user_id: str | None = None,
        cascade: bool = True,
    ) -> int:
        """Soft-delete ``record`` and (optionally) its children.

        Returns the count of records soft-deleted in this call (including
        the parent). Already-deleted records contribute 0.
        """
        if not isinstance(record, SoftDeleteMixin):
            raise ValueError(
                f"{type(record).__name__} does not inherit SoftDeleteMixin"
            )

        mapper = inspect(record).mapper
        table_name = mapper.local_table.name
        try:
            identity = inspect(record).identity
        except Exception:
            identity = None
        ident_key = identity[0] if identity else id(record)
        visit_key = (table_name, ident_key)

        if visit_key in self._visited:
            return 0
        self._visited.add(visit_key)

        if not record.is_active:
            return 0

        record.is_active = False
        record.deactivated_at = datetime.now(UTC)
        record.deactivated_by = user_id
        count = 1

        if cascade:
            count += self._cascade_to_children(record, user_id=user_id)

        # Side-effects that aren't part of the relationship walk.
        self._post_record_hooks(record)

        return count

    def _cascade_to_children(
        self,
        record: object,
        *,
        user_id: str | None,
    ) -> int:
        mapper = inspect(record).mapper
        count = 0

        for rel in mapper.relationships:
            # Walk DOWN the tree only.
            if rel.direction.name not in ("ONETOMANY", "ONETOONE"):
                continue

            child_table = rel.mapper.local_table.name
            if child_table in CASCADE_EXCLUDED_TABLES:
                continue

            # Skip relationships pointing at non-soft-delete-eligible
            # tables. Defence-in-depth — the exclusion list above should
            # already cover these, but a future model addition that
            # forgets to update the list shouldn't cause a TypeError.
            if not issubclass(rel.mapper.class_, SoftDeleteMixin):
                continue

            children = getattr(record, rel.key)
            if children is None:
                continue

            if isinstance(children, list):
                # Snapshot the iterable — the loader filter
                # (``with_loader_criteria``) gives us only active
                # children, but we materialise to a list so any
                # session state changes during the walk don't trip
                # us up.
                for child in list(children):
                    count += self.soft_delete(
                        child, user_id=user_id, cascade=True
                    )
            else:
                count += self.soft_delete(
                    children, user_id=user_id, cascade=True
                )

        return count

    def _post_record_hooks(self, record: object) -> None:
        """Non-relationship side-effects keyed by record type."""
        table_name = inspect(record).mapper.local_table.name

        if table_name == "analysis_run":
            # Hard-delete CompareCache rows that reference this run on
            # either side. This mirrors CompareService.invalidate_for_run
            # but inlined here so the soft-delete cascade is fully
            # self-contained (no service-locator coupling). The cache
            # rows are recomputable from live runs only — once both
            # endpoints are gone, the cache row would be unreachable.
            try:
                run_id = inspect(record).identity[0]
            except Exception:
                return
            stmt = select(CompareCache).where(
                or_(
                    CompareCache.run_a_id == run_id,
                    CompareCache.run_b_id == run_id,
                )
            )
            for row in self._db.execute(stmt).scalars().all():
                self._db.delete(row)

    # ------------------------------------------------------------------
    # Restore
    # ------------------------------------------------------------------

    def restore(self, record: object) -> int:
        """Restore one record. Does NOT cascade.

        Restoration is a deliberate per-record act — admins decide
        which children (if any) to also restore, since a partial
        cascade may have happened (e.g. a child was deleted before
        the parent was deleted).
        """
        if not isinstance(record, SoftDeleteMixin):
            raise ValueError(
                f"{type(record).__name__} does not inherit SoftDeleteMixin"
            )
        if record.is_active:
            return 0
        record.is_active = True
        record.deactivated_at = None
        record.deactivated_by = None
        return 1

    # ------------------------------------------------------------------
    # Hard delete (delegates to the existing FK-cascade behaviour)
    # ------------------------------------------------------------------

    def hard_delete(self, record: object) -> None:
        """Permanently delete. Falls through to existing ORM/FK cascade.

        The caller is responsible for any pre-cascade work that the
        original (pre-soft-delete) endpoint used to do — for example,
        the SBOM hard-delete still walks ``analysis_finding`` /
        ``analysis_run`` / ``sbom_component`` / ``sbom_analysis_report``
        explicitly because those FKs don't carry ``ON DELETE CASCADE``.
        """
        self._db.delete(record)


__all__ = ["SoftDeleteService", "CASCADE_EXCLUDED_TABLES"]
