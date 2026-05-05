"""Scope-aware finding resolution for AI fix batch generation.

A "scope" describes which findings within a run a batch should process.
Three sources, in precedence order:

1. ``finding_ids`` — explicit selection (e.g. row checkboxes).
2. Filter predicates (``severities``, ``kev_only``, ``fix_available_only``,
   ``search_query``) — mirror the findings-table filter chips.
3. Empty / ``None`` scope — every finding in the run.

Security invariant: ``run_id`` is ALWAYS intersected at the SQL layer,
even when ``finding_ids`` is supplied. A caller cannot poke at findings
from runs they don't own — the run-route already constrains access at
the auth layer, and ``resolve_scope_findings`` enforces the same
constraint at the data layer as defence in depth.

Cache-hit counting: :func:`count_cached_for_finding_ids` joins the
resolved set against ``ai_fix_cache`` in a single SQL statement. This is
the fast path used by the pre-flight estimate endpoint, replacing the
old per-finding ``build_grounding_context`` loop (which was O(N) DB
roundtrips and didn't fit a sub-200ms p95).
"""

from __future__ import annotations

import logging
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from ..models import AiFixCache, AnalysisFinding, KevEntry

log = logging.getLogger("sbom.ai.scope")


SeverityLiteral = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


class AiFixGenerationScope(BaseModel):
    """User-supplied scope spec for a batch generation request.

    All fields optional. Empty scope (or ``None``) means "all findings
    in the run."

    Filter precedence:
      * If ``finding_ids`` is non-empty, it wins (explicit selection).
      * Otherwise, filter predicates apply conjunctively.
    """

    model_config = ConfigDict(extra="forbid")

    severities: list[SeverityLiteral] | None = Field(
        default=None,
        description="Restrict to findings with one of these severities.",
    )
    kev_only: bool = Field(
        default=False,
        description="Restrict to findings whose CVE is on the CISA KEV list.",
    )
    fix_available_only: bool = Field(
        default=False,
        description="Restrict to findings whose ``fixed_versions`` is a non-empty array.",
    )
    search_query: str | None = Field(
        default=None,
        max_length=200,
        description="Substring match against vuln_id, component_name, title.",
    )
    finding_ids: list[int] | None = Field(
        default=None,
        description=(
            "Explicit finding IDs (overrides filter predicates when "
            "non-empty). Always intersected with the run's findings at the "
            "SQL layer for security."
        ),
    )
    label: str | None = Field(
        default=None,
        max_length=120,
        description=(
            "Human-readable scope label for the progress banner "
            "(e.g. 'Critical findings', 'Selected (12)'). The frontend "
            "supplies this; the backend stores it verbatim."
        ),
    )


def resolve_scope_findings(
    db: Session,
    *,
    run_id: int,
    scope: AiFixGenerationScope | None,
) -> list[AnalysisFinding]:
    """Resolve a scope spec into the concrete finding rows to process.

    Always constrains by ``analysis_run_id == run_id`` first. This is
    the security boundary: even if a malicious caller passes
    ``finding_ids`` for a different run, the WHERE clause filters them
    out — the result is the intersection.

    Returns an empty list if no findings match. Callers must handle the
    empty case (router returns 400 / "no findings in scope" message).
    """
    base = select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == run_id)

    if scope is None:
        return list(db.execute(base).scalars())

    # Explicit selection wins: filter to the requested IDs and stop.
    if scope.finding_ids:
        base = base.where(AnalysisFinding.id.in_(scope.finding_ids))
        return list(db.execute(base).scalars())

    if scope.severities:
        base = base.where(AnalysisFinding.severity.in_(scope.severities))

    if scope.kev_only:
        # KEV is a separate table keyed on cve_id == finding.vuln_id.
        # IN-subquery is portable across SQLite + Postgres; correlated
        # EXISTS would also work but is less readable here.
        base = base.where(
            AnalysisFinding.vuln_id.in_(select(KevEntry.cve_id))
        )

    if scope.fix_available_only:
        # ``fixed_versions`` is a JSON-array string; "[]" / "" / NULL all
        # mean "no fix available". Anything else is a non-empty array.
        base = base.where(
            and_(
                AnalysisFinding.fixed_versions.isnot(None),
                AnalysisFinding.fixed_versions != "",
                AnalysisFinding.fixed_versions != "[]",
            )
        )

    if scope.search_query:
        q = f"%{scope.search_query.strip()}%"
        base = base.where(
            or_(
                AnalysisFinding.vuln_id.ilike(q),
                AnalysisFinding.component_name.ilike(q),
                AnalysisFinding.title.ilike(q),
            )
        )

    return list(db.execute(base).scalars())


def count_cached_for_finding_ids(
    db: Session,
    *,
    finding_ids: list[int],
) -> int:
    """Count how many of the given findings have a fresh cached AI fix.

    Single SQL statement joining ``ai_fix_cache`` against
    ``analysis_finding`` on the natural cache-key dimensions
    (``vuln_id``, ``component_name``, ``component_version``). Used by the
    pre-flight estimate endpoint, which must respond in <200ms p95 even
    for 10k-finding scopes — the previous per-finding grounding loop
    couldn't meet that target.

    The count is "fresh" by virtue of:
      * The cache layer evicts on schema_version mismatch at read time,
        not at this count level. So this number is an upper bound on
        actual cache hits at batch run time. The drift between count
        and actual hits is small in practice (schema bumps are rare and
        flush a wide swath of rows when they happen).
      * Expired rows are NOT excluded here. The cache layer's read path
        handles expiry. For a count this is acceptable — the user sees
        "6 already cached" and the batch may regenerate one of them
        because it expired between estimate and run. The estimate is a
        best-effort heuristic, not a contract.

    Returns 0 for an empty ``finding_ids`` list.
    """
    if not finding_ids:
        return 0

    # Inner: distinct (vuln_id, component_name, component_version) tuples
    # from the requested findings. AiFixCache shares those exact column
    # names — the cache key dimensions are denormalised onto the cache
    # row at write time, so we don't need to recompute the sha256 hash.
    sub = (
        select(
            AnalysisFinding.vuln_id,
            AnalysisFinding.component_name,
            AnalysisFinding.component_version,
        )
        .where(AnalysisFinding.id.in_(finding_ids))
        .distinct()
        .subquery()
    )
    stmt = (
        select(func.count())
        .select_from(AiFixCache)
        .where(
            AiFixCache.vuln_id == sub.c.vuln_id,
            AiFixCache.component_name == sub.c.component_name,
            AiFixCache.component_version == sub.c.component_version,
        )
    )
    return int(db.execute(stmt).scalar() or 0)


__all__ = [
    "AiFixGenerationScope",
    "SeverityLiteral",
    "count_cached_for_finding_ids",
    "resolve_scope_findings",
]
