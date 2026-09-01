"""Portfolio-wide vulnerability listing, grouped by ownership.

Backs the Analysis hub's "Vulnerabilities" tab, which the dashboard severity
pie links into. The pie is portfolio-scoped (``findings.latest_per_sbom.*``)
but its click used to route to a single analysis run, so the destination showed
a fraction of the number the user clicked — 77 of 289 High, for example. This
endpoint keeps the two on the same scope by construction: it reads the same
metric family, so a slice and the list it opens can only ever agree.

Per ``CLAUDE.md`` the numbers come from ``app.metrics`` — no finding/run SQL
here (enforced by
``tests/test_metric_consistency.py::test_no_new_direct_finding_or_run_queries_outside_metrics``).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .. import metrics
from ..db import get_db

log = logging.getLogger("sbom.api.vulnerabilities")

router = APIRouter(prefix="/api", tags=["vulnerabilities"])


@router.get("/vulnerabilities")
def list_vulnerabilities(
    severity: str | None = Query(
        None,
        description=(
            "Filter to one canonical severity bucket (critical / high / medium / low / "
            "unknown). Omit for every severity."
        ),
    ),
    page: int = Query(1, ge=1),
    page_size: int = Query(500, ge=1, le=2000),
    db: Session = Depends(get_db),
):
    """Findings in each SBOM's latest successful run, with ownership attached.

    Each row carries its project, product and SBOM so the client can group the
    list without a second round-trip. Ordered by descending CVSS score, so the
    first page is the part worth reading when the result set is truncated.
    """
    try:
        result = metrics.findings_latest_per_sbom_grouped_by_scope(
            db,
            severity=severity,
            limit=page_size,
            offset=(page - 1) * page_size,
        )
    except ValueError as exc:
        # Unknown severity label — a client bug or a hand-edited URL. 422 keeps
        # it distinguishable from "valid filter, no matches".
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        "severity": severity,
        "page": page,
        "page_size": page_size,
        **result,
    }
