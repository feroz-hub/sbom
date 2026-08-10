"""Dashboard v4 — advanced analytics endpoints.

Routes (all additive; nothing existing changes):
  GET /dashboard/forecast       projected findings trajectory + velocity anomaly
  GET /dashboard/exploitation   portfolio P(≥1 CVE exploited, 30d) via EPSS
  GET /dashboard/remediation    MTTR, SLA countdowns, fix velocity
  GET /dashboard/risk-map       treemap cells (one per SBOM, latest run)
  GET /dashboard/risk-matrix    impact × exploitability scatter points

Scoping follows ADR-0001 (latest successful run per SBOM unless stated).
**Every number comes from ``app.metrics`` — no inline metric SQL here**
(docs/dashboard-metrics-spec.md §8; enforced by
tests/test_metric_consistency.py).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy.orm import Session

from .. import metrics
from ..db import get_db
from ..etag import maybe_not_modified

log = logging.getLogger("sbom.api.dashboard_advanced")

router = APIRouter(prefix="/dashboard", tags=["dashboard-advanced"])


@router.get("/forecast")
def dashboard_forecast(
    request: Request,
    response: Response,
    history_days: int = Query(30, ge=14, le=90, description="OLS fit window."),
    horizon_days: int = Query(14, ge=7, le=60, description="Projection length."),
    db: Session = Depends(get_db),
):
    """Projected distinct-active findings trajectory (metrics ``findings.forecast``).

    Derived from the locked daily-distinct-active series; carries
    ``insufficient_history`` so the FE renders an empty state instead of a
    two-point regression. The velocity ``anomaly`` envelope is the
    "something unusual landed yesterday" signal.
    """
    payload = metrics.findings_forecast(db, history_days=history_days, horizon_days=horizon_days)
    nm = maybe_not_modified(request, response, payload)
    if nm is not None:
        return nm
    return payload


@router.get("/exploitation")
def dashboard_exploitation(request: Request, response: Response, db: Session = Depends(get_db)):
    """Portfolio exploitation outlook (metrics ``portfolio.exploitation_outlook``).

    EPSS-composed probability that at least one in-scope CVE is exploited
    within 30 days, with coverage + top drivers so the gauge stays honest.
    """
    payload = metrics.portfolio_exploitation_outlook(db)
    nm = maybe_not_modified(request, response, payload)
    if nm is not None:
        return nm
    return payload


@router.get("/remediation")
def dashboard_remediation(request: Request, response: Response, db: Session = Depends(get_db)):
    """MTTR / SLA / velocity envelope (metrics ``remediation.summary``)."""
    payload = metrics.remediation_summary(db)
    nm = maybe_not_modified(request, response, payload)
    if nm is not None:
        return nm
    return payload


@router.get("/risk-map")
def dashboard_risk_map(request: Request, response: Response, db: Session = Depends(get_db)):
    """Treemap cells, one per analysed SBOM (metrics ``portfolio.risk_map``)."""
    payload = metrics.portfolio_risk_map(db)
    nm = maybe_not_modified(request, response, payload)
    if nm is not None:
        return nm
    return payload


@router.get("/risk-matrix")
def dashboard_risk_matrix(
    request: Request,
    response: Response,
    limit: int = Query(300, ge=10, le=1000, description="Max scatter points."),
    db: Session = Depends(get_db),
):
    """Impact × exploitability scatter (metrics ``portfolio.risk_matrix``)."""
    payload = metrics.portfolio_risk_matrix(db, limit=limit)
    nm = maybe_not_modified(request, response, payload)
    if nm is not None:
        return nm
    return payload
