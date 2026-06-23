"""findings.forecast — projected findings trajectory + velocity anomaly.

Builds on ``findings.daily_distinct_active`` (Convention B series, spec
§3.4) — the forecast is a *derived view* of that locked series, never a
new query shape. Ordinary least squares over the last ``history_days``
daily totals, projected ``horizon_days`` forward with a ±1.96·σ residual
band. Honest by construction:

* ``insufficient_history=True`` until ≥ 7 days carry data — a regression
  over 2 points is a coin toss and the FE renders an empty-state instead.
* The band widens with residual noise; a flat noisy series projects flat.
* ``days_to_zero`` only appears when the slope is credibly negative.

Anomaly detection is a z-score on the day-over-day delta of the same
series (|z| ≥ 2 and |Δ| ≥ 3 to clear the noise floor) — "you added 40
findings yesterday against a ±4 baseline" is the headline use-case.

Math helpers are module-level and pure so the unit tests exercise them
without a DB session.
"""

from __future__ import annotations

import math
from datetime import UTC, date, datetime, timedelta

from sqlalchemy.orm import Session

from .cache import memoize_with_ttl
from .findings import findings_daily_distinct_active

# Minimum days that actually carry a snapshot before we draw a line.
_MIN_HISTORY_DAYS = 7
# Anomaly gates: z-score threshold and absolute-delta noise floor.
_ANOMALY_Z = 2.0
_ANOMALY_MIN_DELTA = 3
# Cap on the days_to_zero claim — beyond a year the line is fiction.
_DAYS_TO_ZERO_CAP = 365


def linear_fit(xs: list[float], ys: list[float]) -> tuple[float, float, float, float]:
    """OLS fit ``y = slope·x + intercept``.

    Returns ``(slope, intercept, r_squared, residual_std)``. Pure function —
    unit-tested directly in ``tests/metrics/test_forecast_math.py``.
    """
    n = len(xs)
    if n < 2 or n != len(ys):
        return (0.0, ys[0] if ys else 0.0, 0.0, 0.0)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    sxx = sum((x - mean_x) ** 2 for x in xs)
    if sxx <= 1e-12:
        return (0.0, mean_y, 0.0, 0.0)
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
    slope = sxy / sxx
    intercept = mean_y - slope * mean_x
    ss_tot = sum((y - mean_y) ** 2 for y in ys)
    residuals = [y - (slope * x + intercept) for x, y in zip(xs, ys, strict=True)]
    ss_res = sum(r * r for r in residuals)
    r_squared = 0.0 if ss_tot <= 1e-12 else max(0.0, 1.0 - ss_res / ss_tot)
    residual_std = math.sqrt(ss_res / (n - 2)) if n > 2 else 0.0
    return (slope, intercept, r_squared, residual_std)


def velocity_anomaly(totals: list[int]) -> dict:
    """Z-score of the latest day-over-day delta vs the prior deltas.

    Pure function. Returns ``{detected, zscore, delta, baseline_mean,
    baseline_std}``; ``detected`` requires |z| ≥ 2 *and* |Δ| ≥ 3 so a
    1→3 wobble on a tiny portfolio doesn't page anyone.
    """
    empty = {
        "detected": False,
        "zscore": None,
        "delta": 0,
        "baseline_mean": 0.0,
        "baseline_std": 0.0,
    }
    if len(totals) < 4:
        return empty
    deltas = [b - a for a, b in zip(totals, totals[1:], strict=False)]
    latest = deltas[-1]
    baseline = deltas[:-1]
    n = len(baseline)
    mean = sum(baseline) / n
    var = sum((d - mean) ** 2 for d in baseline) / n
    std = math.sqrt(var)
    if std <= 1e-9:
        # Perfectly flat baseline: any jump ≥ the noise floor IS the anomaly
        # (z would be infinite). zscore stays None — there is no finite score.
        return {
            **empty,
            "detected": bool(abs(latest - mean) >= _ANOMALY_MIN_DELTA),
            "delta": latest,
            "baseline_mean": round(mean, 2),
        }
    z = (latest - mean) / std
    return {
        "detected": bool(abs(z) >= _ANOMALY_Z and abs(latest) >= _ANOMALY_MIN_DELTA),
        "zscore": round(z, 2),
        "delta": latest,
        "baseline_mean": round(mean, 2),
        "baseline_std": round(std, 2),
    }


def findings_forecast(
    db: Session,
    *,
    history_days: int = 30,
    horizon_days: int = 14,
    today: date | None = None,
) -> dict:
    """findings.forecast — projected distinct-active trajectory.

    History comes from :func:`findings_daily_distinct_active` (its own
    15-min memo absorbs the heavy query); the fit + projection here is
    O(history). Memoised 15 min on the same invalidation tuple.
    """
    end = today or datetime.now(UTC).date()

    def _compute() -> dict:
        return _forecast_uncached(db, history_days, horizon_days, end)

    return memoize_with_ttl(
        name="findings.forecast",
        ttl_seconds=15 * 60,
        db=db,
        key_extra=(history_days, horizon_days, end.isoformat()),
        compute=_compute,
    )


def _forecast_uncached(db: Session, history_days: int, horizon_days: int, end: date) -> dict:
    points = findings_daily_distinct_active(db, days=history_days, today=end)
    totals = [p.total for p in points]
    history = [{"date": p.date, "total": p.total} for p in points]

    days_with_data = sum(1 for t in totals if t > 0)
    payload: dict = {
        "history": history,
        "history_days": history_days,
        "horizon_days": horizon_days,
        "insufficient_history": days_with_data < _MIN_HISTORY_DAYS,
        "projection": [],
        "slope_per_day": 0.0,
        "r_squared": 0.0,
        "current_total": totals[-1] if totals else 0,
        "projected_total": None,
        "days_to_zero": None,
        "anomaly": velocity_anomaly(totals),
        "schema_version": 1,
    }
    if payload["insufficient_history"]:
        return payload

    xs = [float(i) for i in range(len(totals))]
    ys = [float(t) for t in totals]
    slope, intercept, r_squared, resid_std = linear_fit(xs, ys)
    band = 1.96 * resid_std

    projection = []
    last_idx = len(totals) - 1
    for step in range(1, horizon_days + 1):
        x = float(last_idx + step)
        y = slope * x + intercept
        d = (end + timedelta(days=step)).isoformat()
        projection.append(
            {
                "date": d,
                "projected": round(max(0.0, y), 1),
                "lo": round(max(0.0, y - band), 1),
                "hi": round(max(0.0, y + band), 1),
            }
        )

    payload["projection"] = projection
    payload["slope_per_day"] = round(slope, 3)
    payload["r_squared"] = round(r_squared, 3)
    payload["projected_total"] = projection[-1]["projected"] if projection else None

    if slope < -1e-6 and totals[-1] > 0:
        dtz = math.ceil(totals[-1] / -slope)
        payload["days_to_zero"] = int(dtz) if dtz <= _DAYS_TO_ZERO_CAP else None

    return payload


__all__ = ["findings_forecast", "linear_fit", "velocity_anomaly"]
