# Runbook — debugging dashboard metric inconsistencies

**When to use this runbook:** a number on the dashboard, run-detail page, or
lifetime panel doesn't match another number that you'd expect to add up. This
is the structural bug class fixed in Phase 4 ([commit log](../CHANGELOG.md)).

**The rule it locks in:** every number on every surface comes from the
canonical metrics layer in [app/metrics/](../app/metrics/). If you find inline
metric SQL in a router file, that is the bug — not "fix the SQL", but "route
through the canonical layer".

---

## 1. Triage decision tree

Skim this before going deeper.

```
Is the contradiction between
two numbers on the dashboard,
or between dashboard and an API response?
│
├── Two surfaces show different numbers
│      → run pytest -m metric_consistency
│      → If it fails, the broken surface is the one that drifted
│      → Read §2 for the per-invariant playbook
│
├── Numbers feel wrong but don't contradict each other
│      → Likely cache staleness; jump to §3
│
├── Number is impossible (negative, exceeds total, > lifetime)
│      → Spec invariant has been violated; jump to §4
│
└── Number is correct but COPY is misleading
       → Frontend is reading the wrong field; jump to §5
```

---

## 2. Per-invariant playbook (matching `tests/test_metric_consistency.py`)

| Invariant | Test | Where to look first |
|---|---|---|
| I1 — hero severity Σ == total | `test_i1_*` | [findings.py::findings_latest_per_sbom_severity_distribution](../app/metrics/findings.py) |
| I2 — hero total == Σ latest-run totals | `test_i2_*` | check `latest_run_per_sbom_subquery` in [_helpers.py](../app/metrics/_helpers.py) |
| **I3 — hero KEV == Σ run KEVs (Bug 1 lock)** | `test_i3_*` | [kev.py](../app/metrics/kev.py); confirm both run-detail and dashboard call `findings_kev_in_scope` |
| **I4 — trend ≤ lifetime (Bug 3 lock)** | `test_i4_*` | [findings.py::findings_daily_distinct_active](../app/metrics/findings.py) — must use the as-of CTE, never sum raw rows |
| I5 — trend today == latest-state distinct | `test_i5_*` | the as-of CTE in `_helpers.py` |
| **I6 — lifetime ≥ max-run distinct (Bug 4 lock)** | `test_i6_*` | [findings.py::findings_distinct_lifetime](../app/metrics/findings.py) must JOIN on successful runs only |
| **I7 — lifetime runs == sidebar (Bug 2 lock)** | `test_i7_*` | [runs.py::runs_total_lifetime](../app/metrics/runs.py) |
| I8 — trend.runs_total == lifetime.runs_executed_total | `test_i8_*` | trend router exposes runs_total from canonical metric |
| **I9 — is_first_period flag (Bug 5 lock)** | `test_i9_*` | [windows.py::findings_net_change](../app/metrics/windows.py) |
| I10 — first_period.resolved == 0 | `test_i10_*` | same |
| I11 — resolved ≤ surfaced | `test_i11_*` | [services/dashboard_metrics.py::compute_findings_resolved_total](../app/services/dashboard_metrics.py) |
| I12 — per-run severity Σ == total | `test_i12_*` | writer-side invariant in `app/services/analysis_service.py` |

When a test fails, the failing assertion message names both numbers and which
surfaces produced them. Start by running the canonical metric directly in a
REPL against the affected DB — see §6.

---

## 3. Cache staleness checklist

Two cache layers serve dashboard reads:

* **`app/metrics/cache.py`** — TTL cache keyed on
  `(max(analysis_run.id), count(analysis_run), count(sbom_source))`. New runs
  bust the cache automatically.
* **`app/services/dashboard_metrics.py::_lifetime_cache`** — in-process,
  15-minute TTL, same invalidation tuple. Pre-existed the canonical layer.

Reset both:

```python
from app.services.dashboard_metrics import reset_lifetime_cache
reset_lifetime_cache()  # clears both layers
```

If a number still looks stale after the reset, the issue is upstream of cache
— the SQL itself or the data. Move on to §4.

---

## 4. Diagnosing impossible numbers

If you see something like "trend Σ > lifetime distinct" or "resolved >
surfaced", an invariant from spec §4 has been violated. Steps:

1. **Confirm with the consistency suite:**
   ```bash
   pytest -m metric_consistency -v
   ```
   The failing test names the invariant.

2. **Locate the metric.** Each canonical metric is one function in
   `app/metrics/`. The function's docstring references its catalog entry in
   `docs/dashboard-metrics-spec.md` §3.

3. **Check the SQL in isolation.** Drop into the REPL:
   ```python
   from app.db import SessionLocal
   from app import metrics
   db = SessionLocal()
   metrics.findings_kev_in_scope(db, scope="latest_per_sbom")
   ```

4. **Look for forbidden shapes.** From spec §8:
   * `select(func.count(AnalysisFinding.id))` JOIN-ed to `analysis_run` in a
     date window without the `latest_run_per_sbom` filter — that's Bug 3.
   * Two different KEV-membership clauses in the codebase — that's Bug 1.
   * `compute_net_7day_change` returning `tuple[int, int]` — that's Bug 5.
   * Inline metric SQL in a router file — that's the structural bug.

5. **Verify the test catches it.** Before fixing, write a failing test that
   reproduces. It belongs in `test_metric_consistency.py` if the violation
   was an invariant breach, or in a domain-specific test file otherwise.

---

## 5. "Number is right but copy is misleading"

The fix is rarely in the SQL — it's in the wire-shape or FE rendering.

Examples:

* **`+513 / −0` vs "first scan this week"** — the metric `findings_net_change`
  returns `is_first_period`; the FE
  [HeroMetricRow.tsx](../frontend/src/components/dashboard/HeroPostureCard/HeroMetricRow.tsx)
  must branch on it.
* **"1 run so far" with 4 same-day runs** — the FE used to count
  `populatedDays` from the trend payload. The fix exposes
  `runs_total` and `runs_distinct_dates` on `/dashboard/trend` and the FE
  reads those.

Add a check: if the FE component derives a metric from `points`, it is
probably wrong. The server should ship the metric directly.

---

## 6. REPL recipes

### Confirm I3 (the dashboard KEV lock)

```python
from app.db import SessionLocal
from app import metrics
from app.metrics._helpers import latest_run_per_sbom_subquery
from app.models import AnalysisRun
from sqlalchemy import select

db = SessionLocal()
latest = latest_run_per_sbom_subquery()
latest_run_ids = db.execute(
    select(AnalysisRun.id).where(AnalysisRun.id.in_(latest))
).scalars().all()

dashboard_kev = metrics.findings_kev_in_scope(db, scope="latest_per_sbom")
sum_run_kev = sum(
    metrics.findings_kev_in_scope(db, scope="run", run_id=r) for r in latest_run_ids
)
assert dashboard_kev == sum_run_kev, f"I3 BROKEN: {dashboard_kev} != {sum_run_kev}"
```

### Confirm I4 (trend ≤ lifetime)

```python
points = metrics.findings_daily_distinct_active(db, days=30)
lifetime = metrics.findings_distinct_lifetime(db)
max_in_trend = max((p.total for p in points), default=0)
assert max_in_trend <= lifetime, f"I4 BROKEN: trend max {max_in_trend} > lifetime {lifetime}"
```

### Confirm net_7day first-period

```python
from datetime import datetime, timedelta, UTC
from sqlalchemy import func
from app.metrics.base import COMPLETED_RUN_STATUSES

cutoff = (datetime.now(UTC).date() - timedelta(days=7)).isoformat()
prior_runs = db.execute(
    select(func.count(AnalysisRun.id))
    .where(AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES))
    .where(AnalysisRun.completed_on < cutoff)
).scalar()
result = metrics.findings_net_change(db, days=7)
print(f"prior_runs={prior_runs}  result={result}")
# is_first_period must be True iff prior_runs == 0
```

---

## 7. Adding a new metric

This is the procedure that prevents the bug class from coming back.

1. **Read the spec catalog first.**
   [docs/dashboard-metrics-spec.md](./dashboard-metrics-spec.md) §3 — pick an
   existing metric if it fits.
2. **If you must add one:** open a PR that updates the spec catalog *first*,
   with the metric ID, plain-English definition, exact SQL, scope, dedup key,
   reconciliation invariants, edge cases.
3. **Implement.** One function in the appropriate `app/metrics/<domain>.py`,
   referencing the spec entry in its docstring.
4. **Write the test.** If your metric has a reconciliation invariant with any
   existing metric, add a `metric_consistency` test for it. Even if it
   doesn't, write a unit test in the appropriate place.
5. **Wire it in.** Routers call canonical metrics — never inline SQL. If you
   need to add SQL, it goes in `app/metrics/_helpers.py` first.

PRs that violate this procedure should be rejected with a link to spec §8
(the deny list).

---

## 8. Post-deploy verification recipe

After shipping a metrics-affecting change to staging or production:

```bash
# 1. Hit each surface, dump the numbers.
curl -s $HOST/dashboard/posture | jq '{kev: .kev_count, total: .total_findings, severity: .severity, net: .net_7day}'
curl -s $HOST/dashboard/lifetime | jq
curl -s $HOST/dashboard/trend | jq '{points: (.points|length), runs_total, runs_distinct_dates}'

# 2. For each SBOM, dump latest-run KEV.
curl -s $HOST/api/sboms | jq '.[].latest_run_id' | while read run_id; do
  echo "run $run_id:"
  curl -s "$HOST/api/runs/$run_id/findings-enriched" | jq 'map(select(.in_kev)) | length'
done

# 3. Manually check I3: sum the per-run KEVs and compare to dashboard kev_count.
```

If the consistency tests pass in staging but a number on the live UI looks
wrong, the issue is almost certainly the FE bundle is older than the API and
hasn't picked up new fields like `net_7day` or `runs_total`. Hard-refresh the
browser cache and check the network tab.
