# Dashboard v4 — Advanced Analytics

Status: shipped (additive on top of dashboard v3 — nothing existing moved or changed)
Date: 2026-06-10

Four capability clusters appended to the home dashboard. Every number is
served by `app/metrics/` (conventions per `docs/metric-conventions.md`);
no inline metric SQL exists in the new routers (F9 lock applies).

## 1. Predictive risk engine

**Endpoint:** `GET /dashboard/forecast?history_days=30&horizon_days=14`
**Metric:** `findings.forecast` (`app/metrics/forecast.py`) — Convention B
derived: a pure transform over the locked `findings.daily_distinct_active`
series, never a new query shape.

- OLS fit over the last `history_days` daily totals; projection carries a
  ±1.96·σ residual band (`lo`/`hi` per point).
- `insufficient_history=true` until ≥7 days carry data — the FE renders an
  empty state instead of a 2-point regression. `r_squared` is exposed so a
  noisy fit reads as noisy.
- `days_to_zero` appears only for a credibly negative slope, capped at 365.
- `anomaly` — z-score of the latest day-over-day delta vs the prior deltas
  (|z| ≥ 2 AND |Δ| ≥ 3). A zero-variance baseline falls back to the
  absolute-delta floor (`zscore: null`) so "flat for 29 days, +40
  yesterday" still fires.

## 2. Exploitation outlook

**Endpoint:** `GET /dashboard/exploitation`
**Metric:** `portfolio.exploitation_outlook` (`app/metrics/exploitation.py`)
— Convention A scope (latest successful run per SBOM).

- EPSS scores are 30-day exploitation probabilities, so the portfolio
  outlook composes as `P = 1 − Π(1 − pᵢ)` over the distinct in-scope CVE
  set. The independence assumption is stated in the payload
  (`assumption: "independent"`) and on the card.
- Reads ONLY the local `epss_score` mirror (missing = 0, same as the
  scorer); `coverage` exposes the scored fraction so low coverage gets an
  explicit caveat instead of silent under-reporting.
- KEV is surfaced separately (`kev_cves` + per-driver flag): observed
  exploitation outranks any model. On large portfolios the gauge
  saturates → the FE renders ">99.9%", which is the honest answer; the
  driver list explains why.

## 3. Remediation & SLA analytics

**Endpoint:** `GET /dashboard/remediation`
**Metric:** `remediation.summary` (`app/metrics/remediation.py`).

- Lifecycles derive from per-SBOM run timelines walked in monotonic run-id
  order (ADR-0001): first run containing a `finding_key` opens a period,
  first subsequent run missing it closes one (duration in days), presence
  in the latest run means active (age = today − first_seen). Reopens are
  counted. Cross-SBOM, an active key dedupes to its OLDEST period — the
  conservative read for SLA.
- SLA budgets default to CISA-BOD-19-02-flavoured windows: critical 7d,
  high 30d, medium 90d, low 180d (unknown borrows medium). `due_soon`
  begins at 75% of budget. Budgets are a parameter — a settings surface
  can override without touching the module.
- `velocity` — distinct keys first seen in the last 30d vs periods closed
  in the last 30d, with the net direction.
- MTTR = mean resolved-period duration per severity (null until a tier
  has at least one resolved lifecycle).

## 4. Interactive risk geometry

**Endpoints:** `GET /dashboard/risk-map`, `GET /dashboard/risk-matrix?limit=300`
**Metrics:** `portfolio.risk_map`, `portfolio.risk_matrix`
(`app/metrics/riskmap.py`) — Convention A scope.

- Treemap cells: size = latest-run finding count (off the denormalised
  `analysis_run` columns — reconciles with run-detail by construction),
  colour = worst severity present. Deliberately NO composite score — the
  opaque Risk Index stays retired (`docs/risk-index.md`).
- Matrix points: one per distinct finding (Convention B identity, max
  CVSS kept), x = max EPSS across the finding's CVEs, y = CVSS, KEV and
  fix-availability as modifiers. The cap keeps KEV > EPSS > CVSS first so
  it never drops what matters; `unplotted_no_cvss` is reported.

## 5. AI Security Copilot

**Endpoints:** `GET /api/ai/copilot/briefing[?force=true]`,
`POST /api/ai/copilot/ask {"question": "..."}`
**Service:** `app/ai/copilot.py`; router `app/routers/ai_copilot.py`.

- Grounding: a compact (~2 KB) JSON snapshot assembled EXCLUSIVELY from
  `app.metrics` calls — posture, net-7d, forecast summary, exploitation
  outlook, remediation summary, top-risk SBOMs. No SBOM file contents, no
  component inventories, no credentials.
- The model is instructed to cite only snapshot numbers; briefing ≤250
  words, answers ≤180.
- Briefing cache: in-process, keyed on the metrics invalidation tuple
  (max run id, run count, sbom count), 6h TTL — a new run busts it; a
  quiet portfolio never re-bills.
- Cost & gating: same rollout gate as AI fixes (`evaluate_access`),
  pre-flight `BudgetGuard.check_request`, post-call ledger rows in
  `ai_usage_log` (purposes `copilot_briefing` / `copilot_ask`) — visible
  on `/admin/ai-usage`. Errors map to the FE's typed handling:
  429 `AI_BUDGET_EXCEEDED`, 502 `AI_PROVIDER_ERROR`, 403/404 gate-closed
  (panel hides).

## Frontend

New components under `frontend/src/components/dashboard/advanced/`:
`CopilotPanel`, `ForecastCard`, `ExploitationOutlookCard`,
`PortfolioRiskMap`, `RiskMatrixCard`, `RemediationPanel`. Sections are
appended to `app/page.tsx`; v3 order is untouched.

Query keys: `['dashboard-forecast']`, `['dashboard-exploitation']`,
`['dashboard-remediation']`, `['dashboard-risk-map']`,
`['dashboard-risk-matrix']`, `['copilot-briefing']` — all folded into
`invalidateDashboardTiles` so analysis completion busts the v4 surface
with the classic tiles. The Copilot ask mutation is marked
`@no-invalidation-needed` (read-only probe); briefing regenerate uses
`setQueryData` on `['copilot-briefing']`.

## Tests

`tests/test_dashboard_v4_metrics.py` (marker `metric_consistency`):
pure-math (fit/anomaly/composition/SLA boundaries), seeded lifecycle
semantics (MTTR/overdue/velocity), exploitation composition with seeded
EPSS+KEV, risk map/matrix scope checks, and a 200-smoke over all five
endpoints. The F9 direct-query lock and the FE mutation-invalidation lock
both cover the new code.

## Honesty rules (carried from the v3 redesign)

- No invented composite scores; size/colour/probability are all directly
  observable or sourced from public models (EPSS/KEV) with caveats shown.
- Insufficient data → explicit empty states, never extrapolation.
- The Copilot cites snapshot numbers only and its spend is on the ledger.
