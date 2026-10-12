# Premium portfolio Dashboard

## Reuse assessment

The starting Dashboard already had canonical summary, hierarchy filters, inventory
KPIs, lifetime KPIs, severity, trend, lifecycle/health/VEX summaries and advanced
analytics. Its main limitation was presentation: two KPI rows, large health detail
cards, and prioritization content ahead of the basic overview.

This implementation reuses `DashboardFilters`, `CounterTiles`, `LifetimeStats`,
`SeverityChart`, `FindingsTrendChart`, `Surface`, React Query, Recharts, Lucide,
HCL theme tokens and the existing CVE detail dialog. No parallel metrics layer,
new visualization library, inferred values, or AI workflow was introduced.

New presentation components:

- `PortfolioOverview`: severity bars, compact completeness/lifecycle/VEX summaries,
  high-priority finding rows and recent analysis runs.
- `PortfolioTrend`: tenant/hierarchy-keyed 7/30/90-day selector around the existing
  chart. The initial 30-day series comes from the summary; other windows use the
  existing trend endpoint.

## Hierarchy and retained functionality

Title/subtitle → filters → effective AI status → six canonical KPI cards → severity
and trend charts → portfolio health → operational tables → advanced intelligence.
Six KPIs share a row at 1536px and wider; smaller screens use three, two or one
column. Lifecycle/health cards wrap at tablet sizes. Operational tables contain
horizontal scrolling inside their card where needed, rather than page overflow.

Advanced intelligence retains HeroPostureCard, WhatsNewStrip, QuickActionsV2,
CopilotPanel, VulnerabilityAgePie, TopVulnerableSboms, TrendExplorer, ForecastCard,
ExploitationOutlookCard, RemediationPanel, PortfolioRiskMap, RiskMatrixCard and
ActivityFeed. The complete original lifecycle/health/VEX detail component remains
in a secondary disclosure. Existing scope-dependent Copilot visibility is retained.
No Version Posture notice, duplicate tenant label, or replacement posture banner
is added. Tenant context remains in the sidebar.

## Metric provenance and honesty

| Presentation | Source and convention |
|---|---|
| Stored SBOMs / scanned projects / analyzed SBOMs | Existing `summary.posture` inventory fields |
| Current findings | `posture.total_findings`, canonical current-posture/latest-successful-run set |
| Completed analysis runs | `lifetime.runs_completed_total` (OK/FINDINGS/PARTIAL); missing evidence shows a dash |
| Monitoring duration | Existing `days_monitoring` / `first_run_at` |
| Severity donut and bars | Same `posture.severity`, including Unknown in the denominator |
| Trend | Existing distinct-active-as-of-day history; not raw row sums or invented snapshots |
| SBOM Completeness | Existing `health.completeness_score`; not a new composite quality grade |
| Lifecycle | Independent existing counts; categories can overlap |
| VEX donut | Mutually exclusive effective affected/investigating/not-affected/fixed/unknown counts |
| Requires action | Separate operational count, excluded from the donut denominator |

The completed-run tile now opts into the existing successful-run field instead of
using the all-executed counter under a completed label. Its shared component keeps
the previous default for other callers. No metric calculation changes.

VEX contexts and analyzer findings have different denominators. Olympus currently
has 108 analyzer findings and 110 effective VEX contexts; Requires Action is 109.
These are not forced to agree. No percentage changes are invented. The existing
seven distinct scan-day trend readiness policy is preserved. A short history is
identified explicitly. Changing windows shows loading/unavailable states rather
than previous-window data or zero-valued loading legend counts.

## API and security

Existing APIs reused: `/dashboard/summary`, `/dashboard/runs`, `/dashboard/trend`,
filter-option APIs, effective analysis configuration, and existing CVE detail APIs.

New read-only `GET /dashboard/priority-findings?limit=5`:

- Uses the existing DashboardScope and latest-successful-run helper.
- Additional `analysis:read` gate alongside existing dashboard authorization.
- Selects only required finding columns; no raw reports or enrichment.
- Orders severity (Critical → High → Medium → Low → Unknown), then descending
  CVSS, then ascending stable finding ID.
- SQL limit defaults to 5 and is bounded to 20. No client-side unbounded fetch.
- Returns stored finding instances; repeated CVEs on different components remain
  separate, consistent with the canonical finding metric.

Query keys contain tenant and hierarchy. New finding-detail state remounts on scope
changes. Mapped rows use exact run/component/finding context in the shared dialog;
unmapped rows use global advisory details instead of an arbitrary component.
The existing CVE modal feature flag is honored. No new mutation or AI permissions.

No lifecycle, designation, lineage, VEX reconciliation, assignment, current-posture
selection, source-coverage calculation or database schema changes. No migration.

## Validation and limitations

See the verification section below for executed evidence. The provided attachment
contains only text; the referenced generated image was not available. Visual
validation follows the requested hierarchy and dimensions, not a claimed pixel
comparison to an unavailable reference.

Live browser verification uses the existing Olympus session. Other tenant/permission
combinations are exercised with automated synthetic fixtures; no claim of live
multi-role or live MedTech testing. Browser extension warnings (including Grammarly
injected hydration attributes) are distinguished from application defects.

Local execution helpers in `/tmp` isolate PostgreSQL tests and build output. They
are not repository deliverables. Production build occurs in an ignored isolated
checkout so it does not corrupt the running development server's `.next` files.

Commands using normal repository tooling:

```bash
.venv/bin/python -m pytest -q tests/test_dashboard_priority_findings.py tests/test_dashboard_scope.py tests/test_dashboard_posture_evidence.py tests/test_vex_lifecycle_completion.py tests/test_vex_version_lifecycle.py
.venv/bin/python -m ruff check app/metrics/findings.py app/routers/dashboard_main.py tests/test_dashboard_priority_findings.py tests/test_dashboard_scope.py
cd frontend
npm test
npx tsc --noEmit
npm run lint
npm run build -- --webpack
```

Use a disposable test database for backend tests; no production migration or writes.

### Executed verification (2026-10-09)

- Focused backend dashboard/scope/posture/VEX lifecycle: **77 passed, 0 failed**.
  The new priority endpoint has 8 tests, including deterministic order, SQL limit,
  latest clean-run replacement, four hierarchy scopes, cross-tenant ownership,
  missing permissions and a single-query (no N+1) assertion.
- Full frontend: **1,435 passed in 174 files, 0 failed**.
- Application TypeScript: passed.
- Changed Python lint: four files passed. Python compile/import validation passed.
- Frontend lint: **0 errors, 53 existing warnings**; no new warnings in the new
  overview components. Repository-wide backend suite was not rerun for this UI task.
- `git diff --check`: passed.
- Browser: Olympus metric values verified; 7-day period switching, shared CVE
  details, expanded/collapsed sidebar, light/dark themes, 1920px/1440px desktop,
  768px tablet and 390px mobile checked. No document horizontal overflow.
- Wide layout: six KPI cards in one row, approximately 124px high; primary charts
  approximately 341px high. Real completeness is 82%; current severity is
  Critical 17, High 58, Medium 31, Low 2 (total 108).

The initial scope-suite setup error was a stale synthetic Core insert missing the
required logical SBOM identity. Its fixture now creates that identity explicitly;
no production compatibility or lifecycle logic was changed. Initial new-test
missing timestamps were corrected in the synthetic run fixture. Final runs above
have no failures. A temporary overlap of local test runners was discarded and the
final backend suite was run alone against the disposable database.
- Final isolated **Webpack production build passed** (including its TypeScript
  validation). No production deployment, commit, push or migration was performed.

Task-specific files: `app/metrics/findings.py`, `app/routers/dashboard_main.py`,
`frontend/src/app/page.tsx`, `frontend/src/app/globals.css`,
`frontend/src/lib/api.ts`, `frontend/src/components/dashboard/SeverityChart.tsx`,
`frontend/src/components/dashboard/FindingsTrendChart/FindingsTrendChart.tsx`,
`frontend/src/components/dashboard/LifetimeStats/LifetimeStats.tsx`,
`frontend/src/components/dashboard/PortfolioOverview.tsx`,
`frontend/src/components/dashboard/PortfolioTrend.tsx`,
`frontend/src/components/dashboard/PortfolioOverview.test.tsx`,
`frontend/src/app/__tests__/dashboard-drilldown.integration.test.tsx`,
`tests/test_dashboard_priority_findings.py`, `tests/test_dashboard_scope.py`,
and this document. Existing uncommitted lifecycle and prior UI work is retained.
