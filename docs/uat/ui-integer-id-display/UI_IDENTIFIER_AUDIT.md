# UI identifier audit

Starting branch and local/remote HEAD: `feat/native-user-management` / `bf078cd3c136b027f77586fd9c180d9741ecf076`. Source inspection precedes implementation. No live database observation is inferred from the historical revision-101 report.

| Location | Classification and planned treatment |
|---|---|
| `frontend/src/components/reports/ReportNotificationsPage.tsx:72` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:73` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:136` | Sensitive IAM/tenant identity; use authorized name or descriptive fallback; no integer disclosure |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:144` | Separate domain ID or counter; preserve |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:146` | Separate domain ID or counter; preserve |
| `frontend/src/components/reports/ReportNotificationsPage.tsx:149` | Separate domain ID or counter; preserve |
| `frontend/src/app/analysis/page.tsx:108` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/analysis/page.tsx:152` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/products/[id]/page.tsx:50` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/products/[id]/page.tsx:224` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/products/[id]/page.tsx:272` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/analysis/[id]/page.tsx:148` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/analysis/[id]/page.tsx:251` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/analysis/[id]/page.tsx:252` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/analysis/[id]/page.tsx:255` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/component-advisor/components/[key]/page.tsx:111` | Separate domain ID or counter; preserve |
| `frontend/src/app/component-advisor/components/[key]/page.tsx:198` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/ai-fixes/GlobalAiBatchProgress/GlobalAiBatchBanner.tsx:110` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/analysis/compare/_v1/page.tsx:50` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/analysis/compare/_v1/page.tsx:305` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/component-advisor/recommendations/[id]/page.tsx:70` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/component-advisor/recommendations/[id]/page.tsx:89` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/component-advisor/recommendations/[id]/page.tsx:194` | Separate domain ID or counter; preserve |
| `frontend/src/components/dashboard/ActivityFeed.tsx:232` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/schedules/ScheduleCard.tsx:141` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/schedules/ScheduleCard.tsx:404` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/compare/IdenticalRunsCard/IdenticalRunsCard.tsx:70` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/compare/IdenticalRunsCard/IdenticalRunsCard.tsx:71` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/compare/CompareView.tsx:85` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/docs/sbom-validation-errors/page.tsx:151` | DOM/SVG anchor; preserve |
| `frontend/src/app/schedules/page.tsx:126` | Sensitive IAM/tenant identity; use authorized name or descriptive fallback; no integer disclosure |
| `frontend/src/app/schedules/page.tsx:127` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/schedules/page.tsx:129` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/schedules/page.tsx:132` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/app/schedules/page.tsx:179` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/vex/VexDecisionEditor.tsx:204` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/admin/UserSearchCombobox.tsx:165` | Sensitive IAM/tenant identity; use authorized name or descriptive fallback; no integer disclosure |
| `frontend/src/components/compare/states/CompareStates.tsx:73` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/compare/states/CompareStates.tsx:88` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/compare/states/CompareStates.tsx:116` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/admin/TenantUsersAccess.tsx:254` | Sensitive IAM/tenant identity; use authorized name or descriptive fallback; no integer disclosure |
| `frontend/src/components/admin/TenantUsersAccess.tsx:367` | Sensitive IAM/tenant identity; use authorized name or descriptive fallback; no integer disclosure |
| `frontend/src/components/admin/TenantUsersAccess.tsx:382` | Sensitive IAM/tenant identity; use authorized name or descriptive fallback; no integer disclosure |
| `frontend/src/components/admin/TenantUsersAccess.tsx:394` | Sensitive IAM/tenant identity; use authorized name or descriptive fallback; no integer disclosure |
| `frontend/src/components/admin/TenantUsersAccess.tsx:406` | Sensitive IAM/tenant identity; use authorized name or descriptive fallback; no integer disclosure |
| `frontend/src/components/admin/TenantMembersTable.tsx:29` | Sensitive IAM/tenant identity; use authorized name or descriptive fallback; no integer disclosure |
| `frontend/src/components/analysis/RunDetailHero.tsx:270` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/analysis/RunDetailHero.tsx:339` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:173` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:217` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/compare/SelectionBar/RunPicker.tsx:220` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/dashboard/FindingsTrendChart/FindingsTrendChart.tsx:322` | DOM/SVG anchor; preserve |
| `frontend/src/components/analysis/SbomPreflightChecklist.tsx:130` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/dashboard/PortfolioOverview.tsx:129` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/ui/Select.tsx:168` | DOM/SVG anchor; preserve |
| `frontend/src/components/analysis/AnalysisProgress.tsx:196` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/ui/Sparkline.tsx:101` | DOM/SVG anchor; preserve |
| `frontend/src/components/projects/ProjectApplications.tsx:98` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/projects/ProjectApplications.tsx:99` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/dashboard/TrendChart.tsx:224` | DOM/SVG anchor; preserve |
| `frontend/src/components/analysis/ConsolidatedAnalysisPanel.tsx:116` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/analysis/VulnerabilitiesByScope.tsx:51` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/analysis/VulnerabilitiesByScope.tsx:52` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/analysis/VulnerabilitiesByScope.tsx:273` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/projects/ProjectsTable.tsx:84` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/projects/ProjectsTable.tsx:389` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/analysis/RunsTable.tsx:86` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/analysis/RunsTable.tsx:334` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/analysis/RunsTable.tsx:345` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/analysis/RunsTable.tsx:349` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/analysis/RunsTable.tsx:357` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/sboms/ComponentVexManager.tsx:30` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/sboms/ComponentVexManager.tsx:43` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/sboms/ComponentVexManager.tsx:66` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/layout/Sidebar.tsx:512` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/layout/Sidebar.tsx:565` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/sboms/SbomConversionCard.tsx:272` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/sboms/SbomDetail.tsx:685` | Separate domain ID or counter; preserve |
| `frontend/src/components/sboms/SbomDetail.tsx:1076` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/sboms/SbomDetail.tsx:1913` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/layout/CommandPalette.tsx:284` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/layout/CommandPalette.tsx:288` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/layout/CommandPalette.tsx:296` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/layout/CommandPalette.tsx:301` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/sboms/SbomsTable.tsx:54` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/sboms/SbomsTable.tsx:60` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |
| `frontend/src/components/sboms/SbomsTable.tsx:493` | Business record label; display persisted integer when projected; never derive from UUID; keep selector/key/link unchanged |

## Non-display identities

UUID-valued JSX keys, routes, hrefs, query/cache identities, option values, selection state and mutation arguments remain UUIDs. Source-native bom-ref/PURL/CPE/CVE, provider subjects, audit/correlation IDs, event IDs, roles, findings, recommendations and counters retain their contracts. All remaining `.id` and `String(id)` uses must be reviewed by semantic context, not replaced globally.

## Data sources

Output-only `display_id` for business resource objects; `<reference_without_id>_display_id` for authorized related references. These are captured from actual integers in the already-authorized HTTP projection, after existing scoped identity resolution. IAM Users, Tenants, Memberships and Platform Grants are excluded to avoid global sequential-key disclosure. Missing data renders a name or em dash.

## Additional complete-source pass

The evidence/identifier-occurrence-audit.json inventory classifies 1,565 frontend identity-related source lines (before implementation), including selectors, React keys, URL/cache controls, provider identities, and presentation candidates. A further literal-label search covered helpers/hooks as well as JSX. It found LiveAnalysisCard, useAnalysisStream pending labels and topVulnerableRuns fallbacks; these now use persisted display fields or descriptive text. Findings evidence and AnalysisStatusBadge accessibility labels were also corrected. Source-native document fields, provider model IDs, recommendation ranks/IDs, delivery/subscription IDs, correlation IDs and DOM/SVG references remain unchanged.

No main record label derives digits from a UUID. Explicit technical identity/copy actions remain allowed. Sensitive User/Tenant/Membership/Grant screens intentionally use names instead of sequential keys. Pure ID-only progress/error state has no persisted numeric DTO; it uses descriptive text and preserves the original UUID operation.

## Secondary presentation audit

- `app/services/report_composer.py::public_report_snapshot`: backend-rendered preview identity source; reuse existing tenant-scoped SBOM/Run batches for actual display siblings.
- `app/services/report_rendering.py::report_sections` and `render_email`: visible preview Run/SBOM cells use numeric labels; machine/export references and links retain canonical UUIDs. No stored artifact is modified.
- `frontend/src/components/layout/Sidebar.tsx`: old cached pin labels may contain their own UUID. Render the retained name or descriptive dash; do not change stored key, ID, href or serialized pin format.
- `frontend/src/lib/topVulnerableRuns.ts`: fallback SBOM labels use the returned persisted SBOM display ID, not the Run key.
- `frontend/src/components/sboms/SbomsTable.tsx`: the numeric ID cell itself links to the original UUID route; it does not introduce an integer route.
- Mobile application cards use the same numeric Project/Application/SBOM siblings as desktop. Native document/provider IDs, audit IDs, report-delivery IDs, finding IDs and counters retain their documented independent meanings.

A TypeScript AST comparison preserves all existing selector attributes and HTTP URL expressions in 48 changed frontend implementation files. The one additional reviewed href is the SBOM numeric-label link to `/sboms/${sbom.id}`. The existing `MetaTile.value` presentation property is excluded from selector comparison; its nested href remains checked.
