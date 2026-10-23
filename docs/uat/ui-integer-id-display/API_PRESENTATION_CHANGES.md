# Read-only API presentation additions

Public `id`, path/query/body selectors and relationship references remain UUIDv4. The existing authorized public boundary now emits output-only persisted integer labels for Projects, Products, Logical SBOMs, SBOM Sources, SBOM Components and Analysis Runs. It does not change domain services or SQLAlchemy models.

| Existing public reference | Output-only presentation sibling |
|---|---|
| `id` | `display_id` |
| `project_id` / `projectid` | `project_display_id` |
| `product_id` | `product_display_id` |
| `sbom_id` | `sbom_display_id` |
| `latest_sbom_id` | `latest_sbom_display_id` |
| `current_sbom_id` | `current_sbom_display_id` |
| Other recognized business `<reference>_id` | `<reference>_display_id` |

Example: `{"id":"f5e7f4c4-8a16-4c70-93d8-092173885437","display_id":567}`. These fields originate from the same actual integer passed to scoped UUID resolution. They are emitted only after successful projection, on successful JSON responses. No extra database query is added, including for Latest/Current SBOM references. Missing or invalid/nonpositive/non-safe-integer values do not receive invented labels. Native document/metadata payloads retain their original contracts.

OpenAPI successful response DTOs document integer/null, minimum 1, readOnly presentation fields. UUID selector schemas are unchanged. JSON mutation inputs containing display fields are rejected with 422; they cannot become lookup aliases. Existing error projection remains UUID-based and gains no display fields. No route or privilege was added.

Tenant, IAM User, Membership and Platform Grant sequences are deliberately not projected, including related user/tenant fields. Authorized names/email/roles remain the primary IAM presentation. SBO-73 discovery remains unchanged. Source-native external identities, findings, audit events, recommendations, report deliveries, policies and counters retain their separate contracts.

## Operational and report boundaries

Operational AI progress envelopes under `/api/v1/runs/` and `/api/v1/scans/` retain their exact existing payloads; they do not receive display siblings. Persisted Analysis Run DTOs elsewhere receive their authorized numeric label. Worker, batch and SSE resource identities remain UUID/internal according to their prior contracts.

Backend-rendered report previews also contain visible Run/SBOM cells. The existing `public_report_snapshot` batches now carry display siblings from the same scoped rows. UI/email preview rendering opts into numeric labels, suppressing the tenant UUID in the primary reporting-window/footer presentation. Default PDF/XLSX sections, JSON metadata, scheduled-outcome map keys and machine references retain UUIDs. Historical stored artifacts are not rewritten. Missing labels show an em dash; they are never reconstructed from UUIDs.

## Observed response-schema additions

The task-owned OpenAPI output exposes these optional read-only siblings. They are additive to successful authorized responses; response validation still uses existing domain DTOs and the public boundary projects the display values afterward. Existing UUID selectors are unchanged.

| Response schema | Presentation fields |
|---|---|
| `AnalysisFindingOut` | `analysis_run_display_id`, `component_display_id` |
| `AnalysisRunOut` | `display_id`, `product_display_id`, `project_display_id`, `sbom_display_id` |
| `AnalyzerEvidenceSection` | `analysis_run_display_id` |
| `ComponentSection` | `component_display_id` |
| `InvestigationDetail` | `analysis_run_display_id`, `sbom_display_id` |
| `InvestigationRow` | `analysis_run_display_id`, `component_display_id`, `product_display_id`, `project_display_id`, `sbom_display_id` |
| `LatestAnalysisOut` | `run_display_id` |
| `LogicalSBOMOut` | `display_id`, `product_display_id` |
| `ProductRead` | `current_sbom_display_id`, `display_id`, `latest_sbom_display_id`, `project_display_id` |
| `ProductSummary` | `current_sbom_display_id`, `display_id`, `latest_sbom_display_id`, `project_display_id` |
| `ProjectOut` | `display_id` |
| `PublicRunReference` | `display_id`, `sbom_display_id` |
| `RunSummary` | `display_id`, `product_display_id`, `project_display_id`, `sbom_display_id` |
| `SBOMComponentListItem` | `display_id`, `duplicate_of_component_display_id`, `sbom_display_id` |
| `SBOMComponentOut` | `display_id`, `duplicate_of_component_display_id`, `sbom_display_id` |
| `SBOMSourceOut` | `converted_sbom_display_id`, `display_id`, `logical_sbom_display_id`, `product_display_id`, `project_display_id`, `source_sbom_display_id` |
| `SbomAcceptedResponse` | `logical_sbom_display_id`, `product_display_id`, `project_display_id`, `sbom_display_id` |
| `SbomConversionReportResponse` | `converted_sbom_display_id`, `source_sbom_display_id` |
| `SbomConversionResponse` | `converted_sbom_display_id`, `source_sbom_display_id` |
| `SbomDocumentStatsResponse` | `sbom_display_id` |
| `SbomRawChunkResponse` | `sbom_display_id` |
| `ScheduleOut` | `last_run_display_id`, `product_display_id`, `project_display_id`, `sbom_display_id` |
| `ScheduleTargetOut` | `product_display_id`, `project_display_id`, `sbom_display_id` |
| `ValidationReportResponse` | `sbom_display_id` |
| `VexTopAffectedComponent` | `component_display_id` |
| `VulnerabilityRemediationAuditOut` | `project_display_id` |
| `app__schemas__VulnerabilityRemediationOut__2` | `project_display_id` |

Dynamic/untyped JSON response paths use the same explicit entity classifier and scoped batching. The synthetic route tests exercise full lists, related Latest/Current SBOMs, error paths and operational-envelope exclusions. They do not turn arbitrary JSON `id` values, findings, audit events, external provider IDs or native documents into public database labels.
