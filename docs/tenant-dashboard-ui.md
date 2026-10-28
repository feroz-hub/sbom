# Tenant dashboard UX refinement

The dashboard retains the existing summary API, query keys, URL scope parsing,
Project → Application → SBOM cascade, drill-down destinations and metric definitions.
No backend, migration, authorization or tenant-isolation changes were made.

- Compact scope toolbar with the active tenant badge and filter feedback.
- Inventory and Security & Analysis headings group the six existing KPIs.
- Rounded themed surfaces, responsive one/two/three-column layouts and meaningful
  zero captions. Monitoring remains days since first analysis, not schedule state.
- Empty inventory offers upload only with `sbom:upload`; filtered-empty inventory
  offers Clear filters rather than implying that the tenant has no uploads.
- Existing quick actions also respect active-context permissions.
- Quality completeness is suppressed when scoped inventory is empty. Populated
  scopes retain the backend's reported score; the current API does not provide
  per-score provenance or a separate count of quality-evaluated SBOMs.
- Lifecycle's primary risk count is explicitly EOL, not a sum of overlapping
  categories. Existing additional statuses and recommendations remain available.
- Lifecycle navigation uses the existing SBOM list, which exposes SBOM detail
  lifecycle reports. VEX navigation uses `/vex-investigation`.
- Primary summary errors have Retry; existing loading skeletons remain.

Verification: 28 focused dashboard tests passed. Full frontend suite: 1,195
passed, 8 skipped; the existing shared-session-store suite fails to start because
`redis-server` is absent (ENOENT). Lint: zero errors, 52 existing warnings.
TypeScript, production build and whitespace validation passed. Browser viewport checks were blocked
by the development certificate (`ERR_CERT_AUTHORITY_INVALID`); CSS-class tests
are not a substitute for real checks at 1920/1440/1024/768/390px.
