# VEX Integration

VEX (Vulnerability Exploitability eXchange) records whether a product or
product context is affected by a specific vulnerability. It does not answer
whether the component version is supported. Lifecycle status and VEX status are
stored and displayed separately.

## Status Values

- `affected`: the vulnerability applies to this product context.
- `not_affected`: the vulnerability does not apply to this product context.
- `fixed`: the product/component context is remediated.
- `under_investigation`: impact is still being assessed.
- `unknown`: no reliable VEX statement exists.

## Evidence Rules

- `not_affected` requires a justification or impact statement.
- `fixed` requires a fixed version or evidence/impact statement.
- `under_investigation` is never treated as fixed.
- VEX never suppresses vulnerability records silently. It changes
  exploitability/remediation priority while preserving the underlying finding.
- Manual VEX override requires a reason and writes `vex_override_audit`.

## Supported Inputs

- CycloneDX JSON `vulnerabilities[].analysis` and `affects[]`.
- OpenVEX-style JSON with `statements[]`.
- CSAF/VEX JSON documents with `document`, `product_tree`, and
  `vulnerabilities` sections.
- Embedded CycloneDX vulnerability analysis in trusted imported SBOMs.
- Manual internal VEX overrides via API.

Unsupported VEX formats return `422` instead of being partially trusted.

CSAF product references are matched to SBOM components by PURL, CPE, bom-ref or
component id, component name/version, then supplier/name/version. Unmatched CSAF
statements are stored with low confidence and remain visible in reports; they
are never dropped silently.

Vendor-hosted discovery is best effort. It reads VEX/CSAF/OpenVEX-looking URLs
from SBOM and component external references, uses short HTTP timeouts, caches
responses for 24 hours, and records source URL plus discovery evidence on the
VEX document. Discovery errors are returned to the caller and stored as provider
error metadata when a document is imported; failed discovery does not block SBOM
upload or normal analysis.

## APIs

- `POST /api/sboms/{sbom_id}/vex`: import a VEX JSON document.
- `GET /api/sboms/{sbom_id}/vex`: list stored VEX statements.
- `POST /api/sboms/{sbom_id}/vex/discover`: refresh vendor-hosted VEX
  discovery and import discovered documents.
- `GET /api/sboms/{sbom_id}/vex/report?format=json|csv`: detailed VEX report
  for export/UI. `report_type` can filter `affected`, `not_affected`, `fixed`,
  `under_investigation`, or `unknown`.
- `GET /api/sboms/{sbom_id}/reports/vex-pack`: ZIP pack with JSON and focused
  CSV reports.
- `PATCH /api/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override`: audited manual override.
- `GET /api/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override/history`: manual override audit history.
- `GET /dashboard/vex`: portfolio VEX counts and top affected components.

Upload, discovery, report export, and manual override actions require an
`admin` or `security` role when auth is enabled. Local `API_AUTH_MODE=none`
keeps developer/test behavior permissive.

## Dashboard Semantics

`not_affected` and `fixed` are counted as vulnerabilities reduced by VEX. They
are not the same as "no vulnerability found." `affected`,
`under_investigation`, and `unknown` remain action/review queues.

## Known Limitations

- Vendor-hosted discovery is manual (`POST /vex/discover`) unless a deployment
  wires the service function into a background scheduler.
- VEX statements are matched to components by bom-ref, PURL, CPE, component id,
  or component name. Ambiguous product-level statements are retained but may not
  link to a component id.
- VEX does not modify lifecycle status.
