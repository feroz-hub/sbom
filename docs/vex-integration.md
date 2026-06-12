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
- Embedded CycloneDX vulnerability analysis in trusted imported SBOMs.
- Manual internal VEX overrides via API.

Unsupported VEX formats return `422` instead of being partially trusted.

## APIs

- `POST /api/sboms/{sbom_id}/vex`: import a VEX JSON document.
- `GET /api/sboms/{sbom_id}/vex`: list stored VEX statements.
- `GET /api/sboms/{sbom_id}/vex/report`: detailed VEX report for export/UI.
- `PATCH /api/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override`: audited manual override.
- `GET /dashboard/vex`: portfolio VEX counts and top affected components.

## Dashboard Semantics

`not_affected` and `fixed` are counted as vulnerabilities reduced by VEX. They
are not the same as "no vulnerability found." `affected`,
`under_investigation`, and `unknown` remain action/review queues.

## Known Limitations

- CSAF/VEX parsing is not implemented yet.
- Vendor-hosted VEX discovery is not automatic yet.
- VEX statements are matched to components by bom-ref, PURL, CPE, component id,
  or component name. Ambiguous product-level statements are retained but may not
  link to a component id.
- VEX does not modify lifecycle status.
