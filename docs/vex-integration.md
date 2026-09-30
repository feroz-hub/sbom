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

## Manual decisions for multiple vulnerabilities

Each manual decision applies to one component instance in one SBOM and one
vulnerability identifier. The form offers component-specific identifiers from
stored findings and VEX statements, plus an explicit manual-entry option.
Editing an existing statement locks its identity; choosing a different pair in
the new-decision form resets evidence and loads that pair's current decision
and history. Each save requires a reason and records the authenticated actor.

Statements remain append-only. Current lists, VEX reports, dashboard
counts, scheduled report metrics and FDA report decisions use the newest manual
decision per pair, otherwise the newest imported statement. Subsequent imports
do not replace manual decisions. Override history retains previous values.
Unmatched statements are retained as evidence and cannot reduce a different
component's risk. Bulk editing and override revocation are not offered by this
form; replace a manual decision by explicitly editing the same pair.

Focused checks (explicit disposable SQLite, no fallback enabled):

```sh
DATABASE_URL=sqlite:///:memory: AUTH_ENABLED=false .venv/bin/python -m unittest discover -s tests -p test_vex_decisions.py -v
```

### Component-first management

Every component row has a **Manage VEX** action, separate from the component
lifecycle **Edit** action. The searchable vulnerability table shows detected
findings (including match details), existing decisions, severity, source and
last-updated time. Add Decision, Edit, Override and History operate on the
selected vulnerability only. Add Vulnerability Manually supports externally
reported CVE, GHSA and vendor identifiers without a detected finding.

- `GET /api/sboms/{sbom_id}/components/{component_id}/vulnerabilities` returns
  the union of this component's analysis findings and existing VEX statements.
- `PATCH /api/sboms/{sbom_id}/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override`
  validates both tenant and SBOM ownership before appending one decision.
- `GET /api/sboms/{sbom_id}/components/{component_id}/vulnerabilities/{vulnerability_id}/vex-override/history`
  returns the current decision, full imported/manual statement history and the
  manual audit trail separately. Legacy pair endpoints remain compatible.

The analysis findings APIs and table expose effective VEX independently of
remediation status. Analysis CSV and SARIF exports include effective status and
source. No VEX action writes component lifecycle fields. Unmatched imported
statements remain evidence, not decisions for an arbitrarily chosen component.

### Role-aware investigation ownership

The investigation detail API (`GET /api/vex/investigations/{id}`, also returned
by `resolve`) supplies authoritative `capabilities`, eligible assignment
`candidates`, and a human-readable `owner`. The existing assignment endpoint
(`PUT /api/vex/investigations/{id}/assignment`) accepts one candidate's opaque
`id`, or explicit `null` to unassign, with `row_version` and a reason.
No separate user directory permission or duplicate assignment API is needed.

The existing `VexInvestigation.assigned_to` string stores `membership:<id>` for
new assignments, referring to a tenant membership rather than an email or
external identity. No new column or migration is required. Legacy free-text
owners are not automatically resolved or reassigned and confer no write access;
the UI flags them as inactive until an administrator or analyst assigns an
eligible membership.

| Actor | Assignment candidates | Investigation decisions |
| --- | --- | --- |
| Tenant Administrator | Active Security Analysts and Developers | Tenant records with existing VEX write permission |
| Security Analyst | Active Developers | Tenant records with existing VEX write permission |
| Developer | None | Own assigned record only |
| Viewer | None | Read-only |

Candidate and actor checks use database-authoritative active tenant roles and
usable, verified accounts. Multi-role users with Tenant Administrator are never
assignment candidates; a Security Analyst plus Developer is not a Developer-only
delegation target. Analysts may remove Developer assignments and clear inactive
owners, but may not remove an active Security Analyst assignment. They can
reassign to an eligible Developer. Platform administrators retain the existing
explicit database-grant override in a selected tenant, equivalent to Tenant
Administrator here. A platform-only identity is not an assignment candidate.

Developer retains `vex:read` and does **not** receive `vex:write` or a new catalog
permission. Only the exact investigation decision route passes the read gate;
the service then checks live tenant membership and current ownership on every
mutation. Component mapping, direct component overrides, and imports retain
broad write gates. Assignment fields in a decision request are rejected.
Changing or removing ownership immediately revokes the previous Developer's
access. Disabled, locked, removed, or role-ineligible assignees cannot mutate.

Mutation routes lock the investigation row before authorization/version checks.
Decision statement creation, reconciliation, and investigation audit updates
commit together. Assignment only changes ownership, timestamp and version; it
does not change VEX or reconciliation status. The existing append-only audit
stores previous/new ownership, actor and time; the detail history distinguishes
assignment, mapping and decision entries and limits history to the current
investigation/vulnerability.

## Shared investigation details

The VEX Investigation CVE link and Investigate action open the same
`CveDetailDialog` used by Run Analysis. Vulnerability Details reuses its
cached enrichment, severity/CVSS, aliases, references, KEV/EPSS, and available
fix information. A contextual VEX Investigation tab retains the existing
assignment, decision, mapping, and history workflows. No second CVE API or
VEX state model is introduced.

The selected investigation ID remains the write identity. The dialog retains
SBOM, component, project/application, analyzer, native VEX, effective status,
and reconciliation context. Scan enrichment optionally accepts `component_id`
and returns no component context when that component does not belong to the
scan's tenant/SBOM or has no matching finding. Unresolved investigations use
general advisory details and cannot save component-specific decisions; the
existing authorized mapping action remains available.

Existing server capabilities govern editing: administrators and analysts keep
their existing authority, developers may update only their assigned items,
and viewers remain read-only. Save invalidates investigation, table, and
dashboard queries without resetting filters. Existing fixed-version and
mitigation values are included in decision details and preserved when editing.
Tabs support arrow/Home/End navigation inside the existing focus-trapped,
Escape-dismissable dialog. CVE enrichment failure can be retried independently
of the investigation panel.
