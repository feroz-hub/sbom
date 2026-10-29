# SBOM Analyzer — Manual UI Test Plan

These are reproducible procedures, not recorded passes. Labels, routes and guards
were checked against source e62951c2 on 29 October 2026; **all browser, timing,
provider and data-dependent outcomes remain unverified until exercised**.
Use the [testing guide](docs/testing/README.md) for isolated automated suites.

The original plan's upload, project, validation, analysis, compare, export and
linkage coverage is retained below. Outdated expectations are identified rather
than silently carried forward.

## Navigation

[Fixtures and setup](#0-fixtures-and-evidence) ·
[Dashboard](#2-dashboard-mt-01) · [Projects](#3-project-and-application-mt-02) ·
[Uploads and validation](#4-uploads-and-validation-mt-03-to-mt-06) ·
[SBOM detail](#5-sbom-detail-mt-07) ·
[Runs and exports](#6-analysis-runs-and-exports-mt-08-to-mt-10) ·
[Compare](#7-compare-runs-mt-11) · [Re-analysis](#8-re-analyse-mt-12) ·
[PDF](#9-pdf-report-mt-13) · [Linkage](#10-project-linkage-mt-14) ·
[Finish](#11-finish-and-optional-cleanup-mt-15) ·
[Checklist](#pass-criteria-and-result-record) · [Troubleshooting](#troubleshooting)

## 0. Fixtures and evidence

Use an authorized disposable test environment, synthetic records and a controlled
recipient/capture service. Record source revision, OS/profile, nonsecret target
identity, role/tenant, fixture hash, selected providers and enabled features.
Do not use a populated application/production database or change authentication
to bypass a blocked scenario.

| Fixture | Intended exercise |
| --- | --- |
| [CycloneDX multi-ecosystem](samples/cyclonedx-multi-ecosystem.json) | File selection, format detection, validation, components and eligible analysis. |
| [SPDX web application](samples/spdx-web-app.json) | SPDX detection, validation, import and the same downstream checks. |
| Private local copy with a required field removed | Negative validation: for example, remove top-level specVersion from a CycloneDX copy. Never modify the canonical fixture. |

Names do not prove current validity, exact component counts or vulnerability
findings. Record the actual validation/provider outcome. If a sample is rejected,
complete the negative/repair checks and use a separately approved valid fixture
for positive analysis/export cases.

Keep evidence and downloads private and redacted. Do not commit raw HAR files,
cookies, authorization headers, activation links, screenshots of real accounts,
customer SBOMs or report contents to the public repository.

## 1. Start the stack and sign in

Read [development setup and platform limits](docs/development/README.md), then
the [database compatibility gate](docs/DATABASE_BOOTSTRAP_AND_UPGRADE.md).
Start can write configuration/data and apply or propose migrations.

From the repository root with the configured Python 3.11+ executable:

    python scripts/dev.py --check --profile legacy
    python scripts/dev.py start --profile legacy

Use greenfield only for the intended installed macOS environment. Keep the
foreground terminal; use a second terminal for status/stop. Do not start the
shared home-directory Greenfield stack from another worktree.

Open https://localhost:13000 after reviewing local trust. API origin:
http://127.0.0.1:18000. Check database availability in /health, /ready/iam and real
BFF sign-in. --check or an HTTP 200 alone does not establish acceptance.

Use the approved test enrollment/login flow. Confirm tenant selection and
permissions for project/application creation, SBOM upload, analysis and export.
Record disabled/hidden unauthorized actions as expected restrictions; do not
grant broader roles merely to obtain a pass.

Historical setup expectations retired: machine-specific paths, the port-8001
workaround and the claim that cross-env is missing. cross-env is already declared;
repair an incomplete lockfile installation using the testing/development guides.

## 2. Dashboard (MT-01)

1. Open the application root after sign-in. Record the active tenant and selected
   Project/Application/SBOM filters.
2. Observe portfolio counters, severity distribution, lifecycle/posture evidence,
   recent activity and trend surfaces that the selected role/data make available.
3. Change one scope filter, then clear it. Verify labels, totals and drill-downs
   refer to the same scope and accepted evidence.
4. Inspect console/network failures without exporting secret-bearing captures.

Expected from source: counters and charts use the scoped dashboard summary, with
empty, unavailable, partial and stale states retained where applicable. No fixed
widget set, nonzero count or vulnerability-free result is guaranteed. Unexpected
request failures should be recorded; not every permission-gated request is
expected to return 200.

Source: [dashboard page](frontend/src/app/page.tsx) and
[metric conventions](docs/metric-conventions.md).

## 3. Project and Application (MT-02)

1. Open /projects and choose **New Project**.
2. Enter a unique synthetic **Project Name**, **Details**, and **Status**.
   Choose **Create Project**. Verify the new row appears without a forced reload.
3. Use the row action **Edit project**, update Details and choose **Save Changes**.
   Verify the row/detail reflects the update. Keep this project for later tests.
4. Select the project and use its **Applications** panel, then **Create Application**.
   Enter a synthetic Name and the required fields shown for the selected category;
   choose **Create Application** and verify its Project association.
5. Record the Project and Application public identifiers from links/copy controls,
   separately from human-readable display labels.

Expected from source: create/update invalidates the relevant lists; actions remain
permission-gated. The current UI uses **Details** for Project text and requires an
Application for upload; the old project-only setup is incomplete.

Sources: [ProjectModal](frontend/src/components/projects/ProjectModal.tsx),
[ProjectApplications](frontend/src/components/projects/ProjectApplications.tsx),
[Application form](frontend/src/components/products/ProductFormDialog.tsx).

## 4. Uploads and validation (MT-03 to MT-06)

### MT-03 — CycloneDX upload

1. Open /sboms and **Upload SBOM**.
2. Select the synthetic **Project** and **Application** from MT-02.
3. For the first upload, create a new logical SBOM rather than selecting an
   existing one. Enter a unique **SBOM Name** and **SBOM Version** such as 1.0.0;
   record optional Product Version. There is no current Created By input.
4. Choose **Upload from file** and select the CycloneDX fixture. Observe the
   filename, preview and detected format/version. Leave **SBOM Type / Format**
   at Auto-detect unless the test explicitly covers manual override.
5. Confirm the name suggestion is editable. Detection uses selected/pasted
   content; filename extension alone is not authoritative. The browser preview
   can be truncated while the full file is sent to backend validation.
6. Leave **Set as current SBOM** unchecked unless the test explicitly authorizes
   changing the Application's designated current version and schedule scope.
7. Choose **Upload SBOM** and record the response, validation status, toast and
   destination. For an accepted upload, find the row and retain its public ID.

Expected from source: validated/warning uploads can close the dialog; failed or
unsupported documents can open Repair Workspace; pending/enrichment outcomes
can remain visible. Upload success does not guarantee immediate analysis,
two toasts, a particular row order, finding count or a 30–120 second completion.
Backend-detected metadata and the actual status are the test evidence.

### MT-04 — SPDX upload

Repeat MT-03 with the SPDX fixture and a separate logical SBOM/name. Confirm
content-based SPDX detection, actual validation and the same Project/Application
association. Run downstream cases only for accepted, processing-eligible records.
Do not assume its component count or analysis outcome matches CycloneDX.

### MT-05 — Duplicate revision and version history

1. Reopen the upload dialog and select the same Project/Application.
2. In **SBOM**, select the existing logical SBOM from MT-03.
3. Enter its already used SBOM Version. Verify the existing-version message and
   disabled submission; do not bypass the control or alter existing records.
4. Change to a new revision, upload only if this scenario is authorized, and
   verify prior versions remain available in **Version History**.

Expected from source: uniqueness is checked in the selected logical SBOM/version
context. Typing the same name and tabbing away is not the old global duplicate
name check. Explicitly independent logical SBOM creation is a different operation;
do not invent a universal name-only conflict.

### MT-06 — Required fields and rejected content

1. Open a new empty dialog. Verify submission remains disabled without Project,
   Application, a nonblank name and file/content.
2. Fill fields incrementally and confirm submission only becomes available when
   prerequisites and version-history queries are satisfied. Cancel without writes.
   Do not require the old “SBOM content is required” inline error on a disabled form.
3. Upload the private invalid copy from section 0 with the required selections.
   Record the actual error code, failed stage and persisted validation/repair
   outcome. It must not be represented as a valid imported inventory item.
4. If editing is permitted, open Repair Workspace, inspect errors/full content,
   make an explicit test repair and revalidate. Import only after successful
   validation and explicit confirmation. Security/signature restrictions must
   not be bypassed.
5. Check that the original upload remains available where the workflow promises
   it and that an error is not replaced by a fabricated successful status.

Sources for MT-03–06:
[upload modal](frontend/src/components/sboms/SbomUploadModal.tsx),
[upload handler](app/routers/sbom_upload.py),
[validation guide](docs/sbom-validation.md) and
[repair workspace](docs/sbom-validation-repair-workspace.md).

## 5. SBOM detail (MT-07)

1. Follow the accepted SBOM's link to /sboms/{sbom_id}; use its full public UUID,
   not a display integer.
2. In **Overview & Risk**, verify Name, Product/Application, Project, format/type,
   recorded versions and available dates match the accepted record.
3. Open **Components List**; compare names, versions, PURLs/ecosystems and count
   with the actual parsed fixture and reconciliation evidence. Inspect at least
   one component and exercise available search/filter controls.
4. Inspect **Normalization**, **Version History**, validation and **Analysis Runs**
   as relevant. Verify warnings, unavailable evidence and historical status remain
   visible rather than becoming zero or successful state.
5. Repeat for the accepted SPDX record.

Source: [SbomDetail](frontend/src/components/sboms/SbomDetail.tsx).
The original fixed “six or more libraries” expectation is unverified and is not
an acceptance threshold. Risk/severity totals require an analysis, not just upload.

## 6. Analysis runs and exports (MT-08 to MT-10)

### MT-08 — Start analysis and inspect run detail

1. For an accepted, eligible SBOM, choose **Run Analysis** from its detail page,
   or use the consolidated analysis selection and **Run analysis** on /analysis.
2. Record the allowed sources, selected SBOM public ID and new run public ID.
   Observe progress and the terminal or blocked outcome; do not enable additional
   providers or disclose keys to make a finding appear.
3. On /analysis, inspect the resulting run's SBOM, Project/Application, status,
   findings, severity, source evidence and available time/duration. Clear filters
   and check paging if a known run is absent.
4. Follow /analysis/{run_id}. Inspect findings for available vulnerability ID,
   component/version, severity, source, CVSS, match evidence and fixed versions.
   Verify filters/drill-downs preserve scope; unavailable fields remain explicit.
5. Repeat for the other eligible fixture if the intended scenario needs two runs.

Current status codes include PENDING, RUNNING, OK, FINDINGS, PARTIAL, ERROR and
NO_DATA; interrupted evidence can also be rendered. Labels vary by surface.
The old forced ANALYSING-to-COMPLETED sequence is not a current universal
contract. FINDINGS is a completed analysis with findings; PARTIAL is incomplete
coverage and must not imply vulnerability-free status, even with zero findings.

Sources: [consolidated analysis](frontend/src/components/analysis/ConsolidatedAnalysisPanel.tsx),
[run list](frontend/src/components/analysis/RunsTable.tsx),
[run detail](frontend/src/app/analysis/[id]/page.tsx),
[status labels](frontend/src/lib/analysisRunStatusLabels.ts).

### MT-09 — SARIF export

1. From an eligible run detail, open **Export → SARIF**.
2. Save only the synthetic report to the private test evidence location.
3. Verify JSON parses, version is 2.1.0 and a runs array contains the expected
   results collection; an empty results array can be valid for a zero-finding run.
4. Check representative rule/component references against this run, not an
   unrelated scan or the current filtered page. Record unauthorized/unavailable
   outcomes separately.

The filename can end in .sarif; do not require the old .sarif.json suffix.

### MT-10 — CSV export

1. From the same run choose **Export → CSV** and parse it as CSV, not by splitting
   on commas. Check quoted descriptions, Unicode and empty optional fields.
2. Verify headers and representative vulnerability/component/severity/source
   values against the export's full run scope.
3. Reconcile rows to the findings selected by the export contract, not merely the
   visible page/filter. Record any scope/count difference for investigation.

Sources for exports: [run detail menu](frontend/src/app/analysis/[id]/page.tsx),
[export handlers](app/routers/analysis.py). Export is not permission to publish
the resulting data to the public repository.

## 7. Compare runs (MT-11)

1. Open /analysis/compare and select two distinct, eligible runs using the pickers
   or the comparison action from run history.
2. Preserve the generated URL. run_a and run_b contain public UUIDs; the original
   numeric run_a=1/run_b=2 example is obsolete.
3. Inspect selected run identities, relationship/scope and available severity/
   posture summaries. In Findings, exercise added, resolved, severity-changed and
   unchanged filters. Review Components separately.
4. Swap baseline/current and confirm direction is reflected. Clear filters and
   enable unchanged findings where appropriate before comparing totals.
5. Select the same run on both sides as a negative case. The current v2 surface
   shows a same-run guard; do not expect a normal empty-diff result.
6. For two distinct runs whose retained results are equivalent, verify the
   no-change/identical-results state and shared findings where applicable.

Added/Removed/Common were the original broad expectations. Current findings use
resolved/unchanged categories, while component removals are a separate concept.
Different SBOMs need not produce a substantial difference. Outcomes depend on
actual run evidence. An enabled v1 fallback has different fidelity: record the
banner and use its declared contract rather than asserting v2 parity.

Sources: [CompareView](frontend/src/components/compare/CompareView.tsx),
[URL state](frontend/src/hooks/useCompareUrlState.ts),
[compare runbook](docs/runbook-compare.md).

## 8. Re-analyse (MT-12)

1. Return to an eligible SBOM and record its existing run public IDs.
2. Choose **Run Analysis** again. Record the newly returned run ID and outcome;
   verify the previous run remains in history.
3. Once both runs are eligible, select them for MT-11 and verify baseline/current
   attribution. A provider change can change findings; identical results are also
   valid and no fixed duration is promised.

The old Re-analyse/Analyze again wording has been replaced by the current detail
button label. Do not reuse a display label as a run lookup key.

## 9. PDF report (MT-13)

1. From an eligible run detail choose **Export → PDF report**, or the run list's
   available **Download PDF** action.
2. Confirm a PDF downloads and opens; verify it represents the selected run/SBOM,
   available timestamp, severity summary and representative finding details.
3. Reconcile declared report scope with persisted synthetic results and record
   missing/partial information. Cover-page styling, pagination and exact layout
   are live visual checks, not verified by this documentation revision.
4. Confirm ineligible records remain guarded and an unauthorized context cannot
   obtain the report. Do not regenerate an ineligible record's report to bypass
   its processing restriction.

Sources: [run detail](frontend/src/app/analysis/[id]/page.tsx),
[PDF handler](app/routers/pdf.py).

## 10. Project linkage (MT-14)

1. Return to /projects, select the synthetic project and inspect Applications.
2. Open the Application used by both uploads. Verify accepted SBOMs/versions are
   associated with it and the same Project. Check the SBOM detail association.
3. Distinguish stored versions, latest/head and designated Current SBOM in counts
   and selectors. Rejected validation sessions must not inflate accepted inventory.
4. Verify create/edit/upload updates appear without a forced reload.

Source: [ProjectApplications](frontend/src/components/projects/ProjectApplications.tsx).
The current hierarchy is Project → Application/Product → logical SBOM/versions;
do not expect a project-only flat list to replace this hierarchy.

## 11. Finish and optional cleanup (MT-15)

Record results before disposal. Cleanup is optional and requires authorization for
the exact synthetic records. If permitted, use ordinary tenant-aware UI actions
for those SBOMs, Applications and Project in dependency order; respect guards,
audit and retention behavior. Record a refusal rather than force deletion.
Otherwise retain the fixture and mark cleanup not run.

The original direct SQLite-file deletion instruction is retired from runnable
guidance. Do not wipe a database, volume, private state or unrelated test record.
The complete original plan is retained in controlled local review artifacts.

Stop only this checkout's launcher-owned processes using the matching profile:

    python scripts/dev.py stop --profile legacy

Stop preserves data services and volumes. No cleanup was executed in this
documentation phase.

## Pass criteria and result record

Each scenario needs its own PASS, FAIL, BLOCKED or NOT RUN result with source
revision, fixture/target, public IDs, commands/actions and redacted evidence.
Feature/permission/provider prerequisites that are absent are BLOCKED or NOT RUN,
not inferred passes. Do not publish test identities or captured payloads.

- [ ] MT-01: dashboard scope, charts, empty/error/evidence states
- [ ] MT-02: project create/edit and prerequisite Application
- [ ] MT-03 / MT-04: CycloneDX and SPDX uploads with recorded validation outcomes
- [ ] MT-05: duplicate revision guard and preserved version history
- [ ] MT-06: required-field gating and rejected/repair workflow
- [ ] MT-07: SBOM metadata, components and evidence
- [ ] MT-08: explicit analysis, run history/detail and actual statuses
- [ ] MT-09 / MT-10: SARIF and CSV content and full export scope
- [ ] MT-11: distinct-run compare, filters/direction and same-run guard
- [ ] MT-12: re-analysis creates a new run and retains old evidence
- [ ] MT-13: PDF content, visual review and access restrictions
- [ ] MT-14: Project/Application/SBOM linkage and refresh behavior
- [ ] MT-15: results preserved; optional authorized cleanup or explicit not-run

Additional role/VEX/remediation, scheduling and mail cases remain in their
[feature requirements](docs/requirements/vex-dashboard-investigation.md) and
[report operations](docs/runbook-report-notifications.md). Legacy worker alone
omits reports; Greenfield's periodic schedule is restricted. Do not start another
Beat or enable real recipients merely to complete a checkbox.

## Troubleshooting

| Symptom | Source-aware next check |
| --- | --- |
| Loading/API connection failure | Verify selected profile, API/BFF upstream and database/IAM readiness; do not adopt an old machine's port workaround. |
| Missing upload actions or disabled submit | Check permissions, Project/Application, file/content, name and version-history state. |
| Duplicate conflict | Inspect selected logical SBOM and revision; do not delete another record to reuse its name. |
| Validation or size rejection | Read actual stage/code and configured upload limits; the old fixed 20 MB claim is obsolete. |
| Analysis pending, partial or failed | Inspect allowed providers, coverage and worker evidence. Never treat partial/no data as clean. |
| Missing run/compare | Clear scope/paging filters, use public UUIDs and distinct processing-eligible runs. |
| Export unavailable/fails | Check role, eligibility, selected run and captured error without sharing data or tokens. |
| Missing cross-env | Repair the documented dependency install; it is already declared. |
| Port conflict | Inspect the owner via documented lifecycle diagnostics; do not kill unrelated listeners. |

Use [operations troubleshooting](docs/operations/troubleshooting.md) for logs,
trust, ownership and migration refusals. This plan certifies neither production
nor other OS/device/accessibility behavior without their own observed acceptance.
