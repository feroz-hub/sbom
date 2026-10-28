# Repair Workspace UI redesign

Target: `/repair/:sessionId` (Next.js route parameter is named `workspaceId`).

## 1. Files changed for this task

- `frontend/src/app/repair/[workspaceId]/page.tsx`: compact breadcrumb and workspace sizing; reset workspace state on session change.
- `frontend/src/components/sboms/ValidationRepairWorkspace.tsx`: workflow layout and retained session/draft/action orchestration.
- `frontend/src/components/sboms/ValidationRepairWorkspace.test.tsx`: existing regression coverage adapted and new workflow checks.
- `frontend/src/components/sboms/SbomAutoRepairPanel.tsx`: optional disabled prop to prevent candidate actions during unsaved edits or active workspace operations; default behavior unchanged.
- `frontend/src/components/sboms/repair/RepairIssueNavigator.tsx`: structured issue navigation.
- `frontend/src/components/sboms/repair/RepairQualitySummary.tsx`: compact quality summary and findings dialog.
- `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx`: existing large-file viewer/search/line-patch editor extracted into a working pane.
- `frontend/src/lib/repairIssuePresentation.ts`: presentation-only error titles, deterministic guidance, classification matching and source location mapping.
- `frontend/src/lib/repairIssuePresentation.test.ts`: source mapping and issue presentation tests.
- This report.

Other pre-existing working-tree changes for logical SBOM version management are separate from this redesign.

## 2. Existing components found

The existing workspace included a full-draft textarea, a chunked large-file viewer with line patching, session metadata, validation status, quality findings, deterministic automatic repair, AI patch review, and repair history. `SbomQualityPanel` remains unchanged for other screens. The existing `SbomAutoRepairPanel` and shared accessible `Dialog` are reused for candidate review.

## 3. Layout changes

Compact filename/format/status header, free-navigation three-step workflow aid, compact quality indicators, approximately 32/68 desktop issue/editor panes, and sticky Save draft/Revalidate/Import actions. Large metadata and redundant validation status cards were removed. The working area has a minimum height so short viewports cannot collapse the editor beneath its toolbar. Neutral surfaces and HCL blue highlight selection; error/warning colors are localized.

## 4. Issue navigator

Severity, short code, known human-readable title, truncated location, concise explanation, selected guidance and actual primitive current value. Search and All/Errors/Warnings/Auto-fixable/Manual review filters use returned validation severities and repair classifications. Empty automatic repair options are disabled. Raw validator messages, full paths, original codes and stage/spec information remain available under collapsed Technical details. Selection uses stable code/path/severity keys and survives edits and removal of unrelated issues.

## 5. Editor integration

The full draft remains the existing plain textarea. It now has synchronized actual line numbers, selected-line highlighting and text search. Unsupported format/undo/redo APIs were not introduced. Large files retain server-backed chunk retrieval, search, paging and explicit line-patch persistence. Download original, draft and validation report remain available in Editor utilities.

## 6. Go to issue

Valid JSON paths and JSON pointers are mapped to exact offsets in the original editor text, including arrays, repeated keys, escaped pointer keys and Unicode. The editor selects the actual value and scrolls to its actual line; no line numbers are invented. An in-range validator-reported line is a fallback. Large-file reported lines fetch the corresponding chunk; path-only issues search the existing server search facility and ask the user to verify the full path. Unmappable locations offer Copy path. XML/SPDX paths without a reliable text mapping retain this honest fallback.

## 7. Revalidation and import

Revalidate remains the main working action and saves a full-editor draft using the existing update token before calling the existing validation API. Large-file revalidation validates saved patches without sending an empty textarea. Active requests disable duplicate actions. Refreshed reports replace the issue list while the editor remains mounted. Successful validation shows a success state and makes Import the primary action. Invalid, incomplete, busy, unassigned or locally edited drafts show the relevant disabled-import explanation.

Two frontend defects were corrected: Unicode byte counts incorrectly appeared as unsaved edits, and local edits could leave Import enabled based on an earlier validation. Dirty state now compares text against its loaded/saved baseline, and local edits require successful revalidation before import. Backend import gates are unchanged.

## 8. Session metadata

Filename, detected format, size, line count, session UUID and original/draft SHA-256 values are collapsed under SBOM Information. Destination project remains a visible import-preparation control using the existing update API. Repair History remains available in a separate collapsed disclosure.

## 9. Responsive behavior

Desktop panes use approximately 32/68 proportions; tablet panes approximately 38/62. Small screens use Issues/Editor tabs instead of narrow parallel columns. Headers wrap, filenames/paths truncate with full values available via titles/details, technical values wrap, and quality labels remain readable in a three-column mobile summary. Focus mode maximizes the workspace, hides secondary metadata and quality, and retains issues plus revalidation/import controls.

## 10. Accessibility

Named regions and controls, native keyboard-operable buttons/selects/disclosures, visible focus styles, accessible import helper text, polite status feedback, Previous/Next controls and Alt+Up/Down issue navigation. Mobile tabs support Left/Right/Home/End and roving tab focus. Focus mode provides dialog semantics, Tab containment and Escape exit; existing review dialogs retain the shared dialog's focus handling. The editor remains directly keyboard accessible.

## 11. Verification

59 focused Vitest tests passed across workspace, source mapping, existing automatic repair and existing quality panel suites. Coverage includes failed sessions, exact source selection, persisted selection, filters/classifications, fallback copying, draft saving, revalidation/report refresh, disabled/enabled import, Unicode dirty state, project assignment, original/report downloads, focus mode, mobile keyboard navigation, security-blocked sessions, partial chunks, large-file navigation and duplicate validation prevention.

TypeScript `tsc --noEmit` passed. Targeted ESLint passed without warnings.

Browser verification used the actual components with isolated API fixtures, not a live production session. Checked desktop 1440×900, tablet 900×900 and mobile 390×844, plus the initial 1280×720 viewport. Verified source selection of `"PACKAGE-MANAGER"`, actual line 24, focus mode and mobile tabs. No horizontal document overflow was observed on mobile or tablet. Real-server import was not performed during visual verification.

## 12. Production build

`npm run build` passed using Next.js 16.3.4/Turbopack, including TypeScript, all 47 static pages and the dynamic repair route. Built an isolated copy of the current frontend with a local public API URL and the existing dependency installation; no live development output or production configuration was changed.

## 13. Business logic preservation

This task changed frontend presentation and interaction only. Validation rules, engine/error models, repair APIs, import behavior, safe/manual repair classification, candidate approval behavior, permissions, session security, hash integrity and audit/logging were not modified. Safe repair review uses explicitly returned AUTO_FIX classifications; MANUAL_ONLY findings never offer safe repair. Existing candidate approval still imports the candidate, and the review dialog explains that consequence. Separate earlier backend changes already present in the working tree are not part of this UI task.
