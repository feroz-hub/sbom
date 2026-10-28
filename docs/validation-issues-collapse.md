# Collapsible Validation Issues pane

Scope: `/repair/:sessionId`, frontend layout and issue readability only.

## Changed files

- `frontend/src/components/sboms/ValidationRepairWorkspace.tsx`: Hide/Show pane state, safe focus transfer, full-width editor grid, bounded shared pane height, current issue counts and retained mobile tabs.
- `frontend/src/components/sboms/repair/RepairIssueNavigator.tsx`: accessible Hide control, mobile Escape handling, expandable full Details, wrapping identifiers/copy location, unclamped explanations and independently scrolling list.
- Their respective `.test.tsx` files: adapted disclosure queries and added preservation, long-content and keyboard dismissal coverage.
- This report.

## Behavior

The navigator and editor stay mounted. Hiding applies CSS visibility and changes the shared grid to a single column; reopening restores the split. Search, filter, selected issue, native disclosure state, list scroll, editor node, text, selection and highlight are retained. No save, validation or repair requests occur because of collapse/reopen. Reopen shows actual finding count and existing error/warning summaries. Focus moves to Show validation issues when hidden, and to the issues pane when reopened. Review workflow and mobile Issues tab can also restore the pane.

Findings use unclamped descriptions and expandable Details with full issue/code/location/description, existing validator guidance and available current value. Long values wrap anywhere and paths have a Copy location action. Raw validator output stays nested under Technical details. No expected values or advice were invented. Opening Details retains its state across hiding. Previous/Next and Go to location retain the existing selection/source navigation. Mobile tabs remain; Hide and mobile Escape return to Editor without parallel narrow panes.

A bounded common grid aligns both panes and gives the issue list its own scroll container. Header/filter/search/navigation and readiness footer sit outside that container. Focus mode uses the remaining container height. No resizing dependency or optional drawer was added.

## Verification

68 tests passed across workspace, navigator, presentation/source mapping, existing automatic repair and quality suites. New tests cover hiding/reopening, single-column layout, DOM identity, unsaved edits, cursor, selection, filter/search/list-scroll persistence, long expanded content, independent scroll classes, fixed header/footer presence and mobile Escape dismissal. Existing tests continue to cover source navigation, revalidation, import gating and security-blocked states. TypeScript and targeted ESLint passed; `git diff --check` passed.

Browser verification used actual components with isolated API fixtures. Desktop editor width after hiding matched the complete grid width (1234px). Expanded list had more content than its bounded height with overflow-y auto; both panes aligned to the same shared working area. Reopen retained search, filter, expanded details and line-24 source highlight. Mobile 390×844 Hide returned to Editor with no horizontal document overflow. No live import was performed.

Production Next.js/Turbopack build passed in an isolated frontend copy, including TypeScript and static-page generation. Development build output was untouched.

Validation rules, error meanings/counts/severities, repair algorithms, auto/manual classifications, save behavior, revalidation APIs and import gating were unchanged. Earlier working-tree changes are separate from this task.
