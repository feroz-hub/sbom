# SBOM Inventory enterprise UI/UX redesign

Scope: the tenant SBOMs inventory page only. Frontend presentation refactor. No API contract, backend business logic, schema or permission change.

## Observed design issues
October 23 screenshot shows distracting blue/violet table header, overly saturated row stripes, deeply truncated names, verbose and space-consuming row actions, wide filter controls, weak report-disabled explanation, and poor small-screen ergonomics.

## What changed
- A purposeful page subtitle and responsive content gutters.
- An inventory section with total/filtered counts, primary search, expandable filters, removable filter chips, and selection guidance.
- A persisted List/Grid toggle using the app's existing ViewToggle and useViewMode. First visits below 768px default to grid after hydration; explicit preferences win.
- Compact, wrap-aware names and accessible record/version/history links.
- Shared permission-aware InventoryActionMenu for View, Repair Workspace, Version history, Delete; existing lifecycle badge/action and PinButton retained.
- Selection (including all filtered SBOMs), FDA report, existing pagination/sort, activation/inactivation, delete-impact preflight, and upload flows preserved.
- Scoped neutral inventory table styling and subtle alternating rows without modifying the shared table design.
- Grid cards show the ID, name, project, product, format, version, validation, analysis, author, date, lifecycle state and actions.

## Code paths
- frontend/src/app/sboms/page.tsx
- frontend/src/components/sboms/SbomsTable.tsx
- frontend/src/components/sboms/sbom-inventory.module.css
- frontend/src/components/sboms/SbomsTable.ux.test.tsx

## Behavioral acceptance checklist
1. Upload and optimistic add, permissions and query invalidation unchanged.
2. Search and filters including project/product dependencies, clear chips, empty/loading/error states.
3. Sort and pagination in list, page items and select-all in both views, selection preserved when changing view.
4. Export FDA report only for a selected single project with the original eligibility/reanalysis checks.
5. Detail/analysis links, version history, validation drill-down, repair workspace and pin.
6. Lifecycle state and reason dialog, delete archive/permanent and impact confirmation.
7. Role-based access, multiple tenants and unauthorized actions.
8. Laptop/tablet/mobile at 1440, 1024, 768, 390px; dark mode, keyboard focus, Escape, contrast, long titles and touch.

## Validation
Added focused Vitest coverage of numeric display ID/UUID navigation, filter disclosure and clearing, list/grid alternatives, and mixed-project selection.
Existing relevant tests: frontend/src/components/sboms/SbomsTable.analysis.test.tsx and frontend/src/app/sboms/page.test.tsx.

Run in the repository:

    cd frontend
    npm ci
    npm test -- src/components/sboms/SbomsTable.analysis.test.tsx src/components/sboms/SbomsTable.ux.test.tsx src/app/sboms/page.test.tsx
    npx tsc --noEmit --incremental false
    npx eslint src/app/sboms/page.tsx src/components/sboms/SbomsTable.tsx src/components/sboms/SbomsTable.ux.test.tsx
    npm run build

**Validation limitation:** The execution container could not resolve github.com to clone the repository. The source was reviewed using the connected GitHub integration, but Vitest, TS, lint, production build and live browser regression have NOT run in this environment. Do not claim all tests pass. Keep the PR as draft pending independently executed commands and target browser UAT.

## Deployment and rollback
Merge only after review into feat/native-user-management. Test with a disposable tenant on staging first. Frontend artifact promotion only; no migration or backend change. Roll back using the prior frontend image/artifact. No running HCL server/database touched during preparation.
