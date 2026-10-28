# Projects page UX implementation

Route: `/projects`

## Files changed

- `frontend/src/app/projects/page.tsx`
- `frontend/src/components/projects/ProjectsTable.tsx`
- `frontend/src/components/projects/ProjectApplications.tsx` (new)
- `frontend/src/components/projects/InventoryActionMenu.tsx` (new)
- `frontend/src/app/projects/page.test.tsx` (new)
- `frontend/src/components/projects/ProjectsTable.viewmode.test.tsx`
- `frontend/src/components/projects/InventoryActionMenu.test.tsx` (new)
- This report.

## Project cards

Cards show name, description, consistent textual status badges, available inventory counts, creator and date. Selection uses a subtle blue border/surface and a Selected label. The existing list/grid preference remains available; new Projects page visitors default to cards. Counts use the existing project response and already-cached applications. No count-only API calls were added, and unavailable counts are not fabricated.

## Selected-project behavior

A selected project controls one Applications section. Selection persists in `selectedProject` URL state, including refresh and back/forward. This separate key preserves existing dashboard `project`, `product`, `sbom` and `scanned` filtering. Initial selection uses the requested allowed project, otherwise the first current result. Bookmarked projects on another project page are brought into view. Search, status filters and pagination select a visible fallback when necessary. Unavailable project IDs never cause an application request for an unauthorized/out-of-result project.

## Applications section

The previous repeated tables were extracted into `ProjectApplications`, mounted once for the selected project. Its header names the project and supplies its Create Application action. Application descriptions sit beneath stronger names; seven columns show Application, SBOMs, Latest, Current, Schedule, Status and Actions. Existing SBOM links remain intact. Application search/status filtering and client pagination operate on the existing response. The API currently returns a complete application's project list without server-pagination parameters; that contract is unchanged. Other projects are not fetched just to render this section. Loading and errors stay inside the section.

## Actions

Project overflow menus retain selection/view, edit, schedule, the existing notification-settings route and delete. Application menus retain view, edit, SBOM upload and delete; Schedule opens the existing application details page containing its scheduling control. Menus use a portal to avoid table/card clipping. Destructive entries are separated. Existing deletion-impact checks, archive/permanent options, typed-name confirmation and application deletion semantics remain in the shared confirmation dialog. Create/upload dialogs receive the selected project/application IDs.

## Responsive behavior

Project cards use one column on small screens, two at medium widths and three where desktop space permits. Application tables become readable cards below the desktop breakpoint, retaining SBOM links, schedule, status, view and overflow actions. Fixture-browser checks at 1440 × 1000 and 390 × 844 confirmed contextual selection, mobile application cards, visible menus and no mobile document horizontal overflow. These checks used actual frontend components with isolated API fixtures and a simplified application shell, not a live authenticated backend.

## Accessibility

Project selection uses keyboard-operable native buttons with `aria-pressed`, accessible project names and visible focus styles. Status includes text. Menus announce expanded state and support Arrow keys, Home/End and Escape with focus restoration. Links/buttons have meaningful labels. Desktop tables retain semantic headings; mobile inventory uses definition lists. The existing focus-trapped delete dialog remains in place. Application counts use a polite live region.

## Verification

- 34 tests passed across Projects page, ProjectsTable view modes, ProjectModal, InventoryActionMenu and shared DeleteConfirmDialog suites.
- Coverage includes initial and URL selection, one contextual application table, switching/back context, selected create/upload IDs, edit/delete dialogs, notification/schedule routes, SBOM links, project/application searches and status filters, project pagination and off-page bookmarks, empty states, retained dashboard scope, invalid selection rejection and menu keyboard/focus behavior.
- TypeScript (`tsc --noEmit`): passed.
- ESLint on Projects page/tests/components: passed.
- `git diff --check`: passed.
- Frontend production build: passed using an isolated frontend copy and the existing dependencies, avoiding interference with the development build.

## Business behavior preserved

No backend, API client, permissions, tenant-isolation logic, notification/scheduling logic, SBOM relationships or deletion implementations were changed. Existing mutation functions, dialogs and invalidations are reused. Project pagination behavior is retained. Authorization and tenant isolation continue to rely on the existing API/authentication implementation; mocked frontend tests do not constitute a new backend security audit.
