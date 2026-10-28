# Permission-aware UI implementation report

## Authorization architecture

Backend authorization remains authoritative. `/api/auth/me` supplies database-resolved effective permissions for the authenticated identity and current tenant, including multiple active roles. The permission catalogue lives in `app/core/permissions.py`; request routing in `app/core/security.py`, endpoint dependencies, and service/resource checks add the applicable restrictions. No backend production authorization, permission grants, tenant isolation, repair algorithms, validation, or import rules were changed.

## Existing frontend handling

`useAuth`, `hasPermission`, AuthContext tenant-context resolution, and existing server-provided capabilities were reused. Some navigation and administrative pages already checked permissions; many mutation buttons and inventory menu items did not. A browser-storage role check in SBOM VEX controls previously defaulted to granting UI access and was removed.

## Centralized components

- `usePermissions`: effective permissions, stable `can`, loading/error state; unknown permissions fail closed.
- `PermissionButton`: one or multiple required permissions, resource capability, existing business-state disabled/loading conditions, action-specific explanation, genuinely disabled native button.
- `PermissionExplanation`: keyboard-focusable explanation wrapper, screen-reader description, portalled hover/focus tooltip, Escape dismissal. Availability changes preserve the button element.
- `PermissionLink`: blocks unauthorized navigation without an active href.
- `PermissionGate`: hides inappropriate creation/administrative content.
- `PermissionFields`: read-only fields and implicit-submit prevention.
- `PermissionRouteGuard`: loading/restricted state before mounting unauthorized route content.
- `InventoryActionMenu`: per-item permission checks, accessible reasons, blocked click/keyboard activation, existing keyboard navigation.
- `permissionUi`: centralized action descriptions and direct-route read requirements. There is no runtime frontend role-to-permission table.

## Pages and modules

Updated Projects/Applications, Dashboard links and quick actions, SBOM inventory/details/upload/conversion/VEX import, Repair Workspace and large-file editor, Analysis/remediation/AI-fix controls, CISA KEV sync, Schedules, VEX decisions/assignment, component-advisor permission handling, tenant/platform settings, AI/lifecycle configuration, vendor records, user-management entry points, notifications scheduling, sidebar, command palette, and AppShell route access. Existing component-advisor action capabilities and safe-repair approval capabilities remain authoritative and were retained rather than replaced with a broad role check.

## Permission-to-action mapping

| Action | Existing required permission/capability |
| --- | --- |
| Create/edit/delete project | `project:create` / `project:update` / `project:delete` |
| Create/edit/delete application | `product:create` / `product:update` / `product:delete` |
| Upload SBOM | `sbom:upload` and `product:assign_sbom` |
| Assign an existing SBOM | `sbom:update` and `product:assign_sbom` |
| Edit/delete/export SBOM | `sbom:update` / `sbom:delete` / `sbom:export` |
| Download VEX/lifecycle reports | `vex:read` / `lifecycle:read`, plus existing SBOM processing conditions |
| Download raw SBOM | `sbom:read` (actual endpoint requirement) |
| Run/cancel analysis | `analysis:run` |
| Save remediation | `remediation:write` |
| Edit/save/apply repair draft | `sbom:repair:update`, plus existing repair/session conditions |
| Revalidate/import manual repair session | `sbom:repair:revalidate`, plus existing validation/import conditions |
| Repair downloads / large-file search | `sbom:repair:download` / `sbom:repair:search` |
| Safe repair approval | Existing backend capabilities, including upload/assignment requirements |
| Manage schedules | `schedule:write` and `product:manage_schedule` |
| Legacy VEX import/override | `vex:write` |
| Investigation decision/assignment/mapping | Backend resource capabilities; assigned-only Developer exception preserved |
| Component lifecycle override/refresh | `lifecycle:override` |
| Generate/regenerate/control legacy AI fixes | `tenant:settings:update` (current backend request mapping) |
| AI configuration | Scope-specific `tenant:ai:*` / `platform:ai:*` permissions |
| Lifecycle provider settings | Existing tenant/platform scoped provider permissions |
| Lifecycle vendor records | `lifecycle:vendor-record:write` / `lifecycle:vendor-record:delete` |
| Advisor recommendations/decisions | Existing recommendation permissions and resource capabilities |
| User/platform administration | Existing operation-specific tenant/platform catalogue permissions |

These are UI checks of current backend policy, not changes to that policy. In particular, AI execution controls follow the current legacy endpoint requirement; AI availability remains independently readable. Personal notification preferences retain the server's owner/admin policy instead of being treated as tenant-wide administration.

## Role-specific behavior

Actual effective grants determine behavior, including custom grants and multiple roles. The catalogue regression matrix covers PLATFORM_ADMIN, TENANT_ADMIN, SECURITY_ANALYST, DEVELOPER, and VIEWER. A Viewer cannot open project/application creation forms or activate forbidden mutation actions; read navigation and selection remain available. Security Analyst project creation/update and other existing authorized security operations are retained. Developer mutation rights are not inferred from their role name. Platform administrative grants do not automatically grant tenant-resource access.

## Resource-specific restrictions

Assigned Developer VEX decisions use the backend's `can_update` capability, not global `vex:write`. Assignment and mapping likewise retain backend capabilities/reasons. Repair controls retain safe/manual-only eligibility, validation success, partial-content restrictions, imported state, and request-in-progress gating. SBOM lifecycle deletion retains its existing combined permission and backend admin-role exception. No capability or permission grants were broadened.

## Disabled UX and accessibility

Disabled actions have readable neutral styling, no executable click/keyboard action, and specific permission explanations. Native-disabled buttons are wrapped by a focusable explanation so keyboard users can discover the reason. Tooltip text is exposed through `aria-describedby`; visible tooltips escape clipped containers via a portal. Forbidden menu items use `aria-disabled`, block invocation and omit active links, while remaining keyboard discoverable. Read-only fieldsets prevent editing and implicit form submission. Empty-state creation CTAs are hidden when unauthorized. Direct privileged URLs render Access restricted with Dashboard navigation rather than mounting a broken administrative form.

## Tenant switching and performance

Reuse the existing authenticated tenant context and its query-cache clearing/refresh behavior. `usePermissions` becomes pending-disabled during tenant resolution and consumes the new effective permissions after resolution. It does not make per-button authorization requests or maintain a separate permission cache. User/session/tenant changes therefore do not reuse a previous tenant's UI authority. Tests exercise loading, resolution failure and tenant permission transitions.

## Backend enforcement confirmation

No production backend files changed. Scoped authorization and tenant-isolation regression tests continue rejecting unauthorized requests. Test expectations were corrected where they assumed unrestricted platform tenant rights; the platform VEX test now explicitly supplies tenant grants. Frontend catalogue fixtures are test-only and checked against the backend catalogue by a Python regression test.

## Tests and results

- Full frontend Vitest suite: **171 files, 1,392 tests passed**.
- After final permission/form/report corrections: **2 SBOM detail files, 30 tests passed**, including a regression proving that generic component editing does not enable lifecycle overrides. The shared permission control tests also passed in the preceding targeted run (3 files, 53 tests).
- Backend authorization regression suite: **28 passed** (`test_rbac_permissions`, `test_vex_scoped_authorization`, `test_tenant_isolation`, `test_phase8_authorization_catalog_api`, `test_permission_ui_catalogue`).
- Changed-source ESLint: **0 errors**; 28 warnings in the changed-source pass; no lint errors.
- `git diff --check`: passed.
- Production Next.js build: passed with `NEXT_PUBLIC_API_URL=http://127.0.0.1:8000`.

Role/resource tests cover effective custom/multiple grants, Viewer creation blocking, read navigation, direct-route denial before child mount, tooltip focus/Escape, loading/error fail-closed behavior, tenant changes, combined permissions, menu invocation, read-only form submission, VEX assigned capabilities, repair business states, and existing module workflows. This is automated regression coverage; interactive browser sessions for every role/tenant combination were not performed. Isolated PostgreSQL/Redis test containers were used; the temporary PostgreSQL container was stopped afterward. No deployment was performed.

## Files changed

- `frontend/src/app/component-advisor/componentAdvisor.test.tsx`
- `frontend/src/app/component-advisor/components/[key]/page.tsx`
- `frontend/src/app/kev/page.test.tsx`
- `frontend/src/app/kev/page.tsx`
- `frontend/src/app/products/[id]/page.test.tsx`
- `frontend/src/app/products/[id]/page.tsx`
- `frontend/src/app/projects/page.product-category.test.tsx`
- `frontend/src/app/projects/page.test.tsx`
- `frontend/src/app/projects/page.tsx`
- `frontend/src/app/sboms/page.test.tsx`
- `frontend/src/app/sboms/page.tsx`
- `frontend/src/app/schedules/page.test.tsx`
- `frontend/src/app/schedules/page.tsx`
- `frontend/src/app/settings/advisor-policies/page.test.tsx`
- `frontend/src/app/settings/page.tsx`
- `frontend/src/app/settings/platform/page.test.tsx`
- `frontend/src/app/settings/platform/page.tsx`
- `frontend/src/app/settings/platform/tenants/[tenantId]/page.test.tsx`
- `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx`
- `frontend/src/app/settings/platform/tenants/page.tsx`
- `frontend/src/app/settings/tenant/page.test.tsx`
- `frontend/src/app/vex-investigation/page.test.tsx`
- `frontend/src/components/admin/LifecycleProviderSettings.test.tsx`
- `frontend/src/components/admin/LifecycleProviderSettings.tsx`
- `frontend/src/components/admin/LifecycleVendorRecordsPage.tsx`
- `frontend/src/components/admin/NativeUserInviteForm.test.tsx`
- `frontend/src/components/admin/NativeUserInviteForm.tsx`
- `frontend/src/components/admin/ScopedAdvisorPolicies.tsx`
- `frontend/src/components/admin/ScopedLifecycleConfiguration.test.tsx`
- `frontend/src/components/admin/ScopedLifecycleConfiguration.tsx`
- `frontend/src/components/admin/TenantUsersAccess.tsx`
- `frontend/src/components/admin/UserLifecycle.tsx`
- `frontend/src/components/ai-fixes/AiFixSection/AiFixGenerateButton.tsx`
- `frontend/src/components/ai-fixes/AiFixSection/AiFixMetadata.tsx`
- `frontend/src/components/ai-fixes/FreeTierWarningDialog/FreeTierWarningDialog.tsx`
- `frontend/src/components/ai-fixes/GlobalAiBatchProgress/GlobalAiBatchBanner.tsx`
- `frontend/src/components/ai-fixes/RunBatchProgress/BatchControls.tsx`
- `frontend/src/components/ai-fixes/__tests__/AiFixSection.axe.test.tsx`
- `frontend/src/components/ai-fixes/__tests__/AiFixSection.errorCopy.test.tsx`
- `frontend/src/components/ai-fixes/__tests__/AiFixSection.test.tsx`
- `frontend/src/components/ai-fixes/__tests__/RunBatchProgress.test.tsx`
- `frontend/src/components/analysis/ConsolidatedAnalysisPanel.tsx`
- `frontend/src/components/analysis/FindingsTable.tsx`
- `frontend/src/components/analysis/LiveAnalysisCard.tsx`
- `frontend/src/components/dashboard/ActivityFeed.tsx`
- `frontend/src/components/dashboard/CounterTiles.tsx`
- `frontend/src/components/dashboard/DashboardEmptyState.test.tsx`
- `frontend/src/components/dashboard/DashboardEmptyState.tsx`
- `frontend/src/components/dashboard/DashboardQuickActions.tsx`
- `frontend/src/components/dashboard/QuickActionsV2/QuickActionsV2.tsx`
- `frontend/src/components/dashboard/RecentSboms.tsx`
- `frontend/src/components/dashboard/__tests__/managerWidgets.test.tsx`
- `frontend/src/components/layout/AppShell.tsx`
- `frontend/src/components/layout/CommandPalette.tsx`
- `frontend/src/components/layout/ControlPlaneNavigation.test.tsx`
- `frontend/src/components/layout/Sidebar.tsx`
- `frontend/src/components/layout/__tests__/AppShell.test.tsx`
- `frontend/src/components/products/ProductFormDialog.tsx`
- `frontend/src/components/projects/InventoryActionMenu.tsx`
- `frontend/src/components/projects/ProjectApplications.tsx`
- `frontend/src/components/projects/ProjectModal.test.tsx`
- `frontend/src/components/projects/ProjectModal.tsx`
- `frontend/src/components/projects/ProjectsTable.tsx`
- `frontend/src/components/projects/ProjectsTable.viewmode.test.tsx`
- `frontend/src/components/reports/ReportNotificationsPage.tsx`
- `frontend/src/components/sboms/ComponentVexManager.test.tsx`
- `frontend/src/components/sboms/ComponentVexManager.tsx`
- `frontend/src/components/sboms/Fda510kReportDialog.tsx`
- `frontend/src/components/sboms/SbomConversionCard.test.tsx`
- `frontend/src/components/sboms/SbomConversionCard.tsx`
- `frontend/src/components/sboms/SbomDetail.components.test.tsx`
- `frontend/src/components/sboms/SbomDetail.lifecycle.test.tsx`
- `frontend/src/components/sboms/SbomDetail.tsx`
- `frontend/src/components/sboms/SbomRawViewer.tsx`
- `frontend/src/components/sboms/SbomUploadModal.repair.test.tsx`
- `frontend/src/components/sboms/SbomUploadModal.tsx`
- `frontend/src/components/sboms/SbomsTable.tsx`
- `frontend/src/components/sboms/ValidationRepairWorkspace.test.tsx`
- `frontend/src/components/sboms/ValidationRepairWorkspace.tsx`
- `frontend/src/components/sboms/VexDocumentImport.tsx`
- `frontend/src/components/sboms/repair/LargeFileRepairEditor.tsx`
- `frontend/src/components/sboms/repair/RepairIssueNavigator.test.tsx`
- `frontend/src/components/sboms/repair/RepairIssueNavigator.tsx`
- `frontend/src/components/schedules/ScheduleCard.test.tsx`
- `frontend/src/components/schedules/ScheduleCard.tsx`
- `frontend/src/components/schedules/ScheduleEditor.test.tsx`
- `frontend/src/components/schedules/ScheduleEditor.tsx`
- `frontend/src/components/settings/ai/ScopedAiConfiguration.tsx`
- `frontend/src/components/settings/ai/__tests__/ScopedAiConfiguration.test.tsx`
- `frontend/src/components/ui/PermissionButton.test.tsx`
- `frontend/src/components/ui/PermissionButton.tsx`
- `frontend/src/components/ui/PermissionGate.tsx`
- `frontend/src/components/ui/PermissionLink.tsx`
- `frontend/src/components/vex/VexDecisionEditor.tsx`
- `frontend/src/components/vex/VexInvestigationPanel.tsx`
- `frontend/src/hooks/usePermission.ts`
- `frontend/src/lib/permissionUi.ts`
- `frontend/src/test/authorizedAuth.ts`
- `frontend/src/test/permissionCatalogue.json`
- `tests/test_permission_ui_catalogue.py`
- `tests/test_rbac_permissions.py`
- `tests/test_vex_scoped_authorization.py`
