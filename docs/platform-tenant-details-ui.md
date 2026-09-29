# Platform Tenant Details UI enhancement

Branch: `feat/native-user-management`

Tenant lifecycle, authentication and authorization behavior was preserved. Changes were limited to the frontend presentation and interaction layer.

## Files changed

- `frontend/src/app/settings/platform/tenants/[tenantId]/page.tsx`: unified tenant details layout, loading/error/not-found handling, route validation, and lifecycle confirmation.
- `frontend/src/components/admin/PlatformTenantOverview.tsx` (new): tenant breadcrumb, identity/header actions, overview, administrator and activation cards, resend interaction, and skeleton.
- `frontend/src/components/admin/StatusBadges.tsx`: shared amber Pending activation badge for existing PENDING state.
- `frontend/src/components/admin/UserSearchCombobox.tsx`: explicit accessible search label.
- `frontend/src/lib/api.ts`: thin frontend wrapper around the existing platform resend endpoint.
- `frontend/src/app/settings/platform/tenants/[tenantId]/page.test.tsx`: onboarding, delivery, permissions, recovery, accessibility, and confirmation coverage.
- `frontend/src/lib/api.tenantHeader.test.ts`: resend route/context contract regression.
- This report.

## Components and design

Created `PlatformTenantOverview`, `TenantBreadcrumb`, and `TenantDetailSkeleton`; a small internal Field helper renders definition-list fields. Reused Card/CardHeader/CardContent, Button, Alert, TenantStatusBadge, ConfirmationDialog, existing notifications, Lucide icons, HCL theme tokens, TenantMembersTable, ManageRolesModal, membership confirmation dialogs, and TenantAuditHistory. No UI library or runtime dependency was added.

The content spans up to 1360px with a light dashboard background, white cards, subtle borders/shadows, a 30px tenant title, initials, a proper breadcrumb, and explicit action hierarchy. Overview data includes only available tenant/administrator identity, creation date, and member count. Missing administrator information has a clear fallback. Account status, activation timestamps, and historical invitation delivery are not inferred or fabricated.

Supported tenant states remain ACTIVE, PENDING, and DISABLED. PENDING is presented as Pending activation, with a normal onboarding information banner. Pending tenants still cannot be manually enabled through the page. Existing active/disabled lifecycle endpoints remain unchanged; status changes now require a confirmation dialog.

## Activation and user management

Resend Activation is separate from Manage Users. Resend uses the existing `/api/platform/tenants/{tenantId}/native-users/{userId}/resend-activation` endpoint and requires both `platform:user:manage_status` and `tenant:user:invite` in addition to page access. It targets the route tenant and initial administrator, displays the recipient before confirmation, warns that the previous activation link is replaced, disables repeat submissions, and distinguishes SENT, PENDING, and failed/unconfirmed delivery. Errors are safe user-facing messages; server diagnostics are not rendered.

Pending tenant Manage Users links retain the existing native-user directory destination. For active/disabled tenants, Manage Users navigates directly to the existing tenant-scoped management section on the page, without switching the active workspace. Existing membership changes, role version checking, self-session refresh, and cache invalidation remain intact.

## Responsive and accessibility

Cards use two columns on desktop and one column on mobile. Header actions stack on small screens, long names/emails/slugs wrap, and the breadcrumb wraps. The existing sidebar was left unchanged; its Settings parent already recognizes this route.

Semantic heading hierarchy, definition lists, current-page breadcrumb, descriptive button/link labels, visible focus indicators, decorative icon hiding, live status/error feedback, skeleton busy state, and the existing modal focus/Escape behavior are used. Secondary text uses theme-aware foreground with reduced opacity for stronger contrast than the existing muted token. A missing accessible label on the shared user search was corrected.

## Verification

- Relevant frontend tests: **126 passed across 16 files**. Includes platform tenant list/details, tenant users, admin components/native users, native sign-in, and API tenant-context tests.
- Added regression coverage: pending/active/disabled states, missing administrator data, loading, safe errors/retry, not found, resend cancellation/Escape, successful/queued/failed delivery, repeated submission prevention, permission gating, route tenant/admin targeting, and tenant lifecycle confirmation.
- Automated axe check: pending tenant details passed. Existing native sign-in and user lifecycle accessibility checks also passed.
- Production build: passed using the required `NEXT_PUBLIC_API_URL=http://localhost:8000`; no build warnings reported.
- ESLint: no errors in changed files. The shared API module reports two pre-existing unused-variable warnings; edited core UI components pass without warnings.
- `git diff --check`: passed.
- Visual review: desktop and 390px mobile fixture generated from the actual tenant component using production CSS/fonts and synthetic data; mobile content width 384px at a 390px viewport, with no horizontal overflow. No console errors observed in that fixture.
- Related screens were reviewed through their shared components/source and relevant regression tests. Live authenticated tenant interactions, live provider sign-in, and actual activation-email delivery were not exercised in the browser. The visual fixture does not include the authenticated sidebar or execute live mutations.

No backend code, database models/migrations, lifecycle state machine, token generation, authentication, authorization, JWT, OIDC, or tenant isolation code changed. Pre-existing edits to `scripts/dev.py` and `tests/test_dev_launcher.py` were left intact. These UI changes are uncommitted.
