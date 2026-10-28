# Platform Dashboard UI polish

UI-only continuation on `codex/platform-tenant-segregation-v2`; preceding
uncommitted security/configuration work is preserved. No backend, permissions,
authorization guards, migrations or inheritance behavior changed in this task.

## Dashboard

- Seven semantic stat cards, responsive 1/2/4-column layout, restrained status
  accents, matching heights, subtle elevation and meaningful zero labels.
- Header includes the permission-gated Create Tenant CTA; on small screens the
  CTA moves into the wrapping toolbar beside Refresh.
- Compact control-plane information banner reinforces tenant data isolation.
- Tenant Overview requests only five records through the existing paginated
  platform tenant endpoint. The existing API sorts by name; the UI explicitly
  says so instead of falsely labelling these “latest”. No backend sorting changed.
- Table shows name/slug, status, members, effective-admin count, creation date
  and a link to the existing platform governance detail page. No member directory
  or tenant business data is displayed. Missing values display a dash, not fake
  zero counts. Small screens have a keyboard-focusable horizontal table scroller.
- Permission-gated governance cards replace plain footer links. Health links to
  the existing health page; no invented service-health checks or values.
- Independent metric/tenant loading, error and retry states. Refresh updates both.
- Existing theme tokens, dark semantic accents, decorative icons, visible focus,
  semantic headings/table/links, and reduced-motion spinner support.

## Navigation and creation

Platform navigation is now Dashboard, Tenants, Configuration (AI/Lifecycle),
Administration (Administrators/Health). Expanded sections use compact uppercase
labels, not a Settings accordion. Collapsed sections retain the existing flyout
behavior. The platform navigation has 44px items and stronger active contrast;
tenant navigation and the API status/footer behavior remain intact.

Create Tenant links to `/settings/platform/tenants#create-tenant`, opening the
existing creation form only when its existing create permission is satisfied.
No duplicate provisioning implementation was introduced.

## Files changed in this task

- `frontend/src/app/platform/page.tsx` and `page.test.tsx`
- `frontend/src/lib/navigation.ts`
- `frontend/src/components/layout/Sidebar.tsx` and `Sidebar.test.tsx`
- `frontend/src/app/globals.css`
- `frontend/src/lib/api.ts` (optional page-size argument; default remains 50)
- `frontend/src/app/settings/platform/tenants/page.tsx` and `page.test.tsx`
- This report.

## Verification

Focused dashboard/sidebar/control-plane/tenant-creation tests passed 44 cases.
Full frontend suite: 1,157 passed, 8 skipped, one existing Redis integration
setup failure because `redis-server` is unavailable (154 files passed, one
failed). Lint: zero errors, 52 existing warnings. Explicit TypeScript typecheck,
configured production build and `git diff --check` passed. The build used
`NEXT_PUBLIC_API_URL=https://localhost:18000`; no project configuration was
overwritten to supply that setting.

Responsive containment/grid and dark theme tokens have automated structural
coverage. Real-browser checks at 1920, 1440, 1024, 768 and 390px, and visual
dark-mode verification remain blocked: the in-app browser rejects the localhost
HTTPS certificate (`ERR_CERT_AUTHORITY_INVALID`) even after user handoff. No
certificate warning was bypassed and no screenshot/viewport success is claimed.

No commit or push.
