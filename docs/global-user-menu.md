# Global authenticated account menu

UI-only continuation on `codex/platform-tenant-segregation-v2`. Existing
uncommitted V2/configuration/navigation work is preserved.

## Existing behavior and change

UserMenu already existed and used the provider-aware `useAuth.logout` hook, but
was mounted by page TopBars. Pages without a TopBar had no guaranteed account
entry point. AppShell now owns ApplicationHeader, with search, UserMenu and
theme controls, for all authenticated protected pages.

Page TopBars suppress their own account/search/theme controls inside the shell,
so the normal app has exactly one menu. Standalone TopBars retain the same
reusable menu as a compatibility fallback; there is no separate dashboard
logout implementation. Page titles/actions remain page-owned. Public and auth
transition routes remain outside the authenticated shell.

## Menu

- Name, email, current platform/tenant context and current tenant role labels.
  External subject/user IDs are never used as display fallbacks.
- Platform workspace choices require explicit ACTIVE tenant memberships.
  Tenant Switch tenant appears only for multiple ACTIVE memberships. Inactive
  or disabled membership options are excluded; no platform tenant-list request.
- Return to Platform is shown only for an independently platform-authorized
  user currently inside a tenant. It calls the existing context-clear action.
- Tenant choices use existing `selectTenant`; dashboard-scoped filters are
  cleared using the same route behavior as the existing switcher.
- No My Profile link: no corresponding profile page exists.
- Theme-token surface, bounded 320px popup, decorative icons, accessible name,
  menu roles, expanded state, arrows/Home/End, native Enter, Escape focus return,
  outside-click/Tab-away close, and visible focus states.

## Logout/security

Logout is untouched: `useAuth.logout` clears authenticated query state, local
tenant/session state, invokes `/api/auth/logout`, then follows existing Native,
HCL.CS or Microsoft Entra redirect behavior. The menu adds a synchronous
one-time submission guard and disabled Signing out state. Real logout replaces
the authenticated shell with its existing Signing out loader.

No backend, provider/session semantics, authorization, routes, membership
authority or migrations changed. Auth-disabled development mode keeps its
existing no-sign-out explanation. No confirmation modal added.

## Files

- New `frontend/src/components/layout/ApplicationHeader.tsx`
- `AppShell.tsx`, `TopBar.tsx`, `UserMenu.tsx` in the same layout directory
- New `UserMenu.test.tsx`
- `frontend/src/components/layout/__tests__/AppShell.test.tsx`
- `frontend/src/app/settings/platform/page.test.tsx` (router harness and safe
  display-name fixture instead of expecting an external subject in the menu)
- This report.

Focused tests: 72 passed. Full suite: 1,185 passed, 8 skipped; one existing Redis
integration setup failed because `redis-server` is unavailable (156 files
passed, one failed). Full lint: zero errors, 52 existing warnings. Changed-file
lint, explicit TypeScript typecheck, configured production build and
`git diff --check`: passed. Native/Entra/HCL logout hook
regressions are included. No live provider sign-out was performed, to avoid
terminating the user's session. Live visual testing remains limited by the
previously observed localhost-certificate blocker. Theme tests are structural,
not a pixel-level contrast certification.

No commit or push.
