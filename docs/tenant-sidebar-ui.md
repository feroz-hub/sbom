# Tenant workspace navigation polish

UI-only continuation on `codex/platform-tenant-segregation-v2`. Existing dirty
Platform/Tenant V2, configuration and platform-dashboard work is preserved.

## Implementation

- Visible tenant items are grouped into Overview, Inventory, Security Operations
  and Administration. Labels are rendered only after the existing permission
  filtering; empty groups are not displayed. No route or permission changed.
- Layered HCL blue surface, smaller brand header, 44px navigation rows, consistent
  icon sizes, stronger outlined active pill and refined submenu spacing/icons.
- Settings remains expandable, with the current permitted tenant utilities.
  Analysis route/query handling and collapsed flyouts are preserved. Expandable
  triggers now reference their submenu with `aria-controls`.
- Workspace switcher shows tenant name, workspace icon, Active tenant sublabel,
  hover/focus contrast and a compact collapsed trigger. The dropdown opens beside
  the collapsed rail. Escape restores trigger focus; arrow keys move between
  existing options; Tab remains normal and closes the popup when focus leaves.
  Selection handlers, authorized membership inputs and context changes are
  unchanged. Pure platform users still do not acquire a tenant switcher.
- Footer has System Status, readable health/timestamp text, layered panel styling
  and existing Collapse/Expand actions. API health polling and interpretation are
  unchanged. Mobile drawer/footer remain available.
- Theme-variable backgrounds, white-on-blue hierarchy, existing dark sidebar
  tokens, reduced-motion support and keyboard-visible focus are retained.

No fake counts, new user-account workflow, backend edit, schema change or
authorization change was introduced. Platform control-plane grouping remains
separate. Shared switcher/footer polish benefits both contexts.

## Files for this task

- `frontend/src/lib/navigation.ts`
- `frontend/src/components/layout/Sidebar.tsx`, `Sidebar.test.tsx`
- `frontend/src/components/layout/TenantSwitcher.tsx`, `TenantSwitcher.test.tsx`
- `frontend/src/components/layout/SidebarStatus.tsx`, new `SidebarStatus.test.tsx`
- `frontend/src/app/globals.css`
- This report.

## Verification

Focused navigation/switcher/status/control-plane tests: 36 passed. They cover
section visibility, permission filtering, active routes, Settings/Analysis,
collapsed controls, tenant switching, keyboard behavior and health text.
Full frontend suite: 1,165 passed, 8 skipped; one existing integration setup
failure because `redis-server` is unavailable (155 files passed, one failed).
Full lint: zero errors, 52 existing warnings. Changed-file lint: passed with no
warnings. Explicit typecheck, production build and `git diff --check`: passed.
Build used `NEXT_PUBLIC_API_URL=https://localhost:18000` without changing saved
environment configuration.

Layout uses the existing responsive drawer and fixed-width rail, bounded
dropdown, truncation and scrollable middle region. Live visual/no-overflow checks
at 1920/1440/1024/768/390px and dark-mode screenshot checks were not completed:
the development in-app browser still has the previously observed untrusted
localhost certificate blocker. No certificate validation was bypassed. Automated
DOM tests do not establish pixel-level overflow or visual contrast compliance.

No commit or push.
