# Platform Tenants directory

This redesign is limited to the tenant directory, its creation dialog, and associated
tests. API functions, tenant status semantics, activation flows, permissions, shared
components, and backend code are unchanged.

The list uses `listPlatformTenants(query, page)` with its existing page size of 50.
Search waits 300 ms, then changes the query and resets to page 1 atomically. Clearing
search resets immediately. Previous/Next navigation uses the existing 50-row heuristic;
there is no total count or claimed last page. A full final page can therefore lead to
an empty next page, which provides a working Previous action.

Administrators/Tenants are styled as navigation tabs but remain links with
`aria-current`, because they navigate separate routes. Row actions remain explicit
buttons; Manage keeps the existing detail route. Disabling retains the access-loss
warning and confirmation. Creation and status requests have both pending UI states
and immediate duplicate-submission guards.

The shared dialog contains tenant details, existing-user selection or the complete
invitation profile, and review. It preserves `#create-tenant` on initial load and hash
changes, slug auto-generation/manual override, `validateTenantForm`, server field
errors, notifications, query invalidation, and navigation after creation. The CSS
module scopes contrast/focus refinements to this screen and dialog.

## Verification

From `frontend`:

```bash
npm run lint
npm run test
npm run build -- --webpack
./node_modules/.bin/tsc --noEmit --incremental false
```

The tenant page tests and the existing platform cache integration tests cover search,
pagination, permissions, creation, invitations, slug validation, duplicate submissions,
status changes, notifications, and invalidation. Browser verification uses intercepted
fixture APIs; it does not perform live provisioning or change tenant status.

## API limitations and follow-up

The API does not guarantee total-record counts, so this UI offers no total pages or
global tenant statistics. Missing member counts and creation dates are shown explicitly.
Narrow viewports scroll the table horizontally within the directory card. Invitation
activation and eligibility continue to be decided by the server. Live staging acceptance
and a complete accessibility audit remain release verification activities.

## Local verification results

- Tenant directory and platform cache-integration tests: 47 passed.
- Full frontend run: 1,706 tests passed, 8 skipped. One suite failed setup with an
  unhandled `spawn redis-server ENOENT` error because `redis-server` is unavailable;
  the failing file is `src/lib/auth/shared-session-store.test.ts`. No runnable test
  assertions failed in the final run.
- Repository-wide `npm run lint` and frontend TypeScript check: passed.
- Fixture browser checks passed for directory/dialog layouts at 1440, 1024, 768 and
  390 pixels, light/dark directory text contrast, debounced search and clear, and
  disable-confirmation cancellation. Desktop and mobile screenshots were inspected.
- Production build (`npm run build -- --webpack`): passed from an isolated source
  copy, without disturbing the running development server. No live provisioning,
  production status changes, or deployment were performed.
