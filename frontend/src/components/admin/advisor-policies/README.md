# Component Advisor Policies frontend

The platform and tenant routes both use `ScopedAdvisorPolicies`. This directory
contains presentation and client-side validation only. API functions, query keys,
authorization hooks, backend policy evaluation, and database schemas are unchanged.

- Accepted Risk has a structured editor and a collapsed JSON editor backed by one
  document. Optional blanks become `null`; invalid JSON and unknown fields are kept
  until corrected, and publication is blocked. The lifecycle values mirror
  `LifecycleBucket` in `lifecycle_mapping.py`.
- Trust and Recommendation Scoring retain JSON editing. Validation mirrors
  `policy.py` and `recommendations/scoring.py`. Scoring weights need a positive total,
  not a sum of one; the backend normalizes them. The backend remains authoritative.
- Tabs keep local edits mounted. A tenant change remounts the console. Publication
  and reload callbacks use `useMutationScope` to ignore stale results and errors.
- Background reads never replace dirty edits or their original `row_version`.
  HTTP 409 blocks further editing/publication until an explicit successful reload
  discards the draft. A failed reload leaves the draft and conflict intact.
- Publication reviews mode, scope, reason and proposed rules before calling the
  existing `publishAdvisorPolicy`. History is read-only and uses the existing endpoint.
- The CSS module adjusts contrast and focus only within this screen and its dialog.

## Validation

From `frontend`:

```bash
npm test -- src/app/settings/advisor-policies/page.test.tsx src/components/admin/advisor-policies/policyRules.test.ts src/lib/queryInvalidation.test.ts
./node_modules/.bin/tsc --noEmit --incremental false
./node_modules/.bin/eslint src/components/admin/ScopedAdvisorPolicies.tsx src/components/admin/advisor-policies src/app/settings/advisor-policies/page.test.tsx
npm run build -- --webpack
```

The regression selection covers publishing all modes, confirmation/cancellation,
Accepted Risk serialization and validation, JSON synchronization, read permissions,
platform independence from tenant context, tenant switching and late async results,
conflicts, history, and accessible tabs/dialogs. Browser verification with intercepted
API fixtures covers light/dark text contrast and 1440/1024/768/390px layouts. Fixture
screenshots are review evidence, not production data.

## Limitations and follow-up

Local edits survive tab changes, but are intentionally not persisted across page
reloads or navigation. Trust and Scoring visual builders, backend drafts, rollback,
and impact counts are outside this change. Backend validation remains the final
check if rules evolve; keep the presentation validators aligned when that happens.
Automated axe checks and keyboard checks do not replace a full accessibility audit.
Staging acceptance with real permissions and concurrent administrators remains a
release verification activity; browser fixture checks do not establish that result.

## Verification results

On branch `feat/native-user-management`, the regression selection above passed all
71 tests across three files. The full frontend TypeScript check and scoped ESLint
check passed without errors or warnings. A production webpack build completed
successfully from an isolated source copy so the active dev server was not disturbed.
The fixture browser checks passed contrast for all three tabs in both themes,
responsive layouts at four widths, and review/cancel/publish with the expected null
optional value and original concurrency token. Desktop and mobile screenshots were
visually inspected. No live policy writes or staging deployment were performed.
