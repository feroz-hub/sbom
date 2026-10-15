# AI configuration UI redesign

Implemented for `/platform/configuration/ai`, using the existing Next.js client components,
TanStack Query hooks, theme tokens, and dialog primitives. The tenant editor reuses the
views only when the existing ownership and update permission checks allow it. Tenant
inheritance and override/reset controls remain in `ScopedAiConfiguration`.

## Behavior inventory and parity

| Existing capability | Redesigned location | Contract retained |
| --- | --- | --- |
| Effective source and configured providers | Summary and Defaults & Overrides | GET effective-config; default selection key comes from the server, including environment providers |
| Add provider; provider-specific validation, costs and optional test | Header → Add provider | POST credentials; POST credentials/test; saving without a test stays supported |
| Edit label, replace secret, base URL, model, tier, costs and local flag | Providers → Edit | PUT credentials/:id; blank replacement keeps the stored key |
| Connection test and last test | Providers → Test connection | POST credentials/:id/test |
| Set default; set fallback; enable/disable | Providers → More actions | PUT set-default / set-fallback / credentials/:id |
| Delete with typed provider-name confirmation | Providers → More actions → Delete | DELETE credentials/:id |
| Model discovery and refresh | Models; provider filter; Manage models shortcut | GET models; POST models/refresh; previous rows remain on failure |
| Exact model IDs, capabilities, limits and timestamps | Models → Capabilities and details | Existing registry fields; unknown stays unknown |
| Model test and activation | Models → Test / Set active | POST models/:id/test / select; no optimistic activation |
| Feature toggle, kill switch, all budget caps | Defaults & Overrides | Existing settings GET/PUT and validations |
| Tenant usage | Tenant Defaults & Overrides | Existing usage summary |
| Tenant source, override creation and reset | Tenant source panel | Existing override POST/DELETE and permission gates |

Default provider, each provider's active model, credential presence, enabled status,
connection test result, and model availability are separate. A disabled provider can
still show its historical connection result. Quota hints identify catalog limits or
explicitly configured requests/minute; they do not report measured usage.

Saved secrets are never loaded into form fields. New/replacement credentials remain
password inputs. Add/Edit dialogs use scroll containment and focus trapping, restore
focus to their trigger on dismissal, and require deliberate discard of changed fields.

The data service change only declares optional diagnostic fields already returned by
the backend. HTTP paths, verbs, payloads, credentials, cache keys, authorization, backend
code and persistence are unchanged. Existing query invalidation updates the summary
and active model after successful mutations.

## Verification

From the repository root:

```bash
npm --prefix frontend test -- src/components/settings/ai src/lib/queryInvalidation.test.ts src/components/dashboard/AiConfigBanner.test.tsx
cd frontend
./node_modules/.bin/tsc --noEmit --incremental false
./node_modules/.bin/eslint src/components/settings/ai src/lib/api.ts
```

Browser checks use a running local frontend with authentication enabled and fulfill
all API calls with fixture data. The fixture cookie has no real authentication value.
No API requests reach the backend, and no inference or saved configuration is changed.

```bash
cd frontend/e2e
npm ci --ignore-scripts
AI_UI_BASE_URL=https://localhost:13000 CHROME_BIN=/usr/bin/google-chrome ./node_modules/.bin/playwright test --config ai-configuration.config.ts
```

The browser suite checks test/discover/activate/reload, read-only permissions, responsive
views at 1440/1024/768/390px, enlarged text and reflow at 720px, dark mode, dialog keyboard
focus, and text contrast. Screenshots are written to `/tmp/sbom-ai-ui/`. The axe checks
are automated evidence, not a claim of complete WCAG certification.

## Rollout and rollback

No feature flag for this view was found; this is a frontend-only release. Before
promotion, review the fixture screenshots and smoke-test saved Gemini/Ollama settings
and tenant overrides in staging with an authorized account. Live provider calls,
staging deployment, and team acceptance remain release activities; local mocked
checks do not establish those outcomes.

Roll back by redeploying the previous frontend artifact. No data migration or database
rollback is needed. Preserve unrelated working-tree edits when preparing the release.

### Local verification record

- Frontend regression selection: 84 tests passed across 12 files, including tenant
  source/override permission tests and cache invalidation tests.
- TypeScript: passed. ESLint: no errors; two pre-existing unused-variable warnings
  remain in the API module outside the diagnostic type declaration.
- Production webpack build: passed from an isolated copy to avoid disturbing the
  running development server.
- Additional backend scope tests were attempted against a disposable SQLite database.
  Five cases failed during application startup, before test execution, because the
  SQLite fixture did not seed the `TENANT_ADMIN` authorization role. The PostgreSQL
  regression run and live staging smoke test remain unverified; no backend code was
  changed to work around this fixture issue.
- Browser verification: all four Playwright checks passed, including light/dark text
  contrast for all three views. Desktop Providers/Models and mobile dark screenshots
  were inspected. Budget controls' existing tests also passed after the dark text fix.
