# Lifecycle Providers UI redesign — 16 October 2026

Implemented in the existing application at `/platform/configuration/lifecycle` and `/admin/lifecycle-providers`. No deployment or production provider-setting changes were performed.

## Before and after

| Before | Implemented experience |
| --- | --- |
| Nine columns with provider keys, URLs, coverage paragraphs, circuit state and repeated inheritance labels | Compact directory: provider, source type, runtime setting, verification, last verified and Manage |
| No summary or discovery tools | Four evidence-based summary counts, search, six filters and four sorting options |
| Edit-first modal; verification details mixed into the directory | Right-hand details drawer with Overview, Configuration, Verification and Activity; full-screen on mobile |
| Dense repeated technical information | Short provider descriptions; technical identifiers and sample evidence disclosed on demand |
| Scope explained through row labels | One scope banner explaining platform defaults or named tenant inheritance; explicit tenant customization |
| Form interactions could lose invalid JSON or dismiss failed saves | Inline validation, preserved drafts, dirty indication, discard confirmation, guarded submission and saved/error state |
| Operational status and evidence coverage difficult to scan | Stored verification, source provenance, runtime enablement and sample evidence are distinct |

Both comparison images render the actual application components in an isolated copy with the same synthetic API data. They do not show production provider health.

- [Before desktop](screenshots/providers-before-desktop.jpg)
- [After desktop](screenshots/providers-desktop.jpg)
- [After laptop](screenshots/providers-laptop.jpg)
- [Verification drawer](screenshots/provider-verification-laptop.jpg)
- [Tenant customization](screenshots/provider-tenant-configuration.jpg)
- [Mobile directory](screenshots/providers-mobile.jpg)
- [Mobile drawer](screenshots/provider-mobile-drawer.jpg)

## Components and files

Paths below are relative to `/home/hcluser1/sbom_native/sbom`.

| File | Change |
| --- | --- |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx` | Summary, searchable/filterable/sortable directory, details integration; retained existing scoped API mutations and cache invalidation |
| `frontend/src/components/admin/LifecycleProviderDetails.tsx` | New accessible details drawer, provider/source overview, verification details, last-known activity and reset/discard confirmations |
| `frontend/src/components/admin/LifecycleProviderForm.tsx` | Capability-driven grouped settings, local draft state, inline validation, separate masked credential editing, save and disable safeguards |
| `frontend/src/components/admin/ScopedLifecycleConfiguration.tsx` | Page description, contextual scope banner, inheritance explanation and help; retained permission checks and scope remount boundary |
| `frontend/src/components/ui/Dialog.tsx` | Optional right-side placement; existing centered dialogs retain their default layout. Included native summary controls in focus containment |
| `frontend/src/lib/lifecycle-provider-presentation.ts` | Shared frontend presentation selectors for proof-based verification, summary, filtering and sorting |
| `frontend/src/test/lifecycle-provider-fixtures.ts` | Explicit synthetic fixtures used only by tests and isolated visual QA |
| `frontend/src/components/admin/LifecycleProviderSettings.test.tsx` | Directory, metrics, details, keyboard, unsaved draft, mutation/error, credential/inheritance and permission regression tests; retained vendor-record coverage |
| `frontend/src/components/admin/LifecycleProviderForm.test.tsx` | Provider-specific fields, defaults, validation, invalid JSON, save/failure, duplicate-submit and credential tests |
| `frontend/src/components/admin/ScopedLifecycleConfiguration.test.tsx` | Updated scope/header/inheritance assertions; retained permission boundary tests |
| `frontend/src/lib/lifecycle-provider-presentation.test.ts` | Proof, static/reference separation, degraded/unsupported status and sorting tests |

## Status and metric definitions

- **Total providers:** count of rows actually returned by the scoped API.
- **Verified operational:** enabled, implemented, non-static sources with a stored successful healthy probe, valid configuration and parsed response, and a valid check timestamp. Network sources also require confirmed connectivity and an actual provider call. Local sources require a local verification probe. A healthy configuration row, HTTP status or timestamp alone is insufficient. A current degraded health record prevents counting a previous successful probe as operational.
- **Needs attention:** enabled, implemented providers with invalid/missing source settings, a recorded degraded/failure state, or no complete successful verification evidence.
- **Disabled providers:** rows whose saved administrative enabled setting is false.
- **Unsupported:** derived from backend capability metadata and shown separately in the directory header/filter.

The directory and summary use persisted API state. An inherited tenant verification result may be shown inside the drawer for the current session without inventing stored platform history or changing summary counts. Static RHEL checks are described as reference checks; they never imply live vendor connectivity or verified reference freshness.

## Preserved backend behavior

No backend code, API type/REST contract, migration, database configuration or provider semantics were changed by this redesign. Migration 079 and the existing encrypted-secret, runtime policy, probe, enrichment and authorization implementation were preserved. The tracked backend/Alembic/Compose diff was compared byte-for-byte against the snapshot taken before UI work and was identical.

Forms use backend capabilities for endpoint editability, feed support, configuration fields, secrets, network settings and cache reload availability. Existing TanStack Query invalidation and tenant mutation guards remain in use. Provider configuration/secret changes clear transient verification results. In-flight verification prevents concurrent editing or dismissal.

Tenant inheritance is explicit: inherited values are read-only until Customize is selected, and the override is created only on Save. Reset warns that the tenant override and tenant credential will be removed. Platform disable warns about inheriting tenants without inventing an affected-tenant count. Secret inputs are empty password fields; saved secret values and previews are not rendered.

## Validation

Run from `/home/hcluser1/sbom_native/sbom/frontend`:

```bash
npm test -- --run src/components/admin/LifecycleProviderSettings.test.tsx src/components/admin/LifecycleProviderForm.test.tsx src/components/admin/ScopedLifecycleConfiguration.test.tsx src/lib/lifecycle-provider-presentation.test.ts src/lib/lifecycle-invalidation.test.ts src/components/sboms/SbomLifecycleControls.test.tsx src/components/sboms/SbomDetail.lifecycle.test.tsx src/components/dashboard/LifecycleHealthTiles.test.tsx src/components/ui/__tests__/DeleteConfirmDialog.test.tsx

npx tsc --noEmit

npx eslint src/components/admin/LifecycleProviderSettings.tsx src/components/admin/LifecycleProviderForm.tsx src/components/admin/LifecycleProviderDetails.tsx src/components/admin/ScopedLifecycleConfiguration.tsx src/components/ui/Dialog.tsx src/lib/lifecycle-provider-presentation.ts src/lib/lifecycle-provider-presentation.test.ts src/components/admin/LifecycleProviderSettings.test.tsx src/components/admin/LifecycleProviderForm.test.tsx src/components/admin/ScopedLifecycleConfiguration.test.tsx src/test/lifecycle-provider-fixtures.ts

NEXT_PUBLIC_API_URL=http://localhost:8000 npm run build
```

Final result: 104 tests passed across 9 files; TypeScript, targeted ESLint and Next.js production build passed. The build generated 47 static pages and the existing dynamic routes. No remaining failures in this targeted set. Earlier iteration failures from changed UI queries and an unsupported Testing Library `exact` option were corrected. This was not a repository-wide test run.

The accessibility test runs axe on the directory and configuration drawer and reports zero violations. jsdom prints unsupported pseudo-element `getComputedStyle` notices, so automated contrast results are limited; this is not a substitute for assistive-technology testing.

### Browser review

The browser loaded the actual Next.js routes, application navigation and updated production UI components in an isolated `/tmp` copy. Only that copy's identity and API transport were replaced with explicit synthetic test fixtures. The production auth implementation, repository environment files and production settings were untouched. No live provider calls or production writes were made through this preview. The global sidebar health indicator reports API unavailable because the fixture does not emulate the unrelated health service.

Verified at 1440×1000 desktop, 1100×800 laptop and 390×844 mobile widths:

- Directory and drawer fit without horizontal overflow.
- Search and Unsupported filter return the expected fixture rows.
- Provider drawer opens, exposes the four sections and becomes full-screen on mobile.
- Keyboard focus remains inside the drawer and returns to its opener after Escape dismissal.
- Edited priority survives section switches and Keep editing; closing requires explicit discard.
- Tenant scope displays the tenant name and inheritance explanation; inherited fields are disabled until Customize.
- Verification displays operation, HTTP/authentication/parsing checks and sample lifecycle coverage separately.

The screenshots are visual QA evidence with synthetic records, not proof of live provider health or a production-backed browser end-to-end run. Deterministic component tests cover successful and failed save/verification calls, scope routing and query invalidation.

## Remaining limits and release notes

- The current backend intentionally skips probes for disabled providers. The UI explains that constraint and requires enabling and saving before verification; it never silently enables a provider. Backend behavior was preserved as requested.
- Official Vendor Lifecycle remains unsupported. Red Hat remains a static RHEL reference with unverified freshness.
- Activity contains only timestamps and state already exposed by the API, not an invented history. Circuit state and cache reload are described as process-local.
- Inherited tenant verification may be session-only according to the existing API contract. It does not change platform verification history.
- Full screen-reader, high-zoom, dark-theme and all-browser acceptance testing was not performed. Keyboard and responsive checks plus automated accessibility checks are included.
- An explicit tenant/scope switch remounts the editor as part of the existing authorization boundary. Drawer dismissal and browser unload have draft guards; drafts are not persisted across account or tenant switches.
- No new dependency, migration or environment variable is required. Use the existing frontend build/deployment process after review. Nothing was deployed automatically.
