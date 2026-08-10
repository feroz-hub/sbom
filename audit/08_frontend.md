# Phase 4 — Frontend Deep-Pass Audit

> Stack: Next.js (App Router code, Next 9 installed — see YAGNI-017), TypeScript strict, React 18, Tailwind, Tanstack Query, React Hook Form + Zod.

---

## 1. TypeScript strictness

### Finding FE-001: TypeScript strict mode is on; almost no escape hatches

- **Severity:** none — verified
- **Location:** [frontend/tsconfig.json:10](../frontend/tsconfig.json) (`"strict": true`).
- **Evidence:**
  ```bash
  $ grep -rEi ': any|<any>|as any|@ts-ignore|@ts-nocheck' frontend/src
  # → no results
  ```
  No `any`, no `@ts-ignore`. The single non-null assertion is in [frontend/src/hooks/useToast.tsx:170](../frontend/src/hooks/useToast.tsx) on a member-access where the conditional was already checked. Acceptable.
- **Status:** **FBT non-negotiable met.** This is genuinely strict TS code — preserve it.

### Finding FE-002: `useBackgroundAnalysis` triple-cast through `Record<string, unknown>`

- **Severity:** Medium
- **Location:** [frontend/src/hooks/useBackgroundAnalysis.ts:65-71](../frontend/src/hooks/useBackgroundAnalysis.ts); see KISS-011 / SUP-LOD-002.
- **Note:** Cross-listed. The casts are because the BE returns a dual-shape dict for `_run_legacy_analysis` and the FE defensively reads both. Fix on the BE side (BE-020 — define the schema) → these casts disappear.

### Finding FE-003: `ConsolidatedAnalysisResult` has `[key: string]: unknown` escape hatch

- **Severity:** Medium
- **Location:** [frontend/src/types/index.ts:216-231](../frontend/src/types/index.ts)
- **Evidence:**
  ```ts
  export interface ConsolidatedAnalysisResult {
    runId: number;
    sbom_id?: number;
    ...
    [key: string]: unknown;
  }
  ```
- **Why this matters:** Any property name compiles. The interface is a partial documentation of fields the FE expects, not a contract — closes off compile-time field-mismatch detection. Required because the BE has no `response_model` for these routes (BE-020).
- **Recommended fix:** Remove the index signature. Add the missing fields the BE returns (`id`, `runId`, `sbom_name`, `project_id`, `run_status`, `status`, `source`, `started_on`, `completed_on`, severity counts, `query_error_count`, plus the `sbom` and `summary` blocks if kept).
- **Effort:** S (after BE-020).
- **Risk of fix:** Low.

### Finding FE-004: `parsed: unknown[]` in `extractCveAlias` is fine

- **Severity:** none
- **Location:** [frontend/src/components/analysis/FindingsTable.tsx:23-35](../frontend/src/components/analysis/FindingsTable.tsx)
- **Note:** Type guards used correctly. **Status:** No violation.

---

## 2. Server vs. Client components

### Finding FE-005: 100% client components — App Router benefits unused

- **Severity:** Medium
- **Location:** All files in [frontend/src/app/](../frontend/src/app/) and 28 of 28 component files declare `'use client'`.
- **Evidence:** `grep -rn "use client"` returns 28 hits — every component file. Only `app/layout.tsx` is a server component (it imports `next/font` and a client `<Providers>` boundary). Pages all begin with `'use client'`.
- **Why this matters:** App Router's value (server-rendered pages, smaller client bundles, server data fetching) is forfeited. Every page is hydrated to the same SPA the project was before. The only Next-specific feature gained is file-based routing.
- **Recommended fix (gradual):**
  1. Pages that are mostly read-only (`/projects`, `/sboms`, `/analysis`, `/analysis/[id]`) become server components that fetch data via the BE and pass to a small client child for interactivity.
  2. Move the data-fetching `useQuery` calls to `loading.tsx` boundaries so the initial render isn't a spinner.
  3. The "Analyze" mutation paths (e.g. `useBackgroundAnalysis`) stay client.
- **Effort:** L (whole-app refactor).
- **Risk of fix:** Medium — significant, but high payoff.
- **Note:** Premature until YAGNI-017 (Next downgrade) is resolved.

### Finding FE-006: `app/page.tsx` (home) is `'use client'` and fetches dashboard data via React Query

- **Severity:** Low
- **Location:** [frontend/src/app/page.tsx:1](../frontend/src/app/page.tsx) (begins with `'use client'`).
- **Note:** Same as FE-005, instance: home page does four `useQuery` calls in the browser.

---

## 3. Data fetching

### Finding FE-007: `lib/api.ts` is a single typed fetch client — clean

- **Severity:** none
- **Location:** [frontend/src/lib/api.ts:1-509](../frontend/src/lib/api.ts).
- **Note:** Custom `HttpError`, `fetchWithTimeout` with caller-signal forwarding, structured error parsing. **Status:** Solid. Two minor follow-ups: FE-008, FE-009.

### Finding FE-008: Four `analyzeSbom*` functions are copy-paste

- **Severity:** Low
- **Location:** see DRY-016.

### Finding FE-009: 30s default timeout vs 180s for analysis is hard-coded across call sites

- **Severity:** Low
- **Location:** [frontend/src/lib/api.ts:280, 289, 412, 459, 480, 487, 494, 501](../frontend/src/lib/api.ts).
- **Evidence:** 8 places set timeout to `180_000` with comments like `// analysis can take up to 120s`. Default is 30_000.
- **Recommended fix:** Two named constants (`SHORT_REQUEST_TIMEOUT_MS = 30_000`, `LONG_REQUEST_TIMEOUT_MS = 180_000`) at the top of the file. Or environment-tunable.
- **Effort:** S
- **Risk of fix:** Low.

### Finding FE-010: `useAnalysisStream` builds its own SSE parser

- **Severity:** Low
- **Location:** see KISS-010.

### Finding FE-011: SSE stream client uses POST + `fetch().body.getReader()` — correct pattern, but no reconnect

- **Severity:** Medium
- **Location:** [frontend/src/hooks/useAnalysisStream.ts:118-266](../frontend/src/hooks/useAnalysisStream.ts).
- **Evidence:** No reconnect on transient disconnect; on `AbortError` the hook silently swallows; on other errors it sets `phase: 'error'`. The BE doesn't send `id:` event IDs so even a "remember last event" reconnect can't pick up cleanly.
- **Why this matters:** A user's WiFi blip mid-analysis loses the stream and they get an "error" with no way to recover except re-trigger. The analysis is still running on the server — they could retrieve via `runs/{id}` once it completes, but the UX surfaces it as an error.
- **Recommended fix:** Either (a) accept it as a tradeoff and document — analyses are server-side persisted, the user can refresh and see the run land in the runs list; or (b) implement basic exponential-backoff reconnect with idempotency-key replay.
- **Effort:** M (option b).
- **Risk of fix:** Low.

### Finding FE-012: `dispatchSbomStatus` is a parallel pub-sub on top of React Query

- **Severity:** Medium
- **Location:** [frontend/src/hooks/useBackgroundAnalysis.ts:14-21](../frontend/src/hooks/useBackgroundAnalysis.ts); see SUP-COU-002.
- **Evidence:**
  ```ts
  export function dispatchSbomStatus(sbomId, status, findingsCount?) {
    if (typeof window === 'undefined') return;
    window.dispatchEvent(new CustomEvent('sbom-analysis-update', {
      detail: { sbomId, status, findingsCount },
    }));
  }
  ```
  And: `queryClient.setQueryData<SBOMSource[]>(['sboms'], …)` updates the cache. Two notification systems for one event.
- **Why this matters:** `SbomStatusBadge` listens to the `CustomEvent`. `SbomsTable` reads from React Query cache. Drift will eventually appear (an event fires; cache update misses; one widget says "ANALYSING" while the other says "PASS").
- **Recommended fix:** Remove the `CustomEvent` channel. `SbomStatusBadge` should subscribe to React Query (`useQuery({ queryKey: ['sboms'] })`). One source of truth.
- **Effort:** S
- **Risk of fix:** Low.

---

## 4. State management

### Finding FE-013: Filter / pagination state held only in component state, not URL

- **Severity:** Low
- **Location:** [frontend/src/app/analysis/page.tsx:23-30](../frontend/src/app/analysis/page.tsx); [frontend/src/components/analysis/RunsTable.tsx:44-49](../frontend/src/components/analysis/RunsTable.tsx).
- **Evidence:** `useState` for `projectFilter`, `sbomFilter`, `statusFilter`, `search`, `selectedForCompare`, `pagination`. Reload loses everything.
- **Why this matters:** Bookmarkable URLs are an Action's-table feature; filter state in `useState` only is fine for an MVP, suboptimal for the analyst persona that this app targets.
- **Recommended fix:** `useSearchParams` + `router.replace(?...)` for non-trivial filter state. App Router has this baked in.
- **Effort:** M
- **Risk of fix:** Low.

### Finding FE-014: `usePendingAnalysisRecovery` uses sessionStorage; analysis status is also in React Query cache; also broadcast via `CustomEvent`

- **Severity:** Medium
- **Location:** [frontend/src/hooks/usePendingAnalysisRecovery.ts](../frontend/src/hooks/usePendingAnalysisRecovery.ts); [frontend/src/lib/pendingAnalysis.ts](../frontend/src/lib/pendingAnalysis.ts); [frontend/src/hooks/useBackgroundAnalysis.ts:51-52](../frontend/src/hooks/useBackgroundAnalysis.ts)
- **Evidence:** Three persistence mechanisms for "is this SBOM analyzing right now":
  * sessionStorage (`addPendingAnalysis`/`removePendingAnalysis`)
  * React Query cache (`SBOMSource._analysisStatus = 'ANALYSING'`)
  * `CustomEvent` channel (FE-012)
- **Why this matters:** Three sources, one truth. The recovery logic re-fires the analysis on reload — but if the analysis has actually completed server-side between page-unload and reload, the FE will issue a duplicate request. (BE-side `Idempotency-Key` would mitigate, but `useBackgroundAnalysis` doesn't send one.)
- **Recommended fix:** On reload, query `/api/runs?sbom_id=X&run_status=PENDING` (after adding such a state) or `/api/runs?sbom_id=X` and check the latest run's age. Drop the sessionStorage and `CustomEvent` channels. React Query is the source of truth, server is the durable record.
- **Effort:** M
- **Risk of fix:** Low.

### Finding FE-015: `_analysisStatus` and `_findingsCount` are client-only fields tacked onto `SBOMSource`

- **Severity:** Low
- **Location:** [frontend/src/types/index.ts:25-27](../frontend/src/types/index.ts)
- **Evidence:**
  ```ts
  export interface SBOMSource {
    ...
    _analysisStatus?: 'ANALYSING' | 'PASS' | 'FAIL' | 'PARTIAL' | 'ERROR' | 'NOT_ANALYSED';
    _findingsCount?: number;
  }
  ```
- **Why this matters:** Mixing API shape with client-only state in the same type. The `_` prefix is a hint that doesn't survive a refactor. If a query returns `SBOMSource[]` from the BE without the `_*` fields, every place that reads them must `?? defaults`.
- **Recommended fix:** Separate `SBOMSourceWithAnalysis` (UI type) from `SBOMSource` (API type). Convert at the boundary.
- **Effort:** S
- **Risk of fix:** Low.

---

## 5. Component cohesion

### Finding FE-016: `AnalysisPage` (422 lines) does five distinct responsibilities

- **Severity:** Medium
- **Location:** [frontend/src/app/analysis/page.tsx](../frontend/src/app/analysis/page.tsx)
- **Evidence:**
  * Filters (project / sbom / status) + their selects.
  * Multi-select state for "Compare runs" + button.
  * Consolidated analysis form + result rendering.
  * Analysis config display.
  * Runs table + export buttons.
- **Why this matters:** Big page component, lots of state. Single re-render touches all of it.
- **Recommended fix:** Split into sub-components: `AnalysisFiltersBar`, `RunCompareSelector`, `AdhocAnalysisPanel`, `AnalysisConfigCard`. Keep them in `frontend/src/components/analysis/`.
- **Effort:** M
- **Risk of fix:** Low.

### Finding FE-017: `SbomDetail` (329 lines) and `RunsTable` (298 lines) are large but cohesive

- **Severity:** Low
- **Note:** Long but each does one job. Defer.

### Finding FE-018: `SbomUploadModal` mixes upload, file detection heuristics, and dup-name prevention in one component

- **Severity:** Low
- **Location:** [frontend/src/components/sboms/SbomUploadModal.tsx:1-262](../frontend/src/components/sboms/SbomUploadModal.tsx)
- **Note:** `detectSbomTypeId` could be a util; `formatUploadError` could too. Acceptable for now.

---

## 6. Form handling

### Finding FE-019: Zod schema validates frontend-only

- **Severity:** Low
- **Location:** [frontend/src/components/sboms/SbomUploadModal.tsx:17-25](../frontend/src/components/sboms/SbomUploadModal.tsx); [frontend/src/components/projects/ProjectModal.tsx](../frontend/src/components/projects/ProjectModal.tsx)
- **Evidence:** Zod schema mirrors Pydantic `SBOMSourceCreate` but is hand-maintained.
- **Why this matters:** Drift between Zod (FE) and Pydantic (BE). Cross-listed in `09_cross_cutting.md`.
- **Recommended fix:** Generate FE types from BE OpenAPI (`openapi-typescript-codegen` or similar). Drop hand-written Zod for shapes that mirror Pydantic; keep Zod for FE-only client checks.
- **Effort:** M
- **Risk of fix:** Low.

### Finding FE-020: 20 MB file-size limit duplicated on FE error message but not in upload code

- **Severity:** Low
- **Location:** [frontend/src/components/sboms/SbomUploadModal.tsx:45-46](../frontend/src/components/sboms/SbomUploadModal.tsx)
- **Evidence:** The error string says `"File too large. Maximum size is 20 MB."` but no client-side check exists in the upload form. (Only handles BE-returned 413.) BE doesn't enforce either — see BE-029.
- **Recommended fix:** Add a pre-upload size check `if (file.size > 20 * 1024 * 1024) ...` AND wire BE-029.
- **Effort:** S
- **Risk of fix:** Low.

---

## 7. Accessibility

### Finding FE-021: `useToast` toast has `role="alert"` and `aria-live` — good; toast button has `aria-label="Dismiss"` — good

- **Severity:** none — verified positive.
- **Location:** [frontend/src/hooks/useToast.tsx:163, 180](../frontend/src/hooks/useToast.tsx).

### Finding FE-022: `Table` has `role="region"` + `aria-label` only when label provided

- **Severity:** Low
- **Location:** [frontend/src/components/ui/Table.tsx:17-18](../frontend/src/components/ui/Table.tsx); ~10 callers don't pass `ariaLabel`.
- **Why this matters:** Tables without `aria-label` are still readable but lose context for screen-reader users. WCAG 2.2 AA recommends.
- **Recommended fix:** Make `ariaLabel` required on the typed prop, OR wrap each callsite that omits it.
- **Effort:** S
- **Risk of fix:** Low.

### Finding FE-023: Custom `Dialog` doesn't trap focus

- **Severity:** Medium
- **Location:** [frontend/src/components/ui/Dialog.tsx](../frontend/src/components/ui/Dialog.tsx) (205 lines)
- **Note:** **`[REQUIRES VERIFICATION]`** — I read 80 lines of `SbomUploadModal` only. Hand-rolled dialogs typically miss focus-trap, return-focus-on-close, and aria-modal. Native `<dialog>` element or Radix Dialog handles all three.
- **Recommended fix:** Replace with [`@radix-ui/react-dialog`](https://www.radix-ui.com/primitives/docs/components/dialog) (already in the shadcn/ui stack the prompt says is in use). Smaller code, accessibility-by-default.
- **Effort:** M
- **Risk of fix:** Low.

### Finding FE-024: Severity colour badges may not meet 4.5:1 contrast in light mode

- **Severity:** [REQUIRES VERIFICATION]
- **Location:** [frontend/src/components/analysis/FindingsTable.tsx:52-58](../frontend/src/components/analysis/FindingsTable.tsx)
- **Evidence:** `text-indigo-700` on `bg-indigo-50` is fine. `text-emerald-700` on `bg-emerald-50` borderline. Verify with axe / Lighthouse before declaring conformant.

### Finding FE-025: All `'use client'` pages render a spinner while loading

- **Severity:** Low
- **Location:** Various `useQuery` `isLoading` branches.
- **Note:** Pure client fetch makes initial paint always be a spinner. Server components + `loading.tsx` would skeleton-render server-side. Cross-listed with FE-005.

---

## 8. Performance

### Finding FE-026: No `loading.tsx` / `error.tsx` per-route boundaries

- **Severity:** Low
- **Location:** verified by `find frontend/src/app -name 'loading.tsx' -o -name 'error.tsx' -o -name 'not-found.tsx'` returns nothing.
- **Note:** App Router supports per-route `loading.tsx` and `error.tsx`. Adding them gives streaming SSR + per-route error boundaries. Defer until FE-005 is tackled (Next downgrade resolved first).

### Finding FE-027: `getSboms(1, 100)` and `getSboms(1, 500)` inconsistent across pages

- **Severity:** Low
- **Location:** [frontend/src/app/analysis/page.tsx:72](../frontend/src/app/analysis/page.tsx); [frontend/src/components/sboms/SbomUploadModal.tsx:72-76](../frontend/src/components/sboms/SbomUploadModal.tsx).
- **Evidence:** Analysis page fetches 100 SBOMs for the dropdown; upload modal fetches 500 for dup-check. Two ad-hoc page sizes.
- **Recommended fix:** A `useAllSboms()` hook that paginates internally. Or accept the cap and treat the dropdown as "first 100 by id".
- **Effort:** S
- **Risk of fix:** Low.

### Finding FE-028: All 28 components are client + Tanstack Query — bundle includes everything

- **Severity:** [REQUIRES VERIFICATION]
- **Note:** Run `next build` and check first-load JS for the home route. Current architecture (`'use client'` everywhere) cannot tree-shake Tanstack Query out of the home page. Cross-listed with FE-005.

### Finding FE-029: `cache: 'no-store'` not used; defaults to no-cache via headers

- **Severity:** none
- **Location:** [frontend/src/lib/api.ts:96-103](../frontend/src/lib/api.ts).
- **Note:** Default `fetch` options set `'Content-Type': 'application/json'` only; no caching directive. Acceptable for a SPA. **Status:** No violation.

---

## 9. Routing

### Finding FE-030: App Router conventions used (`[id]`, `compare/`)

- **Severity:** none
- **Location:** [frontend/src/app/](../frontend/src/app/).
- **Note:** Conventions are correct for the Next 14 App Router that the code targets. Blocked by YAGNI-017 (Next 9 installed).

### Finding FE-031: No parallel routes / intercepting routes / route groups — good (YAGNI)

- **Severity:** none
- **Note:** No premature use of advanced router features. **Status:** No violation.

---

## 10. Theme / styling

### Finding FE-032: `themeInitScript` inlined as `<Script strategy="beforeInteractive">` — anti-FOUC pattern

- **Severity:** none
- **Location:** [frontend/src/app/layout.tsx:19, 29-31](../frontend/src/app/layout.tsx).
- **Note:** Correct technique. **Status:** No violation. Listed as a positive example.

### Finding FE-033: Tailwind dark-mode toggling via `localStorage` (`spectra-theme` key)

- **Severity:** Low
- **Location:** [frontend/src/components/theme/ThemeProvider.tsx](../frontend/src/components/theme/ThemeProvider.tsx) (72 lines).
- **Note:** **`[REQUIRES VERIFICATION]`** of full file. Standard pattern; defer.

---

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 7 |
| Low | 13 |
| Verified-positive | 6 |
| [REQUIRES VERIFICATION] | 3 |
| **Total** | **29** |

**Highest-leverage frontend fixes:**
1. **YAGNI-017** (cross-listed) — Resolve the Next 9 / App Router mismatch first; everything else is contingent.
2. **FE-012 + FE-014** — Collapse the three persistence channels for analysis status into one (React Query). Cuts `dispatchSbomStatus`, `pendingAnalysis.ts`, `usePendingAnalysisRecovery` complexity.
3. **FE-003** — Drop `[key: string]: unknown` from `ConsolidatedAnalysisResult` once the BE has a `response_model`. Restores compile-time field-mismatch detection.
4. **FE-005** — Move data-fetching pages to server components. Big win on initial paint, bundle size, and removes the spinner-on-first-render UX. (Big effort — schedule for after the decision on Next version.)
5. **FE-023** — Replace hand-rolled `Dialog` with Radix Dialog. Accessibility win, code reduction, and the prompt says "shadcn/ui" is the stack — meet that promise.
