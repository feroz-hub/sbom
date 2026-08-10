# AI Fixes UI Integration — Phase 1 Audit

**Date:** 2026-05-04
**Scope:** Read-only audit before Phases 2–5 of the AI fixes UI integration prompt.
**Audit type:** Backend contract verification + frontend artifact inventory + integration-surface mapping.

---

## TL;DR

The premise of the prompt — *"frontend has no integration"* — is **wrong**. A substantial integration is already in place across roughly 40 frontend files, all uncommitted. Backend is solid; nearly every spec endpoint exists with shape-compatible Pydantic schemas, the only path divergence is the trigger endpoint (`POST /runs/{id}/ai-fixes` not `/ai-fixes/generate`) and the regenerate endpoint (`:regenerate` colon syntax). Three real gaps remain: (1) global-progress SSE provider that survives route changes, (2) findings-table AI-fix indicator column, (3) dashboard configuration banner. One design divergence: AI Remediation is rendered as an **inline section** at the bottom of the CVE modal, not as a tab.

We are **ready for Phase 2** with a revised, smaller scope: finish the gaps above and decide whether to consolidate the existing inline AI section into a tab. No backend work needed first.

---

## Section A — Backend contract status

### A.1 Live probe summary

Backend server: `python3 run.py` on `localhost:8000`, running since 2026-05-04 01:11:25.
**Important caveat:** the server process predates several uncommitted backend files (`app/routers/ai_credentials.py` last modified 01:50, `app/ai/registry.py` 01:47). Live 404s on credentials/settings/`providers/available` reflect server staleness, not missing code. After a restart, all routes register correctly per the source.

| Endpoint | Live result | Source registered? | Notes |
|---|---|---|---|
| `GET /api/v1/ai/usage` | **200 OK** | yes — [app/routers/ai_usage.py:143](app/routers/ai_usage.py#L143) | Full payload returned with default budget caps |
| `GET /api/v1/ai/providers` | **200 OK** | yes — [ai_usage.py:176](app/routers/ai_usage.py#L176) | Returns provider availability list |
| `GET /api/v1/ai/providers/available` | 404 (stale) | yes — [ai_usage.py:350](app/routers/ai_usage.py#L350) | Will register on restart |
| `GET /api/v1/ai/credentials` | 404 (stale) | yes — [ai_credentials.py:309](app/routers/ai_credentials.py#L309) | Whole router not loaded yet |
| `GET /api/v1/ai/settings` | 404 (stale) | yes — [ai_credentials.py:644](app/routers/ai_credentials.py#L644) | Whole router not loaded yet |
| `GET /api/v1/runs/1/ai-fixes` | **200 OK** | yes — [ai_fixes.py:348](app/routers/ai_fixes.py#L348) | Returns `{run_id, items: [], total: 0}` |
| `GET /api/v1/runs/1/ai-fixes/progress` | **200 OK** | yes — [ai_fixes.py:312](app/routers/ai_fixes.py#L312) | Full `BatchProgress` shape |
| `GET /api/v1/runs/1/ai-fixes/estimate` | 404 (stale) | yes — [ai_fixes.py:230](app/routers/ai_fixes.py#L230) | Will register on restart |

**Action required before Phase 2:** restart `run.py` so the credential / settings / estimate / provider-catalog endpoints become live.

### A.2 Spec-vs-reality matrix

Routers and their prefixes:
- `ai_usage` — `prefix="/api/v1/ai"` ([ai_usage.py:40](app/routers/ai_usage.py#L40))
- `ai_credentials` — `prefix="/api/v1/ai"` ([ai_credentials.py:55](app/routers/ai_credentials.py#L55))
- `ai_fixes` — `prefix="/api/v1"` ([ai_fixes.py:65](app/routers/ai_fixes.py#L65))

All three are registered in [app/main.py:277-279](app/main.py#L277) under `_protected` auth dependencies.

| Spec endpoint | Source path | Match? | Auth | Notes |
|---|---|---|---|---|
| `GET /api/v1/ai/providers/available` | `/api/v1/ai/providers/available` | ✓ | protected | Returns `list[ProviderCatalogEntry]` — drives the AddProviderDialog dropdown |
| `GET /api/v1/ai/credentials` | `/api/v1/ai/credentials` | ✓ | protected | Returns `list[CredentialResponse]` (preview-only, no raw keys) |
| `POST /api/v1/ai/credentials` | `/api/v1/ai/credentials` | ✓ | protected | Body: `CredentialCreateRequest` |
| `PUT /api/v1/ai/credentials/{id}` | `/api/v1/ai/credentials/{cred_id}` | ✓ | protected | `api_key` optional → omitted preserves existing |
| `DELETE /api/v1/ai/credentials/{id}` | `/api/v1/ai/credentials/{cred_id}` | ✓ | protected | 204 No Content |
| `POST /api/v1/ai/credentials/{id}/test` | `/api/v1/ai/credentials/{cred_id}/test` | ✓ | protected | Decrypts stored key in-memory only |
| `PUT /api/v1/ai/credentials/{id}/set-default` | same | ✓ | protected | Atomic swap: clears all others, sets one |
| `PUT /api/v1/ai/credentials/{id}/set-fallback` | same | ✓ | protected | Same swap pattern |
| `GET /api/v1/ai/settings` | `/api/v1/ai/settings` | ✓ | protected | Singleton; defaults if seed row missing |
| `PUT /api/v1/ai/settings` | `/api/v1/ai/settings` | ✓ | protected | Validates `per_request ≤ per_scan ≤ daily` |
| `GET /api/v1/ai/usage` | `/api/v1/ai/usage` | ✓ | protected | Includes today + 30-day windows + budget caps |
| `POST /api/v1/runs/{id}/ai-fixes/generate` | **`POST /api/v1/runs/{id}/ai-fixes`** | ✗ | protected | **No `/generate` suffix.** Returns `TriggerBatchResponse{progress, enqueued}` |
| `GET /api/v1/runs/{id}/ai-fixes/progress` | same | ✓ | protected | Snapshot for polling |
| `GET /api/v1/runs/{id}/ai-fixes/stream` | same | ✓ | protected | SSE — `event: progress\ndata: <json>\n\n`, terminal `event: end` |
| `POST /api/v1/runs/{id}/ai-fixes/cancel` | same | ✓ | protected | 202 Accepted |
| `GET /api/v1/runs/{id}/ai-fixes/summary` | **no exact match** | ⚠ | — | Spec calls for "summary"; reality: pre-flight estimate at `/estimate` (returns `BatchDurationEstimateResponse`) AND post-batch listing at `/runs/{id}/ai-fixes` (returns `FindingFixListResponse`). Frontend already uses both. |
| `GET /api/v1/findings/{id}/ai-fix` | same | ✓ | protected | Generates on demand if cache cold; envelope `{result?, error?}` |

### A.3 Bonus endpoints (in source, not in spec, already wired in frontend)

| Path | Purpose |
|---|---|
| `POST /api/v1/ai/credentials/test` | Test-before-save with un-persisted config — used by `AddProviderDialog` |
| `POST /api/v1/findings/{id}/ai-fix:regenerate` | Force-refresh single fix — used by `AiFixSection.regenerate` |
| `GET /api/v1/runs/{id}/ai-fixes/estimate` | Pre-flight cost/time estimate — used by `FreeTierWarningDialog` |
| `GET /api/v1/ai/providers/available/{name}` | One-provider catalog lookup |
| `GET /api/v1/ai/usage/trend?days=30` | Per-day cost / call / cache-hit series for sparkline |
| `GET /api/v1/ai/usage/top-cached?limit=20` | Most expensive cached fixes leaderboard |
| `GET /api/v1/ai/pricing` | Public pricing table |
| `GET /api/v1/ai/metrics` and `/metrics/prometheus` | Observability hooks |

### A.4 Schema landmarks

- **`AiFixBundle`** — three artifacts: `RemediationProse`, `UpgradeCommand`, `DecisionRecommendation`. Defined in [app/ai/schemas.py](app/ai/schemas.py). Matches frontend `AiFixBundle` in [frontend/src/types/ai.ts:56](frontend/src/types/ai.ts#L56).
- **`BatchProgress`** — defined in [app/ai/progress.py](app/ai/progress.py). Status enum: `pending | in_progress | paused_budget | complete | failed | cancelled`. Frontend mirror at [types/ai.ts:115](frontend/src/types/ai.ts#L115).
- **Kill switch field** — `ai_settings.kill_switch_active: bool` ([ai_credentials.py:160](app/routers/ai_credentials.py#L160)). Frontend reads via `useAiCredentialSettings`.
- **Test-connection result** — `ConnectionTestResult` from [app/ai/providers/base.py](app/ai/providers/base.py). Includes `success`, `latency_ms`, `detected_models`, `error_message`, `error_kind` (network / auth / rate_limit / model_not_found / invalid_response / unknown).

### A.5 SSE stream verification

Source: [ai_fixes.py:329-345](app/routers/ai_fixes.py#L329). Generator yields:
- `:ok\n\n` — initial keepalive ping
- `event: progress\ndata: <json>\n\n` — on every state change
- `event: end\ndata: {}\n\n` — terminal

Frontend correctly subscribes via `EventSource` in [hooks/useAiFix.ts:134-168](frontend/src/hooks/useAiFix.ts#L134) with polling fallback at 2s. Could not run a live SSE probe against an in-flight batch (no real provider configured against this server), but both ends look correct against each other.

---

## Section B — Existing frontend artifacts

The premise "frontend has no integration" is **incorrect**. The git status shows ~40 uncommitted files that constitute a substantial in-progress integration. Inventory below.

### B.1 API client — `frontend/src/lib/api.ts`

All AI fetch functions present at lines 833–1091. Classification: **REUSE** — every endpoint the UI needs already has a typed wrapper.

| Function | Endpoint | Status |
|---|---|---|
| `getFindingAiFix` | `GET /findings/{id}/ai-fix` | reuse |
| `regenerateFindingAiFix` | `POST /findings/{id}/ai-fix:regenerate` | reuse |
| `triggerRunAiFixes` | `POST /runs/{id}/ai-fixes` | reuse |
| `cancelRunAiFixes` | `POST /runs/{id}/ai-fixes/cancel` | reuse |
| `getRunAiFixProgress` | `GET /runs/{id}/ai-fixes/progress` | reuse |
| `listRunAiFixes` | `GET /runs/{id}/ai-fixes` | reuse |
| `aiFixStreamUrl` | full SSE URL | reuse |
| `listAiProviders` | `GET /ai/providers` | reuse |
| `listAiPricing`, `getAiUsageSummary`, `getAiUsageTrend`, `getAiTopCachedFixes` | `/ai/pricing`, `/ai/usage*` | reuse |
| `listAiCredentials`, `getAiCredential`, `createAiCredential`, `updateAiCredential`, `deleteAiCredential` | `/ai/credentials*` | reuse |
| `setAiCredentialDefault`, `setAiCredentialFallback` | promotion endpoints | reuse |
| `testAiCredentialUnsaved`, `testAiCredentialSaved` | both test forms | reuse |
| `getAiCredentialSettings`, `updateAiCredentialSettings` | singleton settings | reuse |
| `listAiProviderCatalog`, `getAiProviderCatalogEntry` | catalog | reuse |
| `getRunBatchEstimate` | pre-flight estimate | reuse |

The flag `AnalysisConfig.ai_ui_config_enabled` ([api.ts:200](frontend/src/lib/api.ts#L200)) gates the editable settings page; `ai_fixes_enabled` is the master flag.

### B.2 Types — `frontend/src/types/ai.ts`

Comprehensive — 384 lines covering every Pydantic schema. Classification: **REUSE**.

Includes: `AiRemediationProse`, `AiUpgradeCommand`, `AiDecisionRecommendation`, `AiFixBundle`, `AiFixMetadata`, `AiFixResult`, `AiFixError`, `AiFindingFixEnvelope`, `AiBatchStatus`, `AiBatchProgress`, `AiTriggerBatchRequest/Response`, `AiCredential` (+ create/update/test request shapes), `AiCredentialSettings`, `AiProviderCatalogEntry`, `AiBatchDurationEstimate`, etc.

### B.3 Hooks

| File | Hooks exposed | Status |
|---|---|---|
| [hooks/useAiCredentials.ts](frontend/src/hooks/useAiCredentials.ts) | `useAiCredentials`, `useCreateAiCredential`, `useUpdateAiCredential`, `useDeleteAiCredential`, `useSetDefaultCredential`, `useSetFallbackCredential`, `useTestConnection` (returns `{unsaved, saved}` mutations), `useAiCredentialSettings`, `useUpdateAiCredentialSettings`, `useProviderCatalog`, `useRunBatchEstimate` | reuse |
| [hooks/useAiFix.ts](frontend/src/hooks/useAiFix.ts) | `useAiFix` (with embedded regenerate mutation), `useAiBatchProgress` (SSE-with-polling-fallback), `useTriggerAiFixes`, `useCancelAiFixes`, `useRunAiFixList`, `useAiSettings`, `invalidateAllAiFixes` | reuse |

Mutations correctly invalidate query keys. SSE-vs-polling switch is well-implemented but per-component (see Gap G1).

### B.4 Pages / routes

| Route | File | Status |
|---|---|---|
| `/settings` | [app/settings/page.tsx](frontend/src/app/settings/page.tsx) | **REUSE** — index links to `/settings/ai`. Comment confirms old read-only `AiSettings` is "superseded". |
| `/settings/ai` | [app/settings/ai/page.tsx](frontend/src/app/settings/ai/page.tsx) | **REUSE** — gated behind both `ai_fixes_enabled` and `ai_ui_config_enabled` flags. Falls back to friendly env-instruction notice when off. |
| `/admin/ai-usage` | [app/admin/ai-usage/page.tsx](frontend/src/app/admin/ai-usage/page.tsx) | **REUSE** — operator cost dashboard via `CostDashboard` from old settings folder. |
| `/analysis/[id]` | [app/analysis/[id]/page.tsx](frontend/src/app/analysis/[id]/page.tsx) | **EXTEND** — already mounts `<RunBatchProgress runId={id} />` and forwards `aiFixesEnabled` to `FindingsTable`. Missing pre-flight CTA card with explicit estimate display (only the FreeTierWarningDialog short-circuit). |

### B.5 Component inventory

#### B.5.a `frontend/src/components/settings/ai/` — NEW, editable settings UI

| File | Description | Status |
|---|---|---|
| [AiSettingsPage.tsx](frontend/src/components/settings/ai/AiSettingsPage.tsx) | Top-level container. Renders kill-switch banner + `ProvidersList` + `BudgetCapsForm` + `UsageSummary` + `AddProviderDialog` + `EditProviderDialog`. | reuse |
| `ProvidersList/{ProvidersList,ProviderCard,ProviderStatusIndicator,ProviderTierBadge}.tsx` | List, individual card with kebab actions, status indicator, tier badge | reuse |
| `AddProviderDialog/{AddProviderDialog,TestResultDisplay}.tsx` | Single-form dialog with test-before-save gate, dynamic provider fields driven by catalog. Save button disabled until `testMut.data?.success === true` ([line 87](frontend/src/components/settings/ai/AddProviderDialog/AddProviderDialog.tsx#L87)). | reuse |
| `EditProviderDialog/EditProviderDialog.tsx` | Edit existing credential (api_key omitted preserves existing, per backend contract) | reuse |
| `BudgetCapsForm/BudgetCapsForm.tsx` | Three numeric inputs + Save | reuse |
| `UsageSummary/UsageSummary.tsx` | Read-only this-month tile | reuse |
| `__tests__/*` | axe + behavior tests for AddProviderDialog, BudgetCapsForm, ProviderTierBadge, ProviderStatusIndicator, TestResultDisplay, AiSettingsPage | reuse |

API key handling is correct: never written to a DOM element except the input itself; show/hide toggle present; preview shown via `api_key_preview` from backend response only (never the full key).

#### B.5.b `frontend/src/components/ai-fixes/` — Run / modal AI surfaces

| Subdir | Description | Status |
|---|---|---|
| `AiFixSection/` | Inline section rendered inside the CVE modal body. Contains `RemediationProse`, `UpgradeCommandCard`, `DecisionRecommendationCard`, `AiFixMetadata`, `AiFixGenerateButton`. | **EXTEND** — see divergence D1 |
| `RunBatchProgress/` | Banner above findings table on run detail page. Has `BatchControls` (Generate / Cancel buttons), `BatchProgressBar`, integrates with `FreeTierWarningDialog`. | **EXTEND** — needs pre-flight estimate display + global lifting |
| `FreeTierWarningDialog/` | Pre-flight modal shown when `estimate.warning_recommended` flips true (free tier on a large batch). | reuse |
| `Settings/{AiSettings,UsageMetrics,CostDashboard,BudgetCapsForm,ProviderSelect}.tsx` | Older read-only settings family. `AiSettings` is **orphaned** ([only test references](frontend/src/components/ai-fixes/__tests__/AiSettings.test.tsx) plus self-export); `CostDashboard` is still used by `/admin/ai-usage`; `BudgetCapsForm` here is distinct from the new editable one. | **DELETE** for `AiSettings.tsx` (orphan) + `Settings/BudgetCapsForm.tsx` + `Settings/ProviderSelect.tsx` if not referenced; **KEEP** `CostDashboard` and `UsageMetrics` until `/admin/ai-usage` migrates to a new page. |
| `__tests__/*` | Tests for AiFixSection (incl. axe), AiSettings (covers the orphan), RunBatchProgress | extend (drop the orphan test) |

#### B.5.c CVE detail modal integration

| File | Change | Status |
|---|---|---|
| [CveDetailDialog.tsx](frontend/src/components/vulnerabilities/CveDetailDialog/CveDetailDialog.tsx) | Adds `findingId`, `aiFixesEnabled`, `aiProviderLabel` props; forwards to `CveDetailContent` | reuse — already integrated |
| [CveDetailContent.tsx](frontend/src/components/vulnerabilities/CveDetailDialog/CveDetailContent.tsx) | Renders `<AiFixSection findingId={...} />` after the three deterministic sections | **divergence D1** — section, not tab |

#### B.5.d Findings table

[FindingsTable.tsx](frontend/src/components/analysis/FindingsTable.tsx):
- Accepts `aiFixesEnabled` and `aiProviderLabel` props ([line 99–102](frontend/src/components/analysis/FindingsTable.tsx#L99))
- Forwards them to `<CveDetailDialog>` at line 651
- **Does NOT render an AI-fix indicator column** — see Gap G2

### B.6 Sidebar / navigation

[Sidebar.tsx](frontend/src/components/layout/Sidebar.tsx) already contains the Settings nav with two children:
```ts
{ href: '/settings', label: 'Settings', icon: SettingsIcon, children: [
  { href: '/settings/ai', label: 'AI configuration' },
  { href: '/admin/ai-usage', label: 'AI usage' },
]}
```
([lines 56–64](frontend/src/components/layout/Sidebar.tsx#L56)). Active-state matching includes `/admin/ai-usage` under the Settings parent ([line 75](frontend/src/components/layout/Sidebar.tsx#L75)). **Status: REUSE — no change needed.**

### B.7 Global providers / app shell

[providers.tsx](frontend/src/app/providers.tsx) mounts `QueryClientProvider`, `ThemeProvider`, `ToastProvider`, `CommandPalette`, `KeyboardCheatsheet`. **No global AI batch progress provider.** SSE subscription only exists per-component inside `RunBatchProgress`. See Gap G1.

---

## Section C — Integration surfaces

### C.1 Settings nav structure
- **Where:** [components/layout/Sidebar.tsx:56-64](frontend/src/components/layout/Sidebar.tsx#L56)
- **Pattern:** parent route + nested children, expanded accordion when active
- **Already wired:** `/settings/ai` and `/admin/ai-usage` both linked
- **Action:** none — reuse as-is

### C.2 Settings page shell
- **Index:** [app/settings/page.tsx](frontend/src/app/settings/page.tsx) — single-section index pattern, easy to extend with future settings rows
- **AI route:** [app/settings/ai/page.tsx](frontend/src/app/settings/ai/page.tsx) — gates on `ai_fixes_enabled` AND `ai_ui_config_enabled`. Renders `<AiSettingsPage />`.
- **Pattern for new settings:** `TopBar` → `max-w-4xl` main → back link → flag-gate → page component
- **Action:** none — pattern to copy if more settings sections are added

### C.3 Run detail page integration
- **File:** [app/analysis/[id]/page.tsx](frontend/src/app/analysis/[id]/page.tsx)
- **Layout flow:** `TopBar` → back button → `<RunDetailHero>` → run error alert → outcome footnote → `<RunBatchProgress>` (line 219) → findings `<Surface>` with `<FindingsTable>`
- **AI banner placement:** already correct — between hero and findings table, gated by `ai_fixes_enabled`
- **Pre-flight CTA gap:** the prompt asks for an explicit card showing `300 LLM calls · ~$5.10 · ~90 seconds · provider X` *before* the user clicks Generate. Today the banner shows minimal copy ("Generate AI remediation for every finding in this run.") and only triggers `FreeTierWarningDialog` when `estimate.warning_recommended` flips true. The estimate hook (`useRunBatchEstimate`) is already wired but its data isn't surfaced visually until that dialog fires.
- **Action:** Phase 3 — extend `RunBatchProgress` (or wrap it) so the idle state shows the full estimate inline.

### C.4 Findings table integration
- **File:** [components/analysis/FindingsTable.tsx](frontend/src/components/analysis/FindingsTable.tsx)
- **Pattern:** custom `<Table>` (not TanStack Table) with named cell renderers. Columns: vuln_id / severity / score / risk_score / epss / component_name / component_version / fixed_version / source / published_on
- **Where new column slots in:** between `score`/`risk_score` and `component_name`, OR at the far right before published_on. Spec says "between existing columns (placement determined by audit)". Recommend right side, before published_on, conditionally hidden.
- **Hidden when not configured:** column should `display: none` when `aiFixesEnabled === false` per spec §3.9
- **Source of "fix exists" truth:** `useRunAiFixList(runId)` (already exposed, returns the cache list) — set membership lookup by finding id → cache key
- **Action:** Phase 3 — add column.

### C.5 CVE detail modal integration
- **Files:** [CveDetailDialog.tsx](frontend/src/components/vulnerabilities/CveDetailDialog/CveDetailDialog.tsx), [CveDetailContent.tsx](frontend/src/components/vulnerabilities/CveDetailDialog/CveDetailContent.tsx)
- **Existing tab structure:** **none** — the modal is a single scrolling body with three section components (`CveWhatSection`, `CveExploitSection`, `CveFixSection`) and a sticky `CveReferences` footer. There is **no shadcn `<Tabs>` here**.
- **Current AI integration:** `<AiFixSection>` is appended as a fourth body section after `CveFixSection`, separated by a `border-t`.
- **Spec-vs-reality:** spec asks for an "AI Remediation **tab**" alongside Overview / Affected / References. Reality is sectioned single-scroll. **This is a design decision to surface, not a bug.** Two options:
  - Keep section pattern (matches existing modal style; one less click for the user)
  - Refactor to tabs (matches spec; introduces new pattern that doesn't exist anywhere else in the modal)
- **Action:** Phase 4 — owner decides. The audit's recommendation is to keep sections (consistent with existing CVE modal language) and update the prompt's success criteria, but await owner call.

### C.6 App shell / global progress banner mount point
- **Layout file:** [app/layout.tsx](frontend/src/app/layout.tsx) and [app/providers.tsx](frontend/src/app/providers.tsx)
- **Existing top-level providers:** `QueryClientProvider`, `ThemeProvider`, `ToastProvider`, `CommandPalette`, `KeyboardCheatsheet`
- **Where global SSE provider would slot:** inside `<ToastProvider>` so it can emit toasts on completion; can render its banner via portal
- **Action:** Phase 3 — add `<AiBatchProgressProvider>` and a `<GlobalAiBatchBanner>` rendered inside the authenticated layout.

### C.7 Dashboard for "AI not configured" banner
- **Likely file:** `frontend/src/app/page.tsx` (dashboard root) — was not opened in this audit; recommend Phase 5 spike a quick read
- **Pattern to follow:** existing top-of-page alerts (e.g. analysis page error banner)
- **Action:** Phase 5 — add small banner on dashboard root.

### C.8 shadcn / UI primitives in use
[components/ui/](frontend/src/components/ui): `Alert`, `Badge`, `Button`, `Card`, `CvssMeter`, `Dialog`, `EmptyState`, `EpssChip`, `ExportMenu`, `Input`, `KevBadge`, `Motion`, `Pagination`, `PinButton`, `Select`, `Sparkline`, `Spinner`, `Surface`, `Table`, `TableFilterBar`, `Toast`. **No `Tabs` primitive present** — confirms C.5 design call.

### C.9 Theme system
[components/theme/ThemeProvider](frontend/src/components/theme/) provides light/dark. New AI components already use semantic tokens (`bg-surface`, `text-hcl-navy`, `border-border-subtle`, `bg-surface-muted`, primary color etc.) — light/dark parity is already in place across the existing AI surfaces.

---

## Section D — Divergences and gaps

### D1 — Design divergence: AI Remediation is a section, not a tab

**What spec says (Phase 4 §4.1):** The CVE modal gains a new tab "AI Remediation" alongside Overview / Affected / References.

**What exists:** The CVE modal uses a section pattern with no tabs. `<AiFixSection>` is appended after the three deterministic sections inside [CveDetailContent.tsx:48](frontend/src/components/vulnerabilities/CveDetailDialog/CveDetailContent.tsx#L48).

**Why this matters:** Adding tabs would require introducing a `Tabs` primitive that doesn't exist in the design system, and would split the existing well-tested CVE body into tabbed views. The current section pattern is consistent with how the rest of the modal is structured.

**Recommendation:** keep sections. The user's Phase 4 success criteria should be re-stated as "AI Remediation section renders in all four states" rather than "tab renders". Owner sign-off needed before Phase 2 begins so we don't accidentally rebuild what's working.

### G1 — Gap: global SSE progress banner

**What spec says (§3.3 / §3.7):** Persistent banner on every page showing batch progress. Survives navigation. Stacks up to 3 concurrent batches with a "+N more" affordance.

**What exists:** `useAiBatchProgress` is called inside `RunBatchProgress`, which is mounted only on the run detail page. Navigating away terminates the SSE stream and unmounts the hook; coming back restarts it from scratch via `useQuery` cache.

**Fix scope (Phase 3):**
- Add `AiBatchProgressProvider` mounted in `app/providers.tsx`
- Provider tracks an array of active batches; opens an `EventSource` per batch
- Renders `<GlobalAiBatchBanner>` via portal at top of authenticated layout
- Stack rule: max 3 visible, collapse the rest into a counter

### G2 — Gap: findings-table AI-fix indicator column

**What spec says (§3.9):** A column with ✦ icon when a fix exists for that row. Hidden when feature not configured.

**What exists:** `aiFixesEnabled` is plumbed through `FindingsTable` props but no column is rendered. `useRunAiFixList(runId)` is exposed but unused on this surface.

**Fix scope (Phase 3):**
- Conditional column when `aiFixesEnabled === true`
- Cell content: ✦ when present, dim/empty when not, amber-dot when generation failed for that row
- Row click on ✦ opens CVE modal with AI section scrolled into view (or tab pre-selected if D1 is resolved as tabs)
- Lookup: build a `Set<cache_key>` from `useRunAiFixList`; resolve finding → cache_key via the same `build_grounding_context` logic the backend uses (frontend can rely on `vuln_id + component_name + component_version` since backend exposes those on the list response)

### G3 — Gap: dashboard configuration banner

**What spec says (§5.1):** Dashboard shows "AI fixes aren't configured yet · Set up a provider →" when no provider is configured and kill switch is off.

**What exists:** Searched for the copy across `frontend/src/`; **not found**.

**Fix scope (Phase 5):**
- Read `useAiCredentials` and `useAiCredentialSettings` on dashboard root
- Show banner when `credentials.length === 0 && !settings.kill_switch_active`
- Dismissible? Spec doesn't say — recommend persistent until configured (the whole point is to drive setup)

### G4 — Gap: idle-state pre-flight estimate display

**What spec says (§3.2):** The CTA card always shows `300 LLM calls · ~$5.10 · ~90 seconds · provider X` before the Generate button.

**What exists:** Estimate is fetched via `useRunBatchEstimate` and only surfaces inside `FreeTierWarningDialog` after the user clicks Generate AND `warning_recommended === true`.

**Fix scope (Phase 3):**
- Surface the estimate inline in the idle banner state (the "Generate AI remediation for every finding" state in `RunBatchProgress`)
- Layout: callout card with bullet metrics + Generate button bottom-right
- Free-tier path: estimate copy switches to "free · ~20 minutes (rate-limited) · Switch to paid?"

### G5 — Orphan: `components/ai-fixes/Settings/AiSettings.tsx`

The old read-only `AiSettings` component is referenced only by [its own test](frontend/src/components/ai-fixes/__tests__/AiSettings.test.tsx) and its own [index.ts](frontend/src/components/ai-fixes/Settings/index.ts). The settings page comment confirms it has been "superseded".

**Action:** Phase 2 cleanup — delete `AiSettings.tsx`, `AiSettings.test.tsx`, and audit its sibling exports (`BudgetCapsForm`, `ProviderSelect` here) for orphans. **Keep** `CostDashboard` and `UsageMetrics` (still used by `/admin/ai-usage`).

### G6 — Backend server staleness (operational, not a code gap)

The running uvicorn process predates several uncommitted backend file edits. Live probes 404'd on credentials/settings/`providers/available`/`estimate`. **Resolution:** restart `python3 run.py` before Phase 2 verification.

---

## Section E — Phase 2 readiness statement

**Ready to proceed with revised scope.** Backend contracts are essentially aligned with the spec — only path divergences are `POST /runs/{id}/ai-fixes` (no `/generate` suffix) and `:regenerate` colon syntax, both of which the existing frontend client already follows. Frontend is far more built out than the prompt assumed: settings page, providers list, add/edit dialog, run banner, CVE modal AI section, hooks, types, sidebar entries, and admin cost dashboard are all in place uncommitted.

The five-phase plan should be re-scoped to:

- **Phase 2 (settings):** delete orphans (G5), reconcile any small UX gaps in the existing settings page after the live walkthrough, finish a kill-switch confirmation dialog if missing, then commit.
- **Phase 3 (run + bulk):** real new work — global SSE provider (G1), findings-table indicator column (G2), idle-state pre-flight estimate display (G4).
- **Phase 4 (CVE modal):** decide D1 (section vs tab) — recommend keep sections, update prompt success criteria. Otherwise the surface is already done; verify all four states render.
- **Phase 5 (verification + dashboard):** dashboard banner (G3), end-to-end scripted scenarios, commit + flag flip.

**Open questions for owner before Phase 2 starts:**
1. **D1** — accept the existing inline section pattern in the CVE modal, or refactor to tabs?
2. **G5** — confirm OK to delete `components/ai-fixes/Settings/AiSettings.tsx` (orphan)?
3. **Server restart** — please restart `run.py` so the credential / settings / estimate endpoints are live before the Phase 2 walkthrough.
4. **Commit cadence** — the existing uncommitted work is large. Bundle into one feature commit before Phase 2 changes start, or land Phase 2 cleanup as part of the same commit?

Once those are answered, Phase 2 is ~1 short session of work, not the originally-scoped multi-session build.
