# Cache invalidation audit — TanStack Query mutation invariant

**Date:** 2026-05-11
**Phase:** 1 of 4 (audit, read-only)
**Scope:** every `useMutation` and every state-changing async path in `frontend/src/`
**Successor:** [frontend/src/lib/queryInvalidation.ts](../frontend/src/lib/queryInvalidation.ts) — invalidation helpers; [CLAUDE.md](../CLAUDE.md) — current convention

## Why this audit exists

The same one-line bug keeps shipping: a mutation succeeds, but a sibling list view stays stale until the user hits F5. The May 2026 audit captured by [CLAUDE.md](../CLAUDE.md) closed five instances (upload, SBOM delete, project delete, schedule run-now ×2, SBOM revalidate). The owner now reports the pattern recurring on AI provider surfaces and dashboard tiles — evidence that an enforcement gap, not isolated oversight, is the root cause.

This audit lists every mutation, every list-style query it could affect, and the concrete gaps. Phase 2 will close the gaps; phase 3 will install a forbidding test so the next round of mutations cannot ship without invalidation.

---

## Section A — Mutation inventory

`useMutation` appears in 8 files. Two additional state-changing paths bypass `useMutation` entirely and are listed for parity, since a `useMutation`-only forbidding test would miss them.

| # | File | Hook / handler | Entity | Method | Has `onSuccess`? | Invalidates |
|---|------|----------------|--------|--------|------------------|-------------|
| 1 | [hooks/useAiCredentials.ts:66](../frontend/src/hooks/useAiCredentials.ts#L66) | `useCreateAiCredential` | ai-credential | POST | yes | `['ai','credentials']` |
| 2 | [hooks/useAiCredentials.ts:77](../frontend/src/hooks/useAiCredentials.ts#L77) | `useUpdateAiCredential` | ai-credential | PUT | yes | `['ai','credentials']` |
| 3 | [hooks/useAiCredentials.ts:92](../frontend/src/hooks/useAiCredentials.ts#L92) | `useDeleteAiCredential` | ai-credential | DELETE | yes | `['ai','credentials']` |
| 4 | [hooks/useAiCredentials.ts:103](../frontend/src/hooks/useAiCredentials.ts#L103) | `useSetDefaultCredential` | ai-credential | PUT | yes | `['ai','credentials']` |
| 5 | [hooks/useAiCredentials.ts:114](../frontend/src/hooks/useAiCredentials.ts#L114) | `useSetFallbackCredential` | ai-credential | PUT | yes | `['ai','credentials']` |
| 6 | [hooks/useAiCredentials.ts:139](../frontend/src/hooks/useAiCredentials.ts#L139) | `useTestConnection.unsaved` | ai-credential | POST | yes | `['ai','credentials']` |
| 7 | [hooks/useAiCredentials.ts:150](../frontend/src/hooks/useAiCredentials.ts#L150) | `useTestConnection.saved` | ai-credential | POST | yes | `['ai','credentials']` |
| 8 | [hooks/useAiCredentials.ts:174](../frontend/src/hooks/useAiCredentials.ts#L174) | `useUpdateAiCredentialSettings` | ai-cred-settings | PUT | yes | (uses `setQueryData` only) |
| 9 | [hooks/useAiFix.ts:86](../frontend/src/hooks/useAiFix.ts#L86) | `useAiFix.generate` | ai-fix | POST | yes | (uses `setQueryData` only) |
| 10 | [hooks/useAiFix.ts:94](../frontend/src/hooks/useAiFix.ts#L94) | `useAiFix.regenerate` | ai-fix | POST | yes | (uses `setQueryData` only) |
| 11 | [hooks/useAiFix.ts:196](../frontend/src/hooks/useAiFix.ts#L196) | `useTriggerAiFixes` | ai-batch | POST | yes | `['ai-fix-list', runId]` + `setQueryData` for progress |
| 12 | [hooks/useAiFix.ts:211](../frontend/src/hooks/useAiFix.ts#L211) | `useCancelAiFixes` | ai-batch | POST | yes | `['ai-batch-progress', runId]` |
| 13 | [hooks/useAiFix.ts:281](../frontend/src/hooks/useAiFix.ts#L281) | `useTriggerScopedAiFixes` | ai-batch | POST | yes | `['ai-fix-list', runId]`, `['ai-batch-list', runId]` |
| 14 | [hooks/useAiFix.ts:316](../frontend/src/hooks/useAiFix.ts#L316) | `useCancelAiBatch` | ai-batch | POST | yes | `['ai-batch-progress', runId, batchId]`, `['ai-batch-list', runId]` |
| 15 | [components/projects/ProjectModal.tsx:67](../frontend/src/components/projects/ProjectModal.tsx#L67) | (inline mutation, create + update) | project | POST/PUT | yes | `['projects']` |
| 16 | [components/projects/ProjectsTable.tsx:55](../frontend/src/components/projects/ProjectsTable.tsx#L55) | (inline mutation, delete) | project | DELETE | yes | `invalidateProjectLists`, `invalidateSbomLists`, `invalidateRunLists`, `invalidateScheduleLists` |
| 17 | [components/sboms/SbomsTable.tsx:107](../frontend/src/components/sboms/SbomsTable.tsx#L107) | (inline mutation, delete) | sbom | DELETE | yes | `invalidateSbomLists`, `invalidateProjectLists`, `invalidateRunLists` |
| 18 | [components/schedules/ScheduleEditor.tsx:109](../frontend/src/components/schedules/ScheduleEditor.tsx#L109) | (inline mutation, upsert) | schedule | PUT | yes | `['schedule']`, `['schedules']` |
| 19 | [components/schedules/ScheduleCard.tsx:99](../frontend/src/components/schedules/ScheduleCard.tsx#L99) | (inline, pause) | schedule | POST | yes | `['schedule']` |
| 20 | [components/schedules/ScheduleCard.tsx:108](../frontend/src/components/schedules/ScheduleCard.tsx#L108) | (inline, resume) | schedule | POST | yes | `['schedule']` |
| 21 | [components/schedules/ScheduleCard.tsx:117](../frontend/src/components/schedules/ScheduleCard.tsx#L117) | (inline, run-now) | schedule | POST | yes | `invalidateRunLists`, `invalidateSbomLists` |
| 22 | [components/schedules/ScheduleCard.tsx:130](../frontend/src/components/schedules/ScheduleCard.tsx#L130) | (inline, delete) | schedule | DELETE | yes | `['schedule']` |
| 23 | [app/schedules/page.tsx:151](../frontend/src/app/schedules/page.tsx#L151) | (inline, pause) | schedule | POST | yes | `['schedules']`, `['schedule']` |
| 24 | [app/schedules/page.tsx:159](../frontend/src/app/schedules/page.tsx#L159) | (inline, resume) | schedule | POST | yes | `['schedules']`, `['schedule']` |
| 25 | [app/schedules/page.tsx:167](../frontend/src/app/schedules/page.tsx#L167) | (inline, run-now) | schedule | POST | yes | `invalidateRunLists`, `invalidateSbomLists` |
| 26 | [app/schedules/page.tsx:181](../frontend/src/app/schedules/page.tsx#L181) | (inline, delete) | schedule | DELETE | yes | `['schedules']`, `['schedule']` |

### Mutation-like paths that bypass `useMutation`

| # | File | Handler | Entity | Method | Invalidates |
|---|------|---------|--------|--------|-------------|
| B1 | [components/sboms/SbomUploadModal.tsx:138](../frontend/src/components/sboms/SbomUploadModal.tsx#L138) | `onSubmit` → `createSbom` | sbom | POST | none (relies on parent's `onSuccess` to invalidate) |
| B2 | [components/sboms/ValidationReportSection.tsx:175](../frontend/src/components/sboms/ValidationReportSection.tsx#L175) | `handleRevalidate` → `revalidateSbom` | sbom | POST | `['sbom-validation-report', id]`, `['sbom', id]`, `['sbom-info', id]`, `invalidateSbomLists` |
| B3 | [hooks/useBackgroundAnalysis.ts:37](../frontend/src/hooks/useBackgroundAnalysis.ts#L37) | `triggerBackgroundAnalysis` → `analyzeConsolidated` | run | POST | `['runs']` + `setQueryData(['sboms'])` |
| B4 | [components/sboms/SbomDetail.tsx:135](../frontend/src/components/sboms/SbomDetail.tsx#L135) | `handleRunAnalysis` → `useAnalysisStream` | run (SSE) | POST/SSE | `['runs']` (only on `handleReset`, not on every completion) |

---

## Section B — Query reverse-lookup

Every list-style query that could be affected by mutations above. Detail/per-id queries are noted where they matter for invalidation correctness.

### SBOM surfaces

| QueryKey | File | Component / surface |
|----------|------|---------------------|
| `['sboms']` | [hooks/useSbomsList.ts:11](../frontend/src/hooks/useSbomsList.ts#L11) | Main SBOMs table; Analysis page; upload duplicate-name check |
| `['sboms', 'for-schedules']` | [app/schedules/page.tsx:105](../frontend/src/app/schedules/page.tsx#L105) | Schedules page name lookup |
| `['sbom', id]` | [app/sboms/[id]/page.tsx:20](../frontend/src/app/sboms/[id]/page.tsx#L20) | SBOM detail page (per-id) |
| `['sbom-info', id]` | [components/sboms/SbomDetail.tsx:50](../frontend/src/components/sboms/SbomDetail.tsx#L50), [components/analysis/SbomPreflightChecklist.tsx:80](../frontend/src/components/analysis/SbomPreflightChecklist.tsx#L80) | SBOM info card; pre-flight |
| `['sbom-components', id]` | [components/sboms/SbomDetail.tsx:37](../frontend/src/components/sboms/SbomDetail.tsx#L37) | Components list |
| `['sbom-validation-report', id]` | [components/sboms/SbomDetail.tsx:60](../frontend/src/components/sboms/SbomDetail.tsx#L60) | Validation report card |
| `['sbom-risk', id, runId]` | [components/sboms/SbomDetail.tsx:68](../frontend/src/components/sboms/SbomDetail.tsx#L68) | Risk summary card |
| `['sbom-delete-impact', id]` | [components/sboms/SbomsTable.tsx:101](../frontend/src/components/sboms/SbomsTable.tsx#L101) | Pre-delete cascade impact |
| `['sidebar-recent-sboms']` | [components/layout/Sidebar.tsx:362](../frontend/src/components/layout/Sidebar.tsx#L362) | Left sidebar recents |
| `['recent-sboms']` | [components/dashboard/ActivityFeed.tsx:77](../frontend/src/components/dashboard/ActivityFeed.tsx#L77) | Dashboard activity feed |
| `['palette-recent-sboms']` | [components/layout/CommandPalette.tsx:102](../frontend/src/components/layout/CommandPalette.tsx#L102) | ⌘K palette |

### Project surfaces

| QueryKey | File | Component / surface |
|----------|------|---------------------|
| `['projects']` | [app/projects/page.tsx:16](../frontend/src/app/projects/page.tsx#L16), [app/analysis/page.tsx:87](../frontend/src/app/analysis/page.tsx#L87), [app/schedules/page.tsx:100](../frontend/src/app/schedules/page.tsx#L100), [components/sboms/SbomUploadModal.tsx:80](../frontend/src/components/sboms/SbomUploadModal.tsx#L80) | Projects table; analysis filter; schedule label lookup; upload modal dropdown |
| `['project-delete-impact', id]` | [components/projects/ProjectsTable.tsx:49](../frontend/src/components/projects/ProjectsTable.tsx#L49) | Pre-delete cascade impact |

### Run / analysis surfaces

| QueryKey | File | Component / surface |
|----------|------|---------------------|
| `['runs']` | (used widely; invalidated as prefix) | All runs lists |
| `['runs', { … }]` | [app/analysis/page.tsx:94](../frontend/src/app/analysis/page.tsx#L94) | Filtered runs |
| `['runs', { sbom_id }]` | [components/sboms/SbomDetail.tsx:42](../frontend/src/components/sboms/SbomDetail.tsx#L42) | SBOM detail run table |
| `['runs-aggregate', { … }]` | [app/analysis/page.tsx:114](../frontend/src/app/analysis/page.tsx#L114) | Server-side run rollup |
| `['run', id]` | [app/analysis/[id]/page.tsx:68](../frontend/src/app/analysis/[id]/page.tsx#L68) | Run detail |
| `['findings-enriched', id, severity]` | [app/analysis/[id]/page.tsx:74](../frontend/src/app/analysis/[id]/page.tsx#L74) | Enriched findings |
| `['recent-runs']` | [components/dashboard/ActivityFeed.tsx:82](../frontend/src/components/dashboard/ActivityFeed.tsx#L82) | Dashboard activity feed |
| `['sidebar-recent-runs']` | [components/layout/Sidebar.tsx:368](../frontend/src/components/layout/Sidebar.tsx#L368) | Sidebar recents |
| `['palette-recent-runs']` | [components/layout/CommandPalette.tsx:109](../frontend/src/components/layout/CommandPalette.tsx#L109) | ⌘K palette |
| `['top-vulnerable-runs']` | [components/dashboard/TopVulnerableSboms.tsx:61](../frontend/src/components/dashboard/TopVulnerableSboms.tsx#L61) | Dashboard tile |
| `['compare', 'picker', 'recent']` | [components/compare/SelectionBar/RunPicker.tsx:80](../frontend/src/components/compare/SelectionBar/RunPicker.tsx#L80) | Compare flow picker |
| `['compare', 'picker', 'search', q]` | [components/compare/SelectionBar/RunPicker.tsx:86](../frontend/src/components/compare/SelectionBar/RunPicker.tsx#L86) | Compare flow search |
| `['compare', 'sparkline', sbomId]` | [components/compare/Sparkline/Sparkline.tsx:49](../frontend/src/components/compare/Sparkline/Sparkline.tsx#L49) | Compare sparklines |

### Dashboard rollup surfaces

| QueryKey | File | Component / surface |
|----------|------|---------------------|
| `['dashboard-posture']` | [app/page.tsx:38](../frontend/src/app/page.tsx#L38) | Posture card |
| `['dashboard-trend', 30]` | [app/page.tsx:43](../frontend/src/app/page.tsx#L43) | 30-day trend |
| `['dashboard-lifetime']` | [app/page.tsx:48](../frontend/src/app/page.tsx#L48) | Lifetime totals |

### Schedule surfaces

| QueryKey | File | Component / surface |
|----------|------|---------------------|
| `['schedules', { … }]` | [app/schedules/page.tsx:86](../frontend/src/app/schedules/page.tsx#L86) | All schedules table |
| `['schedule', scope, targetId]` | [components/schedules/ScheduleCard.tsx:83](../frontend/src/components/schedules/ScheduleCard.tsx#L83) | Project / SBOM schedule card |

### AI surfaces

| QueryKey | File | Component / surface |
|----------|------|---------------------|
| `['ai', 'credentials']` (`aiCredentialsQueryKey`) | [hooks/useAiCredentials.ts:48](../frontend/src/hooks/useAiCredentials.ts#L48) | Settings → providers list; `AiConfigBanner`; `ProviderStatusIndicator` |
| `['ai', 'credential-settings']` | [hooks/useAiCredentials.ts:49](../frontend/src/hooks/useAiCredentials.ts#L49) | Kill switch / budget caps; `AiConfigBanner` |
| `['ai', 'provider-catalog']` | [hooks/useAiCredentials.ts:50](../frontend/src/hooks/useAiCredentials.ts#L50) | Add-dialog catalog (static, 1-hour staleTime) |
| `['ai-settings', 'providers']` | [hooks/useAiFix.ts:343](../frontend/src/hooks/useAiFix.ts#L343) | Settings page provider info join |
| `['ai-settings', 'pricing']` | [hooks/useAiFix.ts:349](../frontend/src/hooks/useAiFix.ts#L349) | Cost rendering |
| `['ai-settings', 'usage']` | [hooks/useAiFix.ts:355](../frontend/src/hooks/useAiFix.ts#L355) | Usage summary (auto-refetch 30s) |
| `['ai-fix', findingId, providerName]` | [hooks/useAiFix.ts:61](../frontend/src/hooks/useAiFix.ts#L61) (`aiFixQueryKey`) | Per-finding fix cache |
| `['ai-fix-list', runId]` | [hooks/useAiFix.ts:228](../frontend/src/hooks/useAiFix.ts#L228) | Run-detail fix table |
| `['ai-batch-progress', runId]` | [hooks/useAiFix.ts:140](../frontend/src/hooks/useAiFix.ts#L140) | Legacy batch progress |
| `['ai-batch-progress', runId, batchId]` | (multi-batch) | Per-batch progress |
| `['ai-batch-list', runId]` | [hooks/useAiFix.ts:307](../frontend/src/hooks/useAiFix.ts#L307) | Multi-batch history |
| `['ai', 'run-batch-estimate', runId, …]` | [hooks/useAiCredentials.ts:210](../frontend/src/hooks/useAiCredentials.ts#L210), [hooks/useAiFix.ts:267](../frontend/src/hooks/useAiFix.ts#L267) | Pre-flight estimate |
| `['ai-usage-trend', 30]` | [components/ai-fixes/Settings/CostDashboard.tsx:34](../frontend/src/components/ai-fixes/Settings/CostDashboard.tsx#L34) | Cost trend chart |
| `['ai-top-cached', 20]` | [components/ai-fixes/Settings/CostDashboard.tsx:40](../frontend/src/components/ai-fixes/Settings/CostDashboard.tsx#L40) | Top cached fixes |

### Misc surfaces (not list-shaped, listed for completeness)

| QueryKey | Component |
|----------|-----------|
| `['analysis-config']` (4 callers — [app/admin/ai-usage/page.tsx:18](../frontend/src/app/admin/ai-usage/page.tsx#L18), [app/analysis/[id]/page.tsx:87](../frontend/src/app/analysis/[id]/page.tsx#L87), [app/analysis/page.tsx:81](../frontend/src/app/analysis/page.tsx#L81), [app/settings/ai/page.tsx:12](../frontend/src/app/settings/ai/page.tsx#L12), [components/dashboard/AiConfigBanner.tsx:22](../frontend/src/components/dashboard/AiConfigBanner.tsx#L22)) | Server feature flags — read-mostly, `staleTime: 60s` |
| `['cve-detail', scanId, cveId]` | CVE hover card |
| `['compare-runs' / 'compare', 'v2', …]` | Compare results |
| `['sbom-types']` | Upload modal type dropdown |
| `['health-poll']` | Sidebar status dot |

---

## Section C — Cross-reference (what each mutation *should* invalidate)

Read as: **for mutation X, every list query Y that could now display new/changed/missing data**.

### sbom: upload (B1)
- `['sboms']`, `['sboms', 'for-schedules']`
- `['sidebar-recent-sboms']`, `['recent-sboms']`, `['palette-recent-sboms']`
- `['projects']` (project's SBOM count surfaces in lookups; future-proofing)
- `['dashboard-posture']`, `['dashboard-trend', 30]`, `['dashboard-lifetime']` (new SBOM moves totals)

### sbom: delete (#17)
- All of upload (above), plus
- `['runs']`, `['recent-runs']`, `['sidebar-recent-runs']`, `['palette-recent-runs']` (the SBOM's runs disappear)
- `['top-vulnerable-runs']` (deleted SBOM may have led the list)
- `['runs-aggregate', …]`, `['compare', 'picker', 'recent']`
- `['sbom', id]`, `['sbom-info', id]`, `['sbom-validation-report', id]`, `['sbom-risk', id, …]`, `['sbom-components', id]` (per-id detail caches)
- `['schedule', 'SBOM', id]`, `['schedules']` (any override goes away)

### sbom: revalidate (B2)
- `['sbom-validation-report', id]`, `['sbom', id]`, `['sbom-info', id]`
- `invalidateSbomLists` (validation status surfaces in the main table's Upload column)
- Optionally: `['sboms', 'for-schedules']` (already prefix-matched by `['sboms']`, ✓)

### sbom: analyze / analysis completes (B3, B4)
- `['runs']` (prefix-match catches `['runs', { … }]` and `['runs', { sbom_id }]`)
- `['runs-aggregate', …]`
- `['recent-runs']`, `['sidebar-recent-runs']`, `['palette-recent-runs']`
- `['top-vulnerable-runs']`
- `['compare', 'picker', 'recent']`, `['compare', 'sparkline', sbomId]`
- `['sbom-risk', sbomId, …]`, `['sbom-info', sbomId]`
- `['dashboard-posture']`, `['dashboard-trend', 30]`, `['dashboard-lifetime']`

### project: create / update (#15)
- `['projects']`
- `['sboms']` (SBOM rows display `project_name` — joined view goes stale on rename)
- `['sboms', 'for-schedules']` (same)
- `['sidebar-recent-sboms']`, `['recent-sboms']`, `['palette-recent-sboms']` (same — display project name)

### project: delete (#16)
- All of project: create/update
- `['runs']`, `['runs-aggregate', …]`, `['recent-runs']`, `['sidebar-recent-runs']`, `['palette-recent-runs']`, `['top-vulnerable-runs']` (cascade)
- `['schedules']`, `['schedule']` (cascade)
- `['dashboard-posture']`, `['dashboard-trend', 30]`, `['dashboard-lifetime']`
- Already invalidates `invalidateSbomLists`, `invalidateRunLists`, `invalidateScheduleLists`, `invalidateProjectLists` ✓

### schedule: upsert (#18) / pause (#19, #23) / resume (#20, #24) / delete (#22, #26)
- `['schedules']`, `['schedule']`
- The schedule itself doesn't immediately change any run/finding, so no run/sbom/dashboard invalidation needed
- After delete: `['schedule', scope, id]` (prefix-match by `['schedule']` ✓)

### schedule: run-now (#21, #25)
- Already invalidates `invalidateRunLists`, `invalidateSbomLists` ✓
- Missing: `['recent-runs']`, `['sidebar-recent-runs']`, `['palette-recent-runs']`, `['top-vulnerable-runs']`, `['runs-aggregate', …]`, `['dashboard-*']`

### ai-credential: create / update / delete / set-default / set-fallback (#1–#5)
- `['ai', 'credentials']` ✓
- Missing: `['ai-settings', 'providers']` — the Settings page reads providers from this separate joined endpoint; the providers list (e.g. cost breakdown, available-model dropdown) drifts until staleTime expires (60s)
- Missing on first create / last delete: `['analysis-config']` — `ai_fixes_enabled` doesn't change but `AiConfigBanner` switches between "no provider" CTA and silent based on credentials, which is the same query, so prefix-match by `['ai','credentials']` ✓
- For delete: should also drop cached per-provider fixes — `['ai-fix']` (prefix), `['ai-fix-list']`, `['ai-batch-progress']` (i.e. `invalidateAllAiFixes`); a fix cached against a now-deleted provider will display a stale provider name

### ai-credential: test (#6 unsaved, #7 saved)
- Saved test: `['ai', 'credentials']` ✓ (updates `last_test_at` on the row → badge refreshes)
- Unsaved test: invalidating `['ai', 'credentials']` is harmless but unnecessary — the test doesn't touch the saved-credential row. Candidate for `// @no-invalidation-needed`.

### ai-credential-settings: update (#8)
- Uses `setQueryData` only; consumers (AiConfigBanner, BudgetCapsForm) read the same key, so the manual cache write is sufficient ✓
- Candidate to leave as-is and mark with a comment so the forbidding test knows this is intentional

### ai-fix: generate / regenerate (#9, #10)
- `setQueryData(['ai-fix', findingId, providerName], data)` ✓
- Missing: `['ai-fix-list', runId]` — the run-level fix table shows whether each finding has a cached fix. A single-finding generate/regenerate makes the run-level row stale (column flips from "Generate" to "View"). This is the kind of bug the owner is describing.

### ai-batch: trigger (#11) / trigger-scoped (#13)
- Trigger: invalidates `['ai-fix-list', runId]` ✓
- Trigger: missing `['ai-batch-list', runId]` — multi-batch UI tracks every batch; a new trigger creates a new batch and the historical-batch table goes stale until refresh
- Trigger-scoped: invalidates both ✓
- Trigger: missing `['ai', 'run-batch-estimate', runId, …]` — the pre-flight estimate becomes irrelevant after trigger; not a stale-display bug (the user has already committed) so this is optional

### ai-batch: cancel-run (#12) / cancel-batch (#14)
- Cancel-run: invalidates `['ai-batch-progress', runId]` only
- Missing: `['ai-fix-list', runId]` (partial generations got cached; user should see them), `['ai-batch-list', runId]` (status flips to cancelled)
- Cancel-batch: invalidates `['ai-batch-progress', runId, batchId]`, `['ai-batch-list', runId]`
- Missing: `['ai-fix-list', runId]` (same reason)
- Missing: legacy `['ai-batch-progress', runId]` (no batchId) — banner consumers that haven't migrated will not refresh

---

## Section D — Broken / incomplete mutations (Phase 2 work list)

Listed in priority order. Each entry: **what to add, where, why**.

### D1 — AI-credential mutations skip the Settings → providers join (#1, #2, #3, #4, #5)
**Affected:** `useCreateAiCredential`, `useUpdateAiCredential`, `useDeleteAiCredential`, `useSetDefaultCredential`, `useSetFallbackCredential`
**Add:** `qc.invalidateQueries({ queryKey: ['ai-settings'] })` (catches `['ai-settings','providers']`, `['ai-settings','pricing']`, `['ai-settings','usage']`)
**Why:** matches the user-reported "AI provider switch — modal still shows old provider name". The card list refreshes (uses `['ai','credentials']`), but the parallel `['ai-settings','providers']` query that the Settings page composes does not. 30-second window of stale data.

### D2 — AI-credential delete leaves orphaned cached fixes (#3)
**Affected:** `useDeleteAiCredential`
**Add:** `invalidateAllAiFixes(qc)` (already exported from `useAiFix.ts:376`)
**Why:** deleting a provider while a `['ai-fix', findingId, providerName]` entry is cached leaves the modal showing a fix attributed to a no-longer-existing provider.

### D3 — Per-finding ai-fix generate/regenerate doesn't invalidate the run-level list (#9, #10)
**Affected:** `useAiFix.generate`, `useAiFix.regenerate`
**Add:** `qc.invalidateQueries({ queryKey: ['ai-fix-list', runId] })` — requires the hook to know the runId
**Why:** the run-detail page's "AI fix" column says "Generate" when no fix is cached and "View" when one is. Generating from inside the modal leaves the column at "Generate" until refresh. **Structural note:** `useAiFix` currently doesn't know the runId. Two options:
  - (a) thread `runId` through `useAiFix(findingId, { runId, providerName })`
  - (b) invalidate the entire `['ai-fix-list']` prefix (broad but simple)
Recommended: (b) for Phase 2. (a) is cleaner but is a hook-signature change.

### D4 — `useCancelAiFixes` / `useTriggerAiFixes` miss `['ai-batch-list']` (#11, #12)
**Affected:** `useTriggerAiFixes`, `useCancelAiFixes`
**Add:** `qc.invalidateQueries({ queryKey: ['ai-batch-list', runId] })` and on cancel also `['ai-fix-list', runId]`
**Why:** the multi-batch table (Phase 4) on the run-detail page goes stale when a legacy single-batch trigger/cancel fires. `useTriggerScopedAiFixes` already does this correctly — the legacy hooks were left behind.

### D5 — `useCancelAiBatch` doesn't invalidate partial fixes or legacy progress (#14)
**Affected:** `useCancelAiBatch`
**Add:** `qc.invalidateQueries({ queryKey: ['ai-fix-list', runId] })`, `qc.invalidateQueries({ queryKey: ['ai-batch-progress', runId] })` (legacy key for any banner that hasn't migrated)
**Why:** partial generations land in `['ai-fix-list']`; banner consumers using the legacy `['ai-batch-progress', runId]` (no batchId) read a stale "in progress" status.

### D6 — Schedule run-now misses dashboard / recent surfaces (#21, #25)
**Affected:** `runNowM` in `app/schedules/page.tsx`, `runNowMutation` in `components/schedules/ScheduleCard.tsx`
**Add:** dashboard + recent-runs invalidation. Currently invalidates `invalidateRunLists` (good — catches `['runs']` prefix) and `invalidateSbomLists` (good).
**Missing:** `['recent-runs']`, `['sidebar-recent-runs']`, `['palette-recent-runs']`, `['top-vulnerable-runs']`, `['runs-aggregate']`, `['dashboard-posture']`, `['dashboard-trend']`, `['dashboard-lifetime']`
**Why:** enqueueing N runs immediately changes "Recently analysed" feeds and changes the in-flight count on dashboard tiles. The owner's "dashboard tiles after data changes" report most likely lands here and in D7.

### D7 — Background analysis completion only refreshes `['runs']` (B3, B4)
**Affected:** `useBackgroundAnalysis.triggerBackgroundAnalysis` (the post-upload analysis), `useAnalysisStream` completion (`handleReset` in `SbomDetail.tsx:140`)
**Add:** dashboard + recent + risk-summary invalidation
**Missing:** `['recent-runs']`, `['sidebar-recent-runs']`, `['palette-recent-runs']`, `['top-vulnerable-runs']`, `['runs-aggregate']`, `['compare', 'picker', 'recent']`, `['compare', 'sparkline', sbomId]`, `['sbom-risk', sbomId]`, `['sbom-info', sbomId]`, `['dashboard-posture']`, `['dashboard-trend']`, `['dashboard-lifetime']`
**Why:** running analysis is the *primary* event that should refresh dashboard posture, top-vulnerable list, and trend charts. Currently those wait for their own staleTime (varies). This is the strongest candidate for the "Dashboard tiles after data changes" symptom.
**Structural note:** both call sites need the same set, so propose a new helper `invalidateAnalysisCompletionSurfaces(qc, { sbomId? })` in `lib/queryInvalidation.ts`.

### D8 — Project create/update doesn't invalidate SBOM/recent caches that show project name (#15)
**Affected:** `ProjectModal.mutation`
**Add:** `invalidateSbomLists(qc)` (already on delete path; missing on create/update)
**Why:** SBOM rows display `project_name`. Renaming a project leaves the SBOMs table showing the old name until staleTime expires. Low-incidence (renames are rare) but cheap to fix.

### D9 — Schedule upsert is missing schedule sub-queries used by detail cards (#18)
**Affected:** `ScheduleEditor.mutation`
**Status:** invalidates `['schedule']` (prefix) and `['schedules']` ✓
**No fix needed.** Listed here for confirmation only.

### D10 — SbomUploadModal bypasses `useMutation` (B1) — structural
**Affected:** `SbomUploadModal.onSubmit`
**Status:** the single caller invalidates correctly. Risk is that any *future* caller of the modal must remember to wire invalidation.
**Recommended fix:** convert `createSbom` call into a `useUploadSbom()` hook owning its own `onSuccess` invalidation. Move `invalidateSbomLists` / `invalidateProjectLists` into the hook. Optional for Phase 2; required if forbidding test should catch this surface — see Phase 3.

### D11 — ValidationReportSection.handleRevalidate bypasses `useMutation` (B2) — structural
**Affected:** `ValidationReportSection.handleRevalidate`
**Status:** invalidates correctly today.
**Recommended fix:** convert to `useRevalidateSbom()` hook so the forbidding test can verify it. Optional for Phase 2.

### D12 — useTestConnection.unsaved invalidates credentials list unnecessarily (#6)
**Affected:** `useTestConnection.unsaved`
**Status:** unnecessary invalidation; not stale-display bug
**Recommended fix:** drop the invalidation and mark with `// @no-invalidation-needed — test does not touch saved credentials`. Soft; safe to leave alone.

### D13 — useUpdateAiCredentialSettings uses setQueryData only (#8)
**Affected:** `useUpdateAiCredentialSettings`
**Status:** correct as-is; setQueryData primes the same key consumers read.
**Recommended fix:** add `// @no-invalidation-needed — primes cache via setQueryData on same key` so the Phase 3 forbidding test passes without flagging this.

---

## Section E — Phase 2 test plan

After implementing the Phase 2 changes, walk these scenarios on a running dev instance. For each: *the only criterion is that the affected surface updates **without** F5 / `Cmd-R`*.

1. **Upload SBOM** — sidebar Recent SBOMs, dashboard activity feed, ⌘K palette all show the new SBOM ≤ 1 second after the upload modal closes. (D10 if structural conversion done; currently covered by `app/sboms/page.tsx`.)
2. **Delete SBOM** — same surfaces, plus Top Vulnerable tile and dashboard posture / trend, all drop the SBOM. (Covered now; verify Phase 2 didn't regress.)
3. **Create project** — projects table and upload-modal project dropdown both show new project. (Covered.)
4. **Rename project** — SBOMs table reflects the new project name on the joined column. (D8.)
5. **Delete project** — cascade: SBOMs, runs, schedules, dashboard, all panels reflect deletions. (Covered.)
6. **Add AI provider** — Settings list, AiConfigBanner, and any provider-info join refresh immediately. (D1.)
7. **Switch default AI provider** — providers list shows new default star; Settings refresh without lag. (D1.)
8. **Delete AI provider that has cached fixes** — open a CVE detail modal that previously showed a fix from that provider; "Generate" CTA should reappear. (D2.)
9. **Test AI provider connection** — `ProviderStatusIndicator` flips from "Not tested" → "OK" / "Failing" within ~1s. (Covered.)
10. **Generate AI fix from CVE modal** — close modal; open run-detail page; that finding's "AI fix" column shows "View". (D3.)
11. **Trigger AI batch (legacy single-batch)** — multi-batch history table picks up the new batch row. (D4.)
12. **Cancel running AI batch** — partial fixes show in the run-detail list; batch status flips to "cancelled". (D5.)
13. **Schedule run-now (from project page card AND schedules table)** — Recent Runs / sidebar / palette / Top Vulnerable refresh with the newly enqueued runs. (D6.)
14. **Run analysis from SBOM detail page** — when the SSE stream reports `done`, dashboard posture/trend/lifetime tiles, Top Vulnerable, recents (sidebar / dashboard / palette), and the SBOM's own risk card all reflect the new findings. (D7.)
15. **Upload + auto-analysis** — after `useBackgroundAnalysis` completes, dashboard and recents reflect new run. (D7.)

For each scenario, capture a screen recording (or a 2-shot before/after of the affected surface) for Phase 4.

---

## Section F — Open questions for the owner

These are decisions I'd flag before Phase 2 starts:

1. **D3 (per-finding AI fix invalidation)** — should `useAiFix` learn the `runId` (cleaner) or should we invalidate the entire `['ai-fix-list']` prefix on every per-finding generate (simpler)? Recommend the simpler option for Phase 2; revisit if it causes visible re-fetch churn.
2. **D10 / D11 (structural conversions)** — convert `SbomUploadModal` and `ValidationReportSection.handleRevalidate` to `useMutation`-based hooks now (cleaner Phase 3 test net), or defer with a comment + manual test coverage? Recommend converting in Phase 2; both are < 30 LOC each.
3. **Forbidding test escape hatch** — accept the proposed `// @no-invalidation-needed` marker comment? Or prefer a stricter approach (e.g. require a typed "no-op invalidation" call like `qc.noOpInvalidation()` so the marker is grep-able and TS-checked)? Recommend the comment marker — simplest and matches CLAUDE.md style.
4. **`useUpdateAiCredentialSettings` (D13)** — keep `setQueryData`-only with marker, or convert to `invalidateQueries` for consistency? `setQueryData` is correct and faster; recommend keeping with marker.
5. **`['analysis-config']` invalidation on first-credential / last-credential** — currently a 60s staleTime hides this. Worth invalidating on credential CRUD? Probably yes for the "added a provider but banner still shows empty CTA" race. Add to D1's scope?

---

## Phase 1 gate

The Phase 2 work list above is **D1–D13** (D9 is verification-only). D1, D2, D3, D4, D5, D6, D7 are concrete missing-invalidation bugs that match the symptom pattern. D8 is a corner-case rename bug. D10–D13 are structural improvements that enable the Phase 3 forbidding test.

**Pause here — please confirm:**
- Scope: which of D1–D13 should ship in Phase 2 (recommended: all of D1–D8; D10–D13 if you want the Phase 3 test to be maximally effective)?
- Decisions on the open questions in Section F (especially #1 and #2)?
- Anything I missed — particularly any mutation surface or stale-data symptom you've seen that doesn't appear in Section D?

I'll group the Phase 2 fixes into one commit per entity (AI credentials / AI fixes / runs / schedules / projects) as the prompt specifies.
