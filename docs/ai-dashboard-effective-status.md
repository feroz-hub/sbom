# Effective AI dashboard status

## Root cause

`AiConfigBanner` read `/api/v1/ai/credentials` and `/settings`, treating the tenant-local credential list as effective availability. Empty tenant lists are expected when a tenant inherits platform configuration. It also reduced feature/configuration/verification to one boolean, hid disabled states and used provider-specific marketing copy.

A second defect was found during API tests: `/api/analysis/config` used legacy authentication without binding `CurrentContext`. Runtime resolution at this route could therefore select platform scope even for an explicit tenant override. The route now also uses the existing `get_current_tenant_context` dependency. Platform-only callers are permitted on this read route; tenant headers remain authoritative through the normal live membership/context resolver.

## Existing architecture and resolution

- `AiProviderCredential` stores encrypted credentials owned by platform (`tenant_id=NULL`) or tenant. `app/security/secrets.py` manages encryption; no key is copied for inheritance.
- `AiSettings` owns scoped feature, kill-switch and budget controls.
- `app/ai/config_loader.py`: `AiConfigLoader.resolve()` selects the effective snapshot, cached separately per tenant. `resolve_effective_ai_configuration(tenant_id)` establishes explicit background workload scope. Active-tenant checks remain enforced.
- `app/ai/registry.py`: `ProviderRegistry.get_default_config()` selects the exact default credential using the loader's snapshot and existing default/provider policy. Status reuses this selection, not a frontend algorithm.
- Any tenant credential or settings row establishes an override. That override suppresses platform/env providers, including when empty, disabled, undecryptable or invalid. Removing the whole override restores inheritance; deleting one credential may leave tenant settings and does not imply reset.
- Platform rows are authoritative for their provider names; legacy environment providers remain a migration fallback only where the loader permits them.
- `app/ai/model_resolver.py` uses the selected persistent `AiProviderModel`, otherwise the legacy configured model. `app/ai/model_registry.py` supports discovery, selection and model generation tests.
- `app/routers/ai_credentials.py` owns saved connection tests and sanitizes/stores their results; invalid authentication disables a saved credential. Provider health classification is shared through `app/ai/verification.py`.
- Loader invalidation uses the existing cross-process version counter and safety TTL; registry rebuilds follow that snapshot.

## Backend changes

The existing authenticated analysis-config response includes additive `ai_status` metadata from `app/ai/availability.py`: configured, source, provider/model, stored verification, effective feature state, availability, display state, management permissions and settings scope. The service reads only the selected credential's exact allowed owner for stored verification. It validates local configuration with the existing validator and does not instantiate or probe providers. Failures produce `STATUS_UNAVAILABLE`, not a claim of missing configuration.

No keys, previews, ciphertext, credential IDs, secret references, endpoint credentials or raw verification errors are returned in this status. Configuration APIs retain their existing stricter management authorization. Status actions are permitted by current server-resolved scoped AI permissions, never a guessed frontend role.

Stored network failures now share the existing temporary-unavailability classification with HTTP rate-limit/provider-unavailable results. This does not alter execution fallback or credential activation policy.

## Frontend changes and states

`AiConfigBanner` consumes only authoritative `ai_status`. It distinguishes available platform/tenant-managed configuration, configuration required, feature disabled, verification pending, temporary provider failure, configuration needing attention and status lookup failure. Known provider names have readable labels. There is no provider-specific setup marketing.

An available provider requires effective generation enabled, usable selected configuration and successful stored verification. A saved but unverified provider is not called available. Missing configuration offers Configure AI only when allowed; other states offer View AI Settings only when allowed, using `/settings/ai` or `/platform/configuration/ai` according to current scope. Viewers retain status without management actions.

The compact secondary status stays after the existing no-SBOM onboarding block. Upload SBOM remains the primary onboarding action and AI availability does not become another required setup step.

## Feature policy and refresh

Status follows runtime settings exactly: database `AiSettings.feature_enabled` is authoritative when present; `AI_FIXES_ENABLED` is its environment fallback when no settings row exists. An effective false flag or active kill switch renders disabled even with a verified provider. This task does not change that established execution policy by turning the environment fallback into a new absolute switch.

Dashboard cache keys include tenant/platform context. Existing credential/settings mutations invalidate analysis-config; saved connection tests and override creation/reset now do likewise. A lightweight 60-second status refresh observes external platform changes without provider API calls. Server version invalidation/TTL remains unchanged. No browser-storage clearing is required.

## Files changed

- `app/ai/availability.py` (new), `app/ai/verification.py` (new)
- `app/core/security.py`, `app/routers/health.py`, `app/routers/ai_credentials.py`
- `frontend/src/components/dashboard/AiConfigBanner.tsx`
- `frontend/src/components/settings/ai/ScopedAiConfiguration.tsx`
- `frontend/src/hooks/useAiCredentials.ts`
- `frontend/src/lib/api.ts`, `frontend/src/lib/queryInvalidation.ts`
- `tests/test_scoped_configuration.py`, `tests/ai/test_credentials_router.py`
- `frontend/src/components/dashboard/AiConfigBanner.test.tsx` (new)
- This report.

## Validation

Frontend: 26 tests passed across the new AI banner suite, existing dashboard integration suite and scoped AI settings suite. Cases cover platform/tenant labels, all display states, role-gated actions, scope-correct settings links, and mutation-driven refresh. TypeScript passed. ESLint passed with two existing unused-variable warnings in `api.ts`.

Backend: 94 tests passed across scoped configuration, authentication, credential router and AI usage router suites using a disposable PostgreSQL 17 test container. Coverage includes actual Gemini/OpenAI inheritance and overrides, override removal, platform provider/model changes, tenant isolation, Viewer/Platform Admin actions, feature/kill-switch disablement, pending verification, 429/503/network failure classification, invalid override handling, no provider instantiation, and secret-free response fields. Existing authentication and credential-leak regression tests passed. Two final targeted cases also passed, checking the invalid override with an enabled legacy credential row and provider replacement.

Frontend production build: passed (Next.js 16.3.4), from an isolated copy with the existing dependencies. Ruff, Python compilation, TypeScript and `git diff --check` passed. No live provider requests or production database mutations were used. The initial default test database was unavailable; SQLite was unsuitable for current authorization fixtures, so verification used a fresh disposable PostgreSQL instance rather than existing application databases.
