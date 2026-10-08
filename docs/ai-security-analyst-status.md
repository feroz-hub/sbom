# AI capability status for Security Analyst users

## Request investigation before changes

The running native backend's `availability.py`, `health.py` and `config_loader.py` hashes matched this checkout. Read-only configuration inspection found:

- AegisMed is active, tenant ID 4.
- Its active memberships include Tenant Admin and Security Analyst.
- Platform Gemini is enabled, default and verified.
- AegisMed has an explicit `AiSettings` row, enabled with no kill switch, but no tenant provider row.
- Its AI audit history includes tenant settings updates.

In-process HTTP reproduction used the deployment's existing memberships and database-resolved roles/permissions, binding their context through a temporary TestClient dependency override. This did not use or capture browser login credentials and is not a browser-network recording. Only GET requests were made; provider/tenant settings were not changed. This distinguished a real configuration state from an assumed authorization failure.

| Role | Request / tenant context | HTTP response |
| --- | --- | --- |
| Tenant Admin | `GET /api/analysis/config`, `X-Tenant-ID: 4` | 200; `configured=false`, `source=TENANT`, `feature_enabled=true`, `available_for_tenant=false`, `state=CONFIGURATION_REQUIRED`, management actions allowed |
| Security Analyst | Same request/header | 200; same effective provider state; `can_view_settings=false`, `can_configure=false` |
| Tenant Admin | `GET /api/v1/ai/credentials`, same tenant | 200; zero tenant credentials |
| Security Analyst | Same administrative request | 403; `{"detail":"Insufficient permission"}`; requires `tenant:ai:read` |

The banner uses `/api/analysis/config`, not the administrative credentials endpoint. Its safe status route authenticates and resolves authorized tenant context; it does not require AI configuration-management permission. The administrative 403 is expected and did **not** cause the observed banner. The administrative endpoint remains protected.

## Root cause and policy

The old copy offered the same configuration-required explanation to administrators and non-administrators. It also did not explain why an available platform provider was not selected for AegisMed.

`AiConfigLoader.resolve()` intentionally treats **any tenant credential or tenant settings row** as an explicit, all-or-nothing tenant AI override. A settings-only override therefore suppresses platform providers. `ProviderRegistry.get_default_config()` could not select a tenant provider in this case. Both roles correctly received an authoritative HTTP 200 reporting no effective provider; RBAC did not change inheritance.

This policy is preserved. Silently ignoring or deleting AegisMed's settings row would bypass an explicit override and could discard its feature/budget controls. No production override was removed. An authorized Tenant Administrator can review it and explicitly use the existing reset/restore-inheritance action in AI Settings. Once there is no override, the same runtime resolver selects the verified platform Gemini for both roles.

## Backend changes

Reused `/api/analysis/config` and `effective_ai_status()`; no duplicate endpoint/resolver or new configuration model.

- Added safe `configuration_issue=TENANT_OVERRIDE_WITHOUT_EFFECTIVE_PROVIDER` when the existing effective resolver reports an override with no selected provider.
- Added `can_invoke_ai` as current-user RBAC metadata, evaluated through the **existing** `permission_for_request()` policy for the actual finding AI generation route. This is separate from tenant provider availability, verification, feature controls and budget/SBOM eligibility. No permission mapping/grant was changed.
- Existing encrypted credential resolution, active tenant validation, stored verification, selected-model resolution, feature/kill-switch precedence, fallback policy and cache invalidation remain intact.
- No upstream provider calls are added; no keys, ciphertext, credential IDs or secret references are exposed by the status response.

## Frontend changes

`AiConfigBanner` now:

- Shows read-only “AI Fix Generation unavailable” and “Contact your Tenant Administrator” when a user cannot configure and there is no effective provider.
- Explains the active tenant override instead of implying the platform has no AI provider.
- Directs an authorized administrator to review/reset an empty override through View AI Settings rather than presenting Configure AI as another mandatory onboarding step.
- Preserves platform/tenant-managed available, disabled, pending and temporary-unavailability states.
- Makes clear when tenant AI is available but the current user lacks the existing invocation permission, avoiding an implication that Viewer can generate fixes.
- Separates HTTP 401, 403, 404, 5xx and network-error messages. A failed request never becomes configured=false.
- Keys status cache entries by tenant/platform scope, user ID and permission fingerprint; pauses requests during authentication loading. User/tenant/permission changes do not reuse a previous administrator's action metadata.

Underlying availability is consistent across roles. Configuration actions and invocation permissions can differ. Existing mutation invalidation and periodic safe status refresh remain.

## Permissions and isolation

Security Analyst, Developer and Viewer tests verify safe inherited capability visibility while administrative credential/effective-config reads, credential creation/update/deletion, override changes and platform configuration access remain denied. Cross-tenant status requests are denied. Actual generation-route authorization remains unchanged and is tested separately from provider availability. No production configuration/permission data was modified.

## Files changed

- `app/ai/availability.py`
- `frontend/src/components/dashboard/AiConfigBanner.tsx`
- `frontend/src/components/dashboard/AiConfigBanner.test.tsx`
- `frontend/src/lib/api.ts`
- `tests/test_scoped_configuration.py`
- This report.

## Tests and build

Results: **99 backend tests passed** (40 scoped-configuration tests plus 59 authentication, credential-router and AI-usage regression tests). **36 frontend tests passed** across the banner, dashboard integration and scoped AI settings suites. TypeScript, ESLint, Ruff and `git diff --check` passed. The frontend production build passed using an isolated copy and existing dependencies. Backend tests used a disposable PostgreSQL 17 instance, which was removed afterward.

Coverage includes inherited Gemini with identical admin/analyst status, admin endpoint denial, tenant overrides, settings-only override/reset, disabled generation, verification pending, stored 503 failure, Viewer actions, cross-tenant denial, invocation RBAC, user/tenant/permission cache switching and HTTP/network error handling.
