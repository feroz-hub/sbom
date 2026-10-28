# Platform defaults and tenant configuration overrides

## Architecture and migration

Previously AI credentials/settings, lifecycle provider configurations/secrets,
AI registries and lifecycle result caches were global. Existing encrypted
credential storage, provider/model registries, forms and APIs are reused;
there is no second configuration subsystem.

Migration `065_scoped_configuration` follows the unreleased V2 migration 064.
Existing configuration rows are preserved as platform defaults (`tenant_id IS
NULL`). Tenant overrides have a non-null tenant foreign key. Partial unique
indexes enforce one platform slot; tenant/slot unique constraints enforce one
override. AI default/fallback credential uniqueness is per owner, not global.
AI settings retain platform row 1 and permit one row per tenant. Lifecycle cache
identity additionally includes a configuration namespace. Old cache rows remain
in the legacy namespace and cannot supply tenant-specific results.

The frozen V1 snapshot is unchanged. Unreleased V2's explicit Platform Admin
allowlist now contains 19 permissions, including seven configuration permissions.
065 grants seven corresponding tenant permissions to TENANT_ADMIN only:

| Scope | AI | Lifecycle provider |
| --- | --- | --- |
| Platform | `platform:ai:read/update/test` | `platform:lifecycle-provider:read/update/test/sync` |
| Tenant | `tenant:ai:read/update/test` | `tenant:lifecycle-provider:read/update/test/sync` |

These are separate permissions, not a platform tenant-access bypass. Platform
Admin still needs explicit active membership for any tenant context and receives
only that membership's tenant roles there. Tenant Admin gains no platform grants.

Apply both migrations before starting application/worker processes. No existing
credentials or tenant identities are deleted or copied. Automatic downgrade is
refused: flattening overrides would leak/overwrite configuration, and restoring
V1 platform permissions restores customer-data superuser access. Rollback needs
a reviewed backup/application boundary and an explicit security review.
Fresh installations must use the supported `alembic upgrade head`/frozen-047
bootstrap path. The historical 001 live-metadata bootstrap is not a supported
way to construct an empty database at an intermediate revision.

## Resolution and failure policy

`resolve_effective_ai_configuration(tenant_id)` delegates to the single existing
AI loader under the workload's tenant context. An explicit tenant settings or
credential row owns the tenant's provider selection; otherwise platform DB/env
defaults apply. The first tenant provider write also snapshots effective controls
into tenant settings in the same transaction, so later platform budget/enable
changes cannot alter its override. The UI can establish those settings before
editing providers. Platform secrets are never cloned into tenant overrides.

Lifecycle `resolve_effective_lifecycle_provider(db, tenant_id, provider_key)`
overlays each tenant provider independently on the platform provider dictionary.
Overriding one provider leaves all other providers inheriting dynamically.
An explicit disabled override disables that provider rather than re-enabling its
platform default. Reset deletes only the current tenant's relevant configuration
and secrets and immediately restores inheritance.

An invalid/unusable explicit override does **not** silently fall back to platform
or another tenant credentials. Tenant configuration read failures fail closed.
Platform-only legacy environment fallback remains for existing deployments.
Disabled tenants cannot resolve configuration; scheduled tenant analyses and
tenant model discovery skip disabled tenants.

## Credentials, jobs and caches

AI uses the existing SecretCipher; lifecycle uses its existing encrypted secret
service. Every lookup is constrained to the selected configuration's owner.
No tenant override falls back to a platform secret. Normal GET/test/audit
responses do not contain raw keys or key fragments. Legacy lifecycle JSON secret
fields and endpoint userinfo/query values are excluded from safe metadata.
New credentials in endpoint URLs/settings JSON are rejected. Provider errors
are categorized rather than returning exception text containing credentials.

Request pipelines and Celery jobs use workload tenant context, not worker-startup
global configuration. AI fix rollout resolution occurs after binding job scope.
Model discovery explicitly binds each credential owner (including clearing any
inherited tenant context for platform rows). Lifecycle enrichment resolves its
provider chain while bound to the workload tenant.

AI loader/registry keys include tenant identity. Redis invalidation counters are
per scope: tenant writes invalidate that tenant; platform writes propagate to
all effective readers without overwriting overrides. The registry also respects
the loader TTL when Redis is unavailable. Without Redis, cross-process propagation
is bounded by the existing 60-second safety TTL, not guaranteed instantaneous.
AI result keys include tenant and an effective-configuration fingerprint (also
protecting persistent result caches when Redis is unavailable). Lifecycle snapshots are
resolved dynamically, not held under a global cache key; lifecycle result keys
include tenant and a fingerprint of effective provider configurations/owner
credentials. Another tenant's writes cannot supply or overwrite these results.
Lifecycle circuit-breaker/health trackers are also tenant-scoped and reset when
that tenant's effective configuration fingerprint changes; a failing override
cannot open another tenant's circuit breaker.

## API and UI

| Context | UI | API |
| --- | --- | --- |
| Platform AI | `/platform/configuration/ai` | `/api/platform/configuration/ai/*` |
| Tenant AI | `/settings/ai` | `/api/v1/ai/*` configuration routes |
| Platform lifecycle | `/platform/configuration/lifecycle` | `/api/platform/configuration/lifecycle/*` |
| Tenant lifecycle | `/admin/lifecycle-providers` | `/api/admin/lifecycle-providers/*` |

Platform aliases invoke the same endpoint implementations with explicit platform
authorization. They ignore inherited tenant headers and do not accept a tenant
selection/override editor. Tenant endpoints use authenticated live membership
and current context. Foreign credential IDs return 404; foreign tenant contexts
are rejected. Tenant pages show source/tenant name, safe effective metadata,
Override and Reset to Platform Default actions. Platform pages edit only defaults.
All actions and navigation use active-context permissions.

AI test-only configurations remain transient. Saved tests use only owned
credentials; the inheriting AI summary does not expose platform credential
management/testing controls. Lifecycle inherited tests can test the effective
platform provider without changing its health/configuration record. Xeol API
tests use the selected owner's encrypted credential. Existing sync capabilities
are retained; this task does not introduce a new feed scheduler or provider.

## Audit and limitations

Structured audits distinguish PLATFORM_AI_CONFIGURATION_UPDATED/TESTED,
TENANT_AI_OVERRIDE_CREATED/UPDATED/REMOVED/TESTED and corresponding lifecycle
provider events. They carry actor, scope/tenant, safe metadata and request
correlation IDs. Existing AI credential audit records are retained, now scoped.
No raw credential payload is included. Configuration writes retain the existing
best-effort audit reliability semantics.

Supported providers/fields remain those in the existing registry; this change
does not add AWS Bedrock or Azure-specific adapters. Lifecycle vendor reference
records remain the existing reference-data subsystem, not tenant configuration
overrides. Host-local Xeol database paths retain existing validation and require
trusted configuration administrators. No real external provider credentials or
production/deployed containers are used for automated verification.

## Verification

`tests/test_scoped_configuration.py` exercises real authenticated API permission
boundaries, dynamic defaults/reset, per-provider overrides, credential isolation,
cross-tenant rejection, disabled tenant failure, scoped result namespaces and
owner-bound model discovery. Existing AI/provider/model/cache, lifecycle and V2
authorization tests are included in regression runs. Frontend tests cover source
display, override/reset, explicit platform endpoints, role/context visibility and
credential indicators.

Final verification (runs overlap; counts are not cumulative):

| Check | Result |
| --- | --- |
| Broad relevant backend regression sweep | 683 passed, 5 skipped, 2 deselected |
| Final scoped configuration + AI credential regression | 61 passed |
| Lifecycle circuit-breaker/runtime regression | 109 passed |
| Configuration audit/env-migration regression | 86 passed |
| Focused frontend regression | 88 passed across 13 files |
| Full frontend suite | 1,148 passed, 8 skipped; one existing Redis integration setup failed because `redis-server` is unavailable |
| Frontend production build and TypeScript typecheck | Passed |
| Frontend lint | No errors; 53 existing warnings |
| Changed/new Python Ruff | Passed |
| Full-repository Ruff | 25 existing errors in untouched files |
| Migration preservation smoke test | 064 to 065 passed; encrypted payload preserved, legacy plaintext preview cleared |
| `git diff --check` | Passed |

Tests used a disposable PostgreSQL container/database, not deployed application
data. No live browser or external AI/lifecycle-provider smoke test was performed.
The relevant backend sweep is broad but is not the entire repository backend
suite. Fresh database migration to `head` uses the existing frozen-047 baseline;
the historical empty-database intermediate-064 path encounters the pre-existing
001/034 migration incompatibility. No old migration was rewritten.

Changes also include the prior uncommitted V2 implementation documented in
`platform-tenant-v2.md`; it has not been committed or pushed.

## Configuration change manifest

- Schema/catalogue: `alembic/versions/065_scoped_configuration.py`,
  `app/models.py`, `app/authorization_catalog_seed_v2.py`,
  `app/core/permissions.py`, `app/core/security.py`,
  `scripts/compare_authorization_catalog.py`.
  `scripts/migrate_env_to_db.py` restricts env migration/force updates to platform
  credentials; matching tenant credentials are never migrated or overwritten.
  `app/core/context.py` explicitly types clearing a background task context.
- Scope/API: `app/services/configuration_scope.py`, `app/db.py`, `app/main.py`,
  `app/routers/ai_credentials.py`, `app/routers/lifecycle_admin.py`,
  `app/schemas_lifecycle_admin.py`.
- AI runtime/audit: `app/ai/config_loader.py`, `app/ai/registry.py`,
  `app/ai/model_resolver.py`, `app/ai/cache.py`, `app/ai/credential_audit.py`.
- Lifecycle runtime: `app/services/lifecycle/provider_config_service.py`,
  `provider_registry.py`, `secret_service.py`, `lifecycle_cache_repository.py`,
  `lifecycle_enrichment_service.py` in that same directory.
  `provider_status.py` in that directory isolates provider circuit breakers.
- Workers: `app/workers/ai_fix_tasks.py`, `ai_model_discovery.py`,
  `scheduled_analysis.py` in that same directory.
- Pages: `frontend/src/app/platform/configuration/ai/page.tsx`,
  `frontend/src/app/platform/configuration/lifecycle/page.tsx`,
  `frontend/src/app/settings/ai/page.tsx`,
  `frontend/src/app/admin/lifecycle-providers/page.tsx`,
  `frontend/src/app/settings/page.tsx`.
- Shared UI: `frontend/src/components/settings/ai/ConfigurationScope.tsx`,
  `ScopedAiConfiguration.tsx`, `AiSettingsPage.tsx`,
  `AddProviderDialog/AddProviderDialog.tsx`, `ProvidersList/ProviderCard.tsx`,
  `ProvidersList/ProviderModels.tsx` under that AI directory;
  `frontend/src/components/admin/ScopedLifecycleConfiguration.tsx`,
  `LifecycleProviderSettings.tsx`, `LifecycleProviderForm.tsx` under admin.
- Frontend support: `frontend/src/hooks/useAiCredentials.ts`,
  `frontend/src/lib/api.ts`, `navigation.ts`, `queryInvalidation.ts` under lib,
  `frontend/src/types/index.ts`.
- Tests: `tests/test_scoped_configuration.py`, `tests/conftest.py`,
  `tests/ai/test_credentials_router.py`, `tests/test_lifecycle_provider_admin.py`,
  `tests/ai/test_model_registry.py`, `tests/ai/test_provider_contract_matrix.py`,
  `tests/ai/test_migrate_env_to_db.py`,
  `tests/test_lifecycle_enrichment.py`, `tests/test_phase8_authorization_catalog_seed.py`,
  `frontend/src/components/settings/ai/__tests__/ScopedAiConfiguration.test.tsx`,
  `ProviderModels.test.tsx` in that same test directory,
  `frontend/src/components/admin/LifecycleProviderSettings.test.tsx`,
  `frontend/src/components/admin/ScopedLifecycleConfiguration.test.tsx`,
  `frontend/src/hooks/useAuth.test.tsx` (passive-effect timing assertion).
- Documentation: this file and the prior V2 report.
