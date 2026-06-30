# Lifecycle EOL/EOS Current Status Report

## Executive Summary

Status: **PARTIAL**

SBOM Analyser has a real lifecycle implementation, not just documentation. It includes provider classes, a provider chain, admin-configured providers, custom vendor records, lifecycle cache persistence, SBOM/component API responses, report exports, dashboard metrics, and frontend SBOM/admin UI.

It is not GO-ready for EOL/EOS as implemented today because:

- The PostgreSQL lifecycle cache upsert is not safe for components without PURL. The unique constraint includes nullable `purl`, so duplicate cache rows can be inserted for the same `normalized_name`, `normalized_version`, and `ecosystem`.
- `Maintenance` and `Extended Support` are not canonical lifecycle statuses, even though OpenEoX maps those values before canonicalization. They persist as `Unknown` if used as lifecycle status.
- A lifecycle test currently fails because archived GitHub repositories return `Unsupported`, while the test expects `Possibly Unmaintained`.
- Some provider/admin config fields exist but are not fully honored by provider implementations, especially provider-specific `base_url`, `max_retries`, per-provider TTLs, and `circuit_breaker_enabled`.
- Official Vendor Lifecycle is mostly a skeleton that returns `Unknown` with evidence URLs, except Red Hat has a static RHEL cycle implementation.

## Supported Lifecycle Statuses

Defined in `app/services/lifecycle/types.py` as title-case strings.

| Status | Implemented | Persisted | API | UI | Tested | Notes |
| ------ | ----------- | --------- | --- | -- | ------ | ----- |
| `Supported` | Yes | Yes | Yes | Yes | Partial | Used by endoflife.date, vendor, Xeol, Red Hat. |
| `EOL` | Yes | Yes | Yes | Yes | Yes | Main EOL status, dates persist as `eol_date`. |
| `EOS` | Yes | Yes | Yes | Yes | Yes | Main EOS status, dates persist as `eos_date`. |
| `EOF` | Yes | Yes | Yes | Yes | Yes | Main EOF status, dates persist as `eof_date`. |
| `Deprecated` | Yes | Yes | Yes | Yes | Yes | Also sets `deprecated` and legacy `is_deprecated`. |
| `Unsupported` | Yes | Yes | Yes | Yes | Yes | Also sets `unsupported`. Repository archived/disabled maps here. |
| `EOL Soon` | Yes | Yes | Yes | Yes | Partial | Extra implemented status beyond requested list. |
| `Possibly Unmaintained` | Partial | Yes | Yes | Partial | Partial/failing | Defined, but repository inactivity is stored mostly as `maintenance_status`; current failing test expects archived GitHub to map here. |
| `Unknown` | Yes | Yes | Yes | Yes | Yes | Default result for no reliable lifecycle evidence. |
| `extended_support` / `Extended Support` | No canonical status | As `Unknown` if canonicalized | As `Unknown` | No | No | OpenEoX maps `extended_support` to `Extended Support`, but canonical status rejects it. |
| `maintenance` / `Maintenance` | No canonical status | As `Unknown` if canonicalized | As `Unknown` | No | No | Maintenance is represented as `maintenance_status`, not lifecycle status. |

## Provider Status

| Provider | Implemented | Configurable | Enabled | Called During Refresh | Tested | Notes |
| -------- | ----------- | ------------ | ------- | --------------------- | ------ | ----- |
| Custom Vendor Records | Yes | Yes | Disabled by default | Only when enabled and active records exist | Yes | DB records from `lifecycle_vendor_records` plus env JSON are converted to `VendorLifecycleProvider`. Priority default 5. |
| Official Vendor Lifecycle | Partial | Yes | Enabled by default | Yes, if component matches vendor hints | Partial | `OfficialVendorLifecycleProvider` is a skeleton returning `Unknown` with vendor evidence URL. |
| Red Hat Lifecycle | Partial | Yes | Enabled by default | Yes, for RHEL-like components | Partial | Static RHEL 7/8/9 dates, no live Red Hat lifecycle API. |
| endoflife.date | Yes | Yes, but base URL ignored | Enabled by default | Yes, if product slug/version matches | Yes | Calls live v1 and legacy APIs. Product mapping is static plus `aliases.yml`. |
| OpenEoX | Partial/Yes | Yes | Disabled by default | Only when enabled with feed URLs | Yes | Parses generic OpenEoX-compatible JSON feed shapes. Admin requires HTTP(S) feed URLs. No default `https://openeox.org/` feed. |
| Xeol API | Yes | Yes | Disabled by default | Only when enabled | Partial | Uses API URL/key. No CLI in request path. API errors return `Unknown`. |
| Local Xeol DB | Yes | Yes | Disabled by default | Only when enabled with readable path | Yes | Reads Xeol-compatible JSON export via `XEOL_DB_PATH` or admin `config.db_path`. Does not use `xeol.db` format directly unless exported as supported JSON. |
| Package Registry | Yes | Yes, but config not used | Enabled by default | Yes for npm/PyPI/NuGet/Maven/RubyGems | Yes | Correctly treats deprecation/yanked metadata as `Deprecated`, not EOL/EOS. |
| deps.dev | Yes | Yes, but config not used | Enabled by default | Yes for supported ecosystems | Partial | Provides deprecation/advisory/recommendation hints. Does not claim EOL/EOS. |
| OSV | Yes | Yes, but config not used | Enabled by default | Yes for supported ecosystems | Partial | Vulnerability-focused. Returns `Unknown` lifecycle with recommendation/fixed versions. |
| Repository Health | Yes | Yes, but GitHub token config not wired into provider | Enabled by default | Only when repository URL is present | Yes, with one failing expectation | Archived/disabled repos map to `Unsupported`; stale activity maps maintenance evidence, not official EOL. |

## API Endpoints

Actual lifecycle endpoints found:

- `GET /api/lifecycle/sources`
- `GET /api/lifecycle/provider-status`
- `GET /api/lifecycle/component/{component_id}`
- `PUT /api/lifecycle/component/{component_id}`
- `PATCH /api/components/{component_id}/lifecycle-override`
- `POST /api/components/{component_id}/lifecycle/refresh?force=true`
- `POST /api/sboms/{id}/lifecycle/refresh?force=true`
- `GET /api/sboms/{id}/lifecycle`
- `GET /api/sboms/{id}/lifecycle/report?format=json|csv|openeox`
- `GET /api/sboms/{id}/reports/lifecycle-pack`
- `GET /api/admin/lifecycle-providers`
- `PUT /api/admin/lifecycle-providers/{provider_key}`
- `PUT /api/admin/lifecycle-providers/{provider_key}/secret`
- `DELETE /api/admin/lifecycle-providers/{provider_key}/secret/{secret_name}`
- `POST /api/admin/lifecycle-providers/{provider_key}/test`
- `POST /api/admin/lifecycle-providers/{provider_key}/sync`
- `GET /api/admin/lifecycle-vendor-records`
- `POST /api/admin/lifecycle-vendor-records`
- `PUT /api/admin/lifecycle-vendor-records/{record_id}`
- `DELETE /api/admin/lifecycle-vendor-records/{record_id}`
- `POST /api/admin/lifecycle-vendor-records/import`
- `GET /api/admin/lifecycle-vendor-records/export`
- `GET /dashboard/lifecycle`

Sample response shapes from code:

- `/api/lifecycle/sources`: `{ "sources": [{ "name", "provider_key", "provider_type", "priority", "enabled", "status", "last_success", "last_failure", "last_error" }] }`
- `/api/lifecycle/provider-status`: `{ "overall_status", "degraded_count", "providers": [...] }`
- `/api/sboms/{id}/lifecycle`: `{ "sbom_id", "page", "page_size", "total", "items": [component lifecycle dicts] }`
- `/api/sboms/{id}/lifecycle/refresh`: `{ "sbom_id", "total_components", "unique_identities", "cache_hits", "provider_lookups", "updated_components", "unknown_count", "eol_count", "eos_count", "deprecated_count", "provider_errors", "components_enriched", "stale_components" }`

`curl` verification against `localhost:8000` was skipped because no server was listening on port 8000 during the audit.

## Admin UI Status

Implemented UI:

- `/admin/lifecycle-providers`
- `/admin/lifecycle-vendor-records`

Provider UI supports:

- Enable/disable provider: yes.
- Set priority: yes.
- Configure OpenEoX feed URLs: yes.
- Configure Xeol API base URL and API key secret: yes.
- Configure Local Xeol DB path: yes, through JSON config.
- Configure endoflife.date: generic base URL field exists, but backend provider does not use it.
- Save provider secrets: yes for `xeol_api` and `repository_health` in UI; backend secret endpoint is generic.
- Test provider: yes.
- Sync provider: yes, but most providers return a no-op completed message.
- View provider health: yes.
- Create/edit/disable custom vendor records: yes.
- Import/export vendor records: yes.
- Audit logging: yes, backend writes provider config/secret/test/sync/vendor-record audit actions.

Missing or partial:

- No rich provider-specific forms for all providers.
- `max_retries`, provider-specific TTL fields, and `circuit_breaker_enabled` are stored but not fully applied in provider execution.
- Repository health UI can store a secret, but the provider does not use it for GitHub API calls.

## Configuration Status

Actual lifecycle env vars in code/settings/docs:

| Env var | In code | In `.env.example` | In README/docs | Notes |
| ------- | ------- | ----------------- | -------------- | ----- |
| `LIFECYCLE_PROVIDER_TIMEOUT_SECONDS` | Yes | No explicit sample found | Settings-driven | Global timeout. |
| `LIFECYCLE_PROVIDER_MAX_CONCURRENT` | Yes | No explicit sample found | Settings-driven | Present but refresh chain is sequential per component. |
| `LIFECYCLE_XEOL_ENABLED` | Yes | Yes | Yes | Enables Xeol API fallback. |
| `LIFECYCLE_XEOL_API_URL` | Yes | Yes | Yes | Actual name is `API_URL`, not `BASE_URL`. |
| `LIFECYCLE_XEOL_API_KEY` | Yes | Yes | Yes | Also available as encrypted DB secret. |
| `OPENEOX_ENABLED` | Yes | Yes | Yes | Env fallback only. |
| `OPENEOX_FEED_URLS` | Yes | Yes | Yes | Comma-separated feed URLs. |
| `XEOL_ENABLED` | Yes | Yes | Yes | Enables local Xeol DB/JSON fallback. |
| `XEOL_DB_PATH` | Yes | Yes | Yes | Local JSON path. |
| `XEOL_CLI_PATH` | Settings only | Yes | Yes | Not used in request-time provider path. |
| `LIFECYCLE_CACHE_TTL_KNOWN_DAYS` | Yes | Yes | Yes | Used by cache row expiry. |
| `LIFECYCLE_CACHE_TTL_UNKNOWN_HOURS` | Yes | Yes | Yes | Used by cache row expiry. |
| `LIFECYCLE_CACHE_TTL_PROVIDER_FAILURE_MINUTES` | Yes | Yes | Yes | Code supports provider failure TTL, but normal provider failures are not clearly cached with `provider_failure` evidence. |
| `LIFECYCLE_CACHE_TTL_DEPRECATED_DAYS` | Yes | Yes | Yes | Used for deprecated cache entries. |
| `LIFECYCLE_EOL_SOON_DAYS` | Yes | Yes | Yes | Used by risk classification; some providers use hardcoded soon windows. |
| `LIFECYCLE_EOS_SOON_DAYS` | Yes | Yes | Yes | Used by risk classification. |
| `LIFECYCLE_VENDOR_RECORDS_JSON` | Yes | Yes | Yes | Env fallback custom vendor records. |
| `NVD_API_KEY` | Yes, vulnerability side | Yes | Yes | Not a lifecycle provider key. |
| `GITHUB_TOKEN` | Docs/source-cache side | Yes | Yes | Not wired into `RepositoryHealthProvider`. |

Expected but not actual:

- `LIFECYCLE_XEOL_BASE_URL` is not used; actual code uses `LIFECYCLE_XEOL_API_URL`.

## Database Status

Lifecycle persistence is on these models/tables:

- `SBOMComponent` / `sbom_component`: component lifecycle result fields.
- `ComponentLifecycleCache` / `component_lifecycle_cache`: shared lifecycle cache.
- `LifecycleProviderConfig` / `lifecycle_provider_configs`: admin provider settings.
- `LifecycleProviderSecret` / `lifecycle_provider_secrets`: encrypted provider secrets.
- `LifecycleVendorRecord` / `lifecycle_vendor_records`: custom vendor lifecycle records.
- `ComponentLifecycleOverrideAudit` / `component_lifecycle_override_audit`: manual lifecycle override history.
- General `AuditLog` / `audit_log`: provider admin audit events.

Key lifecycle columns include:

- Status/dates: `lifecycle_status`, `eol_date`, `eos_date`, `eof_date`.
- Flags: `deprecated`, `is_deprecated`, `unsupported`.
- Source/evidence: `lifecycle_source`, `lifecycle_source_url`, `lifecycle_confidence`, `lifecycle_evidence_json`, `source_name`, `source_url`, `evidence_json`, `confidence`.
- Freshness: `lifecycle_checked_at`, `lifecycle_is_stale`, `checked_at`, `expires_at`, `is_stale`.
- Identity: `normalized_name`, `normalized_version`, `ecosystem`, `purl`, `cpe`, `lookup_key`.
- Recommendations: `latest_version`, `latest_supported_version`, `recommended_version`, `lifecycle_recommendation`, `recommendation`, `maintenance_status`.

Migrations:

- `020_lifecycle_management_platform.py`: initial lifecycle fields on components.
- `022_component_lifecycle_enrichment.py`: provider enrichment fields and `component_lifecycle_cache`.
- `025_lifecycle_advanced_fields.py`: unsupported/latest/stale/cache lookup additions.
- `026_vex_lifecycle_enrichment.py`: lifecycle override audit table.
- `034_lifecycle_provider_admin.py`: provider configs, secrets, vendor records, default provider seed data.
- `035_widen_audit_log_fields.py`: audit action width for namespaced lifecycle actions.
- `037_stage9_normalization_dedup.py`: normalized identity/dedup fields.

Cache/upsert status:

- PostgreSQL and SQLite use dialect-specific `INSERT ... ON CONFLICT DO UPDATE`.
- Batch rows are deduped before write.
- `force=true` refresh writes through the same upsert path.
- **Bug:** PostgreSQL unique constraint `normalized_name, normalized_version, ecosystem, purl` is unsafe when `purl` is `NULL`; verified two upserts inserted two rows before rollback.

## Refresh Flow Status

`POST /api/sboms/{id}/lifecycle/refresh` calls `LifecycleEnrichmentService.enrich_sbom`.

Flow:

1. Loads non-duplicate SBOM components.
2. Groups components by normalized lifecycle lookup key.
3. Applies manual override first.
4. Reads `component_lifecycle_cache` unless `force=true` or expired.
5. Builds provider chain from DB admin configuration; falls back to static settings on DB failure.
6. Filters providers by `supports(component)`.
7. Calls providers by priority.
8. Stops early on high-confidence known lifecycle evidence.
9. Chooses result by manual override, vendor authority, lifecycle severity, then confidence.
10. Writes cache rows and applies selected result to every component in the identity group.
11. Commits and returns a summary.

Actual priority bands:

- Manual override: 0
- Custom Vendor Records: default 5 from admin config
- Official Vendor / Red Hat: 10
- OpenEoX: 20
- endoflife.date: 30
- Xeol API / DB: 40
- Package Registry: 50
- deps.dev: 60
- OSV: 70
- Repository Health: 80
- Heuristic: 90 constant exists, no provider found

Provider result behavior:

- Disabled DB providers are skipped.
- Provider results are not simply first-match-wins; high-confidence evidence can stop the chain, and the decision engine chooses by severity/confidence/vendor authority.
- Evidence is preserved on the chosen result, with some merged recommendation/evidence data from later actionable results when evaluated.
- Provider failures/timeouts become `Unknown` and should not abort refresh.

## Frontend Lifecycle UI

| UI location | What it shows | Missing/partial |
| ----------- | ------------- | --------------- |
| SBOM detail components tab | Lifecycle status badge, EOL/EOS/EOF dates, source/confidence, recommendation, stale/manual flags, evidence modal, refresh, manual override, CSV/pack export. | No full dedicated lifecycle tab; `Possibly Unmaintained` has no special badge logic. |
| Component edit modal | Lifecycle status, maintenance status, EOL/EOS/EOF dates, recommendation, evidence URL, override reason, deprecated flag. | No `unsupported` checkbox in SBOM edit modal; no Extended Support/Maintenance lifecycle status. |
| Dashboard | `/dashboard/lifecycle` metrics from persisted components. | Depends on lifecycle refresh having run. |
| Reports/export | Lifecycle JSON, CSV, OpenEoX JSON, ZIP pack. | Export is based on persisted component data. |
| Admin providers | Provider list, enable/disable, edit priority/URLs/config/TTL, test, sync, health, selected secrets. | Some config fields are stored but not fully enacted by backend providers. |
| Admin vendor records | CRUD, import/export, search. | Deletes disable records; no hard delete UI. |

## OpenEoX Status

- Provider implemented in `app/services/lifecycle/openeox_provider.py`.
- Not only documented.
- Requires feed URLs in admin when enabled.
- Supports multiple feed URLs.
- Parses generic JSON arrays or objects with `components`, `products`, `entries`, or `lifecycle`.
- Supports `file://` internally, but admin validation only accepts HTTP(S) feed URLs.
- Stores evidence as `{"authority": "openeox", "record": ...}` and confidence High when evidence URL exists, Medium otherwise.
- Tests exist for local `file://` feed parsing and OpenEoX report export.
- Code does not use `https://openeox.org/` as a default feed URL. The default feed list is empty.
- Partial: this is OpenEoX-compatible generic JSON parsing, not a strict schema validator for all OpenEoX documents.
- Bug/Gap: `maintenance` and `extended_support` feed statuses are mapped to non-canonical lifecycle statuses and become `Unknown` after canonicalization.

## Xeol Status

- Xeol API provider implemented in `app/services/lifecycle/xeol_provider.py`.
- Local Xeol DB/JSON provider implemented in `app/services/lifecycle/xeol_db_provider.py`.
- Xeol CLI integration is not implemented in request path; `XEOL_CLI_PATH` is settings/documentation only for scheduled sync, and sync currently clears local DB cache.
- Local provider reads JSON exports, not a native `xeol.db` database.
- Admin validates `config.db_path` exists when enabling local Xeol DB.
- API provider uses `LIFECYCLE_XEOL_API_KEY` or encrypted DB secret `api_key`.
- Actual env vars: `XEOL_ENABLED`, `XEOL_DB_PATH`, `XEOL_CLI_PATH`, `LIFECYCLE_XEOL_ENABLED`, `LIFECYCLE_XEOL_API_URL`, `LIFECYCLE_XEOL_API_KEY`.
- `LIFECYCLE_XEOL_BASE_URL` is not used.
- Path handling uses Python `Path(...).is_file()`; no explicit Windows/macOS path tests were found.
- Provider errors are handled as `Unknown`.
- Tests exist for Xeol DB matching and env-wired Xeol API provider creation.

## endoflife.date Status

- Provider implemented in `app/services/lifecycle/endoflife_date_provider.py`.
- Calls live API by default using v1 and legacy endpoints.
- Product mapping is static plus `app/services/lifecycle/aliases.yml`.
- Mapped products include Node.js, Python, Java/OpenJDK/JDK, .NET, Angular, Django, Spring/Spring Boot, Ubuntu, Debian, PostgreSQL, MySQL, Kubernetes, Go, Ruby, PHP, Nginx, Apache, Redis, OpenSSL, Docker Engine, Alpine, Elasticsearch, Kafka.
- Handles unknown products by returning `Unknown`.
- Handles 404, HTTP errors, JSON errors by returning `Unknown`.
- Has a simple retry loop.
- Results are cached by the lifecycle enrichment cache after refresh.
- Correctly maps EOL/EOS/EOF dates when present.
- Admin `base_url` is stored but not used by this provider.

## Package Registry / deps.dev / OSV / Repo Health

- Package Registry: conservative registry metadata provider. Produces `Deprecated` for npm deprecation, PyPI yanked, NuGet deprecation. Returns `Unknown` plus latest/recommendation for ordinary outdated packages. Does not claim EOL/EOS from age.
- deps.dev: returns `Deprecated` for deprecation metadata and `Unknown` with advisory/recommendation signals otherwise. Does not claim pure EOL/EOS.
- OSV: vulnerability-focused. Returns `Unknown` with vulnerability count and fixed-version recommendation. Does not claim pure EOL/EOS.
- Repository Health: uses repository signals. Archived/disabled repositories return `Unsupported`; stale activity becomes maintenance evidence, not EOL. Current lifecycle test expects archived GitHub as `Possibly Unmaintained`, so behavior and tests disagree.

## Known Issues

1. **Critical:** PostgreSQL lifecycle cache can duplicate rows when `purl IS NULL` because the unique constraint includes nullable `purl`.
2. **Critical:** `Maintenance` and `Extended Support` are not valid lifecycle statuses; OpenEoX status mapping silently canonicalizes them to `Unknown`.
3. **Important:** `tests -k "lifecycle"` fails on repository health archived status expectation.
4. **Important:** Broad `tests -k "provider"` fails due AI provider test fixture cleanup against existing `sbom_validation_sessions`, so provider verification is noisy in this shared DB.
5. **Important:** Official Vendor Lifecycle is mostly a skeleton and should not be represented as full official lifecycle support.
6. **Important:** Admin provider `base_url` for endoflife.date is not used.
7. **Important:** Admin `max_retries`, per-provider TTL overrides, and `circuit_breaker_enabled` are not fully applied to runtime provider behavior.
8. **Important:** Repository health secret/GitHub token is exposed in UI convention but not used by `RepositoryHealthProvider`.
9. **Important:** Local Xeol DB is a JSON export reader, not native `xeol.db` or CLI integration.
10. **Nice-to-have:** `/api/sboms/{id}/lifecycle` is code-verified but was not live-curl verified because no localhost server was running.

## Test Results

Commands run from `/Users/ferozebasha/sbom` with:

```bash
source .venv/bin/activate
export DATABASE_URL="postgresql+psycopg://sbom:sbom@localhost:55439/sbom_analyser"
export APP_SECRET_KEY="dev-secret-change-this"
export AUTH_ENABLED=false
```

Backend:

| Command | Result |
| ------- | ------ |
| `python -m alembic current` | Passed, current head `039_validation_workspace_large_file`. |
| `python -m alembic heads` | Passed, single head `039_validation_workspace_large_file`. |
| `python -m alembic upgrade head` | Passed. |
| `python -m ruff check app tests` | Passed. |
| `python -m pytest -q tests -k "lifecycle"` | Failed: 1 failed, 76 passed, 1448 deselected. Failure: `test_github_archived_maps_possibly_unmaintained` expected `Possibly Unmaintained`, got `Unsupported`. |
| `python -m pytest -q tests -k "provider"` | Failed/noisy: 1 failed, 1 error, 100 passed, 4 skipped, 1419 deselected. Failures came from AI provider tests trying to delete `sbom_source` rows referenced by `sbom_validation_sessions`. |
| `python -m pytest -q tests -k "eol or eos"` | Passed: 15 passed, 1510 deselected. |

Additional cache verification:

```text
Two PostgreSQL cache upserts for the same normalized identity with purl=None inserted 2 rows before rollback.
```

Frontend from `/Users/ferozebasha/sbom/frontend`:

| Command | Result |
| ------- | ------ |
| `npx tsc --noEmit` | Passed, no errors printed. |
| `npm test -- --run lifecycle` | Passed: 3 files, 17 tests. |
| `npm test -- --run admin` | Passed: 1 file, 5 tests. |
| `npm run build` | Passed, Next.js production build completed. |

Live curl:

| Command | Result |
| ------- | ------ |
| `curl http://localhost:8000/api/lifecycle/sources` | Skipped/failed: no server listening on port 8000. |
| `curl http://localhost:8000/api/lifecycle/provider-status` | Skipped/failed: no server listening on port 8000. |
| `curl http://localhost:8000/api/sboms` | Skipped/failed: no server listening on port 8000. |

## Recommended Next Fixes

### 1. Critical blockers

1. Fix lifecycle cache identity for nullable PURL in PostgreSQL. Options: use non-null identity hash/generated key, `COALESCE(purl, '')` expression unique index, or make `lookup_key` the canonical unique key.
2. Decide canonical handling for `Maintenance` and `Extended Support`: add them to allowed statuses or store them only in `maintenance_status` while mapping lifecycle status to `Supported`.
3. Resolve repository health semantics and tests: either archived repository means `Unsupported`, or change provider to return `Possibly Unmaintained`.

### 2. Important improvements

1. Apply admin-configured `base_url`, retries, per-provider TTLs, and circuit breaker flags at runtime.
2. Wire GitHub token/secret into repository health requests or remove the unsupported secret UI affordance.
3. Clarify Official Vendor Lifecycle as skeleton/URL evidence only unless real vendor APIs/static lifecycle tables are added.
4. Add tests for null-PURL cache upsert on PostgreSQL.
5. Add tests for `extended_support` and `maintenance` OpenEoX feed records.
6. Add explicit tests for disabled provider skipping and admin priority changing actual refresh order.

### 3. Nice-to-have

1. Add stricter OpenEoX schema validation and clearer feed validation errors.
2. Add native Xeol DB/CLI sync support if local Xeol is a target deployment mode.
3. Add dashboard/UI special handling for `Possibly Unmaintained`.
4. Add live API smoke tests behind explicit env flags for endoflife.date/OpenEoX/Xeol.

## Final Status

**PARTIAL: some providers/statuses exist but not fully verified.**

The project has a broad lifecycle foundation and several providers are operational, but cache safety, status taxonomy gaps, and provider/admin runtime gaps prevent a GO assessment for EOL/EOS lifecycle support.

## Acceptance Criteria for This Audit

- Actual code inspected: yes.
- Actual providers listed: yes.
- Actual statuses listed: yes.
- API endpoints verified from code: yes.
- Admin UI checked: yes.
- Config/env vars checked: yes.
- Tests run or skipped with reason: yes.
- Gaps clearly listed: yes.
- No unsupported claim made: yes.
- Report saved as `docs/LIFECYCLE_EOL_EOS_STATUS_REPORT.md`: yes.
