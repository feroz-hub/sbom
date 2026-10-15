# Component lifecycle provider remediation — 16 October 2026

## Scope and baseline

Source of truth: clean checkout `codex/component-finding-reconciliation`, commit `51463d2`. No existing working-tree changes were present. No branches were reset, no production settings were edited, and nothing was deployed.

The platform page is `frontend/src/app/platform/configuration/lifecycle/page.tsx`, through `ScopedLifecycleConfiguration` and `LifecycleProviderSettings`. `/admin/lifecycle-providers` is the tenant configuration route. The frontend API client selects `/api/platform/configuration/lifecycle` or `/api/admin/lifecycle-providers`. Both use `app/routers/lifecycle_admin.py`, the configuration/secret services, the registry, provider chain and enrichment service. Refresh persists component fields and scoped `ComponentLifecycleCache` entries; lifecycle reports read those persisted components.

Authorization already uses `app/core/route_policies.py` and the protected router dependency. Component and SBOM access uses tenant-bound SQLAlchemy criteria in `app/db.py`. Those controls were preserved; regression tests exercise guessed foreign component/SBOM IDs. Reference records are platform-owned, while provider configuration and credentials support tenant overrides and dynamic platform inheritance.

Baseline backend command:

```bash
.venv/bin/python -m pytest tests/test_lifecycle_provider_admin.py tests/test_lifecycle_engine_v2.py tests/test_lifecycle_enrichment.py tests/test_lifecycle_cache_upsert.py tests/test_lifecycle_xeol_openeox.py -q
```

Result: **82 passed, 1 failed**, 105.06 seconds. The pre-existing failure was `test_custom_vendor_record_crud_and_lookup_participation`: a tenant actor attempted platform-only reference-record CRUD (403). The test now asserts that denial and uses an explicit platform fixture for authorized record creation; application authorization was not relaxed.

Baseline frontend command, from `frontend`:

```bash
npm test -- --run src/components/admin/LifecycleProviderSettings.test.tsx
```

Result: **30 passed**.

## A. Root causes and fixes

Paths below are relative to `/home/hcluser1/sbom_native/sbom`.

| ID | Original defect / root cause | Severity | Files modified | Implemented correction | Test evidence | Limitations |
|---|---|---|---|---|---|---|
| LC-01 | Six provider types returned unconditional success without executing a lookup | High | `provider_config_service.py`, new `provider_probe.py`, `schemas_lifecycle_admin.py` | Provider-specific network/local verification, structured connection/auth/parsing/coverage flags; placeholder reports unsupported | Genuine method/payload, malformed response, HTTP failures and local probe tests | Network coverage is limited to each displayed sample |
| LC-02 | DB exceptions silently enabled the static provider list | High | `provider_registry.py`, `routers/lifecycle.py` | Configuration failures stop execution; status endpoints report configuration unavailable | Registry DB-failure test; scoped configuration tests | Configuration DB must be available for normal enrichment |
| LC-03 | Configured timeout, retries and breaker toggle were ignored by orchestration | High | `provider_http.py`, `provider_registry.py`, `provider_chain.py`, provider implementations | Effective per-request timeout, bounded transient retries/backoff, Retry-After, per-provider circuit toggle | Transport policy and circuit tests; configured runtime smoke | Breakers are explicitly process-local; no shared Redis health claim |
| LC-04 | Saved cache policy was unused; seven-day service default overrode global/category settings | High | `lifecycle_cache_repository.py`, `lifecycle_enrichment_service.py`, `provider_chain.py` | Per-category TTL from effective config; minimum TTL across consulted providers; legacy explicit programmatic override retained | Known/Unknown/Deprecated/Failure TTL tests, persisted TTL smoke | Request failures use failure TTL even if another provider returned a known result |
| LC-05 | Stale evidence could be rewritten with a new expiry indefinitely | High | `lifecycle_enrichment_service.py`, `settings.py` | Bounded stale grace after original expiry, no recaching stale evidence, original check date and refresh diagnostics retained | Existing stale/cache tests; expiry smoke | Grace defaults to seven days and is operator-configurable |
| LC-06 | Cache identity did not consistently include effective platform configuration/reference changes | High | `provider_config_service.py` | Policy-version/config/credential/reference/environment fingerprint for platform and tenant results | Scoped cache and credential tests | Old rows remain for retention/rollback; normal code cannot read old namespaces |
| LC-07 | GitHub credential editor stored a token unused at runtime | High | `repository_health_provider.py`, `provider_registry.py`, `provider_probe.py` | Effective owner's encrypted token used only for api.github.com; secure presence-only metadata | Header assertions, owner inheritance, sanitized failures | GitLab/Bitbucket authenticated/private repository support is not added |
| LC-08 | Editable arbitrary URLs and automatic redirects exposed network egress | High | `provider_http.py`, `provider_config_service.py`, `settings.py`, compose | HTTPS, no URL credentials/query/fragment; built-in or operator-approved hosts, DNS address checks, reject redirects, TLS/proxy defaults | Metadata/loopback/private DNS/redirect tests | DNS preflight is not socket-level address pinning; use controlled DNS and egress firewall/proxy for stronger isolation |
| LC-09 | Registry latest was labeled supported; a Xeol match could imply support | High | registry/deps.dev/Xeol providers, endoflife provider, vendor/feed providers | Unknown preserved without explicit support evidence; latest registry version stays release metadata; no unsupported-cycle patch advertised as supported | No-evidence Xeol tests, old package Unknown tests, known-cycle tests | Provider data remains subject to source correctness |
| LC-10 | Vendor skeleton and embedded RHEL table were represented as vendor integrations | High | `provider_registry.py`, `official_vendor_providers.py`, new capability/probe contracts | Skeleton excluded from configured runtime and reported unsupported; RHEL local reference labeled freshness-unverified and restricted to RHEL identities | Placeholder/static tests, matching tests | No new live official-vendor implementation or newly invented dates |
| LC-11 | Health existed without proof, including historical fake-success records | High | model, migration 079, config service, status tracker, router | Structured last verification, lookup timestamps, unknown initial health and historical reset; process scope exposed | Unverified-health regression; migration exercised on test PostgreSQL | Historical last-success dates retained as history, not displayed as proof of verified connection |
| LC-12 | Form exposed ignored JSON and blank endpoint fields; invalid JSON silently became `{}` | Medium | provider capabilities, form/settings/types | Backend-owned fields/defaults/source types; unsupported fields rejected; invalid draft retained with accessible feedback | Form and settings tests, TypeScript, ESLint, frontend build | No browser-driven visual/E2E run against a deployed application |
| LC-13 | Sync could acknowledge work no provider performed | Medium | config service, capability contract, settings component | Only Xeol DB exposes Reload cache; other providers return unsupported and have no action button | Sync and invalidation tests | Reload is inline and local to the receiving process; no job is claimed |
| LC-14 | Recommendation metadata could outrank known lifecycle evidence | High | `decision_engine.py`, vendor provider | Known evidence before Unknown hints, confidence before severity, high-confidence vendor handling, preserved manual precedence | Decision, enrichment and manual override tests | No inference of support from absence of vulnerabilities or release age |
| LC-15 | Refresh counts represented identity groups; manual statuses were omitted | Medium | `lifecycle_enrichment_service.py` | Count all affected components and include manual overrides; avoid double counting stale components | Duplicate-group summary regression and refresh/report tests | No unrelated report redesign |

## B. Provider matrix

“Verified live” below refers to read-only smoke calls made in this environment on 16 October 2026, not production health. Configuration rows are never declared healthy just because they exist.

| Provider | Configuration / effective source | Test I/O | Runtime and coverage | Credentials | Observed verification / limitations |
|---|---|---|---|---|---|
| endoflife.date | Built-in `https://endoflife.date/api`; runtime/probe use v1 product endpoint first, legacy fallback; approved HTTPS override allowed | Real Debian product lookup, cycle match and evidence fields | Mapped products, version/release and distro hints | None | Live HTTP 200; Debian 12 cycle/evidence matched. Actual component status derives from source dates, including EOS, not just EOL |
| deps.dev | Read-only `https://api.deps.dev/v3` | Real PyPI requests 2.31.0 GetVersion | npm, PyPI, Maven, Go, NuGet, Cargo metadata and recommendations | None | Live HTTP 200 and version match; no support claim inferred |
| OSV | Read-only `https://api.osv.dev/v1/query` | Real POST package/ecosystem/version query; empty vulnerability list is valid | Advisory recommendations only; lifecycle Unknown without other evidence | None | Live HTTP 200 and advisory match; lifecycle evidence false |
| Package Registry | Built-in npm, PyPI, NuGet, Maven Central, RubyGems endpoints | Representative real PyPI version lookup | Registry deprecation/yank and release metadata | No configurable registry credentials implemented | Live PyPI HTTP 200 and sample match; operational probe does not verify every ecosystem |
| Repository Health | Built-in GitHub/GitLab/Bitbucket public APIs | Real GitHub python/cpython metadata | Archived/disabled/activity signals, explicitly sourced; inactivity alone is not EOL | Optional encrypted `github_token`, used only with GitHub | Live unauthenticated GitHub HTTP 200. Authenticated owner/token behavior uses fixtures, not a user's live token |
| Xeol API | `https://edb-prod.xeol.io/eol/check`, or approved configured HTTPS endpoint | Authenticated POST using existing component contract; validated expected result | Existing Xeol parser, evidence-backed match/date/status handling | Encrypted `api_key`; existing platform environment fallback preserved | Fixture-tested; commercial endpoint/credentials not live-verified. Its current external contract remains an operator verification step |
| OpenEoX | Every configured feed URL, approved HTTPS hosts | Fetch/validate every feed; partial failure is degraded | OpenEoX-compatible JSON adapter and component matching, not a universal standards implementation | No feed credential mechanism added | Fixture-tested; no enterprise feed supplied. Validation does not claim a representative component match |
| Xeol DB | `config.db_path`, no unused URL editor | Read-only SQLite/JSON format verification and representative runtime lookup | Supported existing Xeol export layouts | None | Temporary SQLite fixture verified. Path/format/freshness depend on operator-provided file; cache reload is process-local |
| Custom Vendor Records | Active platform records plus existing approved environment records | Actual record retrieval and representative service match | Name/version/ecosystem curated evidence; audited platform CRUD | Platform permissions for record mutation | Local fixture verified; accuracy/freshness rests with reference maintainers |
| Red Hat Lifecycle | Embedded RHEL 7–9 table, source policy URL displayed | Local representative RHEL lookup | RHEL only; existing reference data retained, no live vendor request | None | Local verification only; reference freshness unverified; not an OpenShift/RHCOS lifecycle integration |
| Official Vendor Lifecycle | Existing skeleton | Unsupported capability result | Excluded from configured provider chain | Not applicable | Unknown / unimplemented; never reported as a successful live vendor connection |

The API contracts were checked against the primary [deps.dev v3 documentation](https://docs.deps.dev/api/v3/) and [OSV query documentation](https://google.github.io/osv.dev/post-v1-query/). Xeol's commercial contract could not be independently established from accessible vendor documentation; the existing repository contract was preserved and is explicitly unverified live.

## C. Files changed

All files are inside `/home/hcluser1/sbom_native/sbom`.

| Files | Purpose |
|---|---|
| `app/services/lifecycle/provider_probe.py` (new) | Provider-specific structured verification |
| `app/services/lifecycle/provider_http.py` (new) | Egress restrictions, safe diagnostics, effective timeout/retry policy |
| `app/services/lifecycle/provider_capabilities.py` (new) | Shared backend-owned source/field/action/default metadata |
| `app/services/lifecycle/provider_config_service.py` | Validation, verification persistence, truthful health/sync, config fingerprint |
| `app/services/lifecycle/provider_registry.py` | Runtime configuration, secure token wiring, fail-closed policy |
| `app/services/lifecycle/provider_chain.py` | Effective HTTP/circuit policies, selected-source provenance, outcomes and TTL policy |
| `app/services/lifecycle/provider_status.py` | Initial Unknown and scoped process-local circuit state |
| `app/services/lifecycle/lifecycle_cache_repository.py` | Effective category TTLs |
| `app/services/lifecycle/lifecycle_enrichment_service.py` | Cache retention, lookup persistence and accurate summaries |
| `app/services/lifecycle/decision_engine.py` | Evidence/confidence precedence |
| `app/services/lifecycle/endoflife_date_provider.py` | Shared transport and supported-cycle recommendations |
| `app/services/lifecycle/deps_dev_provider.py`, `osv_provider.py`, `package_registry_provider.py` | Shared transport; metadata/support separation; malformed response diagnostics |
| `app/services/lifecycle/repository_health_provider.py` | Shared transport and scoped GitHub authentication |
| `app/services/lifecycle/xeol_provider.py`, `xeol_db_provider.py` | Preserve Unknown without support evidence; avoid raw API payload persistence |
| `app/services/lifecycle/openeox_provider.py` | Lazy runtime feed fetch through shared policy, explicit status/date handling |
| `app/services/lifecycle/official_vendor_providers.py`, `vendor_lifecycle_provider.py` | Reference provenance, RHEL identity restriction, curator confidence/support metadata |
| `app/models.py`, `app/schemas_lifecycle_admin.py` | Additive verification fields and expanded API contracts |
| `app/routers/lifecycle.py` | Truthful aggregate Unknown/configuration-unavailable status |
| `app/settings.py`, `docker-compose.server.yml` | Operator-owned egress allowlist and bounded stale policy |
| `alembic/versions/079_lifecycle_provider_verification.py` (new) | Add fields and reset unproven health while preserving configuration/history/secrets |
| `frontend/src/components/admin/LifecycleProviderForm.tsx` | Meaningful provider fields, defaults, masked credential controls, draft validation |
| `frontend/src/components/admin/LifecycleProviderSettings.tsx` | Overview, detailed probes, local circuit state and supported reload action |
| `frontend/src/types/index.ts` | Capability/verification/runtime status interfaces |
| `tests/test_lifecycle_provider_verification.py` (new) | Deterministic probe/transport/policy/accuracy regression coverage |
| `tests/test_lifecycle_provider_e2e.py` (new) | Configured HTTP fixture through DB/report/cache expiry; tenant isolation |
| `tests/test_lifecycle_provider_admin.py`, `test_lifecycle_engine_v2.py`, `test_lifecycle_cache_upsert.py`, `test_lifecycle_enrichment.py`, `test_scoped_configuration.py` | Extended expectations, real fixture transports and preserved authorization |
| `frontend/src/components/admin/LifecycleProviderForm.test.tsx` (new), `LifecycleProviderSettings.test.tsx` | Draft validation, capabilities, safe secrets, probe rendering and invalidation |
| `tests/test_lifecycle_provider_live.py` (new) | Explicit opt-in live API → disposable PostgreSQL → report/cache test; excluded from normal CI |
| `scripts/lifecycle_provider_smoke.py` (new) | Explicit opt-in live checks; never reads/writes DB configuration |

## D. Validation

The comprehensive serial backend run passed **183 tests** (89 existing Pydantic/Alembic deprecation warnings), in **230.51 seconds**, with this exact command:

```bash
.venv/bin/python -m pytest tests/test_lifecycle_provider_verification.py tests/test_lifecycle_provider_admin.py tests/test_lifecycle_engine_v2.py tests/test_lifecycle_enrichment.py tests/test_lifecycle_cache_upsert.py tests/test_lifecycle_xeol_openeox.py tests/test_scoped_configuration.py tests/test_lifecycle_provider_e2e.py tests/test_fda_510k_excel_report.py -q
```

This includes FDA Excel lifecycle report/export regressions. Final follow-up checks below cover the last URL/request-attempt and blocked-network cache-expiry refinements. The prior comprehensive run had **177 passes and one failure** because an old assertion expected an EOL-cycle patch to be recommended as supported; the assertion now preserves `latest_version` while requiring no unsupported support/recommendation claim.

Frontend: **46 tests passed** in three files. TypeScript and targeted ESLint passed. The configured Next.js production build passed, including both lifecycle routes. Python Ruff and compileall checks and `git diff --check` passed.

Additional static verification commands executed:

```bash
.venv/bin/ruff check app/services/lifecycle app/routers/lifecycle.py app/schemas_lifecycle_admin.py tests/test_lifecycle_provider*.py scripts/lifecycle_provider_smoke.py
.venv/bin/python -m compileall -q app/services/lifecycle app/schemas_lifecycle_admin.py app/routers/lifecycle.py alembic/versions/079_lifecycle_provider_verification.py
git diff --check
```

Final follow-up results (overlapping suites, **not additive totals**):

| Command | Result |
|---|---|
| `.venv/bin/python -m pytest tests/test_lifecycle_provider_e2e.py tests/test_lifecycle_provider_verification.py tests/test_lifecycle_engine_v2.py tests/test_lifecycle_enrichment.py tests/test_lifecycle_cache_upsert.py -q` | **114 passed**, 122.51 s |
| `.venv/bin/python -m pytest tests/test_lifecycle_provider_verification.py tests/test_lifecycle_provider_admin.py tests/test_lifecycle_xeol_openeox.py -q` | **86 passed**, 95.11 s; includes final malformed URL, cached feed-error and evidence-parsing checks |
| `.venv/bin/python -m pytest tests/test_lifecycle_enrichment.py tests/test_lifecycle_cache_upsert.py -q` | **33 passed**, 42.79 s; includes explicit cache-hit/expiry/stale provenance |
| `LIFECYCLE_LIVE_SMOKE=1 .venv/bin/python -m pytest -m integration tests/test_lifecycle_provider_live.py -q` | **1 passed**, 6.17 s; real endoflife.date lookup → configured enrichment → disposable PostgreSQL component persistence → lifecycle report → cache reuse |

One earlier final follow-up had **58 passes and one failure**: the new blocked-network persistence assertion exposed negative in-memory product caching that concealed the outage on a later component. It was fixed by not memoizing failed product requests as no-match, preserving cached feed-load diagnostics, and preventing retained valid cache entries from receiving a new expiry. The 114-test and 86-test passing reruns supersede that run.

Normal backend tests use deterministic injected transports and the repository's disposable PostgreSQL test database (`sbom_analyser_test`). Do not run two pytest processes against this same database concurrently. An intermediate overlap was stopped after fixture truncation interfered; serial reruns supersede it. Intermediate failing runs also exposed missing fixture constructor fields, mock configuration handling and obsolete exact-evidence assertions; these were corrected without relaxing production checks.

Frontend validation commands, from `frontend`:

```bash
npm test -- --run src/components/admin/LifecycleProviderSettings.test.tsx src/components/admin/LifecycleProviderForm.test.tsx src/lib/lifecycle-invalidation.test.ts
npx tsc --noEmit
npx eslint src/components/admin/LifecycleProviderForm.tsx src/components/admin/LifecycleProviderSettings.tsx src/components/admin/LifecycleProviderForm.test.tsx
NEXT_PUBLIC_API_URL=http://localhost:8000 npm run build
```

The first `npm run build` (without a URL) failed at prerendering because the repository requires `NEXT_PUBLIC_API_URL`. The explicit local URL build passed. The URL was supplied only to the build command; no environment file was changed. Next's generated type-reference changes were removed from the patch.

Opt-in live commands executed:

```bash
DATABASE_URL=sqlite:///:memory: PYTHONPATH=. .venv/bin/python scripts/lifecycle_provider_smoke.py --live
DATABASE_URL=sqlite:///:memory: PYTHONPATH=. .venv/bin/python scripts/lifecycle_provider_smoke.py --live --provider repository_health
```

Both passed: five HTTP 200 responses, valid samples. No DB queries/settings writes occur in this script; the in-memory URL satisfies the application's import-time DB configuration requirement. An initial attempt without a DB URL stopped at import, before network I/O. Only the successful explicit-URL runs are considered live evidence.

## E. Migration and deployment runbook — not executed against production

1. Record current image tags and back up PostgreSQL, provider configuration exports, encrypted secret records, audit history and the encryption-key configuration using approved operational procedures. Keep secret material out of tickets/logs. Record existing lifecycle results and verification timestamps for an authorized test SBOM.
2. Review the new operator options: `LIFECYCLE_EGRESS_ALLOWED_HOSTS` (comma-separated exact HTTPS enterprise feed/API hosts, empty by default) and `LIFECYCLE_CACHE_MAX_STALE_DAYS` (default 7, zero disables expired retention). Public built-in API hosts need no allowlist entry. Existing custom public feeds now need operator approval. Link-local/metadata/loopback destinations are always prohibited. Verify controlled DNS, proxy policies and corporate CA settings; TLS verification stays enabled.
3. Preserve the existing `APP_SECRET_KEY`/supported secret-encryption environment. Do not rotate it as part of deployment. Configure provider credentials only through the existing authorized encrypted-secret API.
4. Set `SBOM_ANALYSER_VERSION` to the reviewed release tag in the deployment environment and build both matching images from the reviewed checkout; frontend needs the deployment's real `NEXT_PUBLIC_API_URL` and existing public build options. Example build commands, using operator-selected release tags:

   ```bash
   docker build -t sbom-analyser-backend:<release> .
   docker build --build-arg NEXT_PUBLIC_API_URL=https://<approved-api-host> -t sbom-analyser-frontend:<release> frontend
   ```

5. In the normal maintenance sequence, stop lifecycle-producing workers/beat and drain active enrichment requests before migrating. Use the repository's existing deployment environment with the **new backend image**, for example:

   ```bash
   docker compose --env-file .env.server -f docker-compose.server.yml run --rm migrate
   ```

   This invokes the existing `scripts/docker_migrate.py` and upgrades through revision `079_lifecycle_provider_verification`. Do not manually update production configuration rows. Migration adds nullable `last_probe_json` and `last_lookup_at`, resetting health to Unknown/Disabled without replacing admin settings, ciphertext, audit records or historical dates.
6. Start/recreate backend, worker, beat and frontend with the new reviewed image tags. Restart every worker to use the new egress/retry policy and clear process-local circuits/file caches. New cache fingerprints logically invalidate earlier results; there is no destructive cache purge or forced production refresh.
7. Open `/platform/configuration/lifecycle` under an authorized platform identity and the tenant route under an authorized tenant identity. Compare saved priorities/enabled states/endpoints, inheritance and credential presence with the pre-deployment export. Expect unverified health until genuine verification succeeds.
8. Test configured providers, checking sample/auth/coverage separately. Confirm Official Vendor is unsupported, Red Hat is local reference, absent feeds/files are not healthy, and only Xeol DB offers Reload cache. Verify no secrets appear in responses/logs.
9. Refresh an authorized test SBOM, compare normalized identities, persisted source/evidence/dates, reports and summaries before/after. Test expiry, blocked network behavior, manual overrides and a negative cross-tenant request. Review metrics/logs across workers; process-local circuit state may differ.

Rollback: stop producers, restore previous reviewed image tags and environment if needed. Prefer retaining the additive columns until rollback is assessed. Downgrade 079 only with the compatible old backend offline; it removes verification columns but does not restore false historical Healthy states. Cache fingerprints differ across versions: a rollback must prevent older code from reusing historical unsafe cache namespaces, using the approved backup/restore or reviewed cache migration procedure. Do not restore an old app's fake-success behavior as an acceptable final state. Preserve secrets/audit data and reverify afterward.

## F. Remaining risks / explicit boundaries

- No production deployment, production config comparison, production SBOM refresh or browser-driven deployed E2E was performed. Deterministic fixtures, the separate opt-in live API-to-test-DB run and the frontend build are the persistence/rendering evidence.
- Xeol commercial connectivity/authentication and enterprise feeds/files require the operator's actual credentials/sources; deterministic tests do not establish live external compatibility.
- Official Vendor remains explicitly unimplemented. Red Hat remains an embedded, source-linked reference with unverified freshness; no new lifecycle dates were introduced.
- Repository activity and vulnerability advisories are not lifecycle support evidence. Registry latest does not establish supported status. Probe success never asserts universal component coverage.
- Circuit health and local Xeol file-cache reload are per process. Persistent verification is shared DB data; runtime circuits are not distributed. Inherited tenant lookups may have only receiving-process timestamps because platform reference rows are not mutated by tenant activity.
- DNS destination checks are preflight checks, not connection-level IP pinning. Approved enterprise hosts should use controlled DNS and platform egress controls. Proxy/CA behavior is preserved through httpx defaults; no insecure TLS bypass was added.
- The complete application-wide test suite and all report export formats were not automatically assumed to pass; only commands/results listed here are evidence. Unrelated SBOM upload, vulnerability/VEX and reporting implementations were preserved.
