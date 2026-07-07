# SBOM Analyzer — Test Traceability

| | |
|---|---|
| **Doc ID** | SBOM-DOC-002-TST (companion to SBOM-DOC-002 Rev 0.1) |
| **Release Date** | 07-Jul-2026 |
| **Baseline** | 151 backend test files / 1,469 test functions + 75 frontend Vitest files (2026-07-06/07) |
| **Prepared By** | Feroze |

Mapping of design features to existing tests and verification gaps. Test types: unit, integration, API, snapshot, property-based (Hypothesis), performance (pytest-benchmark), security-marked, architectural (metric consistency, mutation invalidation, import-linter layering).

## 1. Test infrastructure and inventory

### 1.1 Infrastructure

- **pytest.ini**: `testpaths=tests`, `addopts=-ra --strict-markers`; markers: `snapshot`, `security` (<100 ms each), `bench` (pytest-benchmark, `-m bench`), `integration`, `property` (Hypothesis), `metric_consistency` ("gate on every PR"), `postgres` (needs `TEST_POSTGRES_DATABASE_URL`) (`pytest.ini:10–17`).
- **DB strategy** (`tests/conftest.py`): **PostgreSQL-first, truncation-based isolation — not SQLite, not transaction rollback.** Module import resolves `TEST_POSTGRES_DATABASE_URL`/`TEST_DATABASE_URL` → default `postgresql+psycopg://sbom:sbom@127.0.0.1:55439/sbom_analyser_test` (L55) and exports it as `DATABASE_URL` **before any `app.db` import** (L97). Safety guard: PG DB name must contain "test" (L65–75). `pytest_sessionstart` runs `alembic upgrade head` as a subprocess then truncates (L154–167); autouse fixture `_reset_postgres_database_before_test` re-`TRUNCATE … RESTART IDENTITY CASCADE`s all public tables except `alembic_version` before every test (L111–151, 224–228). SQLite temp-file path exists only as fallback when the resolved URL is non-Postgres (`app` fixture L185–221). Env pinned per test: `API_AUTH_MODE=none`, `API_RATE_LIMIT_ENABLED=false`, `NVD_ENABLED=false`, real tokens popped (L101–108, 239–269).
- **Fixtures**: session `app`, `client` (TestClient), `sample_sbom_dict`/`seeded_sbom` (fixture SBOM `tests/fixtures/sample_sbom.json`), `mock_external_sources` (L358) — monkeypatches `app.analysis.*_query_by_components*` coroutines with canned fakes (`tests/fixtures/canned_responses`), covering every source adapter via the registry; no respx/requests-mock by design (docstring L16–21).
- **Frontend runner**: Vitest (`frontend/package.json` scripts `test: vitest run`); `frontend/vitest.config.ts` — env `node` default, jsdom opt-in via `// @vitest-environment jsdom` pragma, `@` alias, setup `vitest.setup.ts`.

### 1.2 Counts

- Backend: **151 `test_*.py` files** (84 `tests/`, 29 `tests/ai/`, 15 `tests/nvd_mirror/`, 15 `tests/validation/`, 8 `tests/sources/`); **1,469 test functions** (`grep -rE "^\s*(async )?def test_"`). Snapshot JSONs: `tests/snapshots/` (5 files: analyze_sbom_{consolidated,github,nvd,osv}.json, post_sbom_analyze.json).
- Frontend: **75 `*.test.*` files** under `frontend/src` (unit/component/integration/axe).

## 2. Design-feature to test mapping

| Design area | Test files | Type | Verifies | Gaps |
|---|---|---|---|---|
| Parsing / ingestion / format | `test_sbom_format_detector.py`, `test_sbom_spdx_cyclonedx_conversion.py`, `test_large_sbom_upload_integrity.py`, `test_max_upload_size.py`, `test_sbom_upload_validation_persisted.py` | unit + API | detection, SPDX↔CDX conversion, 413 limits, integrity | — |
| Validation pipeline (ADR-0007) | `validation/` (15 files): `test_stage_{detect,ingress,integrity,ntia,security,semantic,signature}.py`, `test_pipeline.py`, `test_normalize.py`, `test_errors.py`, `test_integration_corpus.py` (+`expected_outcomes.json`), `test_coverage_bump.py` | unit/integration/corpus | 8-stage validator | signature stage flag is hard-off |
| Property-based | `validation/test_property_based.py` (marker `property`) | Hypothesis | validator invariants | only one property file; **hypothesis IS declared** (`pyproject.toml:50` `hypothesis>=6.156.1`; `requirements.txt:33` pinned `6.156.1`) — NOT undeclared |
| Perf/bench | `validation/test_perf.py` — p95 < 500 ms assertion + pytest-benchmark table (`-m bench`); `test_nvd_perf_guards.py` | perf | validation latency, NVD budget guards | `.benchmarks/` dir at repo root exists but is **empty** (no stored baselines) |
| Matching / version ranges / confidence | `sources/test_version_range.py`, `sources/test_nvd_version_range_integration.py`, `sources/test_match_confidence.py`, `test_match_confidence_integration.py`, `sources/test_nvd_applicability.py`, `sources/test_provider_applicability.py`, `sources/test_cpe_distro_routing.py`, `sources/test_distro_cpe.py`, `test_nvd_cpe_query.py`, `test_nvd_identifier_routing.py` | unit + integration | comparator semantics, applicability, distro CPE resolver, confidence scoring | — |
| Dedup / merge / normalization | `test_component_deduplication.py`, `test_stage9_normalization_dedup.py`, `test_component_extraction_reconciliation.py`, `test_component_identity_and_report.py` | unit/integration | canonical identity, dedup | — |
| Enrichment CVSS/EPSS/KEV | `test_metrics_exploitability.py`, `test_kev_cache_refresh.py`, `test_vex_enrichment.py`, `test_cve_*` (aggregator, clients, identifiers, resilience, service, router, phase4 regressions) | unit/API | EPSS/KEV caches, CVE modal aggregation, circuit breakers | — |
| Lifecycle | `test_lifecycle_engine_v2.py`, `test_lifecycle_enrichment.py`, `test_lifecycle_cache_upsert.py`, `test_lifecycle_xeol_openeox.py`, `test_lifecycle_provider_admin.py`, `test_sbom_lifecycle_remediation.py` | unit/API | providers, TTL upserts, admin CRUD | — |
| Source adapters (per source) | `test_sources_adapters.py`, `sources/test_nvd_rejection_logging.py`, `test_nvd_enrichment_service.py`, `test_nvd_source_uses_lookup_service.py`, `test_nvd_ssl_regression.py`, `test_source_cache_{osv,ghsa}_integration.py`, `test_source_response_cache.py`, `test_source_cache_force_refresh.py`, `test_source_cache_sweep.py`, `test_source_cache_integration.py` | unit/integration | adapter registry, per-source cache, sweeps | VulnDB has no dedicated adapter test file found (covered via aggregate suites) |
| Pipeline / orchestration / run states | `test_sboms_analyze_snapshot.py`, `test_analyze_endpoints_snapshot.py` (+`tests/snapshots/*.json`), `test_sboms_analyze_stream.py` (SSE), `test_run_finding_metrics.py`, `test_persist_*_regression.py` (confidence/reason/strategy/query-errors) | snapshot/API | JSON contracts, SSE stream, persisted columns | — |
| Celery tasks / beat | `nvd_mirror/test_tasks.py`, `test_kev_cache_refresh.py`, `test_source_cache_sweep.py`, `test_scheduling_service.py`, `test_schedule_resolver.py`, `test_schedules_api.py` | unit/API | mirror task, refresh/purge/sweep, schedule tick maths | no test spins a real broker (tasks invoked in-process) |
| NVD mirror | `nvd_mirror/` 15 files (api, cve_repository, domain, facade(+integration), health_endpoint, mappers, http adapter, observability, secrets_fernet, settings(+repository), sync_run_repository, tasks, use_cases) | unit/integration | hexagonal mirror slice | — |
| Auth / security / tenancy | `test_auth.py`, `test_auth_integration.py`, `test_hcl_iam_auth.py`, `test_rbac_permissions.py`, `test_tenant_isolation.py`, `test_500_no_leak.py`, `test_dashboard_scoping.py`, `validation/test_security.py` (marker `security`) | API/security | bearer/JWT/OIDC, RBAC, tenant scoping, error-leak | — |
| Audit | audit assertions embedded (e.g. FDA export audit write `app/routers/reports.py:102`); no standalone `test_audit*.py` found (searched `tests/test_audit*`) | — | — | **gap: no dedicated audit-log suite** |
| Metrics / dashboard | `test_metric_consistency.py` (I1–I12 + 2 architectural), `test_dashboard_manager_metrics.py`, `test_dashboard_trend.py`, `test_dashboard_v2.py`, `test_dashboard_v4_metrics.py`, `test_dashboard_scoping.py`, `test_run_finding_metrics.py`, `test_risk_score_v2.py` | architectural/API | reconciliation invariants, tiles | — |
| Exports | `test_fda_510k_excel_report.py`, `test_sbom_vulnerability_excel_report.py`, `test_match_strategy_export.py`, `test_sbom_validation_report_endpoint.py` | API/unit | FDA workbook, vulnerability xlsx, CSV/SARIF strategy columns | no dedicated PDF-content test found |
| DB / migrations | `test_migration_drift.py`, `test_sqlite_postgres_migration.py`, `test_postgresql_integration.py` (marker `postgres`), `test_database_configuration.py`, `test_connection_pool_fix.py`, `test_soft_delete.py` | integration | alembic drift, SQLite→PG migration, pool | — |
| Compare | `test_compare_router.py`, `test_compare_service.py`, `test_compare_v1_deprecation.py`; FE `frontend/src/components/compare/**` (12+ files) | API/unit/FE | diff math, export, deprecation | — |
| AI fixes | `tests/ai/` 29 files (router, batch pipeline/load, catalog/estimator, config loader, cost/budget, credentials router, fix generator, grounding, limiter, env→DB migration, providers incl. sarvam, observability, parse, phase5 e2e scenarios, progress, prompts/cache, registry, rollout, schemas(+lenient), scope/multi-batch, secret cipher, telemetry, test-connection, usage router, real-provider smoke) | unit/API/e2e-ish | full AI subsystem | `test_real_provider_smoke.py` implies opt-in live calls |
| Frontend unit/component | 75 files: dashboard (SeverityChart, managerWidgets, LifecycleHealthTiles, HeroPostureCard, FindingsTrendChart, RemediationPanel, WhatsNewStrip), analysis tables (matchReason/matchConfidence/selection, RunsTable.status), sboms (upload repair, conversion, detail, ValidationRepairWorkspace), compare suite, CveDetailDialog suite (12 files incl. axe), settings/ai (axe + dialogs), `__tests__/auth.test.ts` | Vitest unit/component/integration/a11y(axe) | rendering, hooks, status mapping | — |
| FE architectural | `frontend/src/__tests__/mutation-invalidation.test.ts` — scans all non-test `.ts/.tsx` for `useMutation` without `invalidateQueries`/`setQueryData`/`refetchQueries`/`invalidate*(` helper and without `// @no-invalidation-needed` escape (per CLAUDE.md) | architectural | cache-invalidation convention (D1–D8 audit lock) | — |
| BE architectural | `test_metric_consistency.py` (above) + **import-linter**: 3 contracts in `pyproject.toml:86–127` (parsing ⛔ routers/main; validation ⛔ routers/main/services/db/models; validation ⛔ requests/httpx/urllib) ; `.import_linter_cache/` present at root | architectural | layering | import-linter not wired into pytest — separate `lint-imports` invocation, no CI file found |
| e2e (browser) | — | — | — | **Not implemented — no evidence found**: searched `playwright`, `cypress`, `e2e` dirs repo-wide (excl. node_modules), none |

## 3. Test-only dependencies — declaration status

| Package | pyproject `[dev]` | requirements.txt | Status |
|---|---|---|---|
| pytest 9.1.1 | ✔ (L47) | ✔ (L65) | declared |
| pytest-asyncio 1.4.0 | ✔ | ✔ | declared |
| pytest-benchmark 5.2.3 | ✔ (L49) | ✔ (L64) | declared |
| **hypothesis 6.156.1** | ✔ (L50) | ✔ (L33) | **declared** (question in brief answered: not undeclared) |
| import-linter ≥2.0 | ✔ (L54) | — (not in requirements.txt grep) | declared in dev extras only |
| ruff / mypy | ✔ (L52–53) | — | dev extras |
| `httpx2>=2.5.0` | ✔ (L51) | — | suspicious name (httpx is already a runtime dep at L20) — possible typo'd/nonexistent package |
| FE: vitest, @testing-library, axe | `frontend/package.json` devDependencies | n/a | declared |

## 4. CI vs local execution

**No CI pipeline in repo — no `.github/`, no GitLab/Jenkins files found.** Evidence of intended flow: `pytest -m metric_consistency` "on every PR" (`tests/test_metric_consistency.py:7`), `pytest -m bench` for benchmarks (`tests/validation/test_perf.py:1–3`, "stats table in the CI log"), `postgres` marker gated on `TEST_POSTGRES_DATABASE_URL`. Local helpers: `scripts/bootstrap.sh|.ps1`, `scripts/celery_worker.sh`, `scripts/celery_beat.sh`, `scripts/check_database.py`, `scripts/migrate_sqlite_to_postgres.py`, `scripts/migrate_env_to_db.py`, `scripts/generate_encryption_key.py`. `backend-test-final.txt` is a 3-line truncated capture of a pytest run against Postgres (`alembic … PostgresqlImpl`, dot-progress to ~4% with one `F`) — no summary line, so it evidences *how* tests run (Postgres + alembic head) but not a full pass.

---

## 5. Verification gaps summary

The mapping above shows breadth; the following areas are **not** fully verified (a single passing test does not constitute full verification, and several areas have no tests at all):

- **No CI pipeline** — every gate (pytest markers "gate on every PR", vitest, ruff/mypy, import-linter) is local-run convention only (OQ-040).
- **No browser end-to-end tests** (Playwright/Cypress absent) and no visual-regression tooling (OQ-041).
- **No dedicated audit-log test suite**; audit writes asserted only incidentally. No PDF-content assertion test (OQ-037).
- **VulnDB adapter** is covered only by mocked aggregate suites; behaviour against the live VulDB v3 API is unverified (OQ-012).
- **Celery**: tasks are invoked in-process by tests; no test exercises a real broker, acks/redelivery semantics, or beat scheduling end-to-end (OQ-033).
- **Zombie-run handling and run cancellation** have no tests because the features do not exist (OQ-027, OQ-029).
- **SSE client authentication** paths are untested against an auth-enabled backend (OQ-030).
- **Performance**: `.benchmarks/` is empty (no stored baselines); the only latency assertion is validation p95 < 500 ms (OQ-008).
- **Latest full-suite status unknown**: `backend-test-final.txt` is a truncated 3-line capture showing at least one failing test without identification (OQ-048).
- **Signature verification stage** is a stub behind a hard-off constant; its tests only lock the stub behaviour.
