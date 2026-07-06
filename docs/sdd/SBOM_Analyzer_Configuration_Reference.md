# SBOM Analyzer — Configuration Reference

| | |
|---|---|
| **Doc ID** | SBOM-DOC-002-CFG (companion to SBOM-DOC-002 Rev 0.1) |
| **Release Date** | 07-Jul-2026 |
| **Baseline** | Repository 2026-07-06/07 · `app/settings.py` + side channels |
| **Prepared By** | Feroze |

Environment variables, feature flags, configuration consumers and restart requirements. **No secret values appear in this document** — variable names only; all values `<REDACTED>`. Legend — Consumer: A=API, W=Celery worker, B=Celery beat, F=Frontend, AL=Alembic, DC=docker-compose, T=tests. Restart: R=process restart required (cached at startup/import), req=read per request/call (no restart), build=frontend build-time. Class: S=secret, C=config, P=public (NEXT_PUBLIC values ship in the JS bundle).

Known completeness gaps (tracked as OQ-021, OQ-009): `.env.example` omits `AI_CONFIG_ENCRYPTION_KEY` and `NVD_MIRROR_FERNET_KEY`; `AWS_S3_BUCKET`/`AWS_S3_ENDPOINT_URL` are declared but have no code consumer.

## 1. Configuration sources and reading semantics

### 1.1 Where configuration lives

| Layer | File | Mechanism |
|---|---|---|
| Canonical settings | `app/settings.py` — `class Settings(BaseSettings)` (L31), `get_settings()` singleton (L728), `reset_settings()` (L744) | pydantic-settings; `env_file=".env"`, `case_sensitive=False`, `extra="ignore"` (L557–567). Cached singleton ⇒ env changes need **process restart** unless noted. |
| Analysis-engine knobs | `app/analysis.py` — `get_analysis_settings()` `@lru_cache(maxsize=1)` (L586–616); VulnDB block (L1238–1245) | direct `os.getenv` via `_env_str/_env_int/_env_float/_env_bool_top` (L547–583). Cached per process. |
| NVD mirror | `app/nvd_mirror/settings.py` (L96–118) | direct `os.getenv`, evaluated when settings are built (worker task path). |
| Per-request env reads | `app/auth.py:28–32` (`API_AUTH_MODE`, `API_AUTH_TOKENS`), `app/sources/applicability.py:249` | `os.getenv` at call time — **no restart needed**. |
| Module-import constants | `app/sources/epss.py:36–39`, `app/sources/kev.py:41–47`, `app/idempotency.py:22–26`, `app/http_client.py:37–48`, `app/rate_limit.py:20–29`, `app/logger.py:107–111`, `run.py:30–32`, `app/db.py:35–74` | read at import/startup ⇒ restart required. |
| Hard constants (not env) | `app/settings.py` L661–713: `NVD_API`, `GITHUB_GRAPHQL`, `OSV_API`, `VULNDB_API`, `OSV_MAX_BATCH=1000`, `MAX_UPLOAD_BYTES=50 MiB` (ADR-0007 §4.1), `MAX_DECOMPRESSED_BYTES=200 MiB`, `MAX_DECOMPRESSION_RATIO=100`, `SBOM_SYNC_VALIDATION_BYTES=5 MiB`, `SBOM_SIGNATURE_VERIFICATION=False`, `SBOM_WORKSPACE_STORAGE_DIR="./data/sbom-workspaces"`, `SBOM_*` editor/paste/patch limits, `DEFAULT_RESULTS_PER_PAGE=20`, `APP_VERSION="2.0.0"`. `app/services/sbom/workspace_storage.py:17–27` allows env override of the `SBOM_*` workspace constants by the same names. |
| Frontend | `frontend/.env.local.example`; consumed in `frontend/src/**` | `NEXT_PUBLIC_*` inlined at **build time** (Next.js) — rebuild required. |
| Alembic | `alembic/env.py:30` `get_url()` | `DATABASE_URL` env, falling back to `app.db.DATABASE_URL`; loads `.env` via `python-dotenv` (L8–12). |
| Celery | `app/workers/celery_app.py:29–48` | broker/backend = `CELERY_BROKER_URL` or `REDIS_URL` via `get_settings()`. |

`.env` (real, present at repo root) — variable **names only**, all values `<REDACTED>`: `NVD_API_KEY`, `GITHUB_TOKEN`, `VULNDB_API_KEY`, `ANALYSIS_SOURCES`, `CORS_ORIGINS`, `API_AUTH_MODE`, `HOST`, `PORT`, `DATABASE_URL`, `ANALYSIS_LEGACY_LEVEL`, `LOG_LEVEL`, `LOG_FORMAT`, `AI_FIXES_ENABLED`, `AI_FIXES_UI_CONFIG_ENABLED`, **`AI_CONFIG_ENCRYPTION_KEY`** (the only name in `.env` absent from `.env.example`).
Frontend `frontend/.env.local` (names only): `NEXT_PUBLIC_API_URL`.

## 2. Master variable table

Legend — Consumer: **A**=API, **W**=Celery worker, **B**=Celery beat, **F**=Frontend, **AL**=Alembic, **DC**=docker-compose only, **T**=tests. Restart: **R**=process restart (cached at startup/import), **req**=read per request/call, **build**=FE build-time. Class: **S**=secret, **C**=config, **P**=public.

#### Database / Redis / Celery

| Variable | Purpose | Type | Mandatory? | Default | Consumer | Restart | Class | Missing behavior |
|---|---|---|---|---|---|---|---|---|
| `DATABASE_URL` | SQLAlchemy URL (`postgresql+psycopg://` or `sqlite:///`) | str | **Yes (effective)** | `""` | A,W,B,AL,T | R | S (embeds password) | `app/db.py:66–70` raises `RuntimeError` at import unless `ALLOW_SQLITE=true`; PG URL without password refused (L41–42) |
| `ALLOW_SQLITE` | Permit SQLite fallback `sbom_api.db` beside repo root | bool | No | `false` | A,W,AL | R | C | fallback disabled |
| `DATABASE_POOL_SIZE` / `DATABASE_MAX_OVERFLOW` / `DATABASE_POOL_TIMEOUT` / `DATABASE_POOL_RECYCLE` | Settings-side PG pool (`app/settings.py:80–85`) | int | No | 5 / 10 / 30 / 1800 | A,W | R | C | defaults |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` / `DB_POOL_TIMEOUT` / `DB_POOL_RECYCLE` / `DB_POOL_PRE_PING` | env-based PG pool (`app/settings.py:87–95`; used by `app/db.py::engine_options`) | int/bool | No | 20 / 20 / 30 / 1800 / true | A,W | R | C | defaults |
| `POSTGRES_USER/PASSWORD/DB/HOST/PORT` | compose-side PG bootstrap (`.env.example`) | str/int | No | sbom/sbom/sbom_analyser/localhost/55439 | DC | n/a | S (password) | compose defaults |
| `REDIS_URL` | Celery broker+result backend | str | Yes for async paths | `redis://localhost:6379/0` (`app/settings.py:225`) | A(enqueue),W,B | R | C (S if password in URL) | default localhost; Celery unusable if unreachable |
| `CELERY_BROKER_URL` | Broker override | str | No | `""` → falls back to `REDIS_URL` (`app/workers/celery_app.py:29–34`) | W,B | R | C | uses `REDIS_URL` |

#### Server / CORS / logging / upload

| Variable | Purpose | Type | Mand.? | Default | Consumer | Restart | Class | Missing |
|---|---|---|---|---|---|---|---|---|
| `HOST` / `PORT` / `RELOAD` | uvicorn bind (`run.py:30–32`, `app/settings.py:71–73`) | str/int/bool | No | `0.0.0.0` / 8000 / false | A | R | C/P | defaults |
| `CORS_ORIGINS` | comma list of allowed origins (`app/settings.py:68`, validator L581) | str | No | `*` | A | R | C | `*` (dev-open) |
| `LOG_LEVEL` / `LOG_FORMAT` / `LOG_FILE` / `LOG_MAX_MB` / `LOG_BACKUPS` | logging setup (`app/logger.py:107–111`; also Settings L550–554) | str/int | No | INFO / text / "" / 10 / 5 | A,W,B | R | C | console text INFO |
| Upload limits | **not env** — constants `MAX_UPLOAD_BYTES=50 MiB`, `MAX_DECOMPRESSED_BYTES`, `MAX_DECOMPRESSION_RATIO`, `SBOM_SYNC_VALIDATION_BYTES` (`app/settings.py:677–693`) | — | — | — | A | code change | C | — |
| `SBOM_WORKSPACE_STORAGE_DIR`, `SBOM_SMALL_FILE_MAX_BYTES`, `SBOM_FULL_EDITOR_MAX_LINES`, `SBOM_CONTENT_CHUNK_SIZE_BYTES`, `SBOM_LINE_PAGE_SIZE`, `SBOM_MAX_PASTE_BYTES`, `SBOM_REPAIR_MAX_PATCH_BYTES`, `SBOM_SEARCH_MAX_RESULTS` | repair-workspace storage knobs; env override of constants (`app/services/sbom/workspace_storage.py:17–27`) | str/int | No | constants at `app/settings.py:700–707` | A,W | req (read per use) | C | constants |

#### Auth (HCL IAM / legacy bearer / JWT) + secrets

| Variable | Purpose | Type | Mand.? | Default | Consumer | Restart | Class | Missing |
|---|---|---|---|---|---|---|---|---|
| `AUTH_ENABLED` | require HCL IAM OIDC (`app/settings.py:203`) | bool | No | `false` | A | R | C | dev mode: synthetic admin context |
| `HCL_IAM_ISSUER` / `HCL_IAM_AUDIENCE` / `HCL_IAM_JWKS_URL` / `HCL_IAM_CLIENT_ID` | OIDC validation (`app/settings.py:204–207`) | str | **Yes when AUTH_ENABLED=true** | `""` | A | R | C | `.env.example`: "server refuses to start if missing"; JWKS URL must be https (`app/core/security.py:345`) |
| `HCL_IAM_ALLOWED_ALGORITHMS` / `HCL_IAM_ROLE_CLAIM` / `HCL_IAM_TENANT_CLAIM` | JWT algs & claims (L208–210) | str | No | RS256 / roles / tenant_id | A | R | C | defaults |
| `HCL_IAM_JWKS_CACHE_SECONDS` / `AUTH_CONTEXT_CACHE_SECONDS` | JWKS & auth-context cache TTLs (L211–217) | int | No | 300 / 120 | A | R | C | defaults |
| `DEV_DEFAULT_TENANT` / `DEFAULT_TENANT_SLUG` | dev tenant auto-select (L218–222) | bool/str | No | true / `default` | A | R | C | defaults |
| `API_AUTH_MODE` | legacy gate: none\|bearer\|jwt (`app/auth.py:28`) | str | No | `none` | A | **req** | C | none; unknown value → HTTP error (`app/auth.py:99`) |
| `API_AUTH_TOKENS` | bearer allowlist, comma-sep (`app/auth.py:32`) | str | Yes when mode=bearer | `""` | A | **req** | S | all bearer requests rejected |
| `JWT_SECRET_KEY` / `JWT_ALGORITHM` / `JWT_AUDIENCE` / `JWT_ISSUER` | HS256 validation (`app/settings.py:196–199`, `app/auth.py:61`) | str | KEY required when mode=jwt | "" / HS256 / "" / "" | A | R | S/C | JWT auth fails |
| `AI_CONFIG_ENCRYPTION_KEY` | Fernet key for DB-stored AI credentials (`app/security/secrets.py:69` `ENV_VAR`) | str(b64) | Yes for AI credential storage | — | A,W | R | **S** | encrypt/decrypt of stored credentials fails |
| `APP_SECRET_KEY` / `SETTINGS_SECRET_KEY` | alternate cipher keys for lifecycle provider secrets — `SECRET_ENV_CANDIDATES=("APP_SECRET_KEY","SETTINGS_SECRET_KEY","AI_CONFIG_ENCRYPTION_KEY","JWT_SECRET_KEY")` (`app/services/lifecycle/secret_service.py:15–20`) | str | one of the four | — | A,W | R | **S** | error: "Set APP_SECRET_KEY, SETTINGS_SECRET_KEY, or AI_CONFIG_ENCRYPTION_KEY" (L50) |
| `NVD_MIRROR_FERNET_KEY` | Fernet key for mirror-stored NVD API key (`app/nvd_mirror/adapters/secrets.py:50`) | str | when mirror stores key | — | W | per-task | **S** | mirror secret ops fail |

#### Rate limiting / idempotency / shared HTTP client

| Variable | Purpose | Type | Mand.? | Default | Consumer | Restart | Class | Missing |
|---|---|---|---|---|---|---|---|---|
| `API_RATE_LIMIT_ENABLED` | slowapi on/off (`app/rate_limit.py:20`) | bool | No | true | A | R | C | enabled |
| `API_RATE_LIMIT_DEFAULT` | default bucket (L25) | str | No | `300/minute` | A | R | C | default |
| `API_RATE_LIMIT_ANALYZE` | stricter analyze bucket (L29) | str | No | `15/minute` | A | R | C | default |
| `API_IDEMPOTENCY_ENABLED` / `API_IDEMPOTENCY_TTL_SECONDS` | Idempotency-Key cache (`app/idempotency.py:22–26`) | bool/int | No | true / 86400 | A | R (module-level) | C | defaults |
| `HTTPX_MAX_CONNECTIONS` / `HTTPX_MAX_KEEPALIVE` / `HTTPX_TIMEOUT_SECONDS` / `HTTPX_HTTP2` | shared outbound client (`app/http_client.py:37–48`) | int/float/bool | No | 100 / 20 / 60 / off | A,W | R | C | defaults |
| `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` | CA bundle override for NVD client (`app/services/nvd_client.py:49`) | path | No | certifi | A,W | req | C | certifi |

#### NVD enrichment (Settings block, `app/settings.py:40–57`)

| Variable | Purpose | Type | Mand.? | Default | Consumer | Restart | Class | Missing |
|---|---|---|---|---|---|---|---|---|
| `NVD_API_KEY` | NVD rate-limit key | str | No (recommended) | `""` | A,W | R | **S** | unauth throttle (5 req/30 s) |
| `NVD_ENABLED` | enable optional NVD enrichment | bool | No | true | A,W | R | C | enrichment on |
| `NVD_BASE_URL` | CVE API 2.0 endpoint | str | No | services.nvd.nist.gov… | A,W | R | C | default |
| `NVD_CONNECT_TIMEOUT_SECONDS` / `NVD_READ_TIMEOUT_SECONDS` | timeouts | float | No | 5.0 / 20.0 | A,W | R | C | defaults |
| `NVD_FAILURE_THRESHOLD` | circuit threshold | int | No | 3 | A,W | R | C | default |
| `NVD_MAX_CPE_LOOKUPS_PER_SCAN` / `NVD_MAX_CVE_BATCHES_PER_SCAN` / `NVD_CVE_BATCH_SIZE` | per-scan budget | int | No | 10 / 3 / 100 | W | R | C | defaults |
| `NVD_FAILURE_CACHE_TTL_MINUTES` / `NVD_SUCCESS_CACHE_TTL_HOURS` / `NVD_NO_RESULT_CACHE_TTL_HOURS` | NVD cache TTLs | int | No | 60 / 24 / 24 | A,W | R | C | defaults |
| `NVD_MIN_DELAY_WITHOUT_API_KEY_SECONDS` / `NVD_MIN_DELAY_WITH_API_KEY_SECONDS` | pacing | float | No | 6.0 / 1.0 | A,W | R | C | defaults |
| `NVD_BACKGROUND_ENRICHMENT` | enrich in background | bool | No | true | W | R | C | default |

#### Analysis engine (`app/analysis.py::get_analysis_settings`, L586–616 — lru_cached)

| Variable | Purpose | Default | Consumer | Class |
|---|---|---|---|---|
| `ANALYSIS_SOURCES` | comma list NVD,OSV,GITHUB,VULNDB (`app/settings.py:62`) | `NVD,OSV,GITHUB` | A,W | C |
| `ANALYSIS_LEGACY_LEVEL` | legacy analysis level, coerced ≥1 (`app/settings.py:98`, validator L599) | 1 | A,W | C |
| `ANALYSIS_SOURCE_NAME` / `ANALYSIS_HTTP_USER_AGENT` | source label / UA | `NVD` / `SBOM-Analyzer/enterprise-2.0` | A,W | C |
| `NVD_API_BASE_URL` / `NVD_DETAIL_BASE_URL` / `NVD_API_KEY_ENV` | endpoints & key indirection | NVD URLs / `NVD_API_KEY` | A,W | C |
| `NVD_RESULTS_PER_PAGE` / `NVD_REQUEST_TIMEOUT_SECONDS` / `NVD_MAX_RETRIES` / `NVD_RETRY_BACKOFF_SECONDS` | paging/retry | 2000 / 60 / 3 / 1.5 | A,W | C |
| `NVD_REQUEST_DELAY_WITH_KEY_SECONDS` / `NVD_REQUEST_DELAY_WITHOUT_KEY_SECONDS` / `NVD_CONCURRENCY_WITH_KEY` / `NVD_CONCURRENCY_WITHOUT_KEY` | pacing/concurrency | 0.6 / 6.0 / 10 / 2 | A,W | C |
| `NVD_KEYWORD_RESULTS_LIMIT` / `NVD_KEYWORD_FALLBACK_ENABLED` / `NVD_MAX_PAGES_PER_QUERY` / `NVD_MAX_TOTAL_RESULTS_PER_QUERY` | keyword fallback caps | 5 / true / 3 / 500 | A,W | C |
| `CVSS_CRITICAL_THRESHOLD` / `CVSS_HIGH_THRESHOLD` / `CVSS_MEDIUM_THRESHOLD` | severity cutoffs | 9.0 / 7.0 / 4.0 | A,W | C |
| `ANALYSIS_MAX_FINDINGS_PER_CPE` / `ANALYSIS_MAX_FINDINGS_TOTAL` | result caps | 5000 / 50000 | A,W | C |
| `NVD_REJECTION_DETAIL_LOGGING` | DEBUG per-candidate rejection logs (L615, L130) | false | A,W | C |
| `APPSEC_APPLICABILITY_DIAGNOSTICS` | applicability diagnostics (`app/sources/applicability.py:249`, per-call) | off | A,W | C |

#### GitHub / VulnDB / OSV

| Variable | Purpose | Default | Consumer | Class | Missing |
|---|---|---|---|---|---|
| `GITHUB_TOKEN` | GHSA GraphQL token (`app/settings.py:58`; override plumbed per-request, `app/analysis.py:1875–1877`) | `""` | A,W | **S** | GHSA source unusable/degraded |
| `VULNDB_API_KEY` | VulDB key (`app/settings.py:59`; `app/sources/vulndb.py:194`) | `""` | A,W | **S** | VulDB-only analysis → HTTP 400 (`app/routers/analyze_endpoints.py:472`) |
| `VULNDB_API_BASE_URL` / `VULNDB_API_KEY_ENV` / `VULNDB_API_VERSION` / `VULNDB_LIMIT` / `VULNDB_DETAILS` / `VULNDB_REQUEST_TIMEOUT_SECONDS` / `VULNDB_REQUEST_DELAY_SECONDS` / `VULNDB_MAX_COMPONENTS` | VulDB knobs (`app/analysis.py:1238–1245`) | vuldb.com / VULNDB_API_KEY / 3 / 5 / false / 30 / 0.0 / 100 | A,W | C | defaults |
| OSV | no env — constants `Settings.OSV_API`, `OSV_MAX_BATCH=1000` (`app/settings.py:667–673`) | — | A,W | C | — |

#### EPSS / KEV (module-level, `app/sources/epss.py:36–39`, `app/sources/kev.py:41–47`)

| Variable | Purpose | Default | Consumer | Restart | Class |
|---|---|---|---|---|---|
| `EPSS_API_URL` | FIRST EPSS API | `https://api.first.org/data/v1/epss` | A,W | R | C |
| `EPSS_TTL_SECONDS` / `EPSS_HTTP_TIMEOUT` / `EPSS_BATCH_SIZE` | cache TTL / timeout / batch | 86400 / 20 / 100 | A,W | R | C |
| `KEV_FEED_URL` | CISA KEV JSON feed | CISA URL (kev.py:41) | A,W,B(refresh task) | R | C |
| `KEV_TTL_SECONDS` / `KEV_HTTP_TIMEOUT` / `KEV_FAILURE_RETRY_SECONDS` | TTL / timeout / failure retry | 86400 / 30 / 300 | A,W | R | C |

#### CVE detail modal (`app/settings.py:238–293`)

`CVE_MODAL_ENABLED` (bool, default true — kill switch for in-app modal), `CVE_SOURCES_ENABLED` (default `osv,ghsa,nvd,epss,kev`; validated whitelist L639–645), `CVE_CACHE_TTL_KEV_SECONDS` (21600), `CVE_CACHE_TTL_RECENT_SECONDS` (86400), `CVE_CACHE_TTL_STABLE_SECONDS` (604800), `CVE_CACHE_TTL_ERROR_SECONDS` (900), `CVE_RECENT_WINDOW_DAYS` (90), `CVE_HTTP_CONNECT_TIMEOUT` (3.0), `CVE_HTTP_READ_TIMEOUT` (5.0), `CVE_HTTP_RETRIES` (2), `CVE_CIRCUIT_BREAKER_THRESHOLD` (5), `CVE_CIRCUIT_BREAKER_RESET_SECONDS` (60), `CVE_NVD_UNAUTH_THROTTLE_SECONDS` (6.0), `CVE_NVD_AUTH_THROTTLE_SECONDS` (0.6). All config-class, defaults apply when missing; consumed by A + W (cve_refresh tasks); restart R.

#### Lifecycle providers (`app/settings.py:102–159`)

`LIFECYCLE_PROVIDER_TIMEOUT_SECONDS` (5.0), `LIFECYCLE_PROVIDER_MAX_CONCURRENT` (3), `LIFECYCLE_XEOL_ENABLED` (false; auto-on when key set), `LIFECYCLE_XEOL_API_URL` (edb-prod.xeol.io), `LIFECYCLE_XEOL_API_KEY` (**S**, None), `LIFECYCLE_VENDOR_RECORDS_JSON` (`[]`), `OPENEOX_ENABLED` (false), `OPENEOX_FEED_URLS` (`""`), `XEOL_ENABLED` (false), `XEOL_DB_PATH` (None), `XEOL_CLI_PATH` (None — sync jobs only), `LIFECYCLE_CACHE_TTL_KNOWN_DAYS` (14), `LIFECYCLE_CACHE_TTL_UNKNOWN_HOURS` (24), `LIFECYCLE_CACHE_TTL_PROVIDER_FAILURE_MINUTES` (30), `LIFECYCLE_CACHE_TTL_DEPRECATED_DAYS` (7), `LIFECYCLE_EOL_SOON_DAYS` (90), `LIFECYCLE_EOS_SOON_DAYS` (90), `LIFECYCLE_PROVIDER_FAILURE_THRESHOLD` (3), `LIFECYCLE_PROVIDER_CIRCUIT_COOLDOWN_MINUTES` (15). Consumers A+W; restart R; all C except the API key (S).

#### NVD mirror (`app/nvd_mirror/settings.py:96–118`)

`NVD_MIRROR_ENABLED` (false), `NVD_MIRROR_API_ENDPOINT`, `NVD_MIRROR_API_KEY_ENV_VAR` (default `NVD_API_KEY` — indirection), `NVD_MIRROR_FERNET_KEY_ENV_VAR` (default `NVD_MIRROR_FERNET_KEY`), `NVD_MIRROR_DOWNLOAD_FEEDS_ENABLED` (false), `NVD_MIRROR_PAGE_SIZE` (2000, max 2000), `NVD_MIRROR_WINDOW_DAYS` (119, max 119), `NVD_MIRROR_MIN_FRESHNESS_HOURS` (24). Consumer W/B (`nvd_mirror.mirror_nvd` beat task); read per task build — effectively no API restart.

#### Compare v2 (`app/settings.py:357–372`)

`COMPARE_V1_FALLBACK` (false — kill switch; must ALSO be set as `NEXT_PUBLIC_COMPARE_V1_FALLBACK` on FE, echoed by `GET /health`), `COMPARE_LICENSE_HASH_ENABLED` (false — hard guard on stubbed change_kinds, ADR-0008 §10), `COMPARE_STREAMING_THRESHOLD` (5000 rows → switch to SSE), `COMPARE_CACHE_TTL_SECONDS` (86400; invalidated on reanalysis via Celery hook).

#### AI fix generation (`app/settings.py:391–547`)

| Variable | Purpose | Default | Class |
|---|---|---|---|
| `AI_FIXES_ENABLED` | master flag | false (`.env.example` sets true) | C |
| `AI_FIXES_KILL_SWITCH` | reject every AI call at registry | false | C |
| `AI_FIXES_UI_CONFIG_ENABLED` | Settings→AI UI + DB-backed credentials primary | false (`.env.example` true) | C |
| `AI_DEFAULT_PROVIDER` | provider when unspecified | `anthropic` | C |
| `AI_PROVIDERS` | providers to wire | `anthropic,openai,gemini,grok,sarvam,ollama,vllm,custom_openai` | C |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY` / `GROK_API_KEY` / `SARVAM_API_KEY` / `VLLM_API_KEY` / `AI_CUSTOM_OPENAI_API_KEY` | provider credentials | "" / "" / "" / "" / "" / `EMPTY` / `EMPTY` | **S** |
| `AI_ANTHROPIC_MODEL`=claude-sonnet-4-5, `AI_OPENAI_MODEL`=gpt-4o-mini, `AI_OLLAMA_MODEL`=llama3.3:70b, `AI_VLLM_MODEL`=Meta-Llama-3.1-70B-Instruct, `AI_GEMINI_MODEL`=gemini-2.5-flash, `AI_GROK_MODEL`=grok-2-mini, `AI_SARVAM_MODEL`=sarvam-m, `AI_CUSTOM_OPENAI_MODEL`="" | per-provider models | as listed | C |
| `AI_*_MAX_CONCURRENT` (anthropic 10, openai 20, ollama 8, vllm 32, gemini 4, grok 4, sarvam 10, custom 8) / `AI_*_RPM` (50, 200, 1000, 5000, 15, 60, 60, 5000) | throughput caps | as listed | C |
| `AI_GEMINI_TIER` / `AI_GROK_TIER` | free/paid RPM clamp | free | C |
| `AI_OPENAI_BASE_URL` / `AI_OPENAI_ORGANIZATION` / `OLLAMA_BASE_URL` / `VLLM_BASE_URL` / `AI_SARVAM_BASE_URL` / `AI_CUSTOM_OPENAI_BASE_URL` | endpoints (empty base URL disables ollama/vllm/custom) | api.openai.com / "" / localhost:11434 / "" / api.sarvam.ai / "" | C |
| `AI_CUSTOM_OPENAI_COST_PER_1K_INPUT` / `_OUTPUT` / `AI_CUSTOM_OPENAI_IS_LOCAL` | cost model | 0.0 / 0.0 / true | C |
| `AI_BUDGET_PER_REQUEST_USD` / `AI_BUDGET_PER_SCAN_USD` / `AI_BUDGET_PER_DAY_ORG_USD` | hard budget caps | 0.10 / 5.00 / 5.00 | C |
| `AI_CANARY_PERCENTAGE` | 0–100 deterministic rollout hash (see `app/ai/rollout.py`) | 100 | C |

#### S3 (declared, no direct reader found)

`.env.example` lists `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (**S**), `AWS_REGION`, `AWS_S3_BUCKET`, `AWS_S3_ENDPOINT_URL`. No `os.getenv("AWS_…")` in `app/` — boto3 is a dependency (`pyproject.toml:31`) and reads the credential pair implicitly; `AWS_S3_BUCKET`/`AWS_S3_ENDPOINT_URL` have **no consumer found** (searched `os.getenv`/`environ` across `app/`, `alembic/`, `run.py`).

#### Frontend (`frontend/.env.local.example`; build-time, class P — all NEXT_PUBLIC values ship in the JS bundle)

| Variable | Purpose | Default | Mandatory |
|---|---|---|---|
| `NEXT_PUBLIC_API_URL` | backend base URL | `http://localhost:8000` | **Yes** |
| `NEXT_PUBLIC_AUTH_ENABLED` | enable OIDC login | false | No |
| `NEXT_PUBLIC_HCL_IAM_ISSUER` / `_CLIENT_ID` | OIDC issuer/client | "" | when auth on |
| `NEXT_PUBLIC_HCL_IAM_AUTHORIZATION_URL` / `_TOKEN_URL` / `_LOGOUT_URL` | explicit endpoints (else issuer-derived, Keycloak-compatible) | "" | No |
| `NEXT_PUBLIC_HCL_IAM_REDIRECT_URI` / `_POST_LOGOUT_URI` | redirects | localhost:3000/auth/callback, localhost:3000 | No |
| `NEXT_PUBLIC_HCL_IAM_SCOPES` | OIDC scopes | `openid profile email roles` (code default `openid profile email`) | No |
| `NEXT_PUBLIC_COMPARE_V1_FALLBACK` | render preserved v1 compare page (`frontend/src/app/analysis/compare/_v1/page.tsx`) | unset/false | No |

#### Test-only

`TEST_POSTGRES_DATABASE_URL` / `TEST_DATABASE_URL` — override test DB (`tests/conftest.py:78–91`); default `postgresql+psycopg://sbom:sbom@127.0.0.1:55439/sbom_analyser_test` (L55). Safety: PG DB name must contain "test" or pytest fails (L65–75).

## 3. Feature flags (full list)

| Flag | Default | Read by | Restart semantics |
|---|---|---|---|
| `NVD_ENABLED` | true | API+Worker (Settings singleton) | restart |
| `NVD_BACKGROUND_ENRICHMENT` | true | Worker | restart |
| `NVD_VERSION_RANGE_FILTER_ENABLED` (roadmap #1) | **false** | API+Worker (both Settings L169 and lru-cached analysis settings L611) | restart |
| `SOURCE_CACHE_ENABLED` (roadmap #2 PR-B) | **false** | Worker/API (L321; analysis L612) | restart |
| `DISTRO_CPE_ENABLED` (roadmap #5, gates PR-B routing AND PR-C version-range distro handling together) | **false** | Worker/API (L338; analysis L614) | restart |
| `NVD_KEYWORD_FALLBACK_ENABLED` | true | Worker/API (lru cache) | restart |
| `NVD_REJECTION_DETAIL_LOGGING` | false | Worker/API — checked per call at `app/analysis.py:130` | no restart (per call) |
| `CVE_MODAL_ENABLED` | true | API | restart |
| `COMPARE_V1_FALLBACK` | false | API (`/health` echo) + FE build (`NEXT_PUBLIC_COMPARE_V1_FALLBACK`) | API restart + FE rebuild |
| `COMPARE_LICENSE_HASH_ENABLED` | false | API | restart |
| `AI_FIXES_ENABLED` | false | API+Worker | restart |
| `AI_FIXES_KILL_SWITCH` | false | API+Worker (registry) | restart |
| `AI_FIXES_UI_CONFIG_ENABLED` | false | API (+FE via API response) | restart |
| `AI_CANARY_PERCENTAGE` | 100 | API | restart |
| `AUTH_ENABLED` | false | API | restart |
| `DEV_DEFAULT_TENANT` | true | API | restart |
| `LIFECYCLE_XEOL_ENABLED` / `OPENEOX_ENABLED` / `XEOL_ENABLED` | false ×3 | API+Worker | restart |
| `NVD_MIRROR_ENABLED` / `NVD_MIRROR_DOWNLOAD_FEEDS_ENABLED` | false ×2 | Worker/Beat (per-task settings build) | next task run |
| `API_RATE_LIMIT_ENABLED` | true | API | restart |
| `API_IDEMPOTENCY_ENABLED` | true | API | restart |
| `API_AUTH_MODE` | none | API — `os.getenv` per request (`app/auth.py:28`) | **no restart** |
| `APPSEC_APPLICABILITY_DIAGNOSTICS` | off | Worker/API per call | no restart |
| `SBOM_SIGNATURE_VERIFICATION` | **False, constant** (`app/settings.py:697`) — stage 8 no-op | — | code change |
| FE `NEXT_PUBLIC_AUTH_ENABLED`, `NEXT_PUBLIC_COMPARE_V1_FALLBACK` | false | Frontend | rebuild |

---
