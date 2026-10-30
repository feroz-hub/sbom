> Local development uses `python scripts/dev.py`. Explicit Celery commands in this document are production/operator procedures.

# Phase 1 Gate B environment readiness

Inspected 2026-10-09 on macOS ARM64. Branch `feat/native-user-management`; HEAD `6e7b22e1110ef1849150671b8d253efe0479e074`. This is discovery and planning, not execution authorization. Gate A's recorded **1,630 passing tests** remains the acceptance baseline; tests/build were not rerun in this environment-only task. Gate B remains **BLOCKED**; no A–I live scenario ran.

## Shortest actionable route

Use the **existing Native IAM local development stack**, preferably with a fresh, explicitly disposable Docker Compose project and volumes. Make Docker Desktop reachable, approve the isolated target and local-only mail/worker activity, then use `scripts/dev.py` rather than inventing another deployment. Its supported ports are **HTTPS 13000 / API 18000**, not the manual configuration's 3000/8000.

Before start, identify whether any existing project volumes or `sbom_analyser_dev` database contain work worth retaining. The launcher reuses that fixed database name; it does not create a random acceptance database. An existing development database is **not automatically disposable**. If reuse cannot be authorized, use a fresh Compose project (the same `COMPOSE_PROJECT_NAME` in every Compose and launcher invocation), or use the documented greenfield procedure with a separately named database and explicitly injected environment. Do not change the launcher's fixed database contract.

Browser access is now discoverable: Chrome is running with a connected automation extension; the current computer-use inventory also lists an in-app browser surface. This updates the earlier acceptance report's browser preflight observation without rewriting that report. Actual navigation/login against the application remains unverified because no application is running. No browser install is needed for the interactive Chrome route. Playwright's managed Chromium binary is missing if unattended tests are preferred.

## Current infrastructure evidence

Status meanings: **AVAILABLE** = observed runtime/package/listener; **NOT RUNNING** = expected local listener/process absent; **NOT CONFIGURED** = required target/fixture absent; **INACCESSIBLE** = installed capability cannot reach its service; **NOT VERIFIED** = ownership, authorization, behavior or compatibility not established. Connectivity is not authorization.

| Item | Status | Read-only evidence and limitation |
|---|---|---|
| OS / Python | AVAILABLE | macOS 27.2 ARM64; shell Python and `.venv` Python 3.12.7 |
| Node/npm | AVAILABLE | PATH Node 22.23.2; bundled Node 24.19.0 also available. Use one consistent runtime for startup/build |
| Frontend dependencies | AVAILABLE | Installed Next 16.3.4, React 19.2.7, TanStack Query 5.101.2 |
| Backend dependencies | AVAILABLE | `.venv`: FastAPI 0.139.0, uvicorn 0.50.1, SQLAlchemy 2.0.51, psycopg 3.3.4, Celery 5.6.3, Redis client 6.4.0, Alembic 1.18.5, cryptography 49.0.0, dotenv 1.2.2. Metadata presence is not full backend import/integration validation |
| Frontend/API | NOT RUNNING | No matching Next/uvicorn processes; loopback 3000, 8000, 13000, 18000 TCP unavailable |
| Docker CLI / Compose | AVAILABLE | Docker 29.5.3; Compose v5.1.4 |
| Docker daemon | INACCESSIBLE | `docker info --format '{{.ServerVersion}}'` exit 1. No daemon started; image availability not verified |
| Configured Docker PostgreSQL | NOT RUNNING | Loopback 55439 unavailable; `pg_isready` exit 2. Both root config and saved development config target this port |
| Other local PostgreSQL | AVAILABLE / NOT VERIFIED | 5432 reachable; `pg_isready -h 127.0.0.1 -p 5432` exit 0. CLI is from PostgreSQL 18 installation; server version, operator credentials, ownership and database contents were not queried. Do not substitute it without approval |
| Configured Docker Redis | NOT RUNNING | 56379 unavailable; PING exit 1. Saved dev config uses it for broker/results, sessions and rate limits |
| Other local Redis | AVAILABLE / NOT VERIFIED | 6379 PING returns PONG. No flush, key enumeration or app/session access; isolation unverified |
| Mailpit | NOT RUNNING | SMTP 1025 and UI 8025 unavailable |
| Celery worker / Beat | NOT RUNNING | No matching worker/Beat process. Task routing/readiness not live-tested |
| Native IAM saved settings | AVAILABLE / NOT VERIFIED | `.env.dev.local` exists, Native auth/outbox enabled, HCL disabled; signing/session/outbox key fields populated. Key validity, bootstrap state and accounts not inferred from presence |
| HTTPS files | AVAILABLE / NOT VERIFIED | Frontend certificate and private-key files exist; trust and expiry not tested; no key contents read out |
| Browser surfaces | AVAILABLE / NOT VERIFIED | Current `cua.getState()` discovers Chrome extension and IAB surface. No unrelated tabs inspected or application login performed |
| Playwright | AVAILABLE | `frontend/e2e` installed version 1.63.0; package requests compatible `^1.58.2` |
| Managed Chromium | NOT CONFIGURED | `chromium.executablePath()` does not exist. Installed Google Chrome executable exists |
| Existing E2E manifest | NOT CONFIGURED | `REPAIR_E2E_MANIFEST` not supplied; checked-in suite targets repair, not complete A–I |
| Acceptance accounts / providers | NOT VERIFIED | No live authorized tenant/users, lifecycle settings, inference provider or vulnerability fixture catalog inspected/provisioned |
| Staging target | NOT CONFIGURED | No authorized staging endpoint/credential custody/cleanup target supplied |

`.venv/bin/python scripts/dev.py --check` ran after reviewing its inspection branch. Exit **1**, safe diagnostic: **Mailpit is unavailable**. It starts no services and does not migrate/write configuration in check mode. It can select reachable local PostgreSQL/Redis as fallback; that selection does not establish their disposability. No application configuration values, connection strings, passwords, tokens, tenant records or captured emails were printed.

## Supported topology and configuration

Sources: `README.md`, `docs/dev-launcher-lifecycle.md`, `docs/native-iam-greenfield-setup.md`, `docs/native-tenant-provisioning.md`, `.env.example`, `.env.native-iam.example`, `.env.server.example`, `frontend/.env.local.example`, `docker-compose.yml`, `docker-compose.server.yml`, `scripts/dev.py`, `scripts/dev.py`, `app/settings.py`, `app/workers/celery_app.py`, and both Phase 1 reports. Original audit implementation sections distinguish configuration readiness, inline catalog sync and materialized enrichment.

Recommended local topology:

| Component | Existing supported configuration |
|---|---|
| Browser/BFF | `https://localhost:13000`; authenticated Native session, Redis session store |
| FastAPI | `http://127.0.0.1:18000`; Native JWT validation plus database-backed roles/membership |
| PostgreSQL | Compose PostgreSQL 16 on 55439; isolated project volume; launcher database `sbom_analyser_dev` |
| Redis | Compose Redis 7 on 56379; broker/results DB 0, sessions DB 1, rate limits DB 2. Dedicated instance preferred over sharing an existing Redis DB |
| Mail capture | Compose Mailpit SMTP 1025 / UI 8025; synthetic `.test` addresses only |
| Workers | Existing Celery worker and **one** Beat; analysis, AI and security-mail tasks use the normal worker queue |
| Storage | Isolated upload/workspace/report storage and logs; inspect configured paths before executing, especially server Compose shared application volume |
| Identity | Native-only supported mode; no external OIDC server needed. Auth enabled, `DEV_DEFAULT_TENANT=false`, HCL disabled, catalogue/role assignment fail closed |

Beat is required for automatic security outbox dispatch and scheduled-analysis ticks (every 15 minutes). Run Now enqueue alone does not prove scheduler/worker completion. Beat also registers mirror/KEV/model-refresh/cache/report tasks: starting it authorizes background activity, not merely a UI server. Review existing enablement/configuration and outbound access before starting. Report **target selectors** need the app/database; report delivery is outside these acceptance scenarios and does not require enabling notifications or running a reports worker. If delivery is later explicitly included, use the existing `scripts/dev.py` / `reports` queue and shared private artifacts, not the default worker alone.

Local fallback PostgreSQL 5432 / Redis 6379 is supported but is a second choice until the operator confirms isolated database credentials and Redis state. A dedicated staging server can use existing `docker-compose.server.yml`; it needs prebuilt backend/frontend images, secret/certificate mounts, migration approval and TLS ingress. That Compose includes an automatic `migrate` dependency and defaults for production validation; do not start it with local Mailpit assumptions. A fresh local Compose data stack plus host app launcher is the shortest supported route here.

Configuration drift to account for: `frontend/.env.local` still targets manual API 8000; the launcher injects its resolved API 18000 and Native-only auth flags into all children. Do not start an independent frontend with conflicting upstream/auth settings. The launcher reads `.env.dev.local` and validates local fixed database ownership; manual startup reads different environment files. Inspect inherited/root provider credentials and explicitly isolate provider settings—never allow real root `.env` credentials to become acceptance defaults.

The README's schema head `055_ai_model_registry` and greenfield guide's `062_native_platform_bootstrap` are historical. Read-only AST inspection of current migration files finds one source head: **`077_sbom_selection_mode`**, including the existing untracked migration. No database revision was queried. Confirm the complete working-tree migration set and approved empty target before migration; do not stamp an existing database to make it appear compatible.

## Existing commands — approval required before mutations

These are execution instructions for an approved future session, **not commands run in this task**. Secret settings must be loaded privately from the approved target's environment; placeholders below are deliberately non-executable until replaced.

```sh
# Inspection only; already executed here.
.venv/bin/python scripts/dev.py --check

# After approving Docker runtime start and a fresh isolated Compose project:
# Keep the approved COMPOSE_PROJECT_NAME identical for all following commands.
# Do not use a project name that owns existing non-disposable volumes.
docker compose up -d postgres redis mailpit

# After approving the target DB, schema migration, local email and background work:
.venv/bin/python scripts/dev.py start

# Inspect/manage only this launcher's owned app processes:
.venv/bin/python scripts/dev.py status
.venv/bin/python scripts/dev.py stop
```

The launcher installs missing dependencies, generates/persists keys when necessary, creates/reuses `sbom_analyser_dev`, applies Alembic, generates HTTPS setup as needed, and starts API/worker/Beat/frontend. It is **not a read-only startup probe**. Stop preserves database/Redis/Mailpit containers, volumes and logs. Fixed ports must be free; never kill unrelated owners to force startup.

For a separately named greenfield target, reuse the documented manual procedure with a securely exported target environment:

```sh
# Only after an operator creates/confirms the disposable database and grants approval:
.venv/bin/python -m alembic upgrade head
.venv/bin/python -m alembic current

# Existing launcher-equivalent commands, each in its own supervised terminal,
# all receiving the same approved target, broker, auth and storage environment:
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 18000 --no-proxy-headers
.venv/bin/python -m celery -A app.workers.celery_app worker --loglevel=info
.venv/bin/python -m celery -A app.workers.celery_app beat --loglevel=info
# From frontend/:
npm run dev:https -- --port 13000
```

Do not run `python scripts/dev.py` as a readiness check: it may generate a key into root `.env` and starts the API. Native greenfield setup requires independent RSA JWT signing/public keys, outbox AES-GCM key, session encryption key, Redis session/rate-limit configuration and canonical HTTPS activation/reset URLs. Provider credential storage also needs a stable supported encryption key (`AI_CONFIG_ENCRYPTION_KEY` for AI; lifecycle supports the configured secrets chain). Templates contain examples, not acceptable shared credentials. The launcher already supports Native key generation; never print generated secrets into this report.

## Identity and disposable fixture plan

No accounts, invitations or records created yet. Use a run-specific prefix for every synthetic resource and `.test` email addresses delivered only to Mailpit.

| Fixture | Purpose / creation constraint |
|---|---|
| Platform operator P | Bootstrap through `scripts/bootstrap_native_platform_user.py` and normal activation; no fabricated platform grant |
| Backup platform operator P2 | Preserve recovery while testing grant/revoke/account status; do not remove the final viable administrator |
| Tenants A and B | Distinct slugs; one active tenant plus temporary pending/disabled tenant for A. Never use real tenant records |
| Tenant administrators A/B | Dedicated active verified admins; platform creation can use an eligible existing admin or supported initial-admin invitation. Current provisioning supports both, despite older greenfield guide wording |
| Analysts A/B | Catalogue-authorized inventory, analysis, VEX and AI workflows; exact permissions verified from backend session context |
| Developer A | Assigned current investigation, plus unassigned/historical contexts to verify denial |
| Viewer A | Read-only controls and direct-request denial checks |
| Multi-tenant actor M | Analyst in A, Viewer in B for role/tenant isolation; change only a expendable self-access actor with another admin retained |
| Inventory | Projects A1/A2 and B1; products under each; two revisions of one logical SBOM; unrelated tenant B inventory as isolation control |
| SBOM samples | `sbom_valid_10_samples_v2_corrected/05_cyclonedx_valid_edit_version_management.cdx.json`, `06_cyclonedx_valid_vulnerable_components_osv.cdx.json`, `07_cyclonedx_valid_with_vex_analysis.cdx.json`; `samples/spdx-web-app.json` and `sbom_test_samples_10_files/08_spdx_valid_lifecycle.spdx.json`. Run actual upload validation; filenames are not evidence that current validators pass |
| Findings/VEX | Multiple component-specific findings and severity variants, a current writable context, authored decisions and immutable historical run/revision controls. Backend test fixture builders in `tests/test_vex_acceptance_e2e.py` and `tests/fixtures/vex/` are design references, not live worker evidence |
| Lifecycle | Tenant-owned and inherited configuration, synthetic custom vendor records, known PURL/name/version evidence; no production API credentials or automatic evidence recomputation |
| AI | Prefer an authorized local Ollama/vLLM or already available custom OpenAI-compatible endpoint with known structured output. No inference service observed; no production credential reuse |

First bootstrap requires matching `--confirm-database`, explicit `DATABASE_URL`, temporary `NATIVE_PLATFORM_BOOTSTRAP_ENABLED=true`, Native enrollment/outbox and an approved captured mailbox. Reuse the guide's command structure with synthetic email/phone/operator reference. Activate through the normal captured-email flow, then disable the bootstrap flag. Do not extract tokens from the database or bypass verification. Provision remaining identities/memberships through authorized UI/API workflows, preserving assignment version checks and last-admin guards. Password entry/browser certificate trust may require human handoff under the current computer-use policy.

### Controlled data versus genuine execution

Inventory, VEX, role, readiness and report-selector scenarios can begin with controlled persisted fixtures, but actions/assertions must traverse actual browser/BFF/FastAPI HTTP and database state. Seeded terminal runs alone cannot pass C/G. C must execute the existing analysis path and G must execute the Celery task; observe real authoritative queued/running/terminal results, including an approved failure case. Do not promise fixed vulnerability counts from evolving public provider data. Prefer a known approved catalog/cache fixture; verify it is consumed by the actual analyzer. Existing pytest mocks do not configure a running application's provider endpoints.

F needs a genuine worker call to an authorized inference endpoint and persisted generated fixes/usage. A deterministic non-production endpoint is suitable for orchestration acceptance only if separately provided/approved and conforms to the existing custom provider contract (`/v1/chat/completions`, structured output, token usage, optional `/v1/models`). No ready-made full AI acceptance substitute was found in the reviewed setup. Creating one is not part of this task. Explicitly label substitute evidence; it cannot establish a real provider's reliability or billing. Paid providers require named provider, test credential, egress approval and spending cap before any test/model discovery/generation call.

H can use database custom vendor records without a paid provider. Config secrets/connection checks require a supported credential-bearing test provider; custom catalog fixtures alone cannot pass those cases. Verify actual backend persisted health rather than equating a test result to saved readiness. Current lifecycle sync is inline `completed`/`failed`, `job_id: null`; there is no reliable asynchronous lifecycle job-status endpoint. Catalog edits require explicit component enrichment to change materialized SBOM evidence. Do not claim catalog import reanalyzed SBOMs.

## Browser requirements

Interactive route: connected Chrome via existing computer-use tooling, HTTPS frontend reachable, trusted local certificate, dedicated test login/session. Create dedicated acceptance tabs; do not reuse unrelated signed-in tabs or capture their data. Trust changes/interstitial bypass and entering new passwords require operator handling when the tool policy requires it. Listed IAB availability is inventory evidence, not a successful application navigation test.

Unattended route: existing `frontend/e2e/package.json` supplies Playwright. After approval to download official browser binaries, from `frontend/e2e`:

```sh
npm exec -- playwright install chromium
```

Do not invoke `npm exec` from a directory without the installed package and accidentally install a second toolchain. Existing `npm test` requires an approved `REPAIR_E2E_MANIFEST` generated by `scripts/run_sbom_repair_e2e.py`; that launcher creates/drops a random PostgreSQL database, bootstraps schema, seeds users and starts isolated services. It disables the native security outbox and targets **SBOM repair**, so it cannot replace invitation/email/worker/provider A–I acceptance. Do not run it merely to obtain a manifest. Use interactive acceptance now, or separately authorize expanding the existing harness later. No new harness/configuration was created here.

Record real UI observations and HTTP status/result fields; redact authorization/cookies/tokens/email/PII. Playwright traces/HAR/screenshots can include secrets; do not save unredacted login/email/cookie traffic. Network-count evidence must count requests per scoped query and distinguish deliberate polling, cancellation and mutation-driven refetch.

## A–I execution plan

All groups need browser + BFF/API + isolated PostgreSQL + Redis auth sessions. **All currently BLOCKED** by absent app/approved target/actors; additional requirements are listed below. Expected results are future assertions, not observed passes.

| Group | Services/actors/data | Browser interactions | Authoritative result to compare | External/cost and cleanup |
|---|---|---|---|---|
| A Platform | Common stack; P/P2; fresh tenant and recoverable grant targets; worker/Beat/Mailpit for pending invitations | Cache dashboard; create active/pending tenant; activate/disable; grant/revoke | Mutation success, backend summary tenant-status/admin totals equal displayed counts without F5 | No paid service. Retain backup admin; disable/delete only run-owned records after evidence |
| B Inventory | Common; admin/analyst A; two project/product scopes and versioned CDX/SPDX | Create/rename; upload/edit/reassign; restore; reopen report target searches | Lists/details/old-new scopes reflect committed ownership; restore returns a new revision; targets reflect inventory | No provider needed for metadata. Track uploaded files/new revision IDs; dispose run-owned storage/database |
| C Analysis | Common; analyst A; real analyzer and worker where background path applies; known vulnerable package/provider evidence | Submit; observe status, navigate scopes, remount with recovery tracking | Run persisted status/findings and badges/dashboard agree; failure/partial evidence remains accurate | Public vulnerability endpoints may need approved egress/rate limits; no paid keys by default. Clear only owned recovery markers after terminal state; stop pending owned work before disposal |
| D VEX | Common; analyst/admin/developer; current finding/investigation and assignment control | Save decision; reopen investigation/home dashboard; change assignment separately | Version/concurrency-protected decision and aggregates agree; assignment-only request count excludes unrelated metrics | No provider if evidence fixture prepared. Preserve historical decision/audit controls during testing |
| E Users | Common + Mailpit + worker/Beat; P/admin A/M/viewer B; spare admins | Invite/add member; activate; replace role; controlled self change; logout/switch | Actual outbox/captured activation, membership lists, eligible assignees, auth session roles and server denials | Capture mail only; never real invitations. Keep recovery identities; dispose test sessions/mail with stack |
| F AI | Common + real AI worker + authorized test inference; analyst A, eligible findings | Submit; observe separate batches; completion/failure/cancel/partial output; reopen results/usage | Batch state plus persisted fixes/history/token usage agree; enqueue never claims generated output | Additional blocker: inference endpoint missing. Local compute or explicit provider budget. Stop owned batches, remove only owned cache/artifacts after evidence |
| G Schedules | Common + worker + single Beat; authorized schedule editor; scoped/inherited/excluded targets | Create/edit/pause/resume; preview; Run Now; observe eventual scheduled tick | Schedule/list/targets agree; enqueue vs actual run distinguished; real terminal findings | Same egress approval as C. Pause/delete owned schedules before shutdown; no leftover periodic work |
| H Lifecycle | Common; platform/tenant config admin; owned/inherited test config, secret-bearing safe endpoint/catalog | Save/delete secret/reset override; test connection/inline sync; import records; explicit enrichment | Effective config/health matches backend; transient probes vs persisted health vs catalog/enrichment distinguished | Additional blocker: safe provider unverified. No speculative async tracking. Restore test overrides or dispose whole target; no production secret change |
| I Resilience | Common plus workers/provider for chosen async cases; M + viewer B; historical snapshots/control tenant | Successive mutations; overlap requests; logout/switch/navigation; capture bounded traffic | Server/UI equality, canceled/retired context isolation, disabled observers not fetched, snapshots stable | No added transport. Preserve read-only evidence; destroy only approved run-owned sessions/storage/resources |

Suggested sequence: (1) approve/verify target and services; (2) verify health + IAM readiness + BFF readiness and capture-mail delivery; (3) bootstrap/recovery actors and two tenants; (4) baseline counts and immutable control fixtures; (5) A, B, E; (6) actual C analysis then D; (7) G; (8) H; (9) F only after provider approval; (10) I across preceding workflows; (11) reconcile evidence, defects and owner-approved cleanup. Refresh the acceptance report only with executed observations and redacted HTTP evidence. A terminal seeded fixture, HTTP 200 enqueue, successful connectivity probe or rendered progress counter is insufficient completion evidence.

## Approval boundaries, blockers and cleanup

The next execution session needs explicit authorization for:

1. **Target ownership:** exact disposable Compose project/volumes/database, operator credentials supplied privately, isolated Redis/storage, retention and later disposal scope. Existing local 5432/6379 and old Docker volumes remain unapproved.
2. **Startup/schema:** Docker runtime/data services, creating/migrating the approved database through current source head, key/config/certificate generation, API/BFF startup and outbound-access limits. No shared/production database.
3. **Workers/mail/fixtures:** worker and one Beat, local-only Mailpit dispatch, synthetic bootstrap/accounts/roles/tenants/inventory, controlled self-access changes with spare administrators. No real invitation email.
4. **Providers:** safe lifecycle settings and authorized inference endpoint; any paid provider requires separate explicit cost cap. Review root environment fallback secrets before startup; do not inherit unrelated real-provider credentials.
5. **Browser/cleanup:** official Chromium download if needed, operator certificate trust/password steps, evidence redaction, and eventual deletion of only confirmed run-owned resources. Startup approval does not implicitly authorize deleting old databases/volumes.

Current immediate blockers: inaccessible Docker daemon; absent project data services/Mailpit; app/worker/Beat offline; no approved disposable target/actors; missing inference/test lifecycle endpoint. The browser inventory blocker has improved, but live navigation/auth remains NOT VERIFIED. Existing certificates/packages reduce setup effort; they do not establish readiness.

After testing, pause schedules/cancel or await owned tasks, stop launcher-owned processes, retain redacted evidence, then dispose only approved isolated volumes/database/storage/Mailpit/Redis. Never issue global Redis flush, repository clean, database reset, broad container removal, or delete shared reports. Stop does not remove data services; volume/database deletion requires its own approved target list. No cleanup/migration/service start was performed here.

Only this readiness report was created. Original Phase 1 audit/acceptance reports, production code, environment files and all pre-existing tracked/untracked work were preserved. No commit, push, deployment, database mutation, paid call or live acceptance pass is claimed. **Gate B stays BLOCKED; release readiness remains NOT READY until required real acceptance is executed.**
