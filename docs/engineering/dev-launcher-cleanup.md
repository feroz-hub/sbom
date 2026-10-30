# Single-file local runtime cleanup

This supersedes the earlier retention stage. The only local development manager
is `scripts/dev.py`; old launch/setup implementations and distributed copies are
removed after their callers and regression tests use the canonical implementation.

## Implementation and verification order

1. Transfer the remaining Greenfield provisioning/bootstrap/build functionality
   to explicit, controlled subcommands in the canonical file. Keep specialised
   database schema acceptance/migration utilities separate from runtime orchestration.
2. Migrate utility/test imports to the canonical Greenfield settings and TLS
   implementations. Replace dynamic revision constants with graph discovery.
3. Run separate default/reports consumers and exactly one separate Beat, with
   OS-appropriate pools. Verify database/Redis connectivity, worker control
   responses and actual queues before readiness; verify scheduler tick progress.
4. Support safe setup, preserved legacy Windows configuration and useful health
   diagnostics through the same file. Never execute persisted PowerShell code,
   change root trust, rotate existing credentials or reset existing data.
5. Migrate documentation, frontend configuration, scanner/container manifests
   and all other consumers. Remove redundant files only after the replacement
   tests pass. Record the exact deletion list below.
6. Run lifecycle acceptance on available systems. Distinguish Linux-container
   evidence from full Linux application acceptance; report native Windows gaps.

## Production assessment

- Production Compose already invokes Uvicorn/Celery directly. The API runner is
  copied into the image but is not its command; remove that unused COPY alongside
  the redundant runner and retain the production CMD unchanged.
- Worker shell files are convenience wrappers. Migrate operations documentation
  to explicit production Celery commands; keep the existing Compose worker and
  Beat commands and queues unchanged.
- Retain production Docker migration/bootstrap tools, application worker/task
  modules, security scanners and specialised schema/data acceptance tools.
- Existing saved configuration and private profile storage are retained. The
  removed Windows scripts' config is parsed as literal data only, never executed.

## Compatibility risks and decisions

| Existing capability / risk | Canonical replacement or retained capability |
| --- | --- |
| Distributed Python orchestrators and packaged copy | Single Runtime, LocalHttps, GreenfieldStack and GreenfieldProfile implementations within dev.py; no imports or forwarding into retired modules |
| Windows BAT/PowerShell processes, queues, old ports and saved settings | Native process adapters, two workers plus separate Beat, preserved literal Windows configuration family and ports; native execution remains unverified |
| Worker scripts and Greenfield mail-only scheduler | Shared application task registry/routing, default/reports consumers and full separate Beat schedule; Greenfield mail cadence retained, existing task feature/security guards respected |
| Private credentials / database isolation | Existing files reused; incomplete state fails; exact Greenfield resource identities and distinct Legacy configurations; no fallback into another database |
| Setup scripts that installed system packages or trusted roots | Safe project dependency/leaf setup in dev.py; system installation and root trust are explicit external prerequisites |
| Greenfield provisioning/bootstrap/build | Explicit setup flags with exact target confirmation, empty-database/resource checks and isolated frontend build; no automatic schema reset/upgrade |
| run.py environment/key convenience and optional reload | Profile configuration/key setup owns this behavior without modifying root .env; saved RELOAD=true uses the shared API command; optional reload mode has command coverage but no new live reload acceptance |
| Certificate helper scripts | One LocalHttps implementation plus separate Legacy leaf policy; trust approval and TLS verification preserved |
| Process-name/port-based stopping in older scripts | Replaced with recorded OS birth identity/group/descendant checks and instance locks; no unrelated process adoption/termination |
| Production API/workers/Beat and migrations | Production Compose remains direct Uvicorn/Celery; unused Dockerfile runner COPY removed; database administration scripts retained |
| Archived executable startup/test copies | Deleted; immutable outcome/log/hash/patch records retain historical provenance |

Local startup no longer provides an ad-hoc authentication bypass switch. Existing
saved authentication settings are consumed without rewriting them. External
identity service installation, approved CA trust, initial administrators and
native platform acceptance remain separate prerequisites.

## Results

Replacement gates before deletion: 515 focused tests passed; the real Mac runtime
started all five components, verified both workers' ping/PID/queue responses and
scheduler progress, and preserved the private configuration/key/certificate and
container identity bytes. Tests were retargeted to canonical implementations.

### Deleted files

- `docs/uat/remediation/2026-10-20-round1/reload-local-api.py`
- `docs/uat/remediation/2026-10-20-round2/before/tests/test_dev_greenfield.py`
- `docs/uat/remediation/2026-10-20-round2/before/tests/test_dev_launcher.py`
- `docs/uat/remediation/2026-10-20-round2/before/tests/test_dev_lifecycle.py`
- `docs/uat/remediation/2026-10-20-round2/before/tests/test_greenfield_https.py`
- `docs/uat/remediation/2026-10-20-round2/reload-local-api.py`
- `docs/uat/remediation/2026-10-20-round2/restart-ui.py`
- `docs/uat/remediation/2026-10-20-round2/start-api.py`
- `docs/uat/remediation/2026-10-20-round2/start-baseline-api.py`
- `docs/uat/remediation/2026-10-20-round2/start-ui-worker.py`
- `docs/uat/round3/evidence/before/tests/test_dev_lifecycle.py`
- `docs/uat/round3/evidence/reload-local-api-legacy.py`
- `docs/uat/round3/evidence/reload-local-api.py`
- `docs/uat/round4/evidence/before/scripts/greenfield_uuid.py`
- `docs/uat/round4/evidence/start-isolated-redis.py`
- `frontend/scripts/setup-dev-https.ps1`
- `frontend/scripts/setup-dev-https.sh`
- `run.py`
- `sbom_launcher_bundle/DEVELOPER_START.md`
- `sbom_launcher_bundle/dev.py`
- `sbom_launcher_bundle/scripts/__init__.py`
- `sbom_launcher_bundle/scripts/dev.py`
- `sbom_launcher_bundle/scripts/dev_greenfield.py`
- `sbom_launcher_bundle/scripts/dev_runtime.py`
- `sbom_launcher_bundle/tests/test_launcher.py`
- `scripts/bootstrap.ps1`
- `scripts/bootstrap.sh`
- `scripts/celery_beat.sh`
- `scripts/celery_worker.sh`
- `scripts/dev_greenfield.py`
- `scripts/dev_runtime.py`
- `scripts/greenfield_https.py`
- `scripts/greenfield_uuid.py`
- `scripts/greenfield_worker.py`
- `scripts/report_worker.sh`
- `scripts/test_greenfield_setup.py`
- `scripts/windows/Check-SbomStatus.ps1`
- `scripts/windows/Ensure-DevHttpsCert.ps1`
- `scripts/windows/Initialize-SbomLocal.ps1`
- `scripts/windows/Restart-SbomAll.ps1`
- `scripts/windows/Start-SbomAll.ps1`
- `scripts/windows/Start-SbomApi.ps1`
- `scripts/windows/Start-SbomBeat.ps1`
- `scripts/windows/Start-SbomFrontend.ps1`
- `scripts/windows/Start-SbomReportsWorker.ps1`
- `scripts/windows/Start-SbomWorker.ps1`
- `scripts/windows/Stop-SbomAll.ps1`
- `scripts/windows/Stop-SbomLocal.ps1`
- `start-all.bat`
- `start-frontend-https.bat`
- `stop-all.bat`

The archived executable startup/test copies above were redundant implementations;
recorded reports, patches, outcomes and application evidence remain historical
data. Their old filenames in immutable patch/status records are provenance, not
live launch instructions or imports.

### Essential retained files

- `scripts/dev.py`: sole development management implementation, including Celery
  configuration/health, setup, TLS, process ownership and both profiles.
- `app/workers/celery_app.py` and application task modules: shared task registration
  and production schedule/routing authority; no business logic was moved or changed.
- `scripts/greenfield_migrations.py`, `greenfield_auto_migrations.py`,
  `greenfield_resource_migrations.py`, `greenfield_migration_graph.py` and schema
  acceptance/reference tools: specialised database safety/validation, using the
  canonical configuration class instead of a second runtime manager.
- `scripts/bootstrap_fresh_database.py`, `docker_migrate.py`, native administrator
  bootstrap and controlled fixture seed tools: production/data administration;
  explicit database confirmation/empty-database checks remain required.
- Docker/production Compose and `scripts/run_sast_mac.sh`: production execution
  remains direct Uvicorn/Celery; the scanner now includes the canonical manager.
- `tests/test_dev_private_setup.py`: migrated private-state tests; the pre-existing
  architecture-only contract check is retained in `tests/contract_checks/public_uuid.py`.

## Completed verification and limits

- Final focused launcher suite: **540 passed**. Covers ownership, isolated OS
  adapters, signals/locks, profiles, dependency reuse, TLS, controlled schema
  operations, worker responsiveness/queues, scheduler heartbeats, setup guards,
  deleted-file absence and executable consumer scans.
- Actual macOS existing Greenfield runtime: post-deletion restart, default start,
  repeated start with identical five PIDs and both dependency stamps, healthy
  status/doctor, reports/PostgreSQL logs, stop/repeated stop, closed application
  ports with preserved data containers, and recovery from a real owned reports
  worker failure passed. Failure named the component, log and corrective command.
- Private configuration/password/key/certificate and Docker identity bytes were
  compared in memory and remained unchanged. No initialization, migrations,
  trust-store writes or credential rotations were executed. Normal application
  schedules can perform their existing work while running.
- Linux container: **6 native process/CLI smoke tests passed**, using only
  disposable fixtures and no mounted application data/secrets. Full Linux runtime
  and fresh-clone setup were not executed. Native Windows was unavailable.
- Postman local GET /health with a PostgreSQL-available assertion passed;
  event reporting was disabled. No Postman workspace/collection was published.
- Production Compose config validated using synthetic values and an empty env
  file. Production task source/commands and direct Dockerfile CMD are unchanged;
  hosted CI, production image execution and deployment were not run.
- Ruff, changed Python AST parsing, deleted-consumer checks and git diff --check
  passed. No new missing relative Markdown links were introduced; 56 existing
  historical missing evidence links remain outside this cleanup.
- The full backend suite remains blocked by unavailable test PostgreSQL on
  127.0.0.1:55439. The preserved manual public UUID contract audit still fails its
  existing version_id catalog assertion. Its method AST is identical to HEAD's
  former standalone setup audit; no business contract was changed to hide it.
  Reproduce with: python -m unittest tests.contract_checks.public_uuid -q.

Controlled browser/test fixture environment utilities remain test infrastructure,
not public development managers; their configuration imports now use dev.py.
The complete OS/scenario matrix and remaining authentication/fresh-clone gaps are
in [dev-launcher-platform-matrix.md](dev-launcher-platform-matrix.md).

All changes are local/uncommitted on feat/native-user-management. The application
was left running at https://localhost:13000 with five verified components.
