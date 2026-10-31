# Local development lifecycle

The sole local development manager is `scripts/dev.py`. Run from a complete
checkout with Python 3.11+ (use python3 where needed):

```sh
python scripts/dev.py
python scripts/dev.py setup --plan
python scripts/dev.py setup
python scripts/dev.py status
python scripts/dev.py diagnose
python scripts/dev.py logs --service reports --lines 80
python scripts/dev.py logs --service postgres --lines 80
python scripts/dev.py stop
python scripts/dev.py restart
```

No command means start. Start/restart stay in the foreground; keep that terminal
open and use another for management. Ctrl+C stops owned application processes.
`diagnose` performs bounded read-only checks. `--check`, including `setup --check`,
uses the same path before mutable preparation. The temporary `doctor` alias emits
one stderr deprecation notice. Provisioning/initialization/migration/build flags
cannot be combined with diagnostics. See the [diagnostic contract](reference/configuration.md#read-only-diagnostics-sbo-98-phase-2).
Diagnostic results are PASS, WARN, FAIL, BLOCKED or SKIPPED: exit 0 has no failed or
blocked required checks, 1 reports a required failure/block, 2 is invalid usage,
and 130 is cancellation. Status retains exit 0 when healthy and 3 when
stopped/unhealthy. Setup/start failures return 1.

## Profiles

Auto selects an installed private Greenfield directory, otherwise Legacy.
Incomplete state fails without choosing another profile/database. An existing
runtime pins its profile and Legacy configuration family.

| Property | Greenfield | Managed Legacy | Existing Legacy Windows/env |
| --- | --- | --- | --- |
| Configuration | Private ~/.sbom-greenfield-uuid | Ignored .env.dev.local | .windows/sbom.env.ps1 or explicitly selected .env |
| PostgreSQL | sbom_greenfield_uuid, 56044 | sbom_analyser_dev, Docker 55439 or saved local port | Saved local database, excluding Greenfield/system databases |
| Redis | 56381 | Docker 56379 or saved local port | Saved Redis broker |
| Mailpit UI/SMTP | 8026/1026 | 8025/1025 | Saved configuration |
| API/frontend | 18000/13000 | 18000/13000 | Saved ports, defaults 8000/3000 |
| Logs | Private state directory | .dev-logs | .dev-logs |

Use --legacy-config managed|windows|env explicitly. Auto prefers existing managed
settings, then saved Windows settings. Root .env requires explicit selection.
Windows settings are parsed as literal $env:NAME = 'value' assignments; executable
PowerShell is rejected. Existing credentials, signing/encryption keys, authentication
flags, ports and database identities remain authoritative and are not overwritten.

## Preparation and HTTPS

Python 3.11+, Node.js 20.9+ with npm and selected data services are prerequisites.
Greenfield requires Docker/Compose and its approved mkcert CA. Missing system
software produces install instructions. `setup --plan` observes required actions;
interactive `setup` requests category-specific consent and revalidates inputs.
Project virtualenv/pip/npm dependencies are prepared only by authorized setup,
using content-based freshness checks. Bare startup requires prepared dependencies
and never installs packages, discovers database credentials or generates keys.
Startup/build probe only the already-installed native compiler through an owned
Node process; they never use Next's compiler downloader. An explicit
`setup --repair-dependencies` plan and category consent are required to rerun
pinned installers; normal startup and diagnostics never repair dependencies.
System software, OS services and trusted roots are not installed silently.

Ordinary startup authenticates to PostgreSQL/Redis and validates the existing
schema. It does not create, initialize, reset or implicitly upgrade a database.
See [bootstrap instructions](../scripts/BOOTSTRAP.md) for guarded setup flags.
Stop application processes before schema changes. First-user creation remains
the [Native IAM operator procedure](native-iam-greenfield-setup.md).

Greenfield reuses verified containers, networks, volumes, private credentials and
its independently trusted mkcert CA. New leaf creation belongs to explicit,
authorized setup; ordinary startup validates existing material only. Legacy
reuses its pair, or authorized setup creates a missing self-signed leaf;
browser/OS trust requires explicit operator approval. Incomplete pairs fail
without replacing surviving material. TLS and hostname verification remain enabled.
See [controlled preparation and recovery limits](reference/configuration.md#controlled-setup-and-prepared-startup-sbo-98-phase-3)
for new-file Windows DACL safeguards, guarded dependency repair
and retained partial artifacts. Existing private files and trust are not repaired.

## Complete runtime

Dependency order is verified data services (including managed Mailpit),
authenticated PostgreSQL/Redis checks, default celery queue worker, reports queue
worker, one separate Beat, FastAPI, then HTTPS Next.js. API/workers/Beat retain
shared server settings; Node receives only its approved BFF/public inputs in the
prepared environment-free workspace. Parent runtime metadata retains selected
ports and ownership information. See [component environments](reference/configuration.md#component-environments-and-frontend-workspace-sbo-98-phase-4).
Saved RELOAD=true enables the backend reloader using the same owned API command.
Linux workers use prefork, concurrency 1; macOS/Windows use
solo. Windows Celery has upstream platform limitations.

The real application registry/routing and full Beat schedule remain authoritative.
Greenfield retains a 10-second mail cadence while including other schedules and
their existing feature/security guards. Beat uses a profile/database Redis lease
and private schedule file.

Readiness requires owned processes, worker control pings, assigned queues,
matching worker PIDs, fresh connected-consumer heartbeats, real scheduler ticks,
API database/IAM readiness where applicable, and verified HTTPS. A process alone
is insufficient. Monitoring detects crashed processes and lost database/broker/
consumer/scheduler health, reports the component/log/action and cleans owned
application processes. Busy solo workers use consumer heartbeats because task
execution can delay control RPCs. Browser login/providers/delivery need separate
acceptance.

## Ownership, logs and recovery

The ignored private .dev-runtime.json stores checkout/profile/instance and OS
process birth identity. Only recorded children and verified descendants are
managed. PID/name/port alone never establishes ownership. Linux uses /proc boot/
start identity, macOS libproc creation time and Windows native FILETIME/executable
identity. Inaccessible or mismatched identity fails closed. POSIX uses isolated
sessions/groups; Windows uses checked process trees. A persistent OS lock prevents
concurrent owners; instance-specific stop requests trigger cooperative cleanup.

Repeated start verifies the ready instance without spawning duplicates.
Unready/unhealthy instances return a diagnostic failure. Stop/restart reconcile
verified stale children; unrelated port owners are never killed or adopted.
Resolve port conflicts deliberately.

Logs are bounded and redacted; inspect output before sharing. Select postgres,
redis or mailpit for verified Docker logs; external services require their OS
manager. Stop preserves data containers, volumes, databases, credentials,
certificates and logs. See the [cleanup inventory](engineering/dev-launcher-cleanup.md)
and [platform matrix](engineering/dev-launcher-platform-matrix.md).

Before explicit initialization/upgrade, read the [database compatibility gate](DATABASE_BOOTSTRAP_AND_UPGRADE.md).
A populated pre-UUID database cannot cross revision 100. Inspection/stop/status
remain available without complete startup prerequisites. Required setup failures
print a redacted tail (up to 35 lines); this is distinct from application logs.
