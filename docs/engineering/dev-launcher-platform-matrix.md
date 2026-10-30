# Local launcher verification matrix

The only local development manager is `python scripts/dev.py`. The
[cleanup inventory](dev-launcher-cleanup.md) records the plan, compatibility risks,
deleted files and retained production/data tools. This matrix distinguishes
observed execution from adapter tests. Native Windows and full Linux application
support are **not established** by this change.

## Merge integration with main

The merge of main into feature commit 703baa73 retains the original 540-case
consolidation baseline and adds 53 adapted safety/diagnostic regressions in
[tests/test_dev_main_merge.py](../../tests/test_dev_main_merge.py): **593 passed**
on macOS with CI's SQLite/no-conftest safeguards. Python compilation, Ruff,
workflow YAML/target checks and six disposable Linux process smoke tests passed.
The running Mac stack passed read-only status/doctor; database identity/schema
marker, private credential/key/certificate bytes, recorded container identity and
application PIDs were preserved. No restart, provisioning or migration was run.

The workflow now tests the canonical manager on Windows/macOS/Linux runners,
with additional POSIX guard/native-process fixture steps. Hosted CI and native
Windows were not executed locally. These are not full cross-platform application
or browser acceptance claims. The original baseline below remains historical
consolidation evidence.

## Environments and evidence

| Scenario | macOS host | Linux container | Native Windows |
| --- | --- | --- | --- |
| Environment | Existing developer checkout, Python 3.12.7, Node 24.22.1 | Official python:3.12-slim container, disposable fixtures | Unavailable |
| Fresh clone / complete first setup | Not executed; safe-setup, missing-tool and incomplete-state regressions passed | Missing Node and incomplete-profile CLI negatives passed; full setup untested | Untested |
| Complete application startup | Existing Greenfield: PostgreSQL/Redis/Mailpit, default worker, reports worker, separate Beat, FastAPI, HTTPS Next.js passed | Full application untested | Untested |
| Repeated startup | Same five service PIDs, no duplicate instance; dependency stamps preserved | Native lock exclusivity test passed; full app untested | Mocked adapters only |
| Port conflict | Disposable listener remained reachable and unsignalled | Same native smoke test passed | Mocked adapters only |
| Missing dependency | Missing Node gives actionable exit 1 without setup writes | Same native CLI test passed | Mocked adapters only |
| Crashed process | Real owned reports worker failure detected, named component/log/action, owned runtime cleanup and recovery tested | Disposable crashed child reaped; stale state cleanup passed | Mocked identity/failure paths only |
| Stop / repeated stop | Real application ports closed, data containers stayed running; second stop exit 0 | Disposable owned child stopped while unrelated child survived | Mocked process-tree/lock tests only |
| Restart | Complete five-service restart after deletion passed | Full restart untested | Untested |
| Status / doctor / logs | Real PostgreSQL/Redis/consumer/scheduler/API/HTTPS status and doctor passed; worker and verified PostgreSQL logs passed | Only CLI smoke failures covered | Untested |
| HTTPS / authentication | Existing approved certificate and API IAM readiness passed; new browser login not executed | Mocked trust adapter only; browser untested | Mocked trust/ACL adapters only; browser untested |
| Legacy configuration | Unit regressions; real Legacy app/database not started | Unit/command branches only | Saved literal configuration parsing tested on Mac; native installation untested |

macOS verification reused existing data without provisioning, initialization,
schema upgrades, trust-store changes or credential rotation. Configuration,
password, key, certificate and recorded Docker identity bytes were compared in
memory and remained unchanged. Ordinary scheduled application tasks are enabled
with their existing feature guards. These checks are not a database-content
immutability claim while a running application processes normal work.

## Automated checks

The focused DB-free launcher suite covers lifecycle ownership, PID reuse,
unavailable identity, descendant cleanup, locks/signals, profiles, configuration
freshness, TLS, guarded migrations, two workers/queues, scheduler progress,
failed prerequisites, setup controls, deleted consumers and production commands.

```sh
python -m pytest --noconftest -q \
  tests/test_dev_cleanup.py tests/test_dev_background.py \
  tests/test_dev_consolidation.py tests/test_dev_lifecycle.py \
  tests/test_dev_launcher.py tests/test_dev_greenfield.py \
  tests/test_greenfield_https.py tests/test_greenfield_service_ports.py \
  tests/test_greenfield_windows_compat.py tests/test_dev_private_setup.py \
  tests/test_dev_native_process.py tests/test_greenfield_startup_migrations.py \
  tests/test_greenfield_auto_migrations.py tests/test_greenfield_resource_startup.py \
  tests/test_greenfield_governance_startup.py
```

Use the project virtualenv. On Windows enter arguments on one line or use
PowerShell continuation syntax. Original consolidation suite: **540 passed**; merge integration adds the 53 cases described above.
The native smoke subset also ran inside Linux with a read-only fixture containing
only the canonical launcher, empty synthetic manifests and tests: **6 passed**.
No private environment/data was mounted. Linux tests establish process/CLI safety,
not full Linux application or authentication acceptance.

Ruff checks passed for the canonical launcher and newly introduced tests.
Production Compose configuration validated with synthetic required values and an
empty env file. The Dockerfile retains its direct Uvicorn CMD; production
worker/Beat commands and application task source are unchanged. Production image
execution/deployment and hosted CI were not run.

## Limitations and remaining acceptance

- Windows Celery uses solo and separate Beat; native console/process-tree,
  npm .cmd handling, certificates and real tasks still require Windows validation.
  Upstream Celery does not provide native Windows support guarantees.
- macOS uses solo to avoid fork behavior; concurrency is intentionally limited.
  Startup checks control responses and queues. Monitoring uses connected-consumer
  heartbeats while solo tasks can delay RPC replies.
- Windows private frontend links may require approved Developer Mode/symlink
  permission. The launcher does not enable system privileges automatically.
- Greenfield requires its original pinned Docker topology and independently
  trusted mkcert CA. Fresh provisioning needs explicit setup controls and cached
  exact images. Existing incomplete state must be restored, never replaced.
- Pending Greenfield upgrades are blocked on Windows until its native
  backup/restore procedure is verified. Existing current-schema startup is distinct.
- Existing Windows/env Legacy configuration is read and preserved; no full
  Legacy/HCL.CS migration or login acceptance was performed. Database-backed
  Celery transport is explicitly refused pending an approved Redis configuration.
- System Python, Node/npm, Docker/local services, approved trust, external identity
  providers and initial administrators cannot safely be provisioned silently.
- Full backend pytest was blocked by its unavailable configured test PostgreSQL
  on 127.0.0.1:55439; the focused suite avoids that application fixture explicitly.
  The pre-existing standalone public UUID contract audit remains separately in
  tests/contract_checks/public_uuid.py; its version_id catalog assertion is not a
  launcher regression and is not included in the passing count.
- Fresh clones on all three systems, full Linux runtime, real Legacy runtime,
  browser login/email/provider workflows, production deployment and hosted CI
  remain unverified. Do not use passing mocked adapters as platform acceptance.
