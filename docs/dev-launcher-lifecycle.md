# Local development lifecycle

Run from the repository using Python 3.11+ (`python` on Windows if needed):

```sh
python3 scripts/dev.py start
python3 scripts/dev.py stop
python3 scripts/dev.py restart
python3 scripts/dev.py status
python3 scripts/dev.py --check
python3 scripts/dev.py start --verbose
```

No command means `start`. Start/restart run in the foreground. Ctrl+C and SIGTERM
perform cleanup. Stop works from a different terminal and is idempotent. There is
no detached mode; use another terminal for stop/status while the launcher runs.
`--check` overrides any command and remains inspection-only.

## Ports and environment

The current launcher fixes API to 18000 and HTTPS frontend to 13000. Docker
PostgreSQL uses 55439, Redis 56379, Mailpit SMTP 1025 and web UI 8025. Local fallback
PostgreSQL/Redis use 5432/6379. Status probes the dependency ports saved in
`.env.dev.local`, with the existing protocol checks. It does not start containers.

Existing `.env.dev.local` resolution, Native IAM setup, migration/schema checks,
HTTPS certificate generation and dependency-install caching remain in place.
The same resolved environment is passed to API, Celery and frontend. Explicit
`AI_FIXES_ENABLED` values are preserved; the launcher does not add an AI default.

## Ownership and safety

`.dev-runtime.json` is private (0600 on Unix), ignored by Git, and written through
an fsynced temporary file and atomic replacement. It contains repository identity,
instance ID, start time, launcher/process birth identities, service ports and
recorded group members. It contains no environment, secrets or raw command lines.

Only processes recorded directly after this launcher's Popen calls are managed.
Each termination checks OS process birth identity and executable, plus UID,
working directory, process group and session where available. A port, executable
name or PID alone never establishes ownership. Linux uses `/proc` start ticks and
boot ID; macOS uses libproc's microsecond creation time; Windows uses native
process creation FILETIME and executable identity.

On Unix each service starts a new session/group. Stop sends SIGTERM to verified
groups, waits up to five seconds, then rechecks ownership before SIGKILL. Recorded
surviving children permit cleanup after their immediate parent dies. Windows uses
native process-tree snapshots and verified `taskkill /T`, escalating to `/F` only
if necessary. Windows workers retain the existing solo pool.

`.dev-runtime.lock` uses flock on Unix or a byte-range lock on Windows. The OS
releases it even after a crash. The file intentionally remains: unlinking a locked
inode can allow two launchers. `.dev-runtime.stop` is an atomic, instance-scoped
cooperative cancellation request. A live launcher handles it at startup checkpoints
and during readiness/monitoring; stop waits for its lock to release before orphan
cleanup. A long-running setup subprocess may delay this response; stop reports
that cancellation remains pending and can be retried. It never forcibly kills an
unverified launcher or shared setup tool.

## Recovery

- A second start reports the current instance instead of starting duplicate work.
- `status` reports RUNNING, STOPPED, PARTIAL, UNOWNED or UNKNOWN without modifying
  process state. STARTING/STOPPING launchers may have incomplete service rows.
- `stop` and the next `start` reconcile stale records and safely stop verified
  surviving children. Dead Beat PID locks are removed; live legacy locks remain.
- Reused PIDs, inaccessible ownership data and unknown surviving groups are never
  killed. Their records are retained for diagnosis rather than falsely claiming
  successful cleanup.
- Malformed or wrong-repository registry files fail closed. Atomic replacement
  prevents normal interrupted writes from creating partial registry files.
- Instances started by older launcher versions have no trustworthy registry.
  Stop those using Ctrl+C in the original terminal. This launcher will report their
  occupied ports (and PID/executable when Linux permits inspection), but cannot
  safely adopt or kill them.

Stop leaves PostgreSQL, Redis and Mailpit running, preserves volumes and keeps
`.dev-logs/` (api.log, celery-worker.log, celery-beat.log, frontend.log).

## Validation

Unit tests in `tests/test_dev_launcher.py` and `tests/test_dev_lifecycle.py` mock
process operations. Real Linux smoke validation used an isolated temporary
repository and only fixture-owned processes, including descendants, listeners,
crashes, restart, Ctrl+C and SIGTERM. macOS/Windows native code paths are covered
with mocks; execution on those operating systems is still recommended.

On the development server, help/check/status/stop/start/restart were also exercised.
Prerequisites passed. Actual application startup/restart was safely blocked by
pre-existing unregistered listeners on 18000 and 13000; no existing developer
process was terminated to force validation through.

Final focused result: **107 tests passed**. Python compilation and `git diff
--check` passed. The isolated real-process harness passed all eight scenarios and
verified that its service groups and listening ports were gone after shutdown.
