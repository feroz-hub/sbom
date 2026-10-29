# Local development lifecycle

This remains the process-ownership/recovery reference. For current setup,
profile selection and OS limits use the [developer guide](development/README.md).
The Validation section below records earlier results and is not current platform
or release acceptance.

Run from the repository using Python 3.11+ (python on Windows if needed).
Select the intended profile explicitly; the examples use legacy:

```sh
python3 scripts/dev.py start --profile legacy
python3 scripts/dev.py stop --profile legacy
python3 scripts/dev.py restart --profile legacy
python3 scripts/dev.py status --profile legacy
python3 scripts/dev.py --check --profile legacy
python3 scripts/dev.py start --verbose --profile legacy
```

No command means `start`. Start/restart run in the foreground. Ctrl+C and SIGTERM
perform cleanup. Stop works from a different terminal and is idempotent. There is
no detached mode; use another terminal for stop/status while the launcher runs.
`--check` overrides any command and remains inspection-only.

## Ports and environment

Both profiles use API 18000 and HTTPS frontend 13000. Legacy uses Docker
PostgreSQL 55439/Redis 56379 or local 5432/6379, with Mailpit 1025/8025.
Greenfield uses PostgreSQL 56044, Redis 56381 and Mailpit 1026/8026.
See the [profile table](development/README.md#ports-environment-and-queues).

Auto selection chooses an existing home-directory Greenfield installation;
otherwise it uses legacy. Greenfield's current trust verifier requires macOS.
The registry is checkout-local; home-directory Greenfield state is shared across
worktrees, so do not launch it concurrently from another checkout.

Legacy configuration is stored in .env.dev.local and resolved with fixed Native
flags. Greenfield uses its private state, recorded containers, restricted
security-mail scheduler and both worker queues. Startup can propose guarded
pending migrations after confirmation and backup/restore verification; it does
not bootstrap or seed an installation as a normal start step.
See [database operations](DATABASE_BOOTSTRAP_AND_UPGRADE.md#greenfield-startup).
Legacy instead runs ordinary Alembic upgrade for its local target; populated
pre-UUID targets must not cross revision 100 in either mode.

--check does not start or migrate; it is prerequisite inspection, not full
schema/application readiness. [Configuration](reference/configuration.md)
describes precedence and the fields not fixed by each profile.

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

Stop leaves PostgreSQL, Redis and Mailpit running and preserves volumes.
Legacy keeps .dev-logs (api.log, celery-worker.log, celery-beat.log, frontend.log);
Greenfield keeps its private home-directory logs.

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
