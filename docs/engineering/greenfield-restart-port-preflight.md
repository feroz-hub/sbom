# Greenfield restart port preflight — 24 October 2026

The reported traceback failed at `scripts/greenfield_uuid.py`'s plain
`socket.bind()` check for application ports 18000 and 13000, after schema
verification succeeded. This was separate from the database/schema check.

At investigation time both ports were available, the ownership registry was
absent and all PIDs in the older Greenfield process metadata had exited. No
occupied process was killed or adopted. The historical kernel state was no
longer observable. A real loopback reproduction confirmed the preflight bug:
after closing a service that used `SO_REUSEADDR`, a plain bind returned macOS
errno 48 even though no listener remained; a POSIX reusable bind succeeded.
This `TIME_WAIT` false conflict explains how `stop` can correctly report no
running managed environment while the former preflight still rejects restart.

## Correction

- `scripts/greenfield_uuid.py`: use a named application-port check matching the
  POSIX reuse policy of the application listener. Never enable `SO_REUSEADDR`
  on Windows and never enable `SO_REUSEPORT`. A live listener is still refused.
  Port checks precede settings/credential reads, workspace copying and process
  creation. Failures identify the exact port and give a diagnostic command;
  no unverified process is signaled.
- `scripts/dev.py`: translate the typed port error into the existing clear
  setup-error path so a real conflict does not require `--verbose` to identify.
- `tests/test_greenfield_service_ports.py`: real closed/live loopback cases,
  platform policy, side-effect ordering and error propagation.

## Executed verification

```sh
.venv/bin/python -m pytest --noconftest \
  tests/test_greenfield_service_ports.py tests/test_dev_greenfield.py \
  tests/test_dev_launcher.py tests/test_dev_lifecycle.py -q --tb=short
```

**189 passed.** `--noconftest` deliberately excludes the repository's database
bootstrap for these standalone launcher/unit tests. Tests require no database,
application credentials or migrations.

`scripts/dev.py start --check` verified existing containers and HTTPS trust
without starting services. The repository head and existing schema were both
`102_public_membership_grant_analysis_uuid`. Normal `scripts/dev.py start`
then reached Greenfield readiness with the actual API, frontend and worker.
The frontend's ordinary workspace synchronization also picks up the current
checkout's UI changes. No bootstrap, database reset/seed, schema upgrade,
credential rotation or unrelated process termination was performed.

All 19 previously pending tracked files remained byte-identical, including the
existing runtime/lifecycle changes. Patch whitespace checks passed. The running
development environment was left available for the user.
