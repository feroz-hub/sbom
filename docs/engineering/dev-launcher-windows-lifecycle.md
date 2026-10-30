# Native Windows launcher lifecycle investigation

The candidate is on `codex/windows-launcher-lifecycle`, based on main commit
`fcc873112ba9f08b1cccf9f27f3e211895ae32e6`, in the dedicated worktree
`C:\sbom\.windows\worktrees\windows-launcher-lifecycle`. It is not merged.
See also [the lifecycle guide](../dev-launcher-lifecycle.md) and
[historical platform matrix](dev-launcher-platform-matrix.md). Passing mocked
Windows checks or macOS acceptance does not establish native Windows readiness.

## Supplied evidence and reproduced causes

The developer's host is native Windows PowerShell at `C:\sbom`, with Python
3.14.6, Psycopg 3.3.4/binary libpq, Node v26.1.0 and Celery 5.6.3. Managed Legacy
uses PostgreSQL `127.0.0.1:5432`, Redis `127.0.0.1:6379` and Mailpit UI
`127.0.0.1:8025`. `sbom_analyser_dev` was initialized through
`103_tenant_admin_governance`; `pip check` reported no broken requirements.

The supplied command was
`python .\scripts\dev.py --profile legacy --legacy-config managed`. It accepted
the schema and reported workers 14180/2724 and Beat 9928 running, then printed
`Cannot inspect PID 9928.` CIM later found both workers alive and Beat absent;
status showed workers RUNNING and Beat/API/Frontend STOPPED. The supplied Beat
excerpt showed a scheduler tick and `report-notifications-outbox` dispatch at
13:25 local time without a traceback. Its later absence alone does not prove
that Beat crashed independently of launcher failure/cleanup.

This investigation established three distinct native Windows failures:

1. **Exited-process inspection and interrupted cleanup.** Instrumenting original
   main's native `WinDLL` calls observed `QueryFullProcessImageNameW` fail three
   times with **winerror 31** during exit/cleanup. The final error was
   `Cannot inspect PID 16772`; its stack was `main` finally -> `stop_services` ->
   `terminate` -> `_windows_terminate` -> `process_info`. Worker 21968 remained
   RUNNING while reports/Beat were STOPPED. Candidate verified-ownership stop
   cleaned the remaining verified processes. The original implementation queried
   image identity before interpreting process exit and aborted reverse-order
   sibling cleanup on the first inspection exception.
2. **A stale Beat pidfile.** A later candidate startup reported Beat STOPPED,
   **exit_code 73**. Its log named `celerybeat.pid`, containing PID 9360, while
   CIM found that PID absent. Installed Celery 5.6.3's `Pidfile.remove_if_stale`
   uses `os.kill(pid, 0)` and recognizes ESRCH/EPERM; the absent-PID probe on this
   host returned errno 22. The old lock was preserved. On Windows this probe can
   also terminate a live reused PID; it must not be used to inspect an old lock.
3. **Heartbeat replacement contention.** After initial readiness in a later
   run, Beat exited **1** at **2026-10-30 08:32:25 UTC / 14:02:25 Asia/Calcutta**.
   The traceback identified `LocalScheduler.tick` -> `write_service_heartbeat`
   -> `atomic_json` -> `os.replace(..., beat-health.json)`, ending in
   **PermissionError [WinError 5]**. A Windows reader can temporarily block file
   replacement. The exact competing handle in that incident was not captured;
   that explanation is consistent with the error and native held-reader tests,
   rather than proof of the original holder's identity.

These observations do not recover the error code or Beat shutdown cause from
the developer's earlier historical run. Error 31 is an inspection/cleanup defect;
Beat's pidlock exit 73 and heartbeat write error 5 are separate observed causes.

The first candidate harness loaded candidate parent code but original child
`scripts.dev`; its initial READY was partial validation. Final native acceptance
uses the candidate module in both parent and Celery children through an ignored
`C:\sbom\.dev-logs\native-code` overlay, preserving ownership ROOT `C:\sbom` and
leaving main's tracked files unchanged. The harness sets child PYTHONPATH to the
overlay followed by the original repository, while preserving managed settings.

Local redacted evidence: `.dev-logs/native_probe.py`, `native-win32-trace.log`,
`native-baseline.stdout.log`, `native_fixed.py`, `native-fixed.stdout.log` and
`native-restart.stdout.log`. Reproduction used the existing virtualenv:

```powershell
Set-Location C:\sbom
& .\.venv\Scripts\python.exe .\.dev-logs\native_probe.py
& .\.venv\Scripts\python.exe .\.dev-logs\native_fixed.py start --profile legacy --legacy-config managed
```

## Fix and ownership safeguards

Current source references are in [`scripts/dev.py`](../../scripts/dev.py):
Windows helpers/process inspection at lines 47/90/108, tree enumeration at 271,
atomic writes at 352, registration/status/cleanup at 466/514/527/558/614/646,
background readiness at 886/932/947/992/1010, process launch at 3721/3776 and main
at 4106. Line numbers may move with subsequent edits.

- Inspect identity and liveness on a pinned process HANDLE. Zero-time waits
  independently confirm exit before a query failure becomes absence. Capture
  the failed API and numeric error; access denied/unknown identity stays protected.
- Validate Toolhelp completion, parent links and creation ordering with checked
  snapshots and pinned identities. Preserve saved descendant proofs and tree
  uncertainty. Revalidate creation identity/executable and terminate each saved
  process through that same handle; remove broad `taskkill /T` operations.
- Continue cleaning independently verified services after one fails inspection.
  Preserve unresolved runtime records and the initiating startup error. Exact
  Popen-handle cleanup still runs if registration persistence fails; cancellation
  retains its original exception semantics.
- Report component, process status, known exit code, safe API/error code and log
  path. No credentials, connection strings, private keys or tokens are needed.
- Keep Beat's real pidfile enabled on Windows, scoped to the unique runtime
  instance under the exclusive launcher lock and existing Redis scheduler lease.
  Preserve the old pidfile; POSIX keeps its existing path.
- Accept a Windows redirector's worker heartbeat PID only when it is a saved
  descendant with matching current birth/executable. Worker control replies
  must still agree with that verified PID and its assigned queues.
- Retry atomic replacement only on Windows errors 5/32/33: 11 attempts, with at
  most 0.75 seconds of retry sleep. Keep the old complete file; persistent errors
  propagate. POSIX behavior and database/TLS/setup safeguards remain unchanged.

Primary sources: Microsoft documents [handle/PID lifetime](https://devblogs.microsoft.com/oldnewthing/20110107-00/?p=11803),
[`GetProcessTimes`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)
(exit-time output undefined while running),
[`WaitForSingleObject`](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)
(0 exited, 258 running, failure remains unknown),
[`Process32NextW`](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32nextw)
(error 18 is exhausted enumeration),
[`TerminateProcess`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess)
(asynchronous, error 5 can follow exit), and
[`CreateFileW` delete-sharing rules](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
for rename/replacement. [Celery 5.6.3's pidfile implementation](https://github.com/celery/celery/blob/v5.6.3/celery/platforms.py#L183)
and [Python's Windows `os.kill` semantics](https://docs.python.org/3.14/library/os.html#os.kill)
explain why signal 0 is not a safe Windows liveness probe.

## Changed files

| File | Change |
| --- | --- |
| [`scripts/dev.py`](../../scripts/dev.py) | Windows inspection/tree/termination safety, isolated cleanup diagnostics, Beat pidfile/redirector readiness and bounded atomic-write retry |
| [`tests/test_dev_windows_lifecycle.py`](../../tests/test_dev_windows_lifecycle.py) | **47 new cases** covering Windows races, ownership, cleanup, readiness, persistence and native process/file fixtures |
| [`tests/test_dev_lifecycle.py`](../../tests/test_dev_lifecycle.py) | Adapt existing identity/termination tests to same-handle Windows behavior |
| [`tests/test_dev_background.py`](../../tests/test_dev_background.py) | Give synthetic readiness fixtures complete process identities |
| [`.github/workflows/dev-launcher.yml`](../../.github/workflows/dev-launcher.yml) | Run new Windows regressions and native process fixtures on Windows CI |
| [This report](dev-launcher-windows-lifecycle.md) | Evidence, findings, actual validation results and exact guarded procedure |

## Actual validation results

| Check | Result |
| --- | --- |
| Python 3.14 targeted seven-file launcher/Windows/native suite | **288 passed, 16 skipped**, six Alembic warnings, 27.46s |
| Actual Python 3.12: new Windows + lifecycle + background tests | **139 passed, 16 skipped**, two plugin-config warnings, 13.65s; including real Windows API/file fixtures; pure pytest reused from 3.14 site-packages with plugin autoload disabled |
| Python 3.11 | Interpreter unavailable; grammar compilation passed, runtime compatibility remains unverified |
| pip check | No broken requirements |
| Ruff | All changed Python files clean using an isolated Ruff tool |
| Extended launcher suite | Candidate: **80 failed, 252 passed, 1 skipped, 6 errors**, 112.96s; untouched main: the same totals, 75.90s; all **86 failure/error node IDs match exactly**, with no candidate-only or main-only entries |
| Full bare pytest with isolated in-memory SQLite | Collection failed in `test_native_backup_acceptance`: frozen migration-100 byte hash; disk content differs from HEAD only by CRLF (`disk` normalized to LF equals `git show HEAD`); no migration edited |
| Full pytest with `--continue-on-collection-errors` | No progress for over eight minutes; canceled through its exact execution session with Ctrl+C, exit 1; full suite has not passed |
| Native final full-module startup/restart | All five components reached READY; queues/control and Beat progress verified; restart reached READY with a new instance and 22 prior saved identities absent, no UNKNOWN |
| Direct API/IAM/HTTPS probes | `/health` database available=true; `/ready/iam` ready=true; HTTPS `/native-sign-in` returned 200 using the existing verified certificate context |
| Browser | CUA opened HTTPS URL read-only, but navigation failed `net::ERR_CERT_AUTHORITY_INVALID`; existing browser trust remains unaccepted; no bypass/trust changes |
| Final verified stop | All **23 saved identities** absent: no still-owned or unknown processes; runtime state absent; API/frontend ports closed; infrastructure 5432/6379/8025 untouched; schema remains 103 |
| Preservation | Configuration/key/certificate comparison unchanged=true; original Beat pidfile preserved=true |
| Beat with patched atomic replacement | No shutdown observed during the completed candidate observation interval |
| Node 26/frontend | Google Fonts TLS issuer requests failed and fallback fonts were used; HTTPS eventually returned 200; this does not establish a Node-26-specific defect |
| macOS/Linux | Not executed on those hosts in this investigation; existing branches preserved and CI coverage retained |

Targeted Python 3.14 command, from the isolated worktree with
`DATABASE_URL=sqlite:///:memory:`, `TEST_DATABASE_URL=sqlite:///:memory:` and
`PYTHON_DOTENV_DISABLED=1`:

```powershell
& C:\sbom\.venv\Scripts\python.exe -m pytest -p no:cacheprovider --noconftest -q tests/test_dev_launcher.py tests/test_dev_lifecycle.py tests/test_dev_windows_lifecycle.py tests/test_dev_background.py tests/test_dev_main_merge.py tests/test_greenfield_windows_compat.py tests/test_dev_native_process.py
```

Actual Python 3.12 executable:
`C:\Users\ferozebasha.s\AppData\Local\Programs\Python\Python312\python.exe`.
The isolated test command was:

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = '1'
py -3.12 -c "import sys; sys.path.insert(0,'C:/sbom/.venv/Lib/site-packages'); import pytest; raise SystemExit(pytest.main(['-p','no:cacheprovider','--noconftest','-q','tests/test_dev_windows_lifecycle.py','tests/test_dev_lifecycle.py','tests/test_dev_background.py']))"
```

This exercises the actual 3.12 interpreter and Windows APIs while borrowing
pytest's pure Python implementation; it does not validate application dependency
binary compatibility under 3.12. Restore the shell's prior plugin-autoload value
after running the command.

The new tests execute the Windows adapter through a stateful WinDLL boundary,
including each query-stage exit, denied/unknown ownership, PID reuse, enumeration
failure, partial startup and sibling cleanup. Separate disposable native fixtures
exercise actual Windows process and file behavior. The workflow now runs native
process fixtures on Windows as well as POSIX. Skipped POSIX-specific cases do not
count as native Windows successes.

Full-suite SQLite configuration prevents `tests/conftest.py` from automatically
bootstrapping/upgrading/truncating a PostgreSQL test database. Development
`sbom_analyser_dev` was not supplied to destructive test fixtures. Do not obtain a
passing test count by resetting or migrating that database.

Final stop also exercised real fail-closed handling: cooperative launcher cleanup
encountered a temporary `OpenProcess` **winerror 5** on saved reports-worker child
15976, warned and retained its record. The same canonical stop caller acquired
the lock and retried with identity verification, then stopped the verified
reports worker. Final evidence in `.dev-logs/native-final-results.json` recorded
23 checked identities, `still_owned=[]`, `unknown=[]`, no runtime state,
configuration/certificate equality, preserved old Beat pidfile, closed
application ports and untouched infrastructure ports. No unknown process was
silently terminated or forgotten.

An intermediate targeted run failed while a fixture wrote `settings.ps1` before
launcher execution; the final seven-file rerun above passed. The cleanup-persistence
regression is included in the final count; cancellation semantics were preserved
in code, without a newly added cancellation test.

The extended-suite baseline comparison checked the actual FAILED/ERROR node-ID
sets in both directions, not only totals: all 86 match; candidate-only and
main-only sets are empty. The untouched main checkout remained tracked-clean.
Observed failure categories include the frozen migration-100 CRLF byte hash,
native Windows ACL/symlink privileges and POSIX API assumptions, and deliberate
Greenfield Windows upgrade refusal. No introduced failure was identified by
this comparison. These existing failures still prevent claiming that the entire
extended suite passes on Windows.

## Exact native Windows validation procedure

After review, use a checkout containing candidate code and its existing managed
configuration. The following examples use `C:\sbom`; during isolated investigation
use the documented `native_fixed.py` harness in place of `scripts\dev.py` so
parent and children execute candidate code. Never copy runtime state between
worktrees, rewrite its root, delete pidfiles or kill arbitrary PIDs. Keep startup
in foreground terminal A and management in terminal B. Use saved ports if they
differ from the defaults below. Normal scheduled tasks may write application
records while running; this is not a database-content immutability check.

1. In B inspect, then stop the original runtime through its verified manager:

   ```powershell
   Set-Location C:\sbom
   & .\.venv\Scripts\python.exe .\scripts\dev.py status --profile legacy --legacy-config managed
   & .\.venv\Scripts\python.exe .\scripts\dev.py logs --profile legacy --legacy-config managed --service beat --lines 80
   & .\.venv\Scripts\python.exe .\scripts\dev.py stop --profile legacy --legacy-config managed
   ```

   Retain/report UNKNOWN or UNOWNED records. CIM inspection may select recorded
   ProcessId, ParentProcessId, CreationDate and ExecutablePath, without printing
   CommandLine or environment/configuration objects.

2. In A run ordinary start; do not add setup, migration or initialization flags:

   ```powershell
   & .\.venv\Scripts\python.exe .\scripts\dev.py start --profile legacy --legacy-config managed
   ```

   Require all five services and full worker/scheduler/API/IAM/HTTPS readiness,
   or a component-specific actionable failure plus verified cleanup/reporting.

3. In B check READY, API/IAM and certificate-verified HTTPS; open the browser:

   ```powershell
   & .\.venv\Scripts\python.exe .\scripts\dev.py status --profile legacy --legacy-config managed
   (Invoke-RestMethod 'http://127.0.0.1:18000/health').database.available
   (Invoke-RestMethod 'http://127.0.0.1:18000/ready/iam').ready
   & .\.venv\Scripts\python.exe -c "from urllib.request import urlopen; from scripts import dev; response=urlopen('https://localhost:13000/native-sign-in', context=dev.legacy_https_context(), timeout=10); print('HTTPS', response.status); response.close()"
   Start-Process 'https://localhost:13000/native-sign-in'
   ```

   Require status exit 0/READY, both booleans true and HTTPS success. Report
   browser trust failures separately; do not bypass warnings, change trust or
   weaken TLS/IAM. Repeat start while A runs and compare the same five recorded
   birth identities, with no duplicate workers or Beat.

4. In B stop twice and inspect stopped status. Verify A returns, owned processes
   and verified descendants are gone, unrelated processes survive, API/frontend
   ports close, and PostgreSQL/Redis/Mailpit remain available:

   ```powershell
   & .\.venv\Scripts\python.exe .\scripts\dev.py stop --profile legacy --legacy-config managed
   & .\.venv\Scripts\python.exe .\scripts\dev.py stop --profile legacy --legacy-config managed
   & .\.venv\Scripts\python.exe .\scripts\dev.py status --profile legacy --legacy-config managed
   ```

   Status exit 3 is expected when stopped. In A run `restart` with the same flags,
   repeat step 3 in B, then finish with verified stop. Compare private saved
   configuration/key/certificate bytes before/after and report equality only.

Remaining limits: browser trust has not passed; full application tests have not
passed; Python 3.11 runtime, full application dependencies under Python 3.11/3.12,
and macOS/Linux execution remain unverified. Forced
Windows termination can leave per-instance Beat pidfiles, which remain harmless
preserved artifacts; no old PID is probed. Unknown descendants remain protected
and reported rather than being guessed into ownership. No database reset,
unsolicited migration, credential rotation, certificate/trust change or production
configuration change is part of this investigation.