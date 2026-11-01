# SBO-102 status diagnosis and validation

Date: 2026-11-01. Status inspection: **fixed and verified from the issue worktree**.
Enrollment: **design only; security gates unchanged**. The running `C:\sbom`
checkout has not received the fix, and no merge/deployment is authorized.

## Baseline and conflict checks

Verified remote: `https://github.com/feroz-hub/sbom.git`. Engineering Lead selected
latest `dev` and confirmed no unrecorded overlapping office work. Fetch and
subsequent remote checks found:

- `dev`: `cd8440586fb249d06eb00522f32ea3012be73bb9`.
- `main`: `f6bb19d2c5dfd3b1cddbbdc260b28d33082f7b4c`; one merge commit ahead.
- No other remote branches (including ATLAS/NEXUS branches), no open PRs, no
  pre-existing additional worktrees, and a clean running checkout.

Worktree: `C:\Users\ferozebasha.s\.codex\worktrees\sbo-102-native-admin-onboarding\sbom`.
Branch: `fix/SBO-102-native-admin-onboarding`, based on the approved `dev` SHA.
The final commit SHA and draft PR URL are supplied in the delivery response/PR;
this committed report cannot contain its own final commit SHA.

## Confirmed root cause

The exact original command, under normal Windows user access, returned exit 1:

```powershell
.\.venv\Scripts\python.exe -B scripts/dev.py setup --profile legacy --legacy-config managed --native-admin-status --confirm-database sbom_analyser_dev
```

A thread-aware trace emitted only fixed function names, line numbers and exception
types: `discover:94 DiscoveryError`, then `_inspect_native_enrollment:435
DiscoveryError` at the approved baseline. This occurs **before importing psycopg
or connecting to PostgreSQL**. The catch-all at original `dev_operator.py:506`
misreported migration discovery as `OPERATOR_DATABASE_INSPECTION_FAILED`.

`git ls-files --eol alembic/versions` showed LF in Git and CRLF in the Windows
checkout. All three immutable revisions (100, 101, 102) failed their raw-byte
hash comparisons and matched the existing expected hashes after CRLF-to-LF
conversion. No migration content or expected hash was changed.

Current source references:

- `scripts/greenfield_migration_graph.py:96`: compare frozen content in LF form;
  retain raw hashes in `Revision.sha256`, execution verification and SourceLock.
- `scripts/dev_operator.py:437`: migration discovery precedes connection;
  `:520` now distinguishes source/driver failures and labels query operations.
- `scripts/dev_operator.py:176`: dependency-import failures no longer claim the
  saved Native keys are invalid. System Python lacks cryptography and psycopg;
  the project venv has both. No automatic environment installation or re-exec was
  added to the deliberately inert status boundary.

## Changed files

| File | Reason |
| --- | --- |
| `.gitattributes` | Keep new migration checkouts in LF form. |
| `scripts/greenfield_migration_graph.py` | Accept equivalent existing CRLF checkouts for frozen-content comparison, retaining exact-byte drift protection. |
| `scripts/dev_operator.py` | Fixed, redacted operation diagnostics and distinct missing-dependency reasons. SQL, confirmation, read-only options and deadlines remain unchanged. |
| `tests/test_dev_operator.py` | Real LF/CRLF discovery with mocked PostgreSQL; missing/invalid credentials, dependency errors, exact refusal codes, per-operation errors, redaction and deadline coverage. |
| `tests/test_dev_operator_cli.py` | Run both copied CLI entrypoints under the active venv and base/system interpreter with no site packages or bytecode writes. These are isolated CLI stubs, not live database tests. |
| `tests/test_greenfield_auto_migrations.py` | LF/CRLF equivalence, rejection of edits to all frozen migrations and raw-byte SourceLock invalidation. |
| `docs/engineering/windows-local-onboarding.md` | Correct venv command and safe interpretation of status/error results. |
| `docs/engineering/sbo-102-enrollment-readiness-design.md` | Proposed evidence, approval, replay/concurrency and activation design; pending independent security approval. |
| This report | Reproduction, validation, limitations and delivery evidence. |

No auth service, application settings, database model, migration body, API
contract, private configuration or enrollment gate was changed. The shared
migration discovery consumer is covered by its regression suite. Exact database
confirmation, localhost targeting, libpq override refusal, read-only transactions,
3-second connection/statement limits, 250ms lock limit, 5-second idle transaction
limit, 8-second reporting deadline and rollback/close behavior remain intact.

## Tests actually run

All pytest commands ran from the issue worktree using the existing project venv.
`--noconftest` excluded repository database fixtures; optional plugin autoload and
bytecode writes were disabled. All database/worker/enrollment test operations in
these suites use test doubles. No disposable live database was provisioned.

Final command:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
& C:\sbom\.venv\Scripts\python.exe -B -m pytest --noconftest -p no:cacheprovider -q -k 'not symlink' tests/test_dev_operator.py tests/test_dev_operator_cli.py tests/test_greenfield_auto_migrations.py tests/test_dev_native_enrollment.py tests/test_dev_native_enrollment_cli.py tests/test_dev_diagnose.py tests/test_dev_config.py
```

**PASS: 528 passed, 1 deselected, 2 warnings (44.49 seconds).** The warnings are
unrecognized pytest `timeout`/`timeout_method` settings because optional plugin
autoload was disabled. They do not indicate application timeout controls changed.

Earlier attempts, retained for accuracy:

- The five core suites without `--basetemp` first encountered sandbox temp-file
  permission errors and were interrupted. A repeat with `-x` and
  `--basetemp=C:\Users\ferozebasha.s\.codex\worktrees\sbo-102-native-admin-onboarding\sbom\.sbo102-tests`
  confirmed `WinError 5` at fixture-directory creation. No test assertions ran in
  that repeat. Normal user access resolved the fixture access failure.
- The five core suites with `-x`, normal user access and no `-k` exclusion:
  **107 passed, 1 FAIL**. The existing
  `test_bad_graph_or_frozen_history_refuses[symlink]` could not create its fixture
  (`WinError 1314`, missing Windows symlink privilege). Its test/source was not
  weakened. This one test is deselected in final results and still needs a host
  with symlink privileges. No Windows policy or privilege was changed.
- The five core suites with `-k 'not symlink'`, before the added deadline test:
  **328 passed, 1 deselected**.
- `git diff --check`: **PASS**. AST parsing of all five changed Python files:
  **PASS**. `python -B -m ruff --version`: unavailable (`No module named ruff`);
  lint execution **SKIP**, no packages installed.

## Read-only live verification

The worktree has no copied private configuration. To exercise the patch with the
existing configuration in place, the following explicit harness imported code
from the worktree and pointed only the launcher roots at the original checkout:

```powershell
@'
import sys
from pathlib import Path
from scripts import dev
dev.ROOT = Path(r'C:\sbom')
dev.CONFIG = dev.ROOT / '.env.dev.local'
dev.VENV = dev.ROOT / '.venv'
sys.argv = ['scripts/dev.py', 'setup', '--profile', 'legacy', '--legacy-config', 'managed', '--native-admin-status', '--confirm-database', 'sbom_analyser_dev']
raise SystemExit(dev.main())
'@ | C:\sbom\.venv\Scripts\python.exe -B -
```

**PASS, exit 0:**

```json
{"bootstrap_enabled": false, "code": "ENROLLMENT_REQUIRED", "enrollment_required": true, "existing_users_present": false, "live_readiness_verified": false, "platform_admin_available": false, "state": "NOT_STARTED"}
```

The same harness with `C:\Python314\python.exe -B -` produced the expected
`OPERATOR_NATIVE_DEPENDENCIES_REQUIRED`, exit 1, with guidance to use the existing
venv. This is a correct dependency refusal, not a successful system-Python
database inspection. The original running checkout remains clean and unpatched;
rerunning its original command before integration will still show the old defect.

## Remaining approvals and risks

`scripts/dev_native_enrollment.py:197` and `:427` still enforce the readiness
contract gate. The readiness design is a proposal, not independently security
approved. Approval signer/key distribution, runtime peer attestation, exact server
identity, configuration leases, durable approval replay records and mailbox
access policy remain explicit design decisions. The local Mailpit recipient path
is security-sensitive because mailbox access conveys the activation credential.

Enrollment mutation, activation-email delivery, replay/concurrency integration
testing and privileged-user creation: **SKIP — no separately approved disposable
environment or implementation authorization**. No merge, deployment, migration,
manual SQL edit or account creation occurred. The next step is Engineering Lead
review of the draft status fix and the proposed readiness design, followed by
separate explicit approval before implementing any privileged workflow.
