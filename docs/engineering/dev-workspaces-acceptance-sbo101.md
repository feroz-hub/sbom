# SBO-101 acceptance ledger

This ledger separates contracts from actual application acceptance. Pure plans,
synthetic readiness, supplied engine JSON and a successful CI fixture never
establish a verified isolated application stack. No real provider/database,
privileged enrollment or trust operation is authorized by this file.

The implementation report and exact executed commands are in
[dev-workspaces-sbo101.md](dev-workspaces-sbo101.md). The privileged authority
proposal is [dev-workspaces-security-sbo101.md](dev-workspaces-security-sbo101.md).
Every draft remains subject to independent review; no merge or deployment.

## Required scenario status

In the tables below, “contract” means the indicated unit/synthetic or limited
native observation. “Not run” means the complete real scenario is not executed.
Do not convert those entries to PASS from code inspection alone.

| ID | Contract / limited observation | Complete real scenario |
| --- | --- | --- |
| T01 fresh clone | Fresh-checkout inventory/dispatch tests | Not run: fresh workstation setup |
| T02 prepared checkout | Legacy dispatch/setup regressions | Not run: candidate full-stack readiness |
| T03 two worktrees | Real disposable Git worktrees, separate registry records/IDs/port proposals | Not run: two applications |
| T04 concurrent UI edits | Worktree identity/dirty observations | Not run: parallel UI runtimes |
| T05 baseline/candidate comparison | Public comparison contract | Not run: browser/screenshots/traces |
| T06 mock frontend | Synthetic Next fixture preparation, exact-runtime adapter and inert public-theme extraction | Not run: real Node/HTTPS/browser visual runtime |
| T07 shared backend | Explicit registration, auth/session/tenant/TLS/compiler callback gates and linked source | Not run: actual approved backend/browser acceptance |
| T08 backend edit with another preview | Commit/config drift contract | Not run: parallel runtimes |
| T09 two backend stacks | Unique namespace/target contract | Not run: approved independent providers |
| T10 shared database selection | Dedicated target/role refusal contract | Not run: negative live database access |
| T11 cookie collision across ports | Unique hostname proposal; no port-only isolation claim | Not run: TLS/browser/callback verification |
| T12 unknown port owner | Legacy ownership regressions; proposals do not reserve ports | Not run: isolated bind/rebind race |
| T13 stale/corrupt runtime | Legacy PID reuse/unknown ownership tests; registry corruption refusal | Not run: candidate crash/recovery |
| T14 worker/Beat shutdown | Existing Windows regressions plus candidate Runtime partial-startup cleanup of four real fixture helpers | Not run: real isolated workers/Beat or active jobs |
| T15 queue/Beat collision | Instance namespace/launch contracts | Not run: two live brokers/schedulers |
| T16 unauthorized migration | Nonunit/test/schema operations gated; existing migration guards | Not run: destructive/migration operation |
| T17 protected DB fixtures | Application conftest excluded; sanitized SQLite sentinels | Prohibited without target-specific approval |
| T18 missing config/dependency prep | Actual read-only plan independent of private config; dependency root access-policy refusal | Not run: real package installation |
| T19 private configuration reuse | Concrete new-only private bundle publication and strict known-receipt reuse through protected bindings; unknown/partial material is retained, with no original-file import or silent rotation | Not run: real generation, publication or reuse of approved instance material |
| T20 missing/expired/untrusted TLS | Concrete standalone certificate and bundle adapters; key/CA/SAN/expiry validation, protected receipt reuse and custom-CA/hostname checks; separate browser trust required | Not run: real instance material generation, verified service TLS or approved browser/OS trust |
| T21 Next dependency/compiler state | Dependency policy/stamps; existing native compiler guard | Not run: isolated application compiler readiness |
| T22 branch changes during runtime | Commit drift invalidates plans | Not run: running instance drift |
| T23 API compatibility | Comparison explicitly leaves compatibility unverified | Not run: contract/browser acceptance |
| T24 unregistered external callback | HCL configuration/prerequisite contract | Not run: approved IdP registration |
| T25 Native admin absent/pending | Pure status state machine; closed live gate | Not run: approved database inspection/enrollment |
| T26 tenant boundaries | Existing authorization preserved | Not run: isolated tenant workflows |
| T27 mail/background isolation | Concrete provider/SQL preparation adapters, TLS/auth material and separate broker/session credentials; instance queues, Beat state, mail targets and app consumers wired; passive heartbeat observation separated from active startup control | Not run: real providers, messages/jobs, scheduler persistence or cross-instance negative access |
| T28 parallel agent contracts | Engineering Lead confirmed NEXUS inactive; explicit file ownership | No concurrent independent-agent UAT |
| T29 interrupted/full-disk setup | Synthetic pending journal, retained partial artifacts and publication errors | Not run: real installer/disk exhaustion |
| T30 Windows junction/ACL/AV | Native temporary junction/ACL/publication tests; earlier dependency-root untrusted-grant refusal and current private-home owner-policy refusal are distinct observations | Not run: controlled AV interference or approved private-home resolution |
| T31 secret leakage | Sanitized outputs and synthetic secret tripwires | Not run: real confidential data, intentionally |
| T32 resource pressure | Bounded discovery/helpers/output; host observation only | Not run: simultaneous stacks/resource exhaustion |
| T33 deleted running worktree | Canonical/registry uncertainty refusal contract | Not run: live removal/recovery |
| T34 integration/rebase changes | Public source/controller/manifest fingerprints | Not run: active rebase with running stack |
| T35 platforms | Incremental Windows/macOS/Linux, Python3.11/3.12 and Node22/26 CI matrices; local Windows Python3.14.6 runtime/native selection: 70 passed; final O–Q repair reruns pending | Not run: complete native application/authentication matrix or final exact-head CI acceptance |
| T36 shared service shutdown | Protected services never adopted or stopped | Not run: failure injection |

| ID | Native bootstrap contract | Complete real scenario |
| --- | --- | --- |
| A01 existing admin | Guidance never creates/resets another | Not run: approved DB status |
| A02 fresh installation | Prerequisite/onboarding plan; live gate closed | Blocked: independent authority approval |
| A03 pending enrollment | Preserve reservation; no duplicate | Not run: live delivery/recovery |
| A04 completed enrollment | Never reopen completed reservation | Not run: approved DB status |
| A05 concurrency | Pure concurrent guidance has no mutation capability | Not run: transactional concurrent enrollment |
| A06 missing authority | Direct invocation/closed guard negative tests | Blocked: no enabled authority protocol |
| A07 target/config drift | Context/plan revalidation refuses drift | Not run: live signed capability invalidation |
| A08 SMTP/origin | Exact target/origin prerequisite contracts | Not run: real approved delivery/TLS |
| A09 activation/password | Existing HTTPS activation service unchanged | Blocked: no live enrollment/activation approval |
| A10 atomic grant/audit | Existing approved service unchanged | Not run: disposable transaction acceptance |
| A11 rollback | No new privileged mutation path | Not run: disposable failure injection |
| A12 resend | Closed guard; guidance cannot create duplicate | Blocked: independent resend authority |
| A13 HCL separation | External mode gives IdP approval guidance, no Native password flow | Not run: approved external identity |
| A14 staging/production | No enablement or provisioning implemented | No staging/production action authorized |
| A15 tenant administration | Existing permissions unchanged | Not run: authorized disposable tenant UAT |

## Implemented adapters and remaining integration gates

The source includes executable dependency preparation, private bundle and TLS
preparation, protected bindings, Compose/engine and restricted SQL preparation,
instance Runtime/readiness, mock preview control and private visual-artifact
adapters. Their synthetic tests do not establish that a real target, installed
engine or trusted browser has passed acceptance. A missing company policy blocks
real provisioning; it does not mean these source adapters are absent.

| Implemented source | Required before a real acceptance claim |
| --- | --- |
| New-only private material and continuity receipts (`dev_workspace_bundle`, `dev_workspace_certificates`, `dev_workspace_bindings`) | Exact credential/certificate consent, an approved private home, real generator/validation and protected receipt publication/reuse evidence; no original-file adoption |
| Provider, engine, journal and database preparation adapters | Approved engine/images/nonroot and data policies, exact disposable resources/actions, live creation identities and actual-session TLS-peer attestation; a policy JSON or engine inspect JSON is not authority |
| Runtime and listener-bound API/IAM/frontend readiness | Actual owned process/listener evidence before and after checks, correct target/schema and mode prerequisites; unsupported host-forwarder mapping remains BLOCKED, including container guest PID versus Windows Desktop host forwarding |
| Background readiness and resource isolation | Approved real broker/mail targets, exact worker/queue/Beat progress and independent-instance failure/shutdown evidence; read-only status uses protected heartbeats, never Celery control messages |
| Mock preview and Chromium visual adapters | Actual frontend/compiler readiness, separate live browser/OS trust integration, new private browser state and explicit synthetic-artifact consent; screenshots do not prove API/login/functional acceptance |
| Native/HCL onboarding guidance | Native mutation gate remains closed pending independently approved target-bound authority and disposable activation acceptance; HCL grants require the IdP owner's procedure |

Public mock setup/start is implemented, subject to its concrete prerequisites.
Public isolated/shared start remains blocked until reviewed live bindings exist.
No real provider, database, Node/application/browser start, message, administrator
operation or trust modification was performed for this ledger update.

The most recently recorded candidate read-only mock setup check returned
`CONTROL_HOME_ACCESS_UNVERIFIED`, component `private-home`, category
`OWNER_MISMATCH`, operation `EqualSid`, with `winerror=null` and no plan. This is a
confirmed owner-policy refusal. It is not evidence of an untrusted DACL grant,
an access-denied Win32 code, or PostgreSQL failure. The earlier dependency-root
`GetAce / UNTRUSTED_GRANT` observation concerns a different path and check. Neither
check authorizes ACL/owner repair; preserve the existing state and obtain the
Engineering Lead/IT decision on an approved private location. The integration
review traced the owner refusal to policy: the Windows profile directory is owned
by `NT AUTHORITY\SYSTEM` by default, and anchor checks require the token user as
owner. The decision needed is whether SYSTEM/Administrators-owned anchor
directories are acceptable; see the security review.

## Integration review into main

The complete SBO-98 → SBO-101 chain (#49–#72, candidate `0e83e22`) was merged
onto `main` `fc59432` with history preserved; the merge had no conflicts and
retains SBO-97. Independent review then confirmed and fixed four defects that
the synthetic suites and CI could not see:

- Every 64-bit Windows defines `ProgramFiles(x86)`; the resolver refused the
  inherited process snapshot, so Legacy `start`, `setup`, `diagnose` and Native
  status failed on any Windows workstation.
- The Windows venv `python.exe` is a redirector, so setup consent recorded by the
  launcher was refused after the handoff (`SETUP_APPROVAL_INVALID`).
- One blocked sibling worktree (bare, pruned or unverifiable) blocked default
  `start`/`stop`/`status` in every checkout of the repository.
- Guided setup read a `family` option the CLI never defines, so
  `workspace setup --mode mock --auth native --check` always planned
  `SETUP_SELECTION_REQUIRED`.

Windows hosts with `LongPathsEnabled=0` fail about 47 workspace/bundle/bindings
tests when pytest's default temporary root is deep (user profile temp path plus
`.sbom-dev\repositories\<sha256>\...`). Run them with a short `--basetemp`; the
same tests pass there and on hosted Windows CI. This is a test-path limit, not
evidence for the real `~/.sbom-dev` location.

None of the NOT RUN/BLOCKED scenarios above changed status: the integration adds
no real provider, database, application, browser, trust or administrator
evidence.

## Executed Windows interpreter and cleanup evidence

From `C:\sbom\.windows\worktrees\SBO-101-workspace-plan`, using the existing
sanitized harness, unique disposable scratch files and `--noconftest`:

```powershell
& C:\sbom\.venv\Scripts\python.exe -B `
  C:\sbom\.windows\worktrees\SBO-98-component-env\.dev-logs\safe_pytest.py `
  tests/test_dev_native_process.py tests/test_dev_workspace_runtime.py `
  tests/test_dev_workspace_runtime_native.py
```

Result: **70 passed in 23.12s**, native Windows/Python **3.14.6**. Ruff and
`git diff --check` passed for the three changed runtime/test files. Python3.11
grammar checks passed for those files and the embedded bootstrap; this is not
an executed Python3.11 acceptance run.

The native fixture started four disposable Python helpers through the actual
instance Runtime adapter, deliberately refused frontend construction and verified
cleanup of all four. It no longer waits for helper workload inside its `Popen`
fixture. Production synchronization instead waits for private nonce-qualified
metadata emitted by the final interpreter before application import. Registration
always checks the original `Popen` independently; a signal never proves PID
ownership, readiness or operator authority. Signal files are retained.

Regression cases cover exit, bounded timeout/cancellation, forged or incomplete
signals, PID reuse, access denied/error 5, helper-proof drift and protected unknown
records. Native testing confirmed different Windows path/handle creation-time
metadata and a CRT `errno=13` read race while the private writer holds its
exclusive handle. Full path stamps/content proofs remain enforced. Only that
bounded read is retried after private ACL validation; explicit denial fails
closed and persistent unreadability is reported. No canonical termination or
ownership rule was relaxed.

This proves fixture process behavior, not real Celery tasks, API/IAM, PostgreSQL,
Redis, Mailpit, browser or administrator acceptance. macOS/Linux confirmation of
the interpreter synchronization is **pending exact-head R CI at publication**.
The final repaired O–Q heads each have 20 successful check-runs, zero failures
or pending checks, as do A–N. Those results do not cover unpushed R changes or
establish full native application acceptance. Consult R's PR validation and
exact-head checks for subsequent results.

## Approval-dependent native Windows procedure

Current safe commands from the candidate checkout:

```powershell
python -B scripts/dev.py workspace list --json
python -B scripts/dev.py workspace plan --mode isolated --auth native --json
python -B scripts/dev.py workspace plan --scope dependencies --json
python -B scripts/dev.py workspace setup --mode mock --auth native --check --json
python -B scripts/dev.py workspace status --json
python -B scripts/dev.py workspace diagnose --json
python -B scripts/dev.py workspace logs --service frontend --lines 80 --json
```

Inspect the returned blockers; preserve unknown records. Do not run the old
profile's provisioning to bypass an isolated-instance blocker. Do not delete a
runtime file or kill a PID found on a port. These commands inspect metadata,
plans, checks or bounded log metadata; they do not approve preparation. An exit
1/BLOCKED result must retain its specific diagnostic. Current metadata and
provider plans are not application readiness. Do not run `prepare`, unchecked
`setup`, `start`, `restart` or privileged bootstrap as part of this read-only
procedure. The test command above is a separate disposable fixture validation,
not a status command against the protected application.

Before real acceptance, the Engineering Lead/IT/DBA must approve exact disposable
engine identity, image digests/UID contracts, two instance/resource plans,
restricted role/credential creation, database initialization/schema actions,
isolated mail transport, leaf material and any OS trust changes. Review the
implemented provider/private-material/Settings/Runtime/TLS adapters and complete
the missing live transport, browser-trust and public-binding integrations for
the selected mode. Their presence does not supply approval; approval or inspect
JSON does not substitute for live identity verification.

Then freeze the candidate commit and public plan fingerprints. Record protected
baseline process identities through its own manager and file metadata without
changing or copying private material. Prepare each approved dependency category;
verify actual package/compiler state. Provision only the approved labelled
resources, verify engine/network/volume/container identities and loopback binds,
and test restricted roles plus negative cross-instance access before authorized
schema preparation. Database initialization and each migration remain separate
explicitly approved actions with exact database confirmation; ordinary startup
must not perform them.

Start both through the reviewed instance Runtime adapter. Require exact worker
PIDs/queues, one progressing Beat, a read-only exact-target/schema check, the API
root identity and mode-appropriate IAM readiness,
hostname/chain-verified HTTPS and separate browser contexts. Exercise approved
isolated jobs/mail/session/rate-limit/tenant flows. Cause one approved fixture
failure, inspect its redacted diagnostics, recover it and stop only that instance.
Revalidate PID birth/executable/tree immediately before every termination. Keep
unknown records and volumes. Verify the other instance and protected baseline
remain healthy. Repeat start/restart/stop and compare exact resources afterward.

Real Native creation/resend additionally requires approval of the independent
authority design and disposable A01–A15 acceptance. Human passwords are chosen
only on verified HTTPS activation pages. HCL first-user grants require the IdP
owner's separate procedure. None of these real operations has run in this task.

Before marking any complete scenario PASS, retain the exact candidate commit,
public plan fingerprints, all required exact-head CI outcomes, independent review
and target-specific approvals. Re-run the native Windows/macOS/Linux and both
authentication-mode matrix with approved disposable resources. Record actual
commands, exit codes, safe diagnostics, fresh ownership/readiness observations,
restart/repeated-start/stop outcomes and absence of verified-owned orphans. A
custom client CA is not browser/OS trust. Do not use the API `/health` endpoint as
a read-only probe: its repository-loading path can perform seed writes; the
readiness adapter uses the API root identity plus explicit target/schema and IAM
checks. Keep confidential logs/artifacts private. Any missing evidence stays
NOT RUN/BLOCKED; no full acceptance, merge or deployment is claimed here.
