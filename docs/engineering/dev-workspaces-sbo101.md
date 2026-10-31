# SBO-101: implementation evidence and approval boundaries

Delivery state: safe planning, controlled dependency preparation, restricted test
orchestration, closed onboarding guidance and read-only observations are
implemented in incremental drafts. Full isolated application execution, mock/
shared runtime previews, real private configuration/TLS/provider adapters and
live administrator onboarding remain **incomplete / BLOCKED**. No independent
review, merge, deployment or full native acceptance is claimed by unit/CI results.

## Baseline and coordination

The Engineering Lead authorized `https://github.com/feroz-hub/sbom.git`, including
publication there, and confirmed NEXUS had no active work. The integration
dependency is the unchanged SBO-98 top branch `feature/SBO-98-native-enrollment`,
commit `73d29949b31fa3564a56043128bde7118e804ede`. Its six draft PRs (#49–#54)
remain separate. Remote `main` was
`fc59432a4eec46f009b3809bd751e510d3b2887c` during preflight; its additional CVSS
UI change does not supply the SBO-98 helpers. No old `fcc8731` baseline is used.

The original checkout and ten pre-existing worktrees were clean at preflight.
Implementation uses `.windows/worktrees/SBO-101-workspace-plan`, branch
`feature/SBO-101-workspace-plan`. Git cleanliness does not establish agent
availability. No database, provider, certificate, credential or historical
runtime record was changed. The Linear connector is unavailable; progress text
must be posted to the real SBO-101 issue by the Engineering Lead.

## Existing versus required capability

| Capability | Existing integration baseline | This foundation | Remaining work |
| --- | --- | --- | --- |
| Configuration | Immutable SBO-98 resolver; profile and component projections | Public manifests only; no private configuration adoption | Approved per-instance private configuration |
| Diagnostics | Read-only `diagnose`; deprecated `doctor` alias | Read-only Git/registry inventory and public plans | Provider/schema/worker/HTTPS evidence bound to each instance |
| Process safety | Birth/executable/tree verification; cooperative Windows worker shutdown | Existing lifecycle code unchanged | Connect verified instance resources to existing lifecycle |
| Worktrees | Git worktrees do not imply application isolation | Authoritative Git discovery and canonical filesystem identities | Runtime branch-drift recovery |
| Ownership | Per-launcher runtime records | Protected, locked, atomic public instance registry | Provider/process attestations; a descriptor is not authority |
| Dependencies | Existing controlled setup also needs private configuration | Missing configuration permits dependency-only proposals | Independently consented installation and freshness checks |
| Data services | Greenfield fixed resources; Legacy fixed saved providers | Unique proposed names/ports, no existing service adoption | Approved independent providers and restricted database roles |
| Auth/browser | Native/HCL prerequisites and fail-closed enrollment | Unique proposed HTTPS hostname per instance | Valid TLS, trust and registered callbacks; isolated browser contexts |
| Privileged onboarding | Native create/resend adapter closed | Gate preserved | Guided status; independently approved authority before live enrollment |

## PR A: architecture, registry and safe planning

The new modules are `dev_workspace` (bounded local Git discovery),
`dev_instance_plan` (pure immutable proposals), `dev_instance_storage` (explicit
private-directory creation), `dev_instance_registry` (read-only inspection and
consented metadata publication), and `dev_workspace_cli` (the existing launcher's
additive `workspace` hierarchy). Each has a focused test module.

The registry defaults to
`~/.sbom-dev/repositories/<repository-id>/instances`, outside shared Git ACLs.
Repository and worktree IDs bind canonical filesystem identities, not directory
names or branches. Discovery refuses configured Git filters, ambiguous roots,
redirected manifests and incomplete inventory. Reads do not create directories,
locks or records. The writer requires exact interactive consent, rechecks the
plan and controller inputs, preserves unknown artifacts, and uses compare-and-
swap revisions. Creation never replaces a raced destination. Publication
uncertainty is reported and retained for review.

The descriptor contains public identities and proposed resources only. It
cannot claim verified ownership, live-operation authorization or readiness.
Resource permissions, container/network identity and database grants must
independently enforce isolation; a user-controlled launcher is not a security
boundary against the same OS user.

### Executed local evidence

Environment: native Windows, Python 3.14.6; existing Python 3.12.10 also tested.
Only explicit source/unit lists ran. The established issue-local harness starts
pytest with sanitized environment, SQLite in-memory sentinels, disabled dotenv,
disabled plugin autoload and `--noconftest`; fixtures use unique temporary roots.
`tests/conftest.py` was excluded because it can migrate/truncate PostgreSQL.

From this implementation worktree:

```powershell
& C:\sbom\.venv\Scripts\python.exe -B `
  C:\sbom\.windows\worktrees\SBO-98-component-env\.dev-logs\safe_pytest.py `
  tests/test_dev_workspace.py tests/test_dev_instance_plan.py `
  tests/test_dev_instance_registry.py tests/test_dev_instance_storage.py `
  tests/test_dev_workspace_cli.py tests/test_dev_launcher.py `
  tests/test_dev_main_merge.py tests/test_dev_diagnose.py --timeout=60
```

Result: **441 passed, 13 skipped, 6 existing Alembic deprecation warnings**.
Windows skips cover POSIX permission/rename semantics and newline filenames.
An earlier mistyped test filename caused collection refusal and ran zero tests;
the corrected command above passed. This is not application/DB acceptance.

The five new test modules also passed on Python 3.12.10: **211 passed,
13 skipped**. The entire inspected Windows-applicable unit list from
`.github/workflows/dev-launcher.yml`, plus `tests/test_dev_native_process.py`,
passed on Python 3.14.6: **1,564 passed, 41 skipped, 6 warnings**. That run
preceded the discovery-concurrency refinement below; the affected tests were
rerun afterward. No unreviewed application-wide pytest collection ran.

Real disposable Git fixtures created two linked worktrees and separately
registered public proposals. Their IDs, proposed ports and namespaces differed.
They checked native ACL/locking/publication paths, Git-filter refusal and index
bytes/mtime preservation. Application/provider/socket mutation tripwires stayed
untouched. OS-specific tests are distinguished from simulated failure tests.

Ruff and `git diff --check` passed. Python 3.11 grammar parsing passed; this is
syntax compatibility, not execution on a Python 3.11 runtime. AST comparisons
verify that `Runtime`, process inspection and existing startup helpers remain
identical to the integration dependency. No macOS/Linux native test was run on
this Windows host. PR A is draft [#55](https://github.com/feroz-hub/sbom/pull/55),
commit `6571e0e85e639a8040098c226176d54479c4905a`. Its
[pull-request CI](https://github.com/feroz-hub/sbom/actions/runs/41176063817)
and push CI completed successfully: four launcher OS/Python jobs and six real
frontend-fixture OS/Node jobs per run, including Python 3.11 and Node 26.1.0.
Independent native full-stack acceptance is still required.

### Exact read-only checks

```powershell
python -B scripts/dev.py workspace list --json
python -B scripts/dev.py workspace status --json
python -B scripts/dev.py workspace plan --mode isolated --auth native --json
```

Run with transport-only environment and no application imports, these inspect
Git and public source metadata. A blocked plan is expected until configuration,
provider and operational approvals exist. A plan never reserves an OS port.
No `prepare` command has been run against the actual user's registry.

An initial serial discovery under concurrent test load reached its 30-second
budget and safely reported `GIT_DISCOVERY_TIMEOUT`. Native per-worktree probes
now run with at most four concurrent helpers, retaining that shared deadline,
per-command limits and final inventory recheck. A regression verifies the bound
and Git result order. The affected Git/CLI tests passed afterward: **46 passed,
2 skipped**. Repeated actual inventory returned PASS for 11 worktrees in 18.42s;
planning completed in 16.34s and returned its explicit missing-configuration and
approval blockers. All stderr was empty. Slow/unresponsive filesystems can still
produce a bounded BLOCKED result; the launcher does not silently omit worktrees.

## PR B: dependency preparation and provider abstraction

Adds `dev_workspace_dependencies` and `dev_workspace_provider`, their focused
tests, CLI category consent and ignored same-volume npm attempt directories.
Existing setup/start commands retain their previous configuration/security gates.
Dependency preparation is independent of `.env.dev.local`: its read-only plan
uses public source/tool identity, and its user-level writer requires exact
interactive consent plus repeated input verification. Unknown or partial targets
are retained, not adopted, repaired or deleted. Successful dependency outcomes
explicitly leave compiler/application readiness unverified.

The provider library supplies immutable, image-digest/nonroot-policy proposals
and strict normalized inventory comparisons. It executes no engine command,
generates no credentials and never treats supplied JSON/labels as independent
ownership. An engine-specific ownership adapter is still required in a subsequent
source increment; its development does not wait for installed engines or policy
approval. PostgreSQL's first container boot itself can
initialize data, so provisioning cannot precede target-specific database approval.

Actual native read-only `workspace plan --scope dependencies --json` returned
exit 1 with `private_configuration_required=false`, both dependency actions and
the precise blocker `DEPENDENCY_ROOT_ACCESS_REVIEW_REQUIRED`. A safe native ACL
inspection identified `GetAce / UNTRUSTED_GRANT` (no OS error code). The worktree
has a write grant outside the adapter's trusted principals. No permissions were
changed and no installer ran. Use an approved safe-permission checkout or IT
review; do not repair the protected root automatically.

One pre-final combined test run produced 402 passed and one policy failure:
the approved npm lock has 154 entries without both `resolved` and `integrity`.
The adapter was corrected to preserve exact version pins for those entries while
forcing the registry and strict TLS; partial or unsafe explicit metadata remains
refused. This is not complete artifact-hash attestation. Package manifests and
lockfiles were unchanged. Tests and read-only evidence never used real
pip/npm installation, container creation or database access.

Final Python 3.14.6 command (same safe harness/worktree as PR A):

```powershell
& C:\sbom\.venv\Scripts\python.exe -B `
  C:\sbom\.windows\worktrees\SBO-98-component-env\.dev-logs\safe_pytest.py `
  tests/test_dev_workspace_dependencies.py tests/test_dev_workspace_provider.py `
  tests/test_dev_workspace_cli.py tests/test_dev_setup.py `
  tests/test_dev_diagnose.py tests/test_dev_launcher.py --timeout=60
```

Result: **406 passed in 65.15s**. Python 3.12.10, using its existing interpreter
with the same harness and the dependency/provider test files: **95 passed in
19.14s**. Ruff passed for the six Phase B source/test files; all installers and
engine inventories in tests were synthetic. Native temporary filesystem and
ownership paths were exercised. This is not package/network/provider acceptance.

A subsequent read-only source review found npm's built-in config can override
scoped registries despite isolated user/global config. A focused follow-up binds
that tool-local input and rejects unsupported directives before installer
execution, without exposing values or hashing raw comments into public plans.
This review correction changes only the dependency adapter/tests and evidence;
it does not alter package manifests or install packages.
After that correction, the same safe harness ran dependency/provider/CLI tests:
**146 passed in 74.10s** on Python 3.14.6. The changed dependency tests on
Python 3.12.10: **48 passed in 51.39s**. Ruff passed. All installers remained
synthetic. PR B is draft [#56](https://github.com/feroz-hub/sbom/pull/56).

## PR C: isolated launch contracts, live execution BLOCKED

Adds `dev_workspace_lifecycle`, pure `app/dev_instance` names, matching tests and
actionable CLI refusal for registered-instance start/stop/restart. Immutable
snapshots check exact dedicated targets, roles, Redis databases, paths, origins,
auth flags, key separation and readiness prerequisites. Public serialization
excludes private values and secret hashes. Commands are placeholders; cleanup
only requests the existing Runtime to independently revalidate recorded
identities. Unknown/reused/unregistered identities remain protected, including
partial-start and lost-configuration cases.

This increment **does not implement a full-stack executor**. Required engine,
credential-provenance, Settings-child, Runtime/path and hostname/TLS adapters are
explicit blockers. The pure namespace helper is not yet wired to every API/task/
session/heartbeat consumer. It cannot establish isolation by itself. Concrete
provider selection depends on company engine/image policy and exact approved
disposable targets; no existing protected service may substitute for that work.
Source contracts are reviewable now; full Phase 3 acceptance remains incomplete.
Existing application/lifecycle/shutdown and production consumers are unchanged.

Native Windows Python 3.14.6, same safe harness:

```powershell
& C:\sbom\.venv\Scripts\python.exe -B `
  C:\sbom\.windows\worktrees\SBO-98-component-env\.dev-logs\safe_pytest.py `
  tests/test_dev_workspace_lifecycle.py tests/test_dev_instance_namespaces.py `
  tests/test_dev_windows_lifecycle.py tests/test_dev_windows_shutdown.py --timeout=60
```

Result: **185 passed in 23.16s**. Python 3.12.10 lifecycle/namespace tests:
**103 passed in 0.68s**. Ruff passed. These are pure/synthetic adapter contracts
and existing Windows regressions; no isolated stack, provider, database, TLS or
administrator operation was executed.
Workspace and lifecycle CLI tests on Python 3.14.6, using the same harness and
`tests/test_dev_workspace_cli.py tests/test_dev_workspace_lifecycle_cli.py
--timeout=60`: **64 passed in 21.89s**. Runtime/process/socket/file-write/private-
read tripwires verified that reported READY or caller markers cannot enable live
execution. A changed HEAD blocks start/restart while stop retains its independent
Runtime-adapter diagnosis and preserves records.

## PR D: restricted test command, data suites BLOCKED

Adds `dev_workspace_tests`, its source/CLI tests, explicit `workspace test --suite
unit [--plan]`, workflow and existing guide/reference updates. The suite contains
only the reviewed pure instance-plan/namespace/provider contracts. It binds exact
source/HEAD/filesystem/local-interpreter proofs, uses a newly created private
copied import closure and excludes application conftest, dotenv, pytest config,
external plugins, arbitrary tests/arguments and old temp cleanup. It is trusted
user-level execution, not a sandbox. Only validated counts/codes escape child
output. All data suites unconditionally require a future exact-target adapter
and separate authorization.

Read-only review found a repeated-Ctrl+C cleanup corner: a second cancellation
could lose the original child metadata. The correction reports
`TEST_CHILD_CLEANUP_UNCONFIRMED` with the original PID and false cleanup status
without PID/tree escalation. Root access uncertainty now has its own
`TEST_ROOT_ACCESS_REVIEW_REQUIRED` diagnosis and never repairs permissions.

Native Windows Python 3.14.6, same safe harness:

```powershell
& C:\sbom\.venv\Scripts\python.exe -B `
  C:\sbom\.windows\worktrees\SBO-98-component-env\.dev-logs\safe_pytest.py `
  tests/test_dev_workspace_tests.py tests/test_dev_workspace_tests_cli.py `
  tests/test_dev_workspace_cli.py --timeout=60
```

Final result: **185 passed in 50.99s**. Python 3.12.10, same harness and the two
new test files: **157 passed in 31.10s**. Ruff passed. All delegated suite children
were synthetic. An early combined command before the CLI test file landed
collected zero tests; the completed lists above passed. No real delegated suite
has run because a genuinely SBO-101-prepared interpreter is unavailable.

Actual `workspace test --suite database --plan --json` returned exit 1,
`DISPOSABLE_TARGET_AUTHORIZATION_REQUIRED`, `database_authorized=false` and empty
stderr. A pre-correction actual unit-plan check refused the native root ACL as
generic unverified-worktree; its now-specific diagnosis is covered by the final
negative tests. No data resource, installer, runtime, trust or privileged service
was touched.
The final actual candidate command `workspace test --suite unit --plan --json`
then returned **TEST_ROOT_ACCESS_REVIEW_REQUIRED**, exit 1,
`database_authorized=false`, empty stderr. No real suite child ran. PR B at
`7de355e583d21234ea68237674ce8f88dad2a37a` and PR C (#57) at
`3295afa7e519d4f62292b1cc3abfeabc0eb43065` each had 20 successful CI checks
(push and PR runs) when inspected; no failures were returned.

## PR E: guided Native/HCL overview and closed enrollment state machine

Adds `dev_workspace_onboarding`, focused pure/CLI tests, static administrator
guidance in the existing launcher, the separate authority security proposal and
updates to the existing development/configuration/Native guides. Fresh Native
guidance is explicitly UNKNOWN/uninspected, with no invented target/status/
generation/readiness. HCL has its separate approval code, not a Native-password
route. Mock/shared previews cannot offer enrollment. No identity/password input
or status connection is requested by this guidance.

The pure observation planner covers existing, absent, pending, completed,
conflicting and unknown aggregate states with exact context/schema/status drift
checks. Source review confirmed `dev_operator.py` counts all IAM users and the
bootstrap user FK is nonnull/restricted, so a pending reservation with zero users
now produces CONFLICT and recovery review. All actions remain non-executable;
no public marker, readiness flag or valid plan can authorize creation or resend.
The existing managed guard, standalone bootstrap and bootstrap service have no
diff against `73d29949b31fa3564a56043128bde7118e804ede`.

The [authority proposal](dev-workspaces-security-sbo101.md) distinguishes a
developer-controlled launcher from an independent privileged boundary and leaves
principal deployment, token consumption/revocation/commit atomicity, readiness
attestation and activation-time DB privilege design for explicit security/DBA/
Engineering Lead review. It is not an implemented/enabled authority protocol.

Native Windows Python 3.14.6, same safe harness:

```powershell
& C:\sbom\.venv\Scripts\python.exe -B `
  C:\sbom\.windows\worktrees\SBO-98-component-env\.dev-logs\safe_pytest.py `
  tests/test_dev_workspace_onboarding.py tests/test_dev_workspace_onboarding_cli.py `
  tests/test_dev_native_enrollment.py tests/test_dev_native_enrollment_cli.py `
  tests/test_dev_operator.py --timeout=60
```

Result: **356 passed in 37.04s**. Python 3.12.10, same harness with the two new
onboarding files: **128 passed in 6.04s**. Ruff passed. Aggregate observations,
services and contexts were synthetic; direct-invocation/drift/redaction/mutation
tripwires passed. No protected administrator availability was inspected and no
live creation, resend, email, activation, grant or database operation occurred.
Actual candidate `workspace plan --scope administrator --mode isolated --auth
native --json` returned UNKNOWN/ONBOARDING_INSPECTION_REQUIRED; the `--auth hcl`
form returned HCL_APPROVAL_REQUIRED/HCL_OPERATOR_IDP_APPROVAL_REQUIRED. Both
returned exit 1, `inspection_performed=false`,
`live_enrollment_authorized=false`, empty identity-field lists and empty stderr.
These are static guidance results, not database status or authenticated authority.

## PR F: source comparison, redacted observations and acceptance ledger

Adds `dev_workspace_observe`, focused native-file/CLI tests and the existing
launcher's compare/log/status/diagnose integration. Git inventory remains distinct
from application readiness: status/diagnose explicitly return BLOCKED/exit 1
while the concrete readiness adapters are missing, even for caller-reported READY.
Fresh/unregistered diagnostics do not fabricate descriptors. Optional CPU/home-
disk observations are separate from service or memory/capacity acceptance.
Diagnose reuses only public dependency inspection, with bounded owned helper
objects, no installer, private environment, package-readiness or compiler claim.

Comparison exposes observed sources and proposed origins/resources; runtime,
API, screenshot/trace, visual and authenticated acceptance flags stay false.
Local logs use fixed files under the private per-instance `.dev-logs` root and
never fall back to historical checkout logs. Only allowlisted metadata escapes;
raw messages/identity/credentials remain withheld. Provider logs are blocked.
Follow is bounded to 30 seconds, records to 200 and reads to a fixed tail.

Real Windows temporary-file testing found that `lstat` and `fstat` expose different
creation/change-time values on this host. Cross-open comparison uses stable
identity/size/mtime, while full stamps remain checked within each API. ACL,
owner, regular-file, single-link and path pinning are retained. This is confirmed
native file behavior, separate from Runtime PID birth/executable verification.

Focused observer tests exercised native private ACL/file reads plus synthetic
identity drift/redaction; CLI tests exercised the actual boundary with synthetic
Git/registry observations. An early test fixture forbade every public read and
produced three teardown errors when software inspection was connected; it was
corrected to allow only exact public manifest/controller paths while keeping
private/mutable/network/app tripwires. No protected resource operation occurred.

Python 3.12.10, same safe harness with
`tests/test_dev_workspace_observe.py tests/test_dev_workspace_observe_cli.py
tests/test_dev_workspace_cli.py --timeout=60`: **116 passed, 2 skipped in 45.86s**.
The skips are POSIX mode semantics and unavailable Windows symlink privilege;
native private ACL reads passed. Ruff passed for all new source/tests. The final
complete inspected Windows-applicable workflow list plus native fixture-owned
process smoke passed on Python 3.14.6: **2,202 passed, 43 skipped, 6 existing
Alembic warnings in 296.70s**. No test failure remained. This selected 41 reviewed
launcher/workspace files; it was not application-wide pytest.

Exact final selection/command, from the implementation worktree:

```powershell
@'
import re, subprocess, sys
from pathlib import Path
text = Path('.github/workflows/dev-launcher.yml').read_text(encoding='utf-8')
block = text.split('- name: Cross-platform unit and mocked adapter regressions', 1)[1].split('\n      - name:', 1)[0]
tests = list(dict.fromkeys(re.findall(r'tests/[a-z0-9_]+\.py', block) + ['tests/test_dev_native_process.py']))
assert tests and all(Path(p).is_file() and p.startswith(('tests/test_dev_', 'tests/test_greenfield_windows_compat')) for p in tests)
raise SystemExit(subprocess.run([sys.executable, '-B',
    'C:/sbom/.windows/worktrees/SBO-98-component-env/.dev-logs/safe_pytest.py',
    *tests, '--timeout=60']).returncode)
'@ | & C:\sbom\.venv\Scripts\python.exe -B -
```

The command used the existing issue-local sanitized harness; its transport-only
environment, SQLite sentinels, disabled dotenv/plugin autoload/cache/bytecode,
unique temporary root and `--noconftest` policy remain as described above.
AST checks confirm Runtime/process/start helpers are still unchanged from the
integration baseline. All 12 new modules parse with Python 3.11 grammar; actual
cross-platform Python 3.11 execution is covered by the CI matrix, not this host.
The managed enrollment guard/bootstrap/service still have an empty baseline diff.

The [T01–T36 / A01–A15 ledger](dev-workspaces-acceptance-sbo101.md) marks each
limited contract separately from unexecuted real acceptance and gives the
approval-dependent native procedure. Real two-stack/background/browser/tenant/
activation tests are not run; no approved provider, private material or privileged
authority exists for them on this host. No protected services were adopted.

## Risks, conflicts and required decisions

| Area | Files / dependencies | Risk or gate | Current protection |
| --- | --- | --- | --- |
| Source integration | SBO-98 #49–#54 → SBO-101 #55 onward | Draft stack dependency; no independent sign-off claimed | Old branches unchanged; issue-only worktree/branches; no merge |
| Legacy lifecycle | `scripts/dev.py`, existing Runtime | Native process regression / unknown PID | Lifecycle AST unchanged; native regression list; no new termination path |
| New runtime | `dev_workspace_lifecycle`, `app/dev_instance` | Execution/consumer/config/TLS adapters unimplemented | Unconditional live block; no fabricated READY |
| Data services | `dev_workspace_provider` | Company engine/images/UID policy and exact disposable resource approval absent | Pure proposals/consistency only; no daemon/DB executor |
| Dependencies | `dev_workspace_dependencies`, CLI | Untrusted root grant; binary-only/public-index policy; interrupted state | Specific native refusal; exact consent/revalidation; retained journals; no repair/adoption |
| Privileged Native | `dev_workspace_onboarding`, unchanged SBO-98 guard | Independent principal/authority/readiness/commit design not approved | All live actions closed; exact context drift tests; separate security proposal |
| HCL.CS | Existing provider services / approved registration | IdP-owner first-user and per-origin callback/trust decisions | No invented identity, password fallback or privileged provisioning |
| Shared contracts | Application/DTO/schema/migrations | Other-agent or deployment conflict | No NEXUS active work confirmed; these consumers/schemas/deployment files unchanged |
| Observations | `dev_workspace_observe`, CLI | Metadata/consistency cannot prove live health; unknown private source | No service contact, raw message content or state mutation; ACL/identity checks |
| Tests | Fixed source closure / explicit workflow lists | Application fixtures can migrate/truncate; fake execution is not E2E | No application conftest; sanitized SQLite sentinels; real data suites blocked |

Engineering Lead/IT must provide the approved Docker/Podman policy and image/data/
port/user contracts before a concrete provider is used for real resources. Source
development and synthetic validation of provider-agnostic Compose-compatible
adapters continue without them. Exact provider/database/
credential/schema/TLS operations then need separate target-specific approval.
The Native authority proposal requires security/DBA/Engineering Lead review and
disposable acceptance before enablement; HCL provisioning additionally needs its
IdP owner. Original service health/database contents have not been re-inspected:
no command targeted them or wrote their configuration, certificates or runtime.

Linear updates cannot be sent in this session; provide the actual draft/commit/
test/blocker summary for the Engineering Lead to post to SBO-101. Do not mark the
issue complete while these implementation and acceptance gates remain.

### Subsequent Engineering Lead direction

After this foundation, the Engineering Lead explicitly directed continued source
implementation of concrete provider interfaces, capability discovery, manifest
generation, lifecycle/ownership/approval boundaries, limits/health, previews and
remaining setup/runtime phases. Missing Docker/Podman and unconfirmed company
policy are **real-execution limits only**, not reasons to stop independent coding.
The pinned references in `infra/greenfield-uuid/compose.yml` are source references,
not approved images/policy. Architecture/provenance/scanning/registry/nonroot/
platform checks and exact resource/database approval are required before use.
No engine install, image pull, container/volume/database creation, virtualization
change or protected-service substitution is authorized. Follow-on drafts will
distinguish implemented synthetic paths from pending real-provider acceptance.

## Increment G — Compose-compatible provider adapter

Implemented source: `dev_workspace_compose.py`, `dev_workspace_engine.py` and
`dev_workspace_provider_input.py`, with provider planning in the existing public
launcher. No reference digest is silently selected. A proposed policy explicitly
supplies the engine identity, policy reference, pinned images, numeric nonroot
UID/GID, platform, limits, data ownership/population contract, health budgets and
fourteen private file references. File contents and paths are absent from public
output. Duplicate/unknown JSON fields, credentials-as-fields and mutable image
tags are refused. A policy file is a proposal, not an authorization source.

```powershell
python scripts/dev.py workspace plan --scope provider --mode isolated --auth native --json
python scripts/dev.py workspace plan --scope provider --mode isolated --auth native --provider-policy <reviewed-proposal.json> --json
```

These commands do not invoke an engine or read the referenced secret files.
Without a policy they report `PROVIDER_POLICY_SELECTION_REQUIRED`; with a valid
proposal they return the redacted contract and review gates. `prepare --scope
provider` requires separate exact-target authorization and performs no mutation.
The Python adapter can execute approved operations through an injected trusted
policy authority and durable creation journal; the CLI does not turn JSON review
markers into that authority.

The generator emits Compose JSON (a YAML subset). The concrete Docker adapter
consumes that same specification but deliberately avoids `compose up`: resource
creation records returned immutable network/container IDs, and fresh anonymous
data volumes are obtained from those new container receipts. Logical names and
labels alone never authorize adoption or shutdown. Start/stop re-inspect engine,
image, process/container and resource identities immediately before operations.
Partial or uncertain results retain receipts and report unconfirmed operations;
there is no remove-volume, pull, build, automatic database initialization or
destructive recovery path. Podman is a separate explicitly unsupported adapter
until implemented and validated, rather than assumed Docker equivalence.

PostgreSQL runtime invokes `postgres` directly, not its auto-initializing image
entrypoint. Fresh `initdb`, restricted-role/schema preparation and nonroot volume
ownership need separately approved preparation. Host TLS/auth health adapters
are explicit prerequisites; an image health status is not verified readiness.
Mailpit's internal readyz behavior is insufficient to establish certificate
verification. File-backed Compose secrets do not remap host UID/GID/mode: the
approved image/host must demonstrate actual nonroot readability and protected
permissions. Rootless engines alone do not prove this contract.

Synthetic generation, policy parsing and fake Docker runner tests exercise real
command construction, denial paths, drift and partial outcomes. Real engine
discovery/provisioning, image provenance/architecture/scanning/registry checks,
nonroot integration and service/database readiness remain **NOT RUN**. Missing
runtime/policy blocks those real operations only. Runtime wiring, guided private
preparation and previews continue as independent source increments.

Executed G validation on Windows / Python 3.14.6:

```powershell
& C:\sbom\.venv\Scripts\python.exe -B C:\sbom\.windows\worktrees\SBO-98-component-env\.dev-logs\safe_pytest.py tests/test_dev_workspace_engine.py tests/test_dev_workspace_compose.py tests/test_dev_workspace_provider_input.py tests/test_dev_workspace_provider.py tests/test_dev_workspace_cli.py --timeout=60
```

Result: **240 passed in 325.96s**, including all 64 engine tests on the final
mutation-boundary source. The harness disables application conftest/plugin
autoload, uses in-memory SQLite sentinels and a new private temporary directory.
Compose/parser compatibility on the existing Python 3.12.10 validation
interpreter: **78 passed in 1.23s**. Scoped Ruff checks passed. Existing PRs
#58, #59 and #60 each reported 20 completed successful checks at their exact
heads when rechecked; each remains Draft. These are source/fixture results, not
real provider or complete application acceptance.

## Increment H — Application resource and settings isolation

The persistent `SBOM_DEV_RESOURCE_ID` now reaches actual Celery default/report
routes and task decorators, both report publishers, Native mail-worker heartbeat
writer/reader, Native IP/account limit buckets and the BFF Redis session store.
The launcher consumes those same queues for worker commands/readiness and the
same persistent namespace for Beat leases. Its independent `SBOM_DEV_INSTANCE`
still identifies each process launch. No UUID means the exact legacy names.
Malformed or ambiguous UUIDs fail closed. The UUID is server metadata, never a
`NEXT_PUBLIC_*` value or ownership/authorization proof.

Isolated application `get_settings()` now requires explicit development mode,
python-dotenv disabled, authentication enabled and default-tenant bypass disabled.
It creates real `Settings(_env_file=None)` and binds the cached instance to the
resource UUID. This closes the separate Pydantic dotenv source; setting
`PYTHON_DOTENV_DISABLED` alone does not close it. Ordinary source selection is
unchanged without the explicit UUID. No temporary settings/module overlay is
used. Private bundle resolution remains a separate explicit launcher adapter.

Changed source: five queue/Native service consumers, `app/settings.py`,
`scripts/dev.py`, the pure component projector, and the server session namespace
helper/store. Three focused regression files and the existing workflow are
updated. No schema, migration, production manifest or enrollment source changed.

Executed through the existing inspected safe harness on Windows/Python 3.14.6:

```powershell
& C:\sbom\.venv\Scripts\python.exe -B C:\sbom\.windows\worktrees\SBO-98-component-env\.dev-logs\safe_pytest.py tests/test_dev_workspace_namespace_wiring.py tests/test_dev_workspace_settings_isolation.py tests/test_dev_workspace_launcher_namespace.py tests/test_dev_instance_namespaces.py tests/test_settings_paths.py tests/test_dev_config.py tests/test_dev_component_environments.py tests/test_dev_lifecycle.py --timeout=60
```

Result: **356 passed, 17 skipped in 31.25s**. Skips are POSIX-only primitives and
unapproved Windows fixture-symlink privilege. This includes three real Celery
memory-only routing checks, actual Pydantic dotenv-source behavior and the pure
TypeScript namespace executed by Node; no worker, application server, broker or
database connected. Ruff passed. The initial two positive Settings fixtures
omitted explicit `DEV_DEFAULT_TENANT=false`; they were corrected and this full
selection passed. A Python 3.12 run failed collection because its existing minimal
validation venv lacks Celery/Pydantic; no packages were installed. Runtime
compatibility is therefore delegated to the existing full-dependency CI matrix,
not reported as a local 3.12 pass.

AST comparison against `73d29949b31fa3564a56043128bde7118e804ede` confirms
`Runtime`, `process_info`, `windows_children`, `start_process`,
`start_background` and `wait_for_background` unchanged. Protected Native
bootstrap/enrollment service sources also have no diff. Actual simultaneous
queues/sessions/Beat/rate-limit and full-stack acceptance remain **NOT RUN**.

## Increment I — Preview preparation and canonical Runtime adapter

Implemented `dev_workspace_preview.py`, `dev_workspace_preview_cli.py` and
`dev_workspace_runtime.py`, exposed through the existing public launcher:

```powershell
python scripts/dev.py workspace plan --scope preview --mode mock --auth native --preview-settings <existing-preview-settings.json> --json
python scripts/dev.py workspace prepare --scope preview --mode mock --auth native --preview-settings <existing-preview-settings.json>
```

The strict version-1 settings object contains `node` (an absolute executable),
`tls` (`certificate`, `private_key`, `ca_bundle` existing absolute paths), and
`shared_backend` (`null` for mock, otherwise the explicit registration object).
It never contains passwords, key contents or readiness/authorization markers.
Planning reads metadata; preparation requires a current, expiring, exact-plan
TTY confirmation, creates only private files/links, and reuses verified existing
preparation without another write prompt. Unknown state is retained/refused.
These are source review interfaces; guided bundle selection remains subsequent
integration, so the final onboarding UX need not ask users to discover these paths.

Mock uses a separate synthetic Next app with selected inert design tokens, no
real application layout/auth/API routes, no remote font dependency and no data
services. It is a theme/layout fixture, not arbitrary application-page coverage.
Source style changes require re-preparation; shared/isolated real source is linked
for HMR. Shared mode requires explicit non-production origin, permitted tenant,
auth/callback/session verification and a warning that browser actions can mutate
that backend. No extra worker/Beat is launched. Isolated frontend binding instead
requires the exact own API port and persistent UUID. It cannot adopt a shared
backend registration.

TLS, backend and native compiler verification are trusted runtime integrations,
not caller JSON flags. The existing compiler guard remains unchanged. The
Runtime adapter uses the canonical launcher's Runtime via injection, private
per-instance state/logs, original process handles, process creation/executable
checks, and canonical verified cleanup. Backend children use an isolated Python
runpy entry with explicit source and an environment-free private CWD; real
Settings source control comes from H, with no monkeypatch/module overlay.
Ambient application settings/preloads and TLS key logging are refused/projected
away. The deferred frontend factory runs only after backend/API probes, then
requires frontend verification and all five owned records before service readiness.
Its bounded callbacks perform read-only verification/construction, never spawning
or preparation. Stop/restart remain independent of private configuration/source
loss; uncertain process/tree records are retained. Public CLI start remains
blocked until approved target/provider/private-bundle/readiness bindings are
connected, rather than accepting a supplied READY marker.

Executed Windows/Python 3.14.6 safe-harness command:

```powershell
& C:\sbom\.venv\Scripts\python.exe -B C:\sbom\.windows\worktrees\SBO-98-component-env\.dev-logs\safe_pytest.py tests/test_dev_workspace_runtime_native.py tests/test_dev_workspace_runtime.py tests/test_dev_workspace_preview.py tests/test_dev_workspace_preview_cli.py tests/test_dev_workspace_cli.py tests/test_dev_windows_acl.py tests/test_dev_native_process.py --timeout=60
```

Result: **170 passed in 65.36s**. A later added real-public-theme extraction test
passed separately (**1 passed, 0.32s**). The native fixture recheck after adding
its private recovery sentinel also passed (**1 passed, 3.05s**). Existing Python
3.12.10, preview/runtime/native-fixture selection: **68 passed in 55.02s**. Ruff
and Python 3.11 grammar checks passed. The initial native fixture exposed safe
callback error categories being replaced by a generic error; only enumerated
redacted categories are now preserved, with unknown exception text suppressed.

The native fixture starts four real disposable Python helpers through this
candidate Runtime adapter. Their workload/readiness is synthetic, and they honor
the existing Windows shutdown protocol; deliberate frontend refusal cleans all
four, preserves specific diagnostics and leaves no runtime record or live child.
It never overlays candidate app modules or runs a database, provider, real worker,
API, Node server or privileged enrollment. Existing API shutdown can force a
freshly revalidated handle where no cooperative hook exists, with an explicit
active-work warning; that baseline trade-off is preserved. These results do not
establish application startup, authenticated readiness, browser trust/login,
general mock-page coverage, real Next HTTPS/HMR or simultaneous full-stack
acceptance. Those real scenarios remain **NOT RUN**, with explicit approval and
integration prerequisites. No existing configuration, certificate, database or
historical runtime record was altered.

## Disposable acceptance procedure (not yet authorized or executed)

1. Review the candidate diff and CI on Windows/macOS/Linux, preserving SBO-98.
   Confirm exact worktrees, agent reservations and current commits.
2. Use `workspace list` and `workspace plan` for two fresh disposable worktrees;
   retain the public instance IDs, fingerprints, hostnames and resource names.
3. Obtain separate approval for the company-managed container engine and exact
   provider resources, database roles/targets/schema operations, private material
   creation, and any OS certificate trust changes. Existing protected services
   are never substitutes. Docker/Podman are currently absent from this host's PATH.
4. Once those adapters and approvals exist, prepare independent dependencies,
   providers and configurations; verify labels, loopback bindings, restricted
   roles and negative cross-instance access before schema actions.
5. Verify each candidate's actual API/IAM readiness, TLS hostname/chain, workers,
   Beat, broker, sessions and separate Mailpit. Run both simultaneously, perform
   separately approved disposable jobs, stop one and verify the other and the
   original checkout remain healthy. Preserve volumes and uncertain records.
6. Native enrollment remains BLOCKED until independent, target-bound,
   short-lived, single-use operator authority is approved and enforced at the
   private child and mutation boundaries. Only then may separately authorized
   disposable activation acceptance run. Human passwords belong on the verified
   HTTPS activation page. HCL onboarding additionally needs the IdP owner's
   approved procedure.

T01–T36 and A01–A15 in the master specification remain the acceptance checklist.
The unit/synthetic evidence above covers selected contracts only; none of those
scenarios is claimed as full end-to-end acceptance. Actual provider/database,
two-stack, browser/tenant and privileged-enrollment scenarios are **NOT RUN /
BLOCKED** pending implementation and their specific approvals. No merge or
deployment is authorized by a draft PR or green CI.
