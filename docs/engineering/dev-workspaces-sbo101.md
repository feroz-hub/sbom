# SBO-101: implementation evidence and approval boundaries

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
this Windows host; CI and independent native acceptance are still required.

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
