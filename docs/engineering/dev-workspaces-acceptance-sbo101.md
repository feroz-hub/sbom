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
| T06 mock frontend | Mode proposal excludes data services/workers/Beat | Not run: mock runtime adapter |
| T07 shared backend | Mode proposal requires explicit registration | Not run: target/tenant/TLS/session approvals |
| T08 backend edit with another preview | Commit/config drift contract | Not run: parallel runtimes |
| T09 two backend stacks | Unique namespace/target contract | Not run: approved independent providers |
| T10 shared database selection | Dedicated target/role refusal contract | Not run: negative live database access |
| T11 cookie collision across ports | Unique hostname proposal; no port-only isolation claim | Not run: TLS/browser/callback verification |
| T12 unknown port owner | Legacy ownership regressions; proposals do not reserve ports | Not run: isolated bind/rebind race |
| T13 stale/corrupt runtime | Legacy PID reuse/unknown ownership tests; registry corruption refusal | Not run: candidate crash/recovery |
| T14 worker/Beat shutdown | Existing Windows cooperative-shutdown/native process regressions | Not run: isolated active jobs |
| T15 queue/Beat collision | Instance namespace/launch contracts | Not run: two live brokers/schedulers |
| T16 unauthorized migration | Nonunit/test/schema operations gated; existing migration guards | Not run: destructive/migration operation |
| T17 protected DB fixtures | Application conftest excluded; sanitized SQLite sentinels | Prohibited without target-specific approval |
| T18 missing config/dependency prep | Actual read-only plan independent of private config; native ACL refusal | Not run: real package installation |
| T19 private configuration reuse | No blind copy/adoption implemented | Not run: separately approved provenance adapter |
| T20 missing/expired/untrusted TLS | Existing TLS and new prerequisite contracts | Not run: instance-specific leaf/trust |
| T21 Next dependency/compiler state | Dependency policy/stamps; existing native compiler guard | Not run: isolated application compiler readiness |
| T22 branch changes during runtime | Commit drift invalidates plans | Not run: running instance drift |
| T23 API compatibility | Comparison explicitly leaves compatibility unverified | Not run: contract/browser acceptance |
| T24 unregistered external callback | HCL configuration/prerequisite contract | Not run: approved IdP registration |
| T25 Native admin absent/pending | Pure status state machine; closed live gate | Not run: approved database inspection/enrollment |
| T26 tenant boundaries | Existing authorization preserved | Not run: isolated tenant workflows |
| T27 mail/background isolation | Unique providers/queues/mail targets proposed | Not run: real messages/jobs |
| T28 parallel agent contracts | Engineering Lead confirmed NEXUS inactive; explicit file ownership | No concurrent independent-agent UAT |
| T29 interrupted/full-disk setup | Synthetic pending journal, retained partial artifacts and publication errors | Not run: real installer/disk exhaustion |
| T30 Windows junction/ACL/AV | Native temp junction/ACL/publication tests; actual root ACL blocker | Not run: controlled AV interference |
| T31 secret leakage | Sanitized outputs and synthetic secret tripwires | Not run: real confidential data, intentionally |
| T32 resource pressure | Bounded discovery/helpers/output; host observation only | Not run: simultaneous stacks/resource exhaustion |
| T33 deleted running worktree | Canonical/registry uncertainty refusal contract | Not run: live removal/recovery |
| T34 integration/rebase changes | Public source/controller/manifest fingerprints | Not run: active rebase with running stack |
| T35 platforms | PR A CI Windows/macOS/Linux, Python3.11/3.12, Node22/26 fixtures | Not run: complete native application matrix |
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

## Approval-dependent native Windows procedure

Current safe commands from the candidate checkout:

```powershell
python -B scripts/dev.py workspace list --json
python -B scripts/dev.py workspace plan --mode isolated --auth native --json
python -B scripts/dev.py workspace plan --scope dependencies --json
python -B scripts/dev.py workspace status --json
python -B scripts/dev.py workspace diagnose --json
```

Inspect the returned blockers; preserve unknown records. Do not run the old
profile's provisioning to bypass an isolated-instance blocker. Do not delete a
runtime file or kill a PID found on a port. Current metadata and provider plans
are not application readiness.

Before real acceptance, the Engineering Lead/IT/DBA must approve exact disposable
engine identity, image digests/UID contracts, two instance/resource plans,
restricted role/credential creation, database initialization/schema actions,
isolated mail transport, leaf material and any OS trust changes. The corresponding
ownership-verifying provider, private configuration, Settings child, Runtime and
TLS adapters must be implemented and reviewed. Those adapters are not implied by
an approval or supplied inspect JSON.

Then freeze the candidate commit and public plan fingerprints. Record protected
baseline process identities through its own manager and file metadata without
changing or copying private material. Prepare each approved dependency category;
verify actual package/compiler state. Provision only the approved labelled
resources, verify engine/network/volume/container identities and loopback binds,
and test restricted roles plus negative cross-instance access before authorized
schema preparation.

Start both through the reviewed instance Runtime adapter. Require exact worker
PIDs/queues, one progressing Beat, API database health, Native IAM readiness,
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
