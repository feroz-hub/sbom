# IAM User UUID Git delivery report

Repository: https://github.com/feroz-hub/sbom. Branch: `feat/native-user-management`.

This delivery publishes the reviewed IAM User UUID implementation and sanitized evidence. Migration 101 is **unapplied** to the populated Greenfield database. No application restart, deployment, merge, production release or Linear status change is authorized or performed.

## Commits and remote verification

| Item | Exact SHA / scope |
|---|---|
| Previous local and fetched remote | `aa264cd3673b074b3f9c15c9cc72a4ed95bdb222` |
| Implementation | [`409212f66be418a9d71c707d505d156a2a2df58c`](https://github.com/feroz-hub/sbom/commit/409212f66be418a9d71c707d505d156a2a2df58c), 73 source files |
| Documentation and evidence | [`19b64ff4b2acd2592c226bb1dfdfb43cbb7617b3`](https://github.com/feroz-hub/sbom/commit/19b64ff4b2acd2592c226bb1dfdfb43cbb7617b3), 43 files |
| Remote verified before this attestation | `19b64ff4b2acd2592c226bb1dfdfb43cbb7617b3`, independently matched by `git ls-remote` and GitHub REST API |
| Final attestation commit | This report, the local Linear delivery draft, a sanitized verification summary, one evidence-only attributes file and restoration of the build log's exact bytes; five changed paths |
| Final combined scope | 120 distinct paths relative to the previous SHA: 73 implementation and 47 documentation/evidence paths |

The final attestation commit cannot contain its own SHA. Its exact SHA, final remote match and GitHub file verification are recorded in the operator response and protected post-push evidence after commit creation. No commit history is rewritten. Both pushes use ordinary fast-forward updates; no force push, main merge, release tag or deployment is performed.

GitHub confirmed both commit objects, their parent chain and all 116 original pushed paths. Final verification must additionally compare all 120 branch paths and blob identities after this attestation push. The reviewed 73 source hashes and all 855 frozen Python source hashes still match. The original implementation patch exactly describes the implementation relative to the previous SHA.

## Security and publication review

Gitleaks **8.30.1**, built-in rules, scanned exact index blobs before each commit. Implementation: **73 files, exit 0, zero findings**. Documentation: **43 files, exit 1 with 170 findings**, individually established as source SHA256 digests; **zero confirmed secrets**. Every digest finding was compared to its referenced current source or original Git blob. Exact file/line adjudications are in `evidence/git-delivery-secret-review.json`. No rule was disabled, no baseline suppression or allow-comment bypass was used. The attestation's exact index scan is completed before committing it and retained privately.

Additional review checked private-key delimiters, JWT literals and credential-bearing URLs. The final JUnit and node inventory contain only a deliberate synthetic `user:pass` HTTP endpoint in a negative security-test name. No real credential was found. Historical incident evidence, revoked setup credential outputs, raw failure logs, cookies, tokens, authenticated traces, screenshots, workspaces, local environment files and task database/Redis contents remain excluded. Original protected evidence is preserved locally. No setup/runtime/user credential is changed by this delivery.

The generic `*.log` ignore rule initially refused nine curated final passing logs; only those nine explicitly reviewed paths were then added with `git add -f`. No broad add or ignore-rule change was used. An auxiliary ignore probe initially encountered the existing fsmonitor daemon error; subsequent delivery checks use `git -c core.fsmonitor=false` without changing repository/global settings.

`git diff --cached --check` passed for implementation. The verbatim evidence check reports only single-space blank patch-context lines and original terminal whitespace in three logs; all other staged source and documentation pass. Those four exact evidence exceptions are documented in PUBLICATION_NOTES.md, with full diagnostics retained privately. No application whitespace rule is weakened.

The first remote byte comparison found `core.autocrlf=input` had normalized three CRLFs in frontend-build.log. This attestation adds a narrowly scoped `frontend-build.log -text` attribute and records the original reviewed log bytes. No test/source semantics changed, no test rerun is claimed, and the published evidence manifest now corresponds to exact remote artifact bytes.

## Frozen test evidence reviewed, not newly executed

| Check | Recorded result |
|---|---|
| Complete backend | 4,421 collected; **4,414 PASS, 7 SKIP, 0 FAIL/ERROR**, plus **12 passing subtests** |
| Frontend | **1,812 PASS / 200 files** |
| Installed Chrome | **9 PASS**, TLS verification enabled |
| TypeScript and production frontend build | PASS |
| Ruff: app, tests and new scripts | PASS |
| ESLint | 0 errors, 52 documented warnings |
| Global scripts Ruff | Four unchanged historical findings, explicitly not reported as passing |

Seven skips remain: four real AI-provider tests lack their respective keys; Native empty-database/Mailpit acceptance is opt-in; dual-real-BFF logout/revocation is opt-in; actual HTTP expiry denial is opt-in. Live HCL.CS/Entra provider acceptance, staging and release sign-off remain outstanding. The historical 193-case transitional integrity suite is not counted as these IAM results.

Evidence reviewed: final attempt8 JUnit/log/outcome, 855-file frozen source register, full 4,421-node result inventory, frontend logs, Chrome results, static checks and disposable schema/upgrade records. The final JUnit SHA256 is `7c7d0ad6de410580cb62984f94b4514a24f81344893c86de03447a66e6544917`. Delivery reran source/hash/secret/whitespace/preservation checks only; it did not rerun application test suites or start applications.

## Populated database and service preservation

Bounded authenticated READ ONLY checks before delivery and after the source/documentation push verified PostgreSQL 16.15 at `127.0.0.1:56044/sbom_greenfield_uuid`, cluster `7698349709013049382`, sole marker **100_greenfield_uuid_final**, and **no iam_users.public_id** column. Recorded counts remain 19 users, 19 provider identities, 18 Native credentials, 21 memberships, 21 assignments and four platform grants. Integer IAM foreign-key definitions match the prior baseline. Each check acknowledged ROLLBACK and physically closed/disposed its connection. No migration, backfill, DDL, user mutation or UUID regeneration was executed.

Original API/frontend/worker PIDs 84305, 84306 and 84344 retain their observed start times (09:54:29/09:54:29/09:54:30 on 2026-10-21). No task-owned or existing application service was restarted or deployed. Protected A/B/D/E/F and production databases were not accessed. All 1,914 snapshotted unrelated untracked files and 120 excluded IAM evidence files retain their hashes. No reset, checkout, stash, rebase or deletion was performed.

The tracked working tree/index is expected clean after the attestation commit; unrelated historical untracked files remain. This is intentionally not described as a completely clean repository.

## CI and remaining gates

GitHub API inspection at the verified documentation SHA found **no tracked workflow files, zero Actions runs, zero check runs and zero commit statuses**. The combined-status endpoint returned `pending` with zero statuses; this is **not CI PASS**. Final remote CI observations are recorded with the last SHA in the external attestation.

Populated migration 101 still requires independently reviewed exact source, fresh row counts, protected backup/recovery proof, owner/privilege/lock/writer-window approval and a coordinated application cutover. Matching backend/frontend must not be restarted against schema100. Internal integer PK/FKs, membership/grant IDs, provider claims, JWT subjects and integer Analysis Run IDs remain unchanged. Staging, external-provider acceptance and production release are separate gates.

LINEAR_GIT_DELIVERY_EVIDENCE.md supplies review links for a future Platform & Identity issue referencing SBO-20, SBO-22, SBO-55, SBO-66 and SBO-73. No external issue was created, marked Done or changed, and the SBO-73 privacy decision remains intact.
