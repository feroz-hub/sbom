# Ten-resource UUIDv4 Git delivery

Date: 2026-10-22. Repository: [feroz-hub/sbom](https://github.com/feroz-hub/sbom). Branch: `feat/native-user-management`.

## Verified source and documentation publication

| Checkpoint | Exact SHA |
|---|---|
| Starting local, fetched remote and GitHub REST branch ref | `e0c454029dea624e16d7511a1de0499e53fce237` |
| Implementation commit, 141 files | [`1815f636a8ba3c6490cec00c81e25f68138baa40`](https://github.com/feroz-hub/sbom/commit/1815f636a8ba3c6490cec00c81e25f68138baa40) |
| Documentation commit, 40 files | [`4d25c5b4cdb319f4ee1459facad846da09c1252c`](https://github.com/feroz-hub/sbom/commit/4d25c5b4cdb319f4ee1459facad846da09c1252c) |
| Independently verified local HEAD, Git remote HEAD and GitHub REST branch ref at this checkpoint | `4d25c5b4cdb319f4ee1459facad846da09c1252c` |
| Complete GitHub tree at this checkpoint | `90b4dfd6803a337ea7f794e4051302f03c029438` |

Both commits extend the starting baseline linearly. Immediately before pushing, a second fetch confirmed that the remote had not advanced. Normal push succeeded without history rewriting. The GitHub commit objects independently confirmed both exact parents.

The source/documentation publication contains 181 distinct files: 141 implementation files, seven reports, 32 selected evidence files and one narrowly scoped `.gitattributes` file. This attestation adds one file, making **182 distinct delivered files** when its separate commit is included. No source changes were made during delivery. The Linear draft was supplemented with the requested delivery references; no Linear API write occurred.

This report is committed afterward as a separate attestation. Its own commit SHA and the final local/remote HEAD must be verified and reported externally after commit and push; embedding that SHA inside this same committed document would be self-referential. The table above records the completed, independently verified source/documentation checkpoint, not a fabricated attestation SHA.

## Independent remote content verification

Git `ls-remote` and GitHub's REST Git-ref endpoint matched the checkpoint SHA. The recursive Git tree response was explicitly `truncated=false`; no capped comparison-file listing was used. Every one of the 181 delivered paths was verified against its local committed Git blob identity, file mode and full decoded GitHub blob bytes. SHA256 values matched the reviewed source/index records. Migration 102 and all 141 source-manifest entries were included. Frozen revisions 100 and 101 were also fetched and independently compared with the starting baseline; both are unchanged.

The 141 implementation entries reconcile to 129 modified tracked files and 12 new sources. The patch contains exactly those 141 paths. Its preserved byte SHA256 is `e6514c69b878c80c5f4d5785aa0b73f3e001b65b2226ec8c0a335c35240852c7`. The seven original UUID resources and the three new resources retain integer persistence keys; public Membership, Grant and Run UUIDs have separate ownership and authorization contracts. Review covered the forward-only migration, immutable guards, scoped public boundary, error projection, SSE/report handling, OpenAPI, frontend consumers and regression fixtures. No newly established security or contract defect required a source change during publication.

## Exact-index security and whitespace review

Gitleaks **8.30.1** scanned private extractions of the actual staged index blobs, rather than an unrelated working-directory or historical scan. Built-in default rules remained enabled, inline allow comments were ignored, and no ignore file or broad allowlist was used.

- Implementation index: 141 exact blobs, **zero findings**.
- Documentation index: 40 exact blobs, 11 `generic-api-key` matches, **zero credential findings**. Each match was individually checked at its exact path/line against the SHA256 of independently inspected repository source bytes. The locations and source associations are in `evidence/secret-review.json`; the new index scan independently reconfirmed all 11. These are source hashes, not credential hashes.
- The attestation index receives its own exact-blob scan before commit; any unresolved finding prevents publication.

No raw private logs, XML, authentication traces, screenshots, credentials, cookies, session material, private keys or runtime environment dumps were selected. Browser harnesses retain their nonsecret machine-specific executable/evidence locations to preserve the actual executed source hashes; their credential values are loaded only into process memory and are absent from the published bytes. They are execution provenance, not portable credential configuration.

Implementation whitespace checks passed. The initial documentation check reported 524 trailing-whitespace diagnostics, all in the saved patch's blank context lines. The original diagnostic output remains private. A single exact-path attribute, `docs/uat/public-resource-uuid/evidence/implementation-source.patch -text whitespace=-blank-at-eol`, preserves that reviewed artifact without changing its bytes or relaxing application-source checks. The final staged check passed. Remote patch bytes were independently verified against the SHA256 above.

## Frozen acceptance evidence, reverified rather than rerun

All **950** frozen backend source hashes and **626** frozen frontend/configuration hashes matched the filesystem and reviewed final source. All 141 implementation hashes matched the staged and committed bytes. Static parsing of the 67 implementation Python sources passed without importing application modules or connecting to services.

Backend acceptance is a complete reconciliation of disjoint frozen-source executions, **not one monolithic Pytest run**:

| Segment | PASS | SKIP |
|---|---:|---:|
| Focused shard | 2,120 | 2 |
| Final primary shard | 2,368 | 7 |
| Separate isolated load tests | 2 | 0 |
| Unique total | **4,490** | **9** |

There are 4,499 collected unique cases, zero FAIL/ERROR and 12 additional passing subtests. Private original XML bytes were checked against the recorded hashes; case identities and outcomes were independently reconciled with the published ledger, with no missing or duplicate case. Six dynamic parameter labels were normalized only in the four explicitly recorded functions, preserving cardinality and outcomes. No test result was normalized. The focused shard's application/shared source is equivalent to final source; only three primary-only test modules changed, and the primary shard reran on that corrected final test source. Earlier failures and interrupted runs remain historical evidence.

Frontend: **1,820 PASS in 201 files**, zero failures/skips. Existing frozen evidence records TypeScript, scoped Ruff and the Webpack production build passing; ESLint has zero errors and 52 historical warnings. Four unchanged global-scripts Ruff findings remain documented. Chrome acceptance comprises **11 distinct passing scenarios with TLS verification enabled**, including Native role coverage, User stability, Membership lifecycle, Grant/revoke, Run SSE/history/findings, invalid integers and foreign-tenant denials. These executions were not repeated during this Git delivery. No new claim is made about the older standalone 193-case harness.

The nine skipped case identities remain SKIP:

1. `tests/ai/test_real_provider_smoke.py::test_real_gemini_free_tier_test_connection`
2. `tests/ai/test_real_provider_smoke.py::test_real_grok_free_tier_test_connection`
3. `tests/ai/test_real_provider_smoke.py::test_real_anthropic_test_connection`
4. `tests/ai/test_real_provider_smoke.py::test_real_openai_test_connection`
5. `tests/test_greenfield_startup_postgresql.py::test_real_confirmed_startup_encrypts_and_restores_backup_then_commits101`
6. `tests/test_greenfield_startup_postgresql.py::test_real_precommit_failure_keeps100_and_retains_claim`
7. `tests/test_native_greenfield_empty.py::test_empty_database_to_native_population`
8. `tests/test_native_http_acceptance.py::test_two_actual_bffs_logout_recovery_and_security_revocation`
9. `tests/test_native_http_acceptance.py::test_actual_http_expiry_denies_mutation`

The first four require unavailable external-provider credentials; the next two are opt-in historical startup/backup acceptance, the seventh is opt-in empty-database/Mailpit acceptance and the last two require opt-in dual-BFF HTTP topology. `TEST_RESULTS.md` retains their exact reasons and frozen evidence.

## Local preservation and execution boundary

All **1,976 excluded untracked files** were privately inventoried before staging and independently checked afterward for unchanged bytes, size and permissions (and symlink identity where applicable). None was staged. These include unrelated historical migration experiments, private/raw prior UAT evidence and runtime workspace artifacts. Their private filenames and hashes are not republished. The tracked worktree and index were clean at the verified source/documentation checkpoint; only this subsequently added attestation is intended for the final commit.

**POPULATED_DATABASE_MIGRATION_102_NOT_APPLIED.** This Git task made zero database connections, executed no SQL or migrations, read no credential contents, ran no startup/bootstrap scripts, issued no Docker commands and restarted no services. It did not touch seeded accounts or protected databases. The latest pre-existing read-only implementation observation is revision `101_iam_user_public_uuid`, not historical revision 100: 19 IAM users, 19 provider identities, 18 Native credentials, 21 memberships, 21 role assignments, four platform grants, 40 runs and 70 findings. These remain historical observations from `evidence/populated-preservation.json`; they were not newly measured during Git delivery. Migration 102 was tested only on disposable synthetic databases. No merge, tag, deployment or production release occurred.

## CI and remaining approval gates

At the verified checkpoint, GitHub reported zero repository workflows, zero workflow runs, zero check runs and zero commit statuses. The aggregate status was `pending` with zero statuses. **CI was not executed and is not claimed PASS.** The final attestation commit requires the same independent status check after push.

Remaining gates include independent code/security review, an updated populated **101→102** cutover assessment, protected backup/restore rehearsal, explicit DBA/Product/Security migration authority, CI, staging and live HCL.CS/Entra acceptance. SBO-78's older 100→101 approval text requires revision; this delivery does not grant migration authority. The delivery draft references SBO-66, SBO-77, SBO-78, SBO-54, SBO-55, SBO-57 and SBO-59 without creating/updating issues or marking them Done. SBO-73 remains unchanged.

**FULL_UAT_SIGNOFF_WITHHELD.** Development-branch publication is separate from populated migration, application startup, staging acceptance and release approval.
