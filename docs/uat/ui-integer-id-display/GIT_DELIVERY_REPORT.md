# UI integer-ID display Git delivery

Date: 2026-10-23. Repository: [feroz-hub/sbom](https://github.com/feroz-hub/sbom). Branch: `feat/native-user-management`.

## Verified publication checkpoint

The source and sanitized evidence were committed and pushed normally, with no rewritten history. Git `ls-remote` and the GitHub REST branch-ref endpoint independently agreed at this checkpoint.

| Item | Exact SHA |
|---|---|
| Starting local/fetched/REST remote baseline | `bf078cd3c136b027f77586fd9c180d9741ecf076` |
| [Implementation commit](https://github.com/feroz-hub/sbom/commit/8f9f00e1f2fc143ac3ca1893d6d94e5860865177) | `8f9f00e1f2fc143ac3ca1893d6d94e5860865177` |
| [Documentation commit](https://github.com/feroz-hub/sbom/commit/8dfd9d8c2ea5e3d20ff0e0d4088b81df403ff16a) | `8dfd9d8c2ea5e3d20ff0e0d4088b81df403ff16a` |
| Independently verified local/remote HEAD before this attestation | `8dfd9d8c2ea5e3d20ff0e0d4088b81df403ff16a` |

This report is the sole file in a subsequent attestation commit. Its own commit SHA and final remote SHA must be reported separately after that commit is created and pushed; no self-referential future SHA is embedded here. The expected final delivery is **96 distinct files**: 73 implementation source/test files, 20 original reports/evidence files, one narrowly scoped `.gitattributes` change, one additional sanitized verification summary, and this report. The implementation commit contains 66 modified and seven new source/test files. The documentation commit contains 22 files. There are no deleted files.

At the checkpoint, the GitHub commit objects confirmed baseline → implementation → documentation, the complete recursive tree contained 2,759 blobs with `truncated=false`, and every one of the 95 delivered blobs was downloaded through the GitHub Git-blob API and matched local bytes. The compare endpoint returned exactly the same 95 paths. The attestation is subject to the same final ref/tree/blob verification after publication.

## Scope and source verification

All 73 staged implementation blob SHA256 values matched the reviewed manifest. The complete 140,112-byte patch was applied to a separate temporary Git index based on the original baseline; all 73 resulting file hashes matched current source. This did not change the real index or working files. The labeled source manifest's SHA256 is `e6bad94d5036a9e8e0b68becb57cc379bc09d157175275d4c2aeb50ea6602561`.

All 1,504 final frozen source hashes matched current bytes: 470 application, 627 frontend, 52 script and 355 test files. Of these, 1,499 were unchanged since the broad backend execution started. The five changed test modules have complete corrected-module reruns; their test signatures/decorators and the original five snapshot JSON files are unchanged. No application/common runtime source changed after that broad run began. No new database or browser test was run for Git delivery.

Existing migrations 100, 101 and 102 remain byte-identical to the starting commit and to their GitHub tree blobs. This feature introduces no migration, model, schema, stored-ID, permission or business-logic change. `display_id` siblings contain the actual positive safe integer used by existing authorized scoped UUID resolution, including related Latest/Current SBOM references. The public UUID remains in API selectors, links, mutations, cache/query identities, React keys, worker/SSE and report-resource contracts. No numeric selector or new per-row lookup was added.

## Staged publication security and whitespace

Gitleaks **8.30.1**, embedded default rules, clean environment and `--ignore-gitleaks-allow` scanned protected exports of the exact Git index blobs: **73 implementation files, zero findings**, and **22 documentation/evidence/attribute files, zero findings**. Each export was independently matched to its index blob. The attestation is scanned separately before commit. Zero confirmed credentials were found in the reviewed publication set. No `.env`, credential file, authenticated browser state, raw log/XML, dump, screenshot, private incident material or runtime workspace is published.

The five earlier implementation-stage generic-key alerts were verified source SHA256 metadata, not secrets; individual adjudications remain in `evidence/secret-scan-review.json`. No rule was disabled and no broad secret allowlist was added. Source hashes were not altered to resolve those alerts.

The implementation's `git diff --cached --check` passed. Documentation first reported a space-before-tab on an unchanged context line inside the complete unified patch. Its original bytes are retained. An exact-path `.gitattributes` entry for only this artifact sets `-text` and disables only blank-at-EOL and space-before-tab checks, which are part of its diff context notation. The subsequent documentation check passed. Application/test whitespace settings remain enforced. Remote patch bytes were downloaded and verified unchanged.

A supplemental Codex Security scan was started but **remains INCOMPLETE**: semantic draft validation failed, and finalization reported “The latest saved scan draft is incomplete; continue the scan before completing it.” No completed scan, no-findings certificate or independent security sign-off is claimed from that tool. Manual review of the actual publication diff and the required Gitleaks index scans were performed; the tool failure is retained as a limitation, not converted to PASS. Review was performed sequentially by the parent, without an independent architecture worker.

## Existing frozen execution evidence

These are historical executions whose raw protected artifact hashes, case IDs and source equivalence were independently rechecked during delivery:

| Segment | PASS | SKIP |
|---|---:|---:|
| Unchanged main cases, excluding replaced modules and later opt-ins | 4,571 | 9 |
| Complete corrected-module reruns | 49 | 0 |
| Two separately executed opt-ins | 2 | 0 |
| Two isolated load tests | 2 | 0 |
| **Unique backend total** | **4,624** | **9** |

There are 4,633 collected unique cases, zero missing/overlapping/unexpected case IDs, zero parameter-label normalizations, zero remaining FAIL/ERROR, and 12 additional passing subtests. The preserved broad run itself ended **4,606 PASS / 11 SKIP / 7 FAIL / 7 ERROR**, exit 1; two load tests were deselected. It is not one green monolithic Pytest execution. Complete corrected-module runs replace all 49 original module outcomes, and later actual opt-ins replace their two original skips. Earlier failures and interruptions remain protected locally and summarized in TEST_RESULTS.md.

Full frontend: **1,838 PASS across 203 files**, zero FAIL/SKIP. TypeScript, Webpack production build and app/tests-scoped Ruff passed. ESLint reported zero errors and 52 historical warnings. Browser evidence establishes **six installed-Chrome scenarios PASS with TLS verification enabled**, using the isolated application/database and local OSV simulation. There is no live HCL.CS/Entra, physical-device/VoiceOver or staging acceptance.

The nine backend SKIP nodes remain SKIP:

- `tests/ai/test_real_provider_smoke.py::test_real_anthropic_test_connection`
- `tests/ai/test_real_provider_smoke.py::test_real_gemini_free_tier_test_connection`
- `tests/ai/test_real_provider_smoke.py::test_real_grok_free_tier_test_connection`
- `tests/ai/test_real_provider_smoke.py::test_real_openai_test_connection`
- `tests/test_greenfield_startup_postgresql.py::test_real_confirmed_startup_encrypts_and_restores_backup_then_commits101`
- `tests/test_greenfield_startup_postgresql.py::test_real_precommit_failure_keeps100_and_retains_claim`
- `tests/test_native_greenfield_empty.py::test_empty_database_to_native_population`
- `tests/test_native_http_acceptance.py::test_actual_http_expiry_denies_mutation`
- `tests/test_native_http_acceptance.py::test_two_actual_bffs_logout_recovery_and_security_revocation`

See TEST_RESULTS.md and `evidence/git-delivery-source-verification.json` for the reconciliation and source freeze; raw execution logs/XML remain private. This delivery did not rerun the full suites or present old results as new executions.

## Privacy exceptions and outstanding issue

Tenant, IAM User, Tenant Membership and Platform Grant sequential keys are intentionally not added to the presentation contract. Their views retain authorized names, emails, roles and descriptions. This preserves SBO-73 directory privacy and is not a failure to convert a business-record label. Any later disclosure of those global sequences needs a separate Product/Security decision.

The existing `subscription_out()` IAM integer field and the IAM route classifier are byte-identical to the baseline. This patch removes its visible UI label and neither introduces nor widens its API exposure. Separate IAM response-contract/privacy review remains necessary; Git delivery does not certify that old field as appropriate. No global discovery or permission rule is changed.

## Preservation, CI and release gates

The original 1,977 unrelated untracked files were privately snapshotted and verified by path/content SHA256/size/mode before commit/push; none was staged. Protected historical test failures/packages and the original patch bytes remain locally preserved. Tracked working tree and index were clean at the verified two-commit checkpoint, aside from this new attestation. Final preservation/index checks are required after its push.

No database connection was opened during Git delivery. No schema/stored values, seeded identities or credentials were read or changed, and no migration was applied. The populated revision-101 observation is historical and was not remeasured. No original API/frontend/worker, Docker or PostgreSQL service was started, stopped or restarted. No merge, tag, deployment, release or Linear issue/status change occurred.

GitHub REST inspection at the documentation HEAD found **zero configured workflows, zero Actions runs, zero check runs and zero commit statuses**. The aggregate status says `pending` with zero statuses; this is **not CI PASS**. CI must be checked again at the final attestation HEAD.

Release requires paired API/frontend rollout, an independently confirmed compatible populated schema and the existing separately approved revision-102 cutover gate, code review, CI, staging and UAT. No such authority is provided by publication. LINEAR_DRAFT.md contains the manual delivery draft and flags the older SBO-78 100→101 text for a current 101→102 cutover assessment. No full UAT/release sign-off is granted.

`DATABASE_SCHEMA_AND_STORED_VALUES_UNCHANGED`

`PUBLIC_UUID_API_CONTRACT_PRESERVED`

`NO_DEPLOYMENT_OR_MIGRATION_PERFORMED`

`FULL_UAT_SIGNOFF_WITHHELD`
