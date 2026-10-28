# Git delivery report — 2026-10-21

Repository: https://github.com/feroz-hub/sbom. Branch: `feat/native-user-management`.

The implementation and sanitized evidence were committed and their first fast-forward push was verified through Git refs and the GitHub commit API. This report is added in a separate documentation attestation commit after that verification. No merge, deployment, database operation, seeded identity change or policy change occurred.

| Reference | Verified value |
| --- | --- |
| Original local and remote HEAD | `2f48ff835d9e692fc84b31aaa951aad2495888ac` |
| Final implementation HEAD | `d88ea570418787bc899ce08e26086b40fc28642e` |
| Verified local and remote delivery HEAD before report attestation | `b0217bf90c178c3e4b74edac00b764798bc8c983` |
| Final report carrier HEAD | The commit containing this report; resolve with `git log -1 --format=%H -- docs/uat/round4/GIT_DELIVERY_REPORT.md` and compare with `git ls-remote origin refs/heads/feat/native-user-management`. Its literal SHA is recorded after the final push in the delivery response/private post-push attestation, avoiding a self-referential fabricated commit hash. |
| Initial synchronization | Local/remote equal; no divergence |
| Push destination | `origin/feat/native-user-management`, ordinary fast-forward only |

## Commits and scope

| Commit | Message | Files |
| --- | --- | ---: |
| [d88ea570418787bc899ce08e26086b40fc28642e](https://github.com/feroz-hub/sbom/commit/d88ea570418787bc899ce08e26086b40fc28642e) | feat: complete Greenfield UUID integration and UAT remediations | 277 |
| [b0217bf90c178c3e4b74edac00b764798bc8c983](https://github.com/feroz-hub/sbom/commit/b0217bf90c178c3e4b74edac00b764798bc8c983) | docs: preserve sanitized UUID and UAT Rounds 1–4 evidence | 524 |
| Documentation commit containing this report | docs: record verified development Git delivery | 3 touched; 2 newly added |

Final intended delivery: **803 unique files** across three cohesive commits (804 per-commit file touches because the Linear draft is updated in the attestation). Source changes overlap across remediation rounds, so separate artificial per-round implementation commits would risk inconsistent intermediate states.

Implementation includes six UUIDv4 public resource identities with internal integer relationships retained; scoped request/response/OpenAPI translation; Native IAM tenant selection and frontend UUID integration; VEX serialization/concurrency, Dashboard hierarchy, Advisor policy history, KEV permission UI, member popup/provider wording, repair-byte integrity, CUSTOM cron, session 503 recovery, legacy analysis boundaries, bounded response lookups, report UUID composition and safe maintenance scope. Dependencies pin croniter/rfc3986-validator and vendor the JSF schema.

The source diff was reviewed against the actual original HEAD, using the Round1–4 task patches, source manifests and per-node regression classifications. Historical Native IAM code already present in HEAD is preserved rather than duplicated. No SBO-73 discovery-policy change was introduced.

## Publication security

- Gitleaks **8.30.1**, full candidate copies and exact staged content: **zero unresolved findings** after individual false-positive review. Exact fingerprint dispositions cover hashes, audit/catalog digests, public-package test hashes and two prose matches; no secret rule was disabled globally. Two additional staged line fingerprints referred to the same reviewed SHA256 manifest values.
- Twelve actual private credential/key/token values were loaded only into memory and checked against candidates: **zero matches**. Candidate scan found no private-key PEM or complete JWT. No private environment, user credential file or raw browser session storage was staged.
- Scoped Codex Security review `50f41e5b-f503-4131-874b-9378e2b6bce8`: zero reportable findings. This is a changed-code review plus frozen-test provenance verification, not production penetration acceptance. Workbench measured usage: total 4,280,488; input 4,267,912; cached input 4,110,336 tokens (whole measured thread scope).
- Every explicit staged path and its content was examined/compared against the reviewed list. Implementation whitespace checks passed. Documentation whitespace checks passed after excluding 11 immutable raw artifacts; originals were not rewritten. Git normalizes CRLF to LF in the generated CSV evidence only; local original bytes remain unchanged.
- **1,901 local files excluded and preserved unchanged**, listed with reasons and original hashes in [git-delivery-exclusions.json](evidence/git-delivery-exclusions.json): historical/proposed migration framework, runtime workspaces, duplicate before-source snapshots/attempt archives, screenshots/downloads/binaries/caches and 11 whitespace-bearing raw patch/XML/text artifacts. Private development state is outside the repository. Original UAT reports/registers and protected evidence remain intact; excluded raw links still refer to locally retained artifacts.

## Final validation provenance

All **1,593 source/test files** in the passing Round4 frozen manifest still match their SHA256 hashes after committing. No application/test source was edited during Git delivery. The existing frozen suite was verified, not represented as a newly rerun suite.

| Check | Result |
| --- | --- |
| Frozen backend, 4,392 unique nodes | **4,385 PASS / 7 SKIP / 0 FAIL / 0 ERROR**; 0 XFAIL/XPASS/NOT RUN |
| Additional subtests | **12 PASS**, separate from node total |
| Original 228 failures | All 228 PASS in final execution |
| Previously unexecuted 346 | All 346 PASS in their executed run; final per-node evidence retained |
| Frontend Vitest | **1,805 PASS**, 199 files |
| TypeScript / Ruff / production build | PASS |
| ESLint | PASS, zero errors, **52 documented warnings** |
| Staged whitespace and secret scans | PASS for delivered content |

### Seven explicit backend limitations

| Test node | Recorded reason |
| --- | --- |
| `tests/ai/test_real_provider_smoke.py::test_real_gemini_free_tier_test_connection` | GEMINI_API_KEY not set — skipping real-provider smoke |
| `tests/ai/test_real_provider_smoke.py::test_real_grok_free_tier_test_connection` | GROK_API_KEY not set — skipping real-provider smoke |
| `tests/ai/test_real_provider_smoke.py::test_real_anthropic_test_connection` | ANTHROPIC_API_KEY not set — skipping real-provider smoke |
| `tests/ai/test_real_provider_smoke.py::test_real_openai_test_connection` | OPENAI_API_KEY not set — skipping real-provider smoke |
| `tests/test_native_greenfield_empty.py::test_empty_database_to_native_population` | explicit empty DB/Mailpit acceptance |
| `tests/test_native_http_acceptance.py::test_two_actual_bffs_logout_recovery_and_security_revocation` | opt-in real HTTP acceptance |
| `tests/test_native_http_acceptance.py::test_actual_http_expiry_denies_mutation` | opt-in real HTTP acceptance |

No paid-provider credentials were activated to perform Git delivery. Existing integration/topology limitations remain explicit. See [ROUND4_BACKEND_REGRESSION_REPORT.md](ROUND4_BACKEND_REGRESSION_REPORT.md), [ROUND4_TEST_RESULTS.json](ROUND4_TEST_RESULTS.json), [frozen source manifest](evidence/frozen-acceptance-attempt2-manifest.json) and [verification snapshot](evidence/git-push-verification.json).

## GitHub, remaining files and review gates

The two code/evidence commit objects and branch SHA were verified on GitHub. No check runs or Actions workflow runs were available for the verified documentation head at 2026-10-21T02:51:19.784210+00:00; local validation must not be described as GitHub CI success. The report carrier is checked/pushed afterward and its final concrete SHA/CI observation is returned separately.

Before this attestation there were zero tracked uncommitted files; all 1,901 excluded files remained local and unchanged. After the attestation, only those deliberately excluded files are expected to remain untracked. No reset, rebase, force push, history rewrite, branch-protection bypass or unrelated-file commit was used.

Linear drafts for SBO-57, SBO-54 and SBO-66 are in [GIT_LINEAR_RESULTS.md](GIT_LINEAR_RESULTS.md); no tracker status was changed. SBO-73 remains Decision Needed. The original **485-case baseline remains 454 PASS / 12 FAIL / 11 BLOCKED / 8 NOT RUN** and is not replaced by later regression totals.

**Full application UAT and release sign-off remain withheld.** Staging/Ubuntu validation, explicit provider/topology limits and outstanding product/security gates require their own acceptance. This delivery authorizes no merge or deployment.
