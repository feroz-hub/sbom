# Round 2 — Linear review drafts

Prepared for independent review. No issue status, comment, Done state, commit, push, merge or deployment was performed. Exact final commands/counts and remaining failures are in [RESULTS.md](RESULTS.md). The original 485-case baseline is preserved. These drafts do not imply full application UAT sign-off.

## SBO-76 / UAT-DEF-007 — Advisor policy history

**Change:** `app/public_api.py` no longer infers SBOM identity from a generic `versions` collection or generic `version_id` field. Explicit source-version route ownership preserves logical/SBOM/VEX picker UUIDs and restore-version validation. Policy history retains its intended integer policy-version identity, including same-number policy/SBOM collisions. Permissions, tenant scope and optimistic concurrency remain authoritative.

**Files:** `app/public_api.py`, `tests/test_policy_public_identity.py`, `tests/test_scoped_configuration.py` (UUID tenant-header fixtures), `docs/secure-component-advisor/implementation-plan.md`.

**Evidence:** `api-policy.json` reproduces all three nonempty history 500s before reload and 200 after, publication 201, stale 409 with no extra version, own/foreign history separation, platform read and lower-role denials. `browser-policy.json` and `policy-{kind}.png` show actual accepted-risk, trust and scoring histories with persisted reasons. `pytest-policy-before.log` demonstrates the integer collision returning an unrelated SBOM UUID; focused final acceptance includes empty, nonempty, no-SBOM and same-number collisions, platform authorization, isolation and genuine SBOM version endpoints. See final results for the complete rerun outcome.

**Local outcome:** FIXED_AND_RETESTED.

**Recommended status:** In Review; final expanded backend regressions pass. Do not mark Done automatically.

## SBO-74 / UAT-DEF-005 — KEV authorization mismatch

**Change:** Tenant KEV synchronization now requires `platform:admin`, matching the existing server contract. Tenant views retain catalog reading and a disabled global action. A `PlatformKevSync` control is available on the platform dashboard only with current platform context and effective platform permission. Successful synchronization invalidates all three KEV query surfaces. Backend authorization was not relaxed.

**Files:** `frontend/src/app/kev/page.tsx`, `frontend/src/app/platform/page.tsx`, `frontend/src/components/admin/PlatformKevSync.tsx`, corresponding component regression test.

**Evidence:** `api-kev.json` verifies Platform 200 with future cutoff/no pruning/zero upserts, all five tenant-role requests 403, and exact catalog digest unchanged. `browser-kev.json` verifies all six role presentations; `kev-platform.png` and `kev-tenant.png` show the platform and tenant controls. `browser-kev-scope.json` records 7 passing checks, including the additional real platform button invocation with explicitly controlled future/no-prune request settings. Controlled request settings are identified separately from unmodified UI presentation checks. Unit regressions verify platform context plus effective permission and cache invalidation.

**Local outcome:** FIXED_AND_RETESTED.

**Recommended status:** In Review; independently retested, with limitations recorded in RESULTS.md.

## SBO-72 / UAT-DEF-001 — Candidate popup / Cancel

**Change:** Candidate results reserve space inside the scrolling body instead of overlapping the footer. The member dialog uses the shared fixed footer and an explicitly associated submit form. Outside-click dismissal waits until click completion, preventing layout movement between pointer-down and click. Combobox/listbox/option semantics, arrow selection, Enter, Escape, focus and loading presentation are covered. Discovery eligibility, search fields and backend policy are unchanged.

**Files:** `UserSearchCombobox.tsx`, `TenantUsersAccess.tsx`; combobox tests and shared-consumer integration selectors updated to accessible roles in settings tenant/platform tests.

**Evidence:** `browser-before.json` reproduces blocked Cancel with the real empty 200 response. `browser-after.json` records 16 passing checks: normal Cancel, four response states at 1440/800/390 px, keyboard selection, popup Escape and dialog Escape. `browser-candidate-visual.json` adds two passing desktop/mobile footer hit-test and normal-click checks, with screenshots. Loading/error states use explicitly controlled responses; empty/populated results use actual API data. `browser-membership.json` proves selected-member submission through the footer, followed by disposable membership cleanup. Frontend full suite: 1,800 passed across 199 files (`vitest-all-final.log`).

**Local outcome:** FIXED_AND_RETESTED.

**Recommended status:** In Review.

## SBO-75 / UAT-DEF-004 — Provider-neutral membership wording

**Change:** Both membership disable and remove confirmations now refer to the user's “sign-in identity.” Account, roles, self-warnings, confirmation checkbox and lifecycle callbacks are unchanged.

**Files:** `frontend/src/components/admin/MembershipConfirmDialogs.tsx`, its existing confirmation-dialog test.

**Evidence:** `browser-membership.json`, `membership-disable.png`, `membership-remove.png`: actual Native disposable member disable/enable and removal; account status/roles preserved during activation changes, original four Olympus memberships restored. Tests retain checkbox/callback behavior and assert provider-neutral wording. No claim of live HCL.CS or Entra login in this Native environment.

**Local outcome:** FIXED_AND_RETESTED.

**Recommended status:** In Review.

## SBO-54 — VEX regression fixtures and source-document boundary

**Change:** All original 13 failing nodes reproduced before edits. Public SBOM/component/project/product HTTP fixtures now use UUIDv4 IDs. Internal DB keys and stored audit assertions remain integers. Explicit invalid-integer tests remain and a new rejection/no-mutation control was added. The same four-file original VEX suite passes 69 tests (55 prior passes + 13 corrected nodes + one new negative case).

**Files:** VEX API/audit fixtures and `tests/vex_foreign_fixture.py`; expanded VEX lifecycle/acceptance/roadmap/work-queue fixtures; logical-SBOM test UUID/internal-key separation. `app/public_api.py` also corrects the independently reproduced CSAF source-document collision: document-native product IDs are preserved after the addressed SBOM's UUID/auth/tenant checks. `tests/test_vex_source_public_identity.py` verifies native IDs, unchanged raw source document and negative resource isolation.

**Evidence:** `SBO-54_FAILURE_CLASSIFICATION.md` lists every original node and final outcome; `pytest-vex-before.log` is 55 passed/13 failed, `pytest-vex-after.log` is 69 passed/0 failed. `api-vex-source-document-before.json` reproduces the genuine source-native ID rejection; `api-vex-source-document-after.json` records fresh-disposable import 200, foreign 404 and integer path 422. Final expanded backend acceptance passed 320 tests plus 8 subtests; Native/IAM/KEV/RBAC passed 287 tests, both with zero failures/skips. Exact commands are in RESULTS.md; do not equate the original-suite pass with all-repository green.

**Recommended status:** In Review. All original 13 failures and final selected backend regressions pass.

## SBO-73 / UAT-DEF-002 — Global discovery policy

**Disposition:** **Decision Needed**. Read-only implementation/security review is complete; no policy source change or tracker write.

See [SBO-73_DECISION_PROPOSAL.md](SBO-73_DECISION_PROPOSAL.md) for Option A (retain global browsing), Option B (exact-email/invitation-first), exposure, response minimization, permissions, audit, token-independent abuse budgets, consent and UX. Recommended Option B needs explicit Product Owner/Security approval. Exact-email lookup alone does not eliminate targeted enumeration. `api-discovery-review.json` distinguishes allowed global IAM visibility from rejected foreign Olympus business/membership access and proves discovery source unchanged.

**Recommended status:** Keep open, **Decision Needed**.
