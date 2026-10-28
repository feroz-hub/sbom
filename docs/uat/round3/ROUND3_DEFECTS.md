# Round 3 — Confirmed defects and unresolved gaps

## R3-DEF-001 — Repair candidate download changes bytes before hash approval

Severity: High (deterministic repair approval blocked when the reviewer supplies the downloaded artifact hash). Proposed existing tracking: SBO-55 coverage/acceptance, with SBO-54 regression evidence; no tracker write or duplicate created.

Reproduction: upload the synthetic uppercase `LIBRARY` fixture; analyze and generate a REPAIRED candidate; download `/api/sbom-validation-sessions/{session_id}/repair/{job_id}/download`; calculate SHA256; submit that hash to approval. Actual: 409 `Candidate differs from the reviewed hash`; expected: 200 after valid explicit approval. Evidence: `evidence/repair.json`, `evidence/repair-candidate-approve.json`, correlated request `89cd89f1cdc7`. The preceding wrong-hash negative attempt also returned 409 and did not import.

Root cause: `app/public_api.py` parses and compactly serializes every application/json Response. The native candidate download uses Response, so bytes change while `candidate_sha256` correctly refers to the stored immutable artifact. Original/draft downloads stream bytes and follow a different path. Scope correction to successful candidate downloads after normal route authentication/tenant handling; keep business response public-ID translation enabled.

Status: FIXED_AND_RETESTED locally. New focused immutable-byte/hash/conflict/idempotency test passed; fresh live reject/approve and security cases in evidence/repair-after.json passed.

## R3-DEF-002 — Supported CUSTOM cadence dependency missing

Severity: Medium. Existing tracking: SBO-55/SBO-54; original ENV-002. Supported schema/service expose CUSTOM but neither installation manifest declared croniter. Real valid and invalid disabled expressions both returned 422 dependency-not-installed, so syntax could not be accepted. Evidence: evidence/scope-creation.json. Pin croniter 6.2.4 in both manifests; install only isolated repository venv. Enforce the existing documented five-field contract and reject impossible schedules through strict validation. Upstream reference: https://pypi.org/project/croniter/. Fixed and independently retested: evidence/cron-accepted.json (13 PASS), pytest-cron.log (20 PASS).

## R3-DEF-003 — Invalid display timezone accepted

Severity: Low. Existing tracking: SBO-55 scheduling acceptance. POST MONTHLY with `timezone=Mars/Base` returned 201 on an owned disabled schedule although the API declares an IANA name. Evidence: evidence/timezone-before.json; owned schedule removed through API. Add IANA validation without changing the documented UTC firing semantics; Monthly data and seeded contexts unchanged. Fixed and independently retested: evidence/cron-accepted.json (13 PASS), pytest-cron.log (20 PASS).

## R3-DEF-004 — Signed CycloneDX fails structural validation due to missing JSF schema

Severity: Medium. Proposed tracking: SBO-55 SBOM validation acceptance / SBO-54 regression. `signature` in the vendored BOM schema references `jsf-0.82.schema.json`, which was absent and unregistered. Real validation returned internal schema error E025 before the explicit deferred verifier could run. Evidence: evidence/conversion.json R3-SIGNATURE-IMPLEMENTATION-CONTRACT; source `app/validation/stages/schema.py`. Vendor the immutable upstream dependency from the existing schema commit and register it locally; add signed-document/no-network/malformed-signature tests. Do not implement or claim deferred cryptographic verification. Retest in progress.

R3-DEF-004 follow-up: the first focused run caught a syntax typo (corrected before API reload), then revealed jsonschema's optional URI format checker was absent. Without it, JSF `algorithm` oneOf matches both the known-name enum and unchecked URI branch. Pin/install jsonschema's non-GPL URI checker dependency `rfc3986-validator==0.1.1` in both manifests. Do not relax the schema's oneOf, type, format or signature validation. The new test's reference to a nonexistent ErrorReport convenience property was corrected to inspect its typed entries. Initial failures remain in the evidence logs.


R3-DEF-004 current status: FIXED_AND_RETESTED structural schema handling only. Eight focused signed-schema/signature-stage tests passed. Real explicit verify_signature=true reaches E110 deferred verifier contract; cryptographic acceptance remains BLOCKED. Source provenance and URI checker installation are retained.

## R3-DEF-005 — Transient session-check outage redirects authenticated users to login

Severity: Medium. Existing tracking recommendation: SBO-54 regression / SBO-55 browser acceptance; no duplicate created. Real clean Native Admin session check returned200/authenticated true, auth/me200, followed by503/authenticated false under development-host pressure. The original AuthProvider treated any non-OK session response as confirmed unauthenticated, cleared tenant context and triggered login navigation. Evidence: evidence/browser-session-diagnostic.json and failed project navigation attempts.

Correction: use the existing error/service-unavailable bootstrap state for non-OK session responses other than401. Clear the exposed user, render no protected content, preserve tenant preference, and require Retry to revalidate the server session. Confirmed invalid/expired session200 false and401 continue to clear authentication. Do not accept a503 as authenticated or disable token validation.

Before regression: 3 FAIL/26 PASS. After:29 PASS. Actual browser:503 injected at session-check boundary shows Retry without dashboard/login redirect; cookie retained without recording its value; retry validates live backend and restores Dashboard and protected Projects. evidence/browser-session-retry-accepted.json:3 PASS. The first post-fix browser attempt still served the private runtime source copy; exact corrected hook hash was synced and the accepted rerun tests that code (evidence/frontend-sync.json). No service/database reset.

Status: FIXED_AND_RETESTED locally; final full frontend/type/lint/build rerun pending.

## R3-ENV-001 — Development stability acceptance remains unmet

Observation / release-validation gap; application-leak root cause unconfirmed. Bounded current Chrome navigation reached seven modules with200, but Users & Access did not render the required heading within60s. Before/after snapshots: same Next PID80918 and unchanged single historical restart-warning count; no additional ERR_EMPTY_RESPONSE. Host swap7897.94→9143.81MiB and expensive dev compilation were observed alongside broad PostgreSQL regressions. Separate current session-check503 was reproduced and its incorrect login redirect fixed as R3-DEF-005. Do not claim this resolves host memory pressure, prove a leak, change OS swap, or kill unrelated apps. Original UAT-ENV-FRONTEND-RESTART is currently FAIL after an actual partial attempt. Repeat serial navigation and bounded normal concurrency after regressions settle, then profile isolated service if still reproducible. Tracking recommendation SBO-55/SBO-54, with SBO-59 sign-off withheld.


## R3-DEF-006 — Advertised legacy analysis routes omitted from UUID boundary

Severity: Medium. Existing tracking recommendation SBO-54 / SBO-55. The five deprecated routes still advertise a future sunset and keep analysis:run authorization, but install_public_boundary selected only /api/ and /dashboard routes. Supported /analyze-sbom-{nvd,github,osv,vulndb,consolidated} therefore rejected valid SBOM UUIDs422 as integer parsing errors and retained internal integer wire IDs. The original regression snapshots reproduced this; current isolated real OSV request on an owned R3 SBOM returned422 (request657bb345f8a7).

Correction: include only the explicit five legacy paths in the existing boundary, after their unchanged authorization dependency. Preserve integer domain FK/run IDs while translating public SBOM references. Rewrite the advertised successor Link from the resulting public SBOM UUID. No blanket route/policy relaxation. Exact current tests include five positive existing-run/idempotency cases and five parametrized integer/unknown/foreign/Viewer no-mutation cases. The first new fixture omitted the required completed_on column and produced10setupERROR; corrected the fixture, retained the diagnostic run, final rerun in progress. Existing five analysis snapshots plus policy/repair/VEX serialization guards22PASS in that intermediate run.

Real after-reload acceptance: evidence/legacy-analysis-after.json7PASS. Viewer403, foreign404, integer422, unknown UUID404; real OSV analysis200, UUID response and successor header, numeric run ID, persisted run readback200/five findings. API restart was limited to verified local PID/main Greenfield target without bootstrap/migrations; see evidence/api-reload-legacy.json. Final focused guard summary pending.


## Final defect dispositions

| Defect | Local outcome | Final evidence |
|---|---|---|
| R3-DEF-001 candidate artifact bytes | FIXED_AND_RETESTED | Fresh repair API approval/rejection/security/idempotency; actual review/decision UI10PASS; final immutable-byte regression included in32PASS. |
| R3-DEF-002 CUSTOM dependency/strict cron | FIXED_AND_RETESTED | croniter pinned both manifests;20focusedPASS/13livePASS. |
| R3-DEF-003 invalid IANA timezone | FIXED_AND_RETESTED | Invalid timezone422, valid timezone/UTC next-run and Monthly preservation; same focused/live scheduling evidence. |
| R3-DEF-004 signed schema dependencies | FIXED_AND_RETESTED for structural handling |8focusedPASS, real E110 deferred verifier contract. Crypto itself remains BLOCKED. |
| R3-DEF-005 session503 bootstrap | FIXED_AND_RETESTED | Browser Retry3PASS; final full frontend1,805PASS/type/lint/build. No authentication bypass. |
| R3-DEF-006 legacy UUID boundary | FIXED_AND_RETESTED | Final32focusedPASS, actual OSV/scoping/persistence7PASS. VulnDB without credentials remains required400. |
| R3-ENV-001 overlapping-load timeout | Initial FAIL retained; serial follow-up PASS |18checks/two8-module rounds, same PID, no added restart/empty-response records. Resource/performance acceptance remains limited; no leak claim. |

The legacy guard's intermediate1FAIL was an invalid assumption that VulnDB-only execution works without its required provider key. The final test asserts its existing400 configuration gate; remaining paths return their existing run, and all five routes retain integer/foreign/Viewer no-mutation checks. No provider key or Product decision was invented.

## Unresolved regression and scope gaps

The diagnostic backend run has244 failures;17 exact nodes now pass in independent retests and227 remain failing/unresolved. The separately executed Advisor benchmark adds1 failure: guarded raw SQL fixture bootstrap is rejected before any performance measurement. This is a test-maintenance/coverage gap, not evidence of a business-data leak or permission defect. Do not relax tenant guards. All exact node diagnostics and next actions are in evidence/backend-failure-classification.json; optional benchmark trace is in evidence/pytest-advisor-benchmark.log.346 current inventory nodes still have no execution evidence.

No full application sign-off. Five original acceptance cases remain BLOCKED:3 account-status lifecycles, cryptographic verification, independent idle-expiry contract. SBO-73 remains Decision Needed; Ubuntu/staging/CI acceptance remains unexecuted. Reuse SBO-54/SBO-55/SBO-59 for these reconciliation drafts; no new tracker issue or Done transition.
