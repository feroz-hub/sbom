# Round 4 proposed Linear updates

Draft only. Existing issues were read; no issue was created, changed or marked Done.

## SBO-54 — backend/frontend regression

Existing issue: https://linear.app/sbom-analyzer/issue/SBO-54/run-full-backendfrontend-regression-against-latest-source-and-classify

Proposed status: retain In Progress pending final evidence/reviewer acceptance. Current checkpoint: `ROUND4_BACKEND_REGRESSION_PARTIALLY_COMPLETED`.

The exact 346 previously unexecuted nodes passed (8 additional passing subtests). All 228 original unresolved nodes have passing focused retests, with individual original-to-current selectors and root-cause classification. Current complete collection is 4,392 cases. Frozen run: **FINISHED**, outcomes **{"PASS": 4383, "SKIP": 8, "FAIL": 1, "ERROR": 0, "XFAIL": 0, "XPASS": 0, "NOT RUN": 0}**, source unchanged **True**. Final frontend/static validation: **NOT RUN**. These are distinct executions, not an aggregate green result.

Confirmed fixes: tenant-bound maintenance reconciliation CLI; scoped batched public-ID response serialization (12 queries to one; unchanged 20,000-occurrence benchmark passes); fresh-install Alembic marker width. Obsolete wire integer fixtures now use persisted UUIDv4 values, internal keys remain integers, and historical migration cases use fresh transition-specific databases. Five directory cases assert actual existing V5 HTTP 403 and preserve matching/projection unit coverage; no authorization catalogue or SBO-73 policy change.

Attach: `docs/uat/round4/ROUND4_BACKEND_REGRESSION_REPORT.md`, `ROUND4_FAILURE_CLASSIFICATION.md`, `ROUND4_TEST_RESULTS.json`, frozen manifest/log/XML, task-only patch and source hashes. Preserve initial failed attempts and benchmark timeout. Review exact final skip reasons; no paid-provider credentials were activated. No commit, push or deployment was performed.

## SBO-55 — Ubuntu browser/E2E acceptance

Existing issue: https://linear.app/sbom-analyzer/issue/SBO-55/build-and-execute-full-browser-e2e-acceptance-on-isolated-ubuntu-test

Proposed status: retain In Progress. Round 4 provides backend/PostgreSQL regressions and seven local live API safeguards, not the required full isolated Ubuntu Playwright/Next/FastAPI/Redis/Celery A–I acceptance. Frontend production build and unit tests do not substitute for browser execution. Next action: run existing acceptance scenarios on the authorized Ubuntu environment, record source version/configuration and attach browser/API/worker evidence. Reuse this issue; do not create a duplicate.

## Preserved decisions and release gate

SBO-73 remains Decision Needed. No approval is inferred for global IAM discovery changes, seeded privilege elevation, idle-expiry policy or cryptographic signature verification. Existing SBO-70–76 remediation evidence is preserved; no tracker status is changed. Full application UAT/production sign-off remains withheld pending required target-environment evidence and accepted policy/external exceptions.
