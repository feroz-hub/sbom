# Pending-work delivery — 24 October 2026

This delivery follows the explicit request to commit and push **all** pending
work. It includes the shared VEX/version-evidence correction, viewport/header/
sidebar work, macOS runtime ownership handling, Greenfield port preflight fix,
their tests and documentation, UUID migration preparation/audits, historical
UAT source snapshots and evidence, OpenAPI snapshots, and SBOM repair workspace
artifacts. The complete commit contains 2,018 files: 2,016 originally pending
files, the updated existing `.gitattributes`, and this report.

The archived source trees are historical evidence, not additional production
implementations. The default pytest configuration collects `tests/`, not the
archived `docs/uat/**/before` trees. Migration preparation remains subject to
its existing source locks, approvals and target authorization; committing it
does not authorize execution or refresh those approvals.

## Verification carried forward from the implemented source

- Launcher/runtime/Greenfield: **189 passed**, using standalone unit/loopback
  tests with `--noconftest` and no database bootstrap.
- Backend VEX, posture, Analysis history, tenant authorization and metric
  contracts: **117 passed** on a new disposable PostgreSQL cluster.
- Focused cross-module frontend: **500 passed, 47 files**.
- Full frontend: **1,863 passed, 1 failed, 206 files**. The failure is the
  previously reproduced remote inventory test expecting the removed `View SBOM`
  button. It is not reported as a green full suite.
- Actual-frontend browser checks with intercepted API fixtures: **15 passed**
  (8 existing Analysis scenarios, 7 VEX/product scenarios), including strict
  HTTPS verification, responsive layout, loading/errors, scope and exports.
- TypeScript and the production Webpack build passed. Scoped frontend lint
  found zero errors and 26 warnings reproduced on the existing HEAD baseline.
- Before staging all work, Python AST parsing passed for all **975** pending
  Python files, including historical snapshots. This establishes syntax only.

Exact commands and scope limits are in
[the shared evidence report](shared-version-evidence-ui.md) and
[the Greenfield restart report](greenfield-restart-port-preflight.md).
The later Greenfield start synchronized the current frontend into its usual
workspace and reached actual API/frontend/worker readiness at revision 102.
This supersedes the earlier UI report's initial non-deployment note; a new
authenticated live UI acceptance run is not claimed.

## Additional archived migration checks

Each `infra/uuid-migration/**/test_*.py` script was invoked separately using
`.venv/bin/python -B <path>` without enabling a live mode. Six of sixteen suites
passed. Ten failed or were blocked; the archive is not described as passing
against today's tree.

Passed suites:

- `f-readonly-acceptance/test_correction_offline.py`
- `f-readonly-acceptance/test_readonly_offline.py`
- `frozen047-driver-correction/test_w251_offline.py`
- `frozen047-execution/test_w25_offline.py`
- `frozen047-execution/test_w25_settings_offline.py`
- `staged-runner/test_uuid_integrity_mount_offline.py`

Non-passing suites:

- `f-activation/test_activation_offline.py`
- `f-budget-reconciliation/test_budget_offline.py`
- `f-transaction-correction/test_transaction_offline.py`
- `finalization-tests/test_finalization_offline.py`
- `fresh-bootstrap/test_fresh_bootstrap.py`
- `fresh-coordinator/test_coordinator_offline.py`
- `staged-runner/test_expand_one_step.py`
- `staged-runner/test_uuid_integrity_connection_offline.py`
- `staged-runner/test_uuid_integrity_offline.py`
- `staged-runner/test_w17b5_e_readonly.py`

Observed failures include historical graph/source pins expecting 79 active/91
total revisions while the current tree has 82/94, expired approvals, and missing
historical artifact fixtures. The connection suite first required an artifact
directory; supplying a new temporary directory still left one of nine tests
blocked by its missing `baseline-corrected.private.py` input. No pinned hashes,
expired approval, target rule or frozen migration was changed to turn these
historical checks green. No live migration or provisioning was executed.

## Git and evidence integrity

The credential candidate scan covered all pending text, binary archive members
and exact matches to the active Greenfield runtime/setup credentials. No active
credential matches were found. Reviewed candidates were license identifiers,
synthetic test inputs, redacted/invalid diagnostic URLs and a 27-character private
key *marker* used by a refusal test, containing no key material. No local `.env`,
runtime password, private signing key, cookie state or database file is added.

The existing `.gitattributes` rules are retained and extended to prevent line
ending normalization in hash-referenced UAT/migration inputs and SBOM workspaces.
Staged blob hashes were compared to the original working-file bytes; this caught
and corrected Git's proposed CRLF normalization in three historical inputs.
Historical whitespace is intentionally preserved: the initial staged check
reported 1,012 diagnostics across 35 archived files. Current source/tests/docs
outside those historical artifact directories pass the whitespace check.

Original working files and live application data were not reset, removed or
rewritten for this delivery. Git ignored local runtime state remains private.
