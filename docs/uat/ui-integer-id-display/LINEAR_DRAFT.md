# Linear draft — do not publish automatically

Title: Restore readable persisted record IDs in authorized UI labels

Link to Dashboard/UI Synchronization, SBOM Lifecycle and Platform & Identity workstreams, and existing UUID implementation requirements (SBO-54, SBO-55, SBO-57, SBO-59, SBO-66 and SBO-77 as applicable). Preserve SBO-73 discovery privacy. Resolve exact issue ownership/relationships during manual review; no issue or status was changed by this task.

Implement output-only integer labels for authorized business objects, keep UUID-only public selectors/routing/cache identities, hide sensitive global IAM/tenant sequence keys, and verify Projects → Applications → SBOM → Analysis Run using newly owned fixtures. Require independent code review, CI and staging validation before delivery. No migration is required for this presentation change.

## Development-branch delivery draft

Implementation commit: [8f9f00e1f2fc143ac3ca1893d6d94e5860865177](https://github.com/feroz-hub/sbom/commit/8f9f00e1f2fc143ac3ca1893d6d94e5860865177). See GIT_DELIVERY_REPORT.md for independently verified publication and documentation commits. This is a draft only; no Linear issue/status is changed.

Attach the sanitized source manifest, reconciled backend coverage (4,624 PASS / 9 SKIP; 12 additional subtests), frontend results (1,838 PASS) and six verified-TLS Chrome scenarios. These are existing frozen executions, reverified during Git delivery, not new runtime tests. Preserve earlier failed/interrupted runs as history.

Keep links to SBO-54, SBO-55, SBO-57, SBO-59, SBO-66 and SBO-77 for manual ownership review. Request a separate review of the pre-existing report-subscription IAM response field. Preserve SBO-73 privacy restrictions and the deliberate Tenant/User/Membership/Grant numeric-display exceptions. SBO-78's older 100→101 approval text needs a current 101→102 cutover assessment; this presentation delivery neither executes nor approves that cutover. Release API/UI together only after the existing schema-compatibility gate, independent code review, CI, staging and UAT. Do not mark implementation requirements Done or infer release approval from Git publication.
