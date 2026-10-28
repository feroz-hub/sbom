# Linear IAM User UUID delivery evidence — local draft only

Team: Platform & Identity. Proposed title: Implement immutable UUIDv4 public IAM User identities while retaining integer relationships.

References: SBO-20, SBO-22, SBO-55, SBO-66 and SBO-73. Preserve the existing SBO-73 privacy/global-discovery decision.

- [Implementation commit](https://github.com/feroz-hub/sbom/commit/409212f66be418a9d71c707d505d156a2a2df58c): 73 source files, forward-only migration101, scoped FastAPI/OpenAPI UUID boundary, frontend User UUID integration, database/security/regression tests.
- [Documentation and evidence commit](https://github.com/feroz-hub/sbom/commit/19b64ff4b2acd2592c226bb1dfdfb43cbb7617b3): six reports and curated sanitized evidence.
- [Development branch](https://github.com/feroz-hub/sbom/tree/feat/native-user-management/docs/uat/user-public-uuid): Git delivery report and later attestation. Resolve the exact final attestation SHA from the verified operator delivery response; this document does not embed its own commit SHA.

Recorded disposable acceptance: backend 4,414 PASS / 7 explicit SKIP, zero FAIL/ERROR, plus 12 passing subtests; frontend 1,812 PASS; installed Chrome9 PASS with TLS verification. These executions preceded Git delivery. No GitHub CI pass is asserted.

The populated Greenfield database remains revision100 without the IAM public UUID column. Migration101, backup/recovery/writer-window approval, service cutover, staging and live HCL.CS/Entra acceptance remain pending. This delivery does not authorize execution, UAT sign-off or release. Internal membership/grant/Analysis Run IDs and external provider/session semantics remain unchanged.

No Linear issue, status, requirement or privacy policy is modified by this local evidence draft. Do not mark the requirement Done or interpret commit publication as migration approval.
