# Integer record-label presentation implementation

Date: 2026-10-23. Branch: `feat/native-user-management`. Starting local and freshly fetched remote HEAD: `bf078cd3c136b027f77586fd9c180d9741ecf076`.

## Result and boundaries

**UI_INTEGER_ID_DISPLAY_PARTIALLY_COMPLETED** — business-resource/Run presentation is implemented and validated; sensitive Tenant/IAM User/Membership/Grant sequential-ID exposure is intentionally withheld pending a separate privacy decision. Their authorized names remain visible. Source remains local and unstaged for review. Existing internal integer keys and public UUIDv4 identities remain unchanged. There is no migration or model change.

The API emits the existing persisted integer as an output-only display field, alongside the original UUID, only for already-authorized business resources and Analysis Runs. Related Latest/Current SBOM keys come from their own existing internal references, not from the Application's key or a UUID fragment. Existing scoped UUID batching supplies the same references without another query.

The UI uses a small pure formatter plus accessible RecordIdDisplay component. It accepts positive safe integers only, uses nonwrapping tabular text, and emits a name/descriptive label or em dash when absent. Development-only diagnostics identify a missing presentation contract by resource kind, once per kind, without logging record values. No list index, UUID substring, derived number or synthetic reference is used.

## Visible changes

Projects cards/table, application list/mobile cards, latest/current SBOM links, product logical history, SBOM inventory, analysis list/detail/compare/history, dashboard/sidebar/command palette, VEX component evidence and vulnerability context now use numeric labels where the API projects them. Related names and version labels remain prominent. UUID-only transient stream/progress state uses descriptive text until a persisted DTO is available. Existing technical Copy UUID actions and UUID-backed hrefs remain separate.

Examples: `Project #873`, `Application #45`, `SBOM #567`, `Run #891`; links retain `/sboms/<UUID>` and `/analysis/<UUID>`. Search text for visible IDs uses their presentation values, while mutation arguments, selection, cache keys, React keys, worker/SSE identity and authorization retain UUIDs/internal contracts.

## Deliberate privacy exceptions

Tenant, IAM User, Membership and Platform Grant sequential keys remain private. Their administration, selection and fallback views use authorized names/email/role/tenant descriptions. These global sequences could reveal allocation/order across tenants or purpose-limited account discovery. No new integer lookup or directory access is offered. Provider-issued identifiers and source-native SBOM/VEX identifiers remain technical data, not rewritten labels.

These exceptions are deliberate and documented in SECURITY_REVIEW. If the Product Owner still requires these sensitive numeric keys, a separately reviewed privacy decision is required; this task does not expand SBO-73 visibility.

## Test environment

The operator explicitly clarified that new disposable test databases may be created/populated for E2E. Only newly named `sbom_ui_integer_display_*_test_20261023` databases and new synthetic browser identities are used. Browser API/UI/Redis ports are 18500/13500/56393. Original API18000/UI13000 processes were not targeted. Original populated database connections, migrations, row changes and seeded-account changes are prohibited and were not performed. The historical populated revision 101 is a reference, not a fresh observation.

The disposable schema is built using unchanged existing 100→101→102 sources. This is test fixture setup under the follow-up authorization, not a database migration deliverable. TLS verification uses existing trusted local certificate material without installing a CA or ignoring certificate errors. External provider HTTP is directed to the reviewed local Postman OSV simulation on 19401.

## Verification and remaining gates

See TEST_RESULTS for exact successes, failed development runs, interruptions and remaining runtime limitations. PostgreSQL briefly entered recovery during testing; its original container start timestamp stayed unchanged and no Docker lifecycle repair was performed. Do not infer an OOM cause from timing alone.

No staging, release/UAT sign-off or Git delivery is included. Full HCL.CS/Entra live-provider acceptance remains outside local evidence. Review the additive output contract and sensitive exceptions before publication.

`DATABASE_SCHEMA_AND_STORED_VALUES_UNCHANGED` — existing databases only; explicitly authorized new disposable fixture schemas/data are the sole exception.

`PUBLIC_UUID_API_CONTRACT_PRESERVED`

`NO_COMMIT_PUSH_OR_DEPLOYMENT_PERFORMED`

## Backend-rendered labels and existing caches

Report UI/email previews use a display-only rendering mode while JSON metadata and default PDF/XLSX resource references keep their UUIDs. The existing scoped batch queries supply actual Run/SBOM integer siblings without an extra lookup. Cached sidebar labels containing their own UUID are presented as a retained descriptive name or an unavailable-ID dash; stored pin identities and hrefs are unchanged.

The reviewed implementation currently comprises 73 changed/new source and test files. The exact final hashes and complete patch are recorded under `evidence/`; reports and sanitized summaries are additional documentation.

## Paired rollout requirement

Review and release the API presentation boundary with the corresponding frontend. An older API without display siblings produces names/dashes and a safe development diagnostic, rather than a UUID or invented number. This presentation change needs no migration. It does not waive the separately controlled revision-102 cutover already present on the branch: confirm the populated environment's actual compatible revision independently before any future startup/deployment. No such startup, cutover or deployment is performed here.

Creation of the new disposable databases used the local maintenance database only for cluster/catalog checks and new database creation. Application/test sessions selected the explicit new test databases; none selected the populated application database or historical A/B/D/E/F databases. Newly owned synthetic roles and fixtures are isolated from existing accounts.

## Observed final validation

The exact reconciled backend inventory is 4,633 unique cases: **4,624 PASS, 9 SKIP, 0 remaining FAIL/ERROR**, plus **12 passing subtests**. This combines the preserved non-green broad run with complete corrected test-module reruns, two actual opt-in executions and two isolated load cases; it is not one green monolithic Pytest invocation. Full frontend: **1,838 PASS across 203 files**. Real Chrome: **6 scenarios PASS**, TLS verification enabled. TypeScript, Webpack production build, scoped/full app-and-tests Ruff and ESLint pass; ESLint retains 52 existing warnings.

The complete UI/API audit, 73 source-file hashes/patch, source-equivalence and exact case-coverage proofs, and failed/interrupted development outcomes are available in this directory. Existing databases, original seeded identities, schema/migrations, and unrelated files were not modified by task actions. Only explicitly authorized new disposable fixture databases and task services were written/operated.

Remaining decisions: whether sensitive global sequential keys should ever be shown; independent review of the pre-existing report-subscription IAM reference noted in SECURITY_REVIEW; paired API/UI staging acceptance and existing branch revision compatibility. No full UAT/release sign-off or original-environment restart is implied.

Task-owned API18500/UI13500 were stopped after browser verification; task Redis56393 and OSV simulation19401 were stopped after final tests. New disposable databases and protected raw evidence remain for independent review. No original service was targeted.

Final original-environment metadata: API18000 was not listening, UI13000 remained running; cause unconfirmed. No original service was targeted/restarted by the task. Original-environment availability requires separate follow-up; feature validation used the independent task stack.
