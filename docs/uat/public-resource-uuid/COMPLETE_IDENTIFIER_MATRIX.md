# Complete identifier matrix

All ten designated resources retain integer database primary and foreign keys. Their public selectors and resource references are UUIDv4 only. Provider subjects, session IDs, event IDs, findings, assignments, role codes and counters are separate contracts.

| Resource | Table | Forward revision | Public fields |
|---|---|---|---|
| Tenant | tenants | 100 | id / tenant_id |
| Project | projects | 100 | id / project_id |
| Product | products | 100 | id / product_id |
| Logical SBOM | logical_sbom | 100 | id / logical_sbom_id |
| SBOM Source | sbom_source | 100 | id / sbom_id |
| SBOM Component | sbom_component | 100 | id / component_id |
| IAM User | iam_users | 101 | id / user_id |
| Tenant Membership | tenant_users | 102 | membership_id / tenant_user_id |
| Platform Grant | platform_user_roles | 102 | grant_id |
| Analysis Run | analysis_run | 102 | id / run_id / runId / analysis_run_id / scan_id |

Membership and User are separate: one User UUID may have several tenant-scoped Membership UUIDs. VEX keeps `membership:<integer>` internally; its authenticated public assignee interface uses `membership:<UUID>`. Platform Grants are global and require platform permissions without an active tenant. Runs are tenant-scoped even for platform users. Celery and findings retain integer run keys.

The pre-change audit is preserved in `evidence/identifier-occurrences.before.json` (1,738 occurrences) and `evidence/route-inventory.before.json` (48 matching declarations). The occurrence register distinguishes public boundary, internal persistence/worker, frontend and tests; individual semantic route coverage is recorded in API_CONTRACT_MATRIX.md.

Integer membership/grant/run acceptance is removed at HTTP selectors. No compatibility grace period is enabled. Saved numeric deep links must be reselected after the separately approved cutover; cache/session storage must be cleared. JWT subjects and provider issuer/subject mappings do not change.

Public scalar Run aliases include `run_a`, `run_b`, `run_a_id`, `run_b_id`, `last_run_id`, `last_analysis_run_id`, `previous_run_id`, `current_run_id`, `findings_analysis_run_id`, `lifecycle_analysis_run_id`, and the persisted-Run `scan_id`/`scanId` aliases only on their explicit application routes. Provider mirror/sync run IDs remain separate. Typed nullable fields retain null when no Run exists. Reports and SSE use the same persisted identities; worker/store/cache keys remain integers.

Current generated OpenAPI and the detailed source-file/function/line/method/dependency register are in `evidence/public-resource-route-matrix.json`. The source hash manifest and patch enumerate every implementation and regression fixture change. Internal-only mini-FastAPI DTO tests deliberately retain their original integer inputs; they do not publish the application boundary or authorize integer public selectors.
