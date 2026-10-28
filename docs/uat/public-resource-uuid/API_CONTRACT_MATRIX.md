# API contract matrix

Public HTTP selectors are UUIDv4; internal router DTOs and domain services keep integers. OpenAPI is projected at the public boundary. Authorization dependencies run before UUID lookup.

| Surface | Request | Response | Authority / exclusions |
|---|---|---|---|
| `/api/tenants/{tenant_id}/users` | User UUID, tenant UUID | Membership UUID and User UUID | Tenant invite/member permission; SBO-73 discovery unchanged |
| `/api/tenants/{tenant_id}/users/{membership_id}` and activate/deactivate/profile/audit | Membership UUID | membership_id / target_membership_id UUID | Tenant scope plus endpoint RBAC; assignment/event IDs stay int |
| `/api/tenants/{tenant_id}/users/{user_id}/roles` and history | User UUID | User and Membership references UUID | Role mutations still select the User, not the Membership |
| `/api/v1/auth/tenants/{tenant_id}/memberships` | User UUID | Membership/User/Tenant UUID | Existing enrollment authority |
| Platform user membership summaries | User UUID | Membership UUID | Existing platform discovery restrictions |
| `/api/platform/administrators` and `/{grant_id}` | User UUID for create; Grant UUID for revoke | Grant/User/actor UUID | Platform-only; no active tenant; duplicate/conflict protections |
| `/api/runs` recent/search/detail/findings/cursor and `/dashboard/runs` | Run UUID paths/cursor; existing resource UUID filters | Run UUID and finding analysis_run_id | Tenant-scoped; findings remain integer |
| SBOM analyze JSON and SSE/history/latest | SBOM UUID | Stable Run UUID | Analysis permission; worker integer keys unchanged |
| Legacy `/analyze-sbom-*` | Existing six-resource UUID fields | Run aliases UUID | Existing deprecation headers |
| `/api/v1/runs/{run_id}/ai-fixes` all batch/progress/stream/estimate/cancel variants | Run UUID | Run UUID, batch IDs unchanged | Existing analysis/AI authorization; broker task keys integer |
| `/api/analysis-runs/compare`, `/api/v1/compare` and downloads | Run UUID query/body | Run UUID summaries/download names | Tenant scope; compare cache keys unchanged |
| CSV/SARIF/PDF run exports | Run UUID | UUID run filename/reference | Report IDs and vulnerability IDs unchanged |
| `/api/v1/scans/{scan_id}/cves/{cve_id}` | Analysis Run UUID | Existing CVE contract | `scan_id` is an AnalysisRun alias |
| VEX analysis evidence/run snapshot/version comparison | Run UUID | Run references UUID | VEX investigation/statement/event IDs remain int |
| VEX assignees/assignment/history | `membership:<UUID>` | Same public namespace | Stored `membership:<int>` and developer-assigned checks unchanged |
| Schedules, report selectors, advisor/dashboard references | Named Run UUID references | Same | Schedule/report/recommendation IDs remain int |

The complete source/line occurrence register, pre-change declarations and generated OpenAPI are under evidence. The refreshed register contains 197 route bindings and 196 OpenAPI operations in the audited route families, including neighboring operations that do not themselves select one of the three resources. Each binding records its source function, dependencies and explicit resource selectors; this is not a blanket conversion of every field in those families. TEST_RESULTS records the complete accepted backend inventory, focused checks and real browser evidence separately.

Current FastAPI keeps an original, sometimes unprefixed APIRoute in ASGI scope for included routers. Identity resolution now uses the server-selected effective route template, matching authorization policy lookup. Query-only routes receive decoding after their authorization dependencies. This corrects the demonstrated legacy comparison 422 failure without accepting integer selectors.

Product/project/logical-SBOM nested analysis projections use the same explicit Run field contract. New resource selectors require canonical hyphen positions in addition to UUIDv4/version/variant checks. No numeric compatibility period is enabled. Rollout flags retain their existing 409 behavior for a valid authorized Run; missing resource resolution occurs first and remains 404.

VEX history referencing a physically removed Membership has a null public reference with an explicit identity-unavailable flag. No replacement UUID or integer is emitted; stored audit/authorization keys are preserved. Unrelated event IDs remain integers.

Example wire response (illustrative UUIDs):

```json
{"membership_id":"550e8400-e29b-41d4-a716-446655440000","user_id":"7c9e6679-7425-40de-944b-e07fc1f90ae7"}
```

A persisted analysis returns the same UUID in `id`, applicable `run_id`/`runId` references, polling, findings and history. Background workers and integer relational columns retain their internal keys.
