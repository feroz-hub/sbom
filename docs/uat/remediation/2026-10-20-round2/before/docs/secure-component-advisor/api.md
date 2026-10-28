# Secure Component Advisor — API reference

Router: `app/routers/component_advisor.py`, prefix **`/api/component-advisor`**. All endpoints require an authenticated
tenant context. The tenant comes from the session (`X-Tenant-ID` is checked against the user's memberships) and is
never taken from the request.

## Conventions

| Topic | Rule |
|---|---|
| Scope | Optional `project_id`, `product_id`, `sbom_id` query params, validated by `dashboard_scope_dependency`. A child without its parent → **400**; an unknown or foreign id → **404** (existence is never revealed). |
| Dataset | Active, visible, HEAD SBOMs × the latest successful analysis run × current VEX contexts (spec §1.3). |
| Cross-tenant ids | Always **404**, identical to "not found" (FR-SCA-023). |
| Concurrency | Writes that edit an existing record take `row_version`; a stale one returns **409** with the current `row_version`. |
| Errors | `{"detail": {"code", "message"}}` for 400 / 409 / 422 domain errors; plain `{"detail": "..."}` for 403 / 404. |
| `meta` | Every read returns `applied_filters`, `unsupported_filters`, `scope`, `as_of`, `generated_at`, `historical_view`, `freshness` (latest analysis, lifecycle check, vulnerability source refresh, coverage, `stale_flags`), `policy_versions`, `thresholds`, `capabilities`. |
| As-of | Current state only (decision D-11). A non-current `as_of` → **400 `AS_OF_NOT_SUPPORTED`**. |
| Terminology | The best bucket is `NO_KNOWN_ACTIONABLE_VULNERABILITIES`. `score` orders candidates only (`score_semantics: ORDERS_CANDIDATES_ONLY`). |

## Component intelligence (read: `component_advisor:read`)

| Method & path | Purpose | Notes |
|---|---|---|
| `GET /summary` | Nine KPI cards and distributions (FR-SCA-002) | Each KPI carries the `/components` `filter` that reproduces it. Policy-backed cards return `value: null, status: POLICY_NOT_CONFIGURED`; Trusted has `render: false` until a trust policy exists. ETag-enabled. |
| `GET /components` | Drill-down table (FR-SCA-001/006/007) | Filters: `risk` (repeat or comma-separated: the nine classifications), `lifecycle` (SUPPORTED, MAINTENANCE, EOS, EOL, UNKNOWN), `needs_review`, `frequently_adopted`, `trusted`, `q` + `facet` (`all|name|purl|supplier|ecosystem|category|purpose`). Sort with `sort_by` (`risk|name|occurrences|products|actionable|latest_analysis`) and `sort_order`; page with `limit` (≤500) / `offset`. `total` equals the matching KPI value. |
| `GET /components/{canonical_key}` | One unique version (FR-SCA-001/009/010) | Adds `adoption` (projects / products by name, observed family versions, `CONTEXTUAL_EVIDENCE_NOT_PROOF`), `eligible_triggers` and the open `recommendation`. |
| `GET /components/{canonical_key}/classification` | Why the version is in its bucket (US-SCA-03/04) | `decided_by`, `review_reasons`, and the accepted-risk and trust criterion traces with their policy version ids. |
| `GET /search?q=` | Versions grouped by component family (FR-SCA-008/009) | `search_status`: `OK`, `NO_MATCHING_COMPONENTS` or `INSUFFICIENT_PURPOSE_EVIDENCE`. Purpose and category only match evidenced fields. |
| `GET /analytics?months=` | Effectiveness analytics (FR-SCA-024) | Recommendation outcomes, tenant-observed reuse and new High/Critical components per month. `analytical_only: true`. |

`canonical_key` is the SHA-256 of the canonical identity key (PURL → CPE + version → name + version + ecosystem
[+ supplier]). Rows with no reliable identity use `occ-<component id>`.

## Policies (`tenant:advisor-policy:read` / `update`)

Platform Admin equivalents use `/api/platform/configuration/advisor-policies/{kind}` and
`/{kind}/versions`, with `platform:advisor-policy:read` / `update`. They ignore selected-tenant headers and manage
platform defaults. Platform statuses are ACTIVE or DISABLED; INHERIT is invalid. The same concurrency token,
validation and append-only history apply. Platform state returns `tenant_override: null`, the platform slot's
`row_version`, and `platform_default`. Tenant overrides retain precedence.

| Method & path | Purpose |
|---|---|
| `GET /policies/{kind}` | Effective policy, tenant override and platform default. `kind` = `accepted-risk`, `trust` or `scoring`. |
| `GET /policies/{kind}/versions` | Append-only version history of the tenant override. |
| `POST /policies/{kind}/versions` | Publish a version: `{status: ACTIVE|DISABLED|INHERIT, rules, reason, row_version}` → **201**. Invalid rules → **422 `INVALID_POLICY`**; stale `row_version` → **409**. |

Rule schemas are in [configuration.md](./configuration.md).

## Purpose metadata

| Method & path | Permission | Purpose |
|---|---|---|
| `GET /purpose/{family_key}` | `component_advisor:read` | Purpose rows visible to the tenant (its own and the platform's). |
| `PUT /purpose/{family_key}` | `component:update` | Create or replace the tenant row for `(family_key, source)`. Body: `source` (`CURATED|PACKAGE|AI`), `functional_description`, `primary_use_case`, `technology_category`, `confidence`, `provenance`, `row_version`. AI rows require `provenance.model` and `provenance.generated_at`. |

## Recommendations

| Method & path | Permission | Purpose |
|---|---|---|
| `POST /recommendations` | `…:recommendation:create` | Body `{canonical_key, trigger_type, evaluate=true}`, with scope params for an SBOM-level item. **201** when created; **200** with `created: false` when an equivalent open item already exists. **422 `TRIGGER_NOT_SUPPORTED_BY_EVIDENCE`** when the trigger does not match current evidence. |
| `GET /recommendations` | `component_advisor:read` | List. Filters: `status` (repeatable), `trigger_type`, `canonical_key`, `sbom_id`, `limit`, `offset`. |
| `GET /recommendations/{id}` | `component_advisor:read` | Item, candidates, `review` summary and `capabilities`. |
| `POST /recommendations/{id}/evaluate` | `…:recommendation:create` | Re-run discovery. **409 `INVALID_STATE`** unless the item is OPEN or REVIEW_REQUIRED. |
| `GET /recommendations/{id}/candidates` | `component_advisor:read` | Candidates in review order, with the discovery summary. |
| `POST /recommendations/{id}/candidates` | `…:recommendation:review` | Add a manual candidate (REVIEW_REQUIRED items only). Body: `name`, `version`, `ecosystem`, `purl`, `rationale` (required), `technology_category`, `primary_use_case`, `licenses`, `lifecycle_status`, `compatibility_evidence`. |
| `GET /recommendations/{id}/candidates/{cid}` | `component_advisor:read` | Candidate with all 14 compatibility checks. |
| `GET /recommendations/{id}/candidates/{cid}/compatibility` | `component_advisor:read` | Check results and summary. |
| `GET /recommendations/{id}/candidates/{cid}/evidence` | `component_advisor:read` | Factor breakdown, scoring policy, confidence basis, history, freshness, explanation. |
| `POST /recommendations/{id}/decisions` | `review`, or `accept` for ACCEPT | Body `{decision, reason, row_version, candidate_id?}`. `decision` is RECOMMEND (requires `candidate_id`), ACCEPT, REJECT, DEFER, REQUEST_MORE_EVIDENCE or CLOSE. Responses: 403; 404; 409 stale or invalid state; 422 `CANDIDATE_BLOCKED`, `INSUFFICIENT_EVIDENCE`, `NOT_RECOMMENDED_CANDIDATE`, `CANDIDATE_REQUIRED`, `REASON_REQUIRED`. |
| `GET /recommendations/{id}/events` | `component_advisor:audit:read` | Append-only audit trail for the item. |
| `GET /audit/events?action=` | `component_advisor:audit:read` | Tenant audit history, including `POLICY_VERSION_PUBLISHED`. |

### Recommendation item fields

- `status`: `OPEN` → `EVALUATING` → `REVIEW_REQUIRED` → `RECOMMENDED` → `ACCEPTED | REJECTED | DEFERRED` → `CLOSED`.
- `discovery.status`: `CANDIDATES_FOUND`, `NO_CANDIDATES_FOUND`, `INSUFFICIENT_IDENTITY_EVIDENCE`,
  `SOURCE_NOT_IN_CURRENT_DATASET` or `DISCOVERY_FAILED`.
- `discovery.alternatives_status`: `EVALUATED`, `NO_CANDIDATES_FOUND`, `INSUFFICIENT_ECOSYSTEM_EVIDENCE`,
  `INSUFFICIENT_PURPOSE_EVIDENCE` or `PRODUCT_CONSTRAINTS_UNAVAILABLE`. Any of these can carry the suffix
  `_EXTERNAL_SOURCE_DEGRADED`.
- `capabilities`: `can_evaluate`, `can_recommend`, `can_accept`, `can_reject`, `can_defer`, `can_request_evidence`,
  `can_close`, `can_add_candidate`, `can_view_audit`, `can_decide`, `read_only_reason`. These are UI hints; the API
  enforces every action itself.

### Candidate fields

- `candidate_kind`: `SAME_FAMILY_VERSION | ALTERNATIVE`.
- `source_type`: `TENANT_OBSERVED | EXTERNAL | MANUAL`.
- `rank`: same-family candidates first, blocked last within each kind, then by score.
- `score` (0–100, ordering only), `confidence`, `blocked`, `compatibility` summary, `reasons` / `limitations` (codes),
  `explanation`, `history`, `freshness`, `recommended`.
- `approved_replacement`: true only for the accepted, unblocked candidate of an ACCEPTED / CLOSED item.
