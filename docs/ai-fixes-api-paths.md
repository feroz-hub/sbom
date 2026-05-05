# AI fixes — canonical API paths

Reference for frontend integration. Supersedes the §2.1 endpoint table from the original integration prompt where they differ. Source of truth is the FastAPI router source, not the spec.

## Configuration (admin)

| Method | Path | Source |
|---|---|---|
| GET | `/api/v1/ai/providers/available` | [app/routers/ai_usage.py:350](../app/routers/ai_usage.py#L350) |
| GET | `/api/v1/ai/providers/available/{name}` | [ai_usage.py:365](../app/routers/ai_usage.py#L365) |
| GET | `/api/v1/ai/providers` | [ai_usage.py:176](../app/routers/ai_usage.py#L176) |
| GET | `/api/v1/ai/credentials` | [ai_credentials.py:309](../app/routers/ai_credentials.py#L309) |
| GET | `/api/v1/ai/credentials/{cred_id}` | [ai_credentials.py:317](../app/routers/ai_credentials.py#L317) |
| POST | `/api/v1/ai/credentials` | [ai_credentials.py:332](../app/routers/ai_credentials.py#L332) |
| PUT | `/api/v1/ai/credentials/{cred_id}` | [ai_credentials.py:389](../app/routers/ai_credentials.py#L389) |
| DELETE | `/api/v1/ai/credentials/{cred_id}` | [ai_credentials.py:456](../app/routers/ai_credentials.py#L456) |
| POST | `/api/v1/ai/credentials/test` (unsaved test-before-save) | [ai_credentials.py:554](../app/routers/ai_credentials.py#L554) |
| POST | `/api/v1/ai/credentials/{cred_id}/test` (re-test saved) | [ai_credentials.py:586](../app/routers/ai_credentials.py#L586) |
| PUT | `/api/v1/ai/credentials/{cred_id}/set-default` | [ai_credentials.py:487](../app/routers/ai_credentials.py#L487) |
| PUT | `/api/v1/ai/credentials/{cred_id}/set-fallback` | [ai_credentials.py:519](../app/routers/ai_credentials.py#L519) |
| GET | `/api/v1/ai/settings` | [ai_credentials.py:644](../app/routers/ai_credentials.py#L644) |
| PUT | `/api/v1/ai/settings` | [ai_credentials.py:672](../app/routers/ai_credentials.py#L672) |

## Usage telemetry

| Method | Path | Source |
|---|---|---|
| GET | `/api/v1/ai/usage` | [ai_usage.py:143](../app/routers/ai_usage.py#L143) |
| GET | `/api/v1/ai/usage/trend?days=N` | [ai_usage.py:239](../app/routers/ai_usage.py#L239) |
| GET | `/api/v1/ai/usage/top-cached?limit=N` | [ai_usage.py:290](../app/routers/ai_usage.py#L290) |
| GET | `/api/v1/ai/pricing` | [ai_usage.py:189](../app/routers/ai_usage.py#L189) |
| GET | `/api/v1/ai/metrics` | [ai_usage.py:325](../app/routers/ai_usage.py#L325) |
| GET | `/api/v1/ai/metrics/prometheus` | [ai_usage.py:335](../app/routers/ai_usage.py#L335) |

## Batch fix generation (per run)

| Method | Path | Source | Spec-vs-reality |
|---|---|---|---|
| POST | `/api/v1/runs/{run_id}/ai-fixes` | [ai_fixes.py:150](../app/routers/ai_fixes.py#L150) | **Spec said `/ai-fixes/generate` — actual has no `/generate` suffix.** |
| GET | `/api/v1/runs/{run_id}/ai-fixes/estimate` | [ai_fixes.py:230](../app/routers/ai_fixes.py#L230) | **Pre-flight cost + duration estimate.** Spec called this "summary" — but spec's summary was post-batch; this endpoint is pre-flight only. |
| GET | `/api/v1/runs/{run_id}/ai-fixes/progress` | [ai_fixes.py:312](../app/routers/ai_fixes.py#L312) | match |
| POST | `/api/v1/runs/{run_id}/ai-fixes/cancel` | [ai_fixes.py:322](../app/routers/ai_fixes.py#L322) | match |
| GET | `/api/v1/runs/{run_id}/ai-fixes/stream` | [ai_fixes.py:329](../app/routers/ai_fixes.py#L329) | match (SSE: `event: progress` + `event: end`) |
| GET | `/api/v1/runs/{run_id}/ai-fixes` | [ai_fixes.py:348](../app/routers/ai_fixes.py#L348) | **Post-batch list of cached fixes for the run.** Closest match to spec's "summary"; consume alongside `/estimate` for pre/post views. |

## Single-finding (CVE modal)

| Method | Path | Source | Spec-vs-reality |
|---|---|---|---|
| GET | `/api/v1/findings/{finding_id}/ai-fix` | [ai_fixes.py:419](../app/routers/ai_fixes.py#L419) | match. Generates on demand if cache cold. |
| POST | `/api/v1/findings/{finding_id}/ai-fix:regenerate` | [ai_fixes.py:433](../app/routers/ai_fixes.py#L433) | **Colon syntax**, not slash. `:regenerate` is FastAPI's path-tail convention for actions on a resource. |

## Response envelope

Single-finding endpoints return:
```json
{
  "result": <AiFixResult> | null,
  "error":  <AiFixError>  | null
}
```

Frontend reads `error` first; if non-null, render the structured error code (`schema_parse_failed`, `provider_unavailable`, `circuit_breaker_open`, `budget_exceeded`, `grounding_missing`, `internal_error`). On `error === null && result !== null`, render the bundle.

## Auth

All endpoints sit under the `_protected` dependency chain wired in [app/main.py:277-279](../app/main.py#L277). The rollout gate (`_require_ai_enabled` at [ai_fixes.py:118](../app/routers/ai_fixes.py#L118)) additionally checks: kill switch → master flag → canary bucket. Non-passing requests return 403/503 with `error_code` in the detail object.
