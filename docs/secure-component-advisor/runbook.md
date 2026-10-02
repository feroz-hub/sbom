# Secure Component Advisor — runbook

## What it is

A tenant-scoped, **advisory-only** layer over existing SBOM analysis data. It reads components, findings, VEX contexts
and lifecycle data, and writes **only** its own tables: policies, purpose metadata, recommendations, candidates, checks,
factors and events. It never modifies a dependency, manifest, source file, SBOM, component, finding or VEX record.

## Deploy

1. Apply migrations 067–072 (see [migration-notes.md](./migration-notes.md)) before starting API and workers.
2. Run `python scripts/backfill_component_descriptions.py --dry-run`, then `--apply`.
3. Restart Celery workers so they load the `app.workers.component_advisor_tasks` module (task
   `component_advisor.evaluate_recommendation`).
4. Optionally publish accepted-risk, trust or scoring policies per tenant (see [configuration.md](./configuration.md)).

## Permissions (defaults, spec §9)

| Permission | Tenant Admin | Security Analyst | Developer | Viewer |
|---|---|---|---|---|
| `component_advisor:read` | ✓ | ✓ | ✓ | ✓ |
| `component_advisor:recommendation:create` | ✓ | ✓ | ✓ | |
| `component_advisor:recommendation:review` (recommend, reject, defer, request evidence, close, manual candidate) | ✓ | ✓ | | |
| `component_advisor:recommendation:accept` | ✓ | | | |
| `component_advisor:audit:read` | ✓ | ✓ | | |
| `tenant:advisor-policy:read` | ✓ | ✓ | | |
| `tenant:advisor-policy:update` | ✓ | | | |
| `component:update` (curated purpose writes; existing permission) | ✓ | ✓ | | |

`scripts/compare_authorization_catalog.py` must report zero mismatches after deploy.

## Observability (NFR-SCA-004)

These are structured log events (`app.logger.log_event`). They carry `tenant_id`, ids and counts, never component names
or free text.

| Event | When |
|---|---|
| `secure_component_advisor.query` | Every summary / components / search request (`endpoint`, `scope_level`, `filter_count`, `result_count`) |
| `secure_component_advisor.policy.published` | A policy version is published |
| `recommendation.created` | A work item is created |
| `recommendation.discovery.started` / `.completed` / `.failed` | Evaluation, with `duration_ms`, `status` and the candidate count |
| `recommendation.compatibility.completed` / `.scoring.completed` | Per evaluation, with candidates, blocked count and `duration_ms` |
| `recommendation.reviewed` + `recommendation.{recommended,accepted,rejected,deferred,more_evidence_requested,closed}` | Each decision |

Every event carries the request `correlation_id` (`X-Request-ID`), which is also stored on the work item and its audit
events. There is no Prometheus or OpenTelemetry in the codebase; durations are emitted as log fields so a log pipeline
can derive metrics.

The audit trail lives in two places. `component_recommendation_event` is append-only and served by
`GET /recommendations/{id}/events` and `GET /audit/events`. Creates, evaluations and decisions are also mirrored to the
tenant `audit_log`.

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| KPIs look stale after a VEX decision | Snapshot cache | The change markers include VEX status counts and `row_version` sums, so the cache should bust on the next request. The TTL is at most 300 s. |
| First dashboard load is slow on a large tenant | Cold snapshot build (about 14 s at 200k occurrences) | Expected on a cold cache; warm requests take about 1 s. If it becomes a problem, implement the per-SBOM incremental rollup (NFR-SCA-006). |
| Purpose or category search always empty | No purpose evidence | Run the description backfill; add curated purpose rows. |
| No alternatives proposed | `alternatives_status` explains why: no evidenced category, generic ecosystem, or no product constraints | Add curated `technology_category` rows for the source and candidate families. |
| `*_EXTERNAL_SOURCE_DEGRADED` | An external adapter failed or its breaker is open | Core features are unaffected; check the adapter, and the breaker resets after 15 min. |
| Decision returns 409 | Someone else changed the item | Reload and retry; the UI does this automatically. |
| Decision returns 422 `CANDIDATE_BLOCKED` / `INSUFFICIENT_EVIDENCE` | By design: blocked or under-evidenced candidates cannot be recommended or accepted | Add evidence, or choose another candidate. |
| Background evaluation fails for a non-default tenant | Fixed on 2026-10-02 (audit rows were attributed to tenant 1) | Make sure the deployed code includes the fix. |
| `RuntimeError: … rows are append-only` | Code tried to update or delete a policy version or event | Publish a new version or event instead; never edit history. |

## Performance reference

See the T44 entry in the [implementation plan](./implementation-plan.md) for measured p95 values.
`pytest -m bench tests/test_component_advisor_bench.py -s` reproduces them, with scale set through the `SCA_BENCH_*`
environment variables.

## Local testing notes

- Postgres on this workstation runs on 5432. Set `TEST_DATABASE_URL=…/sbom_analyser_test_<name>` and use one database
  per concurrent pytest run.
- On Windows, stopping a background pytest shell does not stop pytest itself. Check for orphaned `python.exe`
  processes before reusing a test database.
