# Analysis and SBOM compatibility endpoint inventory — 2026-07-22

## Canonical paths

| Purpose | Method and path | Repository callers |
| --- | --- | --- |
| Upload | `POST /api/sboms/upload` | `frontend/src/lib/api.ts:uploadSbom`; upload, validation, and deduplication tests |
| Synchronous analysis | `POST /api/sboms/{id}/analyze` | `frontend/src/lib/api.ts:analyzeSbom`; SBOM detail and snapshot tests |
| Streaming analysis | `POST /api/sboms/{id}/analyze/stream` | `frontend/src/hooks/useAnalysisStream.ts`; SSE contract tests |
| Comparison | `POST /api/v1/compare` | `frontend/src/lib/api.ts:compareRuns`; compare router/service tests |

## Compatibility paths retained

| Method and path | Compatibility contract | Successor | Sunset |
| --- | --- | --- | --- |
| `POST /api/sboms` | JSON SBOM creation; still used by test fixtures and exported as `createSbom` | `POST /api/sboms/upload` | 2027-01-31 |
| `POST /analyze-sbom-nvd` | NVD-only response with flat run fields plus legacy `sbom`/`summary` blocks | `POST /api/sboms/{id}/analyze` | 2027-01-31 |
| `POST /analyze-sbom-github` | GHSA-only equivalent | `POST /api/sboms/{id}/analyze` | 2027-01-31 |
| `POST /analyze-sbom-osv` | OSV-only equivalent | `POST /api/sboms/{id}/analyze` | 2027-01-31 |
| `POST /analyze-sbom-vulndb` | VulDB-only equivalent | `POST /api/sboms/{id}/analyze` | 2027-01-31 |
| `POST /analyze-sbom-consolidated` | Consolidated legacy response; exported by the frontend API module | `POST /api/sboms/{id}/analyze` | 2027-01-31 |
| `GET /api/analysis-runs/compare?run_a=&run_b=` | v1 comparison by vulnerability id set | `POST /api/v1/compare` | 2026-12-31 |

Every retained path remains covered by contract/snapshot tests. No path is
removed in this phase because repository callers still exist. Compatibility
calls emit a structured warning, increment a process-local counter, expose
OpenAPI `deprecated: true`, and return `Deprecation`, `Sunset`, and successor
`Link` headers.
