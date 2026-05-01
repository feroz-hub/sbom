# Changelog

All notable changes to the SBOM Analyzer are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Dashboard data consistency: KEV count, trend totals, lifetime metrics now reconcile across all surfaces.**
  Six P0/P1 contradictions where the same database returned different numbers
  on the dashboard, run-detail page, and lifetime panel. Root cause was the
  absence of a canonical metric layer — every endpoint reinvented its
  aggregation. Fixed by introducing [app/metrics/](app/metrics/) as the single
  source of truth, with a shared KEV-membership predicate, a shared
  latest-run-per-SBOM CTE, and the `findings.daily_distinct_active` query for
  the trend chart (replacing the broken raw-row sum).
  - **Bug 1 (P0):** dashboard "KEV exposed" silently returned `0` while the
    run-detail badge showed `6 KEV`. The dashboard query joined only on
    `vuln_id`, missing findings whose `aliases` contained the KEV-listed CVE.
    Now both surfaces use [`findings.kev_in_scope`](app/metrics/kev.py),
    locked by spec invariant I3.
  - **Bug 2 (P1):** trend empty-state copy reported "1 run so far" with 4
    same-day runs, because the FE counted distinct calendar dates as runs.
    Server now ships canonical `runs_total` on `/dashboard/trend`.
  - **Bug 3 (P0):** trend legend totaled 1,259 findings when lifetime distinct
    was 513 — mathematically impossible. Old query summed raw finding-rows
    across runs in the window. New query snapshots distinct findings as-of
    end-of-day per SBOM. Locked by invariant I4.
  - **Bug 4 (P1):** lifetime "Findings surfaced" included findings from
    ERROR runs, conflating ad-hoc partial output with cumulative truth. Now
    filtered to successful runs only.
  - **Bug 5 (P1):** "Net 7-day change" rendered `+513 / −0` on a first scan,
    treating the absent prior period as zero. The metric now returns an
    explicit `is_first_period` flag and the FE renders "first scan this week"
    copy with an em-dash.
  - **Bug 6 (P2):** trend empty state fired even with 4 runs because the
    condition tested distinct calendar dates < 7. Now uses
    `runs_distinct_dates` from the server.

### Added

- **Canonical metrics layer** under [app/metrics/](app/metrics/). Eight modules,
  one function per metric, every function references its catalog entry in
  [docs/dashboard-metrics-spec.md](docs/dashboard-metrics-spec.md). All
  dashboard, run-detail, and lifetime numbers route through this layer; inline
  metric SQL in router files is now forbidden (spec §8 deny list).
- **Cross-surface consistency tests** at
  [tests/test_metric_consistency.py](tests/test_metric_consistency.py),
  covering twelve invariants from spec §4 (one per Bug 1–6 plus six structural
  reconciliations). Marked `metric_consistency` for the CI gate.
- **`net_7day` envelope** on `/dashboard/posture` carrying `is_first_period`
  and `window_days`. Flat aliases (`net_7day_added`, `net_7day_resolved`)
  preserved for one release of FE back-compat.
- **`runs_total` and `runs_distinct_dates`** on `/dashboard/trend`; new
  `runs_completed_total` and `runs_distinct_dates` on `/dashboard/lifetime`.
- **Audit, spec, and runbook docs:**
  [docs/dashboard-metrics-audit.md](docs/dashboard-metrics-audit.md) (Phase 1
  diagnosis), [docs/dashboard-metrics-spec.md](docs/dashboard-metrics-spec.md)
  (canonical catalog), [docs/runbook-metric-debugging.md](docs/runbook-metric-debugging.md)
  (triage decision tree).
- **Eight-stage SBOM validation pipeline** ([ADR-0007](docs/adr/0007-sbom-validation-architecture.md)).
  Closes the eight P0 / 27 P1 gaps documented in [docs/validation-audit.md](docs/validation-audit.md).
  The pipeline is implemented under [app/validation/](app/validation/) and consists of
  ingress · format-detection · structural-schema · semantic · cross-reference-integrity
  · security · NTIA · signature stages. Every error / warning / info entry uses the
  structured shape `{code, severity, stage, path, message, remediation, spec_reference}`
  documented in [docs/validation-error-codes.md](docs/validation-error-codes.md).
- **`POST /api/sboms/upload`** — new multipart endpoint that runs the full validation
  pipeline before any DB write. Rejected SBOMs never get a row.
- **Vendored SBOM schemas** under [app/validation/schemas/](app/validation/schemas/)
  for SPDX 2.2 / 2.3 (JSON) and CycloneDX 1.4 / 1.5 / 1.6 (JSON + XSD). Provenance
  recorded in `SOURCE.md` per directory; never fetched at runtime.
- **Settings:** `MAX_DECOMPRESSED_BYTES` (200 MB), `MAX_DECOMPRESSION_RATIO` (100),
  `SBOM_SYNC_VALIDATION_BYTES` (5 MB), `SBOM_SIGNATURE_VERIFICATION` (default `false`).
- **Import-linter contracts** forbidding `app.validation` from depending on routers /
  services / DB / models, and forbidding any runtime HTTP fetch from inside the
  validator.

### Changed

- **`MAX_UPLOAD_BYTES` raised from 20 MB to 50 MB** to match ADR-0007 §4.1. The
  ASGI middleware enforces the cap before any body bytes reach a handler.

### Migration notes

- The legacy `POST /api/sboms` endpoint (JSON-string `sbom_data` field) keeps working
  unchanged for one release. New integrations should use the multipart upload.
- Existing SBOMs in the database are **not** retroactively rejected. The next analyse
  on each row re-validates; on failure, the analyse returns 422 with the structured
  report and the row stays in place. A follow-up CLI (`python -m app.validation.audit_existing`)
  will iterate every row and emit a triage queue.
- New runtime dependencies: `jsonschema`, `lxml`, `defusedxml`, `ruamel.yaml`,
  `packageurl-python`, `license-expression`, `spdx-tools`, `cyclonedx-python-lib`.
  `lxml` carries native libxml2 bindings — operators running custom Docker images
  must ensure `libxml2-dev` (or equivalent) is installed at build time.

### Security

- **Removed unsafe `xml.etree.ElementTree` fallback** in the CycloneDX XML parser
  (was at `app/parsing/cyclonedx.py:79`, XXE-vulnerable). All XML now flows through
  `defusedxml.lxml` with DTDs, external entities, and entity expansion forbidden.
- **JSON depth / array-length / string-length caps** (64 / 1,000,000 / 65,536 bytes)
  enforced via a custom `json.JSONDecoder` in stage 6. Prior code path was uncapped
  and vulnerable to nesting bombs.
- **Decompression-bomb defence** (200 MB absolute cap, 100:1 ratio cap) for `gzip`
  and `deflate` `Content-Encoding`. Streamed bombs are rejected mid-decode.
- **Prototype-pollution keys** (`__proto__`, `constructor`, `prototype`) rejected.
