# Changelog

All notable changes to the SBOM Analyzer are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
