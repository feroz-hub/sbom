# SBOM Analyser / SBOM Lifecycle Management Platform

## Codebase-Based Project Explanation and Readiness Assessment

**Audit date:** 22 June 2026  
**Audited path:** `/Users/ferozebasha/sbom`  
**Basis:** current working tree, including currently uncommitted lifecycle-provider/OpenEoX files  
**Decision:** **CONDITIONAL GO** for controlled/internal use; **NO production-wide GO** until the P0/P1 items in section 31 are closed.

This report distinguishes code-confirmed behavior from recommendations. A feature marked **Missing** was not found in the inspected code. A feature marked **Partial** has a real implementation but an incomplete path, control, UI, test, or production property.

---

## 1. Executive Summary

SBOM Analyser is a full-stack Software Bill of Materials lifecycle and vulnerability-management platform. It accepts SPDX and CycloneDX SBOMs, validates them through an eight-stage gate, stages repairable invalid documents in a repair workspace, extracts and deduplicates components, enriches lifecycle evidence, scans multiple vulnerability providers, stores analysis history, manages VEX and remediation records, schedules rescans, compares versions/runs, and exports operational reports.

The implementation is substantial and well tested: FastAPI/SQLAlchemy on the backend, Next.js/React/TanStack Query on the frontend, 31 linear Alembic migrations, Celery/Redis workers for scheduled work, 1,371 passing backend tests, and 461 passing frontend tests. The canonical multipart upload correctly validates before creating a trusted `SBOMSource`, then returns HTTP 202 and backgrounds lifecycle/VEX/completeness/NVD-cache enrichment.

The architecture is best described as a **layered modular monolith moving toward Clean/Hexagonal Architecture**, not completed Clean Architecture. The validation package and vulnerability source adapters have good boundaries. Most other features still let routers and services use SQLAlchemy directly; there is no general `app/repositories/` package despite comments claiming one. Several very large modules remain (`SbomDetail.tsx` 2,395 lines, `app/analysis.py` 2,015, `api.ts` 1,852, `sboms_crud.py` 1,190).

The most important gaps are:

1. The frontend does not attach bearer/JWT authorization headers, while backend production auth is opt-in and defaults to `none`; CORS defaults to `*`.
2. Project permanent deletion does not use the comprehensive SBOM delete service and omits multiple child tables; it is not covered by a comparable hard-delete test suite.
3. Version editing can persist `failed`/`quarantined` content as a normal `SBOMSource`, then sync components and enqueue enrichment, which weakens the trusted-ingress boundary.
4. Signature verification is a feature-flagged stub, not cryptographic verification.
5. Risk score v2 combines CVSS, EPSS, and KEV only; lifecycle, VEX, and remediation are displayed separately rather than included in the score.
6. VEX discovery blocks literal private IPs but does not resolve hostnames or revalidate redirect destinations, leaving DNS-rebinding/redirect SSRF risk.
7. The new NVD client has timeouts, rate limiting, cache, API key support, failure caching, and a per-scan circuit breaker, but intentionally performs no bounded retry; the older `app/analysis.py` path still contains separate retry logic.
8. `npm audit --omit=dev` reports two moderate production dependency findings through Next.js/PostCSS.

---

## 2. Project Purpose

### Simple meaning

SBOM Analyser lets a user upload an SBOM, verify its quality, turn its package inventory into queryable components, find vulnerabilities, identify unsupported or end-of-life software, record VEX exploitability decisions, assign remediation work, preserve versions, and export evidence.

### Why it exists

- **Software supply-chain visibility:** inventory packages from SPDX/CycloneDX rather than relying on a flat application list.
- **Vulnerability tracking:** query NVD, OSV, GitHub Security Advisories, and optionally VulDB; retain findings per analysis run.
- **Lifecycle risk:** distinguish Supported, EOL, EOS, EOF, Deprecated, Unsupported, EOL Soon, Possibly Unmaintained, and Unknown.
- **SBOM quality/compliance:** structural, semantic, cross-reference, security, NTIA-minimum-element, and completeness checks.
- **Exploitability context:** retain VEX statements without deleting the underlying vulnerability.
- **Remediation operations:** owner, due date, status, audit history, aging, MTTR, velocity, and SLA views.
- **Reporting and evidence:** original/converted/enriched SBOMs, lifecycle packs, VEX packs, vulnerability Excel, PDF, CSV, SARIF, and compare exports.

Primary evidence: `README.md`, `app/main.py`, `app/routers/`, `app/services/`, `app/parsing/`, `app/validation/`, `frontend/src/app/`, and `frontend/src/lib/api.ts`.

---

## 3. Technology Stack and Project Map

### Backend map

| Area | Code evidence | Explanation |
|---|---|---|
| FastAPI entry point | `app/main.py`; `run.py` | Constructs the app, middleware, lifespan, auth dependencies, error handler, and routers. |
| Routers | `app/routers/*.py`; `app/nvd_mirror/api.py` | SBOMs, upload, validation sessions, versions, runs, projects, analysis, dashboards, lifecycle, VEX, remediation, schedules, exports, AI, CVEs, health, NVD mirror. |
| Services | `app/services/*.py`; `app/services/lifecycle/*.py` | Conversion, deletion, dedupe, completeness, analysis persistence, lifecycle, NVD cache/client, VEX, remediation, compare, scheduling, reports. |
| Parsers | `app/parsing/{format,extract,cyclonedx,spdx,xml_support}.py` | Normalized extraction from CycloneDX/SPDX JSON and XML. |
| Validators | `app/validation/pipeline.py`; `app/validation/stages/*.py` | Pure eight-stage pipeline with vendored schemas and stable error codes. |
| Converters | `app/services/sbom_conversion_service.py` | SPDX JSON to CycloneDX 1.6 JSON. |
| Enrichers | `app/services/sbom_enrichment_service.py`; `app/services/lifecycle/*`; `app/services/nvd_enrichment_service.py` | Background lifecycle, embedded VEX, completeness, and NVD cache enrichment. |
| Vulnerability sources | `app/sources/{nvd,osv,ghsa,vulndb,runner,factory}.py`; `app/analysis.py` | Provider adapters, fan-out, matching, severity, CPE/PURL logic, legacy implementation. |
| Metrics | `app/metrics/*.py`; `app/services/dashboard_metrics.py` | Canonical dashboard aggregates, trends, exploitability, lifecycle, remediation, SLA, health. |
| Exporters | `app/routers/{analysis,pdf,sbom_versions,vex}.py`; `app/services/{compare_export,sbom_vulnerability_excel_report_service}.py`; `app/pdf_report.py` | Native/enriched SBOM, CSV, SARIF, PDF, XLSX, lifecycle/VEX packs, compare files. |
| Database | `app/db.py`; `app/models.py`; `app/models_mixins.py` | SQLAlchemy; SQLite default, PostgreSQL supported; transparent soft-delete filter. |
| Migrations | `alembic/versions/001_...` through `031_...` | One linear migration head. |
| Background jobs | `app/workers/*.py`; `app/workers/celery_app.py` | Celery/Redis scheduled analysis, cache maintenance, NVD mirror, CVE refresh, AI fix tasks. |
| Tests | `tests/` | 127 `test_*.py` files; validation, providers, lifecycle, VEX, deletion, conversion, scheduling, dashboard, migration drift, auth, resilience. |

### Frontend map

| Area | Code evidence | Explanation |
|---|---|---|
| Framework | `frontend/package.json`; `frontend/src/app/` | Next.js 16 App Router, React 18, TypeScript, Tailwind CSS. |
| API client | `frontend/src/lib/api.ts`; `frontend/src/lib/env.ts` | Direct browser-to-FastAPI fetch wrapper with timeouts and typed `HttpError`. |
| State/cache | `frontend/src/app/providers.tsx`; `@tanstack/react-query` | Five-minute default stale time, one retry, no window-focus refetch. |
| Pages | `frontend/src/app/page.tsx`, `sboms/`, `projects/`, `analysis/`, `analysis/compare/`, `schedules/`, `settings/`, repair session page | Dashboard, inventory, detail, runs, compare, schedules, settings, validation repair. |
| Components | `frontend/src/components/` | Dashboard, SBOM, analysis, compare, project, schedule, CVE modal, AI fix/settings, layout/UI. |
| Hooks | `frontend/src/hooks/` | SBOM mutations, list pagination, streaming analysis, background recovery, AI progress, URL/filter state. |
| Cache invalidation | `frontend/src/lib/queryInvalidation.ts` | Central invalidation maps for SBOMs, projects, runs, findings, dashboard, lifecycle, VEX, schedules, AI. |
| Types | `frontend/src/types/*.ts` | API/domain wire types for SBOMs, findings, dashboards, CVEs, compare, AI. |
| Tests | colocated `*.test.ts(x)` files | 66 test files, 461 passing tests, including accessibility and integration tests. |

### Dependency highlights

- Python 3.11+, FastAPI, SQLAlchemy 2, Pydantic 2, Alembic, httpx/requests, ReportLab, openpyxl, Celery/Redis, PyJWT, cryptography, SlowAPI, jsonschema/lxml/defusedxml/packageurl/SPDX/CycloneDX libraries (`pyproject.toml`, `requirements.txt`).
- Next.js, React, TanStack Query, React Hook Form, Zod, Recharts, Vitest, Testing Library (`frontend/package.json`).

---

## 4. Full Forms and Glossary

| Term | Full form | Simple meaning and project use |
|---|---|---|
| SBOM | Software Bill of Materials | Package/component inventory uploaded into `SBOMSource` and expanded into `SBOMComponent`. |
| SPDX | Software Package Data Exchange | Supported input; parsed by `app/parsing/spdx.py`, validated at versions 2.2/2.3, and convertible to CycloneDX. |
| CycloneDX | Cyclone Dependency-Track Exchange | OWASP BOM format; supported input/output, validation schemas 1.4/1.5/1.6, enriched export target. |
| CVE | Common Vulnerabilities and Exposures | Canonical vulnerability identifiers stored in `AnalysisFinding.vuln_id`; also VEX/remediation keys. |
| CVSS | Common Vulnerability Scoring System | Base score/vector normalized into finding severity and risk score. |
| CPE | Common Platform Enumeration | Platform identifier used for trusted NVD `cpeName` queries. |
| PURL | Package URL | Package identity used for OSV/lifecycle lookup and first-priority component dedupe. |
| NVD | National Vulnerability Database | NIST provider queried by `cveIds` or trusted CPE 2.3 `cpeName`; mirror/cache supported. |
| OSV | Open Source Vulnerabilities | Open-source vulnerability API used in analysis and as lifecycle vulnerability evidence. |
| VEX | Vulnerability Exploitability eXchange | Product-context assertion: affected/not affected/fixed/under investigation/unknown. |
| CSAF | Common Security Advisory Framework | One supported VEX JSON input shape in `VexProvider._parse_csaf`. |
| EOL | End of Life | Product/version lifecycle ended. |
| EOS | End of Support | Vendor support ended or ending. |
| EOF | End of Fix | Vendor no longer supplies fixes. |
| API | Application Programming Interface | FastAPI REST/SSE endpoints consumed by `frontend/src/lib/api.ts`. |
| CRUD | Create, Read, Update, Delete | Projects, SBOM metadata, schedules, credentials, and related resources. |
| CORS | Cross-Origin Resource Sharing | Configured in `app/main.py`; `CORS_ORIGINS` defaults to `*`. |
| ORM | Object-Relational Mapping | SQLAlchemy models and sessions. |
| DB | Database | SQLite by default; PostgreSQL URL supported. |
| FK | Foreign Key | Relationships among SBOMs, components, runs, findings, VEX, schedules, and projects. |
| SSE | Server-Sent Events | Streaming analysis progress and AI batch progress. |
| RBAC | Role-Based Access Control | Narrow role checks for admin/security-sensitive lifecycle, VEX, conversion, and restore operations. |
| SLA | Service-Level Agreement | Severity-based remediation windows and overdue/due-soon dashboard metrics. |
| UI | User Interface | Next.js dashboard and workflow pages. |
| DTO | Data Transfer Object | Pydantic/TypeScript request-response models; the code does not consistently use the name DTO. |
| JSON | JavaScript Object Notation | Primary wire/input/output format. |
| XML | Extensible Markup Language | Supported for CycloneDX input; defensive XML parsing is used. |
| REST | Representational State Transfer | Resource-oriented HTTP API, alongside SSE and legacy action endpoints. |
| JWT | JSON Web Token | Optional HS256 authentication mode in `app/auth.py`. |
| CI/CD | Continuous Integration / Continuous Delivery | SBOM lifecycle metadata recognizes build phases; SARIF supports code-scanning pipelines. Repository CI files were not found in this audit. |
| NTIA | National Telecommunications and Information Administration | Minimum SBOM elements checked in validation stage 7. |
| EPSS | Exploit Prediction Scoring System | FIRST.org probability cached in `epss_score` and used in risk/dashboard exploitability. |
| KEV | Known Exploited Vulnerabilities | CISA catalog cached in `kev_entry`, used in risk and dashboard prioritization. |
| SARIF | Static Analysis Results Interchange Format | Findings export at `/api/analysis-runs/{run_id}/export/sarif`. |
| SCA | Software Composition Analysis | The product performs SCA-like inventory and vulnerability analysis, though “SCA” is not a central code type. |
| GHSA | GitHub Security Advisory | GitHub advisory provider and alias identifier. |
| MTTR | Mean Time To Remediate/Resolve | Computed by `app/metrics/remediation.py`. |
| OpenEoX | Open End-of-Life Exchange | Lifecycle export produced by current `openeox_report.py` work. |

---

## 5. High-Level Architecture

```text
Next.js UI
  ↓ TanStack Query + frontend/src/lib/api.ts
FastAPI routers
  ↓
Services / application functions
  ↓
Parsers · validator pipeline · converters · provider adapters · exporters
  ↓
SQLAlchemy models/session + external HTTPS providers
```

### Architectural classification

**Confirmed:** modular monolith, layered organization, source-adapter pattern, explicit validation pipeline, single deployable backend, single relational database.

**Partial Clean Architecture:**

- Good boundaries: `app/validation` is side-effect-free and import-linter protected; `app/sources/base.py` defines a provider port; `app/nvd_mirror` has explicit domain/application/ports/adapters layers.
- Missing general repository boundary: no `app/repositories/` exists. Routers such as `sboms_crud.py`, `projects.py`, `runs.py`, `dashboard_main.py`, and `sbom_versions.py` issue SQLAlchemy queries directly. Services also import ORM models/session.
- Thick/god modules: `app/analysis.py`, `sboms_crud.py`, `sbom_versions.py`, `frontend/src/lib/api.ts`, and `SbomDetail.tsx` combine multiple concerns.
- Duplicate/legacy paths: v1 and v2 compare APIs coexist; `app/analysis.py` still owns provider implementations behind thin adapters; legacy JSON SBOM creation coexists with canonical multipart upload.
- Export generation partly lives in routers (`routers/analysis.py`, `routers/sbom_versions.py`, `routers/vex.py`) rather than dedicated exporter services.

Preferred next state remains **Clean/Hexagonal Architecture inside a Modular Monolith**. Microservices are not justified by the present evidence.

---

## 6. Backend Architecture

`app/main.py` applies SlowAPI rate limiting, CORS, gzip responses, maximum request-body size, request/response logging, non-leaky 500 handling, auth dependencies, startup schema/seed/backfill, and router registration. It is slimmer than older versions but still contains roughly 600 lines of SQLite compatibility DDL and seed/backfill logic.

The backend layers are:

- **Delivery/API:** FastAPI routers and Pydantic schemas.
- **Application services:** SBOM sync, validation repair, conversion, lifecycle, NVD enrichment, remediation, deletion, scheduling, compare, metrics.
- **Domain/pure logic:** validation stages, parsing helpers, dedupe identities, scheduling calculations, risk formula, lifecycle decision rules.
- **Infrastructure:** SQLAlchemy models/session, external HTTP provider clients, ReportLab/openpyxl, Redis/Celery, credential encryption.

Error handling uses deliberate `HTTPException` envelopes for expected errors and `app/error_handlers.py` for unhandled exceptions. The latter returns `{code, message, correlation_id}` without leaking stack traces. `app/logger.py` supports text/JSON console logs and rotated JSON files; `app/main.py:log_requests` records method, path, status, and duration.

---

## 7. Frontend Architecture

The UI uses Next.js App Router client pages. `frontend/src/lib/api.ts` calls FastAPI directly, applies 30-second default timeouts (longer for upload/analysis/export), parses structured errors into `HttpError`, and returns typed data. There is no Next.js BFF/proxy in the active client design.

TanStack Query is configured in `frontend/src/app/providers.tsx` with five-minute stale data, one retry, and no focus refetch. `queryInvalidation.ts` centralizes most mutation consequences. Pages and components explicitly render skeletons, empty rows, alerts, toast errors, and route-level error/loading boundaries.

Important limitation: `performRequest` and the SSE fetch in `useAnalysisStream.ts` do not add `Authorization`. The SSE hook still sends optional `nvd_api_key`/`github_token` fields that the current backend payload model ignores. Therefore the browser UI is not directly compatible with enabled backend bearer/JWT auth unless an external gateway injects authorization.

---

## 8. Database Architecture

### Core models

| Model/table | Purpose and important relationships | Deletion/scope |
|---|---|---|
| `Projects` / `projects` | Project metadata; owns SBOMs, runs, schedules. | Soft deletable; global portfolio entity. |
| `SBOMType` / `sbom_type` | Reference values such as SPDX/CycloneDX. | Shared reference table. |
| `SBOMSource` / `sbom_source` | Raw SBOM, metadata, validation, completeness, dedupe, version lineage, conversion/enrichment status. FKs to project/type and self-links (`parent_id`, source/converted IDs). | Soft deletable; one row per uploaded/edited/restored/converted version. |
| `SBOMComponent` / `sbom_component` | Extracted component, PURL/CPE, lifecycle evidence, duplicate marker and canonical link. | Soft deletable; SBOM-specific. |
| `SBOMValidationSession` / `sbom_validation_sessions` | Temporary untrusted repair content, report, expiry, import link. | Not a trusted SBOM; events cascade on hard delete. |
| `SBOMValidationSessionEvent` | Append-only repair audit. | Session-specific. |
| `AnalysisRun` / `analysis_run` | Immutable scan execution and severity totals. | Soft deletable; SBOM/project-specific. |
| `AnalysisFinding` / `analysis_finding` | Vulnerability match, CVSS, provenance, component link. | Soft deletable; run-specific. |
| `VexDocument` / `vex_documents` | Uploaded/embedded/discovered VEX source and raw document. | SBOM-specific; DB cascade declared. |
| `VexStatement` / `vex_statements` | Component/vulnerability VEX status and evidence. | SBOM/document-specific; component may be null for unmatched statements. |
| `ComponentLifecycleCache` | Shared normalized provider result with TTL/staleness. | Global/shared cache. |
| `ComponentLifecycleOverrideAudit` | Manual lifecycle override history. | Component-specific. |
| `VexOverrideAudit` | Manual VEX override history. | Component/vulnerability-specific. |
| `VulnerabilityRemediation` | Project-wide remediation keyed by vulnerability/component/version. | Project-specific and deliberately retained on SBOM hard delete. |
| `VulnerabilityRemediationAudit` | Append-only remediation changes. | Cascades with remediation/project. |
| `AnalysisSchedule` | Project or SBOM cadence, next/last run, failures. | Soft deletable; target FK cascades, last-run FK sets null. |
| `SBOMAnalysisReport` | Legacy analysis report. | Soft deletable; retained for compatibility/backfill. |

### Shared/cache/operational models

`RunCache`, `KevEntry`, `EpssScore`, `CveCache`, `SourceResponseCache`, `NvdLookupCache`, `CompareCache`, NVD mirror settings/CVE/sync-run rows, AI usage/provider/fix/batch/credential/settings/audit rows, and general `AuditLog` support caching, provider resilience, comparison, AI remediation, and auditability.

### Relationship and deletion notes

- Many historical FKs have no `ON DELETE CASCADE`; explicit child-first deletion is required.
- `app/db.py` injects `is_active = true` for every `SoftDeleteMixin` SELECT unless `include_deleted=True` is set.
- Restore endpoints restore only the selected parent row, not all tombstoned descendants.
- Global caches and project-scoped remediation intentionally survive SBOM permanent deletion.

---

## 9. End-to-End SBOM Workflow

```text
Upload file
  → ingress size/encoding/decompression checks
  → detect standard/version/encoding
  → schema + semantic + reference + security + NTIA + signature stages
  → reject to repair session OR create trusted SBOMSource
  → extract components
  → calculate identity groups and persist canonical + duplicate rows
  → HTTP 202 to browser
  → background lifecycle + embedded VEX + NVD-cache + completeness enrichment
  → user starts or schedules vulnerability analysis
  → OSV/GHSA/VulDB first, then NVD enrichment
  → cross-source dedupe and persist AnalysisRun/AnalysisFinding
  → dashboard, VEX, remediation, compare, and export views
```

The backend upload itself does **not** create a vulnerability `AnalysisRun`. The SBOM list page calls `triggerBackgroundAnalysis` after upload; scheduled/manual APIs can also create runs. This differs from older README wording.

---

## 10. Upload Workflow

**Purpose:** admit only trusted SBOMs while returning quickly after local parsing/persistence.

**How it works:**

1. `SbomUploadModal.tsx` reads the selected file and calls `useUploadSbom` → `api.uploadSbom`.
2. `api.uploadSbom` builds multipart form data and POSTs `/api/sboms/upload` with a 120-second client timeout.
3. `app/routers/sbom_upload.py:upload_sbom` validates project/type FKs, reads bytes, enforces the 50 MB cap, and runs `app.validation.run`.
4. Errors create a repair session only when safe. No `SBOMSource` is inserted.
5. A clean document is inserted with status `validated`, original/current format, report counts, and enrichment `pending`.
6. `sync_sbom_components` extracts/deduplicates/persists components.
7. FastAPI `BackgroundTasks` runs `run_post_upload_enrichment` after the 202 response.
8. The frontend inserts an optimistic “ANALYSING” row and starts SSE vulnerability analysis.

**Files:** backend `app/routers/sbom_upload.py`, `app/services/sbom_service.py`, `app/services/sbom_enrichment_service.py`; frontend `SbomUploadModal.tsx`, `useSbomMutations.ts`, `useBackgroundAnalysis.ts`, `api.ts`.  
**Models:** `SBOMSource`, `SBOMComponent`, optional validation session/event.  
**Endpoints:** `POST /api/sboms/upload`; legacy `POST /api/sboms`.  
**Tests:** `test_sbom_upload_validation_persisted.py`, `test_max_upload_size.py`, validation integration tests, `SbomUploadModal.repair.test.tsx`.  
**Status:** **Implemented, needs production hardening.**  
**Gaps:** validation is synchronous even above the documented 5 MB async threshold; `BackgroundTasks` is not durable; UI says 20 MB while backend allows 50 MB; UI requires a project although backend does not.

---

## 11. Eight-Stage Validation Workflow

The canonical order is defined by `app/validation/pipeline.py:default_stages`. Stage 7 always runs for a fuller quality report; other later stages skip after prior errors. Error HTTP precedence is 413 > 415 > 422 > 400. At most 100 entries are returned.

| Stage | Purpose and checks | Example | Result/UI behavior | Status |
|---|---|---|---|---|
| 1. Ingress Guard | Empty body, upload/decompressed size, gzip/deflate, compression ratio, UTF-8/BOM. `stages/ingress.py`. | `SBOM_VAL_E001_SIZE_EXCEEDED`, E004 encoding. | Security/ingress failures are blocked and generally not staged. | Implemented. |
| 2. Format & Version Detection | JSON/XML/YAML/tag-value recognition; ambiguous/unknown format; SPDX/CycloneDX version. `stages/detect.py`. | E010 indeterminate, E013 unsupported. | Structured error with stage/path; safe content can enter repair. | Implemented. |
| 3. Structural Schema | Vendored CycloneDX JSON Schema/XSD 1.4–1.6 and SPDX JSON schemas 2.2/2.3; parse/type/required/enum/format violations. `stages/schema.py`, `validation/schemas/`. | E026 missing required field. | Repair UI groups the entry under “Structural schema.” | Implemented; SPDX 3 semantic support deferred. |
| 4. Semantic Validation | SPDX IDs/namespace/data license/license/checksum/timestamp/DESCRIBES; CycloneDX serial number/bom-ref uniqueness/PURL/CPE/hash/version/timestamp/type. `semantic_spdx.py`, `semantic_cyclonedx.py`. | E052 invalid PURL. | Safe failures can be manually/AI repaired and revalidated. | Implemented for supported versions. |
| 5. Cross-Reference Integrity | Dangling/self dependency refs, SPDX relationships, cycles, orphans. `stages/integrity.py`. | E070 dangling ref; W074 cycle; I075 orphan. | Errors block; cycle/orphan entries remain warning/info. | Implemented. |
| 6. Security Checks | Depth ≤64, array/string/blob caps, forbidden prototype keys; defensive XML/YAML parsing. `stages/security.py`, `parsing/xml_support.py`. | E083 XML DTD, E087 `__proto__`. | Unsafe payload is not exposed to repair workspace. | Implemented. |
| 7. NTIA Minimum Elements | Creator, timestamp, dependency relationship, supplier, name, version, unique ID. `stages/ntia.py`. | W100 supplier missing. | Warnings accept by default; `strict_ntia=true` promotes to blocking errors. | Implemented. |
| 8. Signature Verification | Feature-gated signature presence/contract. `stages/signature.py`. | W113 no signature; E110 present but verifier unavailable. | Off by default. If enabled, an actual signature fails because verification is a stub. | **Partial.** |

The frontend receives validation failures through `HttpError.detail`, shows the first error in `SbomUploadModal`, links to `/sbom-validation-sessions/{id}`, and renders full grouped errors in `ValidationRepairWorkspace.tsx`. `ValidationReportSection.tsx` shows persisted reports for trusted SBOMs.

Documentation calls deduplication “stage 9,” but `default_stages()` has eight stages; dedupe occurs after validation during component sync. The warning code W120 exists, but dedupe warnings are not added to the eight-stage `ErrorReport` by the canonical upload route.

---

## 12. Validation Repair Workspace Workflow

```text
Safe invalid upload
  → SBOMValidationSession + created event
  → edit raw content and/or assign project
  → save draft
  → optional AI suggestion (review-only JSON patches)
  → user selects/applies patches
  → same eight-stage validator reruns
  → import enabled only at zero errors (and UI requires project)
  → trusted SBOMSource + components
  → background enrichment
```

`ValidationRepairService` refuses staging for ingress/security codes, filters AI patches that touch signatures/security/prototype keys, requires user approval, and revalidates after a patch. Sessions have seven-day `expires_at`, but no cleanup worker was found.

**Files:** `routers/sbom_validation_sessions.py`, `services/validation_repair_service.py`, `services/validation_patch_service.py`, `ValidationRepairWorkspace.tsx`.  
**Models:** `SBOMValidationSession`, `SBOMValidationSessionEvent`, imported `SBOMSource`.  
**Endpoints:** GET/PATCH session; POST `validate`, `import`, `ai/suggest-fixes`, `apply-patch`; GET `history`.  
**Tests:** `test_validation_repair_workspace.py`, `ValidationRepairWorkspace.test.tsx`, upload repair test.  
**Status:** **Implemented; cleanup and durable background work missing.**

---

## 13. Parsing Workflow

`app/parsing/extract.py:extract_components` accepts dict, JSON string, or XML string. CycloneDX parsing extracts name, version, type, group, supplier, scope, PURL, CPE, bom-ref, licenses, and hashes. SPDX parsing maps `packages[]` and best-effort SPDX-lite `elements[]`, reading external PURL/CPE references, supplier, licenses, and checksums.

The validation layer supports more encodings than the persistence extractor does cleanly. Canonical upload stores the original text, but component extraction is strongest for JSON and CycloneDX XML; SPDX tag-value/XML persistence extraction is best effort. Dedicated parser-named unit files are limited, but parser behavior is heavily exercised through validation corpus, upload, analysis, conversion, and source tests.

**Status:** CycloneDX JSON/XML and SPDX JSON **Implemented**; non-JSON SPDX component persistence **Partial**.

---

## 14. SPDX-to-CycloneDX Conversion Workflow

**Why:** create a consistent CycloneDX 1.6 artifact for downstream enrichment/export while retaining the source SPDX.

1. `POST /api/sboms/{id}/convert/cyclonedx` requires an existing validated SPDX row and admin/security role.
2. `convert_spdx_to_cyclonedx` maps every SPDX package to a CycloneDX component. It preserves SPDXID and several SPDX-only fields as CycloneDX properties.
3. PURL/CPE external refs, supplier, declared license, hashes, download/homepage refs, description, creators, namespace, annotations, and external document refs are mapped or reported as warnings.
4. `DEPENDS_ON`, reversed `DEPENDENCY_OF`, `CONTAINS`, and document `DESCRIBES` relationships become CycloneDX dependency edges where resolvable. Other relationships are recorded in the conversion report.
5. The CycloneDX output is validated before commit.
6. A **new** `SBOMSource` is created with `source_sbom_id` and `parent_id`; the source gets `converted_sbom_id`. The original SPDX `sbom_data` is never overwritten.
7. Components sync locally; lifecycle/VEX/completeness run in background.
8. Enriched export adds `lifecycle:*` CycloneDX properties from `SBOMComponent` rows.

**Files:** `services/sbom_conversion_service.py`, `routers/sbom_versions.py`, `SbomConversionCard.tsx`, `api.ts`.  
**Models:** `SBOMSource` conversion/source fields; `SBOMComponent`.  
**Endpoints:** conversion POST, conversion-report GET, export GET.  
**Tests:** `test_sbom_spdx_cyclonedx_conversion.py`, `SbomConversionCard.test.tsx`.  
**Status:** **Implemented for SPDX JSON → CycloneDX 1.6 JSON.** File-level SPDX data is intentionally skipped; some relationships are report-only.

---

## 15. Component Deduplication Workflow

Duplicates arise when generators repeat equivalent packages under different bom-refs, merge manifests, or emit overlapping inventories.

Identity priority in `component_deduplication_service.py` is:

1. Parsed PURL: ecosystem + lowercase namespace/name + version.
2. Lowercased full CPE.
3. Fallback: supplier + name + version + type + normalized hashes.

Within a group, the canonical candidate prefers a valid PURL, then CPE, then the row with hashes and greatest metadata completeness, with original order as tiebreaker. Licenses/hashes are unioned; supplier conflicts are reported; missing scope/type/group and raw references/properties are merged. Duplicate bom-refs map to the canonical ref and dependency edges are remapped/deduplicated.

Both canonical and duplicate rows are persisted. Duplicate rows set `is_duplicate=true` and `duplicate_of_component_id`; original `SBOMSource.sbom_data` is not altered. `dedupe_report_json` stores counts, conflicts, and mapping. `GET components` defaults `include_duplicates=false`; `SbomDetail.tsx` defaults `showDuplicates=false` and provides Show/Hide Duplicates.

The report's `duplicates_found` counts all members in duplicate groups, while `duplicates_merged` counts extra rows. This can make UI wording counterintuitive. Normalized export can physically remove duplicate definitions in the exported copy only.

**Files:** service above, `services/sbom_service.py`, `routers/sboms_crud.py`, normalized export in `routers/sbom_versions.py`, `SbomDetail.tsx`.  
**Models:** `SBOMComponent`, `SBOMSource.dedupe_report_json`.  
**Endpoints:** components GET, dedupe-report GET, export `export_mode=normalized`.  
**Tests:** `test_component_deduplication.py`, `SbomDetail.components.test.tsx`.  
**Status:** **Implemented; semantics/UI wording need refinement.**

---

## 16. Lifecycle Workflow

```text
SBOMComponent
  → normalize PURL/CPE/name/version/ecosystem
  → manual override wins
  → valid shared cache wins
  → bounded concurrent provider lookup
  → deterministic authority/status/confidence decision
  → preserve prior high/medium evidence if fresh lookup is Unknown
  → persist status, dates, recommendation, evidence, source, confidence, stale flag
```

Default providers are configured vendor records, optional Xeol, endoflife.date, deps.dev, npm/PyPI/NuGet/Maven registries, repository health, and OSV. Provider calls are best-effort and time-bounded. Vendor authority wins; otherwise the decision priority is EOL, EOS, EOF, Deprecated, Unsupported, EOL Soon, Possibly Unmaintained, Supported, Unknown, then confidence. Unknown results cache for one day; evidence for seven days by default.

Manual overrides require a reason, validate dates, set confidence based on evidence URL, and write both general and lifecycle-specific audit rows. Repository health can set maintenance status “Possibly Unmaintained”; it does not always set the lifecycle status to that value.

**Files:** `services/lifecycle/{normalizer,lifecycle_enrichment_service,decision_engine,types,*_provider}.py`, `routers/lifecycle.py`, lifecycle sections in `SbomDetail.tsx`, `LifecycleHealthTiles.tsx`.  
**Models:** `SBOMComponent`, `ComponentLifecycleCache`, `ComponentLifecycleOverrideAudit`, `AuditLog`.  
**Endpoints:** component GET/PUT/PATCH/refresh; SBOM refresh/report/diagnostics/pack; dashboard lifecycle/health.  
**Tests:** `test_lifecycle_enrichment.py`, `test_lifecycle_xeol_openeox.py`, `test_sbom_lifecycle_remediation.py`, frontend lifecycle tests.  
**Status:** **Implemented with provider-dependent coverage.**

Lifecycle risk and vulnerability risk are shown side by side, but the current risk formula does not mathematically combine them. “EOL + vulnerable = high remediation priority” is a sound product rule and is reflected in separate views, but a unified priority score is **Missing**.

---

## 17. Vulnerability Workflow

```text
Canonical components
  → enrich OSV identity and trusted/generated CPE provenance
  → OSV/GHSA/VulDB provider requests
  → known CVE IDs passed to NVD; remaining trusted CPEs queried
  → normalize CVSS/severity/references/fixes/match provenance
  → cross-source deduplicate
  → AnalysisRun + AnalysisFinding rows
  → risk/dashboard/remediation/export consumers
```

`run_sources_concurrently` runs fast sources concurrently, then NVD sequentially so it can enrich already-known CVEs in bounded `cveIds` batches instead of racing per-CPE calls. Provider failures are collected as query errors; they do not cancel other providers. `compute_report_status` returns FINDINGS, PARTIAL, or OK.

`AnalysisFinding` retains match strategy/reason/range/confidence so the UI can flag conservative matches. Risk score v2 is `CVSS × (1 + 5×EPSS) × (2 if KEV)`, aggregated per component, with band determined by the worst finding.

**Files:** `app/sources/*`, `app/analysis.py`, `services/analysis_service.py`, analysis paths in `sboms_crud.py`, `routers/runs.py`, `services/risk_score.py`, analysis frontend pages/components.  
**Models:** `AnalysisRun`, `AnalysisFinding`, `SBOMComponent`, provider caches.  
**Endpoints:** SBOM analyze and analyze/stream; legacy single/consolidated endpoints; runs/findings/risk/CVE detail.  
**Tests:** snapshots, `test_sources_adapters.py`, `test_cve_*`, NVD tests, `test_risk_score_v2.py`, analysis frontend tests.  
**Status:** **Implemented; architecture contains legacy duplication.**

---

## 18. NVD, OSV, deps.dev, GHSA, VulDB Workflow

### NVD

- `build_nvd_params_for_cve_batch` uses the NVD API parameter **`cveIds`** for up to 100 CVE IDs.
- `build_nvd_params_for_cpe` uses **`cpeName`** and requires a valid CPE 2.3 string.
- Only CPEs marked `sbom_provided`, `official_nvd_cpe`, or `manual_verified` are trusted; generated/test/placeholder CPEs are skipped.
- `NvdClient` uses an optional API key, verified CA bundle, connect/read timeouts, process rate spacing, and classifies 429/502/503/504/timeouts/TLS errors.
- `NvdLookupCache` stores success, no-result, rate-limit, timeout, and failure entries with different TTLs.
- `ScanCircuitBreaker` opens after the configured failure threshold or immediately on TLS failure.
- NVD budgets cap CPE lookups and CVE batches per scan.
- New client behavior is “no blind retries.” It honors `Retry-After` by deferring future calls but does not retry the same request. Legacy `app/analysis.py` still has separate bounded retry/backoff code.
- Failure returns provider status `degraded`; it does not fail the full multi-source analysis or background enrichment.

### OSV/GHSA/VulDB

- OSV queries package/ecosystem identities without credentials.
- GHSA uses a server-resolved GitHub token and GraphQL adapter.
- VulDB is optional and server-keyed.
- Raw source responses can be cached by source + canonical component PURL in `SourceResponseCache`.

### deps.dev

deps.dev is a **lifecycle/deprecation provider**, not one of the vulnerability scan adapters. `DepsDevProvider` can identify deprecation/latest-version signals; vulnerability scanning still comes from NVD/OSV/GHSA/VulDB.

**Status:** NVD/OSV/GHSA **Implemented**; VulDB optional; deps.dev lifecycle **Implemented**. Provider resilience is good but NVD code consolidation/retry policy needs improvement.

---

## 19. VEX Workflow

VEX means Vulnerability Exploitability eXchange. Supported statuses are `affected`, `not_affected`, `fixed`, `under_investigation`, and `unknown`.

- CycloneDX `vulnerabilities[].analysis/affects`, OpenVEX-style `statements[]`, and CSAF documents are parsed.
- Statements match components by bom-ref/PURL/CPE/id/name-version/supplier-name-version logic. Unmatched statements remain visible with low confidence.
- Embedded CycloneDX VEX is imported after trusted SBOM upload.
- Vendor discovery searches VEX-looking external references, caches documents for 24 hours, and records source/evidence/provider errors.
- Manual overrides require a reason; `fixed` requires a fixed version or evidence. History is append-only.
- VEX never deletes an `AnalysisFinding`. `not_affected`/`fixed` change dashboard exploitability interpretation but preserve the vulnerability.

**Files:** `services/lifecycle/vex_provider.py`, `vex_discovery.py`, `routers/vex.py`, VEX section in `SbomDetail.tsx`.  
**Models:** `VexDocument`, `VexStatement`, `VexOverrideAudit`.  
**Endpoints:** upload/list/discover/report/report-pack/override/history/dashboard VEX.  
**Tests:** `test_vex_enrichment.py`, `test_vex_roadmap.py`, lifecycle/VEX dashboard tests.  
**Status:** **Implemented with SSRF hardening gap.** Literal private/local hosts are rejected, but DNS resolution and every redirect hop are not validated while redirects are enabled.

---

## 20. Remediation Workflow

```text
Stored finding
  → POST project-scoped remediation
  → assign owner and optional due date
  → Open / In Progress / Fixed / Accepted Risk / Closed
  → append audit record when values change
  → dashboard status, aging, MTTR, velocity, SLA
```

`Fixed`/`Closed` require `resolution_date`; `Fixed` requires a fixed version or notes; `Accepted Risk` requires notes. All currently defined statuses can transition to all others, so the transition table validates vocabulary rather than enforcing a strict state machine.

SLA metrics are inferred from finding first-seen dates across successful runs, not directly from each remediation due date. Defaults are Critical 7d, High 30d, Medium/Unknown 90d, Low 180d; “due soon” begins at 75% of the budget. Aging counts active findings older than 30 days. Remediation rows are keyed by project/vulnerability/component/version and survive SBOM deletion.

**Files:** `routers/remediation.py`, `services/remediation_service.py`, `metrics/remediation.py`, `metrics/remediation_extra.py`, dashboard `RemediationPanel.tsx`; finding UI calls `upsertRemediation`.  
**Models:** `VulnerabilityRemediation`, `VulnerabilityRemediationAudit`, findings/runs.  
**Endpoints:** remediation project/finding/history/upsert; dashboard remediation and remediation-stats.  
**Tests:** `test_sbom_lifecycle_remediation.py`, `test_dashboard_v4_metrics.py`, `RemediationPanel.test.tsx`.  
**Status:** **Implemented; workflow enforcement and dedicated remediation page are limited.**

---

## 21. Dashboard Workflow

Dashboard aggregates are primarily calculated from the **latest successful run per active/head SBOM**, where successful is OK/FINDINGS/PARTIAL. This avoids counting incomplete/error runs.

| Metric | Source |
|---|---|
| SBOM/project totals | `metrics/sboms.py` |
| Findings/distinct vulnerabilities/severity/fix availability | `metrics/findings.py` and helpers |
| KEV/EPSS/exploitability | `metrics/kev.py`, `epss.py`, `exploitation.py` |
| Lifecycle counts | `metrics/lifecycle.py`, `summarize_components` |
| VEX counts | `vex_dashboard_summary` |
| Remediation status/aging/SLA/MTTR/velocity | `metrics/remediation*.py` |
| Recent SBOMs/activity | `dashboard_main.py` |
| Trend/age/forecast/risk map/matrix | `metrics/trend.py`, `age.py`, `forecast.py`, `riskmap.py` |
| Completeness/outdated health | `metrics/health.py` |

The requested component count/unique/duplicate counts are available on SBOM detail/dedupe APIs but are not all first-class portfolio headline cards. The dashboard “risk posture” is exploitability/severity driven, while `/api/sboms/{id}/risk-summary` supplies per-SBOM composite risk.

**Frontend:** `app/page.tsx`, `components/dashboard/*`, advanced dashboard components.  
**Endpoints:** `/dashboard/stats`, recent-sboms, activity, severity, posture, trend, age, lifetime, lifecycle, VEX, health, remediation, forecast, exploitation, risk-map, risk-matrix.  
**Tests:** dashboard v2/v4/manager/scoping/trend/metrics consistency plus frontend dashboard tests.  
**Status:** **Implemented and well tested.**

---

## 22. Export and Report Workflow

| Export | Source and endpoint | Original preserved? | Status |
|---|---|---|---|
| Original/native SBOM | `GET /api/sboms/{id}/export?export_mode=original` | Yes; reads stored source. | Implemented. |
| Converted CycloneDX | Same endpoint with converted mode/format; related converted row | Yes; source SPDX untouched. | Implemented. |
| Enriched SBOM | Same endpoint with `export_mode=enriched`; lifecycle properties/annotations added to an export copy and revalidated | Yes. | Implemented for JSON. |
| Normalized/deduplicated SBOM | `export_mode=normalized` | Yes; changes export copy only. | Implemented for JSON. |
| Conversion report | export format conversion-report or conversion-report API | Yes. | Implemented. |
| Lifecycle JSON/CSV/OpenEoX | `/lifecycle/report`; current OpenEoX service | Yes. | Implemented. |
| Lifecycle ZIP pack | `/reports/lifecycle-pack` | Yes. | Implemented. |
| VEX JSON/CSV/ZIP | `/vex/report`, `/reports/vex-pack` | Yes. | Implemented. |
| Vulnerability XLSX | `/reports/vulnerabilities.xlsx` from latest stored findings | Yes. | Implemented/tested. |
| Run PDF | `POST /api/pdf-report` from RunCache or rebuilt run/findings | N/A. | Implemented. |
| Run CSV | `/api/analysis-runs/{run_id}/export/csv` | N/A. | Implemented. |
| Run SARIF 2.1.0 | `/api/analysis-runs/{run_id}/export/sarif` | N/A. | Implemented. |
| Compare Markdown/CSV/JSON | `/api/v1/compare/{cache_key}/export` | N/A. | Implemented. |
| Version-compare standalone export | No dedicated endpoint found. | N/A. | **Missing.** |

Export logic is distributed between routers and services, increasing maintenance duplication. The frontend exposes original SBOM, vulnerability Excel, lifecycle/VEX exports, per-run PDF/CSV/SARIF, and compare export. Converted/enriched buttons are concentrated in `SbomConversionCard`/detail flows.

---

## 23. Version Management Workflow

- `POST /api/sboms/{id}/edit` clones the selected row, applies metadata/component edits, increments a string version, validates, stores a new child row, syncs components, carries lifecycle evidence, and backgrounds enrichment.
- `GET /api/sboms/{id}/versions` walks to the lineage root then returns all descendants.
- `GET /api/sboms/compare-versions` compares component, metadata, and dependency changes.
- `POST /api/sboms/{id}/restore/{version_id}` clones the target as a new head-like child; it never rewrites history.
- A separate run comparison v2 compares immutable analysis runs, caches results, adds KEV/EPSS context, and exports them.

**Files:** `routers/sbom_versions.py`, `services/version_control_service.py`, `services/compare_service.py`, compare frontend.  
**Models:** self-linked `SBOMSource`, `SBOMComponent`, `CompareCache`, analysis tables.  
**Tests:** assign/edit, conversion, compare service/router/v1 deprecation, compare frontend tests.  
**Status:** **Implemented, with trust-boundary bug:** edited invalid content is stored as a normal failed/quarantined `SBOMSource`, components still sync, and the router schedules enrichment. It should instead reject or create a repair session.

---

## 24. Metadata Edit and Project Assignment Workflow

`PATCH /api/sboms/{id}` updates display name, product name/version, SBOM version, description, and project assignment, with optional owner matching and audit metadata. It does not rewrite the embedded SBOM document. `POST /edit` is the versioned content/component editing path and does modify a cloned document.

Projects support create/list/get/patch/delete-impact/delete/restore. The upload UI requires selecting a project; the backend project FK is optional. Assignment invalidates SBOM, old/new project, and dashboard caches through `invalidateProjectAssignmentSurfaces`.

**Files:** `routers/projects.py`, `routers/sboms_crud.py`, `schemas.py`, project components/pages, `SbomDetail.tsx`.  
**Models:** `Projects`, `SBOMSource`, related runs/schedules.  
**Tests:** `test_sbom_assign_and_edit.py`, soft-delete tests.  
**Status:** **Implemented.**

---

## 25. Delete Workflow

### Soft delete

`SoftDeleteService` walks ownership relationships and marks eligible rows inactive. `app/db.py` hides tombstones globally. Audit/cache tables are excluded where appropriate. Restore endpoints restore one row only, not descendants.

### SBOM permanent delete

`SBOMDeleteService` first builds the full descendant/version/conversion tree and returns delete impact. It detects unknown FKs through database inspection and refuses deletion when an unmapped dependency exists. The child-first order is:

1. validation events;
2. VEX statements and component override audits;
3. findings and AI batches;
4. SBOM schedules; detach project schedules' last run;
5. compare/run caches;
6. analysis runs;
7. VEX documents and validation sessions/reports;
8. components;
9. external self-references;
10. SBOM rows;
11. retained audit entry.

Parent rows cannot be removed first because many historical FKs use NO ACTION. The former SBOM FK failure is **addressed** by this service and covered by rollback/blocker/no-orphan tests. No current SBOM hard-delete FK failure reproduced; the entire suite passed.

### Project permanent delete

`routers/projects.py:delete_project` uses a separate, shorter inline cascade. It deletes findings/runs, components/reports/SBOMs, then the project. It does not explicitly handle VEX, repair sessions/events, self-linked version/conversion trees, component override audits, compare/run caches, or project-scoped remediation before parent deletion. Some FKs cascade, others do not. There is no equivalent dependency-inspection service or comprehensive test set. This is a current high-risk gap and likely FK-conflict/orphan source on populated projects.

**Endpoints:** project/SBOM delete-impact, DELETE, restore.  
**Frontend:** `DeleteConfirmDialog.tsx`, `SbomsTable.tsx`, `ProjectsTable.tsx`.  
**Tests:** `test_sbom_delete_service.py`, `test_soft_delete.py`, delete dialog test.  
**Status:** SBOM delete **Implemented**; project hard delete **Needs Improvement**.

---

## 26. Scheduling and Background Processing

Schedules can be project-scoped or SBOM-specific. An explicit SBOM schedule, even paused, overrides project inheritance. Cadences are daily, weekly, biweekly, monthly, quarterly, or custom cron; dates are computed in UTC and displayed with a timezone label.

Celery Beat scans due schedules every 15 minutes, enqueues one worker task per SBOM, advances the cursor, avoids scans within `min_gap_minutes`, retries worker failures, and applies exponential 1–24 hour failure backoff. “Run now” preserves regular cadence.

`croniter` is optional in code but absent from `pyproject.toml`/`requirements.txt`; therefore CUSTOM cadence returns a validation error in the standard installation. Preset cadences work.

Upload/edit/conversion enrichment uses in-process FastAPI `BackgroundTasks`, not Celery. It is non-durable and processes lifecycle providers sequentially by component; each component creates a bounded provider thread pool with synchronous `httpx.Client` calls. Large SBOM lifecycle enrichment is a likely bottleneck.

**Files:** `routers/schedules.py`, `services/scheduling.py`, `schedule_resolver.py`, `workers/scheduled_analysis.py`, `workers/celery_app.py`.  
**Models:** `AnalysisSchedule`, `AnalysisRun`, targets.  
**Tests:** scheduling service/resolver/API tests.  
**Status:** presets **Implemented**; custom cron and durable enrichment **Partial**.

---

## 27. API Endpoint Summary

The live FastAPI app exposes the following functional groups (exact route registration verified from `app.main.app.routes`):

| Group | Endpoints |
|---|---|
| Health/config | `GET /`, `/health`, `/api/analysis/config`, `/api/types` |
| Projects | `POST/GET /api/projects`; `GET/PATCH/DELETE /api/projects/{id}`; delete-impact; restore |
| SBOM inventory | `POST/GET /api/sboms`; `POST /api/sboms/upload`; `GET/PATCH/DELETE /api/sboms/{id}`; components; dedupe-report; info; validation-report; risk-summary; revalidate; restore |
| Repair | session GET/PATCH; validate/import/AI-suggest/apply-patch/history |
| Version/conversion/export | edit, versions, compare-versions, restore version, convert, conversion report, native/enriched export, lifecycle reports, vulnerability XLSX |
| Analysis | SBOM analyze/analyze-stream; legacy NVD/GitHub/OSV/VulDB/consolidated; runs, aggregate, recent, search, findings, enriched findings |
| CVE detail | `/api/v1/cves/{cve_id}`, batch, scan-context CVE |
| Lifecycle | component get/update/override/refresh; SBOM refresh/report/diagnostics/pack; dashboard lifecycle/health |
| VEX | upload/list/discover/report/pack/override/history; dashboard VEX |
| Remediation | project/finding/history/upsert; dashboard remediation/remediation-stats |
| Dashboard | stats, recent, activity, severity, posture, trend, age, lifetime, forecast, exploitation, risk-map, risk-matrix |
| Reports | PDF; run CSV/SARIF; compare Markdown/CSV/JSON |
| Scheduling | project/SBOM schedule CRUD; list/pause/resume/run-now |
| NVD mirror admin | settings, sync, sync status, watermark reset |
| AI remediation/config | AI fix generation/batches/SSE; usage/metrics/pricing/providers; encrypted credential/settings CRUD; copilot briefing/ask |

No endpoint was invented for this summary; paths come from the registered FastAPI routes.

---

## 28. Feature Status Ledger

This ledger covers every requested feature. “Evidence” names the primary implementation; detailed workflows appear above.

| # | Feature | Evidence | Status / gap |
|---:|---|---|---|
| 1 | SBOM upload | `sbom_upload.py`, upload modal/API | Implemented. |
| 2 | Format detection | validation `detect.py`, `parsing/format.py` | Implemented; two detection implementations. |
| 3 | CycloneDX parsing | `parsing/cyclonedx.py` | Implemented JSON/XML. |
| 4 | SPDX parsing | `parsing/spdx.py` | JSON implemented; other persistence extraction partial. |
| 5 | SPDX→CycloneDX | conversion service/router/card | Implemented for SPDX JSON. |
| 6 | Eight-stage validation | `validation/pipeline.py` | Implemented; signature stage partial. |
| 7 | Repair workspace | repair service/router/component | Implemented. |
| 8 | Revalidation | SBOM and session revalidate APIs | Implemented. |
| 9 | Component list | components endpoint/detail table | Implemented with server paging/search/sort. |
| 10 | Component dedupe | dedupe service/sync | Implemented. |
| 11 | Show/hide duplicates | query flag and detail toggle | Implemented; hidden by default. |
| 12 | Completeness | `completeness_service.py` | Implemented; separate from NTIA. |
| 13 | NTIA elements | validation stage 7 | Implemented soft/strict. |
| 14 | Metadata edit | SBOM PATCH/detail modal | Implemented. |
| 15 | Project assignment | SBOM PATCH/detail/repair | Implemented. |
| 16 | Project management | projects router/page/components | Implemented. |
| 17 | SBOM versions | version service/router/UI | Implemented. |
| 18 | Version compare | `compare_versions`/detail UI | Implemented; no dedicated export. |
| 19 | Version restore | restore-version API | Implemented as clone. |
| 20 | Vulnerability detection | sources/analysis/persistence | Implemented. |
| 21 | NVD integration | source, client, cache, mirror | Implemented with duplicated legacy/new paths. |
| 22 | OSV integration | OSV adapter | Implemented. |
| 23 | deps.dev | lifecycle provider | Implemented for lifecycle, not scan findings. |
| 24 | Lifecycle enrichment | lifecycle service/providers | Implemented. |
| 25 | EOL/EOS/EOF | lifecycle fields/decision/report | Implemented when evidence exists. |
| 26 | Deprecated detection | registry/deps.dev/provider rules | Implemented. |
| 27 | Unsupported detection | lifecycle/repository provider | Implemented. |
| 28 | Possibly unmaintained | repository health/summary | Partial: often maintenance status rather than canonical lifecycle status. |
| 29 | Manual lifecycle override | lifecycle override API/audit | Implemented. |
| 30 | Lifecycle evidence/confidence | component/cache fields/evidence UI | Implemented. |
| 31 | VEX import | VEX POST/provider | Implemented JSON body. |
| 32 | VEX statements | VEX models/list/report | Implemented. |
| 33 | VEX statuses | allowed status set/maps | Implemented. |
| 34 | Remediation | remediation service/API | Implemented. |
| 35 | Owner/due date/SLA | remediation fields/metrics | Implemented; SLA inferred from findings. |
| 36 | Risk summary | risk score v2 endpoint | Implemented CVSS+EPSS+KEV; lifecycle/VEX absent. |
| 37 | Dashboard | dashboard routers/components | Implemented. |
| 38 | Recent SBOMs | dashboard endpoint/components | Implemented. |
| 39 | Metrics | `app/metrics` | Implemented with consistency tests. |
| 40 | Reports | multiple report paths | Implemented. |
| 41 | Original SPDX export | SBOM export original | Implemented. |
| 42 | Converted CycloneDX export | conversion/export modes | Implemented. |
| 43 | Enriched CycloneDX | lifecycle augmentation | Implemented for JSON. |
| 44 | Lifecycle report | JSON/CSV/OpenEoX/ZIP | Implemented. |
| 45 | Vulnerability report | XLSX, run CSV/PDF/SARIF | Implemented. |
| 46 | PDF | `/api/pdf-report` | Implemented. |
| 47 | SARIF/CSV | analysis export router | Implemented. |
| 48 | Analysis runs | run/finding models/APIs/UI | Implemented. |
| 49 | Scheduled scans | schedules + Celery | Implemented presets; custom cron partial. |
| 50 | Health check | `/health` + NVD mirror state | Implemented. |
| 51 | Authentication | none/bearer/JWT + narrow roles | Partial: default open and frontend does not send auth. |
| 52 | Error handling | HTTP envelopes/global handler/UI | Implemented, with some inconsistent envelopes. |
| 53 | Logging | logger/access/provider logs | Implemented. |
| 54 | DB migrations | 31 Alembic revisions | Implemented; startup ad-hoc DDL remains. |
| 55 | Soft delete | mixin/filter/service | Implemented. |
| 56 | Permanent delete | SBOM/project routes | SBOM implemented; project path partial/risky. |
| 57 | Delete impact | project/SBOM impact APIs | Implemented; SBOM much more complete. |
| 58 | Background enrichment | FastAPI BackgroundTasks | Implemented but non-durable. |
| 59 | Provider retry/timeout | lifecycle/NVD/CVE clients | Partial: timeouts/caches/circuit breakers; new NVD no retry. |
| 60 | Query invalidation | `queryInvalidation.ts` | Implemented and tested. |
| 61 | Loading/error states | route boundaries, alerts, skeletons | Implemented. |
| 62 | Test coverage | 1,832 passing tests total | Strong; external-provider/Redis smokes skipped. |

---

## 29. Frontend Page and Component Summary

| Page | Primary UI |
|---|---|
| `/` | Exploitability-led dashboard: counters, lifecycle health, posture, KEV/EPSS/fix signals, severity/age, trends, top SBOMs, remediation, forecast, risk maps. |
| `/sboms` | Upload modal, inventory filters, validation/analysis status, pin/view/delete impact dialog. |
| `/sboms/[id]` | Overview, components/dedupe toggle, lifecycle evidence/override, VEX import/discovery/override, metadata/project edit, versions/compare/restore, runs, schedules, exports. |
| `/sbom-validation-sessions/[id]` | Repair editor, grouped errors, AI suggestions, patch review, history, revalidate/import. |
| `/projects` | Project CRUD/table/delete modal and schedule entry points. |
| `/analysis` | Run inventory/filtering/export. |
| `/analysis/[id]` | Run posture/findings/CVE detail/remediation/AI fixes and PDF/CSV/SARIF export. |
| `/analysis/compare` | Run picker, posture/component/finding diffs, Markdown/CSV/JSON export. |
| `/schedules` | Schedule cards/editor, pause/resume/run now. |
| `/settings`, `/settings/ai`, `/admin/ai-usage` | Feature/configuration and AI provider/usage management. |
| `/docs/sbom-validation-errors` | In-app error-code reference. |

Loading/error states exist at route level and within data tables. Some large components use manual async state rather than `useMutation`, so invalidation discipline is good but not uniformly enforced by hooks.

---

## 30. Tests and Quality Status

### Commands run on 22 June 2026

| Command | Result |
|---|---|
| `ruff check .` | **Passed**. |
| `pytest -q` | **1,371 passed, 5 skipped**, 5 warnings, 337.32s. |
| `alembic heads` | `031_nvd_lookup_cache (head)`; one head. |
| `alembic current` | Current DB at `031_nvd_lookup_cache`. |
| `alembic upgrade head` | **Passed**, no pending migration output. |
| `cd frontend && npx tsc --noEmit` | **Passed**. |
| `cd frontend && npm test` | **66 files, 461 tests passed**. jsdom emitted non-failing pseudo-element/navigation warnings. |
| `cd frontend && npm run build` | **Passed**; 12 routes generated. |
| `npm audit --omit=dev --json` | **Failed audit policy:** 2 moderate findings (`next` via nested `postcss`; PostCSS XSS advisory). |

Backend skips were one Redis integration test and four real AI-provider smoke tests because Redis/API keys were not configured. Warnings were one Pydantic class-config deprecation and intentionally short JWT test keys.

Coverage percentage was not requested/configured and was not measured. Test breadth is strong across validation stages, security, property/corpus/performance, NVD resilience, lifecycle, VEX, remediation, deletion, scheduling, dashboards, compare, migration drift, auth, exports, AI, and frontend accessibility/integration. Remaining weak spots are project hard delete, browser-to-enabled-auth integration, hostname-resolving VEX SSRF protection, durable upload enrichment, and true external-provider end-to-end tests.

No generated `.pyc`, `.next`, `node_modules`, `.DS_Store`, coverage, or database artifacts were found tracked by Git. The worktree already contained unrelated lifecycle changes; this audit did not overwrite them.

---

## 31. Current Bugs and Limitations

| Priority | Issue | Impact / root cause | Fix recommendation |
|---|---|---|---|
| P0 | Backend auth and frontend are not integrated | `API_AUTH_MODE` defaults to none; CORS defaults `*`; frontend fetches do not send Authorization. Enabling auth can break the UI; leaving it off exposes data/actions. | Choose production auth contract, add token/session handling to fetch and SSE, enforce secure defaults outside dev, restrict CORS, add browser integration tests. |
| P1 | Project hard delete is incomplete | Inline route cascade omits VEX, repair, lineage/conversion, caches/audits and relies inconsistently on FKs. | Replace with project delete service that composes `SBOMDeleteService`, inspects unknown FKs, previews full impact, and tests rollback/no-orphans. |
| P1 | Invalid edited versions enter normal SBOM table | `edit_sbom` stores failed/quarantined rows, syncs components, and router backgrounds enrichment. | Reject edit or create a repair session; only create trusted new version after validation passes. |
| P1 | Signature verification is not implemented | Flag-on signed documents produce E110; no cryptographic trust store/verifier. | Implement JSF/PGP/X.509 verification and key management before enabling flag. |
| P1 | VEX discovery SSRF remains bypassable | URL check accepts unresolved hostnames and follows redirects without hop validation. | Resolve A/AAAA, reject private/reserved results, pin/connect safely, validate each redirect, limit body/content type, add DNS-rebinding tests. |
| P1 | Moderate production dependency advisories | Installed Next/PostCSS chain has two moderate audit findings. | Verify upstream fixed Next release/lockfile, upgrade safely, rerun tests/build/audit; avoid npm's implausible downgrade suggestion without review. |
| P2 | Upload enrichment is non-durable | FastAPI BackgroundTasks vanish on process restart and share API capacity. | Move lifecycle/VEX/NVD/completeness enrichment to Celery with idempotency/status/retry. |
| P2 | Large validation is always synchronous | `SBOM_SYNC_VALIDATION_BYTES` comment promises Celery above 5 MB, but upload route always calls `run_validation` inline. | Implement queued validation/job API or remove misleading setting/comment. |
| P2 | New NVD client has no bounded retry | 429/503/timeouts are cached/degraded and future calls deferred; legacy path has separate retries. | Consolidate NVD code and add a small jittered retry policy respecting `Retry-After`, total time budget, and circuit breaker. |
| P2 | Lifecycle enrichment scales poorly | Components are processed sequentially; each creates a thread pool and synchronous clients. | Batch/cache first, reuse async clients, bound SBOM-wide concurrency, move to worker queue, expose progress. |
| P2 | Risk does not combine lifecycle/VEX/remediation | `risk_score.py` uses CVSS+EPSS+KEV only. | Add a separately versioned “operational priority” score; do not silently change existing risk semantics. |
| P2 | No general repository layer | Routers/services directly query SQLAlchemy; `main.py` docstring claims repositories that do not exist. | Introduce ports/repositories per domain incrementally; keep modular monolith. |
| P2 | God modules and duplicated logic | Large router/frontend/analysis files and old/new provider/compare/upload paths. | Split by vertical feature/use case; retire legacy APIs after telemetry; move export logic to services. |
| P2 | CUSTOM schedules unavailable in normal install | `croniter` optional import but absent from dependencies. | Add/pin croniter or remove CUSTOM from public contract. |
| P2 | VEX upload is JSON body only | No multipart/file parser despite “upload” wording. | Add bounded JSON file upload if operationally needed. |
| P2 | Repair-session expiry is not enforced/cleaned | `expires_at` is stored but no cleanup job/read rejection was found. | Enforce expiry and add scheduled purge/retention audit. |
| P2 | Documentation drift | README says upload auto-analysis; ADR says no Celery/Docker/repository state that no longer matches code; validation docs call dedupe stage 9. | Make code-generated architecture/API docs authoritative; update README/ADR and date superseded records. |
| P3 | UI upload limit message is wrong | Modal says 20 MB; backend/validator allow 50 MB. | Return/display limit from config or change message to 50 MB. |
| P3 | Pydantic deprecation | `schemas.py:ORMModel` uses class-based config. | Migrate to `ConfigDict(from_attributes=True)`. |
| P3 | Startup schema mutation duplicates Alembic | `main.py` calls `create_all` and many SQLite `_ensure_*` DDL helpers. | Keep legacy bootstrap only behind an explicit dev/upgrade flag; production should use Alembic. |

No live application logs were present/inspected. NVD 503/timeout behavior is confirmed from client code and tests, not claimed as a currently occurring outage.

---

## 32. Recommended Next Improvements

1. **Production security gate:** integrate frontend auth, lock CORS, verify JWT/bearer/RBAC end to end, and make insecure mode explicitly development-only.
2. **Deletion correctness:** replace project inline hard delete with a dependency-inspecting transactional service and comprehensive tests.
3. **Restore the trust boundary:** route invalid edits to repair; never enrich/scan an invalid version as trusted.
4. **Close VEX SSRF and dependency advisories.**
5. **Make enrichment durable:** Celery job with retries, idempotency, status/progress, SBOM-wide concurrency limits.
6. **Consolidate NVD/provider implementation:** one client, one cache/retry/circuit policy, shared async HTTP pool.
7. **Implement or explicitly defer signatures;** do not enable the flag in production while it is a stub.
8. **Add operational priority:** versioned risk view combining vulnerability severity/exploitability with lifecycle, VEX, and remediation context.
9. **Refactor within the modular monolith:** feature-oriented services/repositories; split the largest backend/frontend modules; move export construction out of routers.
10. **Resolve contract/document drift:** upload limit, async-validation claim, custom cron dependency, current Celery/Docker architecture, and dedupe stage numbering.

---

## 33. Manager-Friendly Summary

This is not a prototype. It has a broad working feature set, strong automated tests, database migrations, lifecycle and VEX evidence, remediation operations, scheduling, and multiple report formats. It is suitable for a controlled internal pilot where operators understand provider data quality and where deployment access is restricted.

It should not yet be declared generally production-ready because the UI/auth contract is unfinished, project hard deletion is unsafe on complex data, edited invalid SBOMs can bypass the canonical trust boundary, signature verification is a stub, and background enrichment is not durable.

**Decision: CONDITIONAL GO** for internal/pilot use after access is externally restricted. Production-wide rollout should wait for priorities 1–4 above.

---

## 34. Developer-Friendly Summary

The strongest seams are `app/validation`, `app/sources`, `app/metrics`, and `app/nvd_mirror`. Preserve those patterns. Move toward feature use cases and repositories without splitting deployment units. The immediate correctness fixes are project deletion and version-edit validation. The immediate security fixes are browser auth/CORS and VEX URL fetching. The immediate reliability fix is moving post-upload work from FastAPI BackgroundTasks to Celery.

The test suite is a valuable safety net: all requested checks passed except the dependency audit. Refactor incrementally behind existing endpoint and schema tests, then add missing tests before changing behavior.

---

## 35. Final Implementation Classification

### Fully implemented

- Canonical upload and eight-stage validation except signature cryptography.
- Safe validation repair, revalidation, audited patches, and trusted import.
- CycloneDX/SPDX JSON extraction, component persistence, dedupe, duplicate toggle.
- SPDX JSON to preserved-source CycloneDX conversion and enriched export.
- Multi-provider vulnerability analysis, findings/runs, NVD cache/budget/circuit behavior.
- Provider-based lifecycle evidence, manual override, VEX import/report/override.
- Remediation records/audit and dashboard SLA/aging metrics.
- Dashboards, version/run compare, reports, soft delete, SBOM hard delete, preset schedules.
- Error handling, logging, migrations, frontend loading/error/cache invalidation, broad tests.

### Partially implemented

- Clean Architecture/repository boundary.
- Signature verification.
- Browser authentication/RBAC deployment path.
- Project permanent delete.
- Possibly-unmaintained canonical status.
- Unified lifecycle/VEX/remediation risk priority.
- Durable upload/edit/conversion enrichment.
- Custom cron, large-file async validation, non-JSON SPDX persistence extraction.
- NVD retry policy and consolidation.

### Missing / not found

- Dedicated version-compare export.
- Cryptographic signature trust store/verifier.
- Repair-session expiry cleanup.
- Full DNS/redirect-safe SSRF defense for VEX discovery.
- Evidence that frontend works with backend bearer/JWT mode.
- A general repository package for the main application.

### Bugs existing now

- Invalid edited versions can be stored/enriched as normal SBOM records.
- Project hard delete can miss dependencies/FKs.
- Frontend auth headers are absent and upload-limit copy is stale.
- CUSTOM cron is advertised but its dependency is not installed.
- Moderate Next/PostCSS production dependency advisories.
- Documentation contains stale architecture/runtime claims.

### One-line project summary

**SBOM Analyser is a well-tested modular-monolith platform that validates, repairs, inventories, enriches, scans, versions, governs, and reports on SPDX/CycloneDX SBOMs, with production rollout conditional on auth, deletion, trust-boundary, SSRF, and background-job hardening.**

