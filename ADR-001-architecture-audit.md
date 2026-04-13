# SBOM Analyser — Architecture Audit & Decision Record
**Prepared by:** Senior Software Architect (Claude — Cowork Mode)  
**Date:** 2026-04-13  
**Repo:** feroz-hub/sbom  
**Status:** Decision Accepted

---

## Reconnaissance Report

### Entry Points

| Entry Point | File | Mechanism |
|---|---|---|
| Primary HTTP server | `run.py` → `app/main.py` | Uvicorn launcher → FastAPI ASGI app |
| ASGI app | `app/main.py` | FastAPI construction, middleware, router wiring |
| No CLI | — | No Click/Typer/argparse entry points found |
| No task runner | — | No Celery, RQ, Dramatiq, or APScheduler registration found |

### Domain Model

The SBOM Analyser is a vulnerability intelligence platform for Software Bill of Materials files. Its core responsibility is to accept a structured SBOM (CycloneDX or SPDX JSON/XML), extract the component inventory from it, query three independent vulnerability databases (NIST NVD, OpenSSF OSV, GitHub Security Advisories), deduplicate findings across sources, score them by CVSS severity, persist the results, and make them queryable via a REST API consumed by a Next.js dashboard.

The domain breaks naturally into four bounded sub-areas: **SBOM Ingestion** (parsing, component extraction, CPE/PURL enrichment), **Vulnerability Analysis** (concurrent fan-out, cross-source deduplication, severity bucketing), **Project & Run Management** (CRUD scaffolding around SBOMs, projects, analysis runs), and **Reporting** (PDF generation via ReportLab, dashboard aggregate queries).

External credentials (NVD API key, GitHub token) are held at the infrastructure boundary and injected into source adapters at construction time — not held in domain objects.

### Current Architecture Style

**Informal Layered Monolith in active transition toward Routers → Services → Repositories.**

`app/main.py` is intentionally slim and explicitly documents its own design principles (SRP, SoC, DIP). A `services/` layer (`sbom_service.py`, `analysis_service.py`, `pdf_service.py`, `dashboard_service.py`) and a `repositories/` layer (`sbom_repo.py`, `analysis_repo.py`, `project_repo.py`, `component_repo.py`) have been introduced. However, the `sources/` adapters implement a clean `VulnSource` protocol that is already Hexagonal in character. The architecture is in mid-flight: the original flat routers (`sbom.py`, `analysis.py`, `dashboard.py`) co-exist with the new-style routers (`sboms_crud.py`, `analyze_endpoints.py`, `dashboard_main.py`), and `app/analysis.py` (~800+ lines) blurs the domain/service boundary by mixing SBOM parsing, CPE enrichment, and NVD query logic in one file.

### Data Flow Summary

```
HTTP POST /api/sboms
  → [Auth middleware] require_auth()
  → [Rate limiter] slowapi check
  → [Idempotency] check/replay cache
  → sboms_crud router (thin controller)
  → sbom_service.py (parse SBOM JSON/XML)
      → extract_components() [analysis.py — CycloneDX/SPDX parser]
      → _augment_components_with_cpe() [PURL→CPE conversion]
      → _upsert_components() [sbom_repo — DB write]
  → analyze_sbom_multi_source_async()
      → run_sources_concurrently() [asyncio.gather]
          → NvdSource.query()   [httpx async → NVD REST API]
          → OsvSource.query()   [httpx async → OSV batch API]
          → GhsaSource.query()  [httpx async → GitHub GraphQL]
      → deduplicate_findings() [CVE↔GHSA cross-dedup]
      → persist_analysis_run() [analysis_repo — DB write]
  → Return AnalysisRunOut JSON

HTTP GET /api/runs/{id}/findings
  → require_auth()
  → runs router
  → analysis_repo.get_findings()
  → Return paginated AnalysisFindingOut JSON

HTTP POST /api/pdf-report
  → require_auth()
  → pdf router → pdf_service.py → ReportLab PDF builder
  → Return PDF byte stream
```

### External Systems

| System | Protocol | Auth | Purpose |
|---|---|---|---|
| NIST NVD | REST (HTTPS) | Optional API key (header) | CVE lookup by CPE/keyword |
| OpenSSF OSV | REST (HTTPS) | None | Vulnerability lookup by PURL/ecosystem |
| GitHub GHSA | GraphQL (HTTPS) | Optional Bearer token | Security advisory lookup |
| SQLite | File I/O (SQLAlchemy) | None | Persistence — all domain entities |

### Async Processing

**Present — asyncio only; no background job queue.**

`run_sources_concurrently()` in `app/sources/runner.py` uses `asyncio.gather()` to fan out NVD, OSV, and GHSA queries concurrently within a single request/response cycle. The SSE streaming endpoint (`POST /api/sboms/{id}/analyze/stream`) surfaces per-source progress via an `asyncio.Queue` drained by a generator. There is **no Celery/RQ/APScheduler worker** — all analysis runs synchronously within the request thread on the Uvicorn event loop. Long-running NVD queries (large SBOMs) block the request connection for the full duration.

### Auth Status

**Present but disabled by default.**

`app/auth.py` implements a bearer-token allowlist with `hmac.compare_digest` timing-attack resistance. Applied via `Depends(require_auth)` at router-include time in `main.py`. The default env value `API_AUTH_MODE=none` makes every `/api/*`, `/analyze-*`, and `/dashboard/*` endpoint unauthenticated. When `API_AUTH_MODE=bearer` is set with an empty `API_AUTH_TOKENS`, the startup hook raises `AuthConfigError` — this is a correct fail-safe.

A known defect exists: `pydantic-settings` is not installed, so `app/settings.py` `BaseSettings` silently degrades to plain `BaseModel` and reads no environment variables. Auth reads `os.environ` directly as a workaround — this has been documented inline in `auth.py`.

### P0 Issues — Current Status

| P0 Issue | Status | Evidence |
|---|---|---|
| No authentication layer | **PARTIALLY MITIGATED** | `auth.py` exists with correct implementation; disabled by default (`API_AUTH_MODE=none`). Must be activated in any shared environment via env var. |
| API keys passed in request body | **STILL PRESENT** | `AnalysisByRefNVD.nvd_api_key`, `AnalysisByRefGitHub.github_token`, `AnalysisByRefConsolidated.nvd_api_key` + `.github_token` remain as optional Pydantic request body fields in `routers/analyze_endpoints.py`. Credentials accepted per-request, not managed via server-side rotation. |
| Bytecode (.pyc) committed to git | **GITIGNORE PRESENT — TRACKING STATUS UNVERIFIED** | `.gitignore` correctly excludes `__pycache__/` and `*.py[cod]`. Two `.pyc` files exist at `app/__pycache__/` on the filesystem. Files committed *before* a `.gitignore` rule is added remain tracked by git until `git rm --cached` is run. Requires `git ls-files --cached 'app/__pycache__/'` to confirm full remediation. |

### Deployment Config Found

| File | Purpose |
|---|---|
| `run.py` | Uvicorn launcher — reads `HOST`, `PORT`, `RELOAD` from env |
| `requirements.txt` | Python dependencies (no `pydantic-settings` listed) |
| `frontend/package.json` | Node dependencies + `dev`/`build`/`start` npm scripts |
| `.env.example` | Backend env template (credentials empty, `API_AUTH_MODE` absent) |
| `frontend/.env.local.example` | Frontend env template (`NEXT_PUBLIC_API_URL`) |
| **No Dockerfile** | — |
| **No docker-compose.yml** | — |
| **No Railway / Render / Vercel config** | — |

---

## Pattern Scorecard

> Scoring axes: **FIT** = domain fit (1–5) · **EFFORT** = implementation effort, 5 = minimal (1–5) · **VALUE** = solves a real current problem (1–5) · **TOTAL** = sum (max 15)  
> ✅ = Top 3 recommended · ❌ = Score ≤ 6, explicitly rejected

| # | Pattern | FIT | EFFORT | VALUE | TOTAL | Notes |
|---|---|:---:|:---:|:---:|:---:|---|
| 02 | ✅ Modular Monolith | 5 | 4 | 5 | **14** | Single deployable unit, natural module seams (ingestion/analysis/reporting/projects) already emerging in the codebase. Zero additional ops overhead. Perfect for Railway free-tier + solo team. |
| 08 | ✅ Hexagonal (Ports & Adapters) | 5 | 3 | 5 | **13** | `VulnSource` protocol in `sources/base.py` IS already a port. Formalising across DB/PDF/settings removes all infrastructure imports from domain. Enables test-in-isolation without live NVD/SQLite. |
| 14 | ✅ Pipeline Architecture | 5 | 4 | 4 | **13** | The analysis workflow is inherently a stage pipeline: parse → enrich → fan-out → deduplicate → score → persist → report. Each stage is already a discrete function in `analysis.py`. Formalising stages makes them individually testable and replaceable (e.g. swap CPE enricher). |
| 10 | Vertical Slice Architecture | 4 | 4 | 4 | **12** | Fits the bounded sub-domains (SBOM ingestion, analysis run, PDF report, project CRUD). Reduces lateral coupling. Complements Hexagonal. Mid-effort restructure, not a rewrite. |
| 01 | Monolithic Architecture | 3 | 5 | 3 | **11** | The app already IS a monolith and that's fine. Naming it explicitly doesn't add value; graduating to Modular Monolith adds the missing internal seams with the same deployment shape. |
| 09 | Clean / Onion Architecture | 4 | 3 | 4 | **11** | Semantically equivalent to Hexagonal for this codebase. Hexagonal is preferred because it names the adapters explicitly, which is the actual design smell to address here. |
| 11 | CQRS | 3 | 3 | 3 | **9** | Real read/write asymmetry exists: dashboard aggregates are complex reads; analysis writes are append-only. A lightweight CQRS read-model for the dashboard is worth considering after core architecture is settled, but full CQRS now adds complexity disproportionate to scale. |
| 17 | Strangler Fig Pattern | 3 | 3 | 3 | **9** | The legacy `/analyze-sbom-*` endpoints are already being strangled by the new `/api/sboms/{id}/analyze` path. Useful as a named migration strategy, not an ongoing architecture style. |
| 05 | Event-Driven Architecture | 3 | 2 | 3 | **8** | Partial fit: analysis jobs are natural events. Full EDA (broker + consumers) would enable true background processing but introduces infrastructure (Redis/RabbitMQ) that violates the low-ops constraint. The SSE streaming endpoint is event-inspired already. |
| 19 | Outbox Pattern | 2 | 2 | 3 | **7** | Would guarantee analysis job durability if the server crashes mid-analysis. Real value only if uptime SLA matters; not warranted for a solo analyst tool on free-tier hosting. |
| 04 | ❌ Serverless / FaaS | 2 | 2 | 2 | **6** | SBOM analysis has stateful DB operations, long-running external API calls (NVD can take 30–60s for large SBOMs), and SSE streaming — all fundamentally incompatible with FaaS execution models and timeout limits. |
| 15 | ❌ Sidecar Pattern | 2 | 2 | 2 | **6** | Kubernetes-specific pattern for deploying auxiliary containers alongside a main workload. Not applicable to a single-container Railway deployment. |
| 16 | ❌ BFF — Backend for Frontend | 2 | 2 | 2 | **6** | BFF addresses the problem of multiple heterogeneous frontend clients requiring different API shapes. With one Next.js frontend, adding a BFF layer is premature optimisation. |
| 18 | ❌ Saga Pattern | 2 | 2 | 2 | **6** | Sagas manage distributed transactions across multiple services. This system has one service and one database. Not applicable. |
| 03 | ❌ Microservices | 1 | 1 | 1 | **3** | Massively over-engineered for a solo-operated tool. NVD, OSV, and GHSA are already external; splitting the application into internal services would add network hops, service discovery, and distributed tracing overhead with zero functional gain. |
| 06 | ❌ SOA / ESB | 1 | 1 | 1 | **3** | Enterprise Integration Bus pattern designed for large-org XML middleware ecosystems. Categorically wrong for a Python microapp. |
| 07 | ❌ Cell-Based Architecture | 1 | 1 | 1 | **3** | Designed for massive, multi-tenant, blast-radius-contained scale. Not applicable to a single-tenant analyst tool with SQLite storage. |
| 12 | ❌ Event Sourcing | 1 | 1 | 1 | **3** | Analysis runs are append-only already, but full event sourcing (event store, projection rebuilds, temporal queries) is gross overkill for a vulnerability dashboard. The audit trail needed here is a simple `created_at` column, not an event log. |
| 13 | ❌ Space-Based Architecture | 1 | 1 | 1 | **3** | Designed for ultra-high-concurrency, horizontally scaled, in-memory data grid deployments. Not applicable at this scale or team size. |

---

## Architecture Recommendation

### 2.1 Primary Pattern: Modular Monolith + Hexagonal (Ports & Adapters)

**Recommended:** A **Modular Monolith** structured internally around **Hexagonal (Ports & Adapters)** principles.

The SBOM Analyser is a single-team, single-deployable tool with a well-defined domain, a small set of external dependencies, and a hard constraint on operational simplicity (Railway free-tier, solo ops). A Modular Monolith preserves the deployment simplicity of a single process (no inter-service latency, no distributed tracing, no service mesh) while enforcing the internal seams that the codebase has already started to define: `routers/`, `services/`, `repositories/`, `sources/`.

Hexagonal (Ports & Adapters) is not an add-on — it is the mechanism by which those seams are *enforced* rather than merely suggested. The `VulnSource` protocol in `app/sources/base.py` is already a port. The `NvdSource`, `OsvSource`, and `GhsaSource` are already adapters. The insight is to apply this thinking universally: the SQLite database is an adapter behind a repository port; the ReportLab PDF renderer is an adapter behind a report-rendering port; the NVD/OSV/GHSA APIs are adapters behind vulnerability-source ports; the FastAPI routes are an adapter behind the delivery port. The domain and application layers sit in the centre with zero imports from infrastructure.

For a solo developer this pattern pays for itself immediately: every piece of domain logic can be unit-tested by injecting in-memory fakes through the ports, without spinning up a real database or hitting live NVD APIs. The existing `conftest.py` and canned-response fixtures confirm this is already the testing intent — formalising the ports just makes it systematic.

### 2.2 Complementary Pattern 1: Pipeline Architecture (Analysis Workflow)

Applied to the analysis execution path only — not the entire application.

The core analysis workflow in `app/analysis.py` is naturally a data pipeline with discrete, composable stages: `parse_sbom → extract_components → enrich_cpe → fan_out_sources → deduplicate → score_severity → persist_run → emit_result`. Each stage consumes the output of the previous, and several stages (CPE enrichment, PURL parsing, severity scoring) are already implemented as pure functions. The problem is that they live in a single 800+ line file that mixes parsing logic, HTTP orchestration, and persistence concerns in ways that make individual stages hard to test or replace.

Formalising the pipeline means defining each stage as a typed, pure-ish function with an explicit input/output contract, and wiring them together in a single orchestrator (`run_analysis_pipeline()`). This does not require a framework — it is an organisational decision. The benefit: swapping the CPE enricher, adding a new deduplication strategy, or inserting a caching stage becomes a single-function change without touching the orchestrator.

### 2.3 Complementary Pattern 2: Strangler Fig (Legacy Endpoint Migration)

Applied to the four legacy `/analyze-sbom-*` ad-hoc endpoints only — not a global architectural concern.

The codebase contains two co-existing endpoint families: the legacy flat endpoints (`/analyze-sbom-nvd`, `/analyze-sbom-github`, `/analyze-sbom-osv`, `/analyze-sbom-consolidated`) and the new resource-oriented endpoints (`/api/sboms/{id}/analyze`, `/api/sboms/{id}/analyze/stream`). The legacy endpoints are explicitly documented as "Phase 3 legacy" in the router comments. The Strangler Fig pattern gives a named, disciplined strategy for this migration: the new endpoints are the growing fig vine; the legacy endpoints are the strangled tree being eliminated over a defined timeline. This means no "big bang" removal — legacy endpoints remain available until consumers are confirmed migrated, then they are pruned.

### 2.4 Layer Map

```
╔═══════════════════════════════════════════════════════════════════╗
║                       DELIVERY LAYER                             ║
║  FastAPI Routes (thin controllers — parse req, call use-case,    ║
║  return response schema. Zero business logic.)                   ║
║                                                                   ║
║  routers/sboms_crud.py  │  routers/analyze_endpoints.py          ║
║  routers/runs.py        │  routers/projects.py                   ║
║  routers/pdf.py         │  routers/dashboard_main.py             ║
║  routers/health.py      │  (legacy: sbom.py, analysis.py)        ║
╠═══════════════════════════════════════════════════════════════════╣
║                   CROSS-CUTTING CONCERNS                         ║
║  auth.py (bearer token)  │  rate_limit.py (slowapi)              ║
║  idempotency.py          │  etag.py  │  logger.py                ║
╠═══════════════════════════════════════════════════════════════════╣
║                     APPLICATION LAYER                            ║
║  Use Cases — one per domain operation                            ║
║                                                                   ║
║  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────┐ ║
║  │  SBOM Ingestion │  │ Analysis Runner │  │ Report Generator │ ║
║  │  (upload+parse) │  │ (pipeline orch.)│  │  (PDF / JSON)    │ ║
║  └─────────────────┘  └─────────────────┘  └──────────────────┘ ║
║  ┌─────────────────┐  ┌─────────────────┐                       ║
║  │  Project CRUD   │  │  Dashboard Agg. │                       ║
║  │                 │  │  (query model)  │                       ║
║  └─────────────────┘  └─────────────────┘                       ║
║                                                                   ║
║  services/sbom_service.py  │  services/analysis_service.py       ║
║  services/pdf_service.py   │  services/dashboard_service.py      ║
╠═══════════════════════════════════════════════════════════════════╣
║                       DOMAIN LAYER                               ║
║  (Pure logic — zero infrastructure imports)                      ║
║                                                                   ║
║  SBOM Parser (CycloneDX / SPDX)  │  Analysis Pipeline Stages     ║
║  CPE / PURL Enrichment            │  CVE Deduplication Rules      ║
║  CVSS Severity Model              │  Component Domain Model       ║
║                                                                   ║
║  analysis.py (to be split)  │  sources/severity.py               ║
║  sources/cpe.py             │  sources/purl.py                   ║
║  sources/dedupe.py                                               ║
╠═══════════════════════════════════════════════════════════════════╣
║                    PORTS (Interfaces / Protocols)                ║
║                                                                   ║
║  VulnSource Protocol       │  SBOMRepository (Port)              ║
║  AnalysisRunRepository     │  ComponentRepository                ║
║  ProjectRepository         │  ReportRenderer (Port)              ║
║  SettingsPort                                                     ║
╠═══════════════════════════════════════════════════════════════════╣
║                  INFRASTRUCTURE ADAPTERS                         ║
║  (Implement ports — may import FastAPI/SQLAlchemy/httpx/os)      ║
║                                                                   ║
║  sources/nvd.py    │  sources/osv.py    │  sources/ghsa.py       ║
║  repositories/sbom_repo.py             │  SQLite (SQLAlchemy)    ║
║  repositories/analysis_repo.py         │  repositories/...       ║
║  pdf_report.py (ReportLab adapter)     │  http_client.py         ║
║  settings.py (os.environ adapter)                                 ║
╚═══════════════════════════════════════════════════════════════════╝
```

### 2.5 Key Boundaries & Rules

```
RULE-01: Dependency Direction
  Domain and Application layers NEVER import from Infrastructure or Delivery.
  All cross-layer calls flow inward. Violation: analysis_service.py currently
  imports SQLAlchemy models directly — this is the primary structural debt.

RULE-02: No Raw DB Calls Above Repository Layer
  Routers and services NEVER call SQLAlchemy Session methods directly.
  All persistence goes through a repository class. This is already the
  intent — sboms_crud.py still has inline Session usage that must migrate.

RULE-03: Domain Layer Has Zero Infrastructure Imports
  app/analysis.py and all files classified as Domain MUST NOT import
  sqlalchemy, httpx, requests, os, fastapi, or reportlab. If a function
  in analysis.py currently does, it belongs in the Service or Infrastructure
  layer, not Domain.

RULE-04: VulnSource Credentials Injected at Construction — Never from os.environ
  NvdSource, OsvSource, GhsaSource MUST receive credentials as constructor
  arguments. They MUST NOT call os.getenv() internally. The caller (service
  layer) is responsible for resolving credentials from settings and injecting
  them. This eliminates the P0 issue of credentials passing through request
  bodies — when credential injection is the service's job, request models
  have no reason to carry API keys.

RULE-05: Auth Enforced at Delivery Boundary Only
  require_auth() is applied once at router-include time in main.py.
  No auth logic appears inside services, domain, or repositories.
  The /health endpoint is the sole explicit exception.

RULE-06: Analysis Pipeline Stages Are Pure Functions
  Each stage of the analysis pipeline (parse, enrich, fan-out, deduplicate,
  score) MUST be a function that takes a typed input and returns a typed
  output with no side effects. Side effects (DB writes, HTTP calls) belong
  in the orchestrating use-case, not inside the stage functions themselves.

RULE-07: All Async I/O via httpx AsyncClient — No New Requests.Session Calls
  app/analysis.py contains a module-level requests.Session (_nvd_session)
  used for blocking HTTP calls. All new code MUST use the shared
  httpx.AsyncClient from http_client.py. The legacy _nvd_session is
  technical debt to be migrated; it must not be copied or extended.
```

---

## ADR-001

```
---
# ADR-001: Core Architecture Pattern — SBOM Analyser
**Date:** 2026-04-13
**Status:** Accepted
**Deciders:** Feroze (FBT)
```

### Context

The SBOM Analyser is a FastAPI-backed vulnerability intelligence platform that accepts Software Bill of Materials files (CycloneDX/SPDX), extracts component inventories, queries three external vulnerability databases (NIST NVD, OpenSSF OSV, GitHub GHSA) concurrently, cross-deduplicates findings, and serves the results through a REST API consumed by a Next.js dashboard. The backend is a single Python 3.13 process using SQLite for persistence, deployed on Railway free-tier with a preference for low operational complexity.

A security and structural audit identified three P0 issues: the auth layer was absent (now partially mitigated by an opt-in bearer token mechanism), API keys were being passed through request bodies, and bytecode artifacts had been committed to the repository. Beyond the security issues, the codebase is in an active architectural transition: a `services/` and `repositories/` layer has been introduced alongside the original flat routers, creating a dual-router situation and an 800+ line `analysis.py` that conflates domain logic, HTTP orchestration, and persistence concerns.

The constraints are explicit: solo operator, Railway free-tier deployment, no Kubernetes, no message broker, low-ops preference, and a codebase that must remain comprehensible and testable by a single developer. This document records the architectural pattern chosen to guide all future development and the reasoning behind that choice.

### Decision

The SBOM Analyser will be structured as a **Modular Monolith with Hexagonal (Ports & Adapters) internal organisation**, complemented by a **Pipeline Architecture** formalised within the analysis workflow and a **Strangler Fig migration strategy** for retiring the four legacy ad-hoc analysis endpoints.

This decision was made because: (a) the Modular Monolith matches the deployment constraint (single Railway process) and the team constraint (solo operator) without sacrificing internal clarity; (b) the `VulnSource` protocol already in `sources/base.py` demonstrates that the codebase's own best instincts are Hexagonal — this decision formalises what is already partially present; and (c) the Pipeline pattern reflects the actual computation shape of the analysis workflow, making each stage independently testable and replaceable without architectural churn.

### Patterns Adopted

| Pattern | Scope | Rationale |
|---|---|---|
| Modular Monolith | Entire application | Single deployable; bounded internal modules enforce seams without inter-service overhead. Matches solo-ops, free-tier Railway constraint. |
| Hexagonal (Ports & Adapters) | All infrastructure boundaries — DB, external APIs, PDF renderer, settings | Formalises the VulnSource protocol pattern already present; enables full domain unit testing without live infrastructure. Eliminates request-body credential leakage by making credential injection the service's responsibility. |
| Pipeline Architecture | `analysis.py` analysis execution path only | parse → enrich → fan-out → deduplicate → score → persist stages each become typed, pure-ish functions. Makes individual stages replaceable and testable. |
| Strangler Fig | Legacy `/analyze-sbom-*` endpoints → new `/api/sboms/{id}/analyze` | Provides a disciplined, timeline-bound migration path. Avoids big-bang removal of endpoints that frontend consumers may still depend on. |

### Patterns Rejected

| Pattern | Reason |
|---|---|
| Microservices | Massively over-engineered for a solo-operated single-tenant tool; would add network hops, service mesh, and distributed tracing overhead with zero functional benefit. |
| Serverless / FaaS | SBOM analysis involves long-running HTTP fan-outs (NVD can take 30–60s for large SBOMs) and SSE streaming, both incompatible with FaaS execution models and timeout limits. |
| Event-Driven Architecture | Full EDA requires a message broker (Redis/RabbitMQ) that violates the low-ops constraint; the asyncio concurrent runner already provides the parallelism benefit without the infrastructure cost. |
| CQRS | Read/write asymmetry exists but is not severe enough at this scale to justify a separate read model; SQLite aggregates are fast enough, and the complexity cost would fall entirely on a solo developer. |
| SOA / ESB | Enterprise integration bus pattern designed for large-organisation XML middleware ecosystems; categorically wrong for a Python web application. |
| Event Sourcing | Analysis runs are naturally append-only, but full event sourcing (event store, projections, temporal queries) is gross overkill for a vulnerability dashboard where a `created_at` column suffices for audit purposes. |
| Cell-Based Architecture | Designed for multi-tenant, blast-radius-isolated scale deployments; not applicable to a single-tenant analyst tool. |
| Space-Based Architecture | Designed for ultra-high-concurrency in-memory data grid systems; not applicable at this scale. |
| Sidecar Pattern | Kubernetes-specific sidecar deployment is not applicable to a single-container Railway deployment. |
| BFF — Backend for Frontend | Adds a dedicated backend layer per frontend client type; with a single Next.js frontend this is premature optimisation. |
| Saga Pattern | Manages distributed transactions across multiple services; with one service and one database, sagas add complexity without a problem to solve. |

### Consequences

#### Positive

- Domain and application logic becomes fully testable without live NVD/OSV/GHSA APIs or a real database — port injection enables in-memory fakes in all tests.
- The credential leakage P0 (API keys in request bodies) is architecturally eliminated: when the service layer owns credential resolution, request models have no reason to carry API keys.
- The auth mechanism already in `auth.py` slots cleanly into the Delivery boundary without touching any inner layer.
- The modular structure makes it possible to swap the SQLite adapter for PostgreSQL without touching domain or application code.
- Individual pipeline stages (CPE enrichment, deduplication, scoring) become independently testable and replaceable.
- A single deployment unit keeps Railway configuration trivial — one process, one `run.py`, no orchestration.

#### Negative / Trade-offs

- `app/analysis.py` must be decomposed into Domain and Service layers — this is non-trivial work on an 800+ line file and carries regression risk without comprehensive tests covering the current behaviour.
- Formalising ports means defining Python Protocols (or ABCs) for each infrastructure boundary — initial overhead for a codebase that previously relied on informal conventions.
- The dual-router situation (legacy + new) will persist until the Strangler Fig migration is complete; the codebase will carry this cognitive overhead through the transition period.
- `pydantic-settings` must be installed and `app/settings.py` must be migrated before the settings port can be formalised; until then, the `os.environ` direct-read workaround in `auth.py` and `analysis_service.py` remains.

#### Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Regression during `analysis.py` decomposition | Medium | Capture current behaviour with snapshot tests before any structural change; the existing `test_sboms_analyze_snapshot.py` and `test_analyze_endpoints_snapshot.py` are the safety net — expand coverage before touching the file. |
| Port abstraction adds ceremony without payoff | Low | Keep protocols minimal — one `query()` method on `VulnSource` is already the pattern. Only introduce a new port when an infrastructure boundary needs to be tested in isolation. |
| Legacy endpoints never get strangled | Medium | Set an explicit deprecation milestone; add a deprecation warning log at INFO level on each legacy route call so usage can be monitored. |
| SQLite remains a scalability ceiling | Low | The modular Hexagonal structure means PostgreSQL migration requires only a new repository adapter implementation, not a domain rewrite. Acceptable risk at current scale. |
| `_nvd_session` (blocking requests.Session) starves the event loop | Medium | Medium-term: replace with `httpx.AsyncClient` calls via `http_client.py`. Short-term: run blocking NVD calls in `asyncio.run_in_executor()` to avoid blocking the Uvicorn worker. |

### Compliance

The following rules MUST be enforced in code review going forward:

- **RULE-01: Dependency Direction** — Domain and Application layers (`analysis.py`, `services/*.py`) MUST NOT import from Infrastructure (`repositories/*.py`, `sources/*.py`, `models.py`, `db.py`) or Delivery (`routers/*.py`). All imports flow inward.
- **RULE-02: No Raw DB Calls Above Repository Layer** — `Session.query()`, `Session.add()`, `Session.execute()` MUST NOT appear in router files or service files. All DB access goes through a `*Repository` class.
- **RULE-03: Domain Has Zero Infrastructure Imports** — Files classified as Domain MUST NOT import `sqlalchemy`, `httpx`, `requests`, `fastapi`, `reportlab`, or `os`. Violations are blocking PR feedback.
- **RULE-04: VulnSource Credentials Injected — Never from os.environ** — `NvdSource`, `OsvSource`, `GhsaSource` constructors accept credential parameters. They MUST NOT call `os.getenv()` internally. Credential resolution is the caller's (service layer's) responsibility.
- **RULE-05: Auth at Delivery Boundary Only** — `require_auth()` is applied at router-include time in `main.py`. No auth logic appears in services, domain, or repositories. `/health` is the sole explicit exclusion.
- **RULE-06: Analysis Pipeline Stages Are Pure Functions** — Each stage (`parse`, `enrich`, `fan_out`, `deduplicate`, `score`) takes a typed input and returns a typed output with no side effects. DB writes and HTTP calls belong in the orchestrating use-case, not inside stage functions.
- **RULE-07: All New Async I/O via httpx.AsyncClient** — New code MUST use the shared `AsyncClient` from `http_client.py`. The module-level `requests.Session` in `analysis.py` (`_nvd_session`) is flagged technical debt; it MUST NOT be copied or extended in new code.

---

*Document status: Accepted — 2026-04-13. Next scheduled review: after legacy endpoint Strangler Fig migration is complete.*
