# Compare Runs — Phase 1 Discovery & Data Model Audit

**Status:** Draft, awaiting reconciliation decisions before Phase 2
**Date:** 2026-04-30
**Scope:** Greenfield design for `/analysis/compare` v2. Audit of existing schema, current v1 surface, and the gap between the v2 prompt and what the codebase can support today.

---

## TL;DR — what changes for the design

The audit surfaced **four material gaps** between the v2 prompt and the codebase. Each forces a design decision before Phase 2 can finalize:

1. **No multi-tenancy.** No `tenant_id` column anywhere. The hard constraint "tenant scope at the SQL layer" is unimplementable today.
2. **Compare v1 already exists.** [app/routers/analysis.py:22](app/routers/analysis.py#L22) and [frontend/src/app/analysis/compare/page.tsx](frontend/src/app/analysis/compare/page.tsx) are both implemented (~540 LOC of frontend, fully wired). The prompt described the page as a placeholder; it isn't. Decide: replace, version-coexist, or extend in place.
3. **No license, content hash, scanner version, sbom hash, branch, or commit SHA stored.** Two of the v2 component change_kinds (`license_changed`, `hash_changed`) and several relationship descriptors (scanner version delta, "same SBOM, different scanner") cannot be computed without schema additions.
4. **Severity is denormalized at scan time onto `analysis_finding`.** Good for `severity_changed` detection across runs. But KEV/EPSS are *not* stored on findings — they are looked up live from `cve_cache`. So `kev_added` requires a join to the cache at diff time, and only works for findings whose CVE is currently cached.

Plus: **Run IDs are `Integer`, not `UUID`.** The v2 Pydantic schemas in the prompt use `UUID`. Trivial to swap, but flagging.

---

## 1. Analysis Run model

**Source:** [app/models.py:120-151](app/models.py#L120-L151)

```python
class AnalysisRun(Base):
    __tablename__ = "analysis_run"

    id = Column(Integer, primary_key=True, index=True)
    sbom_id = Column(Integer, ForeignKey("sbom_source.id"), nullable=False, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True, index=True)

    run_status = Column(String, nullable=False, index=True)
    sbom_name = Column(String, nullable=True)
    source = Column(String, nullable=False, default="NVD")

    started_on = Column(String, nullable=False)         # ISO-8601 string, not TIMESTAMPTZ
    completed_on = Column(String, nullable=False)
    duration_ms = Column(Integer, nullable=False, default=0)

    total_components = Column(Integer, nullable=False, default=0)
    components_with_cpe = Column(Integer, nullable=False, default=0)
    total_findings = Column(Integer, nullable=False, default=0)

    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    unknown_count = Column(Integer, nullable=False, default=0)
    query_error_count = Column(Integer, nullable=False, default=0)

    raw_report = Column(Text, nullable=True)

    sbom = relationship("SBOMSource", back_populates="analysis_runs")
    project = relationship("Projects", back_populates="analysis_runs")
    findings = relationship("AnalysisFinding", back_populates="analysis_run")
```

### Status lifecycle

Status is a free-form `String` column (no `Enum` class). Canonical values, post-ADR-0001:

| Value | Meaning |
|---|---|
| `PENDING` | Queued, not started |
| `RUNNING` | In progress |
| `OK` | Completed, no findings (was `PASS`) |
| `FINDINGS` | Completed, findings present (was `FAIL` — renamed in [005_rename_run_status_fail_to_findings.py](alembic/versions/005_rename_run_status_fail_to_findings.py)) |
| `PARTIAL` | Some sources errored, but partial results were produced |
| `ERROR` | Technical failure |
| `NO_DATA` | No components or scan inputs available |

For compare v2, the **"ready to diff"** set is `{OK, FINDINGS, PARTIAL}`. Anything else returns the *Run-Not-Ready* state.

Frontend currently still accepts `PASS`/`FAIL` as legacy aliases ([frontend/src/types/index.ts:59-68](frontend/src/types/index.ts#L59-L68)). Compare v2 will normalize on read.

### Required-field gap analysis

| Field expected by v2 prompt | Present? | Workaround |
|---|---|---|
| `project_id` | ✓ | — |
| `tenant_id` | ✗ | **No tenancy.** See §5. |
| `created_at` / `started_on` | ✓ (string-typed `started_on`) | Parse on read |
| `completed_at` / `completed_on` | ✓ (string-typed) | Parse on read |
| `sbom_hash` | ✗ | Could derive from `SBOMSource.sbom_data` SHA at read time, or add a column |
| `scanner_version` | ✗ | `source` field carries the upstream provider name (`NVD`, `OSV`, etc.), not a scanner version |
| `branch` / `tag` / `commit_sha` | ✗ | Out-of-scope unless we add columns |

---

## 2. Components

**Source:** [app/models.py:88-117](app/models.py#L88-L117)

```python
class SBOMComponent(Base):
    __tablename__ = "sbom_component"
    id = Column(Integer, primary_key=True, index=True)
    sbom_id = Column(Integer, ForeignKey("sbom_source.id"), nullable=False, index=True)
    bom_ref = Column(String, nullable=True)
    component_type = Column(String, nullable=True)
    component_group = Column(String, nullable=True)
    name = Column(String, nullable=False, index=True)
    version = Column(String, nullable=True, index=True)
    purl = Column(String, nullable=True)
    cpe = Column(String, nullable=True, index=True)
    supplier = Column(String, nullable=True)
    scope = Column(String, nullable=True)
    created_on = Column(String, nullable=True)
    # ...
    __table_args__ = (
        UniqueConstraint("sbom_id", "bom_ref", "name", "version", "cpe",
                         name="uq_sbom_component_fingerprint"),
        Index("ix_sbom_component_sbom_name", "sbom_id", "name"),
    )
```

**Critical attribute:** components are FK'd to `sbom_source`, **not** to `analysis_run`. To get the components for a run, follow `AnalysisRun.sbom_id → SBOMSource → SBOMSource.components`. Two runs of the *same* SBOM share component rows; two runs of different SBOMs don't.

### Field gap analysis

| Expected by v2 prompt | Present? | Notes |
|---|---|---|
| `name` | ✓ | Required, indexed |
| `version` | ✓ | Indexed |
| `purl` | ✓ | Optional, not indexed |
| `ecosystem` | ✗ | **Derive from purl** (`purl_to_ecosystem` already exists in `app/services/cve_service.py`) |
| `license` | ✗ | **Not stored.** Disables `license_changed` change_kind |
| `content_hash` / `hash` | ✗ | **Not stored.** Disables `hash_changed` change_kind (the supply-chain alarm) |

### Identity for diff

The v2 prompt asks for component identity = `(name, ecosystem)` so version bumps can be detected. Recommended adaptation: identity = `(name, ecosystem_from_purl)`, falling back to `(name, "unknown")` when purl is missing. Ecosystem-less components risk false-positive collisions across ecosystems (e.g. `requests` in npm vs PyPI), but in practice CycloneDX/SPDX tooling almost always emits a purl with a `pkg:` scheme.

---

## 3. Findings

**Source:** [app/models.py:153-186](app/models.py#L153-L186)

```python
class AnalysisFinding(Base):
    __tablename__ = "analysis_finding"
    id = Column(Integer, primary_key=True, index=True)
    analysis_run_id = Column(Integer, ForeignKey("analysis_run.id"), nullable=False, index=True)
    component_id = Column(Integer, ForeignKey("sbom_component.id"), nullable=True, index=True)

    vuln_id = Column(String, nullable=False, index=True)
    source = Column(String, nullable=True)
    title = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=True, index=True)
    score = Column(Float, nullable=True)
    vector = Column(String, nullable=True)
    published_on = Column(String, nullable=True)
    reference_url = Column(String, nullable=True)
    cwe = Column(Text, nullable=True)
    cpe = Column(String, nullable=True, index=True)
    component_name = Column(String, nullable=True)
    component_version = Column(String, nullable=True)
    fixed_versions = Column(Text, nullable=True)        # JSON-encoded string
    attack_vector = Column(String, nullable=True)
    cvss_version = Column(String, nullable=True)
    aliases = Column(Text, nullable=True)               # JSON-encoded string

    __table_args__ = (
        UniqueConstraint("analysis_run_id", "vuln_id", "cpe",
                         name="uq_analysis_finding_run_vuln_cpe"),
        Index("ix_analysis_finding_run_severity", "analysis_run_id", "severity"),
    )
```

### Identifiers

- Primary: `vuln_id` (CVE-…, GHSA-…, PYSEC-…, RUSTSEC-…, OSV-…)
- Aliases: JSON list in `aliases` column. Parser at [app/routers/runs.py:193-207](app/routers/runs.py#L193-L207) (`_cve_aliases_for`) extracts every CVE-style id.
- Identifier classification: [app/integrations/cve/identifiers.py:29-50](app/integrations/cve/identifiers.py#L29-L50)

### Severity, KEV, EPSS

| Attribute | Where it lives at diff time |
|---|---|
| `severity` | Denormalized on the finding row at scan time. **Source of truth for `severity_changed`.** |
| `score` (CVSS) | Same — denormalized on finding row |
| KEV-listed | **Not on the finding.** Looked up via `lookup_kev_set_memoized()` against `kev_entry` table |
| EPSS percentile | **Not on the finding.** Looked up via `cve_cache.payload.exploitation.epss_*` |

Implication for the diff engine:

- `kev_added` = both runs contain the same `(vuln_id, component_purl)` finding, AND the CVE was *not* in `kev_entry` at the time of run A but *is* now. Since we don't snapshot KEV state on the finding row, **we approximate this as: CVE is KEV-listed today but the finding existed in run A** — i.e. the alarm is *current* state vs *new-in-B*. This is a defensible simplification but should be called out in tooltip copy: "KEV status reflects current CISA listing."
- Similarly for EPSS: the v2 schema's `epss_a`/`epss_b` cannot be honestly populated from historical data. Recommend collapsing to a single `epss` field (current value) and a `kev` boolean (current value), with a footnote.

### Finding identity for diff

The v2 prompt uses `(vuln_id, component_purl)`. Findings store `component_id` (FK), `component_name`, `component_version`, and `cpe` — **but not `purl`** directly. To get the purl, join through `component_id → sbom_component.purl`, falling back to `(component_name, component_version)` when `component_id` is null (which happens for findings against components that lack a CPE/PURL match).

Practical identity: `(vuln_id, component_name, component_version)` with purl as a tiebreaker when present. Reason: the existing `uq_analysis_finding_run_vuln_cpe` uniqueness key uses CPE, but CPE is often missing for non-OS packages, while `(name, version)` is more universally available.

---

## 4. CVE enrichment cache

**Source:** [app/models.py:315-334](app/models.py#L315-L334), [app/services/cve_service.py](app/services/cve_service.py), [app/schemas_cve.py:98-127](app/schemas_cve.py#L98-L127)

```python
class CveCache(Base):
    __tablename__ = "cve_cache"
    cve_id = Column(String(32), primary_key=True, index=True)
    payload = Column(JSON, nullable=False)               # full CveDetail JSON
    sources_used = Column(String(128), nullable=False)
    fetched_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False, index=True)
    fetch_error = Column(Text, nullable=True)
    schema_version = Column(Integer, nullable=False, default=1)
```

- **Keyed by canonical CVE ID** (CVE-YYYY-NNNN+, also accepts GHSA-/PYSEC-/RUSTSEC-/GO-/OSV-).
- **Payload is the full `CveDetail`** — severity, CVSS, CWE, exploitation (KEV + EPSS + attack vector), fix_versions, references.
- **TTL bucketed** by KEV status / age / fetch outcome ([app/services/cve_service.py:253-263](app/services/cve_service.py#L253-L263)). KEV entries expire in 6h, recent CVEs in 24h, stable in 7d, errors in 15m.
- **Already exposed** via `GET /api/v1/cves/{cve_id}` and `POST /api/v1/cves/batch` ([app/routers/cves.py](app/routers/cves.py)).

For the diff engine: do **batch lookup** of all unique vuln IDs across both runs in one shot, then pull KEV/EPSS/severity from the cache for each diff row. Confirms the v2 constraint "must not refetch" is supported.

---

## 5. Tenant scoping

**No tenancy exists.**

- No `tenant_id` column on any of: `projects`, `sbom_source`, `analysis_run`, `sbom_component`, `analysis_finding`, `cve_cache`, `kev_entry`, `epss_score`.
- No RLS policies.
- Auth is JWT (RS256) via `require_auth` ([app/auth.py](app/auth.py)) but the user identity is not used to filter queries — every authenticated user sees every run.

This directly conflicts with the v2 prompt's hard constraint:

> **Tenant scope at the SQL layer**, not the API layer. Even if the API check is bypassed, the SQL query for run loading filters by `tenant_id = current_user.tenant_id`.

**Decision required.** Three options:

1. **Drop the constraint for v1 of compare v2.** Document the gap, ship single-tenant. The screenshot suggests this is a single-org product today.
2. **Add `tenant_id` columns and a tenant claim in JWT** as part of this feature. Roughly doubles the scope (migration, every existing query touched, JWT changes). Out-of-scope per "Extend, don't break."
3. **Add a per-user authorization check at the API layer only.** Cheaper than full tenancy. Requires a project ↔ user ACL we don't have today.

**Recommendation:** Option 1, with a clearly-marked TODO and an ADR follow-up. Anything else expands this feature into a tenancy refactor.

---

## 6. Existing routers

**Location:** [app/routers/](app/routers/)

| File | Owns | Relevance to compare |
|---|---|---|
| `analysis.py` | `/api/analysis-runs/compare`, SARIF/CSV export | **v1 compare endpoint already lives here** |
| `runs.py` | `/api/runs`, `/api/runs/{id}`, `/api/runs/{id}/findings`, `/api/runs/{id}/findings-enriched` | Picker autocomplete will reuse |
| `cves.py` | `/api/v1/cves/{id}`, `/api/v1/cves/batch` | Diff engine batch enrichment |
| `projects.py` | Project CRUD | Picker filters |
| `sboms_crud.py`, `sbom_upload.py` | SBOM lifecycle | — |
| `dashboard.py`, `dashboard_main.py` | Dashboard widgets | — |
| `health.py`, `pdf.py`, `schedules.py`, `analyze_endpoints.py`, `sbom.py` | Adjacent | — |

### Existing v1 compare endpoint

[app/routers/analysis.py:22-74](app/routers/analysis.py#L22-L74):

```python
@router.get("/compare", status_code=200)
def compare_analysis_runs(
    run_a: int = Query(..., description="First run ID"),
    run_b: int = Query(..., description="Second run ID"),
    db: Session = Depends(get_db),
):
    """Compare two AnalysisRun records and return diff of findings."""
    # returns:
    # {
    #   "run_a": {id, sbom_name, completed_on},
    #   "run_b": {id, sbom_name, completed_on},
    #   "new_findings":      [vuln_id, ...],
    #   "resolved_findings": [vuln_id, ...],
    #   "common_findings":   [vuln_id, ...],
    #   "severity_delta":    {critical, high, medium, low},
    # }
```

- GET, integer query params, no auth dependency wired in (open).
- Identity for diff is **plain `vuln_id` set diff** — no per-component scoping. `(CVE-X against pkgA)` resolved-in-B and `(CVE-X against pkgB)` newly-vulnerable-in-B would both collapse to "common." Major correctness issue for v2.
- Returns aggregate severity counts only, not row-level severity changes.

### API prefix convention

Mixed. Older routers register without a version (`/api/...`); newer routers (`cves.py`) use `/api/v1/...`. Compare v2 should follow the v1-prefixed convention. Decision: **`POST /api/v1/compare`** as the prompt specifies. Keep `/api/analysis-runs/compare` as-is for the existing page during the transition.

---

## 7. Frontend types

**Source:** [frontend/src/types/index.ts:52-122](frontend/src/types/index.ts#L52-L122)

The existing types align cleanly with the backend ORM. The shape returned by v1 compare:

```ts
export interface CompareRunsResult {
  run_a: { id: number; sbom_name: string | null; completed_on: string | null };
  run_b: { id: number; sbom_name: string | null; completed_on: string | null };
  new_findings: string[];
  resolved_findings: string[];
  common_findings: string[];
  severity_delta: { critical: number; high: number; medium: number; low: number };
}
```

CVE detail types in [frontend/src/types/cve.ts:9-111](frontend/src/types/cve.ts#L9-L111) are reusable verbatim for severity/KEV/EPSS chips in the v2 findings table.

API client pattern in [frontend/src/lib/api.ts](frontend/src/lib/api.ts) — typed `request<T>()`, `AbortSignal` plumbed through, `HttpError` for structured failures, `BASE_URL` from `NEXT_PUBLIC_API_URL`. New endpoints will follow this verbatim.

---

## 8. Existing compare page

**Path:** [frontend/src/app/analysis/compare/page.tsx](frontend/src/app/analysis/compare/page.tsx) (~540 LOC, fully implemented)

Not a placeholder. Already includes:

- URL-driven state (`?run_a=`, `?run_b=`)
- TanStack Query fetch via `compareRuns()`
- TopBar with breadcrumbs, "Back" button
- Skeleton, error, empty, and rendered states
- Hero strip (Run A → Run B)
- Distribution bar (proportional segments for new/resolved/common)
- Summary tiles (counts with icons)
- Severity delta table (Critical/High/Medium/Low deltas)
- Free-text filter input
- Three-column layout: New / Resolved / Common findings, each with external links to NVD/GHSA

**The screenshot the prompt references is the empty state — what users see when they hit `/analysis/compare` with no query params.** With params, the full v1 page renders.

**Decision required.** Three options for handling this:

1. **In-place rebuild.** Delete current `page.tsx` body, replace with v2. Risk: any in-flight links / bookmarks to the v1 URL break if behavior changes shape. Lowest URL fragmentation.
2. **Coexist behind a flag.** Keep `compare/page.tsx` as v1, add `compare/v2/page.tsx` (or gate by `?v=2`). Per the prompt's `compare_v2_enabled` feature flag, this is consistent with rollout intent.
3. **Strangler.** Build v2 components alongside v1, swap incrementally as each region ships.

**Recommendation:** Option 2 with the flag. Matches the prompt's rollout plan, keeps a working fallback, allows side-by-side QA.

---

## 9. Scale signals

No production telemetry available; estimates from fixtures + index design:

| Dimension | Typical | Worst observed in fixtures | Worst plausible |
|---|---|---|---|
| Components / run | 50–500 | ~hundreds in `spdx_2_3_realistic.json` | 10,000 |
| Findings / run | 5–500 | ~tens in test fixtures | 50,000 |
| Runs per project (history) | 10–100 | — | 10,000+ |

**Index support is good** for the diff query patterns:

- `ix_sbom_component_sbom_name` (compound) — fast component fetch by SBOM
- `ix_analysis_finding_run_severity` (compound) — fast finding fetch by run
- All FKs implicitly indexed

**Streaming threshold** in the v2 prompt is `len(findings) + len(components) > 5000`. At the worst plausible scale (50k findings + 10k components per run, both runs), a non-streamed diff payload could exceed 60 MB pre-compression. Streaming is justified.

---

## 10. Design assumptions

Things I had to infer because the prompt assumed cleanroom design:

1. **Run IDs are `Integer`, not `UUID`.** All v2 schemas in [§3.1 of the prompt](#) are translated to `int`. Cache key changes from `sha256(min(a,b) || max(a,b))` (over UUIDs) to `f"{min(a,b)}:{max(a,b)}"` then SHA-256.
2. **Component identity for diff** is `(name, ecosystem_from_purl)`, falling back to `(name, "unknown")` when purl is missing. Documented limitation.
3. **Finding identity for diff** is `(vuln_id, component_name, component_version)` because findings don't FK to a stable purl. Component join is best-effort to enrich with purl/ecosystem.
4. **`license_changed` and `hash_changed` change_kinds are stubbed but never fire** in v1 because the source data isn't stored. Plumbing them through means a future migration that adds `license` and `content_hash` to `sbom_component` is a one-liner change to the diff engine. Documented in ADR-0008 out-of-scope.
5. **KEV / EPSS values are *current*, not at-scan-time.** The diff displays today's KEV/EPSS for both A and B. `kev_added` fires when a finding is in both runs and the CVE is currently KEV-listed. Inline footnote on the column header explains.
6. **Risk score weights are hardcoded** in `app/services/risk_scoring.py` (new module). Not tunable per-tenant since there are no tenants. Comment points at ADR-0008.
7. **Run "ready to diff"** = `run_status in {OK, FINDINGS, PARTIAL}`. `RUNNING`/`PENDING` → Run-Not-Ready state; `ERROR`/`NO_DATA` → "this run produced no comparable data" empty state.
8. **`completed_at` and `started_at`** are stored as ISO-8601 strings. Diff engine parses them into `datetime` for the relationship descriptor; if parsing fails, `days_between` is `None`.
9. **Tenant scoping is deferred.** SQL queries use the user's identity for logging/audit only. ADR-0008 records this as an explicit gap with a follow-up issue tagged.
10. **The v1 `/api/analysis-runs/compare` endpoint is left in place** to support the old page. The v2 endpoint is `POST /api/v1/compare`, keyed by JSON body, not query params (per prompt spec). Cache invalidation hook is added in this phase whether v1 stays or not.

---

## 11. Open questions blocking Phase 2

These need decisions before I write [docs/adr/0008-compare-runs-architecture.md](docs/adr/0008-compare-runs-architecture.md):

| # | Question | Default if no input |
|---|---|---|
| Q1 | **Tenancy.** Drop the SQL-layer scoping constraint for now? | Yes — drop, document in ADR, raise as follow-up |
| Q2 | **Old compare page.** Coexist behind `compare_v2_enabled` flag? | Yes — coexist; v2 lives at `/analysis/compare?v=2` initially, becomes default when flag flips |
| Q3 | **Storing license + content hash on components.** Add columns now (one-time migration) so `license_changed` / `hash_changed` work in v1? | No — stub them, ship without; prioritize the supply-chain hash story as a follow-up feature |
| Q4 | **KEV / EPSS as "current" not "at-scan-time."** Acceptable simplification with footnote? | Yes |
| Q5 | **Component identity falls back to `(name, "unknown")` when purl is missing.** Acceptable risk of cross-ecosystem name collisions? | Yes — documented |
| Q6 | **Project picker scope.** Must Run A and Run B share a project, or are cross-project compares supported? | Cross-project supported (per v2 prompt §1.4 reference patterns); show a "Different projects" relationship descriptor |
| Q7 | **Replace v1 endpoint or coexist?** The new `POST /api/v1/compare` is strictly more capable. | Coexist; mark v1 deprecated; remove after v2 ships and old page is retired |

Will proceed with the **defaults** in Phase 2 unless you push back.

---

## Appendix A — Migration history

| Revision | Date | Change |
|---|---|---|
| `001_initial_schema` | 2026-04-13 | Bootstrap |
| `002_nvd_mirror_tables` | — | NVD mirror |
| `003_kev_epss_cache` | 2026-04-29 | KEV + EPSS tables |
| `004_analysis_schedule` | — | Periodic schedules |
| `005_rename_run_status_fail_to_findings` | 2026-04-30 | ADR-0001 status rename |
| `006_cve_cache` | 2026-04-30 | Merged CVE detail cache |
| `007_compare_cache` (planned) | — | New in Phase 3 |

## Appendix B — Files I will touch in Phase 3+

**Backend:**

- `alembic/versions/007_compare_cache.py` (new)
- `app/models.py` (add `CompareCache` model)
- `app/schemas/compare.py` (new)
- `app/services/compare_service.py` (new)
- `app/services/risk_scoring.py` (new — single source of truth for the formula)
- `app/services/compare_export.py` (new — markdown/csv/json formatters)
- `app/routers/compare.py` (new)
- `app/routers/runs.py` (add `/recent` and `/search` endpoints)
- `app/main.py` (register compare router)
- `app/workers/celery_app.py` (cache invalidation hook on run completion)
- `tests/test_compare_service.py`, `tests/test_compare_router.py`, `tests/test_compare_export.py`, `tests/test_compare_cache_invalidation.py`

**Frontend:**

- `frontend/src/app/analysis/compare/page.tsx` (gated by flag, render v2 or v1)
- `frontend/src/components/compare/**` (new tree per Phase 4 §4.2)
- `frontend/src/lib/api.ts` (add `compareV2`, `searchRuns`, `recentRuns`, `exportCompare`)
- `frontend/src/types/compare.ts` (new — mirrors `app/schemas/compare.py`)
- `frontend/src/hooks/useCompareData.ts`, `useRunSearch.ts`, `useCompareUrlState.ts`, `useKeyboardNav.ts` (new)

**Docs:**

- `docs/adr/0008-compare-runs-architecture.md` (Phase 2)
- `docs/features/compare-runs.md` (Phase 6)
- `docs/runbook-compare.md` (Phase 6)
