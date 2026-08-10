# SBOM Analyzer — SPDX & CycloneDX Validation Audit + Implementation

**Project:** FBT SBOM Vulnerability Analyzer
**Owner:** Feroze Basha (CEO, FIROSE Enterprises / Founder, Future Beyond Technology)
**Workflow:** Cowork (Claude Code as primary engineer)
**Prompt type:** Multi-phase audit → design → implementation → test
**Estimated execution:** 4–6 Claude Code sessions

---

## 1. ROLE

You are a **Senior Backend Security Engineer** specializing in:

- Software supply chain security and SBOM standards
- SPDX specification (v2.2, v2.3, v3.0) — ISO/IEC 5962:2021
- CycloneDX specification (v1.4, v1.5, v1.6) — ECMA-424
- NTIA minimum elements for an SBOM (July 2021 guidance)
- CISA SBOM guidance and OpenSSF best practices
- Python backend systems (FastAPI, Pydantic v2, SQLAlchemy 2.x, Celery, Redis, PostgreSQL)
- Defensive parsing (XXE, YAML deserialization, JSON depth attacks, decompression bombs)
- OWASP Dependency-Track and Anchore Grype patterns for SBOM ingestion

You think like a security engineer first, a parser engineer second, and a product engineer third — in that order. You never assume input is well-formed, you never use `yaml.load`, you never use `xml.etree` without `defusedxml`, and you treat every uploaded SBOM as potentially adversarial until proven otherwise.

---

## 2. CONTEXT

### 2.1 The product

The **SBOM Analyzer** is a Python service that:

1. Accepts SBOM uploads (SPDX or CycloneDX, in JSON / XML / YAML / Tag-Value)
2. Parses them into a normalized internal model
3. Resolves components to known vulnerabilities (OSV, NVD, GHSA)
4. Returns a vulnerability report

Validation sits at the entry point. **If validation is wrong, every downstream stage is wrong** — false negatives (missed vulnerabilities) and false positives (phantom matches) both originate here.

### 2.2 Target architecture (already proposed)

- FastAPI (sync ingress, async via Celery)
- JWT auth (access + refresh, RS256)
- Celery + Redis for async parsing/scanning
- PostgreSQL 16 (migration from current store)
- S3-compatible object store for raw SBOM blobs
- Pydantic v2 for all request/response models

### 2.3 Engineering constants (non-negotiable)

- **SOLID, DRY, KISS, YAGNI**
- **Zero `Any` / zero `# type: ignore`** without an inline justification comment
- **Layered validation** with explicit boundaries
- **Fail closed** — unknown format = reject, never "best effort parse"
- **Deterministic errors** — every rejection produces a stable, machine-readable error code
- **Performance budget** — synchronous validation path completes in **< 500 ms p95** for SBOMs up to 5 MB; larger SBOMs go async

### 2.4 What "good" looks like

A user uploads an SBOM. The API responds within 500 ms with one of:

- `202 Accepted` + analysis job ID (SBOM passed validation, queued for scan)
- `400 Bad Request` + structured error list pointing to exact offending paths
- `413 Payload Too Large` (size cap)
- `415 Unsupported Media Type` (unknown format)
- `422 Unprocessable Entity` (semantic / cross-reference failures)

Never `500`. A 500 from the validation layer is a bug.

---

## 3. TASK

Execute the following phases **in order**. Do not skip ahead. After each phase, summarize findings and wait for explicit "continue" before the next phase.

### PHASE 1 — Discovery & audit (read-only)

3.1.1 Map the current validation code path end to end. Produce a numbered list of every function/class/module touched between HTTP ingress and the moment a parsed SBOM is handed to the scanner.

3.1.2 For each step, identify:
  - What it validates (schema / semantic / security / nothing)
  - What it rejects vs. silently coerces
  - What error shape it returns
  - Whether it's spec-compliant for SPDX and CycloneDX *current* versions

3.1.3 Produce a **Validation Coverage Matrix** as a markdown table with rows = SBOM format/version (SPDX 2.2 JSON, SPDX 2.3 JSON, SPDX 2.3 Tag-Value, SPDX 3.0 JSON, CycloneDX 1.4 JSON, CycloneDX 1.4 XML, CycloneDX 1.5 JSON, CycloneDX 1.5 XML, CycloneDX 1.6 JSON, CycloneDX 1.6 XML) and columns = the 8 validation layers from §4.1. Each cell is one of: `✅ full`, `⚠ partial`, `❌ missing`, `N/A`.

3.1.4 Identify **P0 gaps** (security-critical) and **P1 gaps** (correctness).

3.1.5 List every third-party dependency the current validator uses. Flag any that are unsafe (`yaml.load`, `xml.etree`, raw `json.loads` without depth limit, `pickle`, `eval`).

**Phase 1 deliverable:** `docs/validation-audit.md` containing 3.1.1–3.1.5.

---

### PHASE 2 — Design (architecture only, no code)

Design a layered validator with **eight explicit stages**, each implemented as a separate, independently testable component:

**Stage 1 — Ingress guard**
- Hard size cap: 50 MB upload, 200 MB decompressed
- Reject non-UTF-8 with explicit error
- Decompression bomb protection (ratio cap 100:1, absolute cap 200 MB)
- Magic byte / BOM stripping

**Stage 2 — Format & version detection**
- Detect JSON / XML / YAML / SPDX Tag-Value / CycloneDX Protobuf
- Detect SPDX vs CycloneDX from structural fingerprint:
  - SPDX JSON: top-level `spdxVersion` key
  - SPDX Tag-Value: `SPDXVersion:` prefix on first non-comment line
  - CycloneDX JSON: top-level `bomFormat == "CycloneDX"` + `specVersion`
  - CycloneDX XML: root element `{http://cyclonedx.org/schema/bom/...}bom`
- Reject ambiguous documents — never guess
- Output: `(spec: Literal["spdx","cyclonedx"], version: str, encoding: Literal["json","xml","yaml","tag-value","protobuf"])`

**Stage 3 — Structural schema validation**
- Use **official upstream schemas**, vendored into the repo with version pinning:
  - SPDX schemas from `spdx/spdx-spec` GitHub
  - CycloneDX schemas from `CycloneDX/specification` GitHub
- JSON: `jsonschema` with `Draft202012Validator` + format checker
- XML: `lxml` + XSD (never `xml.etree`); use `defusedxml` for parsing entry
- YAML: `ruamel.yaml` in safe mode, then route through JSON schema
- Tag-Value: parse via `spdx-tools` (official Linux Foundation library), then re-validate
- Aggregate errors — never fail on first; collect up to 100 then truncate

**Stage 4 — Semantic validation**

For **SPDX**:
- `SPDXID` format: `^SPDXRef-[a-zA-Z0-9.\-]+$`
- `documentNamespace` is a valid absolute URI without `#`
- `dataLicense` is exactly `CC0-1.0`
- License expressions parseable via `license-expression` library against current SPDX License List + declared `LicenseRef-*`
- Checksum algorithm matches digest length (SHA1=40 hex, SHA256=64 hex, SHA512=128 hex, MD5=32 hex)
- `created` timestamp is ISO 8601 UTC with `Z` suffix
- At least one `DESCRIBES` relationship from `SPDXRef-DOCUMENT`

For **CycloneDX**:
- `serialNumber` matches `^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
- `bom-ref` uniqueness within the document (set check)
- Every `purl` parses via `packageurl-python`
- Every `cpe` matches CPE 2.3 format
- Hash `alg` ↔ `content` length consistency
- `version` field is a non-negative integer (BOM version, not component version)
- `metadata.timestamp` is ISO 8601

**Stage 5 — Cross-reference integrity**
- SPDX: every relationship `spdxElementId` and `relatedSpdxElement` resolves to a declared element or is a valid `DocumentRef-*`
- CycloneDX: every `dependencies[].ref` and `dependencies[].dependsOn[]` resolves to a declared `bom-ref`
- Detect cycles in dependency graph (Tarjan's SCC). Cycles are *warnings*, not errors — many real BOMs have them
- Detect orphan components (components with no inbound or outbound edges) — *info-level* only

**Stage 6 — Security checks**
- JSON: max nesting depth 64, max array length 1,000,000, max string length 65,536
- XML: `defusedxml` with `forbid_dtd=True, forbid_entities=True, forbid_external=True`
- YAML: `ruamel.yaml(typ="safe", pure=True)` — never `unsafe`, never `full_load`
- Reject any document containing fields named `__proto__`, `constructor`, `prototype` (prototype pollution defense)
- Reject any embedded base64 blob > 1 MB unless declared as a known field (`hashes.content` etc.)

**Stage 7 — NTIA minimum elements check**
Soft validation — produces *warnings*, not errors, unless `strict=true` query param:
- Supplier name
- Component name
- Version of the component
- Other unique identifiers (PURL / CPE / SPDXID)
- Dependency relationship
- Author of SBOM data
- Timestamp

**Stage 8 — Signature validation (optional, feature-flagged)**
- CycloneDX: JSF (JSON Signature Format) verification if `signature` block present
- SPDX: external signature file support
- Default off; enable per-tenant

**Design deliverables:**
1. `docs/adr/0007-sbom-validation-architecture.md` — full ADR
2. `docs/validation-pipeline.mmd` — Mermaid sequence diagram of the 8 stages
3. `docs/validation-error-codes.md` — every error code (e.g. `SBOM_VAL_E001_SIZE_EXCEEDED`, `SBOM_VAL_E042_PURL_INVALID`) with HTTP status, severity, example payload, and remediation

---

### PHASE 3 — Implementation

Implement strictly per the Phase 2 design.

**Module layout:**
```
app/
  validation/
    __init__.py
    pipeline.py              # orchestrator, stage 1→8
    errors.py                # error codes, ValidationError, ErrorReport
    stages/
      ingress.py             # stage 1
      detect.py              # stage 2
      schema.py              # stage 3
      semantic_spdx.py       # stage 4 (SPDX branch)
      semantic_cyclonedx.py  # stage 4 (CycloneDX branch)
      integrity.py           # stage 5
      security.py            # stage 6
      ntia.py                # stage 7
      signature.py           # stage 8
    schemas/
      spdx/
        2.2/spdx-schema.json
        2.3/spdx-schema.json
        3.0/spdx-schema.json
      cyclonedx/
        1.4/bom-1.4.schema.json
        1.4/bom-1.4.xsd
        1.5/bom-1.5.schema.json
        1.5/bom-1.5.xsd
        1.6/bom-1.6.schema.json
        1.6/bom-1.6.xsd
    models.py                # Pydantic v2 internal SBOM model
    normalize.py             # spec-specific → internal model
```

**Implementation rules:**

- Each stage exposes `run(ctx: ValidationContext) -> ValidationContext`. Pure function semantics where possible; mutations on `ctx` must be additive only.
- `ValidationContext` accumulates errors with severity (`error`, `warning`, `info`). The pipeline short-circuits to "fail" only after a stage with `errors`. Warnings never fail validation.
- All errors use the structured shape:
  ```json
  {
    "code": "SBOM_VAL_E042_PURL_INVALID",
    "severity": "error",
    "stage": "semantic",
    "path": "components[17].purl",
    "message": "PURL 'pkg:npm/@scope//bad' is malformed: empty namespace segment",
    "remediation": "Use the form pkg:npm/@scope/name@version. See https://github.com/package-url/purl-spec",
    "spec_reference": "CycloneDX 1.6 §4.4.1"
  }
  ```
- All schemas vendored, never fetched at runtime.
- All schemas loaded once at process start, cached on the validator instance.
- No global mutable state.
- Type hints everywhere. `mypy --strict` must pass.
- All public functions have docstrings with at minimum: purpose, params, returns, raises.

**Wire into FastAPI:**

```python
@router.post("/sboms", status_code=202)
async def upload_sbom(
    file: UploadFile,
    strict_ntia: bool = Query(False),
    current_user: User = Depends(require_auth),
) -> SbomAcceptedResponse:
    raw = await read_with_size_limit(file, max_bytes=50 * 1024 * 1024)
    report = await validation_pipeline.run(raw, strict_ntia=strict_ntia)
    if report.has_errors():
        raise HTTPException(
            status_code=report.http_status,  # 400 / 413 / 415 / 422
            detail=report.to_dict(),
        )
    job_id = await enqueue_scan(report.normalized_sbom, owner=current_user.id)
    return SbomAcceptedResponse(job_id=job_id, warnings=report.warnings)
```

**Implementation deliverables:**
- All files under `app/validation/`
- Updated `pyproject.toml` with pinned versions of: `jsonschema`, `lxml`, `defusedxml`, `ruamel.yaml`, `packageurl-python`, `license-expression`, `spdx-tools`, `cyclonedx-python-lib`
- Updated FastAPI router
- Migration note in `CHANGELOG.md`

---

### PHASE 4 — Testing & verification

**Test corpus:** vendor under `tests/fixtures/sboms/` at minimum:

- `valid/spdx_2_3_minimal.json`
- `valid/spdx_2_3_realistic.json` (200+ packages)
- `valid/cyclonedx_1_5_minimal.json`
- `valid/cyclonedx_1_6_realistic.xml` (500+ components)
- `invalid/spdx_missing_data_license.json`
- `invalid/spdx_bad_spdxid_format.json`
- `invalid/cyclonedx_dangling_dep_ref.json`
- `invalid/cyclonedx_duplicate_bom_ref.json`
- `invalid/cyclonedx_bad_purl.json`
- `attack/xxe_billion_laughs.xml`
- `attack/yaml_pickle.yaml`
- `attack/json_depth_bomb.json`
- `attack/zip_bomb.zip`
- `edge/cyclonedx_with_cycle.json`
- `edge/spdx_with_external_doc_ref.json`
- `edge/utf8_bom_prefix.json`

Pull at least 5 real-world SBOMs from public sources for each major spec version (e.g., from `kubernetes/kubernetes`, `npm/cli`, `python/cpython` releases) into `tests/fixtures/sboms/wild/`.

**Test layers:**

1. **Unit tests** — each stage in isolation, ≥ 90% line coverage on `app/validation/`
2. **Integration tests** — full pipeline against the corpus; every fixture has an expected outcome JSON
3. **Property-based tests** — Hypothesis strategies for PURL, CPE, SPDXID, UUID generation; assert the validator rejects all generated invalid forms
4. **Security tests** — every `attack/*` fixture must be rejected at the correct stage with the correct error code, and must not crash, hang, or exceed 100 ms wall time
5. **Performance test** — pytest-benchmark against `realistic` fixtures, asserting p95 < 500 ms

**Test deliverables:**
- `tests/validation/` directory complete
- `pytest --cov=app.validation --cov-fail-under=90` passing
- `pytest -m security` passing in < 5 s total
- `pytest -m bench` produces a summary printed to CI logs

---

### PHASE 5 — Documentation

5.1 Update `README.md` with a "Supported SBOM Formats" table

5.2 Author `docs/sbom-validation.md` for end users:
  - What we validate and why
  - Error code reference (auto-generated from `errors.py`)
  - How to fix common rejections
  - cURL examples for each error class

5.3 Author `docs/runbook-sbom-validation.md` for operators:
  - Metrics to watch (rejection rate per stage, p95 latency, top error codes)
  - How to triage false positives
  - How to bump a vendored schema when a new spec version drops

---

## 4. CONSTRAINTS

### 4.1 Hard constraints (do not violate)

- No `yaml.load` / `yaml.full_load` / `yaml.unsafe_load` — only `safe_load` or `ruamel.yaml(typ="safe")`
- No `xml.etree.ElementTree` for untrusted input — only `defusedxml` or `lxml` with safe configuration
- No `pickle.loads` / `eval` / `exec` anywhere in the validation path
- No `requests` / `httpx` calls during validation — schemas are vendored, never fetched
- No `Any` type unless paired with an inline `# typing: explicit-any reason: <why>` comment
- No silent coercion. If the spec says a field MUST be a string and we got a number, reject with `SBOM_VAL_E0xx_TYPE_MISMATCH`. Never `str(x)` it through.
- Validation must be **side-effect free**. No DB writes, no S3 writes, no log lines above DEBUG until validation completes (then a single structured INFO/WARN/ERROR line)
- All vendored schemas in `app/validation/schemas/` carry a `SOURCE.md` recording origin URL, commit SHA, and license

### 4.2 Soft constraints (justify in PR if violated)

- p95 < 500 ms on 5 MB SBOM
- Error report ≤ 100 entries (truncate with `truncated: true` flag)
- ≥ 90% test coverage on `app/validation/`

### 4.3 Spec adherence

For SPDX, defer to:
- SPDX Spec 2.3: https://spdx.github.io/spdx-spec/v2.3/
- SPDX Spec 3.0: https://spdx.github.io/spdx-spec/v3.0.1/

For CycloneDX, defer to:
- CycloneDX 1.5: https://cyclonedx.org/docs/1.5/json/
- CycloneDX 1.6: https://cyclonedx.org/docs/1.6/json/

When the spec is ambiguous, prefer the **stricter** interpretation and document the choice in an inline comment with a link to the relevant section.

---

## 5. OUTPUT FORMAT

For each phase, deliver in this exact order:

1. **Plan** — a numbered task list you intend to execute (≤ 15 items)
2. **Diff** — actual file changes, grouped logically
3. **Test evidence** — terminal output of relevant test runs
4. **Open questions** — anything ambiguous you decided unilaterally, with the decision and one-line justification
5. **Next phase preview** — one paragraph on what phase N+1 will cover

Stop after each phase. Wait for `continue` before proceeding.

For the final phase, additionally produce:

- A **migration note** for any existing API consumers
- A **rollout plan** (feature flag, canary %, rollback trigger)
- A **post-deploy verification checklist**

---

## 6. SUCCESS CRITERIA

This work is done when **all** of the following are true:

- [ ] Phase 1 audit document exists and lists every P0/P1 gap
- [ ] Phase 2 ADR is committed and signed off
- [ ] All 8 validation stages are implemented as separate testable modules
- [ ] Vendored schemas exist for SPDX 2.2 / 2.3 / 3.0 and CycloneDX 1.4 / 1.5 / 1.6
- [ ] `pytest --cov=app.validation --cov-fail-under=90` passes
- [ ] All `attack/*` fixtures rejected without crash, hang, or > 100 ms parse time
- [ ] p95 < 500 ms on 5 MB realistic SBOM
- [ ] `mypy --strict app/validation` passes
- [ ] `ruff check` and `ruff format` pass
- [ ] Error code reference doc auto-generates from source
- [ ] Existing API contract is preserved or extended (never broken)
- [ ] One real-world SBOM from each major project (kubernetes, npm, cpython) parses and produces a vulnerability report end-to-end on a staging deploy

---

## 7. ANTI-PATTERNS TO AVOID

- ❌ "Best effort" parsing that silently strips unknown fields
- ❌ Returning HTTP 200 with an embedded error object
- ❌ One mega-function `validate_sbom(file)` doing all 8 stages
- ❌ Catching `Exception` broadly and remapping to a single error code
- ❌ Logging the entire SBOM body on validation failure (PII / IP risk)
- ❌ Live-fetching schemas from spdx.org / cyclonedx.org at runtime
- ❌ Mutating the input bytes
- ❌ Using `re` for PURL/CPE — use the dedicated parsers
- ❌ Treating warnings and errors as the same severity
- ❌ Hard-failing on cycles in the dependency graph (real BOMs have them; warn instead)

---

**End of prompt. Begin Phase 1.**
