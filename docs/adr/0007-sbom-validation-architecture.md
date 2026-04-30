# ADR-0007 — SBOM validation architecture (eight-stage layered pipeline)

- **Status:** Proposed (2026-04-30)
- **Context:** [docs/validation-audit.md](../validation-audit.md)
- **Authors:** Feroze Basha (FBT) / Claude
- **Supersedes:** none
- **Related:** [docs/validation-pipeline.mmd](../validation-pipeline.mmd), [docs/validation-error-codes.md](../validation-error-codes.md)

## Context

The Phase 1 audit ([docs/validation-audit.md](../validation-audit.md)) found that the current SBOM ingest is **best-effort parsing, not validation**. Of the eight target stages from §3.2 of the workplan, only stage 1 is partially present, and three stages are entirely missing. Eight findings are P0 / security-critical — the most acute being `xml.etree.ElementTree.fromstring` on untrusted input ([app/parsing/cyclonedx.py:79](../../app/parsing/cyclonedx.py#L79)) and `xmltodict.parse` with default-config expat ([app/parsing/cyclonedx.py:38](../../app/parsing/cyclonedx.py#L38), [app/parsing/spdx.py:73](../../app/parsing/spdx.py#L73)). 27 findings are P1 / correctness — chief among them: zero JSON Schema or XSD validation, zero semantic checks, zero cross-reference resolution.

The audit also surfaced a structural problem: **validation runs once at create, again at every analyse**, because `extract_components` is called from both `sync_sbom_components` and `_run_legacy_analysis`. Storage and parsing are coupled through the `sbom_data: str` Pydantic field, so the validator runs N+1 times per SBOM. Any solution that re-introduces this coupling will leak validator cost into the scanner hot path.

The goal of this ADR is to land an architecture that closes every P0 by **design** (not by patching the existing parsers), every P1 by **structure** (so future spec drift can't regress us), and produces a single set of structured error codes that the frontend can render with stable copy and remediation guidance.

## Decision

### 1. Eight-stage layered pipeline

Validation becomes a chain of eight pure stages, each implemented as a separate module under [app/validation/stages/](../../app/validation/stages/). The orchestrator runs them in order with **explicit short-circuit semantics**: if any stage emits an error-severity entry, subsequent stages run only if their `requires` declaration says they tolerate prior errors (none do, except stage 7 NTIA which always runs to give the user a complete report). Warnings and info entries never short-circuit.

```
1. Ingress guard          — size, encoding, decompression, BOM
2. Format & version       — SPDX | CycloneDX × json | xml | yaml | tag-value | protobuf
3. Structural schema      — vendored JSON Schema / XSD per spec version
4. Semantic validation    — SPDXID, namespace, license, PURL, CPE, hash, timestamps
5. Cross-ref integrity    — relationships / dependencies resolve, cycles, orphans
6. Security checks        — JSON depth, XML entities, YAML safe, prototype keys
7. NTIA minimum elements  — supplier / name / version / id / deps / author / timestamp
8. Signature              — JSF (CycloneDX) / external sig (SPDX), feature-flagged
```

Each stage signature is identical:

```python
# app/validation/pipeline.py
class Stage(Protocol):
    name: ClassVar[str]
    def run(self, ctx: ValidationContext) -> ValidationContext: ...
```

The orchestrator is a *for loop* with no clever scheduling. There is no DAG, no parallelism within the pipeline (the work is sequential and CPU-bound; threading buys nothing here). Parallelism happens above the pipeline — see §6.

### 2. The `ValidationContext` and `ErrorReport`

`ValidationContext` is a Pydantic v2 model accumulated across stages. Mutations are **additive only**: stages append errors and write into named slots they own, never read or overwrite a peer's slot.

```python
# app/validation/errors.py
class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

class ValidationError(BaseModel):
    code: str                    # SBOM_VAL_E042_PURL_INVALID
    severity: Severity
    stage: str                   # "semantic"
    path: str                    # "components[17].purl"
    message: str                 # human-readable
    remediation: str             # how to fix (URL allowed)
    spec_reference: str | None   # "CycloneDX 1.6 §4.4.1"

class ErrorReport(BaseModel):
    entries: list[ValidationError]
    truncated: bool = False      # ≥ 100 entries → True, rest dropped
    @property
    def http_status(self) -> int: ...   # 400 / 413 / 415 / 422
    def has_errors(self) -> bool: ...
    def to_dict(self) -> dict: ...
```

Aggregation rules:
- Hard cap of **100 entries**. After 100, the 101st sets `truncated=True` and the rest are dropped (we never want a 50 MB error response).
- `http_status` is the **highest-priority** status emitted: 413 > 415 > 422 > 400. (A 413 from stage 1 always wins over a 422 from stage 4.)
- Severity ordering: `ERROR > WARNING > INFO`. Only `ERROR` blocks acceptance; `WARNING` and `INFO` flow through to the response body.
- One error code → one HTTP status mapping in [docs/validation-error-codes.md](../validation-error-codes.md). The mapping is owned by the error-codes file, not by the stages — stages can only choose a code, not a status.

### 3. Vendored schemas, never fetched at runtime

All JSON Schema and XSD files live under [app/validation/schemas/](../../app/validation/schemas/) at fixed paths:

```
app/validation/schemas/
├── spdx/
│   ├── 2.2/spdx-schema.json
│   ├── 2.3/spdx-schema.json
│   ├── 3.0/spdx-schema.json
│   └── SOURCE.md
└── cyclonedx/
    ├── 1.4/bom-1.4.schema.json
    ├── 1.4/bom-1.4.xsd
    ├── 1.5/bom-1.5.schema.json
    ├── 1.5/bom-1.5.xsd
    ├── 1.6/bom-1.6.schema.json
    ├── 1.6/bom-1.6.xsd
    └── SOURCE.md
```

Each `SOURCE.md` records: origin URL, upstream commit SHA, retrieval date, licence (CC0 / Apache 2.0). Refreshing a schema is a deliberate PR with the SOURCE.md diff visible alongside the schema diff.

Schemas are loaded **once at process startup** and cached on the validator instance — re-validating each request loads zero filesystem state. Loading is lazy on first request only when running tests; production preloads in the lifespan hook. No `requests.get`, `httpx.get`, or `urllib` call occurs anywhere in the pipeline (enforced via the existing `import-linter` contract; see §10).

### 4. Per-stage decisions

#### 4.1 Stage 1 — Ingress guard

- Hard cap **50 MB** uploaded body, **200 MB** decompressed (vs. the current 20 MB single cap; raise [app/settings.py:215](../../app/settings.py#L215)).
- Decompression-bomb defence: ratio cap 100:1, absolute decompressed cap 200 MB. Streaming gzip / zip / br decoders count bytes incrementally and abort early.
- UTF-8 is mandatory; UTF-8 BOM is stripped, any other BOM (UTF-16 / UTF-32) is rejected with `SBOM_VAL_E004_ENCODING_NOT_UTF8`.
- Empty body rejected with `SBOM_VAL_E005_EMPTY_BODY`.

#### 4.2 Stage 2 — Format & version detection

Format is decided by **structural fingerprint**, not heuristic. The decision tree is fully deterministic and is documented in [docs/validation-pipeline.mmd](../validation-pipeline.mmd):

| Fingerprint | Result |
|---|---|
| First non-whitespace byte `{` AND has `$schema` matching `spdx.org` OR has top-level `spdxVersion` | SPDX JSON, version from `spdxVersion` |
| First non-whitespace byte `{` AND `bomFormat == "CycloneDX"` AND `specVersion` present | CycloneDX JSON, version from `specVersion` |
| First non-whitespace byte `{` AND `@graph` / `@context` referencing `spdx.org/3.0` | SPDX 3.0 JSON-LD |
| First non-whitespace byte `<` AND root element namespace `http://cyclonedx.org/schema/bom/1.x` | CycloneDX XML, version from namespace |
| First non-whitespace byte `<` AND `xmlns="http://spdx.org/rdf/`...| SPDX RDF/XML (out of scope v1) |
| First non-comment line starts with `SPDXVersion:` | SPDX Tag-Value |
| Magic bytes `0a` (varint) AND parses as `cyclonedx.proto.v1_5.Bom` | CycloneDX Protobuf (out of scope v1) |
| Anything else | reject with `SBOM_VAL_E010_FORMAT_INDETERMINATE` |

- A document that satisfies **both** an SPDX and a CycloneDX fingerprint is rejected with `SBOM_VAL_E011_FORMAT_AMBIGUOUS` — never guess.
- An unknown spec version (e.g. `specVersion: "1.99"`) is rejected with `SBOM_VAL_E013_SPEC_VERSION_UNSUPPORTED`. New spec versions arrive via a vendored-schema PR.
- v1 ships SPDX 2.2, 2.3, 3.0 (JSON only), CycloneDX 1.4 / 1.5 / 1.6 (JSON + XML). SPDX RDF/XML and CycloneDX Protobuf are **deferred** with explicit `SBOM_VAL_E013` rejection so the contract is stable.

#### 4.3 Stage 3 — Structural schema

- JSON: `jsonschema.Draft202012Validator(schema, format_checker=FormatChecker())`. We call `iter_errors()` and **collect up to 100** before truncating — never bail on first.
- XML: `lxml.etree.parse(BytesIO(body), parser=lxml.etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False))`. Then `xsd.assertValid(tree)` on the matching XSD.
- Defence-in-depth for XML: the entry point parses with `defusedxml.lxml.fromstring` to fast-fail on DTD / external entities / billion-laughs **before** lxml sees the bytes. (Stage 6 has the canonical security check; stage 3 is just the typed schema check.)
- YAML: `ruamel.yaml.YAML(typ="safe", pure=True).load(...)`, then route the resulting dict through the JSON schema. Never `yaml.load` / `yaml.full_load` / `yaml.unsafe_load`.
- SPDX Tag-Value: `spdx-tools` (the official Linux Foundation lib). Its parser already rejects malformed tag lines; we re-validate the resulting model against the JSON schema for the equivalent SPDX version.
- CycloneDX Protobuf: deferred (see §4.2).

Errors are emitted at `SBOM_VAL_E020`–`E029`. The JSON-Schema validator's native error path is mapped to `SBOM_VAL_E025_SCHEMA_VIOLATION` with the `path` field populated from `error.absolute_path` and a typed sub-code (`E026_REQUIRED`, `E027_TYPE`, `E028_ENUM`, `E029_FORMAT`) chosen from `error.validator`.

#### 4.4 Stage 4 — Semantic validation

Two sibling modules: [semantic_spdx.py](../../app/validation/stages/semantic_spdx.py) (handles 2.2 + 2.3) and [semantic_cyclonedx.py](../../app/validation/stages/semantic_cyclonedx.py). SPDX 3.0 gets its own `semantic_spdx3.py` because the document shape differs (`@graph` / `elements`) — co-locating it with 2.x semantic code would force a switch in every check function. Keeping them separate is structurally cheaper than abstraction.

Checks per spec are enumerated in §3.2.4 of the workplan; the full list of error codes is in [docs/validation-error-codes.md](../validation-error-codes.md). Notable design choices:

- **PURLs go through `packageurl-python`**, never a regex. A malformed PURL produces `SBOM_VAL_E052_PURL_INVALID` with the `packageurl.exceptions` reason in the `message` field.
- **CPEs go through a dedicated CPE 2.3 parser**. We use `cpe23-utils` if a maintained pure-Python option exists; otherwise we vendor a 50-line CPE 2.3 parser based on the NIST grammar. Decision deferred to Phase 3 implementation; either choice satisfies the structural requirement (no `re` for CPE).
- **Licence expressions** parse via `license-expression` against the **current** SPDX License List plus any `LicenseRef-*` declarations in the document. Outdated SPDX License List = warning, not error (stale list is a us-problem, not a user-problem).
- **Hash digest length / algorithm** is asserted exactly (SHA1=40, SHA256=64, SHA512=128, SHA384=96, MD5=32 hex chars). A digest that's wrong-length-for-algorithm is `SBOM_VAL_E044_CHECKSUM_LENGTH_MISMATCH` (SPDX) or `E054_HASH_LENGTH_MISMATCH` (CycloneDX).
- **`bom-ref` uniqueness** is asserted via a `set` — a duplicate produces `SBOM_VAL_E051_BOM_REF_DUPLICATE` with `path` pointing at the second occurrence.

#### 4.5 Stage 5 — Cross-reference integrity

- SPDX: every `relationship.spdxElementId` and `relationship.relatedSpdxElement` must resolve to a declared element OR be a valid `DocumentRef-*`. Unresolved → `SBOM_VAL_E072_RELATIONSHIP_ELEMENT_DANGLING`.
- CycloneDX: every `dependencies[].ref` and every entry in `dependencies[].dependsOn[]` must resolve to a declared `bom-ref`. Unresolved → `SBOM_VAL_E070_DEPENDENCY_REF_DANGLING`.
- **Cycles are warnings, not errors.** Real BOMs frequently have them (mutual dependencies, dev-time circular references). Detected via Tarjan SCC; emitted as `W074_DEPENDENCY_CYCLE_DETECTED` (severity = WARNING). Two-cycle SCCs are common in JS / Rust dependency graphs.
- **Orphans are info, not warnings.** A component that no relationship points at and that has no outbound edges is reported as `W075_ORPHAN_COMPONENT` (severity = INFO) so security teams can spot them without flagging them as wrong.
- Self-edges (`A → A`) are explicit errors (`E071_DEPENDENCY_REF_SELF`) — never legitimate, often a tooling bug.

#### 4.6 Stage 6 — Security checks

This stage is **defensive-only**. Every check has a known-malicious test fixture in `tests/fixtures/sboms/attack/` (Phase 4):

| Check | Limit | Error code |
|---|---|---|
| JSON nesting depth | 64 | `E080_JSON_DEPTH_EXCEEDED` |
| JSON array length | 1,000,000 | `E081_JSON_ARRAY_LENGTH_EXCEEDED` |
| JSON string length | 65,536 | `E082_JSON_STRING_LENGTH_EXCEEDED` |
| XML DTD declaration | forbidden | `E083_XML_DTD_FORBIDDEN` |
| XML external entity | forbidden | `E084_XML_EXTERNAL_ENTITY_FORBIDDEN` |
| XML entity expansion | `defusedxml` defaults | `E085_XML_ENTITY_EXPANSION` |
| YAML unsafe tag (`!!python/object`, …) | rejected by `ruamel.yaml(typ="safe")` | `E086_YAML_UNSAFE_TAG` |
| Prototype-pollution key (`__proto__` / `constructor` / `prototype`) | rejected | `E087_PROTOTYPE_POLLUTION_KEY` |
| Embedded base64 blob > 1 MB outside known fields | rejected | `E088_EMBEDDED_BLOB_TOO_LARGE` |
| Decompression ratio (zip / gzip) | 100:1 | `E089_ZIP_BOMB_RATIO` |

JSON depth / array / string caps are enforced via a custom `json.JSONDecoder` subclass with hooks on `parse_object` / `parse_array` / `parse_string`. We do **not** parse first and walk after — that's how depth bombs win. Counters are incremented during parse and the decoder raises as soon as a limit is exceeded, before allocating the next nested object.

#### 4.7 Stage 7 — NTIA minimum elements

Default = soft validation. Each missing element produces a **warning** (`W100`–`W106`); the response is still 202. Per-request `?strict=true` query param flips warnings to errors and yields 422.

Choosing per-request over per-tenant (the audit's open question): per-request is cheaper for callers to opt into, and per-tenant ends up being a per-request flag in disguise once API consumers integrate with multiple back-ends. Per-tenant strict-mode override can be added later as a Settings flag that **defaults** the query param when the caller does not set it — backwards-compatible.

#### 4.8 Stage 8 — Signature validation

- CycloneDX: JSF (JSON Signature Format) verification when a `signature` block is present. Library: `python-jsf` or roll-our-own using `cryptography` JWS — Phase 3 decides; the contract here is "if the signature is present and the feature flag is on, verify it; emit `SBOM_VAL_E110_SIGNATURE_INVALID` on failure".
- SPDX: external signature file support. Sidecar file accepted via the multipart endpoint as a second part (`signature.asc`).
- **Default off**, feature-flagged per tenant via `Settings.SBOM_SIGNATURE_VERIFICATION` (env: `SBOM_SIGNATURE_VERIFICATION=true`). Production rollout in a follow-up — v1 ships with the stage in place but disabled, so the test corpus + error codes are stable from day one.

### 5. Wire-up to FastAPI

Two ingress shapes are supported, both feeding the same pipeline:

1. **Multipart file upload** (new, primary) — `POST /api/sboms/upload`, `Content-Type: multipart/form-data`. The bytes are streamed directly into the pipeline; the SBOM is persisted to S3 (in production) or to a temp file (in dev) **after** stage 3 succeeds, never before.
2. **JSON-string field** (existing, deprecated-but-supported) — `POST /api/sboms` with `sbom_data: str`. The string is fed into the same pipeline. We accept this for backwards compatibility but mark it deprecated in OpenAPI; new integrations should use the multipart endpoint.

```python
@router.post("/sboms/upload", status_code=202)
async def upload_sbom(
    file: UploadFile,
    strict_ntia: bool = Query(False),
    current_user: User = Depends(require_auth),
) -> SbomAcceptedResponse:
    raw = await read_with_size_limit(file, max_bytes=settings.MAX_UPLOAD_BYTES)
    report = await validation_pipeline.run(raw, strict_ntia=strict_ntia)
    if report.has_errors():
        raise HTTPException(status_code=report.http_status, detail=report.to_dict())
    job_id = await enqueue_scan(report.normalized_sbom, owner=current_user.id)
    return SbomAcceptedResponse(job_id=job_id, warnings=report.warnings)
```

Status mapping is mechanical:

| Outcome                                                | HTTP |
|--------------------------------------------------------|------|
| Accepted (no errors)                                    | 202  |
| Stage 1 size / decompression failure                    | 413  |
| Stage 2 format unknown / unsupported version            | 415  |
| Stage 3 schema violation, stage 4–5 semantic / cross-ref | 422  |
| Stage 1 encoding / empty / stage 3 parse failure / stage 6 security | 400 |

A 500 from any stage is a bug. Error handlers preserve this — the global `Exception` handler in [app/error_handlers.py](../../app/error_handlers.py) will raise an alert if a `ValidationStageError` reaches it (anything with that base class should have been caught and mapped to a `ValidationError` entry).

### 6. Sync vs. async

Stages 1–6 run **synchronously** for any payload up to 5 MB — within the 500 ms p95 budget. Stages 7–8 also run sync (cheap soft-validation walks). Above 5 MB, the request flow becomes:

1. Stages 1–2 still run sync (size / format gating must give a fast 413 / 415).
2. Stages 3–8 are deferred to a Celery task; the sync handler returns `202 Accepted` with a `validation_job_id` and the response body explicitly notes the deferral.
3. The frontend polls the existing analysis-status endpoint pattern (`GET /api/analysis-runs/{id}` extended with `validation_status`).

The 5 MB threshold is a **knob**, not a constant — it lives in `Settings.SBOM_SYNC_VALIDATION_BYTES` so SREs can tune it after seeing real p95 traces.

### 7. Dependencies

`requirements.txt` and `pyproject.toml` gain (Phase 3):

- `jsonschema>=4.21,<5` — Draft 2020-12 validator
- `lxml>=5,<6` — XML + XSD validation, with `no_network=True` and `resolve_entities=False`
- `defusedxml>=0.7,<1` — defence-in-depth wrapper
- `ruamel.yaml>=0.18,<1` — safe YAML
- `packageurl-python>=0.15,<1` — PURL parser
- `license-expression>=30,<31` — SPDX licence expression parser
- `spdx-tools>=0.8,<1` — SPDX Tag-Value parser
- `cyclonedx-python-lib>=8,<10` — used only as a test oracle, not in the validation path

Pins are minimum versions (per the existing `pyproject.toml` style) plus an upper bound to prevent surprise major bumps.

### 8. Module layout

```
app/validation/
├── __init__.py
├── pipeline.py                  # orchestrator (Stage protocol, run loop)
├── errors.py                    # codes, ValidationError, ErrorReport, severity
├── models.py                    # internal Pydantic v2 SBOM model
├── normalize.py                 # spec-specific dict → internal model
├── stages/
│   ├── __init__.py
│   ├── ingress.py               # stage 1
│   ├── detect.py                # stage 2
│   ├── schema.py                # stage 3
│   ├── semantic_spdx.py         # stage 4 (SPDX 2.x)
│   ├── semantic_spdx3.py        # stage 4 (SPDX 3.0)
│   ├── semantic_cyclonedx.py    # stage 4 (CycloneDX)
│   ├── integrity.py             # stage 5
│   ├── security.py              # stage 6
│   ├── ntia.py                  # stage 7
│   └── signature.py             # stage 8
└── schemas/
    ├── spdx/{2.2,2.3,3.0}/spdx-schema.json
    ├── spdx/SOURCE.md
    ├── cyclonedx/{1.4,1.5,1.6}/bom-<v>.schema.json
    ├── cyclonedx/{1.4,1.5,1.6}/bom-<v>.xsd
    └── cyclonedx/SOURCE.md
```

The existing [app/parsing/](../../app/parsing/) tree stays — for one release — but is deprecated and re-exports from `app.validation.normalize`. After one release, it is removed.

### 9. Migration strategy for existing data

The existing `sbom_source.sbom_data` column holds raw SBOM strings that have **never** been validated. We do not retroactively reject them. Instead:

1. The next analyse on each SBOM re-runs the validation pipeline. If validation now fails, the analyse returns 422 with the structured error report — but the SBOM row stays in the DB. The frontend renders a "validation failed, re-upload required" banner on the SBOM detail page.
2. Operators can run `python -m app.validation.audit_existing` (a new CLI Phase 3 ships) which iterates every `sbom_source` row, runs the validator, and writes a `sbom_validation_audit` row per SBOM with the report. This produces an artifact for the runbook and gives Ops a queue to triage.

### 10. Enforcement

The existing [tool.importlinter] contract in [pyproject.toml](../../pyproject.toml) gains a new rule:

```
[[tool.importlinter.contracts]]
name = "Validation never imports HTTP, services, or DB"
type = "forbidden"
source_modules = ["app.validation"]
forbidden_modules = ["app.routers", "app.main", "app.services", "app.db", "app.models"]
```

This forces the side-effect-free property from §4.1 of the workplan to be a build-time check, not a code-review hope.

A second contract forbids `app.validation` from importing `requests`, `httpx`, `urllib.request` — schemas are vendored, never fetched.

A `mypy --strict app/validation` check runs in CI alongside `ruff`. Zero `Any`, zero `# type: ignore` without an inline justification comment.

## Consequences

### Positive

- Every P0 from the audit closes by **architecture**: there is no XML path that doesn't go through `defusedxml` + `lxml` with a vendored XSD; there is no JSON path that doesn't go through the depth-capped decoder; there is no format-detection branch that guesses.
- Every P1 closes by **structure**: a missing semantic check fails a unit test in `tests/validation/`, not a code-review eyeball.
- A single error contract (`{code, severity, stage, path, message, remediation, spec_reference}`) replaces the current grab-bag of `HTTPException(detail=str(exc))`. Frontend can render stable copy keyed by `code`.
- Validation runs **once per SBOM** at create / upload, not once per analyse. The internal Pydantic SBOM model is what gets persisted (or referenced); stages 4–8 never re-execute on a stored SBOM.
- The 8-stage decomposition is independently testable: a regression in stage 5 produces a stage-5-only test failure; no other stage shares state.
- `mypy --strict` + `import-linter` make the side-effect-free / no-runtime-fetch / no-`Any` properties build-time enforced.

### Negative

- **Eight new third-party dependencies** (`jsonschema`, `lxml`, `defusedxml`, `ruamel.yaml`, `packageurl-python`, `license-expression`, `spdx-tools`, `cyclonedx-python-lib`). `lxml` carries native code (libxml2 / libxslt); the existing CI / Docker images need to install `libxml2-dev`. We accept this cost — there is no pure-Python XML schema validator with comparable safety guarantees.
- **Storage migration is not retroactive.** Existing SBOMs with subtly malformed data will appear valid until next analyse. Mitigation: the optional `audit_existing` CLI in §9.
- **Multipart upload is a new endpoint.** Frontend has to be updated to use it; existing JSON-string callers still work but get `Deprecation: …` headers.
- **Spec drift requires a PR per new version.** Adding CycloneDX 1.7 = vendored schema PR + version-table PR + (if shape changed) a new `semantic_cyclonedx_1_7.py`. We accept this — auto-fetching schemas from upstream during runtime is a class-A supply-chain risk and is forbidden by §4.1.
- **First-run cold start is heavier**. Loading + parsing 6 JSON Schemas + 3 XSDs at lifespan startup adds ~150–250 ms (estimated). Negligible against pod startup time, but worth noting.

### Deferred (future ADRs)

- **SPDX RDF/XML and CycloneDX Protobuf** — both deferred from v1 with explicit `SBOM_VAL_E013_SPEC_VERSION_UNSUPPORTED` rejection so the contract is stable. Adding them is two more `detect.py` fingerprints + one more parser each.
- **Per-tenant strict-NTIA default** — in v1 NTIA strict is a per-request `?strict=true` flag. Per-tenant default is additive: a Settings flag that picks the default when the request omits the param.
- **Signature verification rollout** — stage 8 lands behind `SBOM_SIGNATURE_VERIFICATION=false`. A separate ADR will cover the JSF library choice and the SPDX external-sig sidecar key-management story.
- **Audit CLI for existing rows** — Phase 3 adds `app/validation/audit_existing.py` and a `sbom_validation_audit` table. The migration path for the audit table itself is out of scope here.
- **Async hand-off cut-over (5 MB threshold)** — the 5 MB number is a guess. Phase 4 perf tests pin it; a follow-up ADR can revise once production p95 data is in.

## Phase 3 preview

Phase 3 implements the design above. Key files to land:

1. [app/validation/errors.py](../../app/validation/errors.py) — codes, severity, ErrorReport, status mapping.
2. [app/validation/pipeline.py](../../app/validation/pipeline.py) — orchestrator + Stage protocol.
3. [app/validation/stages/](../../app/validation/stages/) — eight modules.
4. [app/validation/schemas/](../../app/validation/schemas/) — vendored schemas + SOURCE.md.
5. New `POST /api/sboms/upload` route in [app/routers/sboms_crud.py](../../app/routers/sboms_crud.py) (or a new `app/routers/sbom_upload.py` if cleaner).
6. Settings additions: `MAX_UPLOAD_BYTES`, `MAX_DECOMPRESSED_BYTES`, `SBOM_SYNC_VALIDATION_BYTES`, `SBOM_SIGNATURE_VERIFICATION`.
7. Updated `pyproject.toml` / `requirements.txt`.
8. Updated `[tool.importlinter]` contracts.

`tests/validation/` is Phase 4 (corpus + property-based + security + perf).
