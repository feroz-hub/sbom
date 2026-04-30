# SBOM Validation Audit — Phase 1

**Status:** read-only audit
**Scope:** every code path between HTTP ingress and the moment a parsed SBOM is handed to the vulnerability scanner.
**Authoritative source for §3 plan:** the audit findings here drive the Phase 2 ADR.

---

## 1. Executive summary

The current SBOM ingest is **best-effort parsing, not validation**. There is no JSON Schema check, no XSD check, no semantic check, no cross-reference check, no NTIA check, no signature check. There is one structural shield (a 20 MB body-size cap) and one defensive coercion (`norm()`), and that is the entire defensive surface. Three of the eight target stages (§3 of the prompt) are completely absent; four more are stubbed at trace levels; only stage 1 (ingress guard) is partially present.

Two findings are **P0 / security-critical** and require an immediate fix even before the larger refactor:

* **`xml.etree.ElementTree` is invoked on untrusted SBOM bytes** as the fallback CycloneDX-XML parser ([app/parsing/cyclonedx.py:79](../app/parsing/cyclonedx.py#L79)). Stdlib `xml.etree` is XXE/entity-bomb vulnerable and is explicitly forbidden by §4.1.
* **`xmltodict.parse` runs with default expat settings** (no `defusedxml`, no entity / DTD blocks) and `xmltodict` is not pinned in `requirements.txt` / `pyproject.toml` — the XML branch silently degrades to the `xml.etree` fallback in any environment that did not transitively install it.

The remaining gaps are **P1 / correctness**: no schema validation, no semantic validation, no cross-reference resolution, silent coercion via `norm()` instead of typed rejection, and bare `ValueError` strings instead of structured error codes.

---

## 2. Current code path (HTTP ingress → scanner)

The application has **no multipart `UploadFile` endpoint**. SBOMs arrive as a JSON string field on the `SBOMSourceCreate` body (`sbom_data: str | None`) or are loaded by id/name from the database for analysis. There are five entry points that re-parse stored SBOM bytes — they all converge on `extract_components`.

| # | Layer                          | Module / function                                                                                                                | Responsibility                                                                                  |
|---|--------------------------------|----------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|
| 1 | ASGI middleware                | [app/middleware/max_body.py](../app/middleware/max_body.py) — `MaxBodySizeMiddleware`                                            | Rejects bodies > `Settings.MAX_UPLOAD_BYTES` (currently **20 MB**). Honest + chunked guards.    |
| 2 | Body-size config               | [app/settings.py:215](../app/settings.py#L215) — `Settings.MAX_UPLOAD_BYTES = 20 * 1024 * 1024`                                  | Configures the cap. **Not** the 50 MB target in §3.1.                                           |
| 3 | Auth dependency                | [app/main.py:256-278](../app/main.py#L256-L278) — `_protected = [Depends(require_auth)]`                                         | Bearer-token / JWT (currently no-op in dev). Runs before route handler.                         |
| 4 | Pydantic ingress               | [app/schemas.py:52-59](../app/schemas.py#L52-L59) — `SBOMSourceCreate`                                                           | `sbom_data: str \| None`. **No format check, no length cap on the field, no UTF-8 assertion.**  |
| 5 | Create route                   | [app/routers/sboms_crud.py:325-398](../app/routers/sboms_crud.py#L325-L398) — `create_sbom`                                      | DB insert → `sync_sbom_components` → `extract_components`. Wraps everything in `Exception` log. |
| 6 | Coercion                       | [app/routers/sboms_crud.py:86-95](../app/routers/sboms_crud.py#L86-L95) — `_coerce_sbom_data`                                    | If client posted a dict/list, JSON-dumps it back to text. **No structure check.**               |
| 7 | Components sync                | [app/routers/sboms_crud.py:180-185](../app/routers/sboms_crud.py#L180-L185) — `sync_sbom_components`                             | Calls `extract_components(sbom_obj.sbom_data)` and upserts components.                          |
| 8 | Format detection               | [app/parsing/format.py:12-35](../app/parsing/format.py#L12-L35) — `detect_sbom_format`                                           | Heuristic dict-key probe: `bomFormat` / `components` / `spdxVersion` / `packages`.              |
| 9 | Top-level extractor            | [app/parsing/extract.py:12-57](../app/parsing/extract.py#L12-L57) — `extract_components`                                         | Strips BOM/zero-width chars, branches on `{`, `[`, `<`, falls back to `json.loads`.             |
| 10 | CycloneDX JSON parser          | [app/parsing/cyclonedx.py:14-32](../app/parsing/cyclonedx.py#L14-L32) — `parse_cyclonedx_dict`                                   | Walks `components[]`. **No schema check, no semantic check, no `bom-ref` uniqueness.**          |
| 11 | CycloneDX XML parser           | [app/parsing/cyclonedx.py:35-112](../app/parsing/cyclonedx.py#L35-L112) — `parse_cyclonedx_xml`                                  | `xmltodict.parse` if available, else **`xml.etree.ElementTree.fromstring`** (XXE-vulnerable).   |
| 12 | SPDX JSON parser               | [app/parsing/spdx.py:14-67](../app/parsing/spdx.py#L14-L67) — `parse_spdx_dict`                                                  | Walks `packages[]` and `elements[]`. No spec-version branching, no semantic check.              |
| 13 | SPDX XML parser                | [app/parsing/spdx.py:70-75](../app/parsing/spdx.py#L70-L75) — `parse_spdx_xml`                                                   | `xmltodict` only; **silently returns `[]` if xmltodict is not installed.**                      |
| 14 | XML-support flag               | [app/parsing/xml_support.py](../app/parsing/xml_support.py) — `XMLTODICT_AVAILABLE`                                              | Optional-import flag. xmltodict is **not pinned** in any requirements file.                     |
| 15 | Field normalisation            | [app/parsing/common.py:6-7](../app/parsing/common.py#L6-L7) — `norm`                                                             | `s.strip() if isinstance(s, str) and s.strip() else None`. **Silently drops any non-string.**   |
| 16 | Service-layer load             | [app/services/sbom_service.py:255-318](../app/services/sbom_service.py#L255-L318) — `load_sbom_from_ref`                         | Re-parses the stored string via `json.loads` then re-runs `extract_components`.                 |
| 17 | Analysis trigger (REST)        | [app/routers/sboms_crud.py:606-636](../app/routers/sboms_crud.py#L606-L636) — `run_analysis_for_sbom`                            | Re-extracts components, fans out to scanner adapters, persists `AnalysisRun`.                   |
| 18 | Analysis trigger (SSE stream)  | [app/routers/sboms_crud.py:639-873](../app/routers/sboms_crud.py#L639-L873) — `analyze_sbom_stream`                              | Re-extracts components, broadcasts SSE progress, persists run.                                  |
| 19 | Legacy single-source endpoints | [app/routers/analyze_endpoints.py:99-256](../app/routers/analyze_endpoints.py#L99-L256) — `_run_legacy_analysis`                 | Loads via `load_sbom_from_ref` → re-extracts → fans out to NVD/GHSA/OSV/VulDB.                  |
| 20 | Unhandled-error handler        | [app/error_handlers.py:28-49](../app/error_handlers.py#L28-L49) — `install`                                                      | Maps any uncaught `Exception` to a canonical 500. **All validation failures land here today.**  |

### 2.1 What each step actually does

| Step | Validates                              | Rejects                                    | Silently coerces                                  | Error shape                                                | Spec-compliant?                                       |
|------|----------------------------------------|--------------------------------------------|---------------------------------------------------|------------------------------------------------------------|-------------------------------------------------------|
| 1    | Body length                            | `Content-Length > 20MB`, streamed > 20 MB  | —                                                 | `{"detail":{"code":"payload_too_large","message":...}}`    | n/a (transport)                                       |
| 4    | `sbom_data: str \| None` (Pydantic)    | non-string, non-null types                 | —                                                 | FastAPI 422 envelope                                       | n/a (only types `str`)                                |
| 6    | —                                      | —                                          | dict/list → `json.dumps`                          | —                                                          | non-compliant: round-trips arbitrary input            |
| 8    | Top-level keys present                 | document with no recognisable keys         | `version` substituted for `specVersion`           | bare `ValueError("Unable to detect SBOM format…")`         | **No version-specific branching**                     |
| 9    | Bytes look like JSON or XML            | non-string, non-dict input                 | strips BOM + zero-width chars                     | bare `ValueError("Unsupported SBOM format…")`              | partial — no encoding assertion, no JSON depth cap    |
| 10   | `components[]` is iterable             | nothing — every field is `norm`-ed         | non-string fields → `None`                        | —                                                          | **No schema check, no PURL/CPE/`bom-ref` validation** |
| 11   | XML well-formedness only               | malformed XML                              | unknown elements                                  | bare `ValueError("Invalid XML SBOM: …")`                   | **XXE-vulnerable, no XSD check**                      |
| 12   | `packages[]` / `elements[]` iterable   | nothing                                    | non-string fields → `None`                        | —                                                          | **No SPDXID format, no relationships, no licenses**   |
| 13   | xmltodict-availability                 | nothing — returns `[]` instead             | XML format mismatch                               | —                                                          | **Silent failure: empty SBOM looks valid**            |
| 16   | JSON parseable + storage column type   | malformed stored JSON                      | unknown `sbom_data` types                         | bare `ValueError("Invalid SBOM JSON in storage: …")`       | partial                                               |
| 20   | —                                      | —                                          | every uncaught error → generic 500                | `{"detail":{"code":"internal_error","correlation_id":…}}`  | violates §2.4 ("never 500 from validation")           |

Net effect: **a malformed-but-parseable SBOM never produces a 4xx**. It either parses to a thin component list (which then yields false-negative scans) or it triggers an `Exception` that is mapped to a generic 500.

---

## 3. Validation coverage matrix

Rows: SBOM format / spec version. Columns: the eight target validation stages from §3.1 of the prompt.

Legend: ✅ full · ⚠ partial · ❌ missing · N/A.

| Format / version             | 1. Ingress guard | 2. Format & version | 3. Structural schema | 4. Semantic validation | 5. Cross-ref integrity | 6. Security checks       | 7. NTIA minimum elements | 8. Signature |
|------------------------------|------------------|---------------------|----------------------|------------------------|------------------------|--------------------------|--------------------------|--------------|
| SPDX 2.2 JSON                | ⚠ partial        | ⚠ partial           | ❌ missing            | ⚠ partial (name/ver only) | ❌ missing             | ⚠ partial (size only)    | ❌ missing                | ❌ missing    |
| SPDX 2.3 JSON                | ⚠ partial        | ⚠ partial           | ❌ missing            | ⚠ partial                 | ❌ missing             | ⚠ partial (size only)    | ❌ missing                | ❌ missing    |
| SPDX 2.3 Tag-Value           | ⚠ partial        | ❌ missing           | ❌ missing            | ❌ missing                | ❌ missing             | ❌ missing                | ❌ missing                | ❌ missing    |
| SPDX 3.0 JSON                | ⚠ partial        | ❌ missing           | ❌ missing            | ❌ missing                | ❌ missing             | ⚠ partial (size only)    | ❌ missing                | ❌ missing    |
| CycloneDX 1.4 JSON           | ⚠ partial        | ⚠ partial           | ❌ missing            | ⚠ partial                 | ❌ missing             | ⚠ partial (size only)    | ❌ missing                | ❌ missing    |
| CycloneDX 1.4 XML            | ⚠ partial        | ⚠ partial           | ❌ missing            | ⚠ partial                 | ❌ missing             | ❌ missing (XXE)         | ❌ missing                | ❌ missing    |
| CycloneDX 1.5 JSON           | ⚠ partial        | ⚠ partial           | ❌ missing            | ⚠ partial                 | ❌ missing             | ⚠ partial (size only)    | ❌ missing                | ❌ missing    |
| CycloneDX 1.5 XML            | ⚠ partial        | ⚠ partial           | ❌ missing            | ⚠ partial                 | ❌ missing             | ❌ missing (XXE)         | ❌ missing                | ❌ missing    |
| CycloneDX 1.6 JSON           | ⚠ partial        | ⚠ partial           | ❌ missing            | ⚠ partial                 | ❌ missing             | ⚠ partial (size only)    | ❌ missing                | ❌ missing    |
| CycloneDX 1.6 XML            | ⚠ partial        | ⚠ partial           | ❌ missing            | ⚠ partial                 | ❌ missing             | ❌ missing (XXE)         | ❌ missing                | ❌ missing    |

Notes:

* **Stage 1 — ingress guard:** body cap exists (20 MB, below the 50 MB target); no decompression-bomb guard, no UTF-8 enforcement at the JSON-string field path, no magic-byte / BOM stripping at the ingress layer (BOM stripping happens in `extract_components`, after the data has already been stored).
* **Stage 2 — format & version detection:** version string is captured but never used to branch parsers; SPDX 3.0 (`@graph` / `elements` top-level) is not recognised; SPDX Tag-Value is rejected because `extract_components` only branches on `{`, `[`, `<`.
* **Stage 3 — structural schema:** there is no `app/validation/schemas/` tree and no `jsonschema`, `lxml`, or XSD code path anywhere in `app/`.
* **Stage 4 — semantic validation:** the parsers extract `name`, `version`, `purl`, `cpe`, `bom_ref`, `supplier`, `scope`, `type`, `group`. No further checks. PURL and CPE are passed through as opaque strings; `bom-ref` uniqueness is not asserted.
* **Stage 5 — cross-ref integrity:** SPDX `relationships[]`, CycloneDX `dependencies[]`, and `externalDocumentRefs` are all ignored.
* **Stage 6 — security:** the JSON depth, array length, and string length are uncapped. The XML path is **XXE-vulnerable** (`xml.etree` fallback; default-config `xmltodict`). No prototype-pollution defence on JSON keys.
* **Stage 7 — NTIA:** not implemented.
* **Stage 8 — signature:** not implemented; no JSF / external-sig support.

---

## 4. P0 gaps (security-critical — fix before refactor lands in main)

| ID  | Gap                                                                        | Evidence                                                                                                          | Why it's P0                                                                                                                  |
|-----|----------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| P0-1 | `xml.etree.ElementTree.fromstring` on untrusted SBOM bytes                | [app/parsing/cyclonedx.py:79-85](../app/parsing/cyclonedx.py#L79-L85)                                              | Stdlib `xml.etree` is XXE / billion-laughs / external-entity vulnerable. Forbidden by §4.1.                                  |
| P0-2 | `xmltodict.parse` with default expat settings                              | [app/parsing/cyclonedx.py:38](../app/parsing/cyclonedx.py#L38) and [app/parsing/spdx.py:73](../app/parsing/spdx.py#L73) | `xmltodict` does not block DTDs / external entities by default. Adversarial XML can read host files or hang the worker.    |
| P0-3 | `xmltodict` is not pinned                                                  | absent from [requirements.txt](../requirements.txt) and [pyproject.toml](../pyproject.toml)                       | Production environments without xmltodict silently fall through to P0-1.                                                     |
| P0-4 | No JSON depth / array-length / string-length caps                          | [app/parsing/extract.py:31](../app/parsing/extract.py#L31), [app/services/sbom_service.py:85](../app/services/sbom_service.py#L85), [app/services/sbom_service.py:303](../app/services/sbom_service.py#L303) | A nested-dict bomb under 20 MB can stack-overflow `json.loads` or balloon memory.                                            |
| P0-5 | Silent failure when xmltodict is absent                                    | [app/parsing/spdx.py:75](../app/parsing/spdx.py#L75) returns `[]`                                                  | A valid SPDX-XML SBOM looks like an empty SBOM — every CVE in it becomes a false negative.                                   |
| P0-6 | All validation failures map to **HTTP 500**                                | [app/error_handlers.py:30-49](../app/error_handlers.py#L30-L49); inside `_run_legacy_analysis`, `create_auto_report`, `analyze_sbom_stream` everything in a broad `except Exception` | Violates §2.4 ("never 500 from the validation layer is a bug") and prevents callers from differentiating bad input.          |
| P0-7 | Body cap is 20 MB, not 50 MB; no decompressed cap                          | [app/settings.py:215](../app/settings.py#L215)                                                                     | A `gzip` content-encoding wrapper or a future zip upload would bypass the cap entirely.                                       |
| P0-8 | Missing `defusedxml` everywhere                                            | not imported in any `app/` module                                                                                  | The fix for P0-1/P0-2 needs `defusedxml` plus `lxml` + XSD for stage 3 — the dep is absent today.                            |

---

## 5. P1 gaps (correctness — fix as part of the refactor)

| ID   | Gap                                                                                  | Evidence                                                                  |
|------|--------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| P1-1 | No JSON Schema validation for any spec / version                                     | no `jsonschema` import; no `app/validation/schemas/` tree                 |
| P1-2 | No XSD validation for any CycloneDX XML version                                      | no `lxml`, no XSD files                                                   |
| P1-3 | SPDX 3.0 documents misclassified                                                     | [app/parsing/format.py:29](../app/parsing/format.py#L29) keys on `spdxVersion`/`packages` only |
| P1-4 | SPDX Tag-Value not parsed                                                            | [app/parsing/extract.py:43-49](../app/parsing/extract.py#L43-L49) only branches on `<` and `{`/`[` |
| P1-5 | Format-version captured but parsers never branch on it                               | `spec_version` never threaded into `parse_cyclonedx_dict` / `parse_spdx_dict` |
| P1-6 | `SPDXID` format never enforced (`SPDXRef-…`)                                         | `parse_spdx_dict` reads SPDXID raw                                        |
| P1-7 | `documentNamespace` URI never validated                                              | not referenced in any parser                                              |
| P1-8 | `dataLicense == CC0-1.0` not enforced                                                | not referenced                                                            |
| P1-9 | License-expression syntax not validated                                              | `license-expression` lib absent                                           |
| P1-10 | Checksum algorithm ↔ digest length consistency not validated                        | not referenced                                                            |
| P1-11 | `created` / `metadata.timestamp` ISO-8601 conformance not validated                 | not referenced                                                            |
| P1-12 | At least one `DESCRIBES` relationship not asserted                                  | relationships ignored entirely                                            |
| P1-13 | CycloneDX `serialNumber` URN-UUID format not validated                              | not referenced                                                            |
| P1-14 | `bom-ref` uniqueness not enforced                                                   | `parse_cyclonedx_dict` collects `bom_ref` blind                           |
| P1-15 | PURL not parsed via `packageurl-python`                                             | dep absent                                                                |
| P1-16 | CPE 2.3 syntax not validated                                                        | dep absent                                                                |
| P1-17 | Hash `alg`↔`content` length not validated                                           | not referenced                                                            |
| P1-18 | Cross-ref: `dependencies[].ref`/`dependsOn[]` not resolved against declared `bom-ref` | not referenced                                                          |
| P1-19 | SPDX `relationships` not resolved against `SPDXRef-` declarations                   | not referenced                                                            |
| P1-20 | Dependency cycles never detected                                                    | not referenced                                                            |
| P1-21 | NTIA minimum-element check absent                                                   | not implemented                                                           |
| P1-22 | Signature validation absent (JSF / external sig)                                    | not implemented                                                           |
| P1-23 | Silent coercion of non-string fields to `None` via `norm()`                         | [app/parsing/common.py:6-7](../app/parsing/common.py#L6-L7) — a `version: 1.2` int silently disappears |
| P1-24 | Heuristic format detection misclassifies docs containing both `components` and SPDX keys | [app/parsing/format.py:22-30](../app/parsing/format.py#L22-L30) — first-match wins |
| P1-25 | `parse_cyclonedx_dict` accepts `components: <non-list>` without checking          | [app/parsing/cyclonedx.py:16](../app/parsing/cyclonedx.py#L16) — `for c in doc.get("components", []) or []` then `c.get(...)` blows up if `c` is a primitive |
| P1-26 | Bare `ValueError("…")` instead of structured `{code, severity, stage, path, …}`    | every `raise` site in `parsing/`                                          |
| P1-27 | Validation runs once at create and again at every analyse → N validators per SBOM | `sync_sbom_components` (create) + `_run_legacy_analysis` (each scan) both call `extract_components` |

---

## 6. Third-party dependencies in (or adjacent to) the validation path

| Package                  | Status in validator             | Pinned?                                        | Risk?                                                                                         |
|--------------------------|---------------------------------|------------------------------------------------|-----------------------------------------------------------------------------------------------|
| `json` (stdlib)          | used directly                   | n/a                                            | ⚠ no depth / array / string caps; vulnerable to nesting bombs                                  |
| `xml.etree.ElementTree`  | **fallback** for CycloneDX XML  | n/a (stdlib)                                   | **❌ unsafe — XXE / billion-laughs**; explicitly forbidden by §4.1                              |
| `xmltodict`              | optional path for both XML branches | **not pinned** — absent from `requirements.txt` & `pyproject.toml`; transitive only        | ❌ default `expat` config; no DTD/entity blocks                                                |
| `defusedxml`             | not imported                    | not in deps                                    | required by §4.1; missing                                                                      |
| `lxml`                   | not imported                    | not in deps                                    | required for XSD validation in stage 3; missing                                                |
| `jsonschema`             | not imported                    | not in deps                                    | required for stage 3 JSON path; missing                                                        |
| `ruamel.yaml`            | not imported                    | not in deps                                    | required for SPDX YAML / future YAML SBOMs; missing                                            |
| `PyYAML 6.0.3`           | installed transitively, **not used** by `app/`                | transitively pulled in                  | low — but if any future code imports it without `safe_load`, it would be unsafe                |
| `packageurl-python`      | not imported                    | not in deps                                    | required for stage 4 PURL semantic check; missing                                              |
| `license-expression`     | not imported                    | not in deps                                    | required for stage 4 SPDX licence parse; missing                                               |
| `spdx-tools` (Linux Foundation) | not imported            | not in deps                                    | required for SPDX Tag-Value parse; missing                                                     |
| `cyclonedx-python-lib`   | not imported                    | not in deps                                    | not strictly required (we own normalisation), but a useful cross-check oracle in tests         |
| `pickle`                 | not imported in `app/parsing` (✅) | n/a                                          | none observed                                                                                  |
| `eval` / `exec`          | not used in `app/parsing` (✅)  | n/a                                            | none observed                                                                                  |
| `requests` / `httpx`     | not called during validation (✅) | pinned in `requirements.txt`                 | none observed (live-fetch of schemas is not done — but only because schemas don't exist yet)   |

Cross-checked with:

```
$ grep -rn "yaml\|xml.etree\|defusedxml\|jsonschema\|xmltodict\|ruamel" app/
app/parsing/cyclonedx.py:11:    import xmltodict  # type: ignore[import-untyped]
app/parsing/cyclonedx.py:36: """Parse CycloneDX XML SBOM using xmltodict or xml.etree fallback."""
app/parsing/cyclonedx.py:38: doc = xmltodict.parse(xml_string)
app/parsing/cyclonedx.py:79: import xml.etree.ElementTree as ET
app/parsing/spdx.py:11:     import xmltodict  # type: ignore[import-untyped]
app/parsing/spdx.py:73:     doc = xmltodict.parse(xml_string)
app/parsing/xml_support.py:1:  """Optional xmltodict for CycloneDX/SPDX XML SBOM parsing."""
```

```
$ .venv/bin/pip list | grep -iE "yaml|xml|defusedxml|jsonschema|spdx|cyclonedx|packageurl|license-expression|ruamel"
PyYAML             6.0.3
```

---

## 7. Phase 2 preview

Phase 2 will produce three artefacts, all driven by the gaps above:

1. **`docs/adr/0007-sbom-validation-architecture.md`** — the eight-stage layered pipeline (§3.2 of the prompt), vendored-schema strategy (`app/validation/schemas/{spdx,cyclonedx}/<version>/`), error-aggregation contract, and the ingress / async hand-off rules. Closes P0-1/2/3/4/5/8 by design and every P1 by structure.
2. **`docs/validation-pipeline.mmd`** — Mermaid sequence diagram from `POST /api/sboms` (or future multipart `/api/sboms/upload`) through stages 1–8 and into the Celery scan enqueue path, with the four explicit short-circuit exits (400 / 413 / 415 / 422).
3. **`docs/validation-error-codes.md`** — the full `SBOM_VAL_E*` code table (HTTP status, severity, stage, example payload, remediation, spec ref).

Open questions to resolve in Phase 2 design (not Phase 1 audit):

* Whether to keep the JSON-string `sbom_data` column or move uploads to a dedicated `POST /api/sboms/upload` multipart endpoint that streams to S3 and validates from a temp file. Recommendation: add multipart, leave the JSON-string field for backward compat but funnel both through the same pipeline.
* Whether NTIA strict mode is a per-tenant flag or a per-request `?strict=true` query param. Prompt §3.2 stage 7 specifies the latter; will confirm in the ADR.
* Whether SPDX 3.0 support ships in v1 of the validator or is feature-flagged. SPDX 3.0 has a different top-level shape (`@graph`/`elements`) and warrants its own `semantic_spdx3.py` next to `semantic_spdx.py`.

---

## Phase 1 deliverable status

* [x] Code-path map (§2)
* [x] Per-step validate / reject / coerce / error-shape / spec-compliance table (§2.1)
* [x] Validation Coverage Matrix (§3)
* [x] P0 gap list (§4)
* [x] P1 gap list (§5)
* [x] Third-party dependency review (§6)

**Stop point.** Awaiting `continue` before starting Phase 2 (design / ADR).
