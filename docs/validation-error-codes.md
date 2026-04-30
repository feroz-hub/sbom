# SBOM validation — error code reference

This document is the **authoritative source** for every error / warning / info code emitted by the validation pipeline. The descriptive tables (message templates, remediation copy, spec references) are hand-maintained; the **machine table** at the end is auto-generated from [app/validation/errors.py](../app/validation/errors.py) by [`scripts/gen_error_code_reference.py`](../scripts/gen_error_code_reference.py) and asserted in CI via `python scripts/gen_error_code_reference.py --check`.

## Conventions

- **Code shape:** `SBOM_VAL_<sev><nnn>_<NAME>` where `<sev>` is `E` (error), `W` (warning), or `I` (info), `<nnn>` is a stage-banded number, and `<NAME>` is `SCREAMING_SNAKE_CASE`.
- **Stage banding:** `001-009` ingress · `010-019` format · `020-039` schema · `040-069` semantic · `070-079` cross-ref · `080-099` security · `100-109` NTIA · `110-119` signature.
- **HTTP status precedence (when many codes fire):** `413 > 415 > 422 > 400`. The orchestrator picks the highest-priority status across all error-severity entries.
- **Severity:** `error` blocks acceptance; `warning` and `info` flow through to the response body and never block.
- **Path:** JSONPath-style locator into the original document (`components[17].purl`, `relationships[3].relatedSpdxElement`, etc.).
- **Spec reference:** stable cite into the SPDX or CycloneDX spec when applicable.
- **Example payload:** the JSON shape returned for a single error entry. The full response is `{"detail": {"entries": [...], "truncated": false}}`.

```json
{
  "code": "SBOM_VAL_E042_DATA_LICENSE_INVALID",
  "severity": "error",
  "stage": "semantic",
  "path": "dataLicense",
  "message": "SPDX dataLicense must be exactly 'CC0-1.0', got 'Apache-2.0'.",
  "remediation": "Set dataLicense to 'CC0-1.0'. The dataLicense field documents the licence of the SBOM document itself, not of the components.",
  "spec_reference": "SPDX 2.3 §6.2"
}
```

---

## Stage 1 — Ingress guard (E001–E009)

| Code | HTTP | Severity | Message template | Remediation | Spec ref |
|---|---|---|---|---|---|
| `SBOM_VAL_E001_SIZE_EXCEEDED` | 413 | error | Uploaded body of {bytes} bytes exceeds MAX_UPLOAD_BYTES ({limit}). | Compress the SBOM or split into a multi-part upload. Async path engages above {sync_limit} bytes. | — |
| `SBOM_VAL_E002_DECOMPRESSED_SIZE_EXCEEDED` | 413 | error | Decompressed body of {bytes} bytes exceeds MAX_DECOMPRESSED_BYTES ({limit}). | Verify that the SBOM is not a decompression bomb. Real SBOMs decompress to < 200 MB. | — |
| `SBOM_VAL_E003_DECOMPRESSION_RATIO_EXCEEDED` | 413 | error | Decompression ratio {ratio}:1 exceeds 100:1 limit. | The compressed payload expanded too aggressively to be a legitimate SBOM. | — |
| `SBOM_VAL_E004_ENCODING_NOT_UTF8` | 400 | error | Body is not valid UTF-8 (or contains a forbidden BOM at offset {offset}). | Re-encode the SBOM as UTF-8. UTF-16 / UTF-32 BOMs are not accepted. | — |
| `SBOM_VAL_E005_EMPTY_BODY` | 400 | error | Request body is empty. | Provide a non-empty SBOM document. | — |
| `SBOM_VAL_E006_UNSUPPORTED_COMPRESSION` | 415 | error | Content-Encoding '{encoding}' is not supported. | Use identity, gzip, or deflate. Brotli / zstd are not yet supported by the validator. | — |

## Stage 2 — Format & version detection (E010–E019)

| Code | HTTP | Severity | Message template | Remediation | Spec ref |
|---|---|---|---|---|---|
| `SBOM_VAL_E010_FORMAT_INDETERMINATE` | 415 | error | Unable to detect SBOM format. No SPDX or CycloneDX fingerprint matched. | The document must be SPDX (2.2 / 2.3 / 3.0 JSON, 2.3 Tag-Value) or CycloneDX (1.4 / 1.5 / 1.6 JSON or XML). | — |
| `SBOM_VAL_E011_FORMAT_AMBIGUOUS` | 415 | error | Document matches both SPDX and CycloneDX fingerprints. | The document mixes SPDX and CycloneDX fields. Pick one format and re-emit. The validator never guesses. | — |
| `SBOM_VAL_E012_ENCODING_INDETERMINATE` | 415 | error | Document encoding is neither JSON, XML, YAML, nor SPDX Tag-Value. | Confirm the document is one of the supported encodings. | — |
| `SBOM_VAL_E013_SPEC_VERSION_UNSUPPORTED` | 415 | error | Spec version '{version}' for {format} is not supported. | Supported: SPDX 2.2 / 2.3 / 3.0; CycloneDX 1.4 / 1.5 / 1.6. SPDX RDF/XML and CycloneDX Protobuf are deferred. | — |
| `SBOM_VAL_E014_SPEC_VERSION_MISSING` | 422 | error | Document is missing the spec-version field ({field}). | Add 'spdxVersion' (SPDX) or 'specVersion' (CycloneDX) at the top level. | SPDX 2.3 §6.1 / CycloneDX 1.6 §3 |
| `SBOM_VAL_E015_SPEC_VERSION_MALFORMED` | 422 | error | Spec-version field has unparseable value '{value}'. | Use the canonical form: 'SPDX-2.3' or '1.6'. | — |

## Stage 3 — Structural schema (E020–E039)

| Code | HTTP | Severity | Message template | Remediation | Spec ref |
|---|---|---|---|---|---|
| `SBOM_VAL_E020_JSON_PARSE_FAILED` | 400 | error | JSON parser failed at line {line}, column {col}: {reason}. | Validate the document with a JSON linter before upload. | — |
| `SBOM_VAL_E021_XML_PARSE_FAILED` | 400 | error | XML parser failed at line {line}, column {col}: {reason}. | Validate the document with an XML linter (xmllint) before upload. | — |
| `SBOM_VAL_E022_YAML_PARSE_FAILED` | 400 | error | YAML parser failed: {reason}. | Validate the document with a YAML linter before upload. | — |
| `SBOM_VAL_E023_TAGVALUE_PARSE_FAILED` | 400 | error | SPDX Tag-Value parser failed at line {line}: {reason}. | Each non-comment line must be `Tag: value`. | SPDX 2.3 §3 |
| `SBOM_VAL_E024_PROTOBUF_PARSE_FAILED` | 400 | error | Protobuf decoder failed: {reason}. | (Deferred; see E013.) | — |
| `SBOM_VAL_E025_SCHEMA_VIOLATION` | 422 | error | Schema violation at {path}: {reason}. | Compare against the relevant spec section. | (varies) |
| `SBOM_VAL_E026_SCHEMA_REQUIRED_FIELD_MISSING` | 422 | error | Required field '{field}' is missing at {path}. | Add the field per the spec. | (varies) |
| `SBOM_VAL_E027_SCHEMA_TYPE_MISMATCH` | 422 | error | Field '{field}' expected type {expected}, got {actual} at {path}. | The validator never coerces types — re-emit with the correct type. | (varies) |
| `SBOM_VAL_E028_SCHEMA_ENUM_VIOLATION` | 422 | error | Field '{field}'='{value}' is not in the allowed set {allowed} at {path}. | Use one of the allowed values. | (varies) |
| `SBOM_VAL_E029_SCHEMA_FORMAT_VIOLATION` | 422 | error | Field '{field}'='{value}' violates format '{format}' at {path}. | Conform to the documented format (date-time, uri, uuid, …). | (varies) |

## Stage 4 — Semantic validation, SPDX (E040–E049)

| Code | HTTP | Severity | Message template | Remediation | Spec ref |
|---|---|---|---|---|---|
| `SBOM_VAL_E040_SPDXID_MALFORMED` | 422 | error | SPDXID '{value}' at {path} does not match `^SPDXRef-[a-zA-Z0-9.\-]+$`. | Rename the SPDXID to start with `SPDXRef-` and contain only `[a-zA-Z0-9.-]`. | SPDX 2.3 §3.2 |
| `SBOM_VAL_E041_DOCUMENT_NAMESPACE_INVALID` | 422 | error | documentNamespace '{value}' is not an absolute URI without a fragment. | Provide an absolute URI with no `#` segment, e.g. `https://example.com/sboms/{uuid}`. | SPDX 2.3 §6.5 |
| `SBOM_VAL_E042_DATA_LICENSE_INVALID` | 422 | error | dataLicense must be exactly 'CC0-1.0', got '{value}'. | Set dataLicense to 'CC0-1.0' — this is the licence of the SBOM document itself, not the components. | SPDX 2.3 §6.2 |
| `SBOM_VAL_E043_LICENSE_EXPRESSION_INVALID` | 422 | error | License expression '{value}' at {path} is unparseable: {reason}. | Use a valid SPDX licence expression. See https://spdx.dev/learn/handling-license-info/. | SPDX 2.3 Annex D |
| `SBOM_VAL_E044_CHECKSUM_LENGTH_MISMATCH` | 422 | error | Checksum at {path} has algorithm '{alg}' but value length {len} hex chars (expected {expected}). | Recompute the digest with the algorithm declared. | SPDX 2.3 §7.10 |
| `SBOM_VAL_E045_CREATED_TIMESTAMP_INVALID` | 422 | error | created '{value}' is not ISO-8601 UTC ending in 'Z'. | Emit timestamps as `2026-04-30T12:34:56Z`. | SPDX 2.3 §6.9 |
| `SBOM_VAL_E046_DESCRIBES_RELATIONSHIP_MISSING` | 422 | error | No `DESCRIBES` relationship from `SPDXRef-DOCUMENT` was found. | Add a relationship `{ "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "..." }`. | SPDX 2.3 §11 |
| `SBOM_VAL_E047_SPDX_VERSION_FIELD_INCONSISTENT` | 422 | error | spdxVersion '{value}' does not match the schema vendored for that version. | Re-emit with a consistent version, or use a different vendored schema PR. | — |

## Stage 4 — Semantic validation, CycloneDX (E050–E069)

| Code | HTTP | Severity | Message template | Remediation | Spec ref |
|---|---|---|---|---|---|
| `SBOM_VAL_E050_SERIAL_NUMBER_INVALID` | 422 | error | serialNumber '{value}' does not match `^urn:uuid:[0-9a-f-]{36}$`. | Use the form `urn:uuid:{uuid4}`. | CycloneDX 1.6 §3 |
| `SBOM_VAL_E051_BOM_REF_DUPLICATE` | 422 | error | bom-ref '{value}' at {path} is duplicated; first seen at {first_path}. | Every bom-ref must be unique within the document. | CycloneDX 1.6 §4.1 |
| `SBOM_VAL_E052_PURL_INVALID` | 422 | error | PURL '{value}' at {path} is malformed: {reason}. | Use the form `pkg:{type}/{namespace}/{name}@{version}`. See https://github.com/package-url/purl-spec. | CycloneDX 1.6 §4.4.1 |
| `SBOM_VAL_E053_CPE_INVALID` | 422 | error | CPE '{value}' at {path} does not parse as CPE 2.3. | Use the CPE 2.3 form: `cpe:2.3:{part}:{vendor}:{product}:{version}:...`. | CycloneDX 1.6 §4.4.1 |
| `SBOM_VAL_E054_HASH_LENGTH_MISMATCH` | 422 | error | Hash at {path} has alg '{alg}' but content length {len} hex chars (expected {expected}). | Recompute the digest with the algorithm declared. | CycloneDX 1.6 §4.4.5 |
| `SBOM_VAL_E055_BOM_VERSION_INVALID` | 422 | error | Top-level 'version' must be a non-negative integer (BOM revision), got '{value}'. | This is the BOM revision, not a component version. Set to an integer ≥ 0. | CycloneDX 1.6 §3 |
| `SBOM_VAL_E056_METADATA_TIMESTAMP_INVALID` | 422 | error | metadata.timestamp '{value}' is not ISO-8601. | Emit timestamps as `2026-04-30T12:34:56Z`. | CycloneDX 1.6 §3.3 |
| `SBOM_VAL_E057_COMPONENT_TYPE_INVALID` | 422 | error | components[{i}].type '{value}' is not in the allowed set. | Allowed: application, framework, library, container, operating-system, device, firmware, file, machine-learning-model, data, cryptographic-asset. | CycloneDX 1.6 §4.4 |

## Stage 5 — Cross-reference integrity (E070–E079)

| Code | HTTP | Severity | Message template | Remediation | Spec ref |
|---|---|---|---|---|---|
| `SBOM_VAL_E070_DEPENDENCY_REF_DANGLING` | 422 | error | dependencies[{i}].ref '{value}' does not match any declared bom-ref. | Either declare a component with that bom-ref, or remove the dependency entry. | CycloneDX 1.6 §6 |
| `SBOM_VAL_E071_DEPENDENCY_REF_SELF` | 422 | error | Dependency entry '{value}' depends on itself. | Self-edges are never legitimate. Remove the entry. | CycloneDX 1.6 §6 |
| `SBOM_VAL_E072_RELATIONSHIP_ELEMENT_DANGLING` | 422 | error | relationships[{i}] references SPDXID '{value}' that is not declared in this document or via DocumentRef-*. | Declare the element, or use a valid DocumentRef-* form. | SPDX 2.3 §11 |
| `SBOM_VAL_E073_EXTERNAL_DOC_REF_INVALID` | 422 | error | externalDocumentRef '{name}' has invalid checksum or URI. | Provide a valid SHA1/SHA256 checksum and an absolute URI. | SPDX 2.3 §6.6 |
| `SBOM_VAL_W074_DEPENDENCY_CYCLE_DETECTED` | — | warning | Dependency cycle detected: {ref_chain}. | Cycles are common in real BOMs and are reported for visibility, not rejected. | — |
| `SBOM_VAL_I075_ORPHAN_COMPONENT` | — | info | Component '{ref}' has no inbound or outbound dependency edges. | Informational. Consider declaring the relationship that brought this component in. | — |

## Stage 6 — Security checks (E080–E099)

| Code | HTTP | Severity | Message template | Remediation | Spec ref |
|---|---|---|---|---|---|
| `SBOM_VAL_E080_JSON_DEPTH_EXCEEDED` | 400 | error | JSON nesting depth exceeds 64 at offset {offset}. | Real SBOMs do not exceed 64 levels. The cap defends against depth bombs. | — |
| `SBOM_VAL_E081_JSON_ARRAY_LENGTH_EXCEEDED` | 400 | error | JSON array at {path} exceeds 1,000,000 entries. | Split the document or remove the offending array. | — |
| `SBOM_VAL_E082_JSON_STRING_LENGTH_EXCEEDED` | 400 | error | JSON string at {path} exceeds 65,536 bytes. | Encoded payloads larger than 64 KB belong in a separate file referenced by URL. | — |
| `SBOM_VAL_E083_XML_DTD_FORBIDDEN` | 400 | error | Document contains a DTD declaration. | DTDs are forbidden — they enable external-entity attacks. Remove the `<!DOCTYPE …>` declaration. | — |
| `SBOM_VAL_E084_XML_EXTERNAL_ENTITY_FORBIDDEN` | 400 | error | Document declares an external entity '{name}'. | External entities are forbidden — they allow file / URL exfiltration. | — |
| `SBOM_VAL_E085_XML_ENTITY_EXPANSION` | 400 | error | XML entity expansion exceeded the safe limit. | Defends against billion-laughs / quadratic-blowup attacks. | — |
| `SBOM_VAL_E086_YAML_UNSAFE_TAG` | 400 | error | YAML document contains unsafe tag '{tag}'. | Use plain YAML scalars. Tags such as `!!python/object` are forbidden. | — |
| `SBOM_VAL_E087_PROTOTYPE_POLLUTION_KEY` | 400 | error | Object key '{key}' at {path} is forbidden. | Forbidden keys: `__proto__`, `constructor`, `prototype`. They enable prototype-pollution attacks against downstream JS consumers. | — |
| `SBOM_VAL_E088_EMBEDDED_BLOB_TOO_LARGE` | 400 | error | Embedded blob at {path} is {bytes} bytes (> 1 MB) and is not a known content field. | Move the blob to a referenced URL, or use one of the standard hash content fields. | — |
| `SBOM_VAL_E089_ZIP_BOMB_RATIO` | 413 | error | Compressed payload expanded to ratio {ratio}:1 (limit 100:1). | The compressed payload expanded too aggressively to be a legitimate SBOM. | — |

## Stage 7 — NTIA minimum elements (W100–W106 default · E100–E106 strict)

When `?strict_ntia=true`, the codes below promote from `warning` to `error` and switch to HTTP 422. The numeric suffix is preserved across modes.

| Code | HTTP (strict) | Severity (default) | Message template | Remediation | Spec ref |
|---|---|---|---|---|---|
| `SBOM_VAL_W100_NTIA_SUPPLIER_MISSING` | 422 | warning | Component at {path} has no supplier name. | Add `supplier.name` (CycloneDX) or `supplier` (SPDX). | NTIA 2021 §1 |
| `SBOM_VAL_W101_NTIA_COMPONENT_NAME_MISSING` | 422 | warning | Component at {path} has no name. | Add the component name. | NTIA 2021 §2 |
| `SBOM_VAL_W102_NTIA_COMPONENT_VERSION_MISSING` | 422 | warning | Component at {path} has no version. | Add the component version. | NTIA 2021 §3 |
| `SBOM_VAL_W103_NTIA_UNIQUE_ID_MISSING` | 422 | warning | Component at {path} has no PURL, CPE, or SPDXID. | Add at least one unique identifier so the scanner can match against vulnerability databases. | NTIA 2021 §4 |
| `SBOM_VAL_W104_NTIA_DEPENDENCY_RELATIONSHIP_MISSING` | 422 | warning | No dependency relationship is declared between any components. | Add at least one dependency edge (CycloneDX `dependencies[]` or SPDX `relationships[]`). | NTIA 2021 §5 |
| `SBOM_VAL_W105_NTIA_AUTHOR_MISSING` | 422 | warning | Document has no author / SBOM-data creator. | Add `creationInfo.creators` (SPDX) or `metadata.tools[]` (CycloneDX). | NTIA 2021 §6 |
| `SBOM_VAL_W106_NTIA_TIMESTAMP_MISSING` | 422 | warning | Document has no created / metadata.timestamp. | Add the document creation timestamp. | NTIA 2021 §7 |

## Stage 8 — Signature (E110–E119)

| Code | HTTP | Severity | Message template | Remediation | Spec ref |
|---|---|---|---|---|---|
| `SBOM_VAL_E110_SIGNATURE_INVALID` | 422 | error | Signature verification failed: {reason}. | Re-sign with a key trusted by this tenant. | CycloneDX 1.6 §11 |
| `SBOM_VAL_E111_SIGNATURE_ALG_UNSUPPORTED` | 422 | error | Signature algorithm '{alg}' is not in the supported set. | Supported: RS256, RS384, RS512, ES256, ES384, EdDSA. | — |
| `SBOM_VAL_E112_SIGNATURE_KEY_NOT_FOUND` | 422 | error | Signing key '{key_id}' is not registered for this tenant. | Register the public key in the tenant's trust store before re-uploading. | — |
| `SBOM_VAL_W113_SIGNATURE_NOT_PRESENT` | — | warning | Signature verification is enabled but no signature block is present. | Embed a JSF signature (CycloneDX) or upload an external signature sidecar (SPDX). | — |

---

## Code → HTTP status quick reference

| HTTP | Codes |
|---|---|
| **400** | E004, E005, E020, E021, E022, E023, E024, E080, E081, E082, E083, E084, E085, E086, E087, E088 |
| **413** | E001, E002, E003, E089 |
| **415** | E006, E010, E011, E012, E013 |
| **422** | E014, E015, E025–E029, E040–E057, E070–E073, E110–E112; **and** E100–E106 in strict-NTIA mode |

## Severity → behaviour quick reference

| Severity | Blocks acceptance? | Carried in response? | Default for stage 7 NTIA codes |
|---|---|---|---|
| `error`   | yes | yes | strict mode only |
| `warning` | no  | yes (`warnings[]`) | default mode |
| `info`    | no  | yes (`info[]`) | — |

## Truncation

Any single response carries **at most 100 entries**. The 101st sets `"truncated": true` and the rest are dropped.

```json
{
  "detail": {
    "entries": [ /* up to 100 */ ],
    "truncated": true
  }
}
```

This keeps a pathological "every component is malformed" response from emitting a 50 MB error body.

## Auto-generated machine table

<!-- AUTO-GENERATED:BEGIN code-table -->

| Code | HTTP | Default severity | Stage |
|---|---|---|---|
| `SBOM_VAL_E001_SIZE_EXCEEDED` | 413 | `error` | 1 ingress |
| `SBOM_VAL_E002_DECOMPRESSED_SIZE_EXCEEDED` | 413 | `error` | 1 ingress |
| `SBOM_VAL_E003_DECOMPRESSION_RATIO_EXCEEDED` | 413 | `error` | 1 ingress |
| `SBOM_VAL_E004_ENCODING_NOT_UTF8` | 400 | `error` | 1 ingress |
| `SBOM_VAL_E005_EMPTY_BODY` | 400 | `error` | 1 ingress |
| `SBOM_VAL_E006_UNSUPPORTED_COMPRESSION` | 415 | `error` | 1 ingress |
| `SBOM_VAL_E010_FORMAT_INDETERMINATE` | 415 | `error` | 2 detect |
| `SBOM_VAL_E011_FORMAT_AMBIGUOUS` | 415 | `error` | 2 detect |
| `SBOM_VAL_E012_ENCODING_INDETERMINATE` | 415 | `error` | 2 detect |
| `SBOM_VAL_E013_SPEC_VERSION_UNSUPPORTED` | 415 | `error` | 2 detect |
| `SBOM_VAL_E014_SPEC_VERSION_MISSING` | 422 | `error` | 2 detect |
| `SBOM_VAL_E015_SPEC_VERSION_MALFORMED` | 422 | `error` | 2 detect |
| `SBOM_VAL_E020_JSON_PARSE_FAILED` | 400 | `error` | 3 schema |
| `SBOM_VAL_E021_XML_PARSE_FAILED` | 400 | `error` | 3 schema |
| `SBOM_VAL_E022_YAML_PARSE_FAILED` | 400 | `error` | 3 schema |
| `SBOM_VAL_E023_TAGVALUE_PARSE_FAILED` | 400 | `error` | 3 schema |
| `SBOM_VAL_E024_PROTOBUF_PARSE_FAILED` | 400 | `error` | 3 schema |
| `SBOM_VAL_E025_SCHEMA_VIOLATION` | 422 | `error` | 3 schema |
| `SBOM_VAL_E026_SCHEMA_REQUIRED_FIELD_MISSING` | 422 | `error` | 3 schema |
| `SBOM_VAL_E027_SCHEMA_TYPE_MISMATCH` | 422 | `error` | 3 schema |
| `SBOM_VAL_E028_SCHEMA_ENUM_VIOLATION` | 422 | `error` | 3 schema |
| `SBOM_VAL_E029_SCHEMA_FORMAT_VIOLATION` | 422 | `error` | 3 schema |
| `SBOM_VAL_E040_SPDXID_MALFORMED` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E041_DOCUMENT_NAMESPACE_INVALID` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E042_DATA_LICENSE_INVALID` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E043_LICENSE_EXPRESSION_INVALID` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E044_CHECKSUM_LENGTH_MISMATCH` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E045_CREATED_TIMESTAMP_INVALID` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E046_DESCRIBES_RELATIONSHIP_MISSING` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E047_SPDX_VERSION_FIELD_INCONSISTENT` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E050_SERIAL_NUMBER_INVALID` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E051_BOM_REF_DUPLICATE` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E052_PURL_INVALID` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E053_CPE_INVALID` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E054_HASH_LENGTH_MISMATCH` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E055_BOM_VERSION_INVALID` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E056_METADATA_TIMESTAMP_INVALID` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E057_COMPONENT_TYPE_INVALID` | 422 | `error` | 4 semantic |
| `SBOM_VAL_E070_DEPENDENCY_REF_DANGLING` | 422 | `error` | 5 integrity |
| `SBOM_VAL_E071_DEPENDENCY_REF_SELF` | 422 | `error` | 5 integrity |
| `SBOM_VAL_E072_RELATIONSHIP_ELEMENT_DANGLING` | 422 | `error` | 5 integrity |
| `SBOM_VAL_E073_EXTERNAL_DOC_REF_INVALID` | 422 | `error` | 5 integrity |
| `SBOM_VAL_E080_JSON_DEPTH_EXCEEDED` | 400 | `error` | 6 security |
| `SBOM_VAL_E081_JSON_ARRAY_LENGTH_EXCEEDED` | 400 | `error` | 6 security |
| `SBOM_VAL_E082_JSON_STRING_LENGTH_EXCEEDED` | 400 | `error` | 6 security |
| `SBOM_VAL_E083_XML_DTD_FORBIDDEN` | 400 | `error` | 6 security |
| `SBOM_VAL_E084_XML_EXTERNAL_ENTITY_FORBIDDEN` | 400 | `error` | 6 security |
| `SBOM_VAL_E085_XML_ENTITY_EXPANSION` | 400 | `error` | 6 security |
| `SBOM_VAL_E086_YAML_UNSAFE_TAG` | 400 | `error` | 6 security |
| `SBOM_VAL_E087_PROTOTYPE_POLLUTION_KEY` | 400 | `error` | 6 security |
| `SBOM_VAL_E088_EMBEDDED_BLOB_TOO_LARGE` | 400 | `error` | 6 security |
| `SBOM_VAL_E089_ZIP_BOMB_RATIO` | 413 | `error` | 6 security |
| `SBOM_VAL_E110_SIGNATURE_INVALID` | 422 | `error` | 8 signature |
| `SBOM_VAL_E111_SIGNATURE_ALG_UNSUPPORTED` | 422 | `error` | 8 signature |
| `SBOM_VAL_E112_SIGNATURE_KEY_NOT_FOUND` | 422 | `error` | 8 signature |
| `SBOM_VAL_I075_ORPHAN_COMPONENT` | 200 | `info` | 5 integrity |
| `SBOM_VAL_W074_DEPENDENCY_CYCLE_DETECTED` | 200 | `warning` | 5 integrity |
| `SBOM_VAL_W100_NTIA_SUPPLIER_MISSING` | 422 | `warning` | 7 ntia |
| `SBOM_VAL_W101_NTIA_COMPONENT_NAME_MISSING` | 422 | `warning` | 7 ntia |
| `SBOM_VAL_W102_NTIA_COMPONENT_VERSION_MISSING` | 422 | `warning` | 7 ntia |
| `SBOM_VAL_W103_NTIA_UNIQUE_ID_MISSING` | 422 | `warning` | 7 ntia |
| `SBOM_VAL_W104_NTIA_DEPENDENCY_RELATIONSHIP_MISSING` | 422 | `warning` | 7 ntia |
| `SBOM_VAL_W105_NTIA_AUTHOR_MISSING` | 422 | `warning` | 7 ntia |
| `SBOM_VAL_W106_NTIA_TIMESTAMP_MISSING` | 422 | `warning` | 7 ntia |
| `SBOM_VAL_W113_SIGNATURE_NOT_PRESENT` | 200 | `warning` | 8 signature |

_Generated by `scripts/gen_error_code_reference.py` from `app/validation/errors.py`. 65 codes total._

<!-- AUTO-GENERATED:END code-table -->
