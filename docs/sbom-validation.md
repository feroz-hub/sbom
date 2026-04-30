# SBOM validation — user guide

The SBOM Analyzer runs every uploaded SBOM through an
[eight-stage validation pipeline](adr/0007-sbom-validation-architecture.md)
**before** anything is written to the database. Rejected SBOMs never get a
row, never enqueue a scan, and always produce a structured response your
client can branch on by error code.

This page is for the people uploading the SBOMs. For the design rationale
read [ADR-0007](adr/0007-sbom-validation-architecture.md); for full
provenance of every code see [the error-code reference](validation-error-codes.md).

---

## What we validate, and why

| Stage | Concern | Why it matters |
|------:|---------|----------------|
| 1 | Size, encoding, decompression bombs | A 50 GB body, a UTF-16 BOM, or a 100,000:1 gzip ratio never reaches the parser |
| 2 | Format & version detection | The validator never guesses — ambiguous documents fail fast |
| 3 | Structural schema (vendored JSON Schema / XSD) | Catches missing required fields, wrong types, bad enums before any custom check runs |
| 4 | Semantic invariants | PURL parses, CPE 2.3 matches, hash length matches algorithm, `bom-ref` is unique |
| 5 | Cross-reference integrity | Every dependency target resolves; cycles are reported as warnings, not errors |
| 6 | Security checks | JSON depth ≤ 64, no `__proto__` keys, no XML DTDs / external entities |
| 7 | NTIA minimum elements | Supplier / version / unique-id / dependency / author / timestamp — soft by default |
| 8 | Signature (feature-flagged) | JSF (CycloneDX) or external sidecar (SPDX); off in v1 |

A successful upload returns **HTTP 202 Accepted**. Warnings and info-level
entries flow through in the response body but never block acceptance.

A rejected upload returns one of **400 / 413 / 415 / 422** with a
machine-readable list of error entries. Status precedence is
`413 > 415 > 422 > 400` when multiple codes fire.

---

## Uploading an SBOM

The recommended endpoint is `POST /api/sboms/upload` (multipart). The
legacy `POST /api/sboms` (JSON-string `sbom_data` field) still works and
flows through the same validator, but is deprecated in the OpenAPI doc.

### `POST /api/sboms/upload`

Form fields:

| Field | Required | Description |
|---|---|---|
| `file` | yes | The SBOM document (SPDX or CycloneDX) |
| `sbom_name` | yes | Display name (1-255 chars) |
| `project_id` | no | Existing project to attach to |
| `sbom_type` | no | SBOM type id |
| `created_by` | no | User identifier for audit trail |
| `?strict_ntia=true` | no | Promote NTIA warnings to hard errors (HTTP 422) |

Successful response shape:

```json
{
  "sbom_id": 42,
  "sbom_name": "my-app-1.0.0",
  "spec": "cyclonedx",
  "spec_version": "1.6",
  "components": 217,
  "warnings": [
    {
      "code": "SBOM_VAL_W104_NTIA_DEPENDENCY_RELATIONSHIP_MISSING",
      "severity": "warning",
      "stage": "ntia",
      "path": "dependencies",
      "message": "No dependency relationship is declared between any components.",
      "remediation": "Add at least one dependency edge (CycloneDX `dependencies[]` or SPDX `relationships[]`).",
      "spec_reference": "NTIA 2021 §5"
    }
  ],
  "info": []
}
```

Rejected response shape (any 4xx):

```json
{
  "detail": {
    "entries": [
      {
        "code": "SBOM_VAL_E052_PURL_INVALID",
        "severity": "error",
        "stage": "semantic",
        "path": "components[17].purl",
        "message": "PURL 'pkg:npm/@scope//bad' is malformed: empty namespace segment",
        "remediation": "Use the form `pkg:{type}/{namespace}/{name}@{version}`. See https://github.com/package-url/purl-spec.",
        "spec_reference": "CycloneDX 1.6 §4.4.1"
      }
    ],
    "truncated": false
  }
}
```

If a single document trips more than 100 entries, only the first 100 are
returned and `truncated` is set to `true`. Fix what's listed and re-upload.

---

## Common rejections — and how to fix them

### `SBOM_VAL_E001_SIZE_EXCEEDED` (HTTP 413)

The body exceeds 50 MB.

```bash
$ curl -X POST http://localhost:8000/api/sboms/upload \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@huge.json" -F "sbom_name=huge"
{"detail":{"entries":[{"code":"SBOM_VAL_E001_SIZE_EXCEEDED",...}],"truncated":false}}
```

**Fix:** compress the SBOM with `gzip` (the validator decompresses up to
200 MB on the wire) or split a monorepo SBOM into per-project files.

### `SBOM_VAL_E010_FORMAT_INDETERMINATE` (HTTP 415)

The document has no SPDX or CycloneDX fingerprint.

```bash
$ echo '{"hello": "world"}' > weird.json
$ curl -X POST http://localhost:8000/api/sboms/upload \
    -F "file=@weird.json" -F "sbom_name=weird"
{"detail":{"entries":[{"code":"SBOM_VAL_E010_FORMAT_INDETERMINATE","stage":"detect",
  "message":"Unable to detect SBOM format. No SPDX or CycloneDX fingerprint matched.",...}]}}
```

**Fix:** verify the document has either `bomFormat: "CycloneDX"` +
`specVersion` (CycloneDX) or `spdxVersion` (SPDX) at the top level.

### `SBOM_VAL_E013_SPEC_VERSION_UNSUPPORTED` (HTTP 415)

The version is in the [Supported SBOM Formats](../README.md#supported-sbom-formats)
deferred column — SPDX 3.0 JSON-LD, SPDX RDF/XML, or CycloneDX Protobuf.

**Fix:** re-export the SBOM from your tool as SPDX 2.3 JSON, SPDX 2.3
Tag-Value, or CycloneDX 1.4 / 1.5 / 1.6 (JSON or XML).

### `SBOM_VAL_E025_SCHEMA_VIOLATION` (HTTP 422)

A required field is missing, has the wrong type, or violates an enum.
The `path` field tells you exactly where:

```json
{
  "code": "SBOM_VAL_E026_SCHEMA_REQUIRED_FIELD_MISSING",
  "path": "components[42].name",
  "message": "Required field 'name' is missing at components[42].name"
}
```

**Fix:** add the field per the relevant
[CycloneDX](https://cyclonedx.org/docs/) or
[SPDX](https://spdx.github.io/spdx-spec/) spec.

### `SBOM_VAL_E040_SPDXID_MALFORMED` (HTTP 422)

```bash
$ curl -X POST http://localhost:8000/api/sboms/upload \
    -F "file=@spdx-bad-id.json" -F "sbom_name=bad-id"
{"entries":[{"code":"SBOM_VAL_E040_SPDXID_MALFORMED",
  "path":"packages[0].SPDXID",
  "message":"SPDXID 'BAD-Package' does not match SPDXRef-/DocumentRef-[a-zA-Z0-9.-]+ pattern."}]}
```

**Fix:** rename the SPDXID to start with `SPDXRef-` and contain only
`[a-zA-Z0-9.-]`. Same applies to `SPDXRef-DOCUMENT`.

### `SBOM_VAL_E042_DATA_LICENSE_INVALID` (HTTP 422)

The SPDX `dataLicense` field documents the license of the **SBOM
document itself**, not of its components. SPDX 2.x specifies
exactly `CC0-1.0`.

**Fix:** set `dataLicense: "CC0-1.0"` at the top of the document.

### `SBOM_VAL_E050_SERIAL_NUMBER_INVALID` (HTTP 422)

CycloneDX `serialNumber` must be a UUID URN.

**Fix:** generate a UUID v4 and prefix `urn:uuid:`. Most CycloneDX
emitters do this automatically.

```bash
$ python -c "import uuid; print(f'urn:uuid:{uuid.uuid4()}')"
urn:uuid:11111111-2222-3333-4444-555555555555
```

### `SBOM_VAL_E051_BOM_REF_DUPLICATE` (HTTP 422)

Two components share the same `bom-ref`. CycloneDX requires every
`bom-ref` to be unique within the document.

**Fix:** make each `bom-ref` unique — typically by appending the
component version or a UUID suffix.

### `SBOM_VAL_E052_PURL_INVALID` (HTTP 422)

The PURL doesn't parse. The validator uses `packageurl-python` and
returns the parser's reason in the `message` field.

**Fix:** use the canonical form `pkg:{type}/{namespace}/{name}@{version}`.

```
pkg:npm/foo@1.0.0
pkg:npm/@scope/name@1.0.0
pkg:pypi/django@4.2
pkg:maven/org.springframework/spring-core@6.1.0
```

### `SBOM_VAL_E054_HASH_LENGTH_MISMATCH` (HTTP 422)

A hash declares an algorithm whose digest length doesn't match the
content. Common cause: declaring `SHA-256` but providing a 40-character
SHA-1.

**Fix:** recompute the digest with the algorithm you declared, or
update the algorithm name to match what you actually computed.

| Algorithm | Hex chars |
|---|---:|
| `MD5` | 32 |
| `SHA-1` | 40 |
| `SHA-256` / `SHA3-256` / `BLAKE2b-256` / `BLAKE3` | 64 |
| `SHA-384` / `SHA3-384` / `BLAKE2b-384` | 96 |
| `SHA-512` / `SHA3-512` / `BLAKE2b-512` | 128 |

### `SBOM_VAL_E070_DEPENDENCY_REF_DANGLING` (HTTP 422)

A `dependencies[].dependsOn[]` entry references a `bom-ref` that no
component declares.

**Fix:** declare the missing component, or remove the dependency entry.

### `SBOM_VAL_E080_JSON_DEPTH_EXCEEDED` (HTTP 400)

JSON nesting depth > 64 levels. This is a security cap, not a bug —
real SBOMs do not exceed 64 levels.

**Fix:** flatten the structure. If you genuinely need deeper nesting,
talk to your operator about raising the cap with a justification.

### `SBOM_VAL_E083_XML_DTD_FORBIDDEN` / `E084_…EXTERNAL_ENTITY` / `E085_…ENTITY_EXPANSION` (HTTP 400)

The XML document contains a `<!DOCTYPE>`, an external entity, or an
expansion attempt. All three are rejected unconditionally — they are
attack vectors, not legitimate SBOM features.

**Fix:** remove the `<!DOCTYPE …>` declaration and any `<!ENTITY …>`
declarations. Legitimate SBOM tools do not emit them.

### `SBOM_VAL_W100_…W106_NTIA_…_MISSING` (HTTP 200)

Missing NTIA minimum elements (supplier, name, version, unique id,
dependency relationship, author, timestamp). Default = warnings; the
upload still succeeds.

**Fix:** populate the missing field. If you cannot, the SBOM still
ingests — but downstream scans may produce more "unknown supplier"
findings than you'd like.

To enforce strictly:

```bash
$ curl -X POST 'http://localhost:8000/api/sboms/upload?strict_ntia=true' \
    -F "file=@partial.json" -F "sbom_name=partial"
# now any W100-W106 returns HTTP 422
```

---

## Auto-generated error-code reference

The full table — every code, its HTTP status, default severity, and
stage band — is in [validation-error-codes.md](validation-error-codes.md).
The machine table at the end of that file is regenerated from
[`app/validation/errors.py`](../app/validation/errors.py) by
[`scripts/gen_error_code_reference.py`](../scripts/gen_error_code_reference.py).

---

## cURL recipes

### Strict NTIA upload

```bash
curl -X POST 'http://localhost:8000/api/sboms/upload?strict_ntia=true' \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@bom.json" \
    -F "sbom_name=my-bom" \
    -F "project_id=3"
```

### Compressed upload

```bash
gzip -k bom.json
curl -X POST http://localhost:8000/api/sboms/upload \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Encoding: gzip" \
    -F "file=@bom.json.gz" \
    -F "sbom_name=my-bom"
```

### Pretty-print error responses with `jq`

```bash
curl -s -X POST http://localhost:8000/api/sboms/upload \
    -F "file=@broken.json" -F "sbom_name=broken" \
    | jq '.detail.entries[] | {code, path, message}'
```

### Validate without persisting (planned)

The current endpoint validates and persists in one step. A future
release will expose `POST /api/sboms/validate` (validation-only, no
DB write) for pre-flight checks; track this in a follow-up issue.

---

## What the validator does NOT do

- It does not scan for vulnerabilities. A successful upload returns
  202 with a `sbom_id`; downstream `POST /api/sboms/{id}/analyze`
  performs the actual NVD / GHSA / OSV / VulDB scan.
- It does not verify provenance. A signed CycloneDX JSF block is
  parsed structurally but not yet cryptographically verified — see
  [ADR-0007 §4.8](adr/0007-sbom-validation-architecture.md).
- It does not enrich missing fields. The validator never coerces, never
  fills in defaults, never silently drops entries. Every field in the
  response was either present in your upload or generated by the scanner.
