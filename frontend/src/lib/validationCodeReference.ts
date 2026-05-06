/**
 * In-app reference for the most-encountered SBOM validation codes.
 *
 * The authoritative long-form reference lives at
 * docs/validation-error-codes.md in the repo. This module is a curated
 * subset for two purposes:
 *
 * 1. The /docs/sbom-validation-errors page renders one anchored section per
 *    entry so the validation-report chip can deep-link directly to the
 *    relevant code (`#sbom_val_e052_purl_invalid`).
 * 2. The validation report tooltip surfaces the canonical name + spec ref
 *    even when the report payload is otherwise sparse.
 *
 * Codes selected: the top causes of upload rejection in the first month of
 * the validator's production run, plus a representative entry per pipeline
 * stage so every stage has at least one in-app docs entry.
 */

export interface ValidationCodeRef {
  code: string;
  /** Canonical anchor — lowercased code, no surrounding hash. */
  anchor: string;
  stage: string;
  stage_number: number;
  http_status: number;
  default_severity: 'error' | 'warning' | 'info';
  /** One-paragraph summary written for an SBOM author. */
  summary: string;
  /** Common-cause bullets — what typically triggers this code. */
  common_causes: string[];
  /** How to fix prose. */
  how_to_fix: string;
  /** Optional canonical spec reference link. */
  spec_link?: { label: string; href: string };
}

const ref = (entry: Omit<ValidationCodeRef, 'anchor'>): ValidationCodeRef => ({
  ...entry,
  anchor: entry.code.toLowerCase(),
});

export const VALIDATION_CODE_REFERENCE: ValidationCodeRef[] = [
  // Stage 1 — Ingress
  ref({
    code: 'SBOM_VAL_E001_SIZE_EXCEEDED',
    stage: 'ingress',
    stage_number: 1,
    http_status: 413,
    default_severity: 'error',
    summary:
      'The uploaded body exceeds the configured maximum byte budget. The validator rejects oversize uploads before any parsing to keep the request path predictable.',
    common_causes: [
      'A multi-tenant monorepo SBOM that exceeds the operator-set MAX_UPLOAD_BYTES (default 50 MB).',
      'Uncompressed SBOMs that would fit comfortably under the cap if gzip-encoded.',
      'A misconfigured CI job that sends the entire build directory instead of the SBOM.',
    ],
    how_to_fix:
      'Compress the SBOM with gzip before upload (the validator accepts gzip and deflate Content-Encoding), split the SBOM into per-component documents, or ask your operator to raise MAX_UPLOAD_BYTES if your real document is genuinely larger than the limit.',
  }),

  // Stage 2 — Format detection
  ref({
    code: 'SBOM_VAL_E011_FORMAT_AMBIGUOUS',
    stage: 'detect',
    stage_number: 2,
    http_status: 415,
    default_severity: 'error',
    summary:
      'The document fingerprints as both SPDX and CycloneDX. The validator never guesses — pick one format and re-emit.',
    common_causes: [
      'A document with both `bomFormat: "CycloneDX"` and `spdxVersion` at the top level.',
      'Hand-edited SBOMs that copy fields between formats.',
    ],
    how_to_fix:
      'Choose one format and remove the other format’s top-level fingerprint fields. SBOMs should be emitted by tools that own the format end-to-end (e.g. syft for CycloneDX, the SPDX SBOM generator for SPDX).',
  }),
  ref({
    code: 'SBOM_VAL_E013_SPEC_VERSION_UNSUPPORTED',
    stage: 'detect',
    stage_number: 2,
    http_status: 415,
    default_severity: 'error',
    summary:
      'The format/spec-version pair is not in the supported set.',
    common_causes: [
      'Older CycloneDX 1.3 documents (pre-PURL canonical form).',
      'SPDX 1.x documents (the validator supports 2.2 / 2.3 / 3.0 only).',
      'CycloneDX Protobuf or SPDX RDF/XML — both deferred.',
    ],
    how_to_fix:
      'Re-emit using a supported version: SPDX 2.2 / 2.3 / 3.0 or CycloneDX 1.4 / 1.5 / 1.6. Most generators have a flag to pick the output spec version.',
  }),

  // Stage 3 — Schema
  ref({
    code: 'SBOM_VAL_E020_JSON_PARSE_FAILED',
    stage: 'schema',
    stage_number: 3,
    http_status: 400,
    default_severity: 'error',
    summary:
      'The JSON parser failed before the schema validator ran. The document is malformed at the syntactic level.',
    common_causes: [
      'A trailing comma, unquoted key, or unescaped backslash.',
      'A SBOM concatenated with another document during shell pipelining.',
      'BOM-prefixed UTF-8 that confuses some parsers.',
    ],
    how_to_fix:
      'Run the document through `jq .` or another JSON validator to find the syntax error, then re-emit. The error message includes the line and column of the first parser failure.',
  }),
  ref({
    code: 'SBOM_VAL_E025_SCHEMA_VIOLATION',
    stage: 'schema',
    stage_number: 3,
    http_status: 422,
    default_severity: 'error',
    summary:
      'JSON Schema (or XSD) validation against the vendored schema for the detected spec version failed at the indicated path.',
    common_causes: [
      'A field with the wrong type (string where an array is expected, etc.).',
      'A required field omitted from a nested object.',
      'A custom field your tool added at a path the spec reserves.',
    ],
    how_to_fix:
      'Compare the document against the relevant spec section. The `path` field on the error entry locates the violating element exactly. The schemas are vendored under `app/validation/schemas/` if you want to test locally.',
  }),

  // Stage 4 — Semantic, SPDX
  ref({
    code: 'SBOM_VAL_E042_DATA_LICENSE_INVALID',
    stage: 'semantic',
    stage_number: 4,
    http_status: 422,
    default_severity: 'error',
    summary:
      'SPDX 2.x requires the `dataLicense` field at the top of the document to be exactly `CC0-1.0`. This is the licence of the SBOM document itself, not of the components inside it.',
    common_causes: [
      'A generator that fills `dataLicense` from the project’s primary licence (e.g. `Apache-2.0`).',
      'A user-edited SBOM where the field was changed by mistake.',
    ],
    how_to_fix:
      'Set `dataLicense` to the literal string `CC0-1.0` at the top level of the SPDX document. Your component licences live separately in each package’s `licenseDeclared` and `licenseConcluded` fields.',
    spec_link: { label: 'SPDX 2.3 §6.2', href: 'https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#62-data-license-field' },
  }),
  ref({
    code: 'SBOM_VAL_E043_LICENSE_EXPRESSION_INVALID',
    stage: 'semantic',
    stage_number: 4,
    http_status: 422,
    default_severity: 'error',
    summary:
      'A licence expression at the indicated path is not parseable as an SPDX licence expression.',
    common_causes: [
      'Free-text licence values like `BSD-3 or MIT`.',
      'Uppercase / lowercase drift on operators (`AND` is correct; `and` is not).',
      'Non-SPDX identifiers like `BSD3` (must be `BSD-3-Clause`).',
    ],
    how_to_fix:
      'Use a valid SPDX licence expression — see the SPDX licence list and the expression grammar. Tools like `licensee` and `cargo about` emit canonical expressions from common project metadata.',
    spec_link: { label: 'SPDX licence expressions', href: 'https://spdx.dev/learn/handling-license-info/' },
  }),

  // Stage 4 — Semantic, CycloneDX
  ref({
    code: 'SBOM_VAL_E050_SERIAL_NUMBER_INVALID',
    stage: 'semantic',
    stage_number: 4,
    http_status: 422,
    default_severity: 'error',
    summary:
      'CycloneDX `serialNumber` must be an RFC-4122 URN UUID — i.e. `urn:uuid:` followed by a 36-character UUID.',
    common_causes: [
      'A serial number using an internal scheme (project ID, build ID).',
      'A UUID emitted without the `urn:uuid:` scheme prefix.',
    ],
    how_to_fix:
      'Generate a UUID v4 and serialise it as `urn:uuid:{uuid}`. Most CycloneDX generators handle this automatically — if you are constructing the SBOM by hand, use a UUID library.',
    spec_link: { label: 'CycloneDX 1.6 §3', href: 'https://cyclonedx.org/docs/1.6/json/#serialNumber' },
  }),
  ref({
    code: 'SBOM_VAL_E051_BOM_REF_DUPLICATE',
    stage: 'semantic',
    stage_number: 4,
    http_status: 422,
    default_severity: 'error',
    summary:
      'Two or more components share the same `bom-ref`. Bom-refs must be unique within the document so dependency / vulnerability references resolve unambiguously.',
    common_causes: [
      'Duplicate components after a faulty merge of two partial SBOMs.',
      'A generator that uses the package name as the bom-ref without disambiguating multiple versions.',
    ],
    how_to_fix:
      'Make every bom-ref unique. The conventional form is the component’s PURL — `pkg:maven/group/artifact@version` — which inherently disambiguates name + version + type.',
  }),
  ref({
    code: 'SBOM_VAL_E052_PURL_INVALID',
    stage: 'semantic',
    stage_number: 4,
    http_status: 422,
    default_severity: 'error',
    summary:
      'A `purl` field does not conform to the Package URL spec. The validator parses each PURL strictly — empty namespaces, missing version segments, and wrong scheme prefixes all fail.',
    common_causes: [
      'Missing `pkg:` scheme prefix.',
      'Empty namespace segment (`pkg:npm/@scope//bad`).',
      'Missing `@version` after the name.',
      'URL-encoded characters in the wrong segments of the PURL.',
    ],
    how_to_fix:
      'Use the canonical form `pkg:{type}/{namespace}/{name}@{version}`. The PURL spec lists the exact rules per package type. Most SBOM generators have a strict mode that catches malformed PURLs at generation time.',
    spec_link: { label: 'Package URL spec', href: 'https://github.com/package-url/purl-spec' },
  }),

  // Stage 5 — Cross-reference integrity
  ref({
    code: 'SBOM_VAL_E070_DEPENDENCY_REF_DANGLING',
    stage: 'integrity',
    stage_number: 5,
    http_status: 422,
    default_severity: 'error',
    summary:
      'A dependency edge references a `bom-ref` that does not correspond to any component in the document.',
    common_causes: [
      'Components removed during post-processing without updating the dependency graph.',
      'A merge of two SBOMs where the dependency block referenced bom-refs from the dropped half.',
    ],
    how_to_fix:
      'Either remove the dangling edges or add the missing components. The `path` on the error locates the offending dependency entry exactly.',
  }),

  // Stage 6 — Security
  ref({
    code: 'SBOM_VAL_E083_XML_DTD_FORBIDDEN',
    stage: 'security',
    stage_number: 6,
    http_status: 400,
    default_severity: 'error',
    summary:
      'The XML document declares a DOCTYPE / DTD. The validator forbids DTDs in uploaded SBOMs to defeat XXE and entity-expansion attacks. SBOMs that pass this stage are quarantined for admin review.',
    common_causes: [
      'A test or fuzz payload designed to probe the validator.',
      'A legitimate XML SBOM emitted by an old tool that included a DOCTYPE for human-readability.',
    ],
    how_to_fix:
      'Remove the `<!DOCTYPE ... >` declaration and any associated `<!ENTITY ... >` definitions. CycloneDX XML SBOMs do not need a DTD — the schema is referenced via xmlns instead.',
  }),

  // Stage 7 — NTIA minimum elements (warning by default)
  ref({
    code: 'SBOM_VAL_W100_NTIA_SUPPLIER_MISSING',
    stage: 'ntia',
    stage_number: 7,
    http_status: 422,
    default_severity: 'warning',
    summary:
      'A component lacks a supplier name. Per the NTIA minimum-elements guidance, every component should declare its supplier so downstream consumers can attribute the package to a real legal entity.',
    common_causes: [
      'Tools that only emit author / publisher metadata when known with confidence.',
      'OSS components where the supplier is genuinely the upstream maintainer org.',
    ],
    how_to_fix:
      'Add `supplier.name` (CycloneDX) or `supplier` (SPDX) per component. For OSS, the supplier is the upstream project (e.g. "Apache Software Foundation" for log4j-core).',
    spec_link: {
      label: 'NTIA minimum elements',
      href: 'https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf',
    },
  }),

  // Stage 8 — Signature
  ref({
    code: 'SBOM_VAL_E110_SIGNATURE_INVALID',
    stage: 'signature',
    stage_number: 8,
    http_status: 422,
    default_severity: 'error',
    summary:
      'The signature attached to the SBOM (JSF for CycloneDX, signed-SPDX for SPDX) failed cryptographic verification.',
    common_causes: [
      'The SBOM was modified after it was signed (whitespace, key reordering by a re-emit).',
      'The wrong public key is configured for verification.',
    ],
    how_to_fix:
      'Re-sign the SBOM after any modifications. If the signature is meant to be optional, set `SBOM_SIGNATURE_VERIFICATION=false` to disable stage 8 entirely.',
  }),
];

const _BY_CODE = new Map(VALIDATION_CODE_REFERENCE.map((r) => [r.code, r]));

export function lookupValidationCode(code: string): ValidationCodeRef | undefined {
  return _BY_CODE.get(code);
}

/** Anchor href for any code — even codes not in the curated reference. */
export function validationCodeAnchor(code: string): string {
  return `/docs/sbom-validation-errors#${code.toLowerCase()}`;
}
