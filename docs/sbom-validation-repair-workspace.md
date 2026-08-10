# SBOM validation repair workspace

The repair workspace is a quarantine lane for SBOM uploads that fail the
normal eight-stage validator. It lets users inspect, edit, request AI
suggestions, revalidate, and import only after validation succeeds.

## Trust boundary

Failed uploads are not inserted into `sbom_source`. Safe-to-store failures are
saved in `sbom_validation_sessions`; unsafe payloads are rejected without a
session. A session is staged data, not a trusted SBOM.

Security-blocked payloads include oversized bodies, decompression bombs,
unsafe encodings, XML DTD/external entity issues, unsafe YAML tags,
prototype-pollution keys, embedded blobs, and other ingress/security-stage
hard errors. These return `can_edit=false` and `can_ai_fix=false`.

## Workflow

1. `POST /api/sboms` or `POST /api/sboms/upload` runs the existing validator.
2. If validation passes, a normal `sbom_source` row is created.
3. If validation fails and the payload is safe to stage, the API creates
   `sbom_validation_sessions` and returns `session_id`.
4. Users open `/sbom-validation-sessions/{session_id}`.
5. Manual edits update only the staged `current_content`.
6. AI suggestions return review-only patch proposals.
7. User-approved patches are applied by the server patch engine.
8. Every patch application reruns the same validator.
9. `POST /api/sbom-validation-sessions/{id}/import` creates a trusted
   `sbom_source` row only when the current content has zero errors.

## APIs

- `GET /api/sbom-validation-sessions/{id}` returns staged content, metadata,
  validation report, and edit/import flags.
- `PATCH /api/sbom-validation-sessions/{id}` saves edited `current_content`.
- `POST /api/sbom-validation-sessions/{id}/validate` reruns all validation
  stages against staged content.
- `POST /api/sbom-validation-sessions/{id}/import` imports only after a clean
  validation run.
- `POST /api/sbom-validation-sessions/{id}/ai/suggest-fixes` asks the
  configured AI provider for structured patch suggestions.
- `POST /api/sbom-validation-sessions/{id}/apply-patch` applies selected
  patches and revalidates.
- `GET /api/sbom-validation-sessions/{id}/history` returns append-only repair
  events.

## AI fix rules

AI output is never applied automatically. Suggestions must include
`requires_user_review=true` and a list of patches with target, operation,
before/after, reason, and validation error codes.

The server filters unsafe suggestions. It rejects or drops patches that target
signature fabrication, security bypasses, or prototype-pollution keys. Signature
errors can be explained to the user, but AI must not invent trust data.

## Patch support

JSON SBOMs use JSON Pointer operations: `add`, `replace`, and `remove`.
The patch engine validates targets and optional `before` preconditions.

XML, YAML, and SPDX Tag-Value currently use exact text replace/remove fallback.
If an exact `before` value does not match exactly once, the patch is rejected.

## Audit history

Every session records append-only events:

- `created`
- `manual_edit`
- `ai_suggestion_generated`
- `patch_applied`
- `validation_run`
- `imported`

Each event stores timestamp, actor if provided, summary, before/after content
hashes, and metadata.

## Limitations

- XML/YAML/SPDX structural patching is intentionally conservative.
- Sessions expire by timestamp but automated cleanup is not yet implemented.
- AI suggestions depend on configured AI provider availability and budget.
- Strict NTIA and signature policy flags are supported by validate/import
  endpoints but the current frontend uses default policy settings.
