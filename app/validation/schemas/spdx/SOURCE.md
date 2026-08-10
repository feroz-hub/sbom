# SPDX schema provenance

| File | Origin | Upstream commit | Retrieved | Licence |
|------|--------|------------------|-----------|---------|
| `2.2/spdx-schema.json` | https://raw.githubusercontent.com/spdx/spdx-spec/v2.2.2/schemas/spdx-schema.json | `a05c12a2dd4652b1396fd2659f2cd3ea1f37faba` | 2026-04-30 | CC0-1.0 |
| `2.3/spdx-schema.json` | https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json   | `aadf3b0b8dbbabdb4d880b0fc714255fea436ff7` | 2026-04-30 | CC0-1.0 |

Schemas are loaded once at process startup (see [app/validation/stages/schema.py](../../stages/schema.py)) and never fetched at runtime — see [docs/adr/0007-sbom-validation-architecture.md §3](../../../../docs/adr/0007-sbom-validation-architecture.md).

## SPDX 3.0 status

SPDX 3.0 has no single canonical JSON Schema vendored at a stable URL — the 3.0 model lives in `spdx/spdx-3-model` and is shipped as JSON-LD context plus per-class shapes, not as one Draft-2020-12 schema.

For Phase 3 v1, **SPDX 3.0 documents are explicitly rejected at stage 2** with `SBOM_VAL_E013_SPEC_VERSION_UNSUPPORTED` (see [app/validation/stages/detect.py](../../stages/detect.py)). The deferral is intentional and is documented in [docs/adr/0007-sbom-validation-architecture.md §"Deferred (future ADRs)"](../../../../docs/adr/0007-sbom-validation-architecture.md). The `semantic_spdx3.py` module is scaffolded so that adding 3.0 support later is a matter of vendoring the schema and removing the explicit reject — no public-API change.

## Refresh procedure

1. Open a PR that updates these files **and** this SOURCE.md row in the same commit.
2. Bump the commit SHA / retrieved date on the affected row(s).
3. Run `pytest tests/validation/ -m schema` to confirm the corpus still passes.
4. Add a CHANGELOG entry if the spec version itself moved.
