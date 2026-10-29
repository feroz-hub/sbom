# CycloneDX schema provenance

| File | Origin | Upstream commit | Retrieved | Licence |
|------|--------|------------------|-----------|---------|
| `1.4/bom-1.4.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.4.schema.json | `29b8bddcd4de5db6bf5abf2387c6a2f695be0c27` | 2026-04-30 | Apache-2.0 |
| `1.4/bom-1.4.xsd`         | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.4.xsd         | `29b8bddcd4de5db6bf5abf2387c6a2f695be0c27` | 2026-04-30 | Apache-2.0 |
| `1.5/bom-1.5.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json | `29b8bddcd4de5db6bf5abf2387c6a2f695be0c27` | 2026-04-30 | Apache-2.0 |
| `1.5/bom-1.5.xsd`         | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.xsd         | `29b8bddcd4de5db6bf5abf2387c6a2f695be0c27` | 2026-04-30 | Apache-2.0 |
| `1.6/bom-1.6.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json | `29b8bddcd4de5db6bf5abf2387c6a2f695be0c27` | 2026-04-30 | Apache-2.0 |
| `1.6/bom-1.6.xsd`         | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.xsd         | `29b8bddcd4de5db6bf5abf2387c6a2f695be0c27` | 2026-04-30 | Apache-2.0 |
| `<v>/spdx.xsd`            | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/spdx.xsd            | `29b8bddcd4de5db6bf5abf2387c6a2f695be0c27` | 2026-04-30 | Apache-2.0 |

The XSDs originally `<xs:import>` `spdx.xsd` via the URL
``http://cyclonedx.org/schema/spdx``. The vendored copies have been edited to
reference the local `spdx.xsd` (one line, recorded by the patch in
[app/validation/schemas/cyclonedx/SOURCE.md](SOURCE.md)) so lxml can resolve
the import without a network round-trip — see ADR-0007 §3 (no runtime fetch).

Schemas are loaded once at process startup (see [app/validation/stages/schema.py](../../stages/schema.py)) and never fetched at runtime — see [docs/adr/0007-sbom-validation-architecture.md §3](../../../../docs/adr/0007-sbom-validation-architecture.md).

## Refresh procedure

1. Open a PR that updates these files **and** this SOURCE.md row in the same commit.
2. Bump the commit SHA / retrieved date on the affected row(s).
3. On an authorized disposable test target, run
   `python -m pytest tests/validation/ -m "not bench"` to include validation
   integration tests. The current pytest configuration has no schema marker;
   follow the [testing guide](../../../../docs/testing/README.md) for target safety.
4. Add a CHANGELOG entry if the spec version itself moved (1.6 → 1.7).

## Round 3 missing signature-schema dependency

`jsf-0.82.schema.json` is vendored unchanged from the same immutable CycloneDX upstream commit `29b8bddcd4de5db6bf5abf2387c6a2f695be0c27` as the BOM schemas, retrieved 2026-10-20. [Upstream file](https://raw.githubusercontent.com/CycloneDX/specification/29b8bddcd4de5db6bf5abf2387c6a2f695be0c27/schema/jsf-0.82.schema.json). Apache-2.0. SHA256: `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae`. The local JSON Schema registry now registers its declared ID. No runtime network retrieval is added. Structural validation does not assert cryptographic verification: the separately deferred Stage 8 verifier still rejects verification requests for present signatures with E110.
