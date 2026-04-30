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
3. Run `pytest tests/validation/ -m schema` to confirm the corpus still passes.
4. Add a CHANGELOG entry if the spec version itself moved (1.6 → 1.7).
