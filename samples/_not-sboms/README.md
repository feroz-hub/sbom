# Not SBOMs — kept for reference

These files were in `samples/` but are **not SBOM documents**, so they can never
pass the 8-stage SBOM validation pipeline (they fail at the **detect** stage with
`SBOM_VAL_E010_FORMAT_INDETERMINATE` — no CycloneDX/SPDX fingerprint). They are
the *output* of other tooling, kept here only as reference fixtures. They are not
referenced by path anywhere in the code or tests.

| File | What it actually is | Top-level keys |
|------|--------------------|----------------|
| `app-sbom.json` | A scan-result / analysis-output JSON (not an SBOM) | `ok`, `dependencyCount`, `summary`, `vulnerabilities`, `license_issues` |
| `outputsbom.json` | An NVD CVE-API 2.0 response (not an SBOM) — also carries a leading U+200B ZERO WIDTH SPACE | `resultsPerPage`, `startIndex`, `totalResults`, `format`, `version`, `timestamp`, `vulnerabilities` |

Making either one "pass" would require fabricating an entire `bomFormat`/`spdxVersion`
SBOM structure, which would be inventing data — so they were moved here instead of
edited. Every file that remains directly under `samples/` is a real SBOM and passes
all 8 stages (0 errors; some carry non-blocking NTIA `W100` supplier-missing warnings).
