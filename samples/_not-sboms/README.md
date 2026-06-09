# Not an SBOM — kept for reference

`outputsbom.json` was in `samples/` but is **not an SBOM document**, so it can never
pass the 8-stage SBOM validation pipeline (it fails at the **detect** stage with
`SBOM_VAL_E010_FORMAT_INDETERMINATE` — no CycloneDX/SPDX fingerprint). It is the
*output* of other tooling, kept here only as a reference fixture. It is not
referenced by path anywhere in the code or tests.

| File | What it actually is | Top-level keys |
|------|--------------------|----------------|
| `outputsbom.json` | An NVD CVE-API 2.0 response (a vulnerability feed, not a bill of materials) — also carries a leading U+200B ZERO WIDTH SPACE | `resultsPerPage`, `startIndex`, `totalResults`, `format`, `version`, `timestamp`, `vulnerabilities` |

Making it "pass" would mean fabricating an SBOM structure or misrepresenting a CVE
feed as an application's component inventory, so it was kept out of the SBOM set
rather than edited.

> Note: a sibling scan-result file (`app-sbom.json`, a Snyk dependency scan) used to
> live here too. It was **converted** into a real CycloneDX SBOM at
> `samples/app-sbom.cdx.json` (built from the 3 packages its findings named), so the
> raw scan-result copy was removed.

Every file directly under `samples/` is a real SBOM and passes all 8 stages
(0 errors; some carry non-blocking NTIA `W100`/`W103` warnings).
