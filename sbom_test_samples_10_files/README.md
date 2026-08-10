# SBOM Analyzer Test Samples

These 10 SBOM files are designed to test the main SBOM Analyzer features:

1. `01_cyclonedx_lifecycle_runtimes.cdx.json` — lifecycle/EOL/EOS provider testing for runtimes, frameworks, OS, DB.
2. `02_cyclonedx_registry_deprecated_old_packages.cdx.json` — npm/PyPI registry, deps.dev, deprecated/old packages.
3. `03_cyclonedx_duplicate_components.cdx.json` — duplicate component deduplication and dependency remapping.
4. `04_cyclonedx_missing_metadata_completeness.cdx.json` — completeness score, missing supplier/license/hash metadata.
5. `05_cyclonedx_invalid_repair_workspace.cdx.json` — safe invalid SBOM for validation repair workspace.
6. `06_cyclonedx_vulnerable_components_osv.cdx.json` — OSV/vulnerability/fixed-version recommendation flow.
7. `07_cyclonedx_with_vex_analysis.cdx.json` — CycloneDX vulnerability analysis/VEX-like states.
8. `08_spdx_valid_lifecycle.spdx.json` — valid SPDX 2.3 JSON with lifecycle components.
9. `09_spdx_invalid_dangling_relationship.spdx.json` — invalid SPDX with dangling relationship for repair workflow.
10. `10_cyclonedx_mixed_enterprise_app.cdx.json` — mixed ecosystem enterprise app with runtime/library dependencies.

Notes:
- Files 05 and 09 are intentionally invalid/safe to test validation failure and repair workspace.
- EOF may remain empty for most components unless your provider source explicitly supports End-of-Fix/Full-Support dates.
- Many library packages may correctly remain `Unknown` for lifecycle if no reliable lifecycle source exists.
