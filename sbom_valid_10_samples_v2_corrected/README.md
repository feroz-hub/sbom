# 10 corrected valid CycloneDX SBOM samples

These files are corrected for validators that require every `dependencies[].ref` to exist in `components[].bom-ref`.

Fix applied:
- The root application component is included in BOTH `metadata.component` and `components[]`.
- Every `dependencies[].ref` and `dependsOn[]` target resolves to a declared `components[].bom-ref`.
- Runtime/platform components include generic PURLs to avoid NTIA unique ID warnings.

Feature coverage:
1. Lifecycle/EOL/EOS runtimes and frameworks
2. Registry/deprecated candidates
3. Duplicate identity deduplication with valid references
4. Completeness/metadata
5. Edit/version/project assignment
6. OSV/vulnerable components
7. VEX analysis states
8. Remediation tracking
9. Mixed enterprise portfolio
10. Dashboard full feature sample
