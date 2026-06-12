# Component Lifecycle Enrichment

## Terms

- **EOL**: End of Life. The lifecycle source says the release or cycle has reached its end-of-life date.
- **EOS**: End of Support. The lifecycle source says standard support has ended.
- **EOF**: End of Fix or End of Full Support, when the source exposes that distinction.
- **Deprecated**: A package registry marks the package or version as deprecated, yanked, or deprecated by policy.
- **Unsupported**: A reliable source or manual override says the component is no longer supported.
- **Possibly Unmaintained**: Repository or metadata signals suggest maintenance risk, but no reliable source proves EOL/EOS/EOF or unsupported status.
- **Unknown**: No reliable lifecycle data was found.

Lifecycle status is different from VEX status. Lifecycle answers whether a
component version is still supported. VEX answers whether this product/context
is actually affected by a vulnerability. See
[vex-integration.md](vex-integration.md).

## Data Sources

Lifecycle enrichment runs through provider classes under `app/services/lifecycle/`.

Provider priority:

1. **Manual Override**: highest priority. Used when an admin/user has supplied a status, dates, reason, and optional evidence URL.
2. **endoflife.date**: authoritative lifecycle dates for runtimes, platforms, frameworks, databases, and operating systems such as Node.js, Python, Java, .NET, Angular, Django, Spring Framework, Ubuntu, Debian, PostgreSQL, MySQL, and Kubernetes.
3. **deps.dev**: package/version metadata for supported open-source ecosystems. Explicit deprecation is lifecycle evidence; advisory/latest-version metadata is recommendation evidence only.
4. **Package registries**: package ecosystem metadata. Current production support includes npm deprecation, PyPI latest/yanked release signals, NuGet deprecation metadata, and Maven latest-version metadata.
5. **Repository health**: conservative repository support signals when a registry or external reference exposes a repository URL. GitHub archived/disabled repositories can mark a component `Unsupported`; stale activity is stored as maintenance evidence only.
6. **OSV**: vulnerability and fixed-version recommendations only. OSV does not mark lifecycle status as EOL/EOS.

## Decision Rules

- Manual overrides are never overwritten by provider refreshes.
- endoflife.date dates can mark `EOL`, `EOS`, `EOF`, `EOL Soon`, or `Supported`.
- A component is `EOL Soon` when a matched EOL date is within 180 days.
- Registry deprecation/yanked metadata marks `Deprecated`.
- Archived or disabled source repositories mark `Unsupported` with medium confidence.
- Old package age alone does not mark a component EOL or unsupported.
- Stale repository activity alone sets `maintenance_status = Possibly Unmaintained`; it does not mark EOL.
- `Possibly Unmaintained` may be surfaced as a lifecycle governance status/count, but it is not equivalent to `Unsupported`.
- OSV findings can set `recommended_version` and `recommendation`, but lifecycle status remains `Unknown` unless another provider supplies status evidence.
- Every stored lifecycle result includes source, confidence, checked time, and evidence JSON when available.

## Confidence

- **High**: manual override with evidence URL, or authoritative lifecycle date source with matched cycle.
- **Medium**: registry deprecation/yanked metadata or manual override without external evidence.
- **Low**: registry latest-version or OSV recommendation without lifecycle status proof.
- **Unknown**: no reliable source result.

## Cache Behavior

Lifecycle lookups are cached in `component_lifecycle_cache`.

- Default TTL: 7 days.
- Cache key: PURL when present, CPE when present, otherwise normalized ecosystem, name, version, and supplier. The version remains part of the identity, so the same package at two versions receives separate lifecycle decisions.
- Non-expired cache entries prevent repeated external API calls.
- If a cache entry is expired and providers return no data or fail, the old cache result is reused and the component is marked stale.
- Manual overrides are component-local and are not written to the shared provider cache.

## Manual Overrides

Use:

- `PATCH /api/components/{component_id}/lifecycle-override`
- Legacy-compatible `PUT /api/lifecycle/component/{component_id}`

Override fields:

- `lifecycle_status`
- `eos_date`
- `eol_date`
- `eof_date`
- `maintenance_status`
- `latest_supported_version`
- `latest_version`
- `recommended_version`
- `unsupported`
- `recommendation`
- `reason`
- `evidence_url`
- `updated_by`

Allowed statuses:

- `Supported`
- `EOL`
- `EOS`
- `EOF`
- `Deprecated`
- `Unsupported`
- `EOL Soon`
- `Unknown`
- `Possibly Unmaintained`

Every override requires a `reason`, writes an `audit_log` row for backward
compatibility, and writes a dedicated
`component_lifecycle_override_audit` row with old/new lifecycle state.

## APIs

- `GET /api/sboms/{sbom_id}/components`: includes lifecycle fields on each component.
- `POST /api/sboms/{sbom_id}/lifecycle/refresh`: refreshes lifecycle data for all components in an SBOM.
- `POST /api/components/{component_id}/lifecycle/refresh`: refreshes one component.
- `PATCH /api/components/{component_id}/lifecycle-override`: applies an audited manual override.
- `GET /dashboard/lifecycle`: returns lifecycle dashboard counts, top risky components, stale counts, and recommended upgrades.
- `GET /api/sboms/{sbom_id}/lifecycle/report`: returns a detailed JSON lifecycle report.
- `GET /dashboard/vex`: returns VEX exploitability counts separately from lifecycle risk.

## Export

CycloneDX JSON native exports include lifecycle metadata as component properties when the augmented document validates:

- `lifecycle:status`
- `lifecycle:eol`
- `lifecycle:eos`
- `lifecycle:eof`
- `lifecycle:unsupported`
- `lifecycle:latest_version`
- `lifecycle:source`
- `lifecycle:confidence`
- `lifecycle:recommendation`

SPDX JSON exports attempt to include lifecycle annotations. If augmentation would make the stored SBOM invalid, export falls back to the original valid native document. The lifecycle report endpoint is the canonical fallback for formats that cannot safely represent lifecycle metadata.

## Known Limitations

- endoflife.date product matching uses a conservative slug map; unknown products fall through to registries/OSV.
- Package age is intentionally not treated as EOL evidence.
- Repository health currently supports GitHub API signals. Other repository hosts are preserved in evidence and return `Unknown`.
- npm, PyPI, NuGet, and Maven are implemented first; other ecosystems normalize to the provider interface but may return `Unknown`.
- Provider calls are synchronous inside the current request flow. A future background enrichment job should move refreshes off the upload path for very large SBOMs.
- Authorization remains at the existing API protection layer; role-based lifecycle override permissions should be added before multi-tenant production use.
