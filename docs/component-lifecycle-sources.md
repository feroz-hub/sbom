# Component Lifecycle Sources

Lifecycle enrichment is evidence-based. The platform must not mark a component
EOL, EOS, EOF, or Unsupported without provider evidence or an audited manual
override.

## Source Priority

1. Manual lifecycle override.
2. Official lifecycle provider (`endoflife.date`).
3. deps.dev explicit deprecation metadata.
4. Native package registry deprecation/retraction metadata.
5. Repository archived/disabled signal.
6. Repository maintenance health signal.
7. OSV vulnerability/fixed-version recommendation.
8. Unknown fallback.

## Provider Coverage

- `endoflife.date`: runtime/platform/framework/database/OS lifecycle cycles.
- `deps.dev`: npm, PyPI, Maven, Go, NuGet, Cargo package metadata where
  available.
- Native registries: npm, PyPI, NuGet, Maven Central.
- Repository health: GitHub archived/disabled/stale activity signals.
- OSV: vulnerability count and fixed-version recommendations only.

## Non-Evidence

These signals do not independently prove EOL/EOS/EOF:

- Package age.
- A newer package version existing.
- Low repository activity without archived/disabled evidence.
- OSV vulnerability presence.

Use `Unknown` or `Possibly Unmaintained` when evidence is insufficient.

## Cache

Provider results are cached for seven days using PURL, then CPE, then
ecosystem/name/version/supplier identity. Expired cache may be reused as stale
when providers are unavailable.
