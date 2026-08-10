# Component Deduplication

## Overview

The SBOM Analyzer implements a robust, safe component deduplication pipeline (Stage 9) to address the issue where duplicate component definitions exist within the same uploaded SBOM. 

Without deduplication, duplicate components inflate dashboard metrics, result in duplicate vulnerability records, cause redundant security scans, and violate database uniqueness expectations.

## Component Identity Rules

Two components are considered identical if they match any of the following three identity rules (checked in descending order of precedence):

1. **Primary: Normalized Package URL (PURL)**
   - Formatted as `purl:{ecosystem}:{namespace}:{name}:{version}`.
   - PURLs are lowercased and namespaces/names are normalized.
2. **Secondary: Normalized Common Platform Enumeration (CPE)**
   - Formatted as `cpe:{cpe_2.3_value}`.
   - CPE values are lowercased and stripped.
3. **Fallback: Identity Key**
   - Formatted as `fallback:{supplier}:{name}:{version}:{type}:{hashes_str}`.
   - Fields are normalized, stripped, and lowercased.
   - Hashes are sorted alphabetically by algorithm and joined to ensure deterministic ordering.

## Merge Behavior

When duplicates are detected, one component is selected as the **canonical (first-seen / most-complete)** representation, and the rest are marked as duplicates. The canonical component absorbs missing attributes from its duplicates:

- **Licenses**: Unions the non-empty licenses. If licenses differ, a conflict is recorded in the report, and the first-seen license is kept.
- **Hashes**: Unions all unique hash algorithms and content values.
- **External References**: Combines all unique external references by URL.
- **Properties**: Combines all unique custom properties by property name.
- **Supplier**: Keeps the longest/most complete supplier name. If supplier names conflict, a conflict is recorded, and the canonical supplier name is kept.
- **Scope & Type/Group**: Keeps the values from the canonical component, falling back to the duplicate if missing in the canonical.

## Dependency Remapping

To preserve the integrity of the dependency graph:
- All dependency relationships in the SBOM (both CycloneDX `dependsOn` arrays and SPDX `relationships` definitions) referencing any duplicate components are remapped to point directly to the canonical component's `bom-ref` or `SPDXID`.
- Remapped lists are deduplicated to avoid duplicate dependencies or schema violations (e.g. CycloneDX `dependsOn` uniqueness requirement).
- Self-dependencies resulting from merges are automatically filtered out.

## Database Storage

Instead of silently discarding duplicate rows, the database stores all component definitions for auditability and compliance, but flags them:
- **Canonical Component**: Saved with `is_duplicate = False` and `duplicate_of_component_id = None`.
- **Duplicate Component**: Saved with `is_duplicate = True` and `duplicate_of_component_id` pointing to the database ID of its canonical counterpart.
- **Deduplication Report**: Saved as `dedupe_report_json` on the `sbom_source` record, tracking the number of duplicates found/merged, resolved conflicts, and ref mappings.

## API Integration

- **GET `/api/sboms/{id}/components`**: Filters out duplicates (`is_duplicate = False`) by default. Passing `include_duplicates=true` returns the full components list, including flagged duplicates.
- **GET `/api/sboms/{id}/dedupe-report`**: Returns the saved deduplication report JSON.
- **Vulnerability Scanning**: The downstream security analysis process only scans canonical components, avoiding redundant API calls and preventing duplicate finding rows.
- **Lifecycle Enrichment**: Only enriches canonical components, avoiding uniqueness constraint violations on `component_lifecycle_cache`.

## Export Modes

When exporting an SBOM via `GET `/api/sboms/{id}/export`, two modes are supported:
1. **`export_mode=original` (Default)**: Returns the original uploaded SBOM raw text exactly as it was, maintaining raw integrity.
2. **`export_mode=normalized`**: Generates a clean, deduplicated SBOM doc containing only canonical components, merged licenses and hashes, and fully remapped/deduplicated dependency graphs.
