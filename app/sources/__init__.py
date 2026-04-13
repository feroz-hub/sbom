"""
Vulnerability source adapter package — peer of ``app/services/``.

Hosts the canonical implementations of the helpers that were previously
inlined inside ``app/analysis.py`` plus the per-source adapter classes
(``NvdSource``, ``OsvSource``, ``GhsaSource``), the registry that maps
canonical source names to those classes, and the concurrent fan-out
runner used by every analyze endpoint.

Layout:

    purl.py        — `parse_purl` (PURL spec parser)
    cpe.py         — `slug`, `cpe23_from_purl` (PURL → CPE 2.3 generator)
    severity.py    — CVSS helpers, severity bucketing, GH severity normaliser
    dedupe.py      — two-pass CVE↔GHSA alias cross-deduplication
    base.py        — `VulnSource` Protocol + `SourceResult` TypedDict
    nvd.py         — `NvdSource(api_key=...)`
    osv.py         — `OsvSource()`
    ghsa.py        — `GhsaSource(token=...)`
    registry.py    — `SOURCE_REGISTRY`, `get_source(name)`
    runner.py      — `run_sources_concurrently(sources, components, settings, ...)`

This package lives at ``app.sources`` (a top-level peer of ``app.services``)
rather than under ``app.services`` because ``app.services.__init__`` eagerly
imports ``analysis_service``, which would create a circular import any time
``app.analysis`` was loaded as a module entrypoint.

Adding a fourth source (e.g. Snyk, OSS Index) is a one-line change in
``registry.py`` plus one new module here. Neither the routers nor the
shared runner need to know about it.
"""

# Phase 2: source adapter classes + registry
from .base import SourceResult, VulnSource, empty_result
from .cpe import cpe23_from_purl, slug
from .dedupe import deduplicate_findings
from .ghsa import GhsaSource
from .nvd import NvdSource
from .osv import OsvSource
from .purl import parse_purl
from .registry import SOURCE_REGISTRY, get_source

# Phase 3: shared concurrent fan-out runner
from .runner import (
    EVENT_COMPLETE,
    EVENT_DONE,
    EVENT_ERROR,
    EVENT_RUNNING,
    run_sources_concurrently,
)
from .severity import (
    GH_SEV_NORM,
    cvss_version_from_metrics,
    extract_best_cvss,
    parse_cvss_attack_vector,
    safe_score,
    sev_bucket,
)

__all__ = [
    # Phase 1 utilities
    "parse_purl",
    "slug",
    "cpe23_from_purl",
    "safe_score",
    "parse_cvss_attack_vector",
    "cvss_version_from_metrics",
    "extract_best_cvss",
    "sev_bucket",
    "GH_SEV_NORM",
    "deduplicate_findings",
    # Phase 2 source adapters
    "SourceResult",
    "VulnSource",
    "empty_result",
    "NvdSource",
    "OsvSource",
    "GhsaSource",
    "SOURCE_REGISTRY",
    "get_source",
    # Phase 3 runner
    "run_sources_concurrently",
    "EVENT_RUNNING",
    "EVENT_COMPLETE",
    "EVENT_ERROR",
    "EVENT_DONE",
]
