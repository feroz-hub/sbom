"""
Vulnerability source adapter package — peer of ``app/services/``.

Phase 1 (current): hosts the canonical, settings-free helpers that were
previously inlined inside ``app/analysis.py`` and partially duplicated in
``app/services/vuln_sources.py``. ``analysis.py`` re-exports these symbols
under their legacy underscore-prefixed names so existing call sites continue
to work without modification.

This package lives at ``app.sources`` (a top-level peer of ``app.services``)
rather than under ``app.services`` because ``app.services.__init__`` eagerly
imports ``analysis_service``, which would create a circular import any time
``app.analysis`` was loaded as a module entrypoint.

Phase 2 (upcoming) will add per-source adapters here:
``nvd.py``, ``osv.py``, ``ghsa.py``, each implementing a uniform
``async query(components, cfg) -> SourceResult`` contract.
"""

from .purl import parse_purl
from .cpe import slug, cpe23_from_purl
from .severity import (
    safe_score,
    parse_cvss_attack_vector,
    cvss_version_from_metrics,
    extract_best_cvss,
    sev_bucket,
    GH_SEV_NORM,
)
from .dedupe import deduplicate_findings

__all__ = [
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
]
