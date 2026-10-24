"""Use cases — orchestrate ports without importing adapters."""

from .bootstrap import BootstrapMirror
from .facade import (
    NvdLookupService,
    SessionScopedNvdLookupService,
    build_nvd_lookup_for_pipeline,
)
from .freshness import compute_freshness
from .incremental import IncrementalMirror
from .query import QueryMirror

__all__ = [
    "BootstrapMirror",
    "IncrementalMirror",
    "NvdLookupService",
    "QueryMirror",
    "SessionScopedNvdLookupService",
    "build_nvd_lookup_for_pipeline",
    "compute_freshness",
]
