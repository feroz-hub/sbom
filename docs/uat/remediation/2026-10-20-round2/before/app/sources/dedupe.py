"""Compatibility entry point for the shared reconciliation policy."""
from .reconciliation import reconcile as deduplicate_findings

__all__ = ["deduplicate_findings"]
