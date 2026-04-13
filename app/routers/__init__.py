"""
Router package for SBOM Analyzer API.

Exposes all router modules for clean import and integration.
"""

from . import analysis, analyze_endpoints, dashboard, dashboard_main, health, pdf, projects, runs, sbom, sboms_crud

__all__ = [
    "health",
    "sboms_crud",
    "runs",
    "projects",
    "analyze_endpoints",
    "pdf",
    "dashboard_main",
    "analysis",
    "sbom",
    "dashboard",
]
