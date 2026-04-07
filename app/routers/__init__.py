"""
Router package for SBOM Analyzer API.

Exposes all router modules for clean import and integration.
"""

from . import health
from . import sboms_crud
from . import runs
from . import projects
from . import analyze_endpoints
from . import pdf
from . import dashboard_main
from . import analysis
from . import sbom
from . import dashboard

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
