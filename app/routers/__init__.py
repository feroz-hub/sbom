"""Router package for SBOM Analyzer API."""

__all__ = [
    "ai_copilot",
    "ai_credentials",
    "ai_fixes",
    "ai_usage",
    "analysis",
    "analyze_endpoints",
    "compare",
    "cves",
    "dashboard",
    "dashboard_advanced",
    "dashboard_main",
    "health",
    "kev",
    "lifecycle",
    "lifecycle_admin",
    "pdf",
    "products",
    "projects",
    "remediation",
    "reports",
    "runs",
    "sbom",
    "sbom_upload",
    "sbom_validation_sessions",
    "sbom_versions",
    "sboms_crud",
    "schedules",
    "tenants",
    "vex",
]


def __getattr__(name: str):
    """Lazy-load routers so importing one router has no unrelated side effects."""
    if name not in __all__:
        raise AttributeError(name)
    from importlib import import_module

    module = import_module(f"{__name__}.{name}")
    globals()[name] = module
    return module
