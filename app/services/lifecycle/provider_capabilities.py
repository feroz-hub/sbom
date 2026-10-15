"""Backend-owned provider capabilities; also consumed by the configuration UI."""

from ...settings import get_settings


def provider_capabilities(key):
    entries = {
        "redhat_lifecycle": (
            "Static Reference",
            "https://access.redhat.com/support/policy/updates/errata",
            "RHEL 7–9 only; embedded reference, freshness unverified",
        ),
        "official_vendor_lifecycle": ("Unsupported", None, "Placeholder: no live vendor integration implemented"),
        "endoflife_date": ("API", "https://endoflife.date/api", "Mapped product release cycles"),
        "deps_dev": (
            "API",
            "https://api.deps.dev/v3",
            "npm, PyPI, Maven, Go, NuGet, Cargo metadata; no support inference",
        ),
        "osv": (
            "API",
            "https://api.osv.dev/v1/query",
            "Vulnerability advisories only; does not establish lifecycle support",
        ),
        "package_registry": (
            "Registry",
            "npm / PyPI / NuGet / Maven Central / RubyGems",
            "Registry deprecation and release metadata",
        ),
        "repository_health": (
            "API",
            "GitHub / GitLab / Bitbucket public APIs",
            "Archive and activity signals; inactivity does not establish EOL",
        ),
        "openeox": ("Custom Feed", None, "Configured OpenEoX-compatible JSON feeds"),
        "xeol_api": ("API", "https://edb-prod.xeol.io/eol/check", "Xeol component lookup; credentials may be required"),
        "xeol_db": ("Local DB", None, "Readable Xeol SQLite or JSON export"),
        "custom_vendor_records": ("Local DB", "Lifecycle vendor records", "Administrator-maintained records"),
    }
    source, endpoint, coverage = entries[key]
    settings = get_settings()
    return {
        "runtime_name": {"custom_vendor_records": "Vendor Lifecycle", "xeol_api": "Xeol", "xeol_db": "Xeol DB"}.get(
            key
        ),
        "data_source_type": source,
        "effective_endpoint": endpoint,
        "coverage": coverage,
        "implemented": key != "official_vendor_lifecycle",
        "editable_endpoint": key in {"endoflife_date", "xeol_api"},
        "feed_urls": key == "openeox",
        "config_fields": ["db_path"] if key == "xeol_db" else [],
        "secret_name": {"xeol_api": "api_key", "repository_health": "github_token"}.get(key),
        "sync_action": "reload_cache" if key == "xeol_db" else None,
        "network": source in {"API", "Registry", "Custom Feed"},
        "circuit_state_scope": "process-local, isolated by effective configuration",
        "cache_defaults": {
            "known_days": settings.lifecycle_cache_ttl_known_days,
            "unknown_hours": settings.lifecycle_cache_ttl_unknown_hours,
            "failure_minutes": settings.lifecycle_cache_ttl_provider_failure_minutes,
            "deprecated_days": settings.lifecycle_cache_ttl_deprecated_days,
        },
    }
