"""Component normalization for lifecycle enrichment providers."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote

try:  # pragma: no cover - exercised when packageurl is installed.
    from packageurl import PackageURL
except ModuleNotFoundError:  # pragma: no cover - fallback covered via parse_purl tests.

    class PackageURL:  # type: ignore[no-redef]
        def __init__(
            self,
            *,
            type: str,
            name: str,
            namespace: str | None = None,
            version: str | None = None,
        ) -> None:
            self.type = type
            self.name = name
            self.namespace = namespace
            self.version = version

        @classmethod
        def from_string(cls, value: str) -> PackageURL:
            if not value.startswith("pkg:"):
                raise ValueError("Invalid purl")
            body = value[4:].split("?", 1)[0]
            package_type, _, remainder = body.partition("/")
            if not package_type or not remainder:
                raise ValueError("Invalid purl")
            path, _, version = remainder.rpartition("@")
            if not path:
                path = remainder
                version = ""
            segments = [unquote(segment) for segment in path.split("/") if segment]
            if not segments:
                raise ValueError("Invalid purl")
            name = segments[-1]
            namespace = "/".join(segments[:-1]) or None
            return cls(type=package_type, namespace=namespace, name=name, version=unquote(version) or None)


from .aliases import apply_alias_to_component_fields
from .types import NormalizedComponent, canonical_ecosystem


def normalize_component(component: Any) -> NormalizedComponent:
    """Normalize an ORM component or component-like object for providers."""

    raw_name = (getattr(component, "name", None) or "").strip()
    raw_version = _clean_version(getattr(component, "version", None))
    raw_purl = _clean_str(getattr(component, "purl", None))
    raw_cpe = _clean_str(getattr(component, "cpe", None))
    supplier = _clean_str(getattr(component, "supplier", None))
    component_type = _clean_str(getattr(component, "component_type", None))
    component_group = _clean_str(getattr(component, "component_group", None))
    ecosystem = canonical_ecosystem(getattr(component, "ecosystem", None) or component_type or component_group)
    normalized_name = raw_name.lower()
    normalized_version = raw_version

    if raw_purl:
        parsed = parse_purl(raw_purl)
        if parsed:
            ecosystem = canonical_ecosystem(parsed.type)
            purl_name = _name_from_purl(parsed)
            normalized_name = purl_name.lower() if purl_name else normalized_name
            normalized_version = _clean_version(parsed.version) or raw_version
            identity_method = "purl"
        else:
            identity_method = "name_version"
    elif raw_cpe:
        parsed_cpe = parse_cpe(raw_cpe)
        normalized_name = parsed_cpe.get("product") or normalized_name
        normalized_version = _clean_version(parsed_cpe.get("version")) or raw_version
        identity_method = "cpe"
    else:
        identity_method = "ecosystem_name_version" if ecosystem != "generic" else "name_version"

    if ecosystem == "generic":
        ecosystem = infer_ecosystem(raw_name, supplier, component_type, component_group, raw_cpe)

    if raw_name:
        normalized_name = normalize_component_name(normalized_name or raw_name, ecosystem)
        canonical_name, alias_ecosystem, _provider_slug = apply_alias_to_component_fields(normalized_name, ecosystem)
        normalized_name = canonical_name
        if alias_ecosystem != "generic":
            ecosystem = alias_ecosystem

    return NormalizedComponent(
        component_id=getattr(component, "id", None),
        name=raw_name,
        version=raw_version,
        normalized_name=normalized_name,
        normalized_version=normalized_version,
        ecosystem=ecosystem,
        purl=raw_purl,
        cpe=raw_cpe,
        supplier=supplier,
        component_type=component_type,
        component_group=component_group,
        repository_url=_repository_url_from_component(component),
        external_references=[],
        identity_method=identity_method,
    )


def parse_purl(value: str | None) -> PackageURL | None:
    """Parse a Package URL, returning ``None`` instead of raising."""
    if not value:
        return None
    try:
        return PackageURL.from_string(value)
    except Exception:
        return None


def parse_cpe(value: str | None) -> dict[str, str]:
    """Parse common CPE 2.2/2.3 fields into a small normalized dict."""
    if not value:
        return {}
    text = value.strip()
    parts = text.split(":")
    if len(parts) >= 13 and parts[0] == "cpe" and parts[1] == "2.3":
        return {
            "part": parts[2],
            "vendor": _cpe_unescape(parts[3]),
            "product": normalize_component_name(_cpe_unescape(parts[4])),
            "version": _cpe_unescape(parts[5]),
        }
    if len(parts) >= 6 and parts[0] == "cpe" and parts[1].startswith("/"):
        return {
            "part": parts[1].lstrip("/"),
            "vendor": _cpe_unescape(parts[2]),
            "product": normalize_component_name(_cpe_unescape(parts[3])),
            "version": _cpe_unescape(parts[4]),
        }
    return {}


def normalize_ecosystem(value: str | None) -> str:
    """Return the canonical lifecycle ecosystem name."""
    return canonical_ecosystem(value)


def normalize_component_name(value: str | None, ecosystem: str | None = None) -> str:
    """Normalize a component name for lifecycle lookups."""
    cleaned = (value or "").strip().lower()
    if not cleaned:
        return ""
    eco = canonical_ecosystem(ecosystem)
    if eco == "npm" and cleaned.startswith("%40"):
        cleaned = "@" + cleaned[3:]
    if eco == "maven":
        cleaned = cleaned.replace(":", "/")
    return re.sub(r"\s+", "-", cleaned)


def _name_from_purl(purl: PackageURL) -> str:
    name = purl.name or ""
    namespace = purl.namespace or ""
    if purl.type == "npm" and namespace:
        return f"@{namespace.lstrip('@')}/{name}"
    if purl.type in {"maven", "golang", "go", "nuget"} and namespace:
        return f"{namespace}/{name}"
    return name


def _clean_str(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _clean_version(value: Any) -> str | None:
    cleaned = _clean_str(value)
    if not cleaned:
        return None
    if cleaned.lower().startswith("version "):
        cleaned = cleaned[8:].strip()
    if cleaned.startswith("v") and len(cleaned) > 1 and cleaned[1].isdigit():
        cleaned = cleaned[1:]
    return cleaned or None


def infer_ecosystem(
    name: str,
    supplier: str | None,
    component_type: str | None,
    component_group: str | None,
    cpe: str | None,
) -> str:
    name_low = name.lower()
    supplier_low = (supplier or "").lower()
    group_low = (component_group or "").lower()
    cpe_low = (cpe or "").lower()

    haystack = " ".join(part for part in (name, supplier or "", component_type or "", component_group or "") if part)
    lowered = haystack.lower()

    # 1. Direct matches on names of known platforms/runtimes
    if name_low in {"node", "nodejs", "javascript", "js", "typescript", "ts"}:
        return "npm"
    if name_low in {"python", "pip"}:
        return "pypi"
    if name_low in {"maven", "java", "openjdk", "jdk"}:
        return "maven"
    if name_low in {"nuget", "dotnet", ".net", "c#"}:
        return "nuget"

    # 2. Check for npm
    npm_libs = {
        "lodash",
        "express",
        "axios",
        "react",
        "angular",
        "vue",
        "uuid",
        "chalk",
        "commander",
        "tslib",
        "semver",
        "debug",
        "moment",
        "webpack",
    }
    if (
        re.search(r"(^|[-_/])npm($|[-_/])", lowered)
        or name_low.startswith("@")
        or name_low.startswith("%40")
        or name_low in npm_libs
        or "node" in supplier_low
        or "npm" in supplier_low
        or "javascript" in lowered
    ):
        return "npm"

    # 3. Check for pypi
    pypi_libs = {
        "requests",
        "urllib3",
        "django",
        "flask",
        "numpy",
        "pandas",
        "cryptography",
        "pillow",
        "jinja2",
        "click",
        "six",
        "certifi",
        "attrs",
        "idna",
        "pip",
        "setuptools",
    }
    if (
        "pypi" in lowered
        or name_low.startswith("python-")
        or name_low in pypi_libs
        or "python" in supplier_low
        or "pypi" in supplier_low
    ):
        return "pypi"

    # 4. Check for nuget
    nuget_libs = {
        "newtonsoft.json",
        "entityframework",
        "dapper",
        "nlog",
        "log4net",
        "serilog",
        "autofac",
        "moq",
        "xunit",
        "nunit",
    }
    if (
        "nuget" in lowered
        or ".net" in lowered
        or "dotnet" in lowered
        or "microsoft" in lowered
        or name_low in nuget_libs
        or "nuget" in supplier_low
        or "microsoft" in supplier_low
    ):
        return "nuget"

    # 5. Check for maven
    maven_libs = {"log4j-core", "jackson-databind", "spring-core", "spring-webmvc", "spring-boot", "junit", "slf4j"}
    if (
        "maven" in lowered
        or "java" in lowered
        or name_low in maven_libs
        or "apache" in lowered
        or "spring" in lowered
        or "fasterxml" in lowered
        or ":" in name_low
        or (component_group and "." in component_group and " " not in component_group)
    ):
        return "maven"

    # 6. Check for others
    if "rubygems" in lowered or name_low.startswith("ruby-") or "gem" in lowered:
        return "gem"
    if "golang" in lowered or name_low.startswith("golang.org/") or name_low.startswith("github.com/"):
        return "go"
    if "cargo" in lowered or "crates.io" in lowered or "rust" in lowered:
        return "cargo"
    if "ubuntu" in lowered or (cpe and ":ubuntu:" in cpe_low):
        return "ubuntu"
    if "debian" in lowered or (cpe and ":debian:" in cpe_low):
        return "debian"
    if "alpine" in lowered or (cpe and ":alpine:" in cpe_low):
        return "alpine"
    if "docker" in lowered or (component_type and component_type.lower() == "container"):
        return "docker"

    return "generic"


def build_lifecycle_lookup_key(component: NormalizedComponent) -> str:
    """Build a stable lookup key for cache/provider identity.

    PURL is primary, CPE secondary, and ecosystem/name/version fallback. The
    version and ecosystem are included so same-name components in different
    ecosystems or versions never collapse into one cache entry.
    """
    if component.purl:
        return f"purl:{component.purl.strip().lower()}"
    if component.cpe:
        return f"cpe:{component.cpe.strip().lower()}"
    name = normalize_component_name(component.normalized_name or component.name, component.ecosystem)
    version = (component.normalized_version or "").strip().lower()
    ecosystem = canonical_ecosystem(component.ecosystem)
    supplier = (component.supplier or "").strip().lower()
    return f"fallback:{ecosystem}:{name}:{version}:{supplier}"


def normalize_version(value: Any) -> str | None:
    """Public helper for version normalization used by VEX/vulnerability flows."""
    return _clean_version(value)


def build_vulnerability_lookup_key(component: NormalizedComponent, vulnerability_id: str | None = None) -> str:
    """Build a stable key for component/vulnerability VEX matching."""
    base = build_lifecycle_lookup_key(component)
    vuln = (vulnerability_id or "").strip().upper()
    return f"{base}:vuln:{vuln}"


def _cpe_unescape(value: str) -> str:
    if value in {"*", "-", ""}:
        return ""
    return value.replace("\\:", ":").replace("\\/", "/").strip().lower()


def _repository_url_from_component(component: Any) -> str | None:
    evidence = getattr(component, "lifecycle_evidence_json", None) or {}
    if isinstance(evidence, dict):
        url = evidence.get("repository_url") or evidence.get("repository")
        if isinstance(url, str) and url.strip():
            return url.strip()
    return None


__all__ = [
    "build_lifecycle_lookup_key",
    "build_vulnerability_lookup_key",
    "infer_ecosystem",
    "normalize_component",
    "normalize_component_name",
    "normalize_ecosystem",
    "normalize_version",
    "parse_cpe",
    "parse_purl",
]
