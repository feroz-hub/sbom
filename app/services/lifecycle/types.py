"""Lifecycle enrichment value types and status helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

SUPPORTED = "Supported"
EOL = "EOL"
EOS = "EOS"
EOF = "EOF"
DEPRECATED = "Deprecated"
UNSUPPORTED = "Unsupported"
EOL_SOON = "EOL Soon"
POSSIBLY_UNMAINTAINED = "Possibly Unmaintained"
UNKNOWN = "Unknown"

ALLOWED_LIFECYCLE_STATUSES = {
    SUPPORTED,
    EOL,
    EOS,
    EOF,
    DEPRECATED,
    UNSUPPORTED,
    EOL_SOON,
    POSSIBLY_UNMAINTAINED,
    UNKNOWN,
}

HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"
UNKNOWN_CONFIDENCE = "Unknown"

ALLOWED_CONFIDENCE_VALUES = {HIGH, MEDIUM, LOW, UNKNOWN_CONFIDENCE}

STATUS_ALIASES = {
    "active": SUPPORTED,
    "supported": SUPPORTED,
    "ok": SUPPORTED,
    "eol": EOL,
    "end of life": EOL,
    "end-of-life": EOL,
    "eos": EOS,
    "end of support": EOS,
    "end-of-support": EOS,
    "eof": EOF,
    "end of fix": EOF,
    "end-of-fix": EOF,
    "deprecated": DEPRECATED,
    "unsupported": UNSUPPORTED,
    "unmaintained": UNSUPPORTED,
    "eol soon": EOL_SOON,
    "nearing eol": EOL_SOON,
    "possibly unmaintained": POSSIBLY_UNMAINTAINED,
    "possibly unsupported": POSSIBLY_UNMAINTAINED,
    "unknown": UNKNOWN,
}

ECOSYSTEM_ALIASES = {
    "node": "npm",
    "nodejs": "npm",
    "javascript": "npm",
    "js": "npm",
    "python": "pypi",
    "pip": "pypi",
    "pypi": "pypi",
    "maven": "maven",
    "java": "maven",
    "nuget": "nuget",
    "dotnet": "nuget",
    "gem": "gem",
    "rubygems": "gem",
    "go": "go",
    "golang": "go",
    "cargo": "cargo",
    "rust": "cargo",
    "deb": "debian",
    "debian": "debian",
    "ubuntu": "ubuntu",
    "apk": "alpine",
    "alpine": "alpine",
    "oci": "docker",
    "docker": "docker",
    "github": "github",
    "generic": "generic",
}


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def canonical_status(value: str | None) -> str:
    if not value:
        return UNKNOWN
    import re

    # Split camelCase / PascalCase transitions preserving consecutive capitals (e.g. EndOfLife -> End Of Life)
    s = re.sub(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", str(value))
    cleaned = " ".join(s.strip().replace("_", " ").replace("-", " ").split())
    if cleaned in ALLOWED_LIFECYCLE_STATUSES:
        return cleaned

    lower_cleaned = cleaned.lower()
    if lower_cleaned in STATUS_ALIASES:
        return STATUS_ALIASES[lower_cleaned]

    # Fallback substring checks for robustness
    if "eol" in lower_cleaned or "end of life" in lower_cleaned:
        return EOL
    if "eos" in lower_cleaned or "end of support" in lower_cleaned:
        return EOS
    if "eof" in lower_cleaned or "end of fix" in lower_cleaned:
        return EOF
    if "deprecated" in lower_cleaned:
        return DEPRECATED
    if "eol soon" in lower_cleaned or "nearing eol" in lower_cleaned:
        return EOL_SOON
    if "possibly unmaintained" in lower_cleaned:
        return POSSIBLY_UNMAINTAINED
    if "unsupported" in lower_cleaned:
        return UNSUPPORTED
    if "unmaintained" in lower_cleaned:
        return UNSUPPORTED
    return UNKNOWN


def canonical_confidence(value: str | None) -> str:
    if not value:
        return UNKNOWN_CONFIDENCE
    cleaned = str(value).strip().title()
    return cleaned if cleaned in ALLOWED_CONFIDENCE_VALUES else UNKNOWN_CONFIDENCE


def canonical_ecosystem(value: str | None) -> str:
    if not value:
        return "generic"
    cleaned = str(value).strip().lower()
    return ECOSYSTEM_ALIASES.get(cleaned, cleaned if cleaned in ECOSYSTEM_ALIASES.values() else "generic")


@dataclass(slots=True)
class NormalizedComponent:
    component_id: int | None
    name: str
    version: str | None = None
    normalized_name: str = ""
    normalized_version: str | None = None
    ecosystem: str = "generic"
    purl: str | None = None
    cpe: str | None = None
    supplier: str | None = None
    component_type: str | None = None
    component_group: str | None = None
    repository_url: str | None = None
    external_references: list[dict[str, Any]] = field(default_factory=list)
    identity_method: str = "name_version"

    @property
    def cache_identity(self) -> tuple[str, str | None, str, str | None, str | None]:
        return (
            self.normalized_name or self.name.lower(),
            self.normalized_version,
            self.ecosystem or "generic",
            self.purl,
            self.cpe,
        )


@dataclass(slots=True)
class LifecycleResult:
    component_name: str
    component_version: str | None
    ecosystem: str
    purl: str | None
    cpe: str | None = None
    supplier: str | None = None
    repository_url: str | None = None
    lifecycle_status: str = UNKNOWN
    eos_date: str | None = None
    eol_date: str | None = None
    eof_date: str | None = None
    deprecated: bool = False
    unsupported: bool = False
    maintenance_status: str | None = None
    latest_version: str | None = None
    latest_supported_version: str | None = None
    recommended_version: str | None = None
    recommendation: str | None = None
    source_name: str | None = None
    source_url: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: str = UNKNOWN_CONFIDENCE
    checked_at: str = field(default_factory=now_iso)
    expires_at: str | None = None
    stale: bool = False
    manual_override: bool = False
    vulnerability_count: int | None = None

    def canonicalized(self) -> LifecycleResult:
        self.lifecycle_status = canonical_status(self.lifecycle_status)
        self.confidence = canonical_confidence(self.confidence)
        if self.lifecycle_status == DEPRECATED:
            self.deprecated = True
        if self.lifecycle_status in {EOL, EOS, EOF, UNSUPPORTED}:
            self.unsupported = True
        return self

    @property
    def is_actionable(self) -> bool:
        return self.lifecycle_status != UNKNOWN or bool(self.recommended_version or self.recommendation)


@dataclass(slots=True)
class VexResult:
    component_name: str
    component_version: str | None
    vulnerability_id: str
    cve_id: str | None = None
    product_context: str | None = None
    vex_status: str = "unknown"
    vex_justification: str | None = None
    impact_statement: str | None = None
    action_statement: str | None = None
    fixed_version: str | None = None
    mitigation: str | None = None
    source_name: str | None = None
    source_url: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: str = UNKNOWN_CONFIDENCE
    checked_at: str = field(default_factory=now_iso)


def unknown_result(component: NormalizedComponent, source_name: str | None = None) -> LifecycleResult:
    return LifecycleResult(
        component_name=component.normalized_name or component.name,
        component_version=component.normalized_version,
        ecosystem=component.ecosystem,
        purl=component.purl,
        cpe=component.cpe,
        lifecycle_status=UNKNOWN,
        source_name=source_name,
        confidence=UNKNOWN_CONFIDENCE,
    )
