"""Provider-independent vulnerability applicability checks.

This module is intentionally small and conservative. Provider adapters may
retrieve advisory candidates, but they must ask this module whether the
installed component is actually affected before emitting a confirmed finding.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .version_range import ApplicabilityResult, ApplicabilityStatus

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class NormalizedComponent:
    name: str
    version: str | None
    ecosystem: str | None = None
    purl: str | None = None
    normalized_name: str | None = None


@dataclass(frozen=True, slots=True)
class NormalizedAdvisory:
    provider: str
    advisory_id: str | None
    package_name: str | None
    ecosystem: str | None = None
    vulnerable_range: str | None = None
    fixed_version: str | None = None


_ECOSYSTEM_ALIASES = {
    "pip": "pypi",
    "pypi": "pypi",
    "python": "pypi",
    "npm": "npm",
    "maven": "maven",
    "go": "golang",
    "golang": "golang",
    "rubygems": "rubygems",
    "gem": "rubygems",
    "nuget": "nuget",
    "composer": "composer",
    "rust": "cargo",
    "cargo": "cargo",
    "crates": "cargo",
}

_GITHUB_RANGE_TOKEN_RE = re.compile(r"^(<=|>=|<|>|=|==)\s*(.+)$")


def normalize_ecosystem(value: str | None) -> str:
    text = (value or "").strip().lower()
    return _ECOSYSTEM_ALIASES.get(text, text)


def normalize_package_name(ecosystem: str | None, name: str | None) -> str:
    text = (name or "").strip()
    if normalize_ecosystem(ecosystem) == "pypi":
        return canonicalize_name(text)
    return text.lower()


def evaluate_fixed_version_fallback(
    installed_version: str | None,
    fixed_version: str | None,
    *,
    ecosystem: str | None = "pypi",
) -> ApplicabilityResult:
    if not fixed_version:
        return ApplicabilityResult(
            status=ApplicabilityStatus.UNKNOWN,
            reason="No affected range or fixed version",
        )
    if not installed_version:
        return ApplicabilityResult(
            status=ApplicabilityStatus.UNKNOWN,
            reason="Installed version is missing",
            fixed_version=fixed_version,
        )

    try:
        installed = _parse_version(ecosystem, installed_version)
        fixed = _parse_version(ecosystem, fixed_version)
    except InvalidVersion as exc:
        return ApplicabilityResult(
            status=ApplicabilityStatus.UNKNOWN,
            reason=f"Invalid version: {exc}",
            fixed_version=fixed_version,
        )

    if installed >= fixed:
        return ApplicabilityResult(
            status=ApplicabilityStatus.NOT_AFFECTED,
            reason=f"Installed version {installed} is greater than or equal to patched version {fixed}",
            fixed_version=str(fixed),
        )

    return ApplicabilityResult(
        status=ApplicabilityStatus.AFFECTED,
        reason=f"Installed version {installed} is below patched version {fixed}",
        fixed_version=str(fixed),
    )


def evaluate_github_vulnerable_range(
    installed_version: str | None,
    vulnerable_range: str | None,
    *,
    ecosystem: str | None = "pypi",
) -> ApplicabilityResult:
    range_text = (vulnerable_range or "").strip()
    if not range_text:
        return ApplicabilityResult(
            status=ApplicabilityStatus.UNKNOWN,
            reason="No vulnerable version range",
        )
    if not installed_version:
        return ApplicabilityResult(
            status=ApplicabilityStatus.UNKNOWN,
            reason="Installed version is missing",
            matched_range=range_text,
        )

    try:
        installed = _parse_version(ecosystem, installed_version)
        spec = SpecifierSet(_github_range_to_pep440(range_text))
    except (InvalidSpecifier, InvalidVersion, ValueError) as exc:
        return ApplicabilityResult(
            status=ApplicabilityStatus.UNKNOWN,
            reason=f"Invalid vulnerable version range: {exc}",
            matched_range=range_text,
        )

    if installed in spec:
        return ApplicabilityResult(
            status=ApplicabilityStatus.AFFECTED,
            reason=f"Installed version {installed} satisfies vulnerable range {range_text}",
            matched_range=range_text,
        )

    return ApplicabilityResult(
        status=ApplicabilityStatus.NOT_AFFECTED,
        reason=f"Installed version {installed} does not satisfy vulnerable range {range_text}",
        matched_range=range_text,
    )


def evaluate_applicability(
    component: NormalizedComponent,
    advisory: NormalizedAdvisory,
) -> ApplicabilityResult:
    component_ecosystem = normalize_ecosystem(component.ecosystem)
    advisory_ecosystem = normalize_ecosystem(advisory.ecosystem)
    if component_ecosystem and advisory_ecosystem and component_ecosystem != advisory_ecosystem:
        return ApplicabilityResult(
            status=ApplicabilityStatus.NOT_AFFECTED,
            reason=f"Ecosystem mismatch: component={component_ecosystem} advisory={advisory_ecosystem}",
        )

    ecosystem = component_ecosystem or advisory_ecosystem
    component_name = normalize_package_name(ecosystem, component.normalized_name or component.name)
    advisory_name = normalize_package_name(ecosystem, advisory.package_name)
    if component_name and advisory_name and component_name != advisory_name:
        return ApplicabilityResult(
            status=ApplicabilityStatus.NOT_AFFECTED,
            reason=f"Package mismatch: component={component_name} advisory={advisory_name}",
        )

    if advisory.vulnerable_range:
        range_result = evaluate_github_vulnerable_range(
            component.version,
            advisory.vulnerable_range,
            ecosystem=ecosystem,
        )
        if range_result.status != ApplicabilityStatus.AFFECTED:
            return range_result

        if advisory.fixed_version:
            fixed_result = evaluate_fixed_version_fallback(
                component.version,
                advisory.fixed_version,
                ecosystem=ecosystem,
            )
            if fixed_result.status == ApplicabilityStatus.NOT_AFFECTED:
                return ApplicabilityResult(
                    status=ApplicabilityStatus.UNKNOWN,
                    reason=(
                        "Vulnerable range includes installed version but fixed version "
                        "fallback says installed version is patched"
                    ),
                    matched_range=range_result.matched_range,
                    fixed_version=fixed_result.fixed_version,
                )
        return ApplicabilityResult(
            status=ApplicabilityStatus.AFFECTED,
            reason=range_result.reason,
            matched_range=range_result.matched_range,
            fixed_version=advisory.fixed_version,
        )

    return evaluate_fixed_version_fallback(
        component.version,
        advisory.fixed_version,
        ecosystem=ecosystem,
    )


def log_candidate_decision(
    *,
    provider: str,
    component: NormalizedComponent,
    advisory: NormalizedAdvisory,
    result: ApplicabilityResult,
    persisted: bool,
) -> None:
    if not _diagnostics_enabled():
        return
    log.info(
        "applicability_decision",
        extra={
            "provider": provider,
            "component": component.name,
            "installed_version": component.version,
            "ecosystem": component.ecosystem,
            "purl": component.purl,
            "advisory_id": advisory.advisory_id,
            "vulnerable_range": advisory.vulnerable_range,
            "fixed_version": advisory.fixed_version,
            "applicability_status": result.status.value,
            "applicability_reason": result.reason,
            "persisted": persisted,
        },
    )


def _diagnostics_enabled() -> bool:
    return (os.getenv("APPSEC_APPLICABILITY_DIAGNOSTICS") or "").strip().lower() in {"1", "true", "yes", "on"}


def _parse_version(ecosystem: str | None, value: str) -> Version:
    # Today PyPI is the high-risk path and uses PEP 440. Other ecosystems keep
    # the same conservative parser until dedicated adapters are introduced.
    return Version(value)


def _github_range_to_pep440(range_text: str) -> str:
    text = range_text.strip()
    if not text:
        raise ValueError("empty range")

    if " - " in text:
        left, right = [part.strip() for part in text.split(" - ", 1)]
        if not left or not right:
            raise ValueError(f"malformed hyphen range: {range_text}")
        return f">={left},<={right}"

    specifiers: list[str] = []
    for raw_part in text.split(","):
        part = raw_part.strip()
        if not part:
            continue
        match = _GITHUB_RANGE_TOKEN_RE.match(part)
        if not match:
            raise ValueError(f"unsupported range token: {part}")
        op, version = match.groups()
        version = version.strip()
        if not version:
            raise ValueError(f"missing version in range token: {part}")
        if op == "=":
            op = "=="
        specifiers.append(f"{op}{version}")
    if not specifiers:
        raise ValueError(f"malformed range: {range_text}")
    return ",".join(specifiers)
