"""Central OSV query-eligibility gate.

Why this module exists
----------------------
OSV's ``/v1/querybatch`` validates every query in the request body and
rejects the WHOLE batch with HTTP 400 when any single one is malformed.
``{"package": {"name": "curl", "ecosystem": "library"}}`` is malformed:
``library`` is a CycloneDX component *classification*, not an OSV
ecosystem. It reaches components through
``app.normalization.component_normalizer.normalize_ecosystem()``, which
falls back to the SBOM component ``type`` (then ``group``) when neither a
PURL nor a real ecosystem was recorded. An SBOM with no PURLs therefore
turned every OSV scan into a 400 and marked the source ERROR — one
unusable component poisoned the batch for all the others.

The rule enforced here: a component is OSV-queryable only when it carries
a real package identity —

  * a syntactically valid PURL (OSV derives the ecosystem itself), or
  * a package name **plus** a recognised OSV ecosystem.

Nothing is invented. If the SBOM did not record a usable identity, the
component is skipped and counted — never guessed at. Callers surface the
skip count in the OSV source summary so "we could not ask" stays visibly
distinct from "we asked and OSV had nothing" and from "OSV failed".

Keep this module dependency-light (``purl`` only) — it is imported from
the analysis hot path.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .purl import parse_purl

# ---------------------------------------------------------------------------
# Skip reasons
# ---------------------------------------------------------------------------

# Aggregate reason recorded on the OSV provider status when NOTHING in the
# SBOM was queryable. Matches the vocabulary of ``routing.NON_ERROR_REASONS``
# in spirit: a skip is not a provider error.
SKIP_REASON_NO_IDENTITY = "missing_supported_package_identity"
SKIP_REASON_MISSING_NAME = "missing_package_name"
SKIP_REASON_UNSUPPORTED_ECOSYSTEM = "unsupported_ecosystem"
SKIP_REASON_PLACEHOLDER_VERSION = "placeholder_version"

# ---------------------------------------------------------------------------
# Recognised OSV ecosystems (OSV schema, ``affected[].package.ecosystem``)
# ---------------------------------------------------------------------------

# Canonical spelling keyed by lowercase form. OSV ecosystem names are
# case-sensitive at the API ("PyPI", not "pypi"), so recognising a value
# also means normalising it to the spelling OSV publishes.
_CANONICAL_OSV_ECOSYSTEMS: dict[str, str] = {
    eco.lower(): eco
    for eco in (
        "AlmaLinux",
        "Alpaquita",
        "Alpine",
        "Android",
        "Bioconductor",
        "Bitnami",
        "Chainguard",
        "ConanCenter",
        "CRAN",
        "crates.io",
        "Debian",
        "Echo",
        "GIT",
        "GitHub Actions",
        "Go",
        "Hackage",
        "Hex",
        "Kubernetes",
        "Linux",
        "Mageia",
        "Maven",
        "MinimOS",
        "npm",
        "NuGet",
        "openEuler",
        "openSUSE",
        "OSS-Fuzz",
        "Packagist",
        "Pub",
        "PyPI",
        "Red Hat",
        "Rocky Linux",
        "RubyGems",
        "SUSE",
        "SwiftURL",
        "Ubuntu",
        "Wolfi",
    )
}

# Spellings that unambiguously denote one of the ecosystems above. These
# are PURL types and the normalised forms this codebase already stores
# (see ``component_normalizer.ECOSYSTEM_ALIASES``) — a rename of a known
# registry, not an inference about an unknown component.
_OSV_ECOSYSTEM_ALIASES: dict[str, str] = {
    "apk": "Alpine",
    "cargo": "crates.io",
    "composer": "Packagist",
    "conan": "ConanCenter",
    "crates": "crates.io",
    "deb": "Debian",
    "gem": "RubyGems",
    "github-actions": "GitHub Actions",
    "githubactions": "GitHub Actions",
    "golang": "Go",
    "hackage": "Hackage",
    "oss-fuzz": "OSS-Fuzz",
    "pypi": "PyPI",
    "redhat": "Red Hat",
    "red-hat": "Red Hat",
    "rhel": "Red Hat",
    "rocky": "Rocky Linux",
    "rockylinux": "Rocky Linux",
    "rubygems": "RubyGems",
    "swift": "SwiftURL",
}

# SBOM component classifications, packaging words and null-ish markers that
# are NOT OSV ecosystems. Sending any of these as ``package.ecosystem`` is
# what produced the HTTP 400. Listed explicitly (rather than relying on the
# lookup miss) so the skip carries the precise
# ``unsupported_ecosystem`` reason and the intent survives future edits.
UNSUPPORTED_ECOSYSTEM_VALUES = frozenset(
    {
        "application",
        "container",
        "data",
        "device",
        "device-driver",
        "driver",
        "file",
        "firmware",
        "framework",
        "generic",
        "library",
        "machine-learning-model",
        "module",
        "n/a",
        "na",
        "none",
        "null",
        "operating system",
        "operating-system",
        "operating_system",
        "os",
        "other",
        "platform",
        "service",
        "unknown",
        "unspecified",
    }
)

# ---------------------------------------------------------------------------
# Placeholder versions
# ---------------------------------------------------------------------------

# Values SBOM authors use to mean "there is no version here". A version
# like these cannot be range-matched, and sending the component without a
# version would return every advisory ever filed against the package.
PLACEHOLDER_VERSION_VALUES = frozenset(
    {
        "-",
        "*",
        "?",
        "bundled",
        "embedded",
        "included",
        "integrated",
        "n/a",
        "na",
        "none",
        "not applicable",
        "not specified",
        "null",
        "tbd",
        "unknown",
        "unspecified",
        "unversioned",
        "various",
    }
)

# Free-text prefixes of the same kind ("Bundled with Windows 11").
PLACEHOLDER_VERSION_PREFIXES = (
    "bundled with",
    "bundled in",
    "included with",
    "included in",
    "integrated with",
    "integrated in",
    "provided by",
    "shipped with",
    "see ",
)


@dataclass(frozen=True)
class OsvQueryDecision:
    """Outcome of the eligibility gate for one component.

    ``query`` is the exact ``/v1/querybatch`` query object to send when
    ``eligible`` is true, and ``None`` otherwise — deciding eligibility and
    building the query is one decision, so one function makes both.
    """

    eligible: bool
    query: dict[str, Any] | None = None
    reason: str | None = None
    ecosystem: str | None = None


def canonical_osv_ecosystem(value: Any) -> str | None:
    """Return the canonical OSV ecosystem for ``value``, else ``None``.

    Handles the release-suffixed forms OSV uses for distro ecosystems
    (``Debian:11``, ``Alpine:v3.16``, ``Red Hat:rhel_aus:8.2``) by
    canonicalising the leading segment and re-attaching the suffix
    verbatim. Returns ``None`` for anything not published by OSV,
    including every value in :data:`UNSUPPORTED_ECOSYSTEM_VALUES`.
    """
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None

    head, sep, suffix = cleaned.partition(":")
    head = head.strip()
    lowered = head.lower()
    if not lowered or lowered in UNSUPPORTED_ECOSYSTEM_VALUES:
        return None

    canonical = _CANONICAL_OSV_ECOSYSTEMS.get(lowered) or _OSV_ECOSYSTEM_ALIASES.get(lowered)
    if canonical is None:
        return None
    return f"{canonical}{sep}{suffix}" if sep else canonical


def is_placeholder_version(value: Any) -> bool:
    """True when ``value`` is a stand-in for a version rather than one."""
    if value is None:
        return True
    text = str(value).strip()
    if not text:
        return True
    lowered = text.lower()
    if lowered in PLACEHOLDER_VERSION_VALUES:
        return True
    return lowered.startswith(PLACEHOLDER_VERSION_PREFIXES)


def usable_version(value: Any) -> str | None:
    """Return the version string OSV can match on, or ``None``."""
    if is_placeholder_version(value):
        return None
    return str(value).strip()


def _component_ecosystem(component: Mapping[str, Any]) -> tuple[str | None, bool]:
    """Resolve the component's recorded ecosystem.

    Returns ``(canonical_ecosystem, had_raw_value)``. Only fields the SBOM
    (or its normalisation) actually recorded are read — deliberately NOT
    ``cpe.ecosystem_from_component``, which falls back to parsing the PURL.
    A component reaching the name branch either has no PURL or an
    unparseable one, and neither is a trustworthy ecosystem source.
    """
    raw_present = False
    for key in ("ecosystem", "normalized_ecosystem"):
        raw = component.get(key)
        if isinstance(raw, str) and raw.strip():
            raw_present = True
            canonical = canonical_osv_ecosystem(raw)
            if canonical:
                return canonical, True
    return None, raw_present


def osv_query_for_component(component: Mapping[str, Any]) -> OsvQueryDecision:
    """Decide whether OSV can be asked about ``component``, and how.

    Eligible when the component has a syntactically valid PURL, or a
    package name together with a recognised OSV ecosystem. Everything else
    is skipped with a reason; no PURL or ecosystem is ever synthesised.
    """
    if not isinstance(component, Mapping):
        return OsvQueryDecision(False, reason=SKIP_REASON_NO_IDENTITY)

    version = usable_version(component.get("version"))

    purl_raw = component.get("purl")
    purl = purl_raw.strip() if isinstance(purl_raw, str) else ""
    if purl:
        parsed = parse_purl(purl)
        if parsed and parsed.get("type") and parsed.get("name"):
            # OSV resolves the ecosystem from the PURL type itself, so a
            # valid PURL needs no ecosystem of ours. The version only
            # travels as a separate field when the PURL omits it.
            query: dict[str, Any] = {"package": {"purl": purl}}
            if not parsed.get("version") and version:
                query["version"] = version
            return OsvQueryDecision(
                True,
                query=query,
                ecosystem=canonical_osv_ecosystem(parsed.get("type")),
            )
        # An unparseable PURL is not sent — fall through to the
        # name + ecosystem branch, which may still have a real identity.

    name_raw = component.get("name")
    name = name_raw.strip() if isinstance(name_raw, str) else ""
    if not name:
        return OsvQueryDecision(False, reason=SKIP_REASON_MISSING_NAME)

    ecosystem, had_raw_ecosystem = _component_ecosystem(component)
    if ecosystem is None:
        return OsvQueryDecision(
            False,
            reason=SKIP_REASON_UNSUPPORTED_ECOSYSTEM if had_raw_ecosystem else SKIP_REASON_NO_IDENTITY,
        )

    # Name + ecosystem queries are only meaningful when version-qualified:
    # OSV returns every advisory for the package when the version is
    # omitted, so a placeholder version is a skip, not a wildcard.
    if version is None:
        return OsvQueryDecision(False, reason=SKIP_REASON_PLACEHOLDER_VERSION, ecosystem=ecosystem)

    return OsvQueryDecision(
        True,
        query={"package": {"name": name, "ecosystem": ecosystem}, "version": version},
        ecosystem=ecosystem,
    )


def is_osv_query_eligible(component: Mapping[str, Any]) -> bool:
    """True when OSV can be queried for ``component``."""
    return osv_query_for_component(component).eligible


def osv_skip_outcome(component: Mapping[str, Any], reason: str | None) -> dict[str, Any]:
    """Structured skip record, shaped like ``routing.queryable_components``."""
    return {
        "outcome": "SKIPPED",
        "source": "OSV",
        "reason": reason or SKIP_REASON_NO_IDENTITY,
        "component": component.get("bom_ref") or component.get("purl") or component.get("name"),
        "component_name": component.get("name"),
        "component_version": component.get("version"),
        "ecosystem": component.get("ecosystem") or component.get("normalized_ecosystem"),
    }


def partition_osv_eligible(
    components: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split ``components`` into OSV-queryable ones and skip records.

    The returned skip records are counted into the OSV source summary; the
    eligible list is what may reach ``/v1/querybatch``.
    """
    eligible: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for component in components:
        item = component if isinstance(component, Mapping) else {}
        decision = osv_query_for_component(item)
        if decision.eligible:
            eligible.append(component)
        else:
            skipped.append(osv_skip_outcome(item, decision.reason))
    return eligible, skipped


__all__ = [
    "PLACEHOLDER_VERSION_PREFIXES",
    "PLACEHOLDER_VERSION_VALUES",
    "SKIP_REASON_MISSING_NAME",
    "SKIP_REASON_NO_IDENTITY",
    "SKIP_REASON_PLACEHOLDER_VERSION",
    "SKIP_REASON_UNSUPPORTED_ECOSYSTEM",
    "UNSUPPORTED_ECOSYSTEM_VALUES",
    "OsvQueryDecision",
    "canonical_osv_ecosystem",
    "is_osv_query_eligible",
    "is_placeholder_version",
    "osv_query_for_component",
    "osv_skip_outcome",
    "partition_osv_eligible",
    "usable_version",
]
