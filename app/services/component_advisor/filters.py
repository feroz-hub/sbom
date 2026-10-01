"""Advisor filters, KPIs, drill-down and search over one snapshot (FR-SCA-002/006/007/008).

Pure functions over :class:`~app.metrics.component_advisor.ComponentVersionIntelligence`
records, so every surface — KPI cards, the component table, search results —
is computed from the *same* filtered list. That is what makes the counts
reconcile with drill-down for identical scope / filters / as-of (spec Step 3,
test T13): a KPI's ``filter`` applied to ``/components`` returns exactly
``value`` rows.

Scope (tenant / project / product / SBOM) is not handled here; it is applied
before the snapshot is built, by the validated ``DashboardScope``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .classification import INFORMATIONAL_SUPPORTED, SEVERITY_RANK, RiskClassification
from .lifecycle_mapping import END_OF_LIFE_BUCKETS, LifecycleBucket

#: "Frequently Adopted Components" KPI: a version used by at least this many
#: distinct products in scope. Spec gives no number; this baseline is exposed
#: in every response (``meta.thresholds``) and recorded as an open item.
FREQUENT_ADOPTION_MIN_PRODUCTS = 3

SEARCH_FACETS = ("all", "name", "purl", "supplier", "ecosystem", "category", "purpose")
#: Facets backed by purpose metadata, which does not exist until Step 4 (FR-SCA-009).
PURPOSE_FACETS = frozenset({"category", "purpose"})

SORT_FIELDS = ("name", "risk", "occurrences", "products", "actionable", "latest_analysis")

#: Most severe first. Review Required sits just below High: it may hide
#: Medium/Low risk but never Critical/High (decision 2026-10-01).
RISK_SORT_RANK = {
    RiskClassification.CRITICAL: 8,
    RiskClassification.HIGH: 7,
    RiskClassification.REVIEW_REQUIRED: 6,
    RiskClassification.MEDIUM: 5,
    RiskClassification.LOW: 4,
    RiskClassification.INFORMATIONAL: 3,
    RiskClassification.ACCEPTED_RISK: 2,
    RiskClassification.UNKNOWN: 1,
    RiskClassification.NO_KNOWN_ACTIONABLE_VULNERABILITIES: 0,
}


class FilterError(ValueError):
    """An unrecognised filter value. Routers map it to HTTP 400."""


@dataclass(frozen=True)
class AdvisorFilters:
    risk: frozenset[RiskClassification] = field(default_factory=frozenset)
    lifecycle: frozenset[LifecycleBucket] = field(default_factory=frozenset)
    needs_review: bool | None = None
    frequently_adopted: bool | None = None
    q: str | None = None
    facet: str = "all"

    @classmethod
    def parse(
        cls,
        *,
        risk: Sequence[str] | None = None,
        lifecycle: Sequence[str] | None = None,
        needs_review: bool | None = None,
        frequently_adopted: bool | None = None,
        q: str | None = None,
        facet: str | None = None,
    ) -> AdvisorFilters:
        return cls(
            risk=frozenset(_parse_enum(RiskClassification, "risk", risk)),
            lifecycle=frozenset(_parse_enum(LifecycleBucket, "lifecycle", lifecycle)),
            needs_review=needs_review,
            frequently_adopted=frequently_adopted,
            q=(q or "").strip() or None,
            facet=_parse_facet(facet),
        )

    @property
    def unsupported(self) -> list[str]:
        """Filter values accepted but unable to match anything, made explicit."""
        out = []
        if RiskClassification.INFORMATIONAL in self.risk and not INFORMATIONAL_SUPPORTED:
            out.append("risk=INFORMATIONAL")
        if self.q and self.facet in PURPOSE_FACETS:
            out.append(f"facet={self.facet}")
        return out

    def normalized(self) -> dict[str, Any]:
        """The applied filters, echoed in every response (spec Step 3 API behaviour)."""
        return {
            "risk": sorted(item.value for item in self.risk),
            "lifecycle": sorted(item.value for item in self.lifecycle),
            "needs_review": self.needs_review,
            "frequently_adopted": self.frequently_adopted,
            "q": self.q,
            "facet": self.facet,
        }


def _parse_enum(enum_cls, name: str, values: Sequence[str] | None):
    out = []
    for raw in values or ():
        for part in str(raw).split(","):
            cleaned = part.strip().upper()
            if not cleaned:
                continue
            try:
                out.append(enum_cls(cleaned))
            except ValueError as exc:
                allowed = ", ".join(item.value for item in enum_cls)
                raise FilterError(f"Unknown {name} filter {part.strip()!r}; expected one of {allowed}") from exc
    return out


def _parse_facet(value: str | None) -> str:
    facet = (value or "all").strip().lower()
    if facet not in SEARCH_FACETS:
        raise FilterError(f"Unknown search facet {value!r}; expected one of {', '.join(SEARCH_FACETS)}")
    return facet


# ---------------------------------------------------------------------------
# Predicates
# ---------------------------------------------------------------------------


def is_frequently_adopted(version) -> bool:
    return len(version.product_ids) >= FREQUENT_ADOPTION_MIN_PRODUCTS


def needs_review(version) -> bool:
    """Any review reason, whatever the bucket (a Critical can still need review)."""
    return bool(version.review_reasons) or version.classification is RiskClassification.REVIEW_REQUIRED


def _contains(haystack: str | None, needle: str) -> bool:
    return bool(haystack) and needle in haystack.lower()


def matches_search(version, q: str, facet: str) -> bool:
    needle = q.lower()
    if facet in PURPOSE_FACETS:
        # No purpose evidence yet (Step 4). Never guess a match from the name.
        return False
    checks = {
        "name": lambda: _contains(version.name, needle) or _contains(version.family_key, needle),
        "purl": lambda: _contains(version.purl, needle),
        "supplier": lambda: _contains(version.supplier, needle),
        "ecosystem": lambda: (version.ecosystem or "").lower() == needle,
    }
    if facet == "all":
        return any(check() for check in checks.values())
    return checks[facet]()


def apply_filters(versions: Iterable, filters: AdvisorFilters) -> list:
    out = []
    for version in versions:
        if filters.risk and version.classification not in filters.risk:
            continue
        if filters.lifecycle and version.lifecycle.bucket not in filters.lifecycle:
            continue
        if filters.needs_review is not None and needs_review(version) != filters.needs_review:
            continue
        if filters.frequently_adopted is not None and is_frequently_adopted(version) != filters.frequently_adopted:
            continue
        if filters.q and not matches_search(version, filters.q, filters.facet):
            continue
        out.append(version)
    return out


# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------


def sort_versions(versions: list, sort_by: str = "risk", sort_order: str = "desc") -> list:
    if sort_by not in SORT_FIELDS:
        raise FilterError(f"Unknown sort field {sort_by!r}; expected one of {', '.join(SORT_FIELDS)}")
    if sort_order not in ("asc", "desc"):
        raise FilterError("sort_order must be 'asc' or 'desc'")
    keys = {
        "name": lambda v: (str(v.name).lower(), str(v.version or "")),
        "risk": lambda v: (
            RISK_SORT_RANK[v.classification],
            SEVERITY_RANK.get(v.highest_actionable_severity or "", -1),
            v.actionable_vulnerability_count,
        ),
        "occurrences": lambda v: v.occurrence_count,
        "products": lambda v: len(v.product_ids),
        "actionable": lambda v: v.actionable_vulnerability_count,
        "latest_analysis": lambda v: v.latest_analysis_at or "",
    }
    # Stable secondary order so pages never shuffle between requests.
    ordered = sorted(versions, key=lambda v: (str(v.name).lower(), str(v.version or ""), v.canonical_key))
    return sorted(ordered, key=keys[sort_by], reverse=(sort_order == "desc"))


# ---------------------------------------------------------------------------
# KPIs
# ---------------------------------------------------------------------------


def _kpi(key: str, label: str, value: int | None, drill: dict[str, Any], *, status: str = "OK", render: bool = True):
    return {"key": key, "label": label, "value": value, "status": status, "render": render, "filter": drill}


def kpis(
    versions: Sequence,
    *,
    accepted_risk_policy_configured: bool = False,
    trust_policy_configured: bool = False,
) -> list[dict[str, Any]]:
    """The nine spec KPI cards (spec Step 3) over an already-filtered list.

    Each card carries the ``/components`` filter that reproduces its rows.
    Policy-backed cards report ``POLICY_NOT_CONFIGURED`` rather than a
    misleading zero; Trusted renders only when a trust policy exists.
    """
    def count(predicate) -> int:
        return sum(1 for version in versions if predicate(version))

    by = lambda bucket: count(lambda v: v.classification is bucket)  # noqa: E731
    accepted = by(RiskClassification.ACCEPTED_RISK)
    return [
        _kpi("unique_component_versions", "Unique Component Versions", len(versions), {}),
        _kpi(
            "no_known_actionable_vulnerabilities",
            "No Known Actionable Vulnerabilities",
            by(RiskClassification.NO_KNOWN_ACTIONABLE_VULNERABILITIES),
            {"risk": [RiskClassification.NO_KNOWN_ACTIONABLE_VULNERABILITIES.value]},
        ),
        _kpi(
            "within_accepted_risk",
            "Components Within Accepted Risk",
            accepted if accepted_risk_policy_configured else None,
            {"risk": [RiskClassification.ACCEPTED_RISK.value]},
            status="OK" if accepted_risk_policy_configured else "POLICY_NOT_CONFIGURED",
        ),
        _kpi("critical", "Critical-Risk Components", by(RiskClassification.CRITICAL), {"risk": ["CRITICAL"]}),
        _kpi("high", "High-Risk Components", by(RiskClassification.HIGH), {"risk": ["HIGH"]}),
        _kpi(
            "end_of_life_or_support",
            "EOL / EOS Components",
            count(lambda v: v.lifecycle.bucket in END_OF_LIFE_BUCKETS),
            {"lifecycle": sorted(bucket.value for bucket in END_OF_LIFE_BUCKETS)},
        ),
        _kpi(
            "frequently_adopted",
            "Frequently Adopted Components",
            count(is_frequently_adopted),
            {"frequently_adopted": True},
        ),
        _kpi(
            "trusted_by_policy",
            "Trusted-by-Policy Components",
            None,
            {},
            status="OK" if trust_policy_configured else "POLICY_NOT_CONFIGURED",
            render=trust_policy_configured,
        ),
        _kpi("requiring_review", "Components Requiring Review", count(needs_review), {"needs_review": True}),
    ]


def distributions(versions: Sequence) -> dict[str, dict[str, int]]:
    by_classification = {bucket.value: 0 for bucket in RiskClassification}
    by_lifecycle = {bucket.value: 0 for bucket in LifecycleBucket}
    for version in versions:
        by_classification[version.classification.value] += 1
        by_lifecycle[version.lifecycle.bucket.value] += 1
    return {"by_classification": by_classification, "by_lifecycle": by_lifecycle}


# ---------------------------------------------------------------------------
# Search results (grouped by component family)
# ---------------------------------------------------------------------------


def search_families(versions: Sequence) -> list[dict[str, Any]]:
    """Group matching versions by component family with each version's posture.

    Spec Step 3: results expose candidate versions and their current risk
    posture. Versions are listed, not ranked — ranking is recommendation work
    (Step 7) and needs compatibility evidence first.
    """
    families: dict[str, dict[str, Any]] = {}
    for version in versions:
        key = version.family_key or version.canonical_key
        family = families.setdefault(
            key,
            {
                "family_key": version.family_key,
                "name": version.name,
                "ecosystem": version.ecosystem,
                "suppliers": set(),
                "versions": [],
            },
        )
        if version.supplier:
            family["suppliers"].add(version.supplier)
        family["versions"].append(
            {
                "canonical_key": version.canonical_key,
                "version": version.version,
                "classification": version.classification.value,
                "highest_actionable_severity": version.highest_actionable_severity,
                "actionable_vulnerability_count": version.actionable_vulnerability_count,
                "lifecycle_bucket": version.lifecycle.bucket.value,
                "active_sbom_occurrences": version.occurrence_count,
                "product_count": len(version.product_ids),
                "latest_analysis_at": version.latest_analysis_at,
            }
        )
    out = []
    for family in families.values():
        family["suppliers"] = sorted(family["suppliers"])
        family["versions"].sort(key=lambda item: str(item["version"] or ""))
        family["version_count"] = len(family["versions"])
        out.append(family)
    out.sort(key=lambda item: (str(item["name"]).lower(), str(item["ecosystem"] or "")))
    return out


__all__ = [
    "FREQUENT_ADOPTION_MIN_PRODUCTS",
    "PURPOSE_FACETS",
    "SEARCH_FACETS",
    "SORT_FIELDS",
    "AdvisorFilters",
    "FilterError",
    "apply_filters",
    "distributions",
    "is_frequently_adopted",
    "kpis",
    "matches_search",
    "needs_review",
    "search_families",
    "sort_versions",
]
