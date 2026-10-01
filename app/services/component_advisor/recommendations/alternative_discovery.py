"""Alternative-component discovery (FR-SCA-012, US-SCA-10).

Runs only when the source's ecosystem, functional purpose and product
constraints can be established (spec Step 6). Purpose means an evidenced
``technology_category`` (SBOM / package / curated metadata, or MEDIUM/HIGH
AI), never a guess from a name. Product constraints are derived from the
ecosystems actually present in the products that use the source.

Order (spec Step 6):

1. ``TENANT_OBSERVED`` — other component families in the tenant's active
   SBOMs with the same category and ecosystem; the safest observed version
   of each family is proposed, with its adoption evidence (T22).
2. ``EXTERNAL`` — configured package-metadata adapters
   (:mod:`..sources`); none are enabled by default.
3. ``MANUAL`` — reviewer-supplied candidates (:func:`manual_candidate`).

A component is never a candidate merely because it has no actionable
findings: it must share the purpose category (T23) and be safer than the
source. Every candidate states why it was selected and what was evaluated;
the compatibility gates then run on it like any other candidate.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from ....integrations.cve.base import FetchOutcome
from ..classification import RiskClassification
from ..filters import RISK_SORT_RANK
from ..lifecycle_mapping import LifecycleBucket, lifecycle_bucket
from ..purpose import PurposeRecord, PurposeSource, ResolvedPurpose, resolve_purpose
from ..sources import ExternalCandidate, SourceResult, query_sources
from .compatibility import CandidateFacts, CompatibilityEvidence, ProductConstraints
from .version_discovery import ALWAYS_LIMITATIONS, CandidateEvaluation, _improves
from .workflow import CandidateKind, CandidateSourceType

MAX_ALTERNATIVES = 10
_GENERIC = {"", "generic", "unknown"}
_ALT_LIMITATIONS = (
    ("MIGRATION_REQUIRED", "A different component needs code changes; it is never a drop-in replacement"),
    ("API_COMPATIBILITY_REQUIRES_VERIFICATION", "The candidate's API differs from the source's"),
)


@dataclass
class AlternativeResult:
    status: str
    candidates: list[CandidateEvaluation] = field(default_factory=list)
    excluded: list[dict[str, Any]] = field(default_factory=list)
    external_sources: list[dict[str, Any]] = field(default_factory=list)
    category: str | None = None


def category_of(purpose: ResolvedPurpose | None) -> str | None:
    if purpose is None:
        return None
    category = purpose.fields.get("technology_category")
    return category.value.strip().lower() if category and category.searchable else None


def product_constraints(source, versions: Iterable) -> ProductConstraints:
    """Ecosystems present in the products (or, tenant-wide, the SBOMs) that use ``source``."""
    products, sboms = set(source.product_ids), set(source.sbom_ids)
    ecosystems = {
        str(v.ecosystem).lower() for v in versions
        if v.ecosystem and (set(v.product_ids) & products if products else set(v.sbom_ids) & sboms)
    } - _GENERIC
    return ProductConstraints(established=bool(ecosystems), ecosystems=frozenset(ecosystems))


def discover_alternatives(
    source,
    versions: Iterable,
    *,
    constraints: ProductConstraints,
    external_query: Callable[..., list[SourceResult]] = query_sources,
    limit: int = MAX_ALTERNATIVES,
) -> AlternativeResult:
    versions = list(versions)
    ecosystem = str(source.ecosystem or "").lower()
    if ecosystem in _GENERIC:
        return AlternativeResult("INSUFFICIENT_ECOSYSTEM_EVIDENCE")
    category = category_of(source.purpose)
    if not category:
        return AlternativeResult("INSUFFICIENT_PURPOSE_EVIDENCE")
    if not constraints.established:
        return AlternativeResult("PRODUCT_CONSTRAINTS_UNAVAILABLE", category=category)

    result = AlternativeResult("EVALUATED", category=category)
    by_family: dict[str, list] = defaultdict(list)
    for version in versions:
        if version.family_key and version.family_key != source.family_key and str(version.ecosystem or "").lower() == ecosystem:
            by_family[version.family_key].append(version)
    for family_key, members in sorted(by_family.items()):
        family_category = next((category_of(v.purpose) for v in members if category_of(v.purpose)), None)
        if family_category != category:
            if family_category:  # explicit purpose mismatch, recorded for transparency (T23)
                result.excluded.append({"family_key": family_key, "reason": "PURPOSE_MISMATCH",
                                        "category": family_category})
            continue
        safer = [v for v in members if _improves(source, v)]
        if not safer:
            result.excluded.append({"family_key": family_key, "reason": "NOT_SAFER_THAN_SOURCE"})
            continue
        best = min(safer, key=lambda v: (RISK_SORT_RANK[v.classification],
                                          0 if v.lifecycle.bucket is LifecycleBucket.SUPPORTED else 1,
                                          -len(v.product_ids), str(v.version or "")))
        result.candidates.append(_observed_candidate(source, best, category))

    try:
        responses = external_query(ecosystem=ecosystem, category=category,
                                   purpose_text=_purpose_text(source.purpose))
    except Exception as exc:  # noqa: BLE001 - the adapter layer must never fail evaluation
        responses = [SourceResult("adapter-layer", FetchOutcome.ERROR, error=type(exc).__name__)]
    result.external_sources = [r.to_dict() for r in responses]
    seen = {(c.name.lower(), str(c.version)) for c in result.candidates}
    for response in responses:
        for external in response.candidates:
            key = (external.name.lower(), str(external.version))
            if key in seen or external.name.lower() == str(source.name).lower():
                continue
            seen.add(key)
            candidate = _external_candidate(source, external, response.source, category)
            if candidate is None:
                result.excluded.append({"name": external.name, "source": response.source, "reason": "PURPOSE_OR_ECOSYSTEM_MISMATCH"})
                continue
            result.candidates.append(candidate)

    result.candidates = result.candidates[:limit]
    if not result.candidates:
        result.status = "NO_CANDIDATES_FOUND"
    if any(r["outcome"] in ("error", "circuit_open") for r in result.external_sources):
        result.status = f"{result.status}_EXTERNAL_SOURCE_DEGRADED"
    return result


def _purpose_text(purpose: ResolvedPurpose | None) -> str | None:
    if purpose is None:
        return None
    use_case = purpose.fields.get("primary_use_case")
    return use_case.value if use_case else None


def _base_reasons(category: str) -> list[dict[str, Any]]:
    return [
        {"code": "SIMILAR_PURPOSE", "detail": f"Same technology category ({category})"},
        {"code": "SAME_ECOSYSTEM"},
    ]


def _limitations(extra: Iterable[tuple[str, str]] = ()) -> list[dict[str, Any]]:
    out = [{"code": code, "detail": detail} for code, detail in _ALT_LIMITATIONS]
    out += [{"code": code, "detail": detail} for code, detail in extra]
    out += [{"code": code, "detail": detail} for code, detail in ALWAYS_LIMITATIONS]
    return out


def _observed_candidate(source, record, category: str) -> CandidateEvaluation:
    reasons = _base_reasons(category)
    if RISK_SORT_RANK[record.classification] < RISK_SORT_RANK[source.classification]:
        reasons.append({"code": "LOWER_CURRENT_RISK", "detail": f"{record.classification.value} vs source {source.classification.value}"})
    if record.classification is RiskClassification.NO_KNOWN_ACTIONABLE_VULNERABILITIES:
        reasons.append({"code": "NO_KNOWN_ACTIONABLE_VULNS_CURRENT_SNAPSHOT",
                        "detail": "No actionable findings in the current eligible snapshot (not proof of security)"})
    reasons.append({"code": "FOUND_IN_N_ACTIVE_TENANT_SBOMS", "count": record.occurrence_count})
    reasons.append({"code": "USED_BY_N_TENANT_PRODUCTS", "count": len(record.product_ids)})
    if record.lifecycle.bucket is LifecycleBucket.SUPPORTED:
        reasons.append({"code": "SUPPORTED_LIFECYCLE"})
    candidate = CandidateEvaluation(
        kind=CandidateKind.ALTERNATIVE, source_type=CandidateSourceType.TENANT_OBSERVED,
        canonical_key=record.canonical_key, name=record.name, version=str(record.version or ""),
        purl=record.purl, ecosystem=record.ecosystem, evidence_sources=["TENANT_OBSERVED"],
        reasons=reasons, limitations=_limitations(),
    )
    candidate.evaluation = {
        "current_posture": {"status": "OBSERVED", "classification": record.classification.value,
                            "highest_actionable_severity": record.highest_actionable_severity,
                            "actionable_vulnerability_count": record.actionable_vulnerability_count,
                            "review_reasons": list(record.review_reasons)},
        "purpose": record.purpose.to_dict(),
        "lifecycle": {"bucket": record.lifecycle.bucket.value, "status": record.lifecycle.status,
                      "effective_date": record.lifecycle.effective_date},
        "license": {"source": list(source.licenses), "candidate": list(record.licenses)},
        "adoption": {"active_sbom_occurrences": record.occurrence_count, "product_count": len(record.product_ids),
                     "interpretation": "CONTEXTUAL_EVIDENCE_NOT_PROOF"},
        "freshness": {"latest_analysis_at": record.latest_analysis_at, "lifecycle_checked_at": record.lifecycle.checked_at},
        "fix_coverage": {"fixed": [], "unknown": list(source.actionable_vulnerability_ids)},
        "version_change": {"direction": "DIFFERENT_COMPONENT", "major_version_change": None,
                           "from": f"{source.name} {source.version or ''}".strip(), "to": f"{record.name} {record.version or ''}".strip()},
        "historical_trend": {"status": "NOT_EVALUATED"},
        "release_cadence": {"status": "NOT_EVALUATED"},
    }
    candidate.facts = CandidateFacts(
        kind=CandidateKind.ALTERNATIVE, name=record.name, version=record.version, ecosystem=record.ecosystem,
        family_key=record.family_key, observed=True, purpose=record.purpose, licenses=tuple(record.licenses),
        lifecycle=record.lifecycle.bucket, major_version_change=None,
    )
    return candidate


def _external_candidate(source, external: ExternalCandidate, source_name: str, category: str) -> CandidateEvaluation | None:
    if str(external.ecosystem or "").lower() != str(source.ecosystem or "").lower():
        return None
    purpose_payload = dict(external.purpose or {})
    purpose = resolve_purpose(records=[PurposeRecord(
        source=PurposeSource.PACKAGE, tenant_id=None,
        purpose=purpose_payload.get("functional_description"), primary_use_case=purpose_payload.get("primary_use_case"),
        category=purpose_payload.get("technology_category"),
        confidence=str(purpose_payload.get("confidence") or "MEDIUM").upper(),
        provenance={"adapter": source_name, **(external.provenance or {})},
    )])
    if category_of(purpose) != category:
        return None
    bucket = lifecycle_bucket(external.lifecycle_status) if external.lifecycle_status else None
    candidate = CandidateEvaluation(
        kind=CandidateKind.ALTERNATIVE, source_type=CandidateSourceType.EXTERNAL, canonical_key=None,
        name=external.name, version=str(external.version or ""), purl=external.purl, ecosystem=external.ecosystem,
        evidence_sources=[f"EXTERNAL:{source_name}"], reasons=_base_reasons(category),
        limitations=_limitations([
            ("VULNERABILITY_POSTURE_NOT_OBSERVED", "Not in the tenant's active SBOMs; current findings unknown"),
            ("EXTERNAL_METADATA_ONLY", f"Evidence from adapter {source_name}; verify before adoption"),
        ]),
    )
    candidate.evaluation = {
        "current_posture": {"status": "NOT_OBSERVED_IN_TENANT"},
        "purpose": purpose.to_dict(),
        "lifecycle": {"bucket": bucket.value if bucket else LifecycleBucket.UNKNOWN.value,
                      "status": external.lifecycle_status or "Unknown", "effective_date": None},
        "license": {"source": list(source.licenses), "candidate": list(external.licenses) if external.licenses else None},
        "adoption": {"active_sbom_occurrences": 0, "product_count": 0},
        "freshness": {"latest_analysis_at": None, "external_retrieved_at": (external.provenance or {}).get("retrieved_at")},
        "fix_coverage": {"fixed": [], "unknown": list(source.actionable_vulnerability_ids)},
        "version_change": {"direction": "DIFFERENT_COMPONENT", "major_version_change": None,
                           "from": f"{source.name} {source.version or ''}".strip(), "to": f"{external.name} {external.version or ''}".strip()},
        "historical_trend": {"status": "NOT_EVALUATED"},
        "release_cadence": {"status": "NOT_EVALUATED"},
        "external_provenance": {"adapter": source_name, **(external.provenance or {})},
    }
    candidate.facts = CandidateFacts(
        kind=CandidateKind.ALTERNATIVE, name=external.name, version=external.version, ecosystem=external.ecosystem,
        family_key=None, observed=False, purpose=purpose, licenses=external.licenses, lifecycle=bucket,
        major_version_change=None,
        evidence=CompatibilityEvidence.from_dict(external.compatibility_evidence, source=f"EXTERNAL:{source_name}"),
    )
    return candidate


def manual_candidate(source, payload: dict[str, Any], versions: Iterable, *, actor: str) -> CandidateEvaluation:
    """A reviewer-proposed candidate (spec Step 6 "manual candidates where supported").

    If the named version is already observed in the tenant, its real posture
    is used; otherwise it is reported as not observed. The reviewer's purpose
    category and compatibility evidence are recorded with their provenance and
    go through the same gates as every other candidate.
    """
    name, version = payload["name"].strip(), str(payload.get("version") or "").strip()
    ecosystem = str(payload.get("ecosystem") or source.ecosystem or "").strip().lower()
    observed = next(
        (v for v in versions if str(v.name).lower() == name.lower() and str(v.version or "") == version
         and str(v.ecosystem or "").lower() == ecosystem),
        None,
    )
    family_key = observed.family_key if observed else f"{ecosystem}:{name.lower()}"
    kind = CandidateKind.SAME_FAMILY_VERSION if source.family_key and family_key == source.family_key else CandidateKind.ALTERNATIVE
    provenance = {"recorded_by": actor, "rationale": payload["rationale"]}
    if observed is not None:
        purpose = observed.purpose
    elif payload.get("technology_category"):
        purpose = resolve_purpose(records=[PurposeRecord(
            source=PurposeSource.CURATED, tenant_id=None, purpose=None, primary_use_case=payload.get("primary_use_case"),
            category=payload["technology_category"], confidence="MEDIUM", provenance={"manual_candidate": True, **provenance},
        )])
    else:
        purpose = ResolvedPurpose({})
    licenses = tuple(observed.licenses) if observed else (tuple(payload["licenses"]) if payload.get("licenses") else None)
    bucket = observed.lifecycle.bucket if observed else (lifecycle_bucket(payload["lifecycle_status"]) if payload.get("lifecycle_status") else None)
    candidate = CandidateEvaluation(
        kind=kind, source_type=CandidateSourceType.MANUAL,
        canonical_key=observed.canonical_key if observed else None, name=name, version=version,
        purl=payload.get("purl") or (observed.purl if observed else None), ecosystem=ecosystem,
        evidence_sources=["MANUAL"] + (["TENANT_OBSERVED"] if observed else []),
        reasons=[{"code": "REVIEWER_PROPOSED", "detail": payload["rationale"]}],
        limitations=_limitations([] if observed else [
            ("VULNERABILITY_POSTURE_NOT_OBSERVED", "Not in the tenant's active SBOMs; current findings unknown")]),
    )
    candidate.evaluation = {
        "current_posture": ({"status": "OBSERVED", "classification": observed.classification.value,
                             "highest_actionable_severity": observed.highest_actionable_severity,
                             "actionable_vulnerability_count": observed.actionable_vulnerability_count,
                             "review_reasons": list(observed.review_reasons)} if observed else {"status": "NOT_OBSERVED_IN_TENANT"}),
        "purpose": purpose.to_dict(),
        "lifecycle": {"bucket": bucket.value if bucket else LifecycleBucket.UNKNOWN.value},
        "license": {"source": list(source.licenses), "candidate": list(licenses) if licenses else None},
        "adoption": ({"active_sbom_occurrences": observed.occurrence_count, "product_count": len(observed.product_ids)}
                     if observed else {"active_sbom_occurrences": 0, "product_count": 0}),
        "fix_coverage": {"fixed": [], "unknown": list(source.actionable_vulnerability_ids)},
        "version_change": {"direction": "MANUAL", "major_version_change": None, "from": source.version, "to": version},
        "historical_trend": {"status": "NOT_EVALUATED"},
        "release_cadence": {"status": "NOT_EVALUATED"},
        "manual_input": {k: v for k, v in payload.items()},
        "manual_provenance": provenance,
    }
    candidate.facts = CandidateFacts(
        kind=kind, name=name, version=version, ecosystem=ecosystem, family_key=family_key, observed=observed is not None,
        purpose=purpose, licenses=licenses, lifecycle=bucket, major_version_change=None,
        evidence=CompatibilityEvidence.from_dict(payload.get("compatibility_evidence"), source=f"MANUAL:{actor}"),
    )
    return candidate


__all__ = ["AlternativeResult", "category_of", "discover_alternatives", "manual_candidate", "product_constraints"]
