"""Secure Component Advisor metrics — per unique component version.

FR-SCA-001 / FR-SCA-003, NFR-SCA-002. Convention A (latest state,
``docs/metric-conventions.md``): every number is computed from

* component occurrences in the caller's eligible SBOM set — active, visible,
  HEAD SBOMs from ``DashboardScope.eligible_sbom_ids()`` (spec §1.3), so
  inactive and superseded SBOMs never contribute to risk or adoption;
* the findings of each SBOM's latest successful analysis run;
* the current VEX context (``VexInvestigation.is_current``) for each
  finding, which supplies the effective status that decides actionability.

Findings are joined to their VEX context exactly the way
``app.services.vex.reconciliation`` builds contexts: by SBOM, component and
the *canonical* vulnerability id from ``canonical_for_finding`` (CVE
preferred over GHSA, VEX-CTX-002). A plain ``upper(vuln_id)`` join would miss
a GHSA finding whose context is keyed by its CVE alias.

The functions take ``tenant_id`` and ``sbom_ids`` explicitly, like
:mod:`app.metrics.vex`, rather than relying only on a session-installed scope:
``VexInvestigation`` is not covered by the dashboard scope hook, and explicit
predicates keep tenant isolation independent of how the session was set up.

Severity is read from the findings and never rewritten (VEX-DATA-005). A VEX
assertion with no analyser finding never fabricates a finding or a severity
(VEX-DATA-003); an AFFECTED one only marks the version for review (D-5).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, AnalysisRun, SBOMComponent, SBOMSource, VexInvestigation
from ..services.component_advisor.classification import (
    RECONCILIATION_REVIEW_REASONS,
    SEVERITY_RANK,
    AcceptedRiskOutcome,
    ClassificationInput,
    ReviewReason,
    RiskClassification,
    bucket_counts,
    classify,
    is_actionable,
    normalize_severity,
)
from ..services.component_advisor.identity import LOW, family_key, split_licenses, version_identity
from ..services.component_advisor.lifecycle_mapping import END_OF_LIFE_BUCKETS, LifecycleView, lifecycle_view
from ..services.component_advisor.policy import TrustOutcome
from ..services.component_advisor.purpose import NOT_AVAILABLE, PurposeRecord, ResolvedPurpose, resolve_purpose
from ..services.vex.identity import canonical_for_finding
from .base import COMPLETED_RUN_STATUSES

_SEVERITY_KEYS = ("critical", "high", "medium", "low", "unknown")

_OCCURRENCE_COLUMNS = (
    SBOMComponent.id,
    SBOMComponent.sbom_id,
    SBOMComponent.name,
    SBOMComponent.version,
    SBOMComponent.purl,
    SBOMComponent.normalized_purl,
    SBOMComponent.cpe,
    SBOMComponent.primary_cpe,
    SBOMComponent.supplier,
    SBOMComponent.normalized_supplier,
    SBOMComponent.component_type,
    SBOMComponent.ecosystem,
    SBOMComponent.normalized_ecosystem,
    SBOMComponent.normalized_name,
    SBOMComponent.normalized_version,
    SBOMComponent.normalized_package_key,
    SBOMComponent.dedupe_canonical_id,
    SBOMComponent.canonical_identity_confidence,
    SBOMComponent.license,
    SBOMComponent.is_duplicate,
    SBOMComponent.lifecycle_status,
    SBOMComponent.eos_date,
    SBOMComponent.eol_date,
    SBOMComponent.eof_date,
    SBOMComponent.lifecycle_checked_at,
    SBOMComponent.lifecycle_is_stale,
    SBOMComponent.lifecycle_source,
    SBOMComponent.lifecycle_manual_override,
    SBOMComponent.description,
    SBOMSource.sbom_name,
    SBOMSource.projectid.label("project_id"),
    SBOMSource.product_id,
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class _VulnAccumulator:
    severity: str = "UNKNOWN"
    actionable: bool = False
    max_score: float | None = None
    vector: str | None = None
    cvss_version: str | None = None
    vex_statuses: set[str] = field(default_factory=set)

    def add(
        self, *, severity: str, actionable: bool, effective: str | None, score: float | None,
        vector: str | None, cvss_version: str | None,
    ) -> None:
        if SEVERITY_RANK[severity] > SEVERITY_RANK[self.severity]:
            self.severity = severity
        self.actionable = self.actionable or actionable
        if actionable:
            # No context yet means UNDER_INVESTIGATION (VEX-REC-002 A).
            self.vex_statuses.add(effective or "UNDER_INVESTIGATION")
        if score is not None and (self.max_score is None or score > self.max_score):
            self.max_score, self.vector, self.cvss_version = score, vector, cvss_version


@dataclass
class ComponentVersionIntelligence:
    """Everything FR-SCA-001 lists for one unique component version."""

    canonical_key: str
    identity_basis: str
    identity_confidence: str
    family_key: str | None
    name: str
    version: str | None
    purl: str | None
    cpe: str | None
    supplier: str | None
    component_type: str | None
    ecosystem: str | None
    licenses: list[str]
    occurrence_count: int
    sbom_ids: list[int]
    project_ids: list[int]
    product_ids: list[int]
    references: list[dict[str, Any]]
    actionable_vulnerability_count: int
    non_actionable_vulnerability_count: int
    actionable_severity_counts: dict[str, int]
    highest_actionable_severity: str | None
    cvss: dict[str, Any]
    classification: RiskClassification
    review_reasons: list[str]
    accepted_risk_policy_version_id: int | None
    lifecycle: LifecycleView
    latest_analysis_at: str | None
    analysed_occurrence_count: int
    evidence: list[dict[str, int]]
    vex_only_context_count: int = 0
    actionable_vex_statuses: frozenset[str] = frozenset()
    #: Canonical ids of the actionable vulnerabilities (remediation evidence).
    actionable_vulnerability_ids: list[str] = field(default_factory=list)
    #: ``(sbom_id, description)`` declared by each occurrence (purpose evidence).
    sbom_descriptions: list[tuple[int, str | None]] = field(default_factory=list)
    purpose: ResolvedPurpose = NOT_AVAILABLE
    accepted_risk: AcceptedRiskOutcome | None = None
    trust: TrustOutcome | None = None
    trust_policy_configured: bool = False

    @property
    def max_actionable_cvss(self) -> float | None:
        return self.cvss.get("max_score")

    @property
    def trusted(self) -> bool:
        return bool(self.trust and self.trust.trusted)

    @property
    def is_end_of_life(self) -> bool:
        return self.lifecycle.bucket in END_OF_LIFE_BUCKETS

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_key": self.canonical_key,
            "identity": {"basis": self.identity_basis, "confidence": self.identity_confidence},
            "family_key": self.family_key,
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "cpe": self.cpe,
            "supplier": self.supplier,
            "component_type": self.component_type,
            "ecosystem": self.ecosystem,
            "licenses": list(self.licenses),
            # Purpose metadata arrives in Step 4 (FR-SCA-009); exposed now so
            # the contract never implies purpose evidence that does not exist.
            "purpose": self.purpose.to_dict(),
            "trust": _trust_dict(self),
            "usage": {
                "active_sbom_occurrences": self.occurrence_count,
                "sbom_count": len(self.sbom_ids),
                "project_count": len(self.project_ids),
                "product_count": len(self.product_ids),
                "references": list(self.references),
            },
            "risk": {
                "classification": self.classification.value,
                "review_reasons": list(self.review_reasons),
                "accepted_risk_policy_version_id": self.accepted_risk_policy_version_id,
                "accepted_risk": _accepted_risk_dict(self.accepted_risk),
                "actionable_vulnerability_count": self.actionable_vulnerability_count,
                "non_actionable_vulnerability_count": self.non_actionable_vulnerability_count,
                "actionable_severity_counts": dict(self.actionable_severity_counts),
                "highest_actionable_severity": self.highest_actionable_severity,
                "cvss": dict(self.cvss),
                "vex_only_context_count": self.vex_only_context_count,
            },
            "lifecycle": {
                "bucket": self.lifecycle.bucket.value,
                "status": self.lifecycle.status,
                "effective_date": self.lifecycle.effective_date,
                "source": self.lifecycle.source,
                "manual_override": self.lifecycle.manual_override,
            },
            "freshness": {
                "latest_analysis_at": self.latest_analysis_at,
                "analysed_occurrences": self.analysed_occurrence_count,
                "total_occurrences": self.occurrence_count,
                "lifecycle_checked_at": self.lifecycle.checked_at,
                "lifecycle_is_stale": self.lifecycle.is_stale,
            },
            # Exact SBOM / analysis versions behind the classification (NFR-SCA-002).
            "evidence": [dict(item) for item in self.evidence],
            # Recommendation work items arrive in Step 5 (FR-SCA-011).
            "recommendation": {"status": "NOT_EVALUATED"},
        }


def _accepted_risk_dict(outcome: AcceptedRiskOutcome | None) -> dict[str, Any] | None:
    if outcome is None:
        return None
    return {
        "policy_version_id": outcome.policy_version_id,
        "satisfied": outcome.satisfied,
        "criteria": [dict(item) for item in outcome.criteria],
    }


def _trust_dict(version: "ComponentVersionIntelligence") -> dict[str, Any]:
    outcome = version.trust
    if outcome is None:
        return {"status": "POLICY_NOT_CONFIGURED", "policy_version_id": None, "criteria": []}
    return {
        "status": "TRUSTED_BY_POLICY" if outcome.trusted else "NOT_TRUSTED",
        "policy_version_id": outcome.policy_version_id,
        "criteria": [criterion.to_dict() for criterion in outcome.criteria],
    }


@dataclass
class ComponentIntelligenceSnapshot:
    versions: list[ComponentVersionIntelligence] = field(default_factory=list)
    #: Actionable findings in the snapshot that cannot be tied to a component
    #: occurrence (``component_id`` NULL). Surfaced, never silently dropped.
    unattributed_actionable_findings: int = 0
    analysed_sbom_count: int = 0
    eligible_sbom_count: int = 0
    latest_analysis_at: str | None = None
    #: Effective policies the snapshot was classified with (set by the service).
    policies: Any = None


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def _latest_run_ids(tenant_id: int, sbom_ids):
    """Latest successful run id per eligible SBOM (Convention A, MAX(id) per ADR-0001)."""
    return (
        select(func.max(AnalysisRun.id))
        .where(
            AnalysisRun.tenant_id == tenant_id,
            AnalysisRun.is_active.is_(True),
            AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES),
            AnalysisRun.sbom_id.in_(sbom_ids),
        )
        .group_by(AnalysisRun.sbom_id)
    )


def advisor_latest_runs(db: Session, *, tenant_id: int, sbom_ids) -> dict[int, tuple[int, str | None]]:
    """``{sbom_id: (run_id, completed_on)}`` for each analysed eligible SBOM."""
    rows = db.execute(
        select(AnalysisRun.sbom_id, AnalysisRun.id, AnalysisRun.completed_on).where(
            AnalysisRun.tenant_id == tenant_id,
            AnalysisRun.id.in_(_latest_run_ids(tenant_id, sbom_ids)),
        )
    ).all()
    return {int(sbom_id): (int(run_id), completed_on) for sbom_id, run_id, completed_on in rows}


def advisor_current_findings(db: Session, *, tenant_id: int, sbom_ids) -> list[Any]:
    """Findings of each eligible SBOM's latest successful run."""
    return list(
        db.execute(
            select(
                AnalysisFinding.analysis_run_id,
                AnalysisFinding.component_id,
                AnalysisFinding.vuln_id,
                AnalysisFinding.aliases,
                AnalysisFinding.severity,
                AnalysisFinding.score,
                AnalysisFinding.vector,
                AnalysisFinding.cvss_version,
            ).where(
                AnalysisFinding.tenant_id == tenant_id,
                AnalysisFinding.is_active.is_(True),
                AnalysisFinding.analysis_run_id.in_(_latest_run_ids(tenant_id, sbom_ids)),
            )
        ).all()
    )


def advisor_component_occurrences(db: Session, *, tenant_id: int, sbom_ids) -> list[Any]:
    """Every active component row in the eligible SBOMs, duplicates included.

    Duplicate rows are kept so findings attached to them still count toward
    their canonical version; usage counts skip them.
    """
    return list(
        db.execute(
            select(*_OCCURRENCE_COLUMNS)
            .join(SBOMSource, SBOMSource.id == SBOMComponent.sbom_id)
            .where(
                SBOMComponent.tenant_id == tenant_id,
                SBOMComponent.is_active.is_(True),
                SBOMComponent.sbom_id.in_(sbom_ids),
                SBOMSource.tenant_id == tenant_id,
            )
            .order_by(SBOMComponent.id)
        ).all()
    )


def advisor_current_vex_contexts(db: Session, *, tenant_id: int, sbom_ids) -> dict[tuple[int, int, str], tuple[str, str]]:
    """``{(sbom_id, component_id, canonical_vuln): (effective, reconciliation)}``.

    Only current, mapped contexts: unresolved mappings have no component and
    cannot be attributed to a version (VEX-MAP-001).
    """
    rows = db.execute(
        select(
            VexInvestigation.sbom_id,
            VexInvestigation.component_id,
            VexInvestigation.canonical_vulnerability_id,
            VexInvestigation.effective_status,
            VexInvestigation.reconciliation_status,
        ).where(
            VexInvestigation.tenant_id == tenant_id,
            VexInvestigation.is_current.is_(True),
            VexInvestigation.component_id.is_not(None),
            VexInvestigation.sbom_id.in_(sbom_ids),
        )
    ).all()
    return {
        (int(sbom_id), int(component_id), str(vuln).upper()): (str(effective), str(reconciliation))
        for sbom_id, component_id, vuln, effective, reconciliation in rows
    }


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def _max_iso(left: str | None, right: str | None) -> str | None:
    if left is None:
        return right
    if right is None:
        return left
    return max(left, right)


def component_intelligence_snapshot(
    db: Session,
    *,
    tenant_id: int,
    sbom_ids,
    accepted_risk_evaluator=None,
    trust_evaluator=None,
    purpose_records: dict[str, list[PurposeRecord]] | None = None,
) -> ComponentIntelligenceSnapshot:
    """Unique component versions with risk, usage, lifecycle, purpose and freshness.

    Seams (supplied by the service layer, pure callables):

    * ``accepted_risk_evaluator(record) -> AcceptedRiskOutcome | None``
      (FR-SCA-004). Called before bucketing, with ``review_reasons`` set.
    * ``trust_evaluator(record) -> TrustOutcome | None`` (FR-SCA-005). Called
      after bucketing; trust is a flag, never a risk bucket.
    * ``purpose_records`` — curated / package / AI purpose rows by family
      key (FR-SCA-009). SBOM-declared descriptions are added here.

    With no seams, nothing is Accepted Risk or Trusted and purpose comes from
    SBOM descriptions only.
    """
    occurrences = advisor_component_occurrences(db, tenant_id=tenant_id, sbom_ids=sbom_ids)
    latest_runs = advisor_latest_runs(db, tenant_id=tenant_id, sbom_ids=sbom_ids)
    findings = advisor_current_findings(db, tenant_id=tenant_id, sbom_ids=sbom_ids)
    contexts = advisor_current_vex_contexts(db, tenant_id=tenant_id, sbom_ids=sbom_ids)

    run_to_sbom = {run_id: sbom_id for sbom_id, (run_id, _) in latest_runs.items()}
    eligible_sbom_count = db.execute(select(func.count()).select_from(sbom_ids.subquery())).scalar() or 0

    # --- group occurrences by unique version --------------------------------
    key_of_component: dict[int, str] = {}
    sbom_of_component: dict[int, int] = {}
    groups: dict[str, list[Any]] = defaultdict(list)
    identities: dict[str, Any] = {}
    # Versions recur across SBOMs (adoption), so derive each distinct identity
    # once. Occurrence-level fallbacks embed the row id and are never shared.
    identity_cache: dict[tuple, Any] = {}
    for row in occurrences:
        fields = (
            row.dedupe_canonical_id, row.normalized_purl, row.primary_cpe, row.normalized_ecosystem,
            row.normalized_name, row.normalized_version, row.normalized_supplier,
            row.canonical_identity_confidence,
        )
        identity = identity_cache.get(fields)
        if identity is None:
            identity = version_identity(row)
            if identity.basis != "occurrence":
                identity_cache[fields] = identity
        key_of_component[row.id] = identity.key
        sbom_of_component[row.id] = row.sbom_id
        groups[identity.key].append(row)
        identities.setdefault(identity.key, identity)

    # --- attach findings via their VEX context -----------------------------
    vulns: dict[str, dict[str, _VulnAccumulator]] = defaultdict(dict)
    review: dict[str, set[ReviewReason]] = defaultdict(set)
    matched_contexts: set[tuple[int, int, str]] = set()
    unattributed_actionable = 0
    for finding in findings:
        sbom_id = run_to_sbom.get(finding.analysis_run_id)
        component_id = finding.component_id
        key = key_of_component.get(component_id) if component_id is not None else None
        canonical = canonical_for_finding(finding).canonical_id
        context_key = (sbom_id, component_id, canonical) if key is not None else None
        context = contexts.get(context_key) if context_key else None
        effective = context[0] if context else None
        actionable = is_actionable(effective)
        if key is None or sbom_of_component.get(component_id) != sbom_id:
            if actionable:
                unattributed_actionable += 1
            continue
        matched_contexts.add(context_key)
        if context and context[1] in RECONCILIATION_REVIEW_REASONS:
            review[key].add(RECONCILIATION_REVIEW_REASONS[context[1]])
        vulns[key].setdefault(canonical, _VulnAccumulator()).add(
            severity=normalize_severity(finding.severity),
            actionable=actionable,
            effective=effective,
            score=finding.score,
            vector=finding.vector,
            cvss_version=finding.cvss_version,
        )

    vex_only: dict[str, int] = defaultdict(int)
    for context_key, (effective, reconciliation) in contexts.items():
        if context_key in matched_contexts:
            continue
        key = key_of_component.get(context_key[1])
        if key is None:
            continue
        vex_only[key] += 1
        if reconciliation in RECONCILIATION_REVIEW_REASONS:
            review[key].add(RECONCILIATION_REVIEW_REASONS[reconciliation])
        if effective == "AFFECTED":
            review[key].add(ReviewReason.VEX_ONLY_AFFECTED)

    # --- build one record per unique version --------------------------------
    snapshot = ComponentIntelligenceSnapshot(
        unattributed_actionable_findings=unattributed_actionable,
        analysed_sbom_count=len(latest_runs),
        eligible_sbom_count=int(eligible_sbom_count),
    )
    for key, rows in groups.items():
        primary_rows = [row for row in rows if not row.is_duplicate] or rows
        lead = primary_rows[0]
        identity = identities[key]
        sbom_set = sorted({row.sbom_id for row in primary_rows})
        analysed = [row for row in primary_rows if row.sbom_id in latest_runs]
        latest_analysis_at = None
        evidence = []
        for sbom_id in sbom_set:
            if sbom_id in latest_runs:
                run_id, completed_on = latest_runs[sbom_id]
                latest_analysis_at = _max_iso(latest_analysis_at, completed_on)
                evidence.append({"sbom_id": sbom_id, "analysis_run_id": run_id})
        snapshot.latest_analysis_at = _max_iso(snapshot.latest_analysis_at, latest_analysis_at)

        version_vulns = vulns.get(key, {})
        actionable_vulns = [v for v in version_vulns.values() if v.actionable]
        severity_counts = {name: 0 for name in _SEVERITY_KEYS}
        for vuln in actionable_vulns:
            severity_counts[vuln.severity.lower()] += 1
        scored = [v for v in actionable_vulns if v.max_score is not None]
        top = max(scored, key=lambda v: v.max_score) if scored else None

        reasons = set(review.get(key, ()))
        if identity.confidence == LOW:
            reasons.add(ReviewReason.LOW_IDENTITY_CONFIDENCE)

        lifecycle = lifecycle_view(primary_rows)
        record = ComponentVersionIntelligence(
            canonical_key=key,
            identity_basis=identity.basis,
            identity_confidence=identity.confidence,
            family_key=family_key(lead),
            name=lead.name,
            version=lead.version,
            purl=lead.normalized_purl or lead.purl,
            cpe=lead.primary_cpe or lead.cpe,
            supplier=lead.supplier,
            component_type=lead.component_type,
            ecosystem=lead.normalized_ecosystem or lead.ecosystem,
            licenses=split_licenses(*(row.license for row in primary_rows)),
            occurrence_count=len(primary_rows),
            sbom_ids=sbom_set,
            project_ids=sorted({row.project_id for row in primary_rows if row.project_id is not None}),
            product_ids=sorted({row.product_id for row in primary_rows if row.product_id is not None}),
            references=[
                {
                    "component_id": row.id,
                    "sbom_id": row.sbom_id,
                    "sbom_name": row.sbom_name,
                    "project_id": row.project_id,
                    "product_id": row.product_id,
                }
                for row in primary_rows
            ],
            actionable_vulnerability_count=len(actionable_vulns),
            non_actionable_vulnerability_count=len(version_vulns) - len(actionable_vulns),
            actionable_severity_counts=severity_counts,
            highest_actionable_severity=None,
            cvss={
                "max_score": top.max_score if top else None,
                "vector": top.vector if top else None,
                "version": top.cvss_version if top else None,
                "scored_vulnerability_count": len(scored),
            },
            classification=RiskClassification.UNKNOWN,
            review_reasons=[],
            accepted_risk_policy_version_id=None,
            lifecycle=lifecycle,
            latest_analysis_at=latest_analysis_at,
            analysed_occurrence_count=len(analysed),
            evidence=evidence,
            vex_only_context_count=vex_only.get(key, 0),
            actionable_vex_statuses=frozenset().union(*(v.vex_statuses for v in actionable_vulns)),
            actionable_vulnerability_ids=sorted(cid for cid, v in version_vulns.items() if v.actionable),
            sbom_descriptions=[(row.sbom_id, row.description) for row in primary_rows],
        )
        record.purpose = resolve_purpose(
            sbom_descriptions=record.sbom_descriptions,
            records=(purpose_records or {}).get(record.family_key or "", ()),
        )
        record.review_reasons = sorted(reason.value for reason in reasons)
        accepted: AcceptedRiskOutcome | None = (
            accepted_risk_evaluator(record) if accepted_risk_evaluator is not None else None
        )
        record.accepted_risk = accepted
        result = classify(
            ClassificationInput(
                has_vulnerability_evidence=bool(analysed),
                actionable_severities=tuple(v.severity for v in actionable_vulns),
                review_reasons=frozenset(reasons),
                accepted_risk=accepted,
            )
        )
        record.classification = result.classification
        record.highest_actionable_severity = result.highest_actionable_severity
        record.review_reasons = list(result.review_reasons)
        record.accepted_risk_policy_version_id = result.accepted_risk_policy_version_id
        if trust_evaluator is not None:
            record.trust = trust_evaluator(record)
            record.trust_policy_configured = record.trust is not None
        snapshot.versions.append(record)

    snapshot.versions.sort(key=lambda v: (str(v.name).lower(), str(v.version or ""), v.canonical_key))
    return snapshot


def advisor_remediation_hints(
    db: Session, *, tenant_id: int, sbom_ids, component_ids: list[int]
) -> dict[str, Any]:
    """Version hints for same-family discovery (FR-SCA-013).

    * ``lifecycle``: latest / latest-supported / recommended versions named by
      lifecycle enrichment on the given occurrences — the most recently
      checked occurrence wins per field.
    * ``fixed_versions``: ``{canonical_vuln_id: [versions]}`` declared by the
      findings of each SBOM's latest successful run (Convention A) on those
      occurrences.
    """
    from ..services.finding_metrics import parse_json_list

    if not component_ids:
        return {"lifecycle": {}, "fixed_versions": {}}
    rows = db.execute(
        select(
            SBOMComponent.latest_version,
            SBOMComponent.latest_supported_version,
            SBOMComponent.recommended_version,
            SBOMComponent.lifecycle_checked_at,
        ).where(SBOMComponent.tenant_id == tenant_id, SBOMComponent.id.in_(component_ids))
    ).all()
    lifecycle: dict[str, str] = {}
    for latest, supported, recommended, _checked in sorted(rows, key=lambda r: r.lifecycle_checked_at or "", reverse=True):
        for name, value in (("LIFECYCLE_LATEST", latest), ("LIFECYCLE_LATEST_SUPPORTED", supported),
                            ("LIFECYCLE_RECOMMENDED", recommended)):
            if value and name not in lifecycle:
                lifecycle[name] = value

    findings = db.execute(
        select(AnalysisFinding.vuln_id, AnalysisFinding.aliases, AnalysisFinding.fixed_versions).where(
            AnalysisFinding.tenant_id == tenant_id,
            AnalysisFinding.is_active.is_(True),
            AnalysisFinding.component_id.in_(component_ids),
            AnalysisFinding.analysis_run_id.in_(_latest_run_ids(tenant_id, sbom_ids)),
        )
    ).all()
    fixed: dict[str, list[str]] = {}
    for finding in findings:
        versions = parse_json_list(finding.fixed_versions)
        if not versions:
            continue
        canonical = canonical_for_finding(finding).canonical_id
        bucket = fixed.setdefault(canonical, [])
        bucket.extend(v for v in versions if v not in bucket)
    return {"lifecycle": lifecycle, "fixed_versions": fixed}


def advisor_version_history(
    db: Session, *, tenant_id: int, sbom_ids, component_ids: list[int], since_iso: str
) -> dict[str, Any]:
    """Vulnerability observations for one version over a window (FR-SCA-016).

    **Convention C** (every successful run, not just the latest) because
    history needs every past detection — but only runs of the caller's
    eligible SBOMs, so inactive / superseded SBOMs never contribute (spec §1.3).
    Returns the finding rows and the run coverage actually available.
    """
    if not component_ids:
        return {"findings": [], "runs": 0, "earliest_run_at": None, "latest_run_at": None}
    runs = select(AnalysisRun.id).where(
        AnalysisRun.tenant_id == tenant_id,
        AnalysisRun.is_active.is_(True),
        AnalysisRun.run_status.in_(COMPLETED_RUN_STATUSES),
        AnalysisRun.sbom_id.in_(sbom_ids),
        AnalysisRun.sbom_id.in_(select(SBOMComponent.sbom_id).where(SBOMComponent.id.in_(component_ids))),
        AnalysisRun.completed_on >= since_iso,
    )
    coverage = db.execute(
        select(func.count(AnalysisRun.id), func.min(AnalysisRun.completed_on), func.max(AnalysisRun.completed_on))
        .where(AnalysisRun.id.in_(runs))
    ).one()
    rows = db.execute(
        select(
            AnalysisFinding.vuln_id, AnalysisFinding.aliases, AnalysisFinding.severity,
            AnalysisFinding.published_on, AnalysisRun.completed_on,
        )
        .join(AnalysisRun, AnalysisRun.id == AnalysisFinding.analysis_run_id)
        .where(
            AnalysisFinding.tenant_id == tenant_id,
            AnalysisFinding.is_active.is_(True),
            AnalysisFinding.component_id.in_(component_ids),
            AnalysisFinding.analysis_run_id.in_(runs),
        )
    ).all()
    findings = [
        {
            "canonical_id": canonical_for_finding(row).canonical_id,
            "severity": normalize_severity(row.severity),
            "published_on": row.published_on,
            "observed_at": row.completed_on,
        }
        for row in rows
    ]
    return {"findings": findings, "runs": int(coverage[0] or 0), "earliest_run_at": coverage[1], "latest_run_at": coverage[2]}


def advisor_vulnerability_source_freshness(db: Session) -> dict[str, Any]:
    """When vulnerability data was last refreshed (FR-SCA-020).

    The NVD mirror's latest successful sync, when the mirror is in use.
    Per-analysis source outcomes stay on each run; this is the platform-level
    refresh signal shown beside every recommendation.
    """
    from ..nvd_mirror.db.models import NvdSyncRunRow

    finished = None
    try:
        # Savepoint: a missing mirror table must not abort the caller's transaction.
        with db.begin_nested():
            finished = db.execute(
                select(func.max(NvdSyncRunRow.finished_at)).where(NvdSyncRunRow.status == "success")
            ).scalar()
    except Exception:  # noqa: BLE001 - absent mirror tables mean "not tracked", never an error
        finished = None
    return {"nvd_mirror_last_success_at": finished.isoformat() if finished else None}


def advisor_invalidation_key(db: Session, *, tenant_id: int) -> tuple:
    """Change markers for a tenant's advisor inputs that the shared metrics key misses.

    ``app.metrics.cache.invalidation_key`` tracks runs, SBOM count and
    findings. The advisor also depends on VEX decisions (a manual NOT_AFFECTED
    must leave the Critical KPI immediately), component lifecycle data, SBOM /
    product / project activation and lineage. Each marker is a single
    aggregate over an indexed tenant column.
    """
    from ..models import Product, Projects

    vex = db.execute(
        select(
            func.count(VexInvestigation.id),
            func.max(VexInvestigation.id),
            func.max(VexInvestigation.updated_at),
            func.coalesce(func.sum(VexInvestigation.row_version), 0),
            func.max(VexInvestigation.last_seen_at),
            # Reconciliation can change status without touching updated_at.
            func.count(VexInvestigation.id).filter(VexInvestigation.is_current.is_(True)),
            func.count(VexInvestigation.id).filter(
                VexInvestigation.effective_status.in_(("AFFECTED", "UNDER_INVESTIGATION"))
            ),
            func.count(VexInvestigation.id).filter(
                VexInvestigation.reconciliation_status.in_(("CONFLICT_REVIEW_REQUIRED", "REVALIDATION_REQUIRED"))
            ),
        ).where(VexInvestigation.tenant_id == tenant_id)
    ).one()
    components = db.execute(
        select(
            func.count(SBOMComponent.id),
            func.max(SBOMComponent.id),
            func.max(SBOMComponent.lifecycle_checked_at),
        ).where(SBOMComponent.tenant_id == tenant_id)
    ).one()
    s = SBOMSource.__table__.c
    sboms = db.execute(
        select(
            func.count(s.id),
            func.count(s.id).filter(s.is_active.is_(True)),
            func.count(s.parent_id),
            func.max(s.modified_on),
        ).where(s.tenant_id == tenant_id)
    ).one()
    p = Product.__table__.c
    products = db.execute(
        select(func.count(p.id).filter(p.is_active.is_(True) & p.deleted_at.is_(None))).where(p.tenant_id == tenant_id)
    ).scalar()
    j = Projects.__table__.c
    projects = db.execute(
        select(func.count(j.id).filter(j.is_active.is_(True))).where(j.tenant_id == tenant_id)
    ).scalar()
    return (tuple(vex), tuple(components), tuple(sboms), products, projects)


def component_advisor_bucket_counts(snapshot: ComponentIntelligenceSnapshot) -> dict[str, Any]:
    """Bucket counts that sum to the unique version count (spec §2, T7)."""
    counts = bucket_counts(version.classification for version in snapshot.versions)
    return {
        "unique_component_versions": len(snapshot.versions),
        "by_classification": counts,
        "end_of_life_or_support": sum(1 for v in snapshot.versions if v.is_end_of_life),
        "unattributed_actionable_findings": snapshot.unattributed_actionable_findings,
    }


__all__ = [
    "advisor_invalidation_key",
    "advisor_version_history",
    "advisor_vulnerability_source_freshness",
    "advisor_remediation_hints",
    "ComponentIntelligenceSnapshot",
    "ComponentVersionIntelligence",
    "advisor_component_occurrences",
    "advisor_current_findings",
    "advisor_current_vex_contexts",
    "advisor_latest_runs",
    "component_advisor_bucket_counts",
    "component_intelligence_snapshot",
]
