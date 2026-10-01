"""Secure Component Advisor — component intelligence over the eligible dataset.

FR-SCA-001 / FR-SCA-003 / FR-SCA-023, NFR-SCA-002, spec §1.3. Covers prompt §10
tests T1–T7 end to end through the metric layer, T10 (inactive / superseded
SBOMs excluded) and T11 (tenant isolation).

Uses an in-memory SQLite schema like ``tests/test_dashboard_scope.py`` so the
VEX contexts can be set to exact states (conflict, VEX-only, missing) without
depending on reconciliation timing. One test runs the real
``recompute_for_sbom`` to pin the canonical (CVE-preferred) join.
"""

import hashlib
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.context import minimal_background_context, tenant_scope
from app.db import Base
from app.metrics.component_advisor import component_advisor_bucket_counts
from app.models import (
    AnalysisFinding,
    AnalysisRun,
    Product,
    Projects,
    SBOMComponent,
    SBOMSource,
    Tenant,
    VexInvestigation,
)
from app.services.component_advisor.intelligence_service import build_snapshot, get_component_version
from app.services.dashboard_scope import DashboardScope

NOW = "2026-09-30T00:00:00Z"


def purl_key(purl):
    return hashlib.sha256(f"purl:{purl}".encode()).hexdigest()


class World:
    """Tiny builder for tenant → project → product → SBOM → component → finding."""

    def __init__(self, db):
        self.db = db
        self._ids = iter(range(1, 10_000))

    def _add(self, tenant_id, *rows):
        with tenant_scope(minimal_background_context(tenant_id)):
            self.db.add_all(rows)
            self.db.flush()
        return rows[0] if len(rows) == 1 else rows

    def product(self, tenant_id=1, name=None):
        name = name or f"p{next(self._ids)}"
        project = self._add(tenant_id, Projects(tenant_id=tenant_id, project_name=f"proj-{name}", project_status=1))
        product = self._add(
            tenant_id,
            Product(tenant_id=tenant_id, project_id=project.id, name=name, normalized_name=name, slug=name, created_at=NOW),
        )
        return product

    def sbom(self, product, *, active=True, parent=None, analysed=True, run_status="FINDINGS"):
        sbom = self._add(
            product.tenant_id,
            SBOMSource(
                tenant_id=product.tenant_id, projectid=product.project_id, product_id=product.id,
                sbom_name=f"sbom-{next(self._ids)}", is_active=active,
                parent_id=parent.id if parent else None,
            ),
        )
        sbom.run = self.run(sbom) if analysed else None
        if analysed and run_status != "FINDINGS":
            sbom.run.run_status = run_status
        return sbom

    def run(self, sbom, status="FINDINGS"):
        return self._add(
            sbom.tenant_id,
            AnalysisRun(
                tenant_id=sbom.tenant_id, sbom_id=sbom.id, project_id=sbom.projectid, product_id=sbom.product_id,
                run_status=status, started_on=NOW, completed_on=NOW,
            ),
        )

    def component(self, sbom, name, version, *, ecosystem="npm", purl=True, duplicate_of=None, **extra):
        normalized_purl = f"pkg:{ecosystem}/{name}@{version}" if purl and version else None
        return self._add(
            sbom.tenant_id,
            SBOMComponent(
                tenant_id=sbom.tenant_id, sbom_id=sbom.id, name=name, version=version,
                bom_ref=f"ref-{next(self._ids)}", normalized_name=name, normalized_version=version,
                normalized_ecosystem=ecosystem, normalized_purl=normalized_purl, purl=normalized_purl,
                normalized_package_key=f"{ecosystem}:{name}", is_duplicate=duplicate_of is not None,
                duplicate_of_component_id=duplicate_of.id if duplicate_of else None, **extra,
            ),
        )

    def finding(self, component, vuln_id, severity, *, run=None, aliases=None, score=None):
        sbom = self.db.get(SBOMSource, component.sbom_id)
        run = run or sbom.run
        return self._add(
            component.tenant_id,
            AnalysisFinding(
                tenant_id=component.tenant_id, analysis_run_id=run.id, component_id=component.id,
                vuln_id=vuln_id, severity=severity, aliases=aliases, score=score,
                cpe=f"cpe-{next(self._ids)}",
            ),
        )

    def vex(self, component, vuln_id, effective, reconciliation="MATCHED", *, current=True):
        return self._add(
            component.tenant_id,
            VexInvestigation(
                tenant_id=component.tenant_id, sbom_id=component.sbom_id, component_id=component.id,
                component_key=component.id, canonical_vulnerability_id=vuln_id,
                effective_status=effective, reconciliation_status=reconciliation, is_current=current,
                first_seen_at=NOW, last_seen_at=NOW, created_at=NOW,
            ),
        )


@pytest.fixture
def world():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        now = datetime.now(UTC)
        db.add_all([
            Tenant(id=1, name="One", slug="one", status="ACTIVE", created_at=now, updated_at=now),
            Tenant(id=2, name="Two", slug="two", status="ACTIVE", created_at=now, updated_at=now),
        ])
        db.flush()
        yield World(db)
    engine.dispose()


def snapshot(world, tenant_id=1, **scope):
    return build_snapshot(world.db, DashboardScope(tenant_id, **scope))


def by_name(snap):
    return {(v.name, v.version): v for v in snap.versions}


# ---------------------------------------------------------------------------
# Risk semantics end to end (T1–T7)
# ---------------------------------------------------------------------------


def test_T01_no_findings_in_analysed_snapshot_is_no_known_actionable__FR_SCA_003(world):
    sbom = world.sbom(world.product())
    world.component(sbom, "left-pad", "1.3.0")
    version = by_name(snapshot(world))[("left-pad", "1.3.0")]
    assert version.classification.value == "NO_KNOWN_ACTIONABLE_VULNERABILITIES"
    assert version.latest_analysis_at == NOW  # freshness stays visible (US-SCA-02)


@pytest.mark.parametrize("status", ["FIXED", "NOT_AFFECTED"])
def test_T02_T03_only_non_actionable_vex_is_no_known_actionable__FR_SCA_003(world, status):
    sbom = world.sbom(world.product())
    lodash = world.component(sbom, "lodash", "4.17.21")
    world.finding(lodash, "CVE-2026-0001", "CRITICAL")
    world.vex(lodash, "CVE-2026-0001", status)
    version = by_name(snapshot(world))[("lodash", "4.17.21")]
    assert version.classification.value == "NO_KNOWN_ACTIONABLE_VULNERABILITIES"
    # Non-actionable findings stay visible in overall findings.
    assert version.non_actionable_vulnerability_count == 1
    assert version.actionable_vulnerability_count == 0


def test_T04_under_investigation_is_actionable__FR_SCA_003(world):
    sbom = world.sbom(world.product())
    lodash = world.component(sbom, "lodash", "4.17.20")
    world.finding(lodash, "CVE-2026-0002", "MEDIUM")
    world.vex(lodash, "CVE-2026-0002", "UNDER_INVESTIGATION", "ANALYZER_ONLY")
    assert by_name(snapshot(world))[("lodash", "4.17.20")].classification.value == "MEDIUM"


def test_finding_with_no_vex_context_is_actionable__VEX_REC_002_A(world):
    sbom = world.sbom(world.product())
    lodash = world.component(sbom, "lodash", "4.17.19")
    world.finding(lodash, "CVE-2026-0003", "HIGH")
    assert by_name(snapshot(world))[("lodash", "4.17.19")].classification.value == "HIGH"


def test_T05_critical_plus_low_is_critical_bucket__FR_SCA_003(world):
    sbom = world.sbom(world.product())
    c = world.component(sbom, "openssl", "1.1.1", ecosystem="generic")
    world.finding(c, "CVE-2026-1000", "CRITICAL", score=9.8)
    world.finding(c, "CVE-2026-1001", "LOW", score=2.0)
    version = by_name(snapshot(world))[("openssl", "1.1.1")]
    assert version.classification.value == "CRITICAL"
    assert version.actionable_severity_counts == {"critical": 1, "high": 0, "medium": 0, "low": 1, "unknown": 0}
    assert version.cvss["max_score"] == 9.8


def test_T06_high_plus_medium_is_high_bucket_and_fixed_critical_is_ignored__FR_SCA_003(world):
    sbom = world.sbom(world.product())
    c = world.component(sbom, "jackson-databind", "2.9.0", ecosystem="maven")
    world.finding(c, "CVE-2026-2000", "HIGH")
    world.finding(c, "CVE-2026-2001", "MEDIUM")
    world.finding(c, "CVE-2026-2002", "CRITICAL")
    world.vex(c, "CVE-2026-2002", "FIXED")
    version = by_name(snapshot(world))[("jackson-databind", "2.9.0")]
    assert version.classification.value == "HIGH"
    assert version.highest_actionable_severity == "HIGH"


def test_T07_bucket_totals_reconcile_with_unique_version_count__FR_SCA_003(world):
    product = world.product()
    a, b = world.sbom(product), world.sbom(world.product())
    world.finding(world.component(a, "x", "1.0"), "CVE-2026-3000", "CRITICAL")
    world.finding(world.component(a, "y", "1.0"), "CVE-2026-3001", "LOW")
    world.component(a, "z", "1.0")
    world.component(b, "x", "1.0")  # same unique version in a second SBOM
    world.component(b, "w", None, purl=False)  # LOW identity → review
    snap = snapshot(world)
    counts = component_advisor_bucket_counts(snap)
    assert counts["unique_component_versions"] == 4
    assert sum(counts["by_classification"].values()) == counts["unique_component_versions"]
    assert counts["by_classification"]["CRITICAL"] == 1
    assert counts["by_classification"]["REVIEW_REQUIRED"] == 1


# ---------------------------------------------------------------------------
# Usage, identity and evidence
# ---------------------------------------------------------------------------


def test_usage_counts_group_occurrences_across_sboms_projects_and_products__FR_SCA_010(world):
    p1, p2 = world.product(), world.product()
    s1, s2, s3 = world.sbom(p1), world.sbom(p1, parent=None), world.sbom(p2)
    for sbom in (s1, s2, s3):
        world.component(sbom, "react", "18.2.0")
    version = by_name(snapshot(world))[("react", "18.2.0")]
    assert version.occurrence_count == 3
    assert len(version.sbom_ids) == 3
    assert len(version.product_ids) == 2
    assert len(version.project_ids) == 2
    assert version.canonical_key == purl_key("pkg:npm/react@18.2.0")
    assert version.family_key == "npm:react"


def test_evidence_references_exact_sbom_and_analysis_run__NFR_SCA_002(world):
    sbom = world.sbom(world.product())
    world.component(sbom, "react", "18.2.0")
    version = by_name(snapshot(world))[("react", "18.2.0")]
    assert version.evidence == [{"sbom_id": sbom.id, "analysis_run_id": sbom.run.id}]


def test_only_latest_successful_run_contributes__convention_A(world):
    sbom = world.sbom(world.product())
    c = world.component(sbom, "axios", "0.21.0")
    old_run = sbom.run
    world.finding(c, "CVE-2026-4000", "CRITICAL", run=old_run)
    newer = world.run(sbom)
    failed = world.run(sbom, status="ERROR")
    world.finding(c, "CVE-2026-4001", "LOW", run=newer)
    world.finding(c, "CVE-2026-4002", "CRITICAL", run=failed)
    version = by_name(snapshot(world))[("axios", "0.21.0")]
    assert version.classification.value == "LOW"
    assert version.evidence[0]["analysis_run_id"] == newer.id


def test_unanalysed_component_is_unknown_not_no_known_actionable__spec_s1_4(world):
    sbom = world.sbom(world.product(), analysed=False)
    world.component(sbom, "mystery-lib", "0.1.0")
    version = by_name(snapshot(world))[("mystery-lib", "0.1.0")]
    assert version.classification.value == "UNKNOWN"
    assert version.analysed_occurrence_count == 0


def test_findings_on_duplicate_rows_count_for_canonical_version_but_not_usage(world):
    sbom = world.sbom(world.product())
    canonical = world.component(sbom, "minimist", "1.2.5")
    duplicate = world.component(sbom, "minimist", "1.2.5", duplicate_of=canonical)
    world.finding(duplicate, "CVE-2026-5000", "HIGH")
    version = by_name(snapshot(world))[("minimist", "1.2.5")]
    assert version.occurrence_count == 1
    assert version.classification.value == "HIGH"


def test_unattributed_actionable_findings_are_surfaced_not_dropped(world):
    sbom = world.sbom(world.product())
    world.component(sbom, "react", "18.2.0")
    world._add(1, AnalysisFinding(tenant_id=1, analysis_run_id=sbom.run.id, component_id=None, vuln_id="CVE-2026-5100", severity="HIGH", cpe="x"))
    snap = snapshot(world)
    assert snap.unattributed_actionable_findings == 1
    assert component_advisor_bucket_counts(snap)["unattributed_actionable_findings"] == 1


# ---------------------------------------------------------------------------
# Review Required triggers (D-3 / D-5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reconciliation", "reason"),
    [("CONFLICT_REVIEW_REQUIRED", "VEX_CONFLICT_REVIEW_REQUIRED"), ("REVALIDATION_REQUIRED", "VEX_REVALIDATION_REQUIRED")],
)
def test_vex_review_states_require_review__D3(world, reconciliation, reason):
    sbom = world.sbom(world.product())
    c = world.component(sbom, "log4j-core", "2.14.1", ecosystem="maven")
    world.finding(c, "CVE-2021-44228", "CRITICAL")
    world.vex(c, "CVE-2021-44228", "UNDER_INVESTIGATION", reconciliation)
    version = by_name(snapshot(world))[("log4j-core", "2.14.1")]
    assert version.classification.value == "REVIEW_REQUIRED"
    assert reason in version.review_reasons
    assert version.highest_actionable_severity == "CRITICAL"


def test_vex_only_affected_requires_review_without_fabricating_a_finding__D5_VEX_DATA_003(world):
    sbom = world.sbom(world.product())
    c = world.component(sbom, "commons-text", "1.9", ecosystem="maven")
    world.vex(c, "CVE-2022-42889", "AFFECTED", "VEX_ONLY")
    version = by_name(snapshot(world))[("commons-text", "1.9")]
    assert version.classification.value == "REVIEW_REQUIRED"
    assert "VEX_ONLY_AFFECTED_ASSERTION" in version.review_reasons
    assert version.actionable_vulnerability_count == 0
    assert version.highest_actionable_severity is None


def test_retired_vex_context_is_ignored(world):
    sbom = world.sbom(world.product())
    c = world.component(sbom, "commons-text", "1.10.0", ecosystem="maven")
    world.vex(c, "CVE-2022-42889", "AFFECTED", "VEX_ONLY", current=False)
    assert by_name(snapshot(world))[("commons-text", "1.10.0")].classification.value == "NO_KNOWN_ACTIONABLE_VULNERABILITIES"


def test_ghsa_finding_joins_vex_context_keyed_by_cve_alias__VEX_CTX_002(world):
    from app.services.vex.reconciliation import recompute_for_sbom

    sbom = world.sbom(world.product())
    c = world.component(sbom, "lodash", "4.17.15")
    world.finding(c, "GHSA-p6mc-m468-83gw", "HIGH", aliases='["CVE-2020-8203"]')
    with tenant_scope(minimal_background_context(1)):
        recompute_for_sbom(world.db, tenant_id=1, sbom_id=sbom.id)
        world.db.flush()
    context = world.db.query(VexInvestigation).one()
    assert context.canonical_vulnerability_id == "CVE-2020-8203"
    context.effective_status = "NOT_AFFECTED"
    context.reconciliation_status = "MATCHED"
    world.db.flush()
    version = by_name(snapshot(world))[("lodash", "4.17.15")]
    assert version.classification.value == "NO_KNOWN_ACTIONABLE_VULNERABILITIES"


# ---------------------------------------------------------------------------
# Effective dataset (T10) and tenant isolation (T11)
# ---------------------------------------------------------------------------


def test_T10_inactive_and_superseded_sboms_do_not_contribute__spec_s1_3(world):
    product = world.product()
    inactive = world.sbom(product, active=False)
    old = world.sbom(product)
    head = world.sbom(product, parent=old)
    world.finding(world.component(inactive, "express", "4.0.0"), "CVE-2026-6000", "CRITICAL")
    world.finding(world.component(old, "express", "4.17.0"), "CVE-2026-6001", "CRITICAL")
    world.component(head, "express", "4.18.2")
    versions = by_name(snapshot(world))
    assert set(versions) == {("express", "4.18.2")}
    assert versions[("express", "4.18.2")].classification.value == "NO_KNOWN_ACTIONABLE_VULNERABILITIES"


def test_T10_inactive_product_sboms_do_not_contribute__spec_s1_3(world):
    product = world.product()
    world.component(world.sbom(product), "express", "4.18.2")
    product.is_active = False
    world.db.flush()
    assert snapshot(world).versions == []


def test_T11_tenant_a_intelligence_never_includes_tenant_b__FR_SCA_023(world):
    mine = world.sbom(world.product(tenant_id=1))
    theirs = world.sbom(world.product(tenant_id=2))
    world.component(mine, "react", "18.2.0")
    shared = world.component(theirs, "react", "18.2.0")
    world.finding(shared, "CVE-2026-7000", "CRITICAL")
    world.vex(shared, "CVE-2026-7000", "AFFECTED")
    world.component(theirs, "only-in-b", "1.0.0")

    tenant_a = by_name(snapshot(world, tenant_id=1))
    assert set(tenant_a) == {("react", "18.2.0")}
    react = tenant_a[("react", "18.2.0")]
    assert react.occurrence_count == 1
    assert react.sbom_ids == [mine.id]
    assert react.classification.value == "NO_KNOWN_ACTIONABLE_VULNERABILITIES"

    tenant_b = by_name(snapshot(world, tenant_id=2))
    assert tenant_b[("react", "18.2.0")].classification.value == "CRITICAL"


def test_T11_cross_tenant_canonical_key_is_not_found__FR_SCA_023(world):
    theirs = world.sbom(world.product(tenant_id=2))
    world.component(theirs, "only-in-b", "1.0.0")
    key = purl_key("pkg:npm/only-in-b@1.0.0")
    assert get_component_version(world.db, DashboardScope(2), key) is not None
    assert get_component_version(world.db, DashboardScope(1), key) is None


def test_scope_narrows_to_product__FR_SCA_006(world):
    p1, p2 = world.product(), world.product()
    world.component(world.sbom(p1), "react", "18.2.0")
    world.component(world.sbom(p2), "vue", "3.4.0")
    narrowed = snapshot(world, project_id=p1.project_id, product_id=p1.id)
    assert set(by_name(narrowed)) == {("react", "18.2.0")}


def test_serialised_contract_has_every_fr_sca_001_field(world):
    sbom = world.sbom(world.product())
    world.component(sbom, "react", "18.2.0", license="MIT", supplier="Meta")
    payload = by_name(snapshot(world))[("react", "18.2.0")].to_dict()
    assert payload["licenses"] == ["MIT"]
    assert payload["purpose"]["status"] == "NOT_AVAILABLE"
    assert set(payload["usage"]) >= {"active_sbom_occurrences", "project_count", "product_count", "references"}
    assert set(payload["risk"]) >= {"classification", "actionable_severity_counts", "highest_actionable_severity", "cvss"}
    assert set(payload["lifecycle"]) >= {"bucket", "status", "effective_date"}
    assert set(payload["freshness"]) >= {"latest_analysis_at", "lifecycle_checked_at"}
    assert payload["recommendation"]["status"] == "NOT_EVALUATED"
