"""PR-3 tests — VEX dashboard metrics over reconciled contexts.

Spec: docs/requirements/vex-dashboard-investigation.md sections 21-26 and 45.

The headline case is section 24: three analyser CVEs plus one embedded
VEX-only CVE must report 3 analyser findings and 4 VEX contexts. Those two
totals are deliberately different (VEX-DASH-001).
"""

import unittest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.metrics.vex import vex_context_counts
from app.models import (
    AnalysisFinding,
    AnalysisRun,
    Base,
    SBOMComponent,
    SBOMSource,
    VexDocument,
    VexInvestigation,
    VexStatement,
)
from app.services.lifecycle.vex_provider import vex_dashboard_summary, vex_report
from app.services.vex.reconciliation import recompute_for_sbom

NOW = "2026-09-24T00:00:00Z"


class _MetricsTestCase(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.db = Session(self.engine)
        self.sbom = SBOMSource(sbom_name="metrics-test", sbom_data="{}", tenant_id=1, is_active=True)
        self.db.add(self.sbom)
        self.db.flush()
        self.component = SBOMComponent(
            sbom_id=self.sbom.id, name="openssl", version="1.1.1", tenant_id=1
        )
        self.db.add(self.component)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def _run(self, status="OK"):
        run = AnalysisRun(
            sbom_id=self.sbom.id, tenant_id=1, run_status=status,
            started_on=NOW, completed_on=NOW,
        )
        self.db.add(run)
        self.db.flush()
        return run

    def _finding(self, run, vuln_id, component=None):
        self.db.add(
            AnalysisFinding(
                analysis_run_id=run.id,
                component_id=(component or self.component).id,
                vuln_id=vuln_id,
                tenant_id=1,
                source="NVD",
            )
        )
        self.db.flush()

    def _statement(self, vuln_id, status, component=None):
        document = VexDocument(
            sbom_id=self.sbom.id, tenant_id=1, source_type="embedded",
            format="cyclonedx", author="Vendor", source_document_id=f"doc-{vuln_id}",
            uploaded_at=NOW,
        )
        self.db.add(document)
        self.db.flush()
        statement = VexStatement(
            vex_document_id=document.id,
            sbom_id=self.sbom.id,
            component_id=(component or self.component).id,
            vulnerability_id=vuln_id,
            tenant_id=1,
            status=status,
            normalized_status=status.upper(),
            source_name="Vendor",
            created_at=NOW,
        )
        self.db.add(statement)
        self.db.flush()
        return statement

    def summary(self):
        recompute_for_sbom(self.db, tenant_id=1, sbom_id=self.sbom.id)
        self.db.commit()
        return vex_dashboard_summary(self.db, tenant_id=1, sbom_ids=[self.sbom.id])


class SpecSection24Tests(_MetricsTestCase):
    """The worked example from spec section 24, end to end."""

    def test_three_analyser_cves_and_one_vex_only__VEX_DASH_001(self):
        run = self._run()
        for vuln in ("CVE-2026-5001", "CVE-2026-5002", "CVE-2026-5003"):
            self._finding(run, vuln)
        self._statement("CVE-2026-4001", "not_affected")

        payload = self.summary()

        # Two separate totals: 3 analyser findings, 4 reconciled contexts.
        self.assertEqual(self.db.query(AnalysisFinding).count(), 3)
        self.assertEqual(payload["total_contexts"], 4)

        self.assertEqual(payload["affected_count"], 0)
        self.assertEqual(payload["not_affected_count"], 1)
        self.assertEqual(payload["fixed_count"], 0)
        self.assertEqual(payload["under_investigation_count"], 3)

        self.assertEqual(payload["matched_count"], 0)
        self.assertEqual(payload["analyzer_only_count"], 3)
        self.assertEqual(payload["vex_only_count"], 1)
        self.assertEqual(payload["needs_review_count"], 0)


class InvariantTests(_MetricsTestCase):
    """VEX-DASH-002 — the status totals must reconcile."""

    def _assert_invariant(self, payload):
        self.assertEqual(
            payload["total_contexts"],
            payload["affected_count"]
            + payload["not_affected_count"]
            + payload["fixed_count"]
            + payload["under_investigation_count"],
        )

    def test_invariant_holds_for_mapped_contexts__VEX_DASH_002(self):
        run = self._run()
        self._finding(run, "CVE-2026-5001")
        self._finding(run, "CVE-2026-5002")
        self._statement("CVE-2026-5001", "not_affected")
        self._statement("CVE-2026-4001", "affected")
        self._assert_invariant(self.summary())

    def test_unresolved_mappings_are_excluded_from_the_total__VEX_DASH_002(self):
        """An unresolved mapping must not deflate a disposition count."""
        self._run()
        document = VexDocument(
            sbom_id=self.sbom.id, tenant_id=1, source_type="uploaded",
            format="openvex", author="Vendor", source_document_id="doc-x", uploaded_at=NOW,
        )
        self.db.add(document)
        self.db.flush()
        self.db.add(
            VexStatement(
                vex_document_id=document.id, sbom_id=self.sbom.id, component_id=None,
                vulnerability_id="CVE-2026-9999", tenant_id=1, status="not_affected",
                normalized_status="NOT_AFFECTED", source_name="Vendor", created_at=NOW,
            )
        )
        self.db.flush()
        self._statement("CVE-2026-4001", "affected")

        payload = self.summary()
        self.assertEqual(payload["unresolved_mapping_count"], 1)
        self.assertEqual(payload["total_contexts"], 1, "unresolved is excluded")
        self._assert_invariant(payload)

    def test_needs_review_covers_conflict_and_revalidation__VEX_DASH_003(self):
        run = self._run()
        self._finding(run, "CVE-2026-4006")
        self._statement("CVE-2026-4006", "fixed")  # redetected -> REVALIDATION_REQUIRED
        payload = self.summary()
        self.assertEqual(payload["revalidation_required_count"], 1)
        self.assertEqual(payload["needs_review_count"], 1)


class ResponseShapeTests(_MetricsTestCase):
    """VEX-API-001 — new fields added, every legacy field retained."""

    LEGACY_FIELDS = (
        "affected_count",
        "not_affected_count",
        "fixed_count",
        "under_investigation_count",
        "unknown_count",
        "vulnerabilities_reduced_by_vex",
        "vulnerabilities_requiring_action",
        "top_affected_components",
    )
    NEW_FIELDS = (
        "total_contexts",
        "analyzer_only_count",
        "vex_only_count",
        "matched_count",
        "conflict_review_count",
        "revalidation_required_count",
        "unresolved_mapping_count",
        "needs_review_count",
    )

    def test_every_legacy_field_survives__VEX_API_001(self):
        payload = self.summary()
        for field in self.LEGACY_FIELDS:
            self.assertIn(field, payload, f"{field} must remain for compatibility")

    def test_new_reconciliation_fields_are_present__VEX_API_001(self):
        payload = self.summary()
        for field in self.NEW_FIELDS:
            self.assertIn(field, payload)

    def test_unknown_count_is_deprecated_and_folded_in__section_8(self):
        run = self._run()
        self._finding(run, "CVE-2026-5001")
        self._statement("CVE-2026-4001", "unknown")
        payload = self.summary()
        self.assertEqual(payload["unknown_count"], 0)
        # The unknown assertion is under investigation, not a fifth status.
        self.assertGreaterEqual(payload["under_investigation_count"], 2)

    def test_top_affected_components_is_deterministic(self):
        run = self._run()
        for index in range(3):
            component = SBOMComponent(
                sbom_id=self.sbom.id, name=f"lib{index}", version="1", tenant_id=1
            )
            self.db.add(component)
            self.db.flush()
            self._finding(run, f"CVE-2026-60{index}", component=component)
            self._statement(f"CVE-2026-60{index}", "affected", component=component)

        first = self.summary()["top_affected_components"]
        second = self.summary()["top_affected_components"]
        self.assertEqual(first, second, "ordering must be stable across calls")
        self.assertEqual(len(first), 3)
        self.assertTrue(all(item["status"] == "affected" for item in first))


class ScopeTests(_MetricsTestCase):
    """VEX-DASH-004/005 — scope is explicit and excludes inactive SBOMs."""

    def _second_sbom(self, *, is_active=True, parent_id=None):
        other = SBOMSource(
            sbom_name="other", sbom_data="{}", tenant_id=1,
            is_active=is_active, parent_id=parent_id,
        )
        self.db.add(other)
        self.db.flush()
        component = SBOMComponent(sbom_id=other.id, name="zlib", version="1", tenant_id=1)
        self.db.add(component)
        run = AnalysisRun(
            sbom_id=other.id, tenant_id=1, run_status="OK", started_on=NOW, completed_on=NOW
        )
        self.db.add(run)
        self.db.flush()
        self.db.add(
            AnalysisFinding(
                analysis_run_id=run.id, component_id=component.id,
                vuln_id="CVE-2026-7001", tenant_id=1, source="NVD",
            )
        )
        self.db.commit()
        recompute_for_sbom(self.db, tenant_id=1, sbom_id=other.id)
        self.db.commit()
        return other

    def test_counts_respect_the_supplied_sbom_scope__VEX_DASH_004(self):
        run = self._run()
        self._finding(run, "CVE-2026-5001")
        other = self._second_sbom()
        self.summary()

        both = vex_dashboard_summary(self.db, tenant_id=1, sbom_ids=[self.sbom.id, other.id])
        just_one = vex_dashboard_summary(self.db, tenant_id=1, sbom_ids=[self.sbom.id])
        self.assertEqual(both["total_contexts"], 2)
        self.assertEqual(just_one["total_contexts"], 1)

    def test_excluded_sbom_contributes_nothing__VEX_DASH_005(self):
        """Whatever the scope leaves out — inactive or superseded — is absent.

        The active/HEAD rules themselves live in
        ``DashboardScope.eligible_sbom_ids`` and are tested there; what matters
        here is that this aggregation honours the ids it is given.
        """
        run = self._run()
        self._finding(run, "CVE-2026-5001")
        excluded = self._second_sbom(is_active=False)
        self.summary()

        payload = vex_dashboard_summary(self.db, tenant_id=1, sbom_ids=[self.sbom.id])
        self.assertEqual(payload["total_contexts"], 1)
        # The context still exists for history, it is simply out of scope.
        self.assertEqual(
            self.db.query(VexInvestigation).filter_by(sbom_id=excluded.id).count(), 1
        )

    def test_tile_counts_equal_the_rows_a_query_would_return__VEX_DASH_004(self):
        """Tiles and the future investigation table must agree by construction."""
        run = self._run()
        self._finding(run, "CVE-2026-5001")
        self._finding(run, "CVE-2026-5002")
        self._statement("CVE-2026-4001", "not_affected")
        payload = self.summary()

        rows = self.db.scalars(
            select(VexInvestigation).where(
                VexInvestigation.tenant_id == 1,
                VexInvestigation.is_current.is_(True),
                VexInvestigation.sbom_id.in_([self.sbom.id]),
                VexInvestigation.reconciliation_status != "UNRESOLVED_MAPPING",
            )
        ).all()
        self.assertEqual(payload["total_contexts"], len(rows))

    def test_counts_are_tenant_scoped__VEX_SEC_002(self):
        run = self._run()
        self._finding(run, "CVE-2026-5001")
        self.summary()
        other_tenant = vex_context_counts(self.db, tenant_id=2, sbom_ids=[self.sbom.id])
        self.assertEqual(other_tenant["total_contexts"], 0)


class ExportCompatibilityTests(_MetricsTestCase):
    """DoD 19 — the existing report path keeps working."""

    def test_vex_report_still_produces_statement_rows(self):
        run = self._run()
        self._finding(run, "CVE-2026-5001")
        self._statement("CVE-2026-4001", "not_affected")
        self.summary()

        report = vex_report(self.db, self.sbom.id)
        self.assertIn("summary", report)
        self.assertIn("statements", report)
        self.assertEqual(report["summary"]["not_affected"], 1)
        self.assertEqual(report["summary"]["total"], 1)


if __name__ == "__main__":
    unittest.main()
