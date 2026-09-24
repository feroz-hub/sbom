"""PR-2 engine tests — VEX reconciliation rules, mapping and applicability.

One test per spec section 47 row that the engine owns, named
``test_<scenario>__<REQ_ID>``. Dashboard aggregation (PR-3), the portfolio API
(PR-4) and the UI (PR-5) are out of scope here.

Spec: docs/requirements/vex-dashboard-investigation.md sections 4, 11, 14-20.
"""

import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

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
from app.services.lifecycle.vex_provider import is_vex_assertion
from app.services.vex.matching import match_component, version_applies
from app.services.vex.reconciliation import recompute_for_sbom

NOW = "2026-09-24T00:00:00Z"


class _EngineTestCase(unittest.TestCase):
    """Disposable database with one SBOM and two component versions."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.db = Session(self.engine)
        self.sbom = SBOMSource(sbom_name="engine-test", sbom_data="{}", tenant_id=1)
        self.db.add(self.sbom)
        self.db.flush()
        self.openssl_111 = self._component("openssl", "1.1.1", purl="pkg:generic/openssl@1.1.1")
        self.openssl_308 = self._component("openssl", "3.0.8", purl="pkg:generic/openssl@3.0.8")
        self.zlib = self._component("zlib", "1.2.11", purl="pkg:generic/zlib@1.2.11")
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def _component(self, name, version, **kwargs):
        component = SBOMComponent(
            sbom_id=self.sbom.id, name=name, version=version, tenant_id=1, **kwargs
        )
        self.db.add(component)
        self.db.flush()
        return component

    def _run(self, status="OK", query_error_count=0):
        run = AnalysisRun(
            sbom_id=self.sbom.id,
            tenant_id=1,
            run_status=status,
            started_on=NOW,
            completed_on=NOW,
            query_error_count=query_error_count,
        )
        self.db.add(run)
        self.db.flush()
        return run

    def _finding(self, run, component, vuln_id, source="NVD", aliases=None):
        finding = AnalysisFinding(
            analysis_run_id=run.id,
            component_id=component.id,
            vuln_id=vuln_id,
            tenant_id=1,
            source=source,
            aliases=aliases,
        )
        self.db.add(finding)
        self.db.flush()
        return finding

    def _document(self, *, author="Supplier A", source_document_id="doc-a"):
        document = VexDocument(
            sbom_id=self.sbom.id,
            tenant_id=1,
            source_type="uploaded",
            format="openvex",
            author=author,
            source_document_id=source_document_id,
            uploaded_at=NOW,
        )
        self.db.add(document)
        self.db.flush()
        return document

    def _statement(
        self,
        component,
        vuln_id,
        status,
        *,
        document=None,
        manual=False,
        version_applicable=None,
    ):
        statement = VexStatement(
            vex_document_id=None if manual else (document or self._document()).id,
            sbom_id=self.sbom.id,
            component_id=component.id if component else None,
            vulnerability_id=vuln_id,
            tenant_id=1,
            status=status,
            normalized_status=status.upper(),
            source_name="Manual VEX Override" if manual else "Imported",
            created_at=NOW,
            version_applicable=version_applicable,
        )
        self.db.add(statement)
        self.db.flush()
        return statement

    def contexts(self):
        return {
            (c.component_id, c.canonical_vulnerability_id): c
            for c in self.db.query(VexInvestigation).all()
        }

    def reconcile(self):
        result = recompute_for_sbom(self.db, tenant_id=1, sbom_id=self.sbom.id)
        self.db.commit()
        return result


class ReconciliationRuleTests(_EngineTestCase):
    """VEX-REC-002 scenarios A-H."""

    def test_analyzer_only__VEX_REC_002_A(self):
        run = self._run()
        self._finding(run, self.openssl_111, "CVE-2026-5001")
        self.reconcile()
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-5001")]
        self.assertEqual(context.effective_status, "UNDER_INVESTIGATION")
        self.assertEqual(context.reconciliation_status, "ANALYZER_ONLY")

    def test_analyzer_and_vex_not_affected__VEX_REC_002_B(self):
        run = self._run()
        self._finding(run, self.openssl_111, "CVE-2026-4001")
        self._statement(self.openssl_111, "CVE-2026-4001", "not_affected")
        self.reconcile()
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-4001")]
        self.assertEqual(context.effective_status, "NOT_AFFECTED")
        self.assertEqual(context.reconciliation_status, "MATCHED")
        self.assertEqual(len(self.contexts()), 1, "must not duplicate the context")

    def test_vex_only_not_affected__VEX_REC_002_C(self):
        self._run()
        self._statement(self.openssl_111, "CVE-2026-4001", "not_affected")
        self.reconcile()
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-4001")]
        self.assertEqual(context.effective_status, "NOT_AFFECTED")
        self.assertEqual(context.reconciliation_status, "VEX_ONLY")
        self.assertEqual(self.db.query(AnalysisFinding).count(), 0)

    def test_vex_only_affected_is_flagged__VEX_REC_002_D(self):
        self._run()
        self._statement(self.openssl_111, "CVE-2026-4002", "affected")
        self.reconcile()
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-4002")]
        self.assertEqual(context.effective_status, "AFFECTED")
        self.assertEqual(context.reconciliation_status, "VEX_ONLY")

    def test_vex_only_fixed__VEX_REC_002_C(self):
        self._run()
        self._statement(self.openssl_111, "CVE-2026-4003", "fixed")
        self.reconcile()
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-4003")]
        self.assertEqual(context.effective_status, "FIXED")
        self.assertEqual(context.reconciliation_status, "VEX_ONLY")

    def test_analyzer_and_vex_affected__VEX_REC_002_E(self):
        run = self._run()
        self._finding(run, self.openssl_111, "CVE-2026-4004")
        self._statement(self.openssl_111, "CVE-2026-4004", "affected")
        self.reconcile()
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-4004")]
        self.assertEqual(context.effective_status, "AFFECTED")
        self.assertEqual(context.reconciliation_status, "MATCHED")

    def test_analyzer_and_vex_under_investigation__VEX_REC_002_F(self):
        run = self._run()
        self._finding(run, self.openssl_111, "CVE-2026-4005")
        self._statement(self.openssl_111, "CVE-2026-4005", "under_investigation")
        self.reconcile()
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-4005")]
        self.assertEqual(context.effective_status, "UNDER_INVESTIGATION")
        self.assertEqual(context.reconciliation_status, "MATCHED")

    def test_redetected_fixed_requires_revalidation__VEX_REC_002_G(self):
        run = self._run()
        self._finding(run, self.openssl_111, "CVE-2026-4006")
        statement = self._statement(self.openssl_111, "CVE-2026-4006", "fixed")
        self.reconcile()
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-4006")]
        self.assertEqual(context.effective_status, "UNDER_INVESTIGATION")
        self.assertEqual(context.reconciliation_status, "REVALIDATION_REQUIRED")
        # The source's FIXED assertion is preserved, not rewritten.
        self.db.refresh(statement)
        self.assertEqual(statement.status, "fixed")
        self.assertEqual(statement.normalized_status, "FIXED")

    def test_conflicting_independent_sources__VEX_INV_005(self):
        run = self._run()
        self._finding(run, self.openssl_111, "CVE-2026-4007")
        a = self._document(author="Supplier A", source_document_id="doc-a")
        b = self._document(author="Supplier B", source_document_id="doc-b")
        self._statement(self.openssl_111, "CVE-2026-4007", "not_affected", document=a)
        self._statement(self.openssl_111, "CVE-2026-4007", "affected", document=b)
        self.reconcile()
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-4007")]
        self.assertEqual(context.effective_status, "UNDER_INVESTIGATION")
        self.assertEqual(context.reconciliation_status, "CONFLICT_REVIEW_REQUIRED")
        # Neither assertion was discarded; both remain accessible.
        self.assertEqual(self.db.query(VexStatement).count(), 2)

    def test_new_version_of_one_document_is_not_a_conflict__VEX_INV_005(self):
        """A newer version of the same document supersedes its predecessor."""
        run = self._run()
        self._finding(run, self.openssl_111, "CVE-2026-4008")
        document = self._document(author="Supplier A", source_document_id="doc-a")
        self._statement(self.openssl_111, "CVE-2026-4008", "affected", document=document)
        self._statement(self.openssl_111, "CVE-2026-4008", "not_affected", document=document)
        self.reconcile()
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-4008")]
        self.assertEqual(context.reconciliation_status, "MATCHED")
        self.assertEqual(context.effective_status, "NOT_AFFECTED")

    def test_manual_decision_outranks_later_import__VEX_INV_004(self):
        run = self._run()
        self._finding(run, self.openssl_111, "CVE-2026-4009")
        self._statement(self.openssl_111, "CVE-2026-4009", "not_affected", manual=True)
        self._statement(self.openssl_111, "CVE-2026-4009", "affected")
        self.reconcile()
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-4009")]
        self.assertEqual(context.effective_status, "NOT_AFFECTED")
        # The import is still stored and visible.
        self.assertEqual(self.db.query(VexStatement).count(), 2)


class ContextIdentityTests(_EngineTestCase):
    """VEX-CTX-001/002 and VEX-REC-003 — one context per real vulnerability."""

    def test_ghsa_finding_and_cve_vex_share_one_context__VEX_CTX_002(self):
        run = self._run()
        self._finding(
            run, self.openssl_111, "GHSA-abcd-1234-5678", aliases='["CVE-2026-4001"]'
        )
        self._statement(self.openssl_111, "CVE-2026-4001", "not_affected")
        self.reconcile()
        self.assertEqual(len(self.contexts()), 1)
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-4001")]
        self.assertEqual(context.reconciliation_status, "MATCHED")
        self.assertIn("GHSA-ABCD-1234-5678", context.aliases_json)

    def test_same_cve_on_two_components_is_two_contexts__VEX_CTX_001(self):
        run = self._run()
        self._finding(run, self.openssl_111, "CVE-2026-4001")
        self._finding(run, self.zlib, "CVE-2026-4001")
        self.reconcile()
        self.assertEqual(len(self.contexts()), 2)

    def test_same_cve_on_two_versions_is_two_contexts__VEX_CTX_001(self):
        run = self._run()
        self._finding(run, self.openssl_111, "CVE-2026-4001")
        self._finding(run, self.openssl_308, "CVE-2026-4001")
        self.reconcile()
        self.assertEqual(len(self.contexts()), 2)

    def test_multiple_scanners_collapse_to_one_context__VEX_REC_003(self):
        run = self._run()
        self._finding(run, self.openssl_111, "CVE-2026-4001", source="NVD")
        self._finding(run, self.openssl_111, "CVE-2026-4001", source="OSV")
        self._finding(
            run, self.openssl_111, "GHSA-abcd-1234-5678",
            source="GITHUB", aliases='["CVE-2026-4001"]',
        )
        self.reconcile()
        self.assertEqual(len(self.contexts()), 1)


class DetectionStateTests(_EngineTestCase):
    """VEX-REC-004 — a failed query is not a negative determination."""

    def test_source_failure_is_not_not_detected__VEX_REC_004(self):
        self._run(query_error_count=2)
        self._statement(self.openssl_111, "CVE-2026-4001", "not_affected")
        self.reconcile()
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-4001")]
        self.assertEqual(context.analyzer_detection_state, "SOURCE_ERROR")

    def test_clean_run_without_a_hit_is_not_detected__VEX_REC_004(self):
        self._run(query_error_count=0)
        self._statement(self.openssl_111, "CVE-2026-4001", "not_affected")
        self.reconcile()
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-4001")]
        self.assertEqual(context.analyzer_detection_state, "NOT_DETECTED")

    def test_no_run_at_all_is_not_queried__VEX_REC_004(self):
        self._statement(self.openssl_111, "CVE-2026-4001", "not_affected")
        self.reconcile()
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-4001")]
        self.assertEqual(context.analyzer_detection_state, "NOT_QUERIED")

    def test_only_the_latest_successful_run_counts__GAP_008(self):
        old_run = self._run()
        self._finding(old_run, self.openssl_111, "CVE-2026-OLD1")
        new_run = self._run()
        self._finding(new_run, self.openssl_111, "CVE-2026-NEW1")
        self.reconcile()
        keys = {key[1] for key in self.contexts()}
        self.assertIn("CVE-2026-NEW1", keys)
        self.assertNotIn("CVE-2026-OLD1", keys)


class ReanalysisTests(_EngineTestCase):
    """VEX-INV-001/002 — evidence updates, decisions survive, history stays."""

    def test_reanalysis_preserves_a_manual_decision__VEX_INV_001(self):
        run = self._run()
        self._finding(run, self.openssl_111, "CVE-2026-5001")
        self._statement(self.openssl_111, "CVE-2026-5001", "not_affected", manual=True)
        self.reconcile()
        first = self.contexts()[(self.openssl_111.id, "CVE-2026-5001")]
        self.assertEqual(first.effective_status, "NOT_AFFECTED")
        first_seen = first.first_seen_at

        second_run = self._run()
        self._finding(second_run, self.openssl_111, "CVE-2026-5001")
        self.reconcile()
        again = self.contexts()[(self.openssl_111.id, "CVE-2026-5001")]
        self.assertEqual(again.effective_status, "NOT_AFFECTED")
        self.assertEqual(again.first_seen_at, first_seen)
        self.assertEqual(again.last_analysis_run_id, second_run.id)

    def test_recompute_is_idempotent(self):
        run = self._run()
        self._finding(run, self.openssl_111, "CVE-2026-5001")
        first = self.reconcile()
        second = self.reconcile()
        self.assertEqual(first["created"], 1)
        self.assertEqual(second["created"], 0)
        self.assertEqual(self.db.query(VexInvestigation).count(), 1)
        # An unchanged recompute must not churn row_version.
        context = self.contexts()[(self.openssl_111.id, "CVE-2026-5001")]
        self.assertEqual(context.row_version, 1)

    def test_vanished_context_is_retired_not_deleted__VEX_INV_002(self):
        run = self._run()
        self._finding(run, self.openssl_111, "CVE-2026-5001")
        self.reconcile()

        later = self._run()
        self._finding(later, self.openssl_111, "CVE-2026-5002")
        self.reconcile()

        rows = {c.canonical_vulnerability_id: c for c in self.db.query(VexInvestigation).all()}
        self.assertEqual(len(rows), 2, "history is retained")
        self.assertFalse(rows["CVE-2026-5001"].is_current)
        self.assertTrue(rows["CVE-2026-5002"].is_current)


class MappingTests(_EngineTestCase):
    """VEX-MAP-001/002 — candidates, ambiguity and version applicability."""

    def test_purl_beats_name_and_binds_exactly__VEX_MAP_001(self):
        match = match_component(
            {"purl": "pkg:generic/openssl@3.0.8"},
            [self.openssl_111, self.openssl_308, self.zlib],
        )
        self.assertEqual(match.component_id, self.openssl_308.id)
        self.assertEqual(match.strategy.value, "PURL")
        self.assertEqual(match.confidence.value, "EXACT")

    def test_ambiguous_weak_match_does_not_bind__VEX_MAP_001(self):
        """Two components share the name 'openssl': never pick the first."""
        match = match_component("openssl", [self.openssl_111, self.openssl_308])
        self.assertTrue(match.is_ambiguous)
        self.assertIsNone(match.component_id)
        self.assertEqual(match.confidence.value, "UNRESOLVED")
        self.assertEqual(len(match.candidates), 2)

    def test_unique_weak_match_binds_but_stays_weak__VEX_MAP_001(self):
        match = match_component("zlib", [self.openssl_111, self.zlib])
        self.assertEqual(match.component_id, self.zlib.id)
        self.assertEqual(match.confidence.value, "WEAK")

    def test_unmatched_reference_is_retained_not_dropped__VEX_MAP_001(self):
        match = match_component("nothing-like-this", [self.openssl_111])
        self.assertTrue(match.is_unmatched)
        self.assertIsNone(match.component_id)

    def test_unresolved_mapping_becomes_its_own_context__VEX_MAP_001(self):
        self._run()
        self._statement(None, "CVE-2026-4001", "not_affected")
        self.reconcile()
        context = self.db.query(VexInvestigation).one()
        self.assertIsNone(context.component_id)
        self.assertEqual(context.component_key, 0)
        self.assertEqual(context.reconciliation_status, "UNRESOLVED_MAPPING")
        self.assertNotEqual(context.unresolved_discriminator, "")

    def test_two_unresolved_assertions_do_not_collide__VEX_MAP_001(self):
        self._run()
        a = self._document(author="A", source_document_id="doc-a")
        b = self._document(author="B", source_document_id="doc-b")
        self._statement(None, "CVE-2026-4001", "not_affected", document=a)
        self._statement(None, "CVE-2026-4001", "affected", document=b)
        self.reconcile()
        self.assertEqual(self.db.query(VexInvestigation).count(), 2)
        # And recompute stays idempotent for them.
        self.reconcile()
        self.assertEqual(self.db.query(VexInvestigation).count(), 2)

    def test_version_range_that_does_not_apply__VEX_MAP_002(self):
        self.assertTrue(version_applies("1.2", ">= 1.0, < 1.4"))
        self.assertFalse(version_applies("2.0", ">= 1.0, < 1.4"))
        self.assertIsNone(version_applies("2.0", None))
        self.assertTrue(version_applies("1.1.1", ["1.1.1", "1.1.2"]))
        self.assertFalse(version_applies("3.0.8", ["1.1.1"]))

    def test_non_applicable_statement_cannot_become_effective__VEX_MAP_002(self):
        run = self._run()
        self._finding(run, self.openssl_308, "CVE-2026-4001")
        self._statement(
            self.openssl_308, "CVE-2026-4001", "not_affected", version_applicable=False
        )
        self.reconcile()
        context = self.contexts()[(self.openssl_308.id, "CVE-2026-4001")]
        self.assertEqual(context.effective_status, "UNDER_INVESTIGATION")
        self.assertEqual(context.reconciliation_status, "ANALYZER_ONLY")
        # Retained as evidence.
        self.assertEqual(self.db.query(VexStatement).count(), 1)


class EmbeddedDetectionTests(unittest.TestCase):
    """VEX-ING-001 — disclosure data is not an exploitability determination."""

    def test_plain_vulnerability_entry_is_not_a_vex_assertion__VEX_ING_001(self):
        self.assertFalse(is_vex_assertion({"id": "CVE-2026-4001"}))
        self.assertFalse(
            is_vex_assertion({"id": "CVE-2026-4001", "affects": [{"ref": "openssl"}]})
        )

    def test_analysis_block_makes_it_a_vex_assertion__VEX_ING_001(self):
        self.assertTrue(
            is_vex_assertion({"id": "CVE-2026-4001", "analysis": {"state": "not_affected"}})
        )
        self.assertTrue(
            is_vex_assertion({"id": "CVE-2026-4001", "analysis": {"justification": "x"}})
        )

    def test_affected_version_status_makes_it_a_vex_assertion__VEX_ING_001(self):
        self.assertTrue(
            is_vex_assertion(
                {
                    "id": "CVE-2026-4001",
                    "affects": [{"ref": "openssl", "versions": [{"status": "unaffected"}]}],
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
