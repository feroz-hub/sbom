"""Focused VEX decision regressions (unittest; no application server required)."""
import unittest
from unittest.mock import Mock, patch

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models import Base, AnalysisRun, AnalysisFinding, SBOMSource, SBOMComponent, VexStatement, VexOverrideAudit
from app.services.lifecycle.vex_provider import (
    apply_vex_override, effective_vex_statements, list_vex_statements, vex_report,
)


class VexDecisionTests(unittest.TestCase):
    def setUp(self):
        # Explicit disposable database, never the application's configured engine.
        self.engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(self.engine)
        self.db = Session(self.engine)
        sbom = SBOMSource(sbom_name='vex-test', sbom_data='{}', tenant_id=1)
        self.db.add(sbom)
        self.db.flush()
        self.component = SBOMComponent(sbom_id=sbom.id, name='demo', version='1', tenant_id=1)
        self.db.add(self.component)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def override(self, vuln, status='affected', **kwargs):
        return apply_vex_override(self.db, self.component.id, vuln,
                                  {'status': status, 'reason': 'reviewed', **kwargs}, changed_by='reviewer')

    def test_multiple_cves_and_history_are_independent(self):
        self.override('cve-2026-0001')
        self.override('CVE-2026-0002')
        self.override('CVE-2026-0001', 'fixed', fixed_version='2')
        data = list_vex_statements(self.db, self.component.sbom_id)
        self.assertEqual({r['vulnerability_id']: r['status'] for r in data['statements']},
                         {'CVE-2026-0001': 'fixed', 'CVE-2026-0002': 'affected'})
        self.assertEqual(self.db.query(VexStatement).count(), 3)
        self.assertEqual(self.db.query(VexOverrideAudit).count(), 3)
        self.assertEqual(vex_report(self.db, self.component.sbom_id)['summary']['total'], 2)
        self.assertEqual(len(data['vulnerability_options']), 2)

    def test_manual_decision_survives_later_import(self):
        manual = self.override('CVE-2026-0001', 'fixed', fixed_version='2')
        imported = VexStatement(id=manual.id + 1, tenant_id=1, sbom_id=manual.sbom_id,
            component_id=manual.component_id, vulnerability_id='cve-2026-0001',
            status='affected', source_name='Imported', created_at='2026-01-01')
        self.assertEqual(effective_vex_statements([imported, manual]), [manual])

    def test_invalid_pair_and_blank_evidence_are_rejected(self):
        for vuln, values in [('CVE-2026-0001,CVE-2026-0002', {}), ('CVE-bad', {}),
                             ('CVE-2026-0001', {'reason': ' '}),
                             ('CVE-2026-0001', {'status': 'fixed', 'fixed_version': ' '})]:
            with self.subTest(vuln=vuln, values=values), self.assertRaises(HTTPException):
                self.override(vuln, **values)
        self.assertEqual(self.db.query(VexStatement).count(), 0)

    def test_detected_findings_are_options_without_a_vex_statement(self):
        run = AnalysisRun(sbom_id=self.component.sbom_id, tenant_id=1, run_status='completed', started_on='2026-01-01T00:00:00Z', completed_on='2026-01-01T00:01:00Z')
        self.db.add(run)
        self.db.flush()
        self.db.add(AnalysisFinding(analysis_run_id=run.id, component_id=self.component.id,
                                   vuln_id='CVE-2026-1234', tenant_id=1))
        self.db.commit()
        data = list_vex_statements(self.db, self.component.sbom_id)
        self.assertEqual(data['statements'], [])
        self.assertEqual(data['vulnerability_options'], [
            {'component_id': self.component.id, 'vulnerability_id': 'CVE-2026-1234'}])

    def test_same_cve_in_other_scopes_remains_independent(self):
        rows = [VexStatement(id=i, tenant_id=tenant, sbom_id=sbom, component_id=component,
                             vulnerability_id='CVE-2026-0001', status='affected')
                for i, (tenant, sbom, component) in enumerate([(1, 1, 1), (1, 2, 2), (2, 3, 3)], 1)]
        self.assertEqual(len(effective_vex_statements(rows)), 3)

    def test_non_cve_identifier_is_supported(self):
        self.assertEqual(self.override('ghsa-abcd-1234-5678').vulnerability_id, 'GHSA-ABCD-1234-5678')

    def test_actor_is_taken_from_authenticated_context(self):
        from app.routers.vex import patch_vex_override
        context = Mock(tenant_id=1)
        context.actor_label.return_value = 'authenticated-reviewer'
        statement = self.override('CVE-2026-0001')
        with patch('app.routers.vex.get_component_for_tenant', return_value=self.component), patch(
            'app.routers.vex.apply_vex_override', return_value=statement
        ) as apply:
            patch_vex_override(self.component.id, 'CVE-2026-0001', {'updated_by': 'someone-else'}, context, self.db)
            self.assertEqual(apply.call_args.kwargs['changed_by'], 'authenticated-reviewer')
