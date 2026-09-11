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

    def test_three_decisions_and_another_sbom_version_are_independent(self):
        from app.services.lifecycle.vex_provider import component_vulnerabilities, pair_history, vex_dashboard_summary
        self.override('CVE-2026-0001', 'affected')
        self.override('CVE-2026-0002', 'not_affected', justification='code not present')
        self.override('CVE-2026-0003', 'fixed', fixed_version='2')
        sbom2 = SBOMSource(sbom_name='vex-test-v2', sbom_data='{}', tenant_id=1)
        self.db.add(sbom2)
        self.db.flush()
        comp2 = SBOMComponent(sbom_id=sbom2.id, name='demo', version='1', tenant_id=1)
        self.db.add(comp2)
        self.db.commit()
        apply_vex_override(self.db, comp2.id, 'CVE-2026-0001', {'status': 'affected', 'reason': 'other version'})
        self.override('CVE-2026-0001', 'under_investigation')
        data = component_vulnerabilities(self.db, tenant_id=1, sbom_id=self.component.sbom_id, component_id=self.component.id)
        self.assertEqual({r['vulnerability_id']: r['current_decision']['status'] for r in data['vulnerabilities']}, {
            'CVE-2026-0001': 'under_investigation', 'CVE-2026-0002': 'not_affected', 'CVE-2026-0003': 'fixed'})
        other = component_vulnerabilities(self.db, tenant_id=1, sbom_id=sbom2.id, component_id=comp2.id)
        self.assertEqual(other['vulnerabilities'][0]['current_decision']['status'], 'affected')
        history = pair_history(self.db, tenant_id=1, sbom_id=self.component.sbom_id,
                               component_id=self.component.id, vulnerability_id='CVE-2026-0001')
        self.assertEqual(len(history['statements']), 2)
        self.assertEqual(vex_report(self.db, self.component.sbom_id)['summary']['total'], 3)
        self.assertEqual(vex_dashboard_summary(self.db)['affected_count'], 1)

    def test_scoped_api_rejects_wrong_tenant_or_sbom(self):
        from app.routers.vex import get_component_vulnerabilities, patch_vex_override, get_vex_override_history
        from app.services.lifecycle.vex_provider import component_vulnerabilities
        self.override('CVE-2026-0001')
        for tenant, sbom in [(2, self.component.sbom_id), (1, 999)]:
            with self.subTest(tenant=tenant, sbom=sbom), self.assertRaises(HTTPException):
                component_vulnerabilities(self.db, tenant_id=tenant, sbom_id=sbom, component_id=self.component.id)
        context = Mock(tenant_id=1)
        for endpoint, args in [(patch_vex_override, (self.component.id, 'CVE-2026-0001', {'status': 'fixed', 'reason': 'test', 'fixed_version': '2'})),
                               (get_vex_override_history, (self.component.id, 'CVE-2026-0001'))]:
            with self.subTest(endpoint=endpoint.__name__), self.assertRaises(HTTPException):
                endpoint(*args, context=context, db=self.db, sbom_id=999)
        self.assertEqual(self.db.query(VexStatement).count(), 1)

    def test_scoped_list_union_and_history_include_imports(self):
        from app.services.lifecycle.vex_provider import component_vulnerabilities, pair_history
        self.test_detected_findings_are_options_without_a_vex_statement()
        imported = VexStatement(tenant_id=1, sbom_id=self.component.sbom_id, component_id=self.component.id,
            vulnerability_id='CVE-2026-1234', status='affected', source_name='Vendor', created_at='2026-01-01')
        self.db.add(imported)
        self.db.commit()
        self.override('CVE-2026-1234', 'fixed', fixed_version='2')
        self.override('VENDOR-42', 'under_investigation')
        data = component_vulnerabilities(self.db, tenant_id=1, sbom_id=self.component.sbom_id, component_id=self.component.id)
        self.assertEqual(len(data['vulnerabilities']), 2)
        self.assertEqual(len(data['vulnerabilities'][0]['findings']), 1)
        self.assertEqual(data['vulnerabilities'][1]['findings'], [])
        history = pair_history(self.db, tenant_id=1, sbom_id=self.component.sbom_id,
                               component_id=self.component.id, vulnerability_id='cve-2026-1234')
        self.assertEqual([r['status'] for r in history['statements']], ['fixed', 'affected'])
        self.assertEqual(history['current_decision']['status'], 'fixed')

    def test_analysis_and_exports_use_effective_pair_decisions(self):
        import csv
        import io
        import json
        from app.routers.analysis import export_csv, export_sarif
        from app.routers.runs import list_run_findings, list_run_findings_enriched
        from app.services.lifecycle.vex_provider import vex_report_csv
        from app.metrics.reporting import latest_snapshots
        from app.metrics.base import COMPLETED_RUN_STATUSES
        from app.services.fda_510k_excel_report_service import Fda510kExcelReportService
        run = AnalysisRun(sbom_id=self.component.sbom_id, tenant_id=1, run_status=next(iter(COMPLETED_RUN_STATUSES)),
                          started_on='2026-01-01T00:00:00Z', completed_on='2026-01-01T00:01:00Z')
        self.db.add(run)
        self.db.flush()
        for vuln in ['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003']:
            self.db.add(AnalysisFinding(analysis_run_id=run.id, component_id=self.component.id,
                component_name='demo', component_version='1', vuln_id=vuln, tenant_id=1, severity='HIGH'))
        self.db.commit()
        self.override('CVE-2026-0001', 'under_investigation')
        self.override('CVE-2026-0001', 'affected')
        self.override('CVE-2026-0002', 'not_affected', justification='not shipped')
        self.override('CVE-2026-0003', 'fixed', fixed_version='2')
        expected = {'CVE-2026-0001': 'affected', 'CVE-2026-0002': 'not_affected', 'CVE-2026-0003': 'fixed'}
        context = Mock(tenant_id=1)
        findings = list_run_findings(run.id, severity=None, page=1, page_size=100, context=context, db=self.db)
        self.assertEqual({row.vuln_id: row.vex_status for row in findings}, expected)
        enriched = list_run_findings_enriched(run.id, severity=None, page=1, page_size=100, context=context, db=self.db)
        self.assertEqual({row['vuln_id']: row['vex_status'] for row in enriched}, expected)
        data = list(csv.DictReader(io.StringIO(export_csv(run.id, context, self.db).body.decode())))
        self.assertEqual({row['vuln_id']: row['vex_status'] for row in data}, expected)
        sarif = json.loads(export_sarif(run.id, context, self.db).body)
        self.assertEqual({row['ruleId']: row['properties']['vex_status'] for row in sarif['runs'][0]['results']}, expected)
        self.assertEqual(len(list(csv.DictReader(io.StringIO(vex_report_csv(self.db, self.component.sbom_id))))), 3)
        snapshot = latest_snapshots(self.db, sbom_ids=[self.component.sbom_id], tenant_id=1, as_of='2027-01-01')
        self.assertEqual(snapshot[self.component.sbom_id]['vex_reduced_count'], 2)
        rows = Fda510kExcelReportService(self.db)._vulnerability_rows({self.component.sbom_id: run})
        self.assertEqual(len(rows), 3)
        self.assertEqual({row['vulnerability_id']: row['vex_status'].lower().replace(' ', '_') for row in rows}, expected)

    def test_unmatched_evidence_does_not_reduce_component_risk_counts(self):
        from app.services.lifecycle.vex_provider import vex_dashboard_summary
        self.db.add(VexStatement(tenant_id=1, sbom_id=self.component.sbom_id, component_id=None,
            vulnerability_id='CVE-2026-0001', status='not_affected', source_name='Vendor', created_at='2026-01-01'))
        self.db.commit()
        report = vex_report(self.db, self.component.sbom_id)
        self.assertEqual(report['summary']['unmatched'], 1)
        self.assertEqual(report['summary']['total'], 0)
        self.assertEqual(vex_dashboard_summary(self.db)['vulnerabilities_reduced_by_vex'], 0)
