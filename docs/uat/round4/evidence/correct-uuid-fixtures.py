"""Explicit Round4 fixture corrections; public wire IDs and internal ORM keys stay distinct."""
from pathlib import Path
import json,sys
preview='--preview' in sys.argv
R=Path('/Users/ferozebasha/sbom');D=Path(__file__).resolve().parent
if not preview:
 manifest=json.loads((D/'remaining-run-manifest.json').read_text())
 assert manifest['sourceUnchangedDuringRun'] and manifest['exitCode'] in (0,1)
changed=[]
planned={}
def edit(name, pairs):
 p=R/'tests'/name;s=planned.get(name,p.read_text())
 for old,new in pairs:
  assert old in s,(name,old)
  s=s.replace(old,new)
 planned[name]=s;changed.append(name)
# Existing ORM objects: only URL interpolations change. Their .id remains the FK.
for name, names in {
 'test_sbom_vulnerability_excel_report.py':['sbom'],
 'test_lifecycle_cache_upsert.py':['sbom'],
 'test_lifecycle_enrichment.py':['sbom','component'],
 'test_lifecycle_xeol_openeox.py':['sbom'],
 'test_metric_consistency.py':['s1'],
 'test_sbom_lifecycle_remediation.py':['child','sbom','proj'],
 'test_sbom_operational_lifecycle.py':['sbom'],
 'test_sboms_analyze_stream.py':['sbom'],
}.items():
 pairs=[('{'+n+'.id}', '{'+n+'.public_id}') for n in names]
 # These expressions occur only in HTTP URLs in the reviewed files.
 edit(name,pairs)
edit('test_sbom_vulnerability_excel_report.py', [('"/api/sboms/999999999/reports/vulnerabilities.xlsx"','f"/api/sboms/{uuid4()}/reports/vulnerabilities.xlsx"')])
edit('test_lifecycle_enrichment.py', [('from datetime import', 'from uuid import uuid4\n\nfrom datetime import'), ('"/api/components/999999/lifecycle-override"','f"/api/components/{uuid4()}/lifecycle-override"')])
edit('test_sbom_operational_lifecycle.py', [('other_id = other.id','other_id = str(other.public_id)'), ('"version_a": sbom.id, "version_b": other.id','"version_a": str(sbom.public_id), "version_b": str(other.public_id)'), ('json={"sbom_id": sbom.id}', 'json={"sbom_id": str(sbom.public_id)}')])
edit('test_component_deduplication.py', [('sbom_id = sbom.id','sbom_id = str(sbom.public_id)')])
edit('test_component_finding_reconciliation.py', [('assert finding["component_id"] == stored.id','assert finding["component_id"] == str(stored.public_id)')])
edit('test_dashboard_v4_metrics.py', [('i["sbom_id"] == s.id','i["sbom_id"] == str(s.public_id)')])
edit('test_sbom_latest_analysis_summary.py', [('sbom_id=sbom.id)', 'sbom_id=str(sbom.public_id))'), ('== [default_sbom.id]', '== [str(default_sbom.public_id)]')])
edit('test_large_sbom_upload_integrity.py', [('from tests.tenant_fixture_scope import','from tests.public_id_fixture import public_row\nfrom tests.tenant_fixture_scope import'), ('verify_upload_integrity(db, sbom_id,','verify_upload_integrity(db, public_row(db, SBOMSource, sbom_id).id,'), ('item["id"] == sbom.id','item["id"] == str(sbom.public_id)')])
edit('test_sbom_upload_version_lineage.py', [('from tests.tenant_fixture_scope import','from tests.public_id_fixture import public_row\nfrom tests.tenant_fixture_scope import'), ('db.get(SBOMSource, resp.json()["sbom_id"])','public_row(db, SBOMSource, resp.json()["sbom_id"])'), ('db.get(SBOMSource, second_id)','public_row(db, SBOMSource, second_id)'), ('child.parent_id == first_id','child.parent_id == public_row(db, SBOMSource, first_id).id'), ('db.get(SBOMSource, v3).parent_id == v2','public_row(db, SBOMSource, v3).parent_id == public_row(db, SBOMSource, v2).id'), ('parent_sbom_id=99_999_999','parent_sbom_id=str(uuid.uuid4())')])
# Fixture exposes UUID to HTTP; only _set_pending performs an internal write.
edit('test_sbom_revalidate_endpoint.py', [('return sbom.id','return str(sbom.public_id)'), ('assert db.get(SBOMSource, sbom_id) is not None','from tests.public_id_fixture import public_row\n        row = public_row(db, SBOMSource, sbom_id)'), ('SBOMSource.id == sbom_id,','SBOMSource.id == row.id,'), ('"/api/sboms/99999999/revalidate"','f"/api/sboms/{uuid.uuid4()}/revalidate"')])
edit('test_sbom_validation_report_endpoint.py', [('"/api/sboms/99999999/validation-report"','f"/api/sboms/{uuid.uuid4()}/validation-report"')])
# Foreign fixtures are materialized while the actual owner is bound.
edit('test_tenant_isolation.py', [('"tenant_b_id": t2.id','"tenant_b_id": str(t2.public_id)'), ('"project_b_id": project_b.id','"project_b_id": str(project_b.public_id)'), ('"product_b_id": product_b.id','"product_b_id": str(product_b.public_id)'), ('"sbom_b_id": sbom_b.id','"sbom_b_id": str(sbom_b.public_id)'), ('    if resp.status_code == 200:\n        # Same numeric id may exist in tenant A — must not return tenant B\'s row.\n        assert resp.json().get("sbom_name") != "sbom-b"\n    else:\n        assert resp.status_code == 404','    assert resp.status_code == 404'), ('    if resp.status_code == 200:\n        assert resp.json().get("project_name") != "Project B"\n    else:\n        assert resp.status_code == 404','    assert resp.status_code == 404')])
# Internal restoration assertion still uses the integer key, request uses known foreign UUID.
edit('test_tenant_boundary_hardening.py', [('    response = client.post(f"/api/projects/{identifiers[tenant_b, False]}/restore")','    with tenant_scope(minimal_background_context(tenant_b)), SessionLocal() as db:\n        foreign = db.scalar(select(Projects).where(Projects.id == identifiers[tenant_b, False]).execution_options(include_deleted=True))\n        public_id = str(foreign.public_id)\n    response = client.post(f"/api/projects/{public_id}/restore")')])
# All references in these fields are public API scope DTOs, not domain scopes.
edit('test_component_advisor_api.py', [('    AnalysisFinding,','    AnalysisFinding,\n    Projects,\n    Tenant,'), ('"project_id": other.project_id, "product_id": other.id','"project_id": str(other.project.public_id), "product_id": str(other.public_id)'), ('params["project_id"] = product.project_id','params["project_id"] = str(product.project.public_id)'), ('params["product_id"] = product.id','params["product_id"] = str(product.public_id)'), ('{s.id for s in seeded["sboms"][:2]}','{str(s.public_id) for s in seeded["sboms"][:2]}'), ('def test_T11_tenant_a_responses_never_include_tenant_b__FR_SCA_023(client, seeded):','def test_T11_tenant_a_responses_never_include_tenant_b__FR_SCA_023(client, seeded, db):'), ('summary["meta"]["scope"]["tenant"]["id"] == 1','summary["meta"]["scope"]["tenant"]["id"] == str(db.get(Tenant, 1).public_id)'), ('params={"product_id": product.id}','params={"product_id": str(product.public_id)}'), ('params = {"project_id": product.project_id, "product_id": product.id}','params = {"project_id": str(product.project.public_id), "product_id": str(product.public_id)}'), ('own_project = seeded["products"][0].project_id','own_project = str(seeded["products"][0].project.public_id)')])
edit('test_component_advisor_recommendations_api.py', [('== seeded["sboms"][0].id','== str(seeded["sboms"][0].public_id)'), ('"project_id": product.project_id, "product_id": product.id, "sbom_id": sbom.id','"project_id": str(product.project.public_id), "product_id": str(product.public_id), "sbom_id": str(sbom.public_id)')])
edit('test_component_advisor_review_api.py', [('project_id = db.scalar(select(Projects.id).order_by(Projects.id).limit(1))','project_id = str(db.scalar(select(Projects.public_id).order_by(Projects.id).limit(1)))')])
# .id in audits and service calls stays internal; only project delete URL changes.
edit('test_soft_delete.py', [('f"/api/projects/{pid}"','f"/api/projects/{proj.public_id}"')])
# One delete fixture names the object project, not proj.
s=planned['test_soft_delete.py'];start=s.index('def test_permanent_project_delete_removes_repair_workspaces');end=s.index('\ndef ',start+5)
s=s[:start]+s[start:end].replace('{proj.public_id}', '{project.public_id}')+s[end:];planned['test_soft_delete.py']=s
for name,source in planned.items():
 import ast
 ast.parse(source)
if preview:
 print('Validated proposed edits for',len(planned),'files; repository source untouched');sys.exit(0)
for name,source in planned.items():
 p=R/'tests'/name;backup=D/'before'/'tests'/name;backup.parent.mkdir(parents=True,exist_ok=True)
 assert not backup.exists();backup.write_text(p.read_text());p.write_text(source)
(D/'fixture-correction-files.json').write_text(json.dumps(changed,indent=2)+'\n')
print('Explicit fixture corrections:',len(set(changed)))
