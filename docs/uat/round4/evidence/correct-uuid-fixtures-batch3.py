"""Repair, ingestion and background-task tests retain internal integer FKs."""
from pathlib import Path
import ast,json,re
R=Path('/Users/ferozebasha/sbom');D=Path(__file__).resolve().parent;changed=[]
def edit(name,pairs):
 p=R/'tests'/name;s=before=p.read_text()
 for old,new in pairs:
  assert old in s,(name,old);s=s.replace(old,new)
 ast.parse(s)
 if s!=before:
  b=D/'before'/'tests'/name;b.parent.mkdir(parents=True,exist_ok=True)
  if not b.exists():b.write_text(before)
  p.write_text(s);changed.append(name)
for name in ['test_sbom_repair_release.py','test_sbom_quality_integration.py','test_sbom_spdx_integration.py','test_sbom_spdx_release.py','test_sbom_upload_validation_persisted.py','test_sboms_analyze_snapshot.py','test_sbom_assign_and_edit.py','test_postgresql_integration.py','test_schedules_api.py']:
 p=R/'tests'/name;s=p.read_text();tree=ast.parse(s)
 future=[n for n in tree.body if isinstance(n,ast.ImportFrom) and n.module=='__future__'];line=future[-1].end_lineno if future else tree.body[0].end_lineno if isinstance(tree.body[0],ast.Expr) and isinstance(tree.body[0].value,ast.Constant) and isinstance(tree.body[0].value.value,str) else 0
 lines=s.splitlines(keepends=True);lines.insert(line,'\nfrom tests.public_id_fixture import public_row\n');s=''.join(lines)
 # Reviewed get() usages in these repair modules all consume HTTP response identities.
 if name in ['test_sbom_repair_release.py','test_sbom_quality_integration.py','test_sbom_spdx_integration.py']:
  s=s.replace('db.get(SBOMSource,','public_row(db, SBOMSource,')
 edit(name,[(p.read_text(),s)])
edit('test_sbom_repair_release.py',[('from app.models import AuditLog,','from app.models import Product, Projects, AuditLog,'), ('accepted.product_id == product["id"]','accepted.product_id == public_row(db, Product, product["id"]).id'),('accepted.projectid == project["id"]','accepted.projectid == public_row(db, Projects, project["id"]).id'),('candidate.parent_id == parent["sbom_id"]','candidate.parent_id == public_row(db, SBOMSource, parent["sbom_id"]).id'),('candidate.product_id == product["id"]','candidate.product_id == public_row(db, Product, product["id"]).id'),('db.get(Product, product["id"])','public_row(db, Product, product["id"])'),('permanently_delete_sbom(deleted[2],','permanently_delete_sbom(public_row(db, SBOMSource, deleted[2]).id,')])
edit('test_sbom_quality_integration.py',[('"/api/sboms/987654/quality"','f"/api/sboms/{__import__(\'uuid\').uuid4()}/quality"'),('permanently_delete_sbom(sbom_id,','permanently_delete_sbom(public_row(db, SBOMSource, sbom_id).id,')])
edit('test_sbom_spdx_release.py',[('permanently_delete_sbom(deleted[2],','permanently_delete_sbom(public_row(db, SBOMSource, deleted[2]).id,')])
edit('test_sbom_upload_validation_persisted.py',[('SBOMComponent.sbom_id == accepted["sbom_id"]','SBOMComponent.sbom_id == public_row(db, SBOMSource, accepted["sbom_id"]).id'),('db.get(SBOMSource, accepted["sbom_id"])','public_row(db, SBOMSource, accepted["sbom_id"])'),('assert scheduled == [accepted["sbom_id"]]','with SessionLocal() as db, verified_fixture_tenant(db, 1):\n        assert scheduled == [public_row(db, SBOMSource, accepted["sbom_id"]).id]'),('AnalysisRun.sbom_id == accepted["sbom_id"]','AnalysisRun.sbom_id == public_row(db, SBOMSource, accepted["sbom_id"]).id'),('"project_id": "999999"','"project_id": str(uuid.uuid4())')])
edit('test_sboms_analyze_snapshot.py',[('from app.models import AnalysisRun','from app.models import AnalysisRun, SBOMSource'),('sbom_id=seeded_sbom["id"]','sbom_id=public_row(db, SBOMSource, seeded_sbom["id"]).id'),('AnalysisRun.sbom_id == seeded_sbom["id"]','AnalysisRun.sbom_id == public_row(db, SBOMSource, seeded_sbom["id"]).id')])
edit('test_sbom_assign_and_edit.py',[('from app.models import AnalysisRun, AuditLog, SBOMComponent','from app.models import AnalysisRun, AuditLog, SBOMComponent, SBOMSource, Projects'),('target_id=sbom["id"]','target_id=public_row(db, SBOMSource, sbom["id"]).id'),('audit.metadata_json["new_project_id"] == project["id"]','audit.metadata_json["new_project_id"] == public_row(db, Projects, project["id"]).id'),('filter_by(sbom_id=sbom["id"])','filter_by(sbom_id=public_row(db, SBOMSource, sbom["id"]).id)'),('r.project_id == project["id"]','r.project_id == public_row(db, Projects, project["id"]).id')])
edit('test_postgresql_integration.py',[('from app.models import SBOMComponent\n','from app.models import SBOMComponent, SBOMSource\n'), ('SBOMComponent.sbom_id == sbom_id','SBOMComponent.sbom_id == public_row(session, SBOMSource, sbom_id).id')])
# Assert the queued domain keys independently of the HTTP public-ID response.
edit('test_schedules_api.py',[('assert (sbom_id, sched_id) in _stub_celery','with SessionLocal() as db, verified_fixture_tenant(db, 1):\n        assert (public_row(db, SBOMSource, sbom_id).id, sched_id) in _stub_celery'),('assert _stub_celery == [(sbom_id, sched_id)]','with SessionLocal() as db, verified_fixture_tenant(db, 1):\n        assert _stub_celery == [(public_row(db, SBOMSource, sbom_id).id, sched_id)]')])
edit('test_component_extraction_reconciliation.py',[('response = client.post(f"/api/sboms/{sbom_id}/components/reprocess")','response = client.post(f"/api/sboms/{_get_sbom(sbom_id).public_id}/components/reprocess")'),('sbom_id = sbom.id\n            before','sbom_id = str(sbom.public_id)\n            before'),('item["id"] == sbom_id','item["id"] == str(_get_sbom(sbom_id).public_id)')])
edit('test_dashboard_posture_evidence.py',[('def response(client, **params):\n    r = client.get(URL, params=params)', '''def response(client, **params):
    # Positive domain fixtures supply internal IDs to the metric layer. The
    # HTTP boundary requires the corresponding public UUIDs.
    from app.db import SessionLocal
    models = {"project_id": Projects, "product_id": Product, "sbom_id": SBOMSource}
    with SessionLocal() as db:
        from tests.tenant_fixture_scope import verified_fixture_tenant
        with verified_fixture_tenant(db, 1):
            wire_params = {key: str(db.get(models[key], value).public_id) for key, value in params.items()}
    r = client.get(URL, params=wire_params)'''),('item["target_sbom_id"] == b.id and item["posture_sbom_id"] == a.id','item["target_sbom_id"] == str(b.public_id) and item["posture_sbom_id"] == str(a.public_id)'),('i["target_sbom_id"] == missing.id','i["target_sbom_id"] == str(missing.public_id)'),('params={"project_id": app_line.project.id, "product_id": app_line.product.id, "sbom_id": sbom.id}','params={"project_id": str(app_line.project.public_id), "product_id": str(app_line.product.public_id), "sbom_id": str(sbom.public_id)}')])
edit('test_dashboard_priority_findings.py',[('from app.models import AnalysisFinding, AnalysisRun','from app.models import AnalysisFinding, AnalysisRun, Projects'),('assert client.get("/dashboard/priority-findings?project_id=3").status_code == 404','with verified_fixture_tenant(scoped_db, 2):\n            foreign_project = str(scoped_db.get(Projects, 3).public_id)\n        assert client.get(f"/dashboard/priority-findings?project_id={foreign_project}").status_code == 404')])
(D/'fixture-correction-batch3-files.json').write_text(json.dumps(changed,indent=2)+'\n')
print('Updated',len(set(changed)),'fixture modules')
