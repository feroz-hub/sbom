"""Independent dashboard UUID scope and tenant-isolation controls."""
import importlib.util
import json
from pathlib import Path
from urllib.parse import urlencode

out=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('round1_api',out/'live-round1-protection.py')
client=importlib.util.module_from_spec(spec);spec.loader.exec_module(client)
client.PHASE='dashboard';f=json.loads((out/'fixtures.json').read_text())
scope={'project_id':f['project_id'],'product_id':f['product_id'],'sbom_id':f['sbom_id']}
baseline=None
for role in ('admin','analyst','developer','viewer'):
    r=client.api(role,'/dashboard/summary?'+urlencode(scope))
    data=r['data'].get('posture')
    if role=='admin':baseline=data
    client.case('R1-DASHBOARD-ROLE-'+role,'Authorized role receives identical scoped posture for disposable UUID hierarchy',r,r['status']==200 and data==baseline and data['total_sboms']==1,role)
for key,value in [('project_id','1'),('project_id','not-a-uuid'),('product_id','not-a-uuid'),('sbom_id','not-a-uuid')]:
    query={**scope,key:value};r=client.api('admin','/dashboard/summary?'+urlencode(query))
    client.case('R1-DASHBOARD-INVALID-'+key+'-'+value,'Invalid public ID is rejected server-side with 422',r,r['status']==422)
for path in ('/dashboard/summary?'+urlencode(scope),'/dashboard/filter-options/applications?project_id='+f['project_id'],'/dashboard/filter-options/sboms?'+urlencode(scope)):
    r=client.api('foreign',path)
    client.case('R1-DASHBOARD-ISOLATION-'+str(len(client.CASES)),'Foreign tenant cannot resolve Olympus metric/option scope UUIDs',r,r['status']==404,'foreign')
for query in ({'product_id':f['product_id']},{'sbom_id':f['sbom_id']},{'project_id':f['project_id'],'sbom_id':f['sbom_id']}):
    r=client.api('admin','/dashboard/summary?'+urlencode(query))
    client.case('R1-DASHBOARD-ORPHAN-'+str(len(client.CASES)),'Backend rejects orphaned child scope rather than widening it',r,r['status']==400)
projects=client.rows(client.api('admin','/api/projects')['data'])
other=next(p for p in projects if p['id']!=f['project_id'])
r=client.api('admin','/dashboard/summary?'+urlencode({**scope,'project_id':other['id']}))
client.case('R1-DASHBOARD-WRONG-PARENT','Mismatched same-tenant hierarchy is rejected without unrelated metrics',r,r['status'] in (400,404))
