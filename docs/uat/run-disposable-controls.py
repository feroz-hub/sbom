"""Deletion/recovery and configuration denial checks on fresh UAT resources."""
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

folder=Path('/Users/ferozebasha/sbom/docs/uat/evidence/2026-10-19')
users=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text())
tokens={}
cases=[]
def api(role,path,method='GET',body=None):
    base='http://127.0.0.1:18000'
    if role not in tokens:
        u=users[role]
        req=urllib.request.Request(base+'/api/auth/native/login',data=json.dumps({'email':u['email'],'password':u['password']}).encode(),headers={'Content-Type':'application/json'})
        tokens[role]=json.load(urllib.request.urlopen(req,timeout=30))['access_token']
    h={'Authorization':'Bearer '+tokens[role],'Content-Type':'application/json'}
    if users[role]['tenant_id']:h['X-Tenant-ID']=users[role]['tenant_id']
    req=urllib.request.Request(base+path,method=method,headers=h,data=None if body is None else json.dumps(body).encode())
    try:r=urllib.request.urlopen(req,timeout=30)
    except urllib.error.HTTPError as e:r=e
    raw=r.read();return {'status':r.status,'data':json.loads(raw) if raw else None,'request_id':r.headers.get('x-request-id')}
def record(id,module,role,expected,result,passed,steps):
    cases.append({'id':id,'module':module,'role':role,'preconditions':'Only resources created in this script are modified; seeded accounts and existing configuration unchanged','steps':steps,'expected':expected,'actual':result,'api':result['status'],'status':'PASS' if passed else 'FAIL','defect':None,'time':datetime.now(timezone.utc).isoformat()})
    (folder/'disposable-controls.json').write_text(json.dumps(cases,indent=2));print(id,cases[-1]['status'],result['status'])

created=api('admin','/api/projects','POST',{'project_name':'UAT Recovery '+str(time.time_ns()),'project_status':1});pid=created['data'].get('id')
if created['status']!=201 or not pid:raise SystemExit('Disposable project creation failed')
product=api('admin',f'/api/projects/{pid}/products','POST',{'name':'UAT empty product'});product_id=product['data'].get('id')
if product_id:
    denied=api('viewer',f'/api/products/{product_id}','DELETE');record('UAT-PRODUCT-DELETE-DENY','Products','viewer','Viewer cannot delete even an empty product',denied,denied['status']==403,'DELETE only UAT-owned empty product')
    removed=api('admin',f'/api/products/{product_id}','DELETE');record('UAT-PRODUCT-DELETE','Products','admin','Empty disposable product can be deleted',removed,removed['status']==200,'DELETE fresh empty product')
    missing=api('admin',f'/api/products/{product_id}');record('UAT-PRODUCT-DELETED-READ','Products','admin','Deleted product is concealed from normal lookup',missing,missing['status']==404,'Read soft-deleted UAT product')
impact=api('admin',f'/api/projects/{pid}/delete-impact');record('UAT-PROJECT-DELETE-IMPACT','Projects','admin','Preview excludes unrelated seeded business resources',impact,impact['status']==200 and impact['data']['sboms']==0 and impact['data']['runs']==0,'GET fresh UAT project deletion impact')
denied=api('viewer',f'/api/projects/{pid}?confirm=yes','DELETE');record('UAT-PROJECT-DELETE-DENY','Projects','viewer','Viewer cannot delete project',denied,denied['status']==403,'DELETE only UAT-owned empty project')
unconfirmed=api('admin',f'/api/projects/{pid}','DELETE');record('UAT-PROJECT-DELETE-CONFIRM','Projects','admin','Deletion requires explicit request confirmation',unconfirmed,unconfirmed['status'] in (400,422),'DELETE own disposable project without confirm flag')
removed=api('admin',f'/api/projects/{pid}?confirm=yes','DELETE');record('UAT-PROJECT-SOFT-DELETE','Projects','admin','Confirmed disposable project deletion remains recoverable',removed,removed['status']==200 and removed['data'].get('permanent') is False,'Soft delete only fresh UAT project; no permanent deletion')
missing=api('admin',f'/api/projects/{pid}');record('UAT-PROJECT-DELETED-READ','Projects','admin','Normal lookup conceals deleted project',missing,missing['status']==404,'GET deleted UAT project')
restored=api('admin',f'/api/projects/{pid}/restore','POST');record('UAT-PROJECT-RESTORE','Projects','admin','Supported recovery restores UAT project under original UUID',restored,restored['status']==200,'POST restore on this script\'s deleted project')
visible=api('admin',f'/api/projects/{pid}');record('UAT-PROJECT-RESTORE-READ','Projects','admin','Restored original project UUID can be read',{'status':visible['status'],'id':visible['data'].get('id')},visible['status']==200 and visible['data']['id']==pid,'GET restored disposable UUID')
cleanup=api('admin',f'/api/projects/{pid}?confirm=yes','DELETE');record('UAT-PROJECT-CLEANUP','Projects','admin','Leave only this script\'s project soft deleted',cleanup,cleanup['status']==200,'Archive disposable recovery-test project again')
for role in ('analyst','developer','viewer'):
    for label,path,method,body in [
        ('ai-read','/api/v1/ai/credentials','GET',None),
        ('ai-write','/api/v1/ai/credentials','POST',{'provider_name':'unknown-uat-provider','label':'UAT denial','enabled':False}),
        ('tenant-provider','/api/admin/lifecycle-providers/endoflife_date','PUT',{'enabled':False}),
        ('platform-provider','/api/platform/configuration/lifecycle/endoflife_date','PUT',{'enabled':False}),
        ('platform-grant','/api/platform/administrators','POST',{'user_id':2147483000}),
    ]:
        r=api(role,path,method,body);record('UAT-CONFIG-DENY-'+role+'-'+label,'Settings authorization',role,'Server rejects configuration or platform privilege outside current role',r,r['status']==403,method+' protected configuration endpoint; writes expected to be denied before mutation; no credentials provided')
invalid=api('admin','/api/v1/ai/credentials','POST',{'provider_name':'unknown-uat-provider','label':'UAT invalid','enabled':False})
record('UAT-AI-INVALID-PROVIDER','AI configuration and providers','admin','Unknown provider configuration fails validation without persistence or outbound call',invalid,invalid['status'] in (400,422),'POST disabled unknown provider without credentials')
before=api('admin','/api/v1/ai/credentials');record('UAT-AI-INVALID-NO-PERSIST','AI configuration and providers','admin','Rejected provider configuration does not create a credential',{'status':before['status'],'count':len(before['data']) if isinstance(before['data'],list) else None},before['status']==200 and before['data']==[],'Read real credential list after rejected provider create; values withheld')
