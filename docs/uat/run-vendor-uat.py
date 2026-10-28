"""Platform global vendor-catalog controls using a unique disposable record."""
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
folder=Path(__file__).resolve().parent/'evidence/2026-10-19'
users=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text())
cases=[];tokens={}
def api(role,path,method='GET',body=None):
    base='http://127.0.0.1:18000'
    if role not in tokens:
        req=urllib.request.Request(base+'/api/auth/native/login',data=json.dumps({k:users[role][k] for k in ('email','password')}).encode(),headers={'Content-Type':'application/json'})
        tokens[role]=json.load(urllib.request.urlopen(req,timeout=30))['access_token']
    h={'Authorization':'Bearer '+tokens[role],'Content-Type':'application/json'}
    if users[role]['tenant_id']:h['X-Tenant-ID']=users[role]['tenant_id']
    req=urllib.request.Request(base+path,method=method,headers=h,data=None if body is None else json.dumps(body).encode())
    try:r=urllib.request.urlopen(req,timeout=30)
    except urllib.error.HTTPError as e:r=e
    data=r.read();return {'status':r.status,'data':json.loads(data) if data else None,'request_id':r.headers.get('x-request-id')}
def record(id,role,expected,result,passed,steps):
    cases.append({'id':id,'module':'Vendor records and configuration','role':role,'preconditions':'Only globally scoped UAT vendor record is created/updated/disabled; no seeded component matches its name','steps':steps,'expected':expected,'actual':result,'api':result['status'],'status':'PASS' if passed else 'FAIL','defect':None,'time':datetime.now(timezone.utc).isoformat()})
    (folder/'vendor-cases.json').write_text(json.dumps(cases,indent=2));print(id,cases[-1]['status'],result['status'],flush=True)
name='UAT-Vendor-'+str(time.time_ns())
base='/api/admin/lifecycle-vendor-records'
body={'vendor_name':name,'product_name':name+'-Product','ecosystem':'generic','lifecycle_status':'SUPPORTED','enabled':False,'confidence':'HIGH','evidence':{'purpose':'Synthetic UAT record only'}}
for role in ('admin','analyst','developer','viewer','foreign'):
    r=api(role,base,'POST',body)
    record('UAT-VENDOR-CREATE-DENY-'+role,role,'Global vendor catalog writes require platform authority',r,r['status']==403,'POST disabled synthetic record with tenant role; independently verify server rejection')
bad=api('platform',base,'POST',{**body,'eol_date':'invalid-date'})
record('UAT-VENDOR-DATE-VALIDATION','platform','Invalid lifecycle date rejected HTTP 422 without persistence',bad,bad['status']==422,'POST unique disabled vendor with malformed date')
created=api('platform',base,'POST',body)
record('UAT-VENDOR-CREATE','platform','Platform can create a disabled disposable vendor record',created,created['status']==201 and created['data'].get('enabled') is False,'POST only unique synthetic record; no change to provider credentials or existing vendor records')
if created['status']==201:
    rid=created['data']['id'];path=base+'/'+str(rid)
    for role in ('admin','viewer','foreign'):
        r=api(role,path,'PUT',{'recommended_version':'9.9.9'})
        record('UAT-VENDOR-UPDATE-DENY-'+role,role,'Tenant roles cannot update a global vendor record',r,r['status']==403,'PUT only newly created synthetic vendor record')
    r=api('platform',path,'PUT',{'recommended_version':'1.0.1','enabled':True})
    record('UAT-VENDOR-UPDATE','platform','Platform can update/enable its synthetic vendor record',r,r['status']==200 and r['data'].get('recommended_version')=='1.0.1' and r['data'].get('enabled') is True,'Enable only a uniquely named UAT product that matches no real component')
    listing=api('admin',base+'?search='+name)
    record('UAT-VENDOR-SEARCH','admin','Catalog search returns the unique UAT record',listing,listing['status']==200 and listing['data']['total']==1 and listing['data']['items'][0]['id']==rid,'Search public global catalog with authorized tenant reader; this shared catalog is distinct from tenant-owned business records')
    export=api('admin',base+'/export')
    serial=json.dumps(export['data'])
    record('UAT-VENDOR-EXPORT','admin','Tenant lifecycle reader can export active global catalog including synthetic entry',{'status':export['status'],'containsUatVendor':name in serial,'request_id':export['request_id']},export['status']==200 and name in serial,'Read export under implemented lifecycle:read policy; retain only UAT presence signal')
    denied=api('viewer',path,'DELETE')
    record('UAT-VENDOR-DELETE-DENY','viewer','Viewer cannot disable even the synthetic global vendor record',denied,denied['status']==403,'DELETE only UAT-created vendor record')
    removed=api('platform',path,'DELETE')
    record('UAT-VENDOR-CLEANUP','platform','Platform deletion disables only UAT record HTTP 204',removed,removed['status']==204,'Disable synthetic record after test; keep audit history')
    listing=api('admin',base+'?search='+name)
    export=api('admin',base+'/export')
    safe={'status':listing['status'],'matchingRecords':listing['data'].get('items'),'exportStatus':export['status'],'excludedFromActiveExport':name not in json.dumps(export['data'])}
    record('UAT-VENDOR-DISABLED-EXCLUDED','admin/platform','Disabled record is retained for administration and excluded from active provider export',safe,listing['status']==200 and listing['data']['items'][0]['enabled'] is False and export['status']==200 and name not in json.dumps(export['data']),'Re-read disabled UAT catalog entry and active provider export')
for role in ('analyst','developer','viewer'):
    r=api(role,'/api/component-advisor/policies/trust/versions','POST',{'status':'DISABLED','rules':None,'reason':'UAT permission rejection','row_version':0})
    record('UAT-POLICY-WRITE-DENY-'+role,role,'Non-administrators cannot publish tenant policy versions',r,r['status']==403,'POST protected policy write expected to be rejected before shared policy mutation')
