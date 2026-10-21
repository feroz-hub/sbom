"""Read-only final account, tenant and temporary-control verification."""
import json
import urllib.error
import urllib.request
from datetime import datetime,timezone
from pathlib import Path
folder=Path(__file__).resolve().parent/'evidence/2026-10-19'
users=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text());cases=[]
def call(path,token=None,tenant=None,method='GET',payload=None):
    h={'Content-Type':'application/json'}
    if token:h['Authorization']='Bearer '+token
    if tenant:h['X-Tenant-ID']=tenant
    req=urllib.request.Request('http://127.0.0.1:18000'+path,method=method,headers=h,data=None if payload is None else json.dumps(payload).encode())
    try:r=urllib.request.urlopen(req,timeout=30)
    except urllib.error.HTTPError as e:r=e
    data=r.read();return r.status,json.loads(data) if data else None
def record(id,role,expected,actual,passed,steps):
    cases.append({'id':id,'module':'UAT cleanup','role':role,'preconditions':'Final read-only safeguards after disposable-record tests; independent Native API authentication','steps':steps,'expected':expected,'actual':actual,'api':actual.get('status'),'status':'PASS' if passed else 'FAIL','defect':None,'time':datetime.now(timezone.utc).isoformat()})
    (folder/'final-state-cases.json').write_text(json.dumps(cases,indent=2));print(id,cases[-1]['status'],flush=True)
tokens={};expected={'admin':'TENANT_ADMIN','analyst':'SECURITY_ANALYST','developer':'DEVELOPER','viewer':'VIEWER','foreign':'TENANT_ADMIN','platform':'PLATFORM_ADMIN'}
for role,user in users.items():
    status,data=call('/api/auth/native/login',method='POST',payload={k:user[k] for k in ('email','password')})
    if status!=200:record('UAT-FINAL-IDENTITY-'+role,role,'Original seeded credentials/role/context still work',{'status':status},False,'Native Login original test account after UAT; response secrets withheld');continue
    token=data['access_token'];tokens[role]=token
    code,me=call('/api/auth/me',token,user.get('tenant_id'))
    safe={'status':code,'loginStatus':status,'email':me.get('email'),'roles':me.get('roles'),'tenant_id':me.get('tenant_id'),'is_platform_admin':me.get('is_platform_admin')}
    passed=code==200 and expected[role] in me.get('roles',[]) and me.get('tenant_id')==user.get('tenant_id')
    record('UAT-FINAL-IDENTITY-'+role,role,'Original seeded credentials, roles and tenant/platform context remain valid',safe,passed,'Authenticate with unchanged private credentials; read actual auth/me; store no tokens or passwords')
code,members=call('/api/tenants/'+users['admin']['tenant_id']+'/users',tokens['admin'],users['admin']['tenant_id'])
rows=members if isinstance(members,list) else members['items']
safe=[{k:m.get(k) for k in ('email','role','status','user_status','email_verified')} for m in rows]
record('UAT-FINAL-OLYMPUS-DIRECTORY','admin','Olympus has original four active verified seeded members with original roles',{'status':code,'members':safe},code==200 and len(rows)==4 and all(m['email'] in {users[r]['email'] for r in ('admin','analyst','developer','viewer')} and m['status']=='ACTIVE' and m['user_status']=='ACTIVE' and m['email_verified'] and expected[next(r for r in ('admin','analyst','developer','viewer') if users[r]['email']==m['email'])]==m['role'] for m in rows),'Read final directory after UAT membership cleanup')
fixture=json.loads((folder/'business-fixtures.json').read_text())
code,data=call('/api/platform/tenants/'+fixture['temporary_tenant_id'],tokens['platform'])
record('UAT-FINAL-DISPOSABLE-TENANT','platform','UAT-created tenant remains disabled',{'status':code,'tenant_id':data.get('id'),'name':data.get('name'),'tenantStatus':data.get('status')},code==200 and data.get('status')=='DISABLED' and data.get('name','').startswith('UAT Tenant '),'Read only the UAT-created tenant status after settings and reset tests')
code,data=call('/api/products/'+fixture['product_id']+'/schedule',tokens['admin'],users['admin']['tenant_id'])
record('UAT-FINAL-SCHEDULE-CLEANUP','admin','UAT product has no enabled analysis schedule',{'status':code,'schedule':data},code==200 and (data is None or data.get('enabled') is False) or code==404,'Read disposable product schedule after deletion; no schedule execution requested')
code,data=call('/api/report-subscriptions',tokens['admin'],users['admin']['tenant_id'])
rows=data if isinstance(data,list) else data.get('items',[])
matching=[{k:r.get(k) for k in ('id','enabled','sbom_id')} for r in rows if r.get('sbom_id')==fixture['sbom_id']]
record('UAT-FINAL-SUBSCRIPTION-CLEANUP','admin','No UAT SBOM report subscription remains enabled',{'status':code,'matchingUatSubscriptions':matching},code==200 and all(r.get('enabled') is False for r in matching),'Read actual subscription list after immediate report/ownership test cleanup')
