"""Read-only application safeguards; no credentials or session contents emitted."""
import importlib.util,json
from pathlib import Path
out=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('api',out.parent/'2026-10-20-round1/live-api.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
cases=[]
roles={'admin':'TENANT_ADMIN','analyst':'SECURITY_ANALYST','developer':'DEVELOPER','viewer':'VIEWER','foreign':'TENANT_ADMIN','platform':'PLATFORM_ADMIN'}
for role,expected in roles.items():
 r=m.api(role,'/api/auth/me');d=r['data'];safe={k:d.get(k) for k in ('email','roles','tenant_id','is_platform_admin')};cases.append({'id':'R2-FINAL-IDENTITY-'+role,'role':role,'expected':'Seeded credentials, role and tenant context unchanged','actual':{'status':r['status'],**safe},'result':'PASS' if r['status']==200 and d.get('roles')==[expected] and d.get('tenant_id')==m.USERS[role].get('tenant_id') else 'FAIL'})
r=m.api('admin','/api/tenants/'+m.USERS['admin']['tenant_id']+'/users');members=m.rows(r['data']);cases.append({'id':'R2-FINAL-OLYMPUS','expected':'Exactly original four active verified members with original roles','actual':{'status':r['status'],'members':[{k:x.get(k) for k in ('email','role','roles','status','user_status','email_verified')} for x in members]},'result':'PASS' if r['status']==200 and len(members)==4 and all(x['status']=='ACTIVE' and x['user_status']=='ACTIVE' and x['email_verified'] and x['role']==roles[next(k for k,v in m.USERS.items() if v['email']==x['email'])] for x in members) else 'FAIL'})
f=json.loads((out/'fixtures.json').read_text());r=m.api('admin','/api/vex/investigations/'+str(f['investigation_id']));cases.append({'id':'R2-FINAL-VEX-ASSIGNMENT','expected':'No retained disposable assignment','actual':{'status':r['status'],'assigned_to':r['data']['internal_decision']['assigned_to']},'result':'PASS' if r['status']==200 and r['data']['internal_decision']['assigned_to'] is None else 'FAIL'})
f=json.loads((out/'policy-fixture.json').read_text());r=m.api('platform','/api/platform/tenants/'+f['tenant_id']);cases.append({'id':'R2-FINAL-DISPOSABLE-TENANT','expected':'Round 2 policy tenant left disabled','actual':{'status':r['status'],'tenantStatus':r['data']['status']},'result':'PASS' if r['status']==200 and r['data']['status']=='DISABLED' else 'FAIL'})
(out/'final-guards.json').write_text(json.dumps(cases,indent=2));print([(x['id'],x['result']) for x in cases])
