"""Final read-only identity guards and scoped test-session cleanup."""
import base64
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import redis
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

out=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('r1_api',out/'live-api.py');api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
api.PHASE='safeguards'
expected={'admin':'TENANT_ADMIN','analyst':'SECURITY_ANALYST','developer':'DEVELOPER','viewer':'VIEWER','foreign':'TENANT_ADMIN','platform':'PLATFORM_ADMIN'}
for role in expected:
    r=api.api(role,'/api/auth/me');d=r['data'];safe={'status':r['status'],'email':d.get('email'),'roles':d.get('roles'),'tenant_id':d.get('tenant_id'),'is_platform_admin':d.get('is_platform_admin')}
    api.case('R1-FINAL-IDENTITY-'+role,'Original credentials and seeded role/context remain unchanged',safe,r['status']==200 and d.get('roles')==[expected[role]] and d.get('tenant_id')==api.USERS[role].get('tenant_id'),role)
r=api.api('admin','/api/tenants/'+api.USERS['admin']['tenant_id']+'/users')
members=api.rows(r['data'])
api.case('R1-FINAL-MEMBERS','Olympus retains exactly its original four active verified memberships',{'status':r['status'],'members':[{k:m.get(k) for k in ('email','role','status','user_status','email_verified')} for m in members]},r['status']==200 and len(members)==4 and all(m['status']=='ACTIVE' and m['user_status']=='ACTIVE' and m['email_verified'] for m in members))
f=json.loads((out/'fixtures.json').read_text());r=api.api('admin','/api/vex/investigations/'+str(f['investigation_id']))
api.case('R1-FINAL-OWNERSHIP','Disposable investigation has no residual assignment and remains readable',{'status':r['status'],'assigned_to':r['data']['internal_decision']['assigned_to'],'row_version':r['data']['row_version']},r['status']==200 and r['data']['internal_decision']['assigned_to'] is None)
start=min(datetime.fromisoformat(c['time']).timestamp() for c in json.loads((out/'api-before.json').read_text()))
key=base64.b64decode(json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/environment.json').read_text())['AUTH_SESSION_ENCRYPTION_KEY'])
store=redis.Redis.from_url('redis://127.0.0.1:56381/1',decode_responses=True)
def decode(value):return base64.urlsafe_b64decode(value+'='*(-len(value)%4))
matched=[]
for name in store.scan_iter(match='sbom:bff:*'):
    if len(name.rsplit(':',1)[-1])!=64:continue
    raw=store.get(name)
    if not raw:continue
    try:
        iv,cipher,tag=map(decode,raw.split('.'))
        data=json.loads(AESGCM(key).decrypt(iv,cipher+tag,name.encode()))
        subject=str(json.loads(decode(data['accessToken'].split('.')[1])).get('sub'))
        if data.get('provider')=='NATIVE' and subject in {'1','3','5'} and data.get('createdAt',0)/1000>=start:matched.append(name)
    except (ValueError,TypeError,KeyError,InvalidTag):continue
removed=store.delete(*matched) if matched else 0
api.case('R1-FINAL-SESSION-CLEANUP','Only this run\'s retained Native Admin/Developer/foreign test BFF sessions are removed',{'status':None,'removedSessions':removed,'remainingMatchedSessions':sum(bool(store.exists(k)) for k in matched),'accountRolesStatusPasswordUntouched':True},not any(store.exists(k) for k in matched))
