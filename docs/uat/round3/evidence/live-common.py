"""Bounded local Greenfield UAT helpers. Credentials and authentication stay in memory."""
from pathlib import Path
from datetime import datetime,timezone
import json,re,time,secrets,requests
OUT=Path(__file__).resolve().parent
USERS=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text())
TOKENS={}
BASE='http://127.0.0.1:18000'
CASES=[]
def safe(value):
 if isinstance(value,dict):return {k:('[REDACTED]' if re.search(r'^(password|access_token|refresh_token|cookie|authorization|api_key|client_secret|secret_value|encrypted_secret)$',k,re.I) else safe(v)) for k,v in value.items()}
 if isinstance(value,list):return [safe(v) for v in value]
 if isinstance(value,str):
  for u in USERS.values():value=value.replace(u['password'],'[REDACTED]')
  return re.sub(r'eyJ[A-Za-z0-9_.-]+','[REDACTED]',value)
 return value
def login(role):
 r=requests.post(BASE+'/api/auth/native/login',json={k:USERS[role][k] for k in ('email','password')},timeout=45);assert r.status_code==200,'Native Login failed for '+role
 TOKENS[role]=r.json()['access_token'];return TOKENS[role]
def call(path,method='GET',body=None,role='admin',tenant=None,token=None,**kw):
 if token is None:token=TOKENS.get(role) or login(role)
 if tenant is None:tenant=USERS[role].get('tenant_id')
 h={'Authorization':'Bearer '+token}
 if tenant:h['X-Tenant-ID']=tenant
 return requests.request(method,BASE+path,json=body,headers=h,timeout=90,**kw)
def payload(r):
 try:d=r.json()
 except ValueError:d={'bytes':len(r.content),'contentType':r.headers.get('content-type')}
 return safe({'status':r.status_code,'data':d,'request_id':r.headers.get('x-request-id')})
def rec(id,steps,expected,actual,ok,role='admin',file='api-additional.json'):
 CASES.append({'id':id,'role':role,'preconditions':'Verified isolated Greenfield UUID; task-owned fixtures; credentials kept in memory','stepsExecuted':steps,'expected':expected,'actual':safe(actual),'result':'PASS' if ok else 'FAIL','time':datetime.now(timezone.utc).isoformat()})
 (OUT/file).write_text(json.dumps(CASES,indent=2));print(id,CASES[-1]['result'],flush=True)
def create_tenant():
 stamp=str(time.time_ns());email='uat-r3-'+stamp+'@example.test';p=login('platform')
 r=call('/api/tenants','POST',{'name':'UAT R3 '+stamp,'slug':'uat-r3-'+stamp,'initial_admin_invitation':{'first_name':'UAT','last_name':'Round Three','email':email}},role='platform');assert r.status_code==201,payload(r)
 tid=r.json()['tenant']['id'];uid=r.json()['initial_administrator']['user_id']
 (OUT/'disposable-policy-fixture.json').write_text(json.dumps({'tenant_id':tid,'user_id':uid,'email':email,'createdBy':'Round3 create_tenant','cleanup':'Disable only this owned tenant; revoke only returned owned grant'}))
 activation=None
 for _ in range(100):
  messages=requests.get('http://127.0.0.1:8026/api/v1/messages',timeout=10).json().get('messages',[])
  for m in messages:
   if any(x['Address']==email for x in m.get('To',[])):
    msg=requests.get('http://127.0.0.1:8026/api/v1/message/'+m['ID'],timeout=10).json();match=re.search(r'[#?&]token=([A-Za-z0-9_-]+)',msg.get('Text') or msg.get('HTML') or '')
    if match:activation=match.group(1);break
  if activation:break
  time.sleep(.4)
 assert activation,'Mailpit activation not ready'
 password='Uat!'+secrets.token_urlsafe(24)
 r=requests.post(BASE+'/api/auth/native/activate',json={'token':activation,'password':password},timeout=30);assert r.status_code==200
 assert call('/api/platform/tenants/'+tid,'PATCH',{'status':'ACTIVE'},role='platform').status_code==200
 r=requests.post(BASE+'/api/auth/native/login',json={'email':email,'password':password},timeout=30);assert r.status_code==200
 return {'tenant_id':tid,'user_id':uid,'email':email,'password':password,'token':r.json()['access_token']}
