"""Real Greenfield HTTP; disposable credentials stay in memory across reload."""
import json,re,secrets,time,sys
from pathlib import Path
import requests
OUT=Path(__file__).resolve().parent
USERS=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text())
CASES=[]
def req(path,method='GET',body=None,token=None,tenant=None,mail=False):
 h={}
 if token:h['Authorization']='Bearer '+token
 if tenant:h['X-Tenant-ID']=tenant
 r=requests.request(method,('http://127.0.0.1:8026' if mail else 'http://127.0.0.1:18000')+path,json=body,headers=h,timeout=40)
 try:d=r.json()
 except ValueError:d={'bytes':len(r.content)}
 return {'status':r.status_code,'data':d,'request_id':r.headers.get('x-request-id')}
def rec(id,r,ok,expected):
 CASES.append({'id':id,'module':'Advisor policy history','role':'disposable tenant admin / platform','preconditions':'New Round 2 tenant; six seeds unchanged; local Mailpit only','steps':id,'expected':expected,'actual':r,'result':'PASS' if ok else 'FAIL'})
 (OUT/'api-policy.json').write_text(json.dumps(CASES,indent=2));print(id,CASES[-1]['result'],r.get('status'),flush=True)
p=req('/api/auth/native/login','POST',{k:USERS['platform'][k] for k in ('email','password')})['data']['access_token']
stamp=str(time.time_ns());email='uat-r2-'+stamp+'@example.test'
created=req('/api/tenants','POST',{'name':'UAT R2 '+stamp,'slug':'uat-r2-'+stamp,'initial_admin_invitation':{'first_name':'UAT','last_name':'Round Two','email':email}},token=p)
assert created['status']==201
uid=created['data']['initial_administrator']['user_id'];tid=created['data']['tenant']['id']
(OUT/'policy-fixture.json').write_text(json.dumps({'tenant_id':tid,'user_id':uid,'email':email}))
try:
 token=None
 for _ in range(25):
  for m in req('/api/v1/messages',mail=True)['data'].get('messages',[]):
   if any(x['Address']==email for x in m.get('To',[])):
    msg=req('/api/v1/message/'+m['ID'],mail=True)['data'];match=re.search(r'[#?&]token=([A-Za-z0-9_-]+)',msg.get('Text') or msg.get('HTML') or '')
    if match:token=match.group(1);break
  if token:break
  time.sleep(.4)
 assert token
 password='Uat!'+secrets.token_urlsafe(24)
 assert req('/api/auth/native/activate','POST',{'token':token,'password':password})['status']==200
 assert req('/api/platform/tenants/'+tid,'PATCH',{'status':'ACTIVE'},token=p)['status']==200
 a=req('/api/auth/native/login','POST',{'email':email,'password':password})['data']['access_token']
 published={}
 for kind in ('trust','accepted-risk','scoring'):
  path='/api/component-advisor/policies/'+kind+'/versions'
  empty=req(path,token=a,tenant=tid);rec('R2-POLICY-EMPTY-'+kind,empty,empty['status']==200 and empty['data']['total']==0,'200 empty history')
  body={'status':'DISABLED','rules':None,'reason':'Round 2 isolated regression','row_version':0}
  saved=req(path,'POST',body,token=a,tenant=tid);rec('R2-POLICY-PUBLISH-'+kind,saved,saved['status']==201,'201 numeric policy version')
  published[kind]=saved['data']['version']
  before=req(path,token=a,tenant=tid);rec('R2-POLICY-BEFORE-'+kind,before,before['status']==500,'Reproduced baseline 500 before API reload')
 print('READY_FOR_API_RELOAD',flush=True)
 sys.stdin.readline()
 for kind in published:
  path='/api/component-advisor/policies/'+kind+'/versions'
  history=req(path,token=a,tenant=tid);rec('UAT-POLICY-HISTORY-'+kind,history,history['status']==200 and history['data']['total']==1 and all(history['data']['items'][0][k]==v for k,v in published[kind].items()),'200 exact published version; integer ID')
  stale=req(path,'POST',{'status':'DISABLED','reason':'Explicit stale test','row_version':0},token=a,tenant=tid);rec('R2-POLICY-CONFLICT-'+kind,stale,stale['status']==409,'409; no second version')
  assert req(path,token=a,tenant=tid)['data']==history['data']
  foreign=req(path,token=req('/api/auth/native/login','POST',{k:USERS['foreign'][k] for k in ('email','password')})['data']['access_token'],tenant=USERS['foreign']['tenant_id']);rec('R2-POLICY-ISOLATION-'+kind,foreign,foreign['status']==200 and foreign['data']['items']==[],'Foreign own-tenant history empty')
  platform=req('/api/platform/configuration/advisor-policies/'+kind+'/versions',token=p);rec('R2-POLICY-PLATFORM-'+kind,platform,platform['status']==200,'Platform history scope remains separate')
 for role,expected in [('analyst',200),('developer',403),('viewer',403)]:
  t=req('/api/auth/native/login','POST',{k:USERS[role][k] for k in ('email','password')})['data']['access_token']
  r=req('/api/component-advisor/policies/trust/versions',token=t,tenant=USERS[role]['tenant_id']);rec('R2-POLICY-ROLE-'+role,r,r['status']==expected,str(expected)+' per existing read policy')
  r=req('/api/component-advisor/policies/trust/versions','POST',{'status':'DISABLED','reason':'Denied','row_version':0},token=t,tenant=USERS[role]['tenant_id']);rec('R2-POLICY-WRITE-DENY-'+role,r,r['status']==403,'403 mutation denied')
finally:
 r=req('/api/platform/tenants/'+tid,'PATCH',{'status':'DISABLED'},token=p);rec('R2-POLICY-CLEANUP',r,r['status']==200 and r['data']['status']=='DISABLED','Only Round 2 tenant disabled')
