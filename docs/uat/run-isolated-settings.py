"""Settings mutation tests inside the UAT-created tenant, with Mailpit reset."""
import json
import re
import secrets
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
folder=Path(__file__).resolve().parent/'evidence/2026-10-19'
seeded=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text())
prior=json.loads((folder/'extended-cases.json').read_text())
creation=next(c for c in prior if c['id']=='UAT-TENANT-CREATE')['actual']
tenant=creation['tenant']['id'];email=creation['initial_administrator']['email']
if not creation['tenant']['name'].startswith('UAT Tenant ') or not email.startswith('uat-tenant-admin-'):
    raise SystemExit('Disposable tenant ownership check failed')
cases=[]
def req(path,method='GET',body=None,token=None,tenant_id=None,mail=False):
    headers={'Content-Type':'application/json'}
    if token:headers['Authorization']='Bearer '+token
    if tenant_id:headers['X-Tenant-ID']=tenant_id
    base='http://127.0.0.1:8026' if mail else 'http://127.0.0.1:18000'
    r=urllib.request.Request(base+path,method=method,headers=headers,data=None if body is None else json.dumps(body).encode())
    try:response=urllib.request.urlopen(r,timeout=30)
    except urllib.error.HTTPError as e:response=e
    data=response.read();return {'status':response.status,'data':json.loads(data) if data else None,'request_id':response.headers.get('x-request-id')}
def record(id,module,expected,actual,passed,steps):
    cases.append({'id':id,'module':module,'role':'disposable tenant administrator / platform','preconditions':'Only tenant and initial administrator created by this UAT are changed; local Mailpit; six seeded accounts untouched','steps':steps,'expected':expected,'actual':actual,'api':actual.get('status'),'status':'PASS' if passed else 'FAIL','defect':None,'time':datetime.now(timezone.utc).isoformat()})
    (folder/'isolated-settings-cases.json').write_text(json.dumps(cases,indent=2));print(id,cases[-1]['status'],actual.get('status'),flush=True)
platform=req('/api/auth/native/login','POST',{k:seeded['platform'][k] for k in ('email','password')})['data']['access_token']
admin=req('/api/auth/native/login','POST',{k:seeded['admin'][k] for k in ('email','password')})['data']['access_token']
before=req('/api/v1/ai/effective-config',token=admin,tenant_id=seeded['admin']['tenant_id'])
check=req('/api/platform/tenants/'+tenant,token=platform)
if check['status']!=200 or not check['data']['name'].startswith('UAT Tenant '):raise SystemExit('Live disposable guard failed')
sent=req('/api/auth/native/forgot-password','POST',{'email':email})
unknown=req('/api/auth/native/forgot-password','POST',{'email':'uat-no-such-account-'+str(time.time_ns())+'@example.test'})
record('UAT-RESET-NO-ENUMERATION','Native password recovery','Existing and unknown email return same generic reset response',{'status':sent['status'],'unknownStatus':unknown['status'],'sameBody':sent['data']==unknown['data']},sent['status']==200 and unknown['status']==200 and sent['data']==unknown['data'],'Request reset only for disposable account and guaranteed-unique nonexistent test address')
action_token=None
for attempt in range(20):
    mailbox=req('/api/v1/messages',mail=True)['data']
    for item in mailbox.get('messages',[]):
        if not any(t['Address']==email for t in item.get('To',[])) or 'reset' not in item.get('Subject','').lower():continue
        message=req('/api/v1/message/'+item['ID'],mail=True)['data']
        match=re.search(r'[#?&]token=([A-Za-z0-9_-]+)',message.get('Text') or message.get('HTML') or '')
        if match:action_token=match.group(1);break
    if action_token:break
    time.sleep(2)
if not action_token:raise SystemExit('Local reset mail unavailable; no tenant settings changed')
password='Uat!'+secrets.token_urlsafe(24)
reset=req('/api/auth/native/reset-password','POST',{'token':action_token,'new_password':password})
record('UAT-RESET-CONSUME','Native password recovery','Local Mailpit reset changes only disposable account password',{'status':reset['status'],'result':reset['data'],'mailRecipient':email},reset['status']==200,'Consume reset token and generated password in memory; never record activation/reset URLs')
replay=req('/api/auth/native/reset-password','POST',{'token':action_token,'new_password':password})
record('UAT-RESET-SINGLE-USE','Native password recovery','Consumed reset token cannot be reused',replay,replay['status']==400,'Replay only consumed UAT reset token; assert server-side rejection')
active=req('/api/platform/tenants/'+tenant,'PATCH',{'status':'ACTIVE'},token=platform)
if active['status']!=200:raise SystemExit('Disposable tenant could not be activated')
token=None
try:
    login=req('/api/auth/native/login','POST',{'email':email,'password':password})
    token=login['data'].get('access_token')
    record('UAT-RESET-LOGIN','Native password recovery','Disposable account authenticates using reset password',{'status':login['status'],'tokenIssued':bool(token)},login['status']==200 and bool(token),'Native Login with generated reset password; retain token only in memory')
    def own(path,method='GET',body=None):return req(path,method,body,token=token,tenant_id=tenant)
    for kind in ('trust','accepted-risk','scoring'):
        path='/api/component-advisor/policies/'+kind
        state=own(path);version=state['data']['row_version']
        published=own(path+'/versions','POST',{'status':'DISABLED','rules':None,'reason':'UAT isolated tenant policy version','row_version':version})
        record('UAT-POLICY-PUBLISH-'+kind,'Advisor policy configuration','UAT administrator can publish a disabled isolated tenant policy version',published,published['status']==201 and published['data']['tenant_override']['status']=='DISABLED','Publish only in this UAT-created tenant; platform/Olympus policies remain unchanged')
        stale=own(path+'/versions','POST',{'status':'INHERIT','rules':None,'reason':'UAT stale policy check','row_version':version})
        record('UAT-POLICY-CONFLICT-'+kind,'Advisor policy configuration','Stale policy version is rejected HTTP 409',stale,stale['status']==409,'Retry original optimistic version after successful publication')
        history=own(path+'/versions')
        record('UAT-POLICY-HISTORY-'+kind,'Advisor policy configuration','Append-only policy history contains actual published version',history,history['status']==200 and len(history['data']['items'])>=1,'Read actual version history in UAT tenant')
        current=own(path)['data']['row_version']
        inherit=own(path+'/versions','POST',{'status':'INHERIT','rules':None,'reason':'UAT cleanup restore inherited policy','row_version':current})
        record('UAT-POLICY-INHERIT-'+kind,'Advisor policy configuration','UAT tenant can return to inherited policy configuration',inherit,inherit['status']==201 and inherit['data']['tenant_override']['status']=='INHERIT' and inherit['data']['effective']==inherit['data']['platform_default'],'Append INHERIT version only to UAT tenant; latest override version remains visible as INHERIT while effective policy resolves from platform')
    path='/api/admin/lifecycle-providers'
    providers=own(path)
    provider=next(p for p in providers['data'] if p['provider_key']=='endoflife_date')
    key=provider['provider_key'];baseline_source=provider['source']
    updated=own(path+'/'+key,'PUT',{'enabled':False,'priority':provider['priority']})
    safe={k:updated['data'].get(k) for k in ('provider_key','enabled','source','override_enabled','priority')};safe['status']=updated['status']
    record('UAT-LIFECYCLE-CONFIG-OVERRIDE','Lifecycle provider configuration','Isolated tenant override disables only its provider configuration',safe,updated['status']==200 and safe['source']=='TENANT_OVERRIDE' and safe['enabled'] is False,'Save UAT tenant override without credentials or external provider invocation')
    invalid=own(path+'/'+key,'PUT',{'timeout_seconds':0})
    record('UAT-LIFECYCLE-CONFIG-VALIDATION','Lifecycle provider configuration','Out-of-range provider timeout rejected HTTP 422',invalid,invalid['status']==422,'Submit invalid timeout only in UAT tenant')
    removed=own(path+'/'+key+'/override','DELETE')
    record('UAT-LIFECYCLE-CONFIG-RESET','Lifecycle provider configuration','Remove only UAT-created override HTTP 204',removed,removed['status']==204,'Reset newly created override to inherited provider settings')
    restored=next(p for p in own(path)['data'] if p['provider_key']==key)
    record('UAT-LIFECYCLE-CONFIG-INHERITED','Lifecycle provider configuration','Reset recovers inherited source and original enabled setting',{'status':200,'source':restored['source'],'enabled':restored['enabled']},restored['source']==baseline_source and restored['enabled']==provider['enabled'],'Re-read real provider configuration after UAT override removal')
    ai=own('/api/v1/ai/settings','PUT',{'feature_enabled':False,'budget_per_request_usd':0.01,'budget_per_scan_usd':1,'budget_daily_usd':2})
    record('UAT-AI-SETTINGS-OVERRIDE','AI configuration and providers','UAT tenant stores disabled-feature settings with valid budget order',ai,ai['status']==200 and ai['data']['feature_enabled'] is False and ai['data']['budget_daily_usd']==2,'Create isolated UAT AI settings only; no provider credential or inference')
    invalid=own('/api/v1/ai/settings','PUT',{'budget_per_request_usd':3,'budget_per_scan_usd':1,'budget_daily_usd':2})
    record('UAT-AI-BUDGET-VALIDATION','AI configuration and providers','Invalid budget hierarchy is rejected HTTP 400',invalid,invalid['status']==400,'Submit per-request greater than per-scan in UAT settings')
    kept=own('/api/v1/ai/settings')
    record('UAT-AI-BUDGET-ROLLBACK','AI configuration and providers','Rejected budget update leaves previous valid settings intact',kept,kept['status']==200 and kept['data']['budget_per_request_usd']==0.01,'Re-read settings after rejected mutation')
    reset=own('/api/v1/ai/override','DELETE')
    record('UAT-AI-SETTINGS-RESET','AI configuration and providers','Remove only UAT-created AI override HTTP 204',reset,reset['status']==204,'Reset isolated test tenant to inherited AI configuration')
    effective=own('/api/v1/ai/effective-config')
    record('UAT-AI-SETTINGS-INHERITED','AI configuration and providers','UAT tenant returns to inherited platform configuration',{'status':effective['status'],'source':effective['data']['source'],'override_enabled':effective['data']['override_enabled']},effective['status']==200 and effective['data']['source']=='PLATFORM_DEFAULT' and effective['data']['override_enabled'] is False,'Read effective source after override reset')
finally:
    disabled=req('/api/platform/tenants/'+tenant,'PATCH',{'status':'DISABLED'},token=platform)
    record('UAT-SETTINGS-TENANT-CLEANUP','UAT cleanup','Leave only UAT-created tenant disabled',{'status':disabled['status'],'tenantStatus':disabled['data'].get('status')},disabled['status']==200 and disabled['data'].get('status')=='DISABLED','Disable UAT tenant after isolated configuration testing even on test error')
after=req('/api/v1/ai/effective-config',token=admin,tenant_id=seeded['admin']['tenant_id'])
record('UAT-SETTINGS-OLYMPUS-UNCHANGED','Tenant isolation','Olympus effective AI configuration is unaffected by another tenant\'s overrides',{'status':after['status'],'unchanged':after['data']==before['data']},after['status']==200 and after['data']==before['data'],'Compare effective Olympus response before and after all UAT tenant setting mutations; secret values are never returned or recorded')
