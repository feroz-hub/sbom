import importlib.util,json,requests
from pathlib import Path
spec=importlib.util.spec_from_file_location('m',Path(__file__).with_name('live-common.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
f=m.create_tenant();tid=f['tenant_id'];uid=f['user_id'];own=f['token'];grant=None
file='governance-browser.json'
def check(id,steps,expected,r,ok,role='platform'):m.rec(id,steps,expected,m.payload(r),ok,role,file)
try:
 for status in ['SUSPENDED','DISABLED','ACTIVE']:
  r=m.call(f'/api/platform/users/{uid}/status','PATCH',{'status':status},role='platform');check('UAT-ACCOUNT-'+status+'-AUTHORIZATION','Seeded platform requests status on newly activated disposable account','403; current V5 intentionally excludes platform:user:manage_status',r,r.status_code==403)
 r=m.call('/api/auth/me',role='platform');d=r.json();check('R3-PLATFORM-NO-INHERITED-TENANT','Read seeded platform auth context without header','Platform authority; no tenant; no status capability',r,r.status_code==200 and d['tenant_id'] is None and 'platform:user:manage_status' not in d['permissions'])
 r=m.call('/api/auth/me',role='platform',tenant=m.USERS['admin']['tenant_id']);check('R3-PLATFORM-FORGED-HEADER','Seeded platform supplies Olympus UUID without membership','403 membership boundary remains enforced',r,r.status_code==403)
 r=m.call('/api/platform/administrators','POST',{'user_id':uid},role='viewer');check('R3-DELEGATION-VIEWER-DENIED','Viewer attempts platform grant on disposable user','403',r,r.status_code==403,'viewer')
 before=m.call('/api/platform/administrators',role='platform',token=own,tenant='');check('R3-DELEGATION-BEFORE','Disposable tenant admin calls platform directory before delegation','403',before,before.status_code==403,'disposable tenant admin')
 r=m.call('/api/platform/administrators','POST',{'user_id':uid},role='platform');check('R3-DELEGATION-GRANT','Policy-authorized seeded platform grants only new disposable principal','201 effective platform grant',r,r.status_code==201 and r.json().get('is_effective') is True);assert r.status_code==201;grant=r.json()['grant_id']
 (m.OUT/'disposable-grant.json').write_text(json.dumps({'grant_id':grant,'user_id':uid,'tenant_id':tid}))
 import subprocess
 tenant_name='UAT R3 '+f['email'].split('@')[0].removeprefix('uat-r3-')
 details={'email':f['email'],'password':f['password'],'tenant_id':tid,'tenant_name':tenant_name,'foreign_tenant_id':m.USERS['admin']['tenant_id']}
 browser=subprocess.run(['/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node','--use-system-ca',str(m.OUT/'browser-owned-platform.cjs')],input=json.dumps(details),text=True,capture_output=True,timeout=240)
 (m.OUT/'browser-owned-platform.log').write_text((browser.stdout+browser.stderr).replace(f['password'],'[REDACTED]'))
 m.rec('R3-OWNED-PLATFORM-BROWSER-COMPLETE','Real Chrome Native Login and membership switcher on disposable platform principal','Browser case assertions complete',{'exitCode':browser.returncode},browser.returncode==0,'disposable platform administrator',file)

 r=m.call('/api/platform/administrators',role='platform',token=own,tenant='');check('R3-DELEGATION-LIVE-REFRESH','Use same pre-grant Native token after grant','200 current DB authority, no token reissue required',r,r.status_code==200,'disposable platform admin')
 duplicate=m.call('/api/platform/administrators','POST',{'user_id':uid},role='platform');check('R3-DELEGATION-DUPLICATE','Repeat supported grant for same owned user','201 existing action and same grant; no duplicate',duplicate,duplicate.status_code==201 and duplicate.json()['grant_id']==grant and duplicate.json()['action']=='EXISTING')
 r=m.call('/api/auth/me',role='platform',token=own,tenant='');check('R3-WORKING-CONTEXT-PLATFORM-LANDING','Newly authorized platform principal reads context with no header','200 platform context, no inherited tenant',r,r.status_code==200 and r.json()['tenant_id'] is None,'disposable platform admin')
 r=m.call('/api/auth/me',role='platform',token=own,tenant=tid);check('R3-WORKING-CONTEXT-EXPLICIT-SELECTION','Select only own preexisting active tenant membership using supported UUID header','200 tenant context and existing TENANT_ADMIN authority',r,r.status_code==200 and r.json()['tenant_id']==tid and 'TENANT_ADMIN' in r.json()['roles'],'disposable platform admin')
 r=m.call('/api/projects',role='platform',token=own,tenant=tid);check('R3-WORKING-CONTEXT-TENANT-READ','Read projects in explicitly selected authorized tenant','200 own tenant',r,r.status_code==200,'disposable platform admin')
 r=m.call('/api/auth/me',role='platform',token=own,tenant=m.USERS['admin']['tenant_id']);check('R3-WORKING-CONTEXT-FOREIGN-DENY','Attempt Olympus context without membership','403',r,r.status_code==403,'disposable platform admin')
 r=m.call('/api/platform/administrators/'+str(grant),'DELETE',role='platform');check('R3-DELEGATION-REVOKE','Revoke only created disposable grant','204',r,r.status_code==204);assert r.status_code==204;grant=None
 r=m.call('/api/platform/administrators',role='platform',token=own,tenant='');check('R3-DELEGATION-IMMEDIATE-REVOCATION','Replay same Native token after revocation','403 authority revoked immediately',r,r.status_code==403,'disposable former platform admin')
 # Two independent native sessions for this owned principal. Logout-all is never called for seeds.
 second=requests.post(m.BASE+'/api/auth/native/login',json={'email':f['email'],'password':f['password']},timeout=30);assert second.status_code==200;token2=second.json()['access_token']
 r=m.call('/api/auth/native/logout-all','POST',role='platform',token=own,tenant='');check('R3-SESSION-OWNED-LOGOUT-ALL','Two native tokens; revoke owned user sessions via supported logout-all','200; both previous tokens rejected',r,r.status_code==200,'disposable user')
 for name,token in [('first',own),('second',token2)]:
  r=m.call('/api/auth/me',role='platform',token=token,tenant=tid);check('R3-SESSION-OLD-'+name,'Replay '+name+' token after owned logout-all','401',r,r.status_code==401,'disposable user')
finally:
 if grant is not None:m.call('/api/platform/administrators/'+str(grant),'DELETE',role='platform')
 r=m.call('/api/platform/tenants/'+tid,'PATCH',{'status':'DISABLED'},role='platform');check('R3-GOVERNANCE-CLEANUP','Disable only new owned tenant; no seed authority changed','200 disabled',r,r.status_code==200)
