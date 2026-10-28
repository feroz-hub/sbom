"""Recover only this round's disposable account for actual policy-screen checks."""
import importlib.util,json,re,secrets,subprocess,time
from pathlib import Path
import requests
OUT=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('client',OUT.parent/'2026-10-20-round1/live-api.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
f=json.loads((OUT/'policy-fixture.json').read_text());email=f['email'];tid=f['tenant_id'];assert email.startswith('uat-r2-') and f['user_id']>6
assert m.api('platform','/api/platform/tenants/'+tid)['data']['name'].startswith('UAT R2 ')
old_ids={mail['ID'] for mail in requests.get('http://127.0.0.1:8026/api/v1/messages',timeout=20).json().get('messages',[])}
r=requests.post('http://127.0.0.1:18000/api/auth/native/forgot-password',json={'email':email},timeout=30);assert r.status_code==200
token=None
for _ in range(40):
 for mail in requests.get('http://127.0.0.1:8026/api/v1/messages',timeout=20).json().get('messages',[]):
  if mail['ID'] in old_ids:continue
  if 'reset' not in mail.get('Subject','').lower() or not any(x['Address']==email for x in mail.get('To',[])):continue
  msg=requests.get('http://127.0.0.1:8026/api/v1/message/'+mail['ID'],timeout=20).json();match=re.search(r'[#?&]token=([A-Za-z0-9_-]+)',msg.get('Text') or msg.get('HTML') or '')
  if match:token=match.group(1);break
 if token:break
 time.sleep(.5)
assert token,'Local Mailpit reset unavailable'
password='Uat!'+secrets.token_urlsafe(24)
r=requests.post('http://127.0.0.1:18000/api/auth/native/reset-password',json={'token':token,'new_password':password},timeout=30);assert r.status_code==200
assert m.api('platform','/api/platform/tenants/'+tid,'PATCH',{'status':'ACTIVE'})['status']==200
try:
 result=subprocess.run(['/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node','--use-system-ca',str(OUT/'browser-policy.cjs')],input=json.dumps({'email':email,'password':password}),text=True)
finally:
 r=m.api('platform','/api/platform/tenants/'+tid,'PATCH',{'status':'DISABLED'});assert r['status']==200
 (OUT/'policy-browser-cleanup.json').write_text(json.dumps({'tenant_id':tid,'status':r['status'],'tenantStatus':r['data']['status'],'seededCredentialsChanged':False,'browserExit':result.returncode},indent=2))
raise SystemExit(result.returncode)
