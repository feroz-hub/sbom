"""Synthetic secret lifecycle and read-only at-rest/audit proof on one new tenant."""
import importlib.util,json,secrets,threading
from pathlib import Path
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from sqlalchemy import create_engine,text
from scripts.dev import GreenfieldStack
settings = GreenfieldStack.settings
spec=importlib.util.spec_from_file_location('m',Path(__file__).with_name('live-common.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
f=m.create_tenant();tid=f['tenant_id'];token=f['token'];file='secret-lifecycle.json';mockid=None;server=None
expected_key=secrets.token_urlsafe(32);auth_observations=[]
class Mock(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  allowed=self.headers.get('Authorization')=='Bearer '+expected_key;auth_observations.append({'method':'GET','path':self.path,'authenticatedWithCurrentSyntheticKey':allowed});self.send_response(200 if allowed else 401);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps({'object':'list','data':[{'id':'r3-mock-model','object':'model','owned_by':'local-uat'}]} if allowed else {'error':{'message':'Unauthorized'}}).encode())
 def do_POST(self):
  allowed=self.headers.get('Authorization')=='Bearer '+expected_key;self.rfile.read(int(self.headers.get('Content-Length','0')));auth_observations.append({'method':'POST','path':self.path,'authenticatedWithCurrentSyntheticKey':allowed});self.send_response(200 if allowed else 401);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps({'id':'local-synthetic','object':'chat.completion','choices':[{'message':{'role':'assistant','content':'Local mock completion'}}],'usage':{'prompt_tokens':4,'completion_tokens':4,'total_tokens':8}} if allowed else {'error':{'message':'Unauthorized'}}).encode())
def call(path,method='GET',body=None):return m.call(path,method,body,role='platform',tenant=tid,token=token)
def rec(id,steps,expected,r,ok):m.rec(id,steps,expected,m.payload(r) if hasattr(r,'status_code') else r,ok,'disposable tenant admin',file)

def inspect_at_rest(identifier,key):
 engine=create_engine(settings()['DATABASE_URL'],hide_parameters=True)
 with engine.connect() as c:
  c.exec_driver_sql('SET TRANSACTION READ ONLY')
  encrypted=c.execute(text('SELECT api_key_encrypted FROM ai_provider_credential WHERE id=:cid AND tenant_id=(SELECT id FROM tenants WHERE public_id=:tenant)'),{'cid':identifier,'tenant':tid}).scalar_one()
  audit=c.execute(text('SELECT action, detail FROM ai_credential_audit_log WHERE target_id=:cid AND tenant_id=(SELECT id FROM tenants WHERE public_id=:tenant) ORDER BY id'),{'cid':identifier,'tenant':tid}).all()
 engine.dispose()
 rec('R3-SECRET-ENCRYPTION-AUDIT','Read only exact owned credential ciphertext and scoped audit metadata; never print values','Encrypted non-plaintext secret, create/update/test audit and no secret in audit',{'ciphertextStored':bool(encrypted),'plaintextAbsent':key not in str(encrypted),'auditActions':[x[0] for x in audit],'secretAbsentFromAudit':all(key not in (x[1] or '') for x in audit)},bool(encrypted) and key not in str(encrypted) and {'credential.create','credential.update','credential.test'}.issubset({x[0] for x in audit}) and all(key not in (x[1] or '') for x in audit))

try:
 # Synthetic authenticated upstream: separate in-process mock, no paid provider.
 server=ThreadingHTTPServer(('127.0.0.1',18444),Mock);threading.Thread(target=server.serve_forever,daemon=True).start()
 body={'provider_name':'custom_openai','label':'Round3 synthetic rotation','api_key':expected_key,'base_url':'http://127.0.0.1:18444/v1','default_model':'r3-mock-model','tier':'free','enabled':True,'is_local':True}
 r=call('/api/v1/ai/credentials','POST',body);rec('R3-SECRET-CREATE','Create only synthetic scoped credential','201; secret preview redacted and key-present true',r,r.status_code==201 and r.json().get('api_key_present') and r.json().get('api_key_preview') is None and expected_key not in r.text);assert r.status_code==201;mockid=r.json()['id']
 for stage in ['initial','rotated']:
  if stage=='rotated':
   expected_key=secrets.token_urlsafe(32);r=call('/api/v1/ai/credentials/'+str(mockid),'PUT',{'api_key':expected_key});rec('R3-SECRET-ROTATE','Rotate synthetic secret only, same credential identity','200 redacted, verification reset',r,r.status_code==200 and expected_key not in r.text)
  start=len(auth_observations);r=call('/api/v1/ai/credentials/'+str(mockid)+'/test','POST');rec('R3-SECRET-UPSTREAM-'+stage,'Call local authenticated mock through application provider adapter','200 success; mock received current synthetic key',{'response':m.payload(r),'mockRequests':auth_observations[start:],'mockProvider':True},r.status_code==200 and r.json().get('success') is True and any(x['authenticatedWithCurrentSyntheticKey'] for x in auth_observations[start:]))
 r=m.call('/api/v1/ai/credentials/'+str(mockid),'PUT',{'label':'Denied viewer update'},role='viewer');rec('R3-SECRET-ROLE-DENIED','Viewer attempts scoped credential update','403',r,r.status_code==403)
 r=m.call('/api/v1/ai/credentials/'+str(mockid),role='foreign');rec('R3-SECRET-FOREIGN-DENIED','Foreign administrator reads owned credential ID','404',r,r.status_code==404)
 inspect_at_rest(mockid,expected_key)
 r=call('/api/v1/ai/credentials/'+str(mockid),'DELETE');rec('R3-SECRET-REVOKE','Delete only newly owned synthetic credential','204',r,r.status_code==204);assert r.status_code==204
 r=call('/api/v1/ai/credentials/'+str(mockid));rec('R3-SECRET-REVOKED-READ','Read revoked own synthetic credential','404',r,r.status_code==404);mockid=None
finally:
 if mockid is not None:call('/api/v1/ai/credentials/'+str(mockid),'DELETE')
 before=call('/api/v1/ai/settings')
 call('/api/v1/ai/override','DELETE')
 after=call('/api/v1/ai/settings');rec('R3-SECRET-INHERITANCE','Reset only new owned tenant override; compare inherited disabled global state','200 inherited feature disabled; no secret cloned',after,after.status_code==200 and after.json()['feature_enabled'] is False)
 r=m.call('/api/platform/tenants/'+tid,'PATCH',{'status':'DISABLED'},role='platform');rec('R3-SECRET-CLEANUP','Disable only owned synthetic-provider tenant','200',r,r.status_code==200)
 if server:server.shutdown();server.server_close()
