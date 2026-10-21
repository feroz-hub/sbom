"""Approved local inference and synthetic secret lifecycle, scoped to one new tenant."""
import importlib.util,json,secrets,threading,hashlib
from pathlib import Path
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
spec=importlib.util.spec_from_file_location('m',Path(__file__).with_name('live-common.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert (m.OUT/'local-model.json').exists()
f=m.create_tenant();tid=f['tenant_id'];token=f['token'];global_before=m.payload(m.call('/api/v1/ai/settings',role='platform'))['data'];file='ai-local.json';cred=None;mockid=None;server=None
expected_key=secrets.token_urlsafe(32);auth_observations=[]
class Mock(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  allowed=self.headers.get('Authorization')=='Bearer '+expected_key;auth_observations.append({'method':'GET','path':self.path,'authenticatedWithCurrentSyntheticKey':allowed});self.send_response(200 if allowed else 401);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps({'object':'list','data':[{'id':'r3-mock-model','object':'model','owned_by':'local-uat'}]} if allowed else {'error':{'message':'Unauthorized'}}).encode())
 def do_POST(self):
  allowed=self.headers.get('Authorization')=='Bearer '+expected_key;self.rfile.read(int(self.headers.get('Content-Length','0')));auth_observations.append({'method':'POST','path':self.path,'authenticatedWithCurrentSyntheticKey':allowed});self.send_response(200 if allowed else 401);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps({'id':'local-synthetic','object':'chat.completion','choices':[{'message':{'role':'assistant','content':'Local mock completion'}}],'usage':{'prompt_tokens':4,'completion_tokens':4,'total_tokens':8}} if allowed else {'error':{'message':'Unauthorized'}}).encode())
def call(path,method='GET',body=None):return m.call(path,method,body,role='platform',tenant=tid,token=token)
def rec(id,steps,expected,r,ok):m.rec(id,steps,expected,m.payload(r) if hasattr(r,'status_code') else r,ok,'disposable tenant admin',file)
try:
 r=call('/api/v1/ai/settings','PUT',{'feature_enabled':True,'kill_switch_active':False});rec('R3-AI-ISOLATED-FEATURE','Enable only new disposable tenant override','200; global setting unchanged',r,r.status_code==200 and r.json()['feature_enabled']);assert r.status_code==200
 r=call('/api/v1/ai/credentials','POST',{'provider_name':'ollama','label':'Round3 isolated free model','base_url':'http://127.0.0.1:11435','default_model':'qwen2.5:0.5b','tier':'free','enabled':True,'is_default':True,'is_local':True,'max_concurrent':1});rec('R3-AI-LOCAL-CONFIG','Create own tenant local-only free credential','201; separate model service',r,r.status_code==201);assert r.status_code==201;cred=r.json()['id']
 r=call('/api/v1/ai/credentials/'+str(cred)+'/test','POST');rec('R3-AI-LOCAL-HEALTH','Application adapter probes separate real local model','200 successful real provider readiness',r,r.status_code==200 and r.json().get('success') is True)
 r=call('/api/ai/copilot/ask','POST',{'question':'How many SBOMs are in this portfolio? Answer in one short sentence using only the snapshot.'});rec('UAT-AI-LIVE-PROVIDER','Real authenticated application Copilot request to approved separate local Ollama','200 nonempty local model completion at zero cost',r,r.status_code==200 and r.json().get('provider')=='ollama' and bool(r.json().get('answer')) and r.json().get('cost_usd')==0)
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
 r=call('/api/v1/ai/credentials/'+str(mockid),'DELETE');rec('R3-SECRET-REVOKE','Delete only newly owned synthetic credential','204',r,r.status_code==204);assert r.status_code==204
 r=call('/api/v1/ai/credentials/'+str(mockid));rec('R3-SECRET-REVOKED-READ','Read revoked own synthetic credential','404',r,r.status_code==404);mockid=None
finally:
 if mockid is not None:call('/api/v1/ai/credentials/'+str(mockid),'DELETE')
 if cred is not None:call('/api/v1/ai/credentials/'+str(cred),'DELETE')
 call('/api/v1/ai/override','DELETE')
 r=m.call('/api/platform/tenants/'+tid,'PATCH',{'status':'DISABLED'},role='platform');rec('R3-AI-CLEANUP','Remove own override/providers; disable only owned tenant','200',r,r.status_code==200)
 global_after=m.payload(m.call('/api/v1/ai/settings',role='platform'))['data'];rec('R3-AI-GLOBAL-PRESERVED','Compare global AI settings before/after scoped local test','Exact global settings unchanged',{'unchanged':global_before==global_after,'featureEnabled':global_after.get('feature_enabled')},global_before==global_after)
 if server:server.shutdown();server.server_close()
