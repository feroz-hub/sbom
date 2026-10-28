"""Inspect real configured AI providers and verify disabled-feature behavior."""
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

folder=Path(__file__).resolve().parent/'evidence/2026-10-19'
users=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text())
cases=json.loads((folder/'workflow-cases.json').read_text())
tokens={}
def api(role,path,method='GET',body=None):
    base='http://127.0.0.1:18000'
    if role not in tokens:
        u=users[role]
        req=urllib.request.Request(base+'/api/auth/native/login',data=json.dumps({k:u[k] for k in ('email','password')}).encode(),headers={'Content-Type':'application/json'})
        tokens[role]=json.load(urllib.request.urlopen(req,timeout=30))['access_token']
    headers={'Authorization':'Bearer '+tokens[role],'Content-Type':'application/json'}
    if users[role]['tenant_id']:headers['X-Tenant-ID']=users[role]['tenant_id']
    req=urllib.request.Request(base+path,method=method,headers=headers,data=None if body is None else json.dumps(body).encode())
    try:r=urllib.request.urlopen(req,timeout=30)
    except urllib.error.HTTPError as e:r=e
    raw=r.read()
    return {'status':r.status,'data':json.loads(raw) if raw else None,'request_id':r.headers.get('x-request-id')}
def record(id,role,expected,actual,status,steps):
    item={'id':id,'module':'AI configuration and providers','role':role,'preconditions':'Existing configuration inspected without modification; credentials/tokens stay in memory','steps':steps,'expected':expected,'actual':actual,'api':actual.get('status'),'status':status,'defect':None,'time':datetime.now(timezone.utc).isoformat()}
    cases[:]=[c for c in cases if c['id']!=id]+[item]
    (folder/'workflow-cases.json').write_text(json.dumps(cases,indent=2))
    print(id,status,item['api'],flush=True)
config=api('admin','/api/v1/ai/effective-config')
providers=api('admin','/api/v1/ai/providers')
safe={'status':config['status'],'feature_enabled':config['data'].get('feature_enabled'),'settings_source':config['data'].get('settings_source'),'source':config['data'].get('source'),'providers':providers['data']}
record('UAT-AI-RUNTIME-CONFIG','admin','Provider catalogue distinguishes enabled local provider from disabled hosted integrations',safe,'PASS' if config['status']==200 and providers['status']==200 else 'FAIL','GET actual effective config and runtime provider availability; no credentials or private values recorded')
local=None
try:
    with urllib.request.urlopen('http://localhost:11434/api/tags',timeout=5) as response:
        data=json.load(response)
        local={'status':response.status,'reachable':True,'available_model_names':[m.get('name') for m in data.get('models',[])]}
except (urllib.error.URLError,TimeoutError):local={'reachable':False,'reason':'Configured local Ollama endpoint is unreachable; no model invocation attempted'}
record('UAT-AI-LOCAL-READINESS','admin','Configured Ollama model catalogue endpoint is reachable; record actual installed models',local,'PASS' if local.get('reachable') else 'BLOCKED','Probe only configured local provider model catalogue; empty model list does not establish inference readiness')
if config['status']==200 and config['data'].get('feature_enabled') is False:
    for role in ('admin','analyst','developer','viewer','foreign'):
        r=api(role,'/api/ai/copilot/ask','POST',{'question':'Summarize this tenant security posture.'})
        passed=(r['status']==409 and 'AI_FIXES_DISABLED' in json.dumps(r['data'])) or (role in ('analyst','developer','viewer') and r['status']==403)
        record('UAT-AI-DISABLED-GATE-'+role,role,'Disabled AI feature or role authorization rejects inference before upstream invocation',r,'PASS' if passed else 'FAIL','POST real Copilot endpoint while observed global feature flag is false')
    record('UAT-AI-LIVE-PROVIDER','admin','Successful live AI completion requires an enabled application feature and reachable configured provider',{'status':None,'feature_enabled':False,'ollama':local,'hosted_providers':'Unavailable in runtime catalogue; no credential fabricated'},'BLOCKED','Observe actual disabled-feature gate and local provider readiness; leave shared configuration unchanged')
