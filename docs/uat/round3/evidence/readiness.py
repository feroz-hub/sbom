import importlib.util,json,requests,subprocess,time
from pathlib import Path
p=Path(__file__).with_name('live-common.py');spec=importlib.util.spec_from_file_location('common',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
for path,role in [('/api/auth/me','platform'),('/api/v1/ai/settings','admin'),('/api/v1/ai/providers/available','admin'),('/api/v1/ai/credentials','admin')]:
 r=m.call(path,role=role);m.rec('R3-READINESS-'+path,'GET '+path,'Read effective authorization/provider metadata without mutation',m.payload(r),r.status_code==200,role,file='readiness.json')
r=m.call('/api/ai/copilot/ask','POST',{'question':'Summarize the current disposable UAT portfolio'});m.rec('R3-AI-DISABLED-GATE','POST copilot/ask; do not enable feature','409 AI_FIXES_DISABLED when effective feature disabled',m.payload(r),r.status_code==409,file='readiness.json')
try:r=requests.get('http://127.0.0.1:11434/api/tags',timeout=5);data={'status':r.status_code,'models':[x['name'] for x in r.json().get('models',[])]}
except requests.RequestException as e:data={'reachable':False,'error':type(e).__name__}
m.rec('R3-OLLAMA-READINESS','GET existing local Ollama /api/tags; no model download','Record model availability, no completion claim',data,True,file='readiness.json')
