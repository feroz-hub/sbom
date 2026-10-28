"""Approved free local model, separate port/cache; never modifies shared Ollama."""
from pathlib import Path
import os,json,subprocess,time,requests
state=Path('/Users/ferozebasha/.sbom-greenfield-uuid/round3-local-model');state.mkdir(mode=0o700,exist_ok=True)
out=Path(__file__).resolve().parent
assert not subprocess.run(['/usr/sbin/lsof','-tiTCP:11435','-sTCP:LISTEN'],capture_output=True).stdout
model='qwen2.5:0.5b';env=dict(os.environ,OLLAMA_HOST='127.0.0.1:11435',OLLAMA_MODELS=str(state/'models'),OLLAMA_NUM_PARALLEL='1',OLLAMA_MAX_LOADED_MODELS='1',OLLAMA_CONTEXT_LENGTH='2048',OLLAMA_KEEP_ALIVE='0')
with (state/'server.log').open('ab') as log:p=subprocess.Popen(['/usr/local/bin/ollama','serve'],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
(state/'process.json').write_text(json.dumps({'pid':p.pid,'port':11435,'model':model,'owned':True}))
for _ in range(60):
 try:
  if requests.get('http://127.0.0.1:11435/api/tags',timeout=2).status_code==200:break
 except requests.RequestException:pass
 time.sleep(.25)
else:raise RuntimeError('Isolated Ollama not ready')
progress=[]
with requests.post('http://127.0.0.1:11435/api/pull',json={'model':model,'stream':True},stream=True,timeout=(10,300)) as r:
 assert r.status_code==200
 for line in r.iter_lines():
  if line:
   data=json.loads(line);assert 'error' not in data,data.get('error')
   status=data.get('status')
   if not progress or progress[-1]!=status:progress.append(status);print(status,flush=True)
assert progress[-1]=='success'
result={'approval':'Explicit user approval for a small isolated free model test','separatePort':11435,'separateModelCache':str(state/'models'),'model':model,'pull':progress,'available':requests.get('http://127.0.0.1:11435/api/tags',timeout=5).json(),'sharedServiceUnchanged':True}
(out/'local-model.json').write_text(json.dumps(result,indent=2));print('ISOLATED_MODEL_READY',flush=True)
