"""Start only the isolated local API with the preserved pre-Round-2 UUID boundary."""
import importlib.util,os,subprocess,time
from pathlib import Path
import requests
from scripts.greenfield_uuid import ROOT,STATE,settings,verify_resources
from sqlalchemy.engine import make_url
verify_resources();env=settings();u=make_url(env['DATABASE_URL'])
assert u.database=='sbom_greenfield_uuid' and u.host=='127.0.0.1' and u.port==56044
assert subprocess.run(['/usr/sbin/lsof','-tiTCP:18000','-sTCP:LISTEN'],capture_output=True).returncode!=0
baseline=Path(__file__).resolve().parent/'before/app/public_api.py'
code="import importlib.util,sys; s=importlib.util.spec_from_file_location('app.public_api',"+repr(str(baseline))+"); m=importlib.util.module_from_spec(s); sys.modules['app.public_api']=m; s.loader.exec_module(m); import uvicorn; uvicorn.run('app.main:app',host='127.0.0.1',port=18000)"
with (STATE/'backend.log').open('ab') as log:
 p=subprocess.Popen([str(ROOT/'.venv/bin/python'),'-B','-c',code],cwd=STATE,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
for _ in range(80):
 if p.poll() is not None:raise RuntimeError('API start failed; private backend log')
 try:
  if requests.get('http://127.0.0.1:18000/health',timeout=2).status_code==200:break
 except requests.RequestException:pass
 time.sleep(.5)
print('Isolated baseline API ready; no bootstrap or migrations; PID',p.pid)
