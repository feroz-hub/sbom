"""Reload only the verified existing Greenfield API; no bootstrap or migration."""
import json
import os
import re
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from sqlalchemy.engine import make_url

from scripts.greenfield_uuid import ROOT, STATE, settings

out=Path(__file__).resolve().parent
pid=int(subprocess.check_output(['/usr/sbin/lsof','-tiTCP:18000','-sTCP:LISTEN'],text=True).split()[0])
command=subprocess.check_output(['/bin/ps','-p',str(pid),'-o','command='],text=True)
assert 'uvicorn app.main:app' in command and str(ROOT/'.venv/bin/python') in command
environment=subprocess.check_output(['/bin/ps','eww','-p',str(pid),'-o','command='],text=True)
match=re.search(r'(?:^|\s)DATABASE_URL=([^\s]+)',environment)
assert match
observed=make_url(match.group(1))
assert observed.database=='sbom_greenfield_uuid' and observed.host=='127.0.0.1' and observed.port==56044
for name in ('environment.json','runtime-password','security-mail-key'):
    assert (STATE/name).is_file()
env=settings()
assert make_url(env['DATABASE_URL'])==observed
os.kill(pid,signal.SIGTERM)
for _ in range(100):
    check=subprocess.run(['/usr/sbin/lsof','-tiTCP:18000','-sTCP:LISTEN'],capture_output=True)
    if not check.stdout:break
    time.sleep(.1)
else:raise RuntimeError('Verified local API did not stop; no replacement started')
with (STATE/'backend.log').open('ab') as log:
    process=subprocess.Popen([str(ROOT/'.venv/bin/python'),'-B','-m','uvicorn','app.main:app','--host','127.0.0.1','--port','18000'],cwd=STATE,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
for _ in range(80):
    if process.poll() is not None:raise RuntimeError('Local API restart failed; inspect private backend log')
    try:
        response=requests.get('http://127.0.0.1:18000/health',timeout=2)
        if response.status_code==200:break
    except requests.RequestException:pass
    time.sleep(.5)
else:raise RuntimeError('Local API readiness budget exhausted')
from scripts.dev_runtime import Runtime
runtime=Runtime(ROOT)
if runtime.acquire():
    try:
        state=runtime.load()
        if state and state['services'].get('API',{}).get('pid')==pid:
            runtime.state=state;runtime.register('API',process.pid,18000)
    finally:runtime.release()
evidence={'time':datetime.now(timezone.utc).isoformat(),'oldApiPid':pid,'newApiPid':process.pid,'verifiedDatabase':'sbom_greenfield_uuid','healthStatus':response.status_code,'onlyApiRestarted':True,'bootstrapOrMigrationRun':False}
(out/'api-reload.json').write_text(json.dumps(evidence,indent=2))
print(json.dumps(evidence))
