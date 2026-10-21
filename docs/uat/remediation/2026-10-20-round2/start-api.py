"""Start only a stopped isolated API from current sources; no bootstrap/migrations."""
import subprocess,time,json
from pathlib import Path
import requests
from sqlalchemy.engine import make_url
from scripts.greenfield_uuid import ROOT,STATE,settings,verify_resources
verify_resources();env=settings();u=make_url(env['DATABASE_URL']);assert (u.host,u.port,u.database)==('127.0.0.1',56044,'sbom_greenfield_uuid')
assert not subprocess.run(['/usr/sbin/lsof','-tiTCP:18000','-sTCP:LISTEN'],capture_output=True).stdout
with (STATE/'backend.log').open('ab') as log:p=subprocess.Popen([str(ROOT/'.venv/bin/python'),'-B','-m','uvicorn','app.main:app','--host','127.0.0.1','--port','18000'],cwd=STATE,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
for _ in range(100):
 if p.poll() is not None:raise RuntimeError('API startup failed; inspect private log')
 try:
  if requests.get('http://127.0.0.1:18000/health',timeout=2).status_code==200:break
 except requests.RequestException:pass
 time.sleep(.5)
else:raise RuntimeError('API readiness timeout')
e={'pid':p.pid,'health':200,'database':u.database,'onlyStoppedIsolatedAPIStarted':True,'bootstrapOrMigrations':False};(Path(__file__).resolve().parent/'api-recovery.json').write_text(json.dumps(e,indent=2));print(e)
