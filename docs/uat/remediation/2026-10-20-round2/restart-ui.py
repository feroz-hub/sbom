"""Restart only the verified isolated HTTPS frontend; preserve cert and workspace."""
import subprocess,signal,os,time,json
from pathlib import Path
from scripts.greenfield_uuid import ROOT,STATE,settings,node_binary
from scripts import greenfield_https
pid=int(subprocess.check_output(['/usr/sbin/lsof','-tiTCP:13000','-sTCP:LISTEN'],text=True).split()[0]);cmd=subprocess.check_output(['ps','-p',str(pid),'-o','command='],text=True);assert 'next-server' in cmd
# The listener must belong to the exact task-owned private frontend directory.
cwd=subprocess.check_output(['/usr/sbin/lsof','-a','-p',str(pid),'-d','cwd','-Fn'],text=True);assert '\nn'+str(STATE/'frontend')+'\n' in cwd
os.kill(pid,signal.SIGTERM)
for _ in range(100):
 if not subprocess.run(['/usr/sbin/lsof','-tiTCP:13000','-sTCP:LISTEN'],capture_output=True).stdout:break
 time.sleep(.1)
else:raise RuntimeError('Frontend still listening; no replacement started')
cert,key,*_=greenfield_https.ensure_certificate(STATE,prepare=False);node=node_binary();env=settings();env['PATH']=str(node.parent)+':/usr/bin:/bin:/usr/local/bin'
with (STATE/'frontend.log').open('ab') as log:p=subprocess.Popen([str(node),str(ROOT/'frontend/node_modules/next/dist/bin/next'),'dev','--webpack','--hostname','127.0.0.1','--port','13000','--experimental-https','--experimental-https-key',str(key),'--experimental-https-cert',str(cert)],cwd=STATE/'frontend',env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
e={'oldPID':pid,'newPID':p.pid,'onlyIsolatedFrontendRestarted':True,'TLSValidationBypass':False};(Path(__file__).resolve().parent/'ui-restart.json').write_text(json.dumps(e,indent=2));print(e)
