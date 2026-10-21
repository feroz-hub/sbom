"""Start stopped isolated services only; no bootstrap/schema/credential changes."""
import subprocess
from scripts.greenfield_uuid import ROOT, STATE, settings, node_binary, frontend_workspace, verify_resources
from scripts import greenfield_https
verify_resources();env=settings();node=node_binary();env['PATH']=str(node.parent)+':/usr/bin:/bin:/usr/local/bin'
cert,key,*_=greenfield_https.ensure_certificate(STATE,prepare=False)
assert not subprocess.run(['/usr/sbin/lsof','-tiTCP:13000','-sTCP:LISTEN'],capture_output=True).stdout
# Refuse duplicate Greenfield workers.
listing=subprocess.check_output(['ps','-axo','command='],text=True)
assert not any('celery -A scripts.greenfield_worker:celery_app worker' in line and '-c ' not in line for line in listing.splitlines())
commands={
 'frontend':([str(node),str(ROOT/'frontend/node_modules/next/dist/bin/next'),'dev','--webpack','--hostname','127.0.0.1','--port','13000','--experimental-https','--experimental-https-key',str(key),'--experimental-https-cert',str(cert)],frontend_workspace('frontend')),
 'worker':([str(ROOT/'.venv/bin/python'),'-B','-m','celery','-A','scripts.greenfield_worker:celery_app','worker','--loglevel=INFO','--pool=solo','--concurrency=1','--queues=celery,reports','--hostname=greenfield@%h','--beat','--schedule='+str(STATE/'security-mail-schedule')],STATE)}
for name,(cmd,cwd) in commands.items():
 with (STATE/(name+'.log')).open('ab') as log:p=subprocess.Popen(cmd,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 print('Started isolated',name,'PID',p.pid)
