"""Sequential final readback, visual evidence and state guards."""
import subprocess,sys
from pathlib import Path
out=Path(__file__).resolve().parent
node='/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node'
checks=[('browser-vex-readback-final.log',[node,'--use-system-ca',str(out/'browser-protection.cjs'),'vex-readback']),('browser-candidate-visual.log',[node,'--use-system-ca',str(out/'browser-candidate-visual.cjs'),'candidate-visual']),('final-guards.log',[sys.executable,str(out/'final-guards.py')])]
failed=[]
for name,command in checks:
 with (out/name).open('w') as log:result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
 print(name,'exit',result.returncode,flush=True)
 if result.returncode:failed.append(name)
raise SystemExit(bool(failed))
