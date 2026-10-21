"""Resume only unexecuted inventory nodes through the verified task-owned DB wrapper."""
from pathlib import Path
import hashlib,json,subprocess,sys,os,time
ROOT=Path('/Users/ferozebasha/sbom');D=Path(__file__).resolve().parent
nodes=json.loads((D/'remaining-backend-nodes.json').read_text());assert nodes and len(nodes)==len(set(nodes))
for node in nodes:
 p=(ROOT/node.split('::')[0]).resolve()
 assert p.is_relative_to(ROOT/'tests') and p.is_file(), 'Selector must reference existing repository test'
def snapshot():
 return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for base in [ROOT/'app',ROOT/'tests'] for p in base.rglob('*') if p.is_file() and p.suffix in ('.py','.json') and '__pycache__' not in p.parts}
os.environ['ROUND4_EXACT_SELECTION']='1'
started=time.time()
before=snapshot();command=[sys.executable,str(D/'run-fix-regressions.py'),'tests','-o','addopts=','--junitxml='+str(D/'pytest-remaining-backend.xml')]
with (D/'pytest-remaining-backend.log').open('w') as log:r=subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
after=snapshot();(D/'remaining-run-manifest.json').write_text(json.dumps({'startedEpoch':started,'runtimeSeconds':time.time()-started,'selectedNodes':len(nodes),'exitCode':r.returncode,'sourceUnchangedDuringRun':before==after,'beforeSourceHashes':before,'afterSourceHashes':after},indent=2)+'\n');sys.exit(r.returncode)
