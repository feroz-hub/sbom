"""Wait for this exact frozen run, then execute serial validation on success."""
from pathlib import Path
import json,subprocess,sys,time
D=Path(__file__).resolve().parent
while True:
 m=json.loads((D/'frozen-acceptance-attempt2-manifest.json').read_text())
 if m['status']=='FINISHED':break
 time.sleep(10)
if m.get('exitCode')!=0 or not m.get('sourceUnchangedDuringRun'):
 print('Frozen run needs reconciliation before final validation; no checks started',flush=True);sys.exit(1)
sys.exit(subprocess.run([sys.executable,str(D/'run-final-validation.py')]).returncode)
