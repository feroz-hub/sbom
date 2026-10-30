from pathlib import Path
import subprocess,json,os
root=Path('/Users/ferozebasha/sbom');out=Path(__file__).resolve().parent;node='/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node'
commands=[('typescript',[node,'node_modules/typescript/bin/tsc','--noEmit'],root/'frontend'),('eslint-full',[node,'node_modules/eslint/bin/eslint.js','src','--format','json'],root/'frontend'),('build',[str(root/'.venv/bin/python'),'scripts/dev.py','setup','--profile','greenfield','--frontend-build'],root),('ruff-full',[str(root/'.venv/bin/python'),'-m','ruff','check','app','tests','--output-format','json'],root)]
results=[]
for name,args,cwd in commands:
 env=dict(os.environ,PYTHONPATH=str(root))
 with (out/(name+'.log')).open('w') as log:r=subprocess.run(args,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT)
 results.append({'check':name,'command':args,'cwd':str(cwd),'exitCode':r.returncode});(out/'validation-commands.json').write_text(json.dumps(results,indent=2));print(name,r.returncode,flush=True)
