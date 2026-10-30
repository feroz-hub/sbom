from pathlib import Path
import subprocess,json,os,time
ROOT=Path('/Users/ferozebasha/sbom');OUT=Path(__file__).resolve().parent;NODE='/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node';env=os.environ.copy();env['PATH']=str(Path(NODE).parent)+os.pathsep+env['PATH'];entries=[]
checks=[('vitest-full-final',[NODE,'node_modules/vitest/vitest.mjs','run','--maxWorkers=1'],ROOT/'frontend'),('typescript-final',[NODE,'node_modules/typescript/bin/tsc','--noEmit'],ROOT/'frontend'),('eslint-full-final',[NODE,'node_modules/eslint/bin/eslint.js','src','--format','json'],ROOT/'frontend'),('build-final',[str(ROOT/'.venv/bin/python'),'scripts/dev.py','setup','--profile','greenfield','--frontend-build'],ROOT)]
for name,cmd,cwd in checks:
 started=time.monotonic()
 with (OUT/(name+'.log')).open('w') as f:r=subprocess.run(cmd,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT)
 entries.append({'check':name,'command':cmd,'cwd':str(cwd),'exitCode':r.returncode,'seconds':round(time.monotonic()-started,2)});(OUT/'frontend-final-commands.json').write_text(json.dumps(entries,indent=2)+'\n');print(name,'exit',r.returncode,flush=True)
