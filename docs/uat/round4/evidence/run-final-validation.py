"""Run final checks serially after complete frozen backend acceptance."""
from pathlib import Path
import datetime,hashlib,json,os,re,subprocess,time
R=Path('/Users/ferozebasha/sbom'); D=Path(__file__).resolve().parent
m=json.loads((D/'frozen-acceptance-attempt2-manifest.json').read_text())
assert m['status']=='FINISHED' and m['sourceUnchangedDuringRun'], 'Finish and verify frozen source first'
assert not (D/'validation-results.json').exists(), 'Do not overwrite a validation attempt'
node=Path('/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node')
python=R/'.venv/bin/python'; private=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text())
def sanitize(s):
 for user in private.values():s=s.replace(user['password'],'[REDACTED_PASSWORD]')
 s=re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+','[REDACTED_TOKEN]',s)
 s=re.sub(r'(?i)(?:postgresql(?:\+\w+)?|redis|rediss|amqp)://[^\s<>"\x27]+','[REDACTED_CONNECTION]',s)
 s=re.sub(r'(?i)(Bearer\s+)[A-Za-z0-9._~+/-]{16,}',r'\1[REDACTED]',s)
 return s
checks=[('vitest-full-final',[str(node),'node_modules/vitest/vitest.mjs','run','--maxWorkers=1'],R/'frontend'),
 ('typescript-final',[str(node),'node_modules/typescript/bin/tsc','--noEmit'],R/'frontend'),
 ('ruff-final',[str(python),'-m','ruff','check','app','tests','scripts/reconcile_analysis_run_finding_counts.py','scripts/greenfield_uuid.py'],R),
 ('eslint-full-final',[str(node),'node_modules/eslint/bin/eslint.js','.','--format','json'],R/'frontend'),
 ('build-final',[str(python),'-m','scripts.greenfield_uuid','build'],R),
 ('diff-whitespace-final',['git','-c','core.fsmonitor=false','diff','--check'],R)]
def verify_source():
 return sorted(name for name,digest in m['sourceHashesAfter'].items() if not (R/name).is_file() or hashlib.sha256((R/name).read_bytes()).hexdigest()!=digest)
assert not verify_source(), 'Source changed since the backend run'
results={'status':'RUNNING','startedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':[]}
env=os.environ.copy();env['PATH']=str(node.parent)+os.pathsep+env['PATH'];env['PYTHONPATH']=str(R)
for name,command,cwd in checks:
 start=time.time(); path=D/(name+'.log');print('Starting',name,flush=True)
 p=subprocess.Popen(command,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 key=False
 with path.open('w') as log:
  for line in p.stdout:
   if '-----BEGIN' in line and 'PRIVATE KEY-----' in line:key=True;log.write('[REDACTED_PRIVATE_KEY]\n')
   if not key:log.write(sanitize(line));log.flush()
   if '-----END' in line and 'PRIVATE KEY-----' in line:key=False
 code=p.wait(); outcome='PASS' if code==0 else 'FAIL'
 row={'name':name,'command':command,'cwd':str(cwd),'outcome':outcome,'exitCode':code,'runtimeSeconds':round(time.time()-start,3),'log':'evidence/'+path.name}
 clean=re.sub(r'\x1b\[[0-9;]*m','',path.read_text())
 if name=='vitest-full-final':
  for label,key in [('Tests','testCounts'),('Test Files','fileCounts')]:
   match=re.search(r'(?m)^\s*'+label+r'\s+(.+)$',clean)
   if match:row[key]={outcome:int(number.replace(',','')) for number,outcome in re.findall(r'(\d[\d,]*)\s+(passed|failed|skipped|todo)',match.group(1))}
 if name=='eslint-full-final':
  try:
   lint=json.loads(clean);row['fileCount']=len(lint);row['errors']=sum(x['errorCount'] for x in lint);row['warnings']=sum(x['warningCount'] for x in lint)
  except (ValueError,TypeError):row['parserQualification']='See raw sanitized ESLint log'
 results['checks'].append(row);(D/'validation-results.json').write_text(json.dumps(results,indent=2)+'\n');print(name,outcome,row['runtimeSeconds'],flush=True)
results['changedSourceFiles']=verify_source();results['sourceUnchangedFromBackend']=not results['changedSourceFiles']
results['status']='PASS' if all(r['outcome']=='PASS' for r in results['checks']) and results['sourceUnchangedFromBackend'] else 'FAIL';results['finishedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat()
(D/'validation-results.json').write_text(json.dumps(results,indent=2)+'\n');print('Final checks',results['status'],flush=True)
