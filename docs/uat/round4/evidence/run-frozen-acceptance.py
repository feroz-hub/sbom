"""Complete exact-source acceptance; local logs sanitized before persistence."""
from pathlib import Path
import datetime,hashlib,json,os,re,subprocess,sys,time

R=Path('/Users/ferozebasha/sbom');D=Path(__file__).resolve().parent
assert not (D/'frozen-acceptance-manifest.json').exists(), 'Do not overwrite an acceptance run'
def snapshot():
    result={}
    for base in ('app','tests','scripts','alembic','frontend/src'):
        for p in (R/base).rglob('*'):
            if p.is_file() and '__pycache__' not in p.parts and p.suffix in ('.py','.json','.sql','.ts','.tsx','.yaml','.toml'):
                result[str(p.relative_to(R))]=hashlib.sha256(p.read_bytes()).hexdigest()
    for name in ('requirements.txt','pyproject.toml','pytest.ini','frontend/package.json','frontend/package-lock.json'):
        result[name]=hashlib.sha256((R/name).read_bytes()).hexdigest()
    return result
private=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text())
passwords=[u['password'] for u in private.values()]
def sanitize(value):
    for password in passwords:value=value.replace(password,'[REDACTED_PASSWORD]')
    for pattern,replacement in [
        (r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+','[REDACTED_TOKEN]'),
        (r'(?i)(?:postgresql(?:\+\w+)?|redis|rediss|amqp)://[^\s<>"\x27]+','[REDACTED_CONNECTION]'),
        (r'(?i)(Bearer\s+)[A-Za-z0-9._~+/-]{16,}',r'\1[REDACTED]'),
        (r'(?i)(__Host-sbom-session=)[^;\s"<>]+',r'\1[REDACTED]'),
        (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----','[REDACTED_PRIVATE_KEY]'),
    ]:value=re.sub(pattern,replacement,value)
    return re.sub(r'''(?i)((?:"|')?(?:password|access_token|refresh_token|client_secret|api_key)(?:"|')?\s*[:=]\s*)(["'])[^\n]*?\2''',lambda m:m.group(1)+m.group(2)+'[REDACTED]'+m.group(2),value)
command=[sys.executable,str(D/'run-acceptance.py'),'tests','-o','addopts=','--durations=25','--junitxml='+str(D/'pytest-full-frozen.xml')]
before=snapshot();start=time.time()
manifest={'status':'RUNNING','startedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'command':command,
          'cwd':str(R),'sourceHashesBefore':before,'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip(),
          'collectedInventory':len(json.loads((D/'acceptance-inventory.json').read_text())),
          'database':'sbom_greenfield_uuid_round4_acceptance_test_20261020','markerExclusions':[],
          'backupRestoreOptIn':True,'redisIntegration':'task-owned ephemeral loopback server',
          'optionalLimitations':['Four hosted-provider keys absent; no paid/external credentials activated',
                                  'Empty-population scenario assumes legacy global-account management and hardcoded Mailpit topology',
                                  'Two BFF HTTP topology requires separate supported production BFF builds and isolation setup'],
          'applicationSourceOrTestEditsAllowedDuringRun':False}
(D/'frozen-acceptance-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
p=subprocess.Popen(command,cwd=R,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
in_key=False
with (D/'pytest-full-frozen.log').open('w') as log:
    for line in p.stdout:
        if '-----BEGIN' in line and 'PRIVATE KEY-----' in line:
            in_key=True;log.write('[REDACTED_PRIVATE_KEY]\n')
        if not in_key:log.write(sanitize(line));log.flush()
        if '-----END' in line and 'PRIVATE KEY-----' in line:in_key=False
code=p.wait();after=snapshot()
xml=D/'pytest-full-frozen.xml'
if xml.exists():xml.write_text(sanitize(xml.read_text()))
manifest.update(status='FINISHED',exitCode=code,runtimeSeconds=round(time.time()-start,3),finishedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                sourceUnchangedDuringRun=before==after,sourceHashesAfter=after,changedSourceFiles=sorted(k for k in set(before)|set(after) if before.get(k)!=after.get(k)))
(D/'frozen-acceptance-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({k:v for k,v in manifest.items() if k in ('status','exitCode','runtimeSeconds','sourceUnchangedDuringRun','changedSourceFiles')}),flush=True)
sys.exit(code)
