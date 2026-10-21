"""Sanitize only this task's generated logs; preserve all historical evidence."""
from pathlib import Path
import json,re,datetime,xml.etree.ElementTree as ET
D=Path(__file__).resolve().parent
private=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text())
patterns=[(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+','[REDACTED_TOKEN]'),
 (r'(?i)(?:postgresql(?:\+\w+)?|redis|rediss|amqp)://[^\s<>"\x27]+','[REDACTED_CONNECTION]'),
 (r'(?i)(Bearer\s+)[A-Za-z0-9._~+/-]{16,}',r'\1[REDACTED]'),
 (r'(?i)(__Host-sbom-session=)[^;\s"<>]+',r'\1[REDACTED]'),
 (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----','[REDACTED_PRIVATE_KEY]')]
changed=[];validated=[]
# Never rewrite a live stream while the frozen run is writing it.
manifest=json.loads((D/'frozen-acceptance-manifest.json').read_text())
active={'pytest-full-frozen.log','acceptance-outcomes.jsonl'} if manifest['status']=='RUNNING' else set()
second=D/'frozen-acceptance-attempt2-manifest.json'
if second.exists() and json.loads(second.read_text())['status']=='RUNNING':active.update({'pytest-full-frozen-attempt2.log','acceptance-attempt2-outcomes.jsonl'})
validation=D/'validation-results.json'
if validation.exists() and json.loads(validation.read_text())['status']=='RUNNING':active.update({'vitest-full-final.log','typescript-final.log','ruff-final.log','eslint-full-final.log','build-final.log','diff-whitespace-final.log'})
for p in D.iterdir():
 if p.suffix not in ('.log','.xml') or p.name in active:continue
 s=p.read_text();out=s
 for user in private.values():out=out.replace(user['password'],'[REDACTED_PASSWORD]')
 for pattern,replacement in patterns:out=re.sub(pattern,replacement,out)
 out=re.sub(r'''(?i)((?:"|')?(?:password|access_token|refresh_token|client_secret|api_key)(?:"|')?\s*[:=]\s*)(["'])[^\n]*?\2''',lambda m:m.group(1)+m.group(2)+'[REDACTED]'+m.group(2),out)
 if out!=s:p.write_text(out);changed.append(p.name)
 if p.suffix=='.xml':ET.parse(p);validated.append(p.name)
(D/'sanitization-verification.json').write_text(json.dumps({'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Round 4 .log/.xml only; earlier evidence never rewritten','redactedFiles':changed,'xmlValidated':validated,'liveStreamsExcluded':sorted(active),'secretsPrinted':False},indent=2)+'\n')
print('Round 4 logs sanitized:',len(changed),'XML documents validated:',len(validated),'live streams excluded:',len(active))
