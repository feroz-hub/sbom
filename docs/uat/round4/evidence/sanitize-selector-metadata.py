"""Retain exact test selectors privately; public metadata uses stable safe labels."""
from pathlib import Path
import datetime,hashlib,json,os,re
D=Path(__file__).resolve().parent
private=Path('/Users/ferozebasha/.sbom-greenfield-uuid/round4-node-selectors');private.mkdir(mode=0o700,exist_ok=True)
pattern=re.compile(r'(?i)(?:postgresql(?:\+\w+)?|redis|rediss|amqp)://[^\s<>"\x27]+')
changed=[]
for name in ['acceptance-inventory.json','acceptance-outcomes.jsonl','acceptance-attempt2-inventory.json','acceptance-attempt2-outcomes.jsonl']:
 p=D/name;s=p.read_text();n=len(pattern.findall(s))
 if not n:continue
 target=private/name
 fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:f.write(s)
 out=pattern.sub(lambda m:'[REDACTED_CONNECTION_SHA256_'+hashlib.sha256(m.group().encode()).hexdigest()[:12]+']',s)
 if p.suffix=='.json':json.loads(out)
 else:
  for line in out.splitlines():json.loads(line)
 p.write_text(out);changed.append({'file':name,'parameterLabelsRedacted':n,'originalSha256':hashlib.sha256(s.encode()).hexdigest(),'publicSha256':hashlib.sha256(out.encode()).hexdigest()})
(D/'selector-sanitization.json').write_text(json.dumps({'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Three synthetic database-safety parameter URLs in each collection/outcome file. No seeded credentials or actual test database URLs were present.','stableLabels':'SHA256-derived parameter labels retain distinct node identity and multiplicity; exact source-generated selectors remain in private mode0600 task files.','changedFiles':changed},indent=2)+'\n')
print('Public selector metadata sanitized; exact synthetic parameter selectors retained privately')
