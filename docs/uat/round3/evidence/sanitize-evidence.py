"""Sanitize only Round3 generated execution logs/results, never historic evidence or source fixtures."""
from pathlib import Path
import json,re,hashlib
D=Path(__file__).resolve().parent
private=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text());passwords=[u['password'] for u in private.values()]
patterns=[(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+','[REDACTED_TOKEN]'),(r'(?i)(?:postgresql(?:\+\w+)?|redis|rediss|amqp)://[^\s<>"\x27]+','[REDACTED_CONNECTION]'),(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----','[REDACTED_PRIVATE_KEY]'),(r'(?i)(__Host-sbom-session=)[^;\s"<>]+',r'\1[REDACTED]'),(r'(?i)(Bearer\s+)[A-Za-z0-9._~+/-]{16,}',r'\1[REDACTED]')]
changes=[]
for p in D.iterdir():
 if p.suffix not in ('.log','.xml','.json') or p.name in ('sanitize-audit.json',):continue
 # Never touch golden sources/hashes, downloaded native documents, original provenance, code or binary outputs.
 if p.name.startswith(('original-','workspace-before','protected-','git-','before','converted','browser-native-export','repair-','jsf-','scheduled-artifact')) and p.suffix=='.json':continue
 before=p.read_text(errors='replace');after=before
 for password in passwords:after=after.replace(password,'[REDACTED_PASSWORD]')
 for pattern,value in patterns:after=re.sub(pattern,value,after)
 # Redact quoted values in captured traceback/API diagnostic fields while retaining field labels and assertions.
 after=re.sub(r'(?i)((?:"|\x27)?(?:password|access_token|refresh_token|client_secret|api_key)(?:"|\x27)?\s*[:=]\s*)(["\x27])[^\n]*?\2',lambda m:m.group(1)+m.group(2)+'[REDACTED]'+m.group(2),after)
 if before!=after:p.write_text(after);changes.append({'file':p.name,'beforeSha256':hashlib.sha256(before.encode()).hexdigest(),'afterSha256':hashlib.sha256(after.encode()).hexdigest()})
(D/'sanitize-audit.json').write_text(json.dumps({'filesSanitized':changes,'scope':'Only Round3 generated logs/XML/metadata; original evidence and implementation source untouched','secretsExported':False},indent=2)+'\n');print('Sanitized generated execution files:',len(changes))
