"""Remove this run's retained Admin BFF sessions without changing the account."""
import base64
import json
from datetime import datetime, timezone
from pathlib import Path
import redis
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

folder=Path('/Users/ferozebasha/sbom/docs/uat/evidence/2026-10-19')
cases=json.loads((folder/'cases.json').read_text())
start=min(datetime.fromisoformat(c['time'].replace('Z','+00:00')).timestamp() for c in cases)
end=datetime.now(timezone.utc).timestamp()
config=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/environment.json').read_text())
key=base64.b64decode(config['AUTH_SESSION_ENCRYPTION_KEY'])
store=redis.Redis.from_url('redis://127.0.0.1:56381/1',decode_responses=True)
def decode(value):
    return base64.urlsafe_b64decode(value+'='*((-len(value))%4))
matched=[]
for name in store.scan_iter(match='sbom:bff:*'):
    if len(name.rsplit(':',1)[-1])!=64:
        continue
    raw=store.get(name)
    if not raw:
        continue
    try:
        iv,ciphertext,tag=map(decode,raw.split('.'))
        data=json.loads(AESGCM(key).decrypt(iv,ciphertext+tag,name.encode()))
        claims=json.loads(decode(data['accessToken'].split('.')[1]))
        created=data.get('createdAt',0)/1000
        if data.get('provider')=='NATIVE' and str(claims.get('sub'))=='1' and start<=created<=end:
            matched.append(name)
    except (ValueError,KeyError,TypeError,InvalidTag):
        continue
removed=store.delete(*matched) if matched else 0
remaining=sum(bool(store.exists(name)) for name in matched)
previous=json.loads((folder/'session-cleanup.json').read_text()) if (folder/'session-cleanup.json').exists() else {}
passes=previous.get('cleanupPasses',[])
if previous and not passes:passes=[{'deleted':previous['deletedAdminBffSessionsFromThisRun'],'time':'Earlier scoped cleanup in this recorded run'}]
passes.append({'deleted':removed,'time':datetime.now(timezone.utc).isoformat()})
evidence={'deletedAdminBffSessionsFromThisRun':sum(p['deleted'] for p in passes),'remainingMatchedSessions':remaining,'cleanupPasses':passes,'accountRolesStatusPasswordUntouched':True,'scope':'NATIVE subject 1; session createdAt within recorded UAT run; development Redis DB 1 only; no session value/key logged'}
(folder/'session-cleanup.json').write_text(json.dumps(evidence,indent=2))
print(json.dumps(evidence))
