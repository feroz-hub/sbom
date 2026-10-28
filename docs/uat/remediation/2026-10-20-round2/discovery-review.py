import importlib.util,json,hashlib
from pathlib import Path
OUT=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('client',OUT.parent/'2026-10-20-round1/live-api.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
rows=[]
for role,path,expected in [('foreign','/api/tenants/'+m.USERS['foreign']['tenant_id']+'/user-candidates?q=olympus',200),('foreign','/api/tenants/'+m.USERS['admin']['tenant_id']+'/users',404),('viewer','/api/tenants/'+m.USERS['viewer']['tenant_id']+'/user-candidates?q=olympus',403)]:
 r=m.api(role,path);rows.append({'role':role,'path':path,'actual':r,'expectedStatus':expected,'result':'PASS' if r['status']==expected else 'FAIL'})
source=Path('app/routers/tenants.py');before=OUT/'before'/source
assert source.read_bytes()==before.read_bytes()
(OUT/'api-discovery-review.json').write_text(json.dumps({'checks':rows,'discoveryPolicySourceUnchanged':True,'sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),'policyDecision':'Decision Needed; no policy change'},indent=2))
print('Read-only discovery controls:',[(r['role'],r['actual']['status'],r['result']) for r in rows])
