"""Platform-only sync with a future cutoff; compare exact catalog content."""
import importlib.util,json,hashlib
from pathlib import Path
OUT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('r1api',OUT/'live-common.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def api(role,path,method='GET',body=None):return m.payload(m.call(path,method,body,role=role))
cases=[]
def record(id,r,ok,expected,role):
 cases.append({'id':id,'module':'KEV authorization','role':role,'preconditions':'Live Greenfield; no-prune future cutoff','steps':id,'expected':expected,'actual':r,'result':'PASS' if ok else 'FAIL'})
 (OUT/'api-kev-round3.json').write_text(json.dumps(cases,indent=2));print(id,cases[-1]['result'],flush=True)
def catalog():
 entries=[]
 for offset in range(0,10000,500):
  r=api('admin',f'/api/v1/kev?limit=500&offset={offset}');assert r['status']==200
  entries+=r['data']['items']
  if len(entries)>=r['data']['total']:break
 return {'count':len(entries),'sha256':hashlib.sha256(json.dumps(entries,sort_keys=True).encode()).hexdigest()}
before=catalog()
for role in ('admin','analyst','developer','viewer','foreign','platform'):
 r=api(role,'/api/v1/kev/sync','POST',{'since':'2099-01-01','prune_stale':False})
 ok=r['status']==(200 if role=='platform' else 403)
 if role=='platform':ok=ok and r['data']['upserted']==0 and r['data']['matched_after_filter']==0
 record('UAT-KEV-SYNC-'+role,r,ok,'Platform 200 zero writes; every tenant role 403',role)
after=catalog();record('R2-KEV-CATALOG-UNCHANGED',{'before':before,'after':after},before==after,'Exact catalog row digest unchanged','platform')
