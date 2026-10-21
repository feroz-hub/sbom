from pathlib import Path
from uuid import uuid4
import importlib.util,json
s=importlib.util.spec_from_file_location('m',Path(__file__).with_name('live-common.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);fixture=json.loads((m.OUT/'round3-scope.json').read_text());assert fixture['owned']=='Round3';identity=fixture['sbom_ids'][0];file='legacy-analysis-after.json'
def check(id,role,value,expected):
 r=m.call('/analyze-sbom-osv','POST',{'sbom_id':value,'hydrate':True},role=role);m.rec(id,'POST supported deprecated OSV route with '+role+' identity',str(expected),m.payload(r),r.status_code==expected,role,file);return r
check('R3-LEGACY-VIEWER','viewer',identity,403);check('R3-LEGACY-FOREIGN','foreign',identity,404);check('R3-LEGACY-INTEGER','admin',1,422);check('R3-LEGACY-UNKNOWN-UUID','admin',str(uuid4()),404)
r=check('R3-LEGACY-REAL-OSV','admin',identity,200);assert r.status_code==200;d=r.json();m.rec('R3-LEGACY-WIRE-IDENTITY','Inspect persisted real OSV response, run identity and advertised successor','SBOM UUID; numeric run ID; UUID successor; deprecation preserved',{'status':r.status_code,'sbom_id':d.get('sbom_id'),'run_id':d.get('id'),'run_status':d.get('run_status'),'link':r.headers.get('Link'),'deprecation':r.headers.get('Deprecation')},d.get('sbom_id')==identity and isinstance(d.get('id'),int) and r.headers.get('Link')==f'</api/sboms/{identity}/analyze>; rel="successor-version"' and r.headers.get('Deprecation')=='true',file=file)
run=m.call('/api/runs/'+str(d['id']));m.rec('R3-LEGACY-PERSISTED-READ','Read returned real OSV run','200 same UUID and run identity',m.payload(run),run.status_code==200 and run.json().get('sbom_id')==identity,file=file)
