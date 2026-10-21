"""Fresh Round 2 resources verify CSAF source identity handling and isolation."""
import importlib.util,json,time,uuid
from pathlib import Path
out=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('api',out.parent/'2026-10-20-round1/live-api.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
name='UAT R2 source document '+str(time.time_ns())
p=m.api('admin','/api/projects','POST',{'project_name':name,'project_status':1});assert p['status']==201
pid=p['data']['id'];a=m.api('admin',f'/api/projects/{pid}/products','POST',{'name':name+' App','status':'active'});assert a['status']==201
product=a['data']['id'];doc={'bomFormat':'CycloneDX','specVersion':'1.5','serialNumber':'urn:uuid:'+str(uuid.uuid4()),'version':1,'metadata':{'component':{'type':'application','name':name,'version':'1'}},'components':[{'type':'library','name':'openssl','version':'1.1.1','purl':'pkg:generic/openssl@1.1.1','bom-ref':'openssl'}]}
r=m.api('admin','/api/sboms/upload','POST',data={'sbom_name':name,'project_id':pid,'product_id':product},files={'file':('round2-source.cdx.json',json.dumps(doc),'application/json')});assert r['status']==202
sid=r['data'].get('sbom_id') or r['data']['id'];(out/'source-document-fixture.json').write_text(json.dumps({'name':name,'project_id':pid,'product_id':product,'sbom_id':sid},indent=2))
document=json.loads(Path('tests/fixtures/vex/supplier-csaf.json').read_text());document['document']['tracking']['id']='UAT-R2-CSAF-'+str(uuid.uuid4())
cases=[]
for role,path,expected in [('admin','/api/sboms/'+sid+'/vex',200),('foreign','/api/sboms/'+sid+'/vex',404),('admin','/api/sboms/1/vex',422)]:
 r=m.api(role,path,'POST',{'document':document});cases.append({'role':role,'path':path,'expectedStatus':expected,'actual':r,'result':'PASS' if r['status']==expected else 'FAIL'});print('VEX native document',role,r['status'],cases[-1]['result'],flush=True)
(out/'api-vex-source-document-after.json').write_text(json.dumps(cases,indent=2))
