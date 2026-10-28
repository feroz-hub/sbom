import importlib.util,json,time,uuid
from pathlib import Path
spec=importlib.util.spec_from_file_location('m',Path(__file__).with_name('live-common.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
name='UAT R3 '+str(time.time_ns());p=m.call('/api/projects','POST',{'project_name':name,'project_status':1});assert p.status_code==201;m.rec('R3-PROJECT-CREATE','Create owned project','201 UUID project',m.payload(p),True,file='scope-creation.json');pid=p.json()['id']
p=m.call('/api/projects/'+pid+'/products','POST',{'name':name+' Application','status':'active'});assert p.status_code==201;product=p.json()['id'];m.rec('R3-APPLICATION-CREATE','Create owned application','201 UUID application',m.payload(p),True,file='scope-creation.json')
f={'project_id':pid,'product_id':product,'name':name,'owned':'Round3','sbom_ids':[]};(m.OUT/'round3-scope.json').write_text(json.dumps(f,indent=2))
for number in [1,2]:
 doc=json.loads(Path('docs/uat/evidence/2026-10-19/uat.cdx.json').read_text());doc['serialNumber']='urn:uuid:'+str(uuid.uuid4());r=m.call('/api/sboms/upload','POST',data={'sbom_name':name+' SBOM '+str(number),'project_id':pid,'product_id':product},files={'file':('round3.cdx.json',json.dumps(doc).encode(),'application/json')});assert r.status_code==202,m.payload(r);sid=r.json().get('sbom_id') or r.json()['id'];f['sbom_ids'].append(sid);(m.OUT/'round3-scope.json').write_text(json.dumps(f,indent=2));m.rec('R3-SBOM-UPLOAD-'+str(number),'Upload valid fixture with project/application UUIDs','202 public UUID',m.payload(r),True,file='scope-creation.json')
for expr in ['not a cron','*/5 * * * *']:
 r=m.call('/api/products/'+product+'/schedule','POST',{'cadence':'CUSTOM','cron_expression':expr,'enabled':False});m.rec('R3-CRON-BASELINE-'+str(len(expr)),'Submit disabled custom schedule before dependency correction','Reproduce missing supported dependency; no cron syntax acceptance',m.payload(r),r.status_code==422 and 'croniter' in r.text,file='scope-creation.json')
