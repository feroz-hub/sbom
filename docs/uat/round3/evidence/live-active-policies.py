import importlib.util,json,uuid,hashlib
from pathlib import Path
spec=importlib.util.spec_from_file_location('m',Path(__file__).with_name('live-common.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
f=m.create_tenant();tid=f['tenant_id'];token=f['token'];file='active-policies.json'
def call(path,method='GET',body=None,**kw):return m.call(path,method,body,role='platform',token=token,tenant=tid,**kw)
def rec(id,steps,expected,r,ok):m.rec(id,steps,expected,m.payload(r) if hasattr(r,'status_code') else r,ok,'disposable tenant admin',file)
try:
 r=call('/api/projects','POST',{'project_name':'UAT R3 active-policy '+str(uuid.uuid4()),'project_status':1});assert r.status_code==201;pid=r.json()['id']
 r=call('/api/projects/'+pid+'/products','POST',{'name':'Policy fixture','status':'active'});assert r.status_code==201;product=r.json()['id']
 doc={'bomFormat':'CycloneDX','specVersion':'1.6','serialNumber':'urn:uuid:'+str(uuid.uuid4()),'version':1,'components':[{'type':'library','bom-ref':'lodash','name':'lodash','version':'4.17.20','purl':'pkg:npm/lodash@4.17.20'}],'dependencies':[]}
 r=call('/api/sboms/upload','POST',data={'sbom_name':'UAT R3 policy fixture','project_id':pid,'product_id':product},files={'file':('policy.cdx.json',json.dumps(doc),'application/json')});assert r.status_code==202;sid=r.json()['sbom_id']
 r=call('/api/sboms/'+sid+'/analyze/stream','POST',{'sources':['OSV']});events=[]
 for block in r.text.split('\n\n'):
  if 'event: complete' in block:
   events.extend(json.loads(line[6:]) for line in block.splitlines() if line.startswith('data: '))
 rec('R3-POLICY-ANALYSIS','Analyze task-owned lodash fixture against real configured OSV','200 completed analysis with real evidence',{'status':r.status_code,'complete':events},r.status_code==200 and bool(events))
 key=hashlib.sha256(b'purl:pkg:npm/lodash@4.17.20').hexdigest()
 rules={'trust':{'allowed_classifications':['LOW'],'allowed_lifecycle':['SUPPORTED']},'accepted-risk':{'max_actionable_severity':'MEDIUM','max_cvss_score':5.0},'scoring':{'weights':{'current_risk':.3,'lifecycle':.2,'vulnerability_trend':.15,'compatibility':.15,'maintenance':.08,'license':.05,'tenant_adoption':.05,'evidence_freshness':.02},'missing_data':'PENALIZE','history_window_months':24,'stale_after_days':90}}
 versions={}
 for kind,rule in rules.items():
  path='/api/component-advisor/policies/'+kind+'/versions';r=call(path,'POST',{'status':'ACTIVE','rules':rule,'reason':'Round 3 active rule acceptance','row_version':0});rec('R3-ACTIVE-'+kind,'Publish supported active '+kind+' rules in isolated tenant','201 integer policy version',r,r.status_code==201 and isinstance(r.json().get('version',{}).get('id'),int));assert r.status_code==201;versions[kind]=r.json()['version']['id']
  r=call(path,'POST',{'status':'ACTIVE','rules':rule,'reason':'Round 3 explicit stale control','row_version':0});rec('R3-ACTIVE-STALE-'+kind,'Repeat with obsolete row_version','409 no duplicate version',r,r.status_code==409)
  r=call(path);rec('R3-ACTIVE-HISTORY-'+kind,'Read actual nonempty policy history','200 exactly one active immutable rule version',r,r.status_code==200 and r.json()['total']==1 and r.json()['items'][0]['rules']==rule)
 r=call('/api/component-advisor/components/'+key+'/classification');body=r.json();rec('R3-ACTIVE-DOWNSTREAM','Read actual component classification under configured trust/risk rules','200 evaluation records exact active policy version identities',r,r.status_code==200 and body.get('accepted_risk',{}).get('policy_version_id')==versions['accepted-risk'] and body.get('trust',{}).get('policy_version_id')==versions['trust'])
 for kind in rules:
  path='/api/component-advisor/policies/'+kind+'/versions';r=call(path,'POST',{'status':'INHERIT','reason':'Round 3 scoped inheritance reset','row_version':1});rec('R3-POLICY-INHERIT-'+kind,'Append INHERIT version without modifying global defaults','201 own override relinquished',r,r.status_code==201 and r.json().get('tenant_override',{}).get('status')=='INHERIT')
finally:
 r=m.call('/api/platform/tenants/'+tid,'PATCH',{'status':'DISABLED'},role='platform');rec('R3-ACTIVE-POLICY-CLEANUP','Disable only newly owned policy tenant','200',r,r.status_code==200)
