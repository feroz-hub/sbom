import importlib.util,json,uuid,hashlib
from pathlib import Path
spec=importlib.util.spec_from_file_location('m',Path(__file__).with_name('live-common.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
file='repair-after.json'
def rec(id,steps,expected,r,ok,role='admin'):m.rec(id,steps,expected,m.payload(r) if hasattr(r,'status_code') else r,ok,role,file)
for action in ['reject','approve']:
 doc={'bomFormat':'CycloneDX','specVersion':'1.6','serialNumber':'urn:uuid:'+str(uuid.uuid4()),'version':1,'components':[{'type':'LIBRARY','bom-ref':'a','name':'round3-repair','version':'1.0'}],'dependencies':[]}
 raw=json.dumps(doc).encode();sourcehash=hashlib.sha256(raw).hexdigest();(m.OUT/('repair-after-original-'+action+'.json')).write_bytes(raw)
 r=m.call('/api/sboms/upload','POST',data={'sbom_name':'UAT R3 repair '+action+' '+str(uuid.uuid4())},files={'file':('repair-'+action+'.cdx.json',raw,'application/json')})
 rec('R3-REPAIR-QUARANTINE-'+action,'Upload semantic-invalid synthetic SBOM','422; quarantine session created, no accepted SBOM',r,r.status_code==422 and bool(r.json().get('detail',{}).get('session_id')));assert r.status_code==422
 sid=r.json()['detail']['session_id'];base='/api/sbom-validation-sessions/'+sid
 r=m.call(base+'/repair/analyze','POST');rec('R3-REPAIR-PROPOSAL-'+action,'Analyze quarantine','200 deterministic auto-fix proposal',r,r.status_code==200 and r.json().get('auto_fixable',0)>=1)
 r=m.call(base+'/repair','POST');rec('R3-REPAIR-JOB-'+action,'Generate bounded candidate','200 REPAIRED; not implicitly imported',r,r.status_code==200 and r.json().get('status')=='REPAIRED');assert r.status_code==200
 job=r.json();jid=job['repair_job_id'];r2=m.call(base+'/repair','POST');rec('R3-REPAIR-RETRY-'+action,'Repeat repair input','Same repair_job_id; no duplicate job',r2,r2.status_code==200 and r2.json()['repair_job_id']==jid)
 candidate=m.call(base+'/repair/'+jid+'/download');changes=m.call(base+'/repair/'+jid+'/changes');r=m.call(base)
 rec('R3-REPAIR-REVIEW-'+action,'Download candidate and changes; inspect session import state','Candidate differs, diff nonempty, no imported_sbom_id before approval',{'candidateStatus':candidate.status_code,'candidateSha256':hashlib.sha256(candidate.content).hexdigest(),'changes':m.payload(changes),'session':m.payload(r)},candidate.status_code==200 and candidate.content!=raw and changes.status_code==200 and bool(changes.json()['changes']) and r.json()['imported_sbom_id'] is None)
 (m.OUT/('repair-after-candidate-'+action+'.json')).write_bytes(candidate.content)
 r=m.call(base+'/repair/'+jid+'/approve','POST',role='viewer');rec('R3-REPAIR-VIEWER-'+action,'Viewer direct approval attempt','403',r,r.status_code==403,'viewer')
 r=m.call(base+'/repair/'+jid+'/approve','POST',role='foreign');rec('R3-REPAIR-FOREIGN-'+action,'Foreign administrator approval attempt','404',r,r.status_code==404,'foreign')
 if action=='reject':
  r=m.call(base+'/repair/'+jid+'/reject','POST',role='analyst');rec('R3-REPAIR-REJECT','Analyst explicitly rejects own-tenant candidate','200 REJECTED',r,r.status_code==200 and r.json().get('status')=='REJECTED','analyst')
  r=m.call(base+'/repair/'+jid+'/approve','POST');rec('R3-REPAIR-REJECTED-NOT-APPROVABLE','Admin attempts approval of rejected candidate','409',r,r.status_code==409)
 else:
  wrong=m.call(base+'/repair/'+jid+'/approve','POST',{'candidate_sha256':'0'*64});rec('R3-REPAIR-HASH-MISMATCH','Approve with incorrect review hash','409 no import',wrong,wrong.status_code==409)
  r=m.call(base+'/repair/'+jid+'/approve','POST',{'candidate_sha256':hashlib.sha256(candidate.content).hexdigest()});rec('R3-REPAIR-APPROVE','Explicit Admin approval with exact candidate hash','200 imported repaired SBOM',r,r.status_code==200 and bool(r.json().get('imported_sbom_id')));assert r.status_code==200
  imported=r.json()['imported_sbom_id'];again=m.call(base+'/repair/'+jid+'/approve','POST');rec('R3-REPAIR-APPROVAL-RETRY','Repeat same approved job','200 same imported identity; no duplicate import',again,again.status_code==200 and again.json()['imported_sbom_id']==imported)
  r=m.call('/api/sboms/'+str(imported));rec('R3-REPAIR-IMPORTED-READ','Read repaired public identity and validation lineage','200',r,r.status_code==200)
 r=m.call(base+'/download-original');history=m.call(base+'/history');rec('R3-REPAIR-PRESERVATION-'+action,'Download original after terminal decision and read history','Original byte hash unchanged; approval/rejection audit retained',{'status':r.status_code,'originalSha256':sourcehash,'afterSha256':hashlib.sha256(r.content).hexdigest(),'history':m.payload(history)},r.status_code==200 and hashlib.sha256(r.content).hexdigest()==sourcehash and history.status_code==200)
