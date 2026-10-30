"""Actual bounded Beat/worker/report/Mailpit flow; own tenant only, explicit test clock/fault."""
import importlib.util,json,uuid,os,subprocess,time,signal,hashlib,io,zipfile
from datetime import datetime,timezone,timedelta
from pathlib import Path
spec=importlib.util.spec_from_file_location('m',Path(__file__).with_name('live-common.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
from scripts.dev import GreenfieldStack
ROOT = GreenfieldStack.ROOT
STATE = GreenfieldStack.STATE
settings = GreenfieldStack.settings
verify_resources = GreenfieldStack.verify_resources
from sqlalchemy import create_engine,text
verify_resources();f=m.create_tenant();tid=f['tenant_id'];token=f['token'];sub=None;process=None;file='scheduled-report.json'
def call(path,method='GET',body=None,**kw):return m.call(path,method,body,token=token,tenant=tid,role='platform',**kw)
def rec(id,steps,expected,r,ok):m.rec(id,steps,expected,m.payload(r) if hasattr(r,'status_code') else r,ok,'disposable tenant admin',file)
try:
 p=call('/api/projects','POST',{'project_name':'UAT R3 scheduled report '+str(uuid.uuid4()),'project_status':1});assert p.status_code==201;pid=p.json()['id']
 p=call('/api/projects/'+pid+'/products','POST',{'name':'Scheduled report fixture','status':'active'});assert p.status_code==201;product=p.json()['id']
 doc=json.loads((ROOT/'docs/uat/evidence/2026-10-19/uat.cdx.json').read_text());doc['serialNumber']='urn:uuid:'+str(uuid.uuid4())
 p=call('/api/sboms/upload','POST',data={'sbom_name':'UAT R3 scheduled report','project_id':pid,'product_id':product},files={'file':('report.cdx.json',json.dumps(doc),'application/json')});assert p.status_code==202;sid=p.json()['sbom_id']
 r=call('/api/sboms/'+sid+'/analyze/stream','POST',{'sources':['OSV']});rec('R3-REPORT-ANALYSIS','Analyze new owned scope with real OSV','200 terminal completion',{'status':r.status_code,'terminalComplete':'event: complete' in r.text},r.status_code==200 and 'event: complete' in r.text)
 r=call('/api/report-subscriptions','POST',{'scope':'SBOM','sbom_id':sid,'cadence':'DAILY','parts':['A','B'],'formats':['PDF','XLSX'],'timezone':'UTC','enabled':True});rec('R3-REPORT-SCHEDULE-CREATE','Create bounded owned enabled recurring daily report','201',r,r.status_code==201);assert r.status_code==201;sub=r.json()['id']
 engine=create_engine(settings()['DATABASE_URL'],hide_parameters=True)
 with engine.connect() as c:
  c.exec_driver_sql('SET TRANSACTION READ ONLY');internal=c.execute(text('SELECT id FROM tenants WHERE public_id=:id AND name LIKE :name'),{'id':tid,'name':'UAT R3 %'}).scalar_one()
 engine.dispose()
 private=STATE/'round3-report-control.json';private.write_text(json.dumps({'tenant_id':internal,'tenant_uuid':tid,'subscription_id':sub,'deadline':(datetime.now(timezone.utc)+timedelta(seconds=225)).isoformat()}));os.chmod(private,0o600)
 env=settings();env.update(R3_REPORT_CONTROL_FILE=str(private),PYTHONPATH=str(ROOT)+os.pathsep+str(m.OUT),PYTHONDONTWRITEBYTECODE='1');logpath=STATE/'round3-report-worker.log'
 with logpath.open('ab') as log:process=subprocess.Popen([str(ROOT/'.venv/bin/python'),'-B','-m','celery','-A','round3_report_beat:celery_app','worker','--pool=solo','--concurrency=1','--queues=round3_reports_control,round3_reports_generation','--hostname=round3reports@%h','--beat','--schedule='+str(STATE/'round3-report-beat'),'--loglevel=INFO'],cwd=STATE,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 (m.OUT/'scheduled-report-fixture.json').write_text(json.dumps({'tenant_uuid':tid,'tenant_internal_id':internal,'user_id':f['user_id'],'email':f['email'],'subscription_id':sub,'worker_pid':process.pid,'project_id':pid,'product_id':product,'sbom_id':sid,'controlledClock':'Only tenant-local tick receives tomorrow UTC; generator/retry clock remains real','controlledFault':'First owned worker send returns SMTP_UNAVAILABLE; following attempt uses real Mailpit','boundedLeaseSeconds':225},indent=2))
 found=None;observed_retry=False;start=time.monotonic()
 while time.monotonic()-start<205:
  if process.poll() is not None:raise RuntimeError('Owned Beat/worker exited; inspect private log')
  r=call('/api/report-deliveries?subscription_id='+str(sub));assert r.status_code==200;rows=r.json();rows=rows if isinstance(rows,list) else rows.get('items',[])
  if rows:
   found=rows[0]
   if found.get('error_code')=='SMTP_UNAVAILABLE' and not observed_retry:
    observed_retry=True;rec('R3-REPORT-RETRY-PENDING','Observe controlled first-send failure and durable delayed retry','PENDING with SMTP_UNAVAILABLE; no email yet',found,found.get('status')=='PENDING')
   if found['status']=='SENT':break
   if found['status'] in ['FAILED','SUPPRESSED','SKIPPED']:break
  time.sleep(1)
 rec('UAT-REPORT-SCHEDULED-TRIGGER','Actual owned Beat dispatch → worker → controlled first failure → real Mailpit retry','SENT after two attempts and observed retry',{'delivery':found,'elapsedSeconds':round(time.monotonic()-start,2),'controlledTickClock':True,'controlledFirstSendFailure':True},found is not None and found.get('status')=='SENT' and found.get('attempt_count')==2 and observed_retry)
 assert found and found['status']=='SENT'
 # Repeated tick and delayed duplicate task messages must not resend a completed cycle.
 time.sleep(6);again=call('/api/report-deliveries?subscription_id='+str(sub)).json();again=again if isinstance(again,list) else again.get('items',[]);rec('R3-REPORT-CYCLE-DEDUP','Allow another Beat tick after completed cycle','Exactly one cycle and two attempts, one successful SMTP delivery',{'deliveries':again},len(again)==1 and again[0]['attempt_count']==2)
 messages=__import__('requests').get('http://127.0.0.1:8026/api/v1/messages',timeout=10).json()['messages'];recipient_messages=[x for x in messages if any(v['Address']==f['email'] for v in x.get('To',[])) and 'report' in x.get('Subject','').lower()];rec('R3-REPORT-MAILPIT','Read Mailpit metadata for unique owned recipient','Exactly one report message',{'matchingReportMessages':len(recipient_messages),'subjects':[x['Subject'] for x in recipient_messages]},len(recipient_messages)==1)
 for artifact in found.get('artifacts',[]):
  r=call('/api/report-deliveries/'+str(found['id'])+'/artifacts/'+str(artifact['id']));content=r.content;kind='PDF' if content.startswith(b'%PDF') else 'XLSX' if content.startswith(b'PK') else 'JSON';ok=r.status_code==200
  if kind=='XLSX':ok=ok and '[Content_Types].xml' in zipfile.ZipFile(io.BytesIO(content)).namelist()
  if kind=='JSON':json.loads(content)
  name='scheduled-artifact-'+str(artifact['id'])+{'PDF':'.pdf','XLSX':'.xlsx','JSON':'.json'}[kind];(m.OUT/name).write_bytes(content);rec('R3-REPORT-ARTIFACT-'+kind,'Download actual generated retained report','200 valid '+kind+' artifact',{'status':r.status_code,'format':kind,'bytes':len(content),'sha256':hashlib.sha256(content).hexdigest(),'file':name},ok)
  denied=m.call('/api/report-deliveries/'+str(found['id'])+'/artifacts/'+str(artifact['id']),role='foreign');rec('R3-REPORT-ARTIFACT-FOREIGN-'+kind,'Foreign tenant requests known owned artifact','404',denied,denied.status_code==404)
 r=call('/api/report-subscriptions/'+str(sub),'PATCH',{'enabled':False});rec('R3-REPORT-PAUSE','Pause owned schedule before stopping control worker','200 disabled',r,r.status_code==200 and not r.json()['enabled'])
finally:
 if process and process.poll() is None:
  assert os.getpgid(process.pid)==process.pid;os.killpg(process.pid,signal.SIGTERM)
  try:process.wait(timeout=20)
  except subprocess.TimeoutExpired:raise RuntimeError('Owned report worker still stopping; do not start replacement')
 if sub is not None:call('/api/report-subscriptions/'+str(sub),'DELETE')
 r=m.call('/api/platform/tenants/'+tid,'PATCH',{'status':'DISABLED'},role='platform');rec('R3-REPORT-CLEANUP','Stop only owned worker/Beat, remove owned subscription, disable owned tenant','200 cleanup',r,r.status_code==200)
