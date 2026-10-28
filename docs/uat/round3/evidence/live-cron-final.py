import importlib.util,json
from pathlib import Path
from datetime import datetime,timezone
spec=importlib.util.spec_from_file_location('m',Path(__file__).with_name('live-common.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);f=json.loads((m.OUT/'round3-scope.json').read_text());pid=f['product_id'];path='/api/products/'+pid+'/schedule';file='cron-accepted.json'
assert m.call('/api/projects/'+f['project_id']).json()['project_name']==f['name']
def rec(id,steps,expected,r,ok,role='admin'):m.rec(id,steps,expected,m.payload(r),ok,role,file)
try:
 for i,extra in enumerate([{'cron_expression':'not a cron'},{'cron_expression':'* * * * * *'},{'cron_expression':'* * * * * * 2099'},{'cron_expression':'0 0 31 2 *'},{'cron_expression':'0 0 * * *','timezone':'Mars/Base'}]):
  r=m.call(path,'POST',{'cadence':'CUSTOM','enabled':False,**extra});rec('R3-CRON-INVALID-'+str(i),'Submit disabled malformed/unsupported/impossible cron or invalid IANA timezone','422 validation, no missing-dependency error',r,r.status_code==422 and 'pip install' not in r.text)
 r=m.call(path,'POST',{'cadence':'CUSTOM','cron_expression':'0 0 * * *','timezone':'Asia/Kolkata','enabled':False});rec('UAT-SCHEDULE-CUSTOM','Store disabled supported five-field schedule','201 stored disabled with display timezone',r,r.status_code==201 and r.json()['enabled'] is False and r.json()['timezone']=='Asia/Kolkata');assert r.status_code==201;sid=r.json()['id']
 r=m.call('/api/schedules/'+str(sid)+'/resume','POST');data=r.json();next_run=data.get('next_run_at');rec('R3-CRON-NEXT-RUN','Resume only owned daily-midnight schedule, then immediately pause before due','200 strictly future midnight UTC despite display timezone',r,r.status_code==200 and next_run is not None and datetime.fromisoformat(next_run)>datetime.now(timezone.utc) and datetime.fromisoformat(next_run).hour==0)
 r=m.call('/api/schedules/'+str(sid)+'/pause','POST');rec('R3-CRON-PAUSE','Pause owned schedule immediately after next-run check','200 disabled',r,r.status_code==200 and r.json()['enabled'] is False)
 for role,code in [('viewer',403),('foreign',404)]:
  r=m.call(path,'POST',{'cadence':'DAILY','enabled':False},role=role);rec('R3-SCHEDULE-DENY-'+role,'Direct lower-role/foreign mutation of known product UUID',str(code),r,r.status_code==code,role)
 r=m.call(path,'POST',{'cadence':'MONTHLY','day_of_month':1,'hour_utc':2,'timezone':'Asia/Kolkata','enabled':False});rec('R3-SCHEDULE-MONTHLY','Store existing Monthly preset on owned scope','201 cadence MONTHLY unchanged',r,r.status_code==201 and r.json()['cadence']=='MONTHLY');sid=r.json()['id']
 r=m.call('/api/schedules/'+str(sid)+'/resume','POST');rec('R3-MONTHLY-NEXT-RUN','Compute Monthly preset then immediately pause','Future first day 02:00 UTC',r,r.status_code==200 and datetime.fromisoformat(r.json()['next_run_at']).day==1 and datetime.fromisoformat(r.json()['next_run_at']).hour==2)
finally:
 r=m.call(path,'DELETE');rec('R3-SCHEDULE-CLEANUP','Remove only task-owned product schedule after bounded checks','200 soft-deleted',r,r.status_code==200 and r.json().get('status')=='deleted')
