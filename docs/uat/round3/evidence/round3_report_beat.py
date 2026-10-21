"""Bounded task-owned reporting test. No global tenant discovery or other periodic jobs."""
import json,os
from pathlib import Path
from datetime import datetime,timezone,timedelta
from sqlalchemy import select
from app.workers.celery_app import celery_app
from app.workers import report_notifications as reports
from app.services.maintenance_scope import maintenance_tenant
from app.services.email_sender import EmailDeliveryResult,EmailDeliveryStatus
from app.db import SessionLocal
from app.models import Tenant

config=json.loads(Path(os.environ['R3_REPORT_CONTROL_FILE']).read_text())
OWNER=config['tenant_id'];SUB=config['subscription_id'];DEADLINE=datetime.fromisoformat(config['deadline'])
QUEUE='round3_reports_generation'
celery_app.conf.beat_schedule={'round3-owned-report-window':{'task':'round3.reports.tick_owned','schedule':5.0,'options':{'queue':'round3_reports_control'}}}
real_apply=reports.generate.apply_async

def owned_apply(*args,**kwargs):
    values=kwargs.get('args',args[0] if args else ())
    if len(values)!=2 or values[1]!=OWNER:raise RuntimeError('Refuse non-owned reporting task')
    kwargs['queue']=QUEUE
    return real_apply(*args,**kwargs)
reports.generate.apply_async=owned_apply
real_sender=reports.get_email_sender
failed=False
class ControlledFirstFailure:
    def send_email(self,message):
        global failed
        if not failed:
            failed=True
            return EmailDeliveryResult(EmailDeliveryStatus.FAILED,'SMTP_UNAVAILABLE')
        return real_sender().send_email(message)
reports.get_email_sender=lambda:ControlledFirstFailure()
real_datetime=reports.datetime
class DueClock(datetime):
    @classmethod
    def now(cls,tz=None):return real_datetime.now(tz)+timedelta(days=1)

@celery_app.task(name='round3.reports.tick_owned',ignore_result=True)
def tick_owned():
    if real_datetime.now(timezone.utc)>DEADLINE:return {'status':'LEASE_EXPIRED'}
    with SessionLocal() as db:
        owner=db.scalar(select(Tenant).where(Tenant.id==OWNER))
        if not owner or str(owner.public_id)!=config['tenant_uuid'] or not owner.name.startswith('UAT R3 '):raise RuntimeError('Owned tenant identity mismatch')
    with maintenance_tenant(OWNER,'round3.bounded_report_tick'):
        try:
            reports.datetime=DueClock
            reports._tick_for_tenant()
        finally:
            reports.datetime=real_datetime
        return reports._dispatch_for_tenant()
