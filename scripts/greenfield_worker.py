"""Greenfield worker with only local security-mail periodic dispatch.

Do not schedule the application-wide provider, mirror or analysis jobs merely
by starting the development stack.
"""

from app.workers.celery_app import celery_app

celery_app.conf.beat_schedule = {
    "security-mail-outbox": {"task": "security_mail.dispatch", "schedule": 10.0},
}
