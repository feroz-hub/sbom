"""No secrets, recipients or tokens in task arguments or results."""

from celery import shared_task

from ..services.security_mail_outbox import dispatch


@shared_task(name="security_mail.dispatch", ignore_result=True)
def dispatch_pending():
    from ..services.native_operations import heartbeat, validate_configuration
    from ..settings import get_settings

    if not get_settings().native_security_outbox_enabled:
        return
    validate_configuration()
    dispatch()
    heartbeat()
