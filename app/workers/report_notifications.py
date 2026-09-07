"""Isolated report queue. Durable outbox is authority; Celery messages are hints."""

import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from celery import shared_task
from fastapi import HTTPException
from sqlalchemy import func, select

from ..core.context import minimal_background_context, tenant_scope
from ..db import SessionLocal
from ..models import ReportArtifact, ReportDelivery, ReportSubscription, Tenant
from ..schemas_reports import preferences_for
from ..services.audit_service import write_audit_log
from ..services.email_sender import build_email, get_email_sender
from ..services.report_access import authorize_preferences, recipient_context, scope_sboms
from ..services.report_composer import compose_report
from ..services.report_cycles import cadence_window, create_cycles, now_iso
from ..services.report_rendering import render_attachments, render_email
from ..services.report_storage import artifact_path, configuration_errors, store_artifact
from ..settings import get_settings

log = logging.getLogger(__name__)
RETRYABLE = {"SMTP_TIMEOUT", "SMTP_UNAVAILABLE", "SMTP_TEMPORARY_REJECTION", "REPORT_RENDER_FAILED"}


def _subscription(db, delivery):
    return db.scalar(
        select(ReportSubscription)
        .where(ReportSubscription.id == delivery.subscription_id, ReportSubscription.tenant_id == delivery.tenant_id)
        .execution_options(include_deleted=True)
    )


def _audit(db, delivery, context, code):
    if context is None:
        sub = _subscription(db, delivery)
        context = replace(minimal_background_context(delivery.tenant_id), user_id=sub.iam_user_id) if sub else None
    write_audit_log(
        db,
        context,
        "report.delivery.attempt",
        entity_type="report_delivery",
        entity_id=delivery.id,
        new_value={"status": delivery.status, "error_code": code, "attempt": delivery.attempt_count},
    )


def _finish(db, row, status, code, context=None):
    row.status, row.error_code, row.claimed_at = status, code, None
    row.attempts = [
        *row.attempts,
        {"at": now_iso(), "status": status, "error_code": code, "attempt": row.attempt_count},
    ]
    if status == "FAILED" and code in RETRYABLE and row.attempt_count < 3:
        row.status = "PENDING"
        row.next_attempt_at = (datetime.now(UTC) + timedelta(seconds=60 * 2**row.attempt_count)).isoformat()
        row.dispatch_started_at = None
    _audit(db, row, context, code)
    db.commit()
    return {"status": row.status, "error_code": code}


@shared_task(name="report_notifications.generate", queue="reports", ignore_result=True, acks_late=True)
def generate(delivery_id, tenant_id):
    settings = get_settings()
    with tenant_scope(minimal_background_context(tenant_id)):
        with SessionLocal() as db:
            row = db.scalar(
                select(ReportDelivery)
                .where(ReportDelivery.id == delivery_id, ReportDelivery.tenant_id == tenant_id)
                .with_for_update()
            )
            if not row or row.status != "PENDING" or row.claimed_at or row.dispatch_started_at:
                return {"status": "NOT_CLAIMED"}
            if row.next_attempt_at and row.next_attempt_at > now_iso():
                return {"status": "NOT_DUE"}
            payload = dict(row.payload)
            if payload.get("expected") and len(payload.get("completed", {})) < len(payload["expected"]):
                if datetime.fromisoformat(row.created_on) > datetime.now(UTC) - timedelta(
                    seconds=settings.report_generation_timeout_seconds
                ):
                    return {"status": "WAITING_FOR_RUNS"}
                payload["snapshot_at"] = now_iso()
                payload["incomplete_cycle"] = True
                row.payload = payload
            sub = _subscription(db, row)
            if not sub or not sub.enabled or not sub.is_active:
                return _finish(db, row, "SUPPRESSED", "SUBSCRIPTION_DISABLED")
            if (
                not settings.report_notifications_enabled
                or not settings.auth_enabled
                or not settings.email_delivery_enabled
            ):
                return _finish(db, row, "SKIPPED", "DELIVERY_DISABLED")
            if configuration_errors(settings):
                return _finish(db, row, "FAILED", "REPORT_CONFIGURATION_INVALID")
            try:
                context = recipient_context(db, sub)
                preferences = preferences_for(sub)
                authorize_preferences(db, preferences, context)
            except HTTPException as exc:
                return _finish(db, row, "SUPPRESSED", exc.detail["code"])
            row.claimed_at = now_iso()
            row.attempt_count += 1
            row.recipient_email = context.email
            start, end = row.cycle_start, row.cycle_end
            db.commit()
        try:
            with SessionLocal() as db:
                report = compose_report(
                    db,
                    preferences,
                    tenant_id=tenant_id,
                    cycle_start=start,
                    cycle_end=payload.get("snapshot_at", end),
                    sbom_ids=payload["sbom_ids"],
                )
                report["cycle_end"] = end
                if payload.get("incomplete_cycle"):
                    report["caveats"] = [
                        *report["caveats"],
                        "Some scheduled analyses did not finish before the reporting deadline. Last successful data is shown.",
                    ]
                    report["unchanged"] = False
                report["scheduled_outcomes"] = payload.get("completed", {})
            # Session is CLOSED before any PDF/Excel/MIME rendering.
            if preferences.suppress_when_unchanged and report["unchanged"]:
                with SessionLocal() as db:
                    return _finish(db, db.get(ReportDelivery, delivery_id), "SKIPPED", "UNCHANGED", context)
            attachments = render_attachments(report, preferences.formats)
            with SessionLocal() as db:
                row = db.get(ReportDelivery, delivery_id)
                artifacts = [store_artifact(db, row, a) for a in attachments]
                row.artifact_ids = [a.id for a in artifacts]
                row.sbom_count = report["included_sboms"]
                row.run_count = sum(s["A"]["run_id"] is not None for s in report["sboms"])
                base = settings.report_notification_base_url.rstrip("/")
                # Link to authenticated UI; browser download uses normal tenant-aware BFF.
                links = [
                    ("Open delivery and download retained reports", f"{base}/settings/notifications?delivery={row.id}")
                ]
                for sbom in report["sboms"]:
                    links.append((f"{sbom['name']} · latest state", f"{base}/sboms/{sbom['id']}"))
                    for part, comparison in sbom["comparisons"].items():
                        if comparison["status"] == "available":
                            links.append((f"{sbom['name']} · Part {part}", f"{base}/analysis/compare?run_a={comparison['run_a']['id']}&run_b={comparison['run_b']['id']}"))
                db.commit()
            selected, omitted = [], []
            for attachment in attachments:
                if attachment.filename.endswith(".json"):
                    continue
                if len(attachment.content) > settings.report_max_attachment_bytes:
                    omitted.append(
                        f"{attachment.filename} exceeds the attachment limit; download it from delivery history."
                    )
                else:
                    selected.append(attachment)
            while True:
                subject, text, html = render_email(report, links=links, omitted=omitted)
                message = build_email(
                    settings,
                    recipient_email=context.email,
                    subject=subject,
                    text_body=text,
                    html_body=html,
                    attachments=selected,
                )
                if len(message.as_bytes()) <= settings.report_max_message_bytes:
                    break
                if not selected:
                    raise ValueError("REPORT_MESSAGE_TOO_LARGE")
                attachment = selected.pop()
                omitted.append(
                    f"{attachment.filename} omitted to keep the MIME message within its size limit; download it from delivery history."
                )
        except Exception as exc:
            # Never log a raw report payload, uploaded text, recipient or SMTP exception.
            code = (
                str(exc)
                if isinstance(exc, ValueError)
                and str(exc) in {"REPORT_MESSAGE_TOO_LARGE", "REPORT_STORAGE_PERMISSIONS", "REPORT_STORAGE_UNSAFE"}
                else "REPORT_RENDER_FAILED"
            )
            log.warning("report.generate_failed delivery_id=%s code=%s", delivery_id, code)
            with SessionLocal() as db:
                return _finish(db, db.get(ReportDelivery, delivery_id), "FAILED", code, context)
        with SessionLocal() as db:
            # Serialize per tenant for durable hourly quota reservation.
            db.scalar(select(Tenant).where(Tenant.id == tenant_id).with_for_update())
            row = db.scalar(select(ReportDelivery).where(ReportDelivery.id == delivery_id).with_for_update())
            sub = _subscription(db, row)
            try:
                if not sub or not sub.enabled or not sub.is_active:
                    raise HTTPException(403, {"code": "SUBSCRIPTION_DISABLED"})
                current_context = recipient_context(db, sub)
                authorize_preferences(db, preferences_for(sub), current_context)
                if current_context.email != context.email or preferences_for(sub) != preferences:
                    raise HTTPException(403, {"code": "RECIPIENT_OR_PREFERENCES_CHANGED"})
                current_ids = {s.id for s in scope_sboms(db, preferences, tenant_id)}
                if not {s["id"] for s in report["sboms"]} <= current_ids:
                    raise HTTPException(403, {"code": "REPORT_SCOPE_CHANGED"})
            except HTTPException as exc:
                return _finish(db, row, "SUPPRESSED", exc.detail["code"], context)
            count = db.scalar(
                select(func.count(ReportDelivery.id)).where(
                    ReportDelivery.tenant_id == tenant_id,
                    ReportDelivery.dispatch_started_at >= (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
                )
            )
            if count >= settings.report_max_emails_per_tenant_per_hour:
                row.claimed_at = None
                row.next_attempt_at = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
                row.error_code = "TENANT_EMAIL_RATE_LIMIT"
                _audit(db, row, context, row.error_code)
                db.commit()
                return {"status": "DEFERRED"}
            row.dispatch_started_at = now_iso()
            _audit(db, row, context, "SMTP_DISPATCH_STARTED")
            db.commit()
        # A crash after this durable marker is ambiguous: never automatically resend.
        result = get_email_sender().send_email(message)
        with SessionLocal() as db:
            row = db.get(ReportDelivery, delivery_id)
            if result.status == "SENT":
                row.sent_at = now_iso()
                sub = _subscription(db, row)
                sub.last_delivered_at = max(sub.last_delivered_at or "", end)
            return _finish(db, row, str(result.status), result.error_code, context)


@shared_task(name="report_notifications.tick", queue="reports", ignore_result=True)
def tick():
    if not get_settings().report_notifications_enabled:
        return {"status": "DISABLED"}
    now = datetime.now(UTC)
    with SessionLocal() as db:
        subs = list(
            db.scalars(
                select(ReportSubscription).where(
                    ReportSubscription.enabled.is_(True), ReportSubscription.cadence != "ON_EVERY_RUN"
                )
            )
        )
        windows = {s.id: window for s in subs if (window := cadence_window(s, now))}
        create_cycles(db, [s for s in subs if s.id in windows], windows)
        db.commit()
    return dispatch_pending()


@shared_task(name="report_notifications.dispatch_pending", queue="reports", ignore_result=True)
def dispatch_pending():
    if not get_settings().report_notifications_enabled:
        return {"status": "DISABLED"}
    with SessionLocal() as db:
        targets = list(
            db.execute(
                select(ReportDelivery.id, ReportDelivery.tenant_id).where(ReportDelivery.status == "PENDING").limit(500)
            )
        )
    for identifier, tid in targets:
        with tenant_scope(minimal_background_context(tid)), SessionLocal() as db:
            row = db.scalar(select(ReportDelivery).where(ReportDelivery.id == identifier).with_for_update())
            expired = (
                datetime.now(UTC) - timedelta(seconds=get_settings().report_generation_timeout_seconds * 2)
            ).isoformat()
            if row.claimed_at and row.claimed_at < expired:
                if row.dispatch_started_at:
                    _finish(db, row, "FAILED", "SMTP_OUTCOME_UNKNOWN")
                    continue
                _finish(db, row, "FAILED", "REPORT_RENDER_FAILED")
            if row.status != "PENDING" or row.claimed_at or row.next_attempt_at and row.next_attempt_at > now_iso():
                continue
        try:
            generate.apply_async(
                args=[identifier, tid], queue="reports", time_limit=get_settings().report_generation_timeout_seconds
            )
        except Exception:
            log.warning("report.enqueue_deferred delivery_id=%s", identifier)
    return {"pending": len(targets)}


@shared_task(name="report_notifications.purge", queue="reports", ignore_result=True)
def purge():
    if configuration_errors():
        return {"status": "NOT_CONFIGURED"}
    with SessionLocal() as db:
        targets = list(
            db.execute(
                select(ReportArtifact.id, ReportArtifact.tenant_id)
                .where(ReportArtifact.expires_at < now_iso())
                .limit(1000)
            )
        )
    for identifier, tid in targets:
        with tenant_scope(minimal_background_context(tid)), SessionLocal() as db:
            row = db.get(ReportArtifact, identifier)
            artifact_path(row.storage_path).unlink(missing_ok=True)
            db.delete(row)
            db.commit()
    return {"removed": len(targets)}
