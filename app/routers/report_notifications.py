"""Authenticated, tenant-scoped reports. No arbitrary recipients or public downloads."""

import hashlib
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Body, Depends, Query, Response
from fastapi.responses import FileResponse
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import require_permission
from ..db import get_db
from ..models import (
    AuditLog,
    IAMUser,
    Product,
    Projects,
    ReportArtifact,
    ReportDelivery,
    ReportSubscription,
    SBOMSource,
)
from ..schemas_reports import ReportPreferences, preferences_for
from ..services.audit_service import write_audit_log
from ..services.report_access import (
    authorize_preferences,
    is_report_admin,
    recipient_context,
    report_error,
    scope_sboms,
)
from ..services.report_composer import compose_report
from ..services.report_cycles import create_delivery, now_iso
from ..services.report_rendering import render_email
from ..services.report_storage import artifact_path, configuration_errors
from ..settings import get_settings

router = APIRouter(prefix="/api", tags=["report-notifications"])
reader = require_permission("sbom:read")


def subscription_out(row):
    return {
        **preferences_for(row).model_dump(),
        "id": row.id,
        "tenant_id": row.tenant_id,
        "iam_user_id": row.iam_user_id,
        "created_on": row.created_on,
        "modified_on": row.modified_on,
        "last_delivered_at": row.last_delivered_at,
    }


def _subscription(db, identifier, context, *, owner_only=False):
    row = db.scalar(
        select(ReportSubscription).where(
            ReportSubscription.id == identifier, ReportSubscription.tenant_id == context.tenant_id
        )
    )
    if row is None or row.iam_user_id != context.user_id and (owner_only or not is_report_admin(context)):
        raise report_error("REPORT_SUBSCRIPTION_NOT_FOUND", "Subscription not found.", 404)
    return row


def _audit(db, context, action, identifier=None, value=None):
    write_audit_log(db, context, action, entity_type="report_subscription", entity_id=identifier, new_value=value)


def _rate_limit(db, context, action, maximum):
    user = db.scalar(select(IAMUser).where(IAMUser.id == context.user_id).with_for_update())
    if not user:
        raise report_error("REPORT_ACCOUNT_REQUIRED", "Reports require a verified IAM account.")
    count = db.scalar(
        select(func.count(AuditLog.id)).where(
            AuditLog.tenant_id == context.tenant_id,
            AuditLog.user_ref_id == context.user_id,
            AuditLog.action == action,
            AuditLog.created_at >= (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
        )
    )
    if count >= maximum:
        raise report_error("REPORT_RATE_LIMIT", "Report request limit reached. Try again in an hour.", 429)
    _audit(db, context, action)
    db.commit()


@router.get("/report-notifications/config")
def configuration(context: CurrentContext = Depends(reader)):
    settings = get_settings()
    return {
        "enabled": settings.report_notifications_enabled,
        "delivery_enabled": settings.email_delivery_enabled and settings.auth_enabled,
        "diagnostics": configuration_errors(settings),
        "max_sboms": settings.report_max_sboms_per_digest,
        "retention_days": settings.report_retention_days,
        "is_tenant_admin": is_report_admin(context),
        "tenant_scope_allowed": bool({"TENANT_ADMIN", "SECURITY_ANALYST"} & context.roles),
        "recipient_email": context.email,
        "tenant_id": context.tenant_id,
    }


@router.get("/report-subscriptions")
def list_subscriptions(context: CurrentContext = Depends(reader), db: Session = Depends(get_db)):
    return [
        subscription_out(row)
        for row in db.scalars(
            select(ReportSubscription)
            .where(ReportSubscription.tenant_id == context.tenant_id, ReportSubscription.iam_user_id == context.user_id)
            .order_by(ReportSubscription.id)
        )
    ]


@router.get("/report-notifications/targets")
def targets(
    scope: str,
    search: str = Query("", max_length=100),
    context: CurrentContext = Depends(reader),
    db: Session = Depends(get_db),
):
    model, label = {
        "PROJECT": (Projects, Projects.project_name),
        "PRODUCT": (Product, Product.name),
        "SBOM": (SBOMSource, SBOMSource.sbom_name),
    }.get(scope, (None, None))
    if model is None:
        return []
    return [
        {"id": identifier, "label": title}
        for identifier, title in db.execute(
            select(model.id, label)
            .where(model.tenant_id == context.tenant_id, label.ilike(f"%{search}%"))
            .order_by(label, model.id)
            .limit(200)
        )
    ]


@router.get("/tenants/{tenant_id}/report-subscriptions")
def tenant_subscriptions(tenant_id: int, context: CurrentContext = Depends(reader), db: Session = Depends(get_db)):
    if context.tenant_id != tenant_id or not is_report_admin(context):
        raise report_error("REPORT_ADMIN_REQUIRED", "Tenant administrator access is required.")
    return [
        subscription_out(row)
        for row in db.scalars(
            select(ReportSubscription).where(ReportSubscription.tenant_id == tenant_id).order_by(ReportSubscription.id)
        )
    ]


@router.post("/report-subscriptions", status_code=201)
def create_subscription(
    payload: ReportPreferences, context: CurrentContext = Depends(reader), db: Session = Depends(get_db)
):
    authorize_preferences(db, payload, context)
    row = ReportSubscription(
        **payload.database_values(),
        tenant_id=context.tenant_id,
        iam_user_id=context.user_id,
        created_on=now_iso(),
        created_by=context.actor_label(),
    )
    recipient = recipient_context(db, row)
    authorize_preferences(db, payload, recipient)
    db.add(row)
    try:
        db.flush()
        _audit(db, context, "report.subscription.create", row.id, payload.model_dump())
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise report_error(
            "REPORT_SUBSCRIPTION_EXISTS", "You already have an active subscription for this scope.", 409
        ) from exc
    return subscription_out(row)


@router.patch("/report-subscriptions/{identifier}")
def update_subscription(
    identifier: int, payload: dict = Body(...), context: CurrentContext = Depends(reader), db: Session = Depends(get_db)
):
    row = _subscription(db, identifier, context)
    if row.iam_user_id != context.user_id and payload != {"enabled": False}:
        raise report_error(
            "REPORT_OWNER_REQUIRED", "Administrators may disable another user's subscription, not change its content."
        )
    try:
        preferences = ReportPreferences.model_validate({**preferences_for(row).model_dump(), **payload})
    except ValidationError as exc:
        raise report_error(
            "REPORT_INVALID_PREFERENCES", "; ".join(error["msg"] for error in exc.errors(include_input=False)), 422
        ) from exc
    if preferences.enabled:
        authorize_preferences(db, preferences, recipient_context(db, row))
    for key, value in preferences.database_values().items():
        setattr(row, key, value)
    row.modified_on, row.modified_by = now_iso(), context.actor_label()
    _audit(db, context, "report.subscription.update", row.id, preferences.model_dump())
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise report_error(
            "REPORT_SUBSCRIPTION_EXISTS", "An active subscription already exists for this scope.", 409
        ) from exc
    return subscription_out(row)


@router.delete("/report-subscriptions/{identifier}", status_code=204)
def delete_subscription(identifier: int, context: CurrentContext = Depends(reader), db: Session = Depends(get_db)):
    row = _subscription(db, identifier, context)
    row.is_active, row.enabled = False, False
    row.deactivated_at, row.deactivated_by = datetime.now(UTC), context.actor_label()
    _audit(db, context, "report.subscription.delete", row.id)
    db.commit()
    return Response(status_code=204)


def _preview(db, preferences, context):
    authorize_preferences(db, preferences, context)
    _rate_limit(db, context, "report.preview", 10)
    end = now_iso()
    report = compose_report(db, preferences, tenant_id=context.tenant_id, cycle_start=end, cycle_end=end)
    db.close()
    subject, text, html = render_email(report)
    return {"subject": subject, "text_body": text, "html_body": html, "report": report}


@router.post("/report-subscriptions/preview")
def preview_unsaved(
    payload: ReportPreferences, context: CurrentContext = Depends(reader), db: Session = Depends(get_db)
):
    return _preview(db, payload, context)


@router.post("/report-subscriptions/{identifier}/preview")
def preview_saved(identifier: int, context: CurrentContext = Depends(reader), db: Session = Depends(get_db)):
    return _preview(db, preferences_for(_subscription(db, identifier, context, owner_only=True)), context)


@router.post("/report-subscriptions/{identifier}/send-now", status_code=202)
def send_now(identifier: int, context: CurrentContext = Depends(reader), db: Session = Depends(get_db)):
    sub = _subscription(db, identifier, context, owner_only=True)
    if not sub.enabled:
        raise report_error("REPORT_SUBSCRIPTION_PAUSED", "Resume this subscription before sending.", 409)
    authorize_preferences(db, preferences_for(sub), recipient_context(db, sub))
    _rate_limit(db, context, "report.send_now", 5)
    end = now_iso()
    row = create_delivery(
        db,
        sub,
        start=sub.last_delivered_at or sub.created_on,
        end=end,
        sbom_ids=[s.id for s in scope_sboms(db, preferences_for(sub), context.tenant_id)],
        manual=True,
    )
    db.commit()
    from ..workers.report_notifications import generate

    try:
        generate.apply_async(
            args=[row.id, row.tenant_id], queue="reports", time_limit=get_settings().report_generation_timeout_seconds
        )
    except Exception:
        # Retain the outbox; the periodic dispatcher retries enqueue, not SMTP.
        return {"id": row.id, "status": "PENDING", "message": "Saved; waiting for the report worker/broker."}
    return {"id": row.id, "status": "PENDING"}


@router.get("/report-deliveries")
def deliveries(
    all_tenant: bool = False,
    subscription_id: int | None = None,
    delivery_id: int | None = Query(None, ge=1),
    status: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    context: CurrentContext = Depends(reader),
    db: Session = Depends(get_db),
):
    if all_tenant and not is_report_admin(context):
        raise report_error("REPORT_ADMIN_REQUIRED", "Tenant administrator access is required.")
    query = (
        select(ReportDelivery)
        .join(ReportSubscription, ReportSubscription.id == ReportDelivery.subscription_id)
        .where(ReportDelivery.tenant_id == context.tenant_id, ReportSubscription.tenant_id == context.tenant_id)
        .execution_options(include_deleted=True)
    )
    if not all_tenant:
        query = query.where(ReportSubscription.iam_user_id == context.user_id)
    if subscription_id:
        query = query.where(ReportDelivery.subscription_id == subscription_id)
    if delivery_id:
        query = query.where(ReportDelivery.id == delivery_id)
    if status:
        query = query.where(ReportDelivery.status == status)
    result = []
    for row in db.scalars(query.order_by(ReportDelivery.id.desc()).offset(offset).limit(limit)):
        artifacts = list(
            db.scalars(
                select(ReportArtifact).where(
                    ReportArtifact.delivery_id == row.id, ReportArtifact.tenant_id == context.tenant_id
                )
            )
        )
        result.append(
            {
                key: getattr(row, key)
                for key in (
                    "id",
                    "subscription_id",
                    "cycle_start",
                    "cycle_end",
                    "status",
                    "error_code",
                    "attempt_count",
                    "sbom_count",
                    "run_count",
                    "sent_at",
                    "created_on",
                )
            }
            | {
                "artifacts": [
                    {
                        "id": a.id,
                        "filename": a.filename,
                        "kind": a.kind,
                        "size_bytes": a.size_bytes,
                        "expires_at": a.expires_at,
                    }
                    for a in artifacts
                ]
            }
        )
    return result


@router.get("/report-deliveries/{delivery_id}/artifacts/{artifact_id}")
def download(
    delivery_id: int, artifact_id: int, context: CurrentContext = Depends(reader), db: Session = Depends(get_db)
):
    row = db.scalar(
        select(ReportDelivery).where(ReportDelivery.id == delivery_id, ReportDelivery.tenant_id == context.tenant_id)
    )
    sub = (
        db.scalar(
            select(ReportSubscription)
            .where(ReportSubscription.id == row.subscription_id, ReportSubscription.tenant_id == context.tenant_id)
            .execution_options(include_deleted=True)
        )
        if row
        else None
    )
    if not sub or sub.iam_user_id != context.user_id and not is_report_admin(context):
        raise report_error("REPORT_ARTIFACT_NOT_FOUND", "Artifact not found.", 404)
    authorize_preferences(db, preferences_for(sub), context)
    if not is_report_admin(context):
        authorize_preferences(db, preferences_for(sub), recipient_context(db, sub))
    current_ids = {s.id for s in scope_sboms(db, preferences_for(sub), context.tenant_id)}
    if not set(row.payload.get("sbom_ids", [])) <= current_ids:
        raise report_error("REPORT_SCOPE_CHANGED", "Report scope has changed. Generate a new report.")
    artifact = db.scalar(
        select(ReportArtifact).where(
            ReportArtifact.id == artifact_id,
            ReportArtifact.delivery_id == delivery_id,
            ReportArtifact.tenant_id == context.tenant_id,
        )
    )
    if not artifact or artifact.expires_at <= now_iso():
        raise report_error("REPORT_ARTIFACT_EXPIRED", "This artifact has expired or is unavailable.", 410)
    try:
        path = artifact_path(artifact.storage_path)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != artifact.sha256:
            raise ValueError("unavailable")
    except (ValueError, OSError) as exc:
        raise report_error(
            "REPORT_ARTIFACT_UNAVAILABLE", "Artifact is unavailable. Contact an administrator.", 503
        ) from exc
    return FileResponse(
        path,
        media_type=artifact.media_type,
        filename=artifact.filename,
        headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"},
    )
