"""Durable reporting windows, scope overlap and scheduled-run completion barriers."""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..core.context import minimal_background_context, tenant_scope
from ..models import ReportDelivery, ReportSubscription
from ..schemas_reports import preferences_for
from .report_access import scope_sboms

SCOPE_PRIORITY = {"SBOM": 0, "PRODUCT": 1, "PROJECT": 2, "TENANT": 3}


def now_iso():
    return datetime.now(UTC).isoformat()


def cadence_window(subscription, now):
    local = now.astimezone(ZoneInfo(subscription.timezone))
    end = local.replace(hour=0, minute=0, second=0, microsecond=0)
    if subscription.cadence == "DAILY":
        start = end - timedelta(days=1)
    elif subscription.cadence == "WEEKLY":
        end -= timedelta(days=end.weekday())
        start = end - timedelta(days=7)
    elif subscription.cadence == "MONTHLY":
        end = end.replace(day=1)
        start = (end - timedelta(days=1)).replace(day=1)
    else:
        return None
    created = datetime.fromisoformat(subscription.created_on)
    if end <= created:
        return None
    start = max(start, created)
    if subscription.last_delivered_at:
        start = max(created, datetime.fromisoformat(subscription.last_delivered_at))
    if start >= end:
        return None
    return start.astimezone(UTC).isoformat(), end.astimezone(UTC).isoformat()


def create_delivery(db, subscription, *, start, end, sbom_ids, expected=(), manual=False):
    existing = db.scalar(
        select(ReportDelivery).where(
            ReportDelivery.subscription_id == subscription.id,
            ReportDelivery.tenant_id == subscription.tenant_id,
            ReportDelivery.cycle_start == start,
            ReportDelivery.cycle_end == end,
        )
    )
    if existing:
        return existing
    row = ReportDelivery(
        tenant_id=subscription.tenant_id,
        subscription_id=subscription.id,
        cycle_start=start,
        cycle_end=end,
        created_on=now_iso(),
        status="PENDING",
        artifact_ids=[],
        attempts=[],
        attempt_count=0,
        sbom_count=len(sbom_ids),
        run_count=0,
        payload={"sbom_ids": list(sbom_ids), "expected": list(expected), "completed": {}, "manual": manual},
    )
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        row = db.scalar(
            select(ReportDelivery).where(
                ReportDelivery.subscription_id == subscription.id,
                ReportDelivery.tenant_id == subscription.tenant_id,
                ReportDelivery.cycle_start == start,
                ReportDelivery.cycle_end == end,
            )
        )
    return row


def create_cycles(db, subscriptions, windows, *, expected=()):
    """Narrowest scope wins per owner among subscriptions due in this cycle."""
    covered, deliveries = {}, []
    for sub in sorted(subscriptions, key=lambda s: (SCOPE_PRIORITY[s.scope], s.id)):
        owner = (sub.tenant_id, sub.iam_user_id)
        with tenant_scope(minimal_background_context(sub.tenant_id)):
            ids = {s.id for s in scope_sboms(db, preferences_for(sub), sub.tenant_id)}
            if expected:
                ids &= set(expected)
            ids -= covered.setdefault(owner, set())
            covered[owner] |= ids
            start, end = windows[sub.id]
            delivery = create_delivery(
                db, sub, start=start, end=end, sbom_ids=sorted(ids), expected=sorted(ids) if expected else ()
            )
            if not ids and delivery.status == "PENDING":
                delivery.status, delivery.error_code = "SKIPPED", "EMPTY_OR_OVERLAPPED_SCOPE"
            deliveries.append(delivery)
            db.flush()
    return deliveries


def prepare_run_cycle(db, targets, cycle):
    """Called before scheduler enqueue; rows remain recoverable if broker is down."""
    from ..models import SBOMSource

    target_ids = {target.sbom_id for target in targets}
    tenants = {}
    for sid, tid in db.execute(select(SBOMSource.id, SBOMSource.tenant_id).where(SBOMSource.id.in_(target_ids))):
        tenants.setdefault(tid, []).append(sid)
    for tid, ids in tenants.items():
        with tenant_scope(minimal_background_context(tid)):
            subs = list(
                db.scalars(
                    select(ReportSubscription).where(
                        ReportSubscription.tenant_id == tid,
                        ReportSubscription.enabled.is_(True),
                        ReportSubscription.cadence == "ON_EVERY_RUN",
                    )
                )
            )
            windows = {s.id: (s.last_delivered_at or s.created_on, cycle) for s in subs}
            create_cycles(db, subs, windows, expected=ids)
    db.commit()


def record_run_completion(db, *, tenant_id, sbom_id, cycle, status, run_id=None):
    with tenant_scope(minimal_background_context(tenant_id)):
        rows = list(
            db.scalars(
                select(ReportDelivery)
                .where(
                    ReportDelivery.tenant_id == tenant_id,
                    ReportDelivery.cycle_end == cycle,
                    ReportDelivery.status == "PENDING",
                )
                .with_for_update()
            )
        )
        for row in rows:
            payload = dict(row.payload)
            if sbom_id not in payload.get("expected", []):
                continue
            done = dict(payload.get("completed", {}))
            done[str(sbom_id)] = {"status": status, "run_id": run_id}
            payload["completed"] = done
            if len(done) >= len(payload["expected"]):
                payload["snapshot_at"] = now_iso()
            row.payload = payload
        db.commit()
