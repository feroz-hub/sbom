"""PostgreSQL regressions for the shared tenant data-access boundary."""

from datetime import UTC, datetime

import pytest
from app.core.context import get_bound_context, minimal_background_context, tenant_scope
from app.db import SessionLocal
from app.models import Projects, Tenant
from sqlalchemy import delete, insert, select, update
from sqlalchemy.orm import aliased

pytestmark = pytest.mark.postgres


@pytest.fixture
def tenant_projects():
    with SessionLocal() as db:
        now = datetime.now(UTC)
        tenant = Tenant(name="Boundary B", slug="boundary-b", status="ACTIVE", created_at=now, updated_at=now)
        db.add(tenant)
        db.flush()
        tenant_b = tenant.id
        db.commit()
    identifiers = {}
    for tid in (1, tenant_b):
        with tenant_scope(minimal_background_context(tid)), SessionLocal() as db:
            for active in (True, False):
                row = Projects(project_name=f"boundary-{tid}-{active}", tenant_id=tid, is_active=active)
                db.add(row)
                db.flush()
                identifiers[tid, active] = row.id
            db.commit()
    return tenant_b, identifiers


@pytest.mark.parametrize("representation", ["entity", "columns", "alias"])
def test_include_deleted_preserves_tenant_boundary(tenant_projects, representation):
    tenant_b, identifiers = tenant_projects
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        model = aliased(Projects) if representation == "alias" else Projects
        statement = select(model) if representation == "entity" else select(model.id)
        rows = db.scalars(statement.execution_options(include_deleted=True)).all()
        ids = {row.id for row in rows} if representation == "entity" else set(rows)
        assert identifiers[1, False] in ids
        assert identifiers[1, True] in ids
        assert identifiers[tenant_b, False] not in ids
        assert identifiers[tenant_b, True] not in ids


def test_soft_delete_visibility_remains_independent(tenant_projects):
    _, identifiers = tenant_projects
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        assert db.get(Projects, identifiers[1, False]) is None
        assert db.get(Projects, identifiers[1, True]) is not None
        deleted = db.scalar(
            select(Projects).where(Projects.id == identifiers[1, False]).execution_options(include_deleted=True)
        )
        assert deleted is not None
        deleted.is_active = True
        db.commit()
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        assert db.get(Projects, identifiers[1, False]) is not None


def test_foreign_deleted_project_cannot_be_restored(client, tenant_projects):
    tenant_b, identifiers = tenant_projects
    response = client.post(f"/api/projects/{identifiers[tenant_b, False]}/restore")
    assert response.status_code == 404
    with tenant_scope(minimal_background_context(tenant_b)), SessionLocal() as db:
        row = db.scalar(
            select(Projects).where(Projects.id == identifiers[tenant_b, False]).execution_options(include_deleted=True)
        )
        assert row.is_active is False


def test_internal_discovery_returns_only_identifiers(tenant_projects):
    from app.services.maintenance_scope import active_tenant_ids

    tenant_b, _ = tenant_projects
    assert set(active_tenant_ids()) == {1, tenant_b}
    assert all(type(identifier) is int for identifier in active_tenant_ids())
    with tenant_scope(minimal_background_context(1)):
        with pytest.raises(RuntimeError, match="request contexts"):
            active_tenant_ids()


def test_maintenance_validates_scope_and_clears_on_failure(tenant_projects):
    from app.services.maintenance_scope import maintenance_tenant

    tenant_b, identifiers = tenant_projects
    assert get_bound_context() is None
    with pytest.raises(ValueError, match="simulated"):
        with maintenance_tenant(tenant_b, "test.failure"), SessionLocal() as db:
            assert get_bound_context().tenant_id == tenant_b
            assert db.get(Projects, identifiers[1, True]) is None
            assert db.get(Projects, identifiers[tenant_b, True]) is not None
            raise ValueError("simulated")
    assert get_bound_context() is None
    with maintenance_tenant(1, "test.next_job"):
        assert get_bound_context().tenant_id == 1
    assert get_bound_context() is None
    with pytest.raises(RuntimeError, match="Inactive"):
        with maintenance_tenant(987654, "test.invalid"):
            pytest.fail("missing tenant was accepted")
    assert get_bound_context() is None


def test_scheduler_processes_each_tenant_in_its_own_scope(tenant_projects, monkeypatch):
    from app.workers import scheduled_analysis

    tenant_b, identifiers = tenant_projects
    seen = []

    def process():
        tid = get_bound_context().tenant_id
        with SessionLocal() as db:
            rows = set(db.scalars(select(Projects.id)))
        assert rows == {identifiers[tid, True]}
        seen.append(tid)
        return {"due": 1, "enqueued": 0}

    monkeypatch.setattr(scheduled_analysis, "_tick_for_tenant", process)
    assert scheduled_analysis.tick_scheduled_analyses.run()["due"] == 2
    assert seen == [1, tenant_b]
    assert get_bound_context() is None


def test_startup_status_repair_only_updates_active_tenants(tenant_projects, monkeypatch):
    from app.main import _ensure_seed_data
    from app.models import SBOMSource
    from app.settings import get_settings

    tenant_b, _ = tenant_projects
    with SessionLocal() as db:
        db.get(Tenant, tenant_b).status = "DISABLED"
        db.commit()
    ids = {}
    for tid in (1, tenant_b):
        with tenant_scope(minimal_background_context(tid)), SessionLocal() as db:
            row = SBOMSource(tenant_id=tid, sbom_name=f"repair-{tid}", status="validated")
            db.add(row)
            db.commit()
            ids[tid] = row.id
    monkeypatch.setattr(get_settings(), "auth_enabled", True)
    _ensure_seed_data()
    for tid in (1, tenant_b):
        with tenant_scope(minimal_background_context(tid)), SessionLocal() as db:
            assert db.get(SBOMSource, ids[tid]).status == ("pending" if tid == 1 else "validated")
    assert get_bound_context() is None


@pytest.mark.parametrize("operation", ["orm_read", "core_read", "insert", "update", "delete"])
def test_missing_context_fails_closed(tenant_projects, operation):
    _, identifiers = tenant_projects
    with tenant_scope(None), SessionLocal() as db:
        with pytest.raises(RuntimeError, match="Tenant context"):
            if operation == "orm_read":
                db.scalars(select(Projects).execution_options(include_deleted=True)).all()
            elif operation == "core_read":
                db.execute(select(Projects.__table__.c.project_name)).all()
            elif operation == "insert":
                db.add(Projects(tenant_id=1, project_name="unauthorized"))
                db.flush()
            elif operation == "update":
                db.execute(update(Projects).values(project_name="unauthorized"))
            else:
                db.execute(delete(Projects))
        db.rollback()
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        assert db.get(Projects, identifiers[1, True]).project_name != "unauthorized"


@pytest.mark.parametrize("operation", ["update", "delete"])
@pytest.mark.parametrize("core", [False, True])
def test_bulk_dml_cannot_mutate_foreign_rows(tenant_projects, operation, core):
    tenant_b, identifiers = tenant_projects
    model = Projects.__table__ if core else Projects
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        statement = update(model).values(project_name="bulk-own") if operation == "update" else delete(model)
        active = model.c.is_active if core else model.is_active
        statement = statement.where(active.is_(True))
        db.execute(statement)
        db.commit()
    with tenant_scope(minimal_background_context(tenant_b)), SessionLocal() as db:
        assert db.get(Projects, identifiers[tenant_b, True]).project_name == f"boundary-{tenant_b}-True"
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        row = db.get(Projects, identifiers[1, True])
        assert row.project_name == "bulk-own" if operation == "update" else row is None


def test_core_select_and_nested_select_are_tenant_scoped(tenant_projects):
    _, identifiers = tenant_projects
    table = Projects.__table__
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        rows = set(db.scalars(select(table.c.id)))
        nested = select(table.c.id).subquery()
        nested_rows = set(db.scalars(select(nested.c.id)))
        assert rows == nested_rows == {identifiers[1, True], identifiers[1, False]}


def test_identity_map_cannot_return_foreign_project(tenant_projects):
    tenant_b, identifiers = tenant_projects
    with SessionLocal() as db:
        with tenant_scope(minimal_background_context(tenant_b)):
            held = db.get(Projects, identifiers[tenant_b, True])
        with tenant_scope(minimal_background_context(1)):
            assert db.get(Projects, held.id) is None


def test_changing_owner_cannot_steal_a_loaded_foreign_row(tenant_projects):
    tenant_b, identifiers = tenant_projects
    with SessionLocal() as db:
        with tenant_scope(minimal_background_context(tenant_b)):
            held = db.get(Projects, identifiers[tenant_b, True])
        with tenant_scope(minimal_background_context(1)):
            held.tenant_id = 1
            with pytest.raises(RuntimeError, match="Cross-tenant"):
                db.flush()
            db.rollback()


def test_bulk_insert_and_owner_update_reject_foreign_tenant(tenant_projects):
    tenant_b, _ = tenant_projects
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        with pytest.raises(RuntimeError, match="Cross-tenant"):
            db.execute(insert(Projects), [{"tenant_id": tenant_b, "project_name": "forbidden"}])
        db.rollback()


def test_core_union_alias_and_outer_join_preserve_isolation(tenant_projects):
    from app.models import Product
    from sqlalchemy import union_all

    _, identifiers = tenant_projects
    project = Projects.__table__
    product = Product.__table__
    alias = project.alias()
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        own = {identifiers[1, True], identifiers[1, False]}
        assert set(db.scalars(select(alias.c.id))) == own
        assert set(db.scalars(union_all(select(project.c.id), select(alias.c.id)))) == own
        statement = select(project.c.id).select_from(project.outerjoin(product, project.c.id == product.c.project_id))
        assert set(db.scalars(statement)) == own


def test_legacy_bulk_methods_cannot_bypass_boundary(tenant_projects):
    tenant_b, _ = tenant_projects
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        with pytest.raises(RuntimeError, match="tenant-scoped"):
            db.bulk_save_objects([Projects(tenant_id=tenant_b, project_name="forbidden")])
        with pytest.raises(RuntimeError, match="tenant-scoped"):
            db.bulk_insert_mappings(Projects, [{"tenant_id": tenant_b, "project_name": "forbidden"}])
        with pytest.raises(RuntimeError, match="Cross-tenant"):
            db.execute(update(Projects).values(tenant_id=tenant_b))
        db.rollback()


def test_assignment_error_survives_context_manager_traceback():
    from contextlib import contextmanager

    from app.core.identity_states import IdentityErrorCode
    from app.services.tenant_role_assignment_service import AssignmentProblem

    @contextmanager
    def transaction():
        yield

    with pytest.raises(AssignmentProblem) as caught:
        with transaction():
            raise AssignmentProblem(IdentityErrorCode.TENANT_ROLE_NOT_ASSIGNABLE, "rejected", 422)
    assert caught.value.status_code == 422


def test_background_context_is_validated_and_restored(tenant_projects):
    from app.services.maintenance_scope import background_tenant

    tenant_b, _ = tenant_projects
    with pytest.raises(RuntimeError, match="Tenant context"):
        with background_tenant():
            pytest.fail("missing owner accepted")
    with tenant_scope(minimal_background_context(1)):
        with pytest.raises(RuntimeError, match="Cross-tenant"):
            with background_tenant(tenant_b):
                pytest.fail("foreign owner accepted")
        assert get_bound_context().tenant_id == 1
    with pytest.raises(ValueError):
        with background_tenant(tenant_b):
            assert get_bound_context().tenant_id == tenant_b
            raise ValueError("retry")
    assert get_bound_context() is None


def test_ordered_update_cannot_change_tenant_owner(tenant_projects):
    tenant_b, _ = tenant_projects
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        with pytest.raises(RuntimeError, match="Cross-tenant"):
            db.execute(update(Projects.__table__).ordered_values((Projects.tenant_id, tenant_b)))


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_aliased_dml_is_tenant_scoped(tenant_projects, operation):
    tenant_b, identifiers = tenant_projects
    alias = Projects.__table__.alias("target_project")
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        statement = update(alias).values(project_name="alias-own") if operation == "update" else delete(alias)
        db.execute(statement.where(alias.c.is_active.is_(True)))
        db.commit()
    with tenant_scope(minimal_background_context(tenant_b)), SessionLocal() as db:
        assert db.get(Projects, identifiers[tenant_b, True]).project_name == f"boundary-{tenant_b}-True"


def test_expired_owner_cannot_be_reassigned_across_tenants(tenant_projects):
    tenant_b, identifiers = tenant_projects
    with SessionLocal() as db:
        with tenant_scope(minimal_background_context(tenant_b)):
            held = db.get(Projects, identifiers[tenant_b, True])
            db.expire(held, ["tenant_id"])
        with tenant_scope(minimal_background_context(1)):
            held.tenant_id = 1
            with pytest.raises(RuntimeError, match="Cross-tenant"):
                db.flush()
            db.rollback()


@pytest.mark.parametrize("next_tenant", [1, None])
def test_relationship_cache_cannot_return_foreign_project(tenant_projects, next_tenant):
    from app.models import Product

    tenant_b, identifiers = tenant_projects
    with tenant_scope(minimal_background_context(tenant_b)), SessionLocal() as db:
        product = Product(
            tenant_id=tenant_b,
            project_id=identifiers[tenant_b, True],
            name="cached",
            normalized_name="cached",
            slug="cached",
            status="active",
            created_at=datetime.now(UTC).isoformat(),
        )
        db.add(product)
        db.commit()
        product_id = product.id
    with SessionLocal() as db:
        with tenant_scope(minimal_background_context(tenant_b)):
            held = db.get(Product, product_id)
            cached = db.get(Projects, identifiers[tenant_b, True])
            assert "project" not in held.__dict__
        with tenant_scope(minimal_background_context(next_tenant) if next_tenant else None):
            if next_tenant:
                assert held.project is None
            else:
                with pytest.raises(RuntimeError, match="Tenant context"):
                    _ = held.project


def test_queued_schedule_requires_trusted_matching_owners(tenant_projects):
    from app.models import AnalysisSchedule, SBOMSource
    from app.services.maintenance_scope import schedule_tenant_id
    from app.workers.scheduled_analysis import analyze_sbom_async

    tenant_b, projects = tenant_projects
    jobs = {}
    for tid in (1, tenant_b):
        with tenant_scope(minimal_background_context(tid)), SessionLocal() as db:
            sbom = SBOMSource(tenant_id=tid, sbom_name=f"job-{tid}", projectid=projects[tid, True])
            db.add(sbom)
            db.flush()
            schedule = AnalysisSchedule(
                tenant_id=tid,
                scope="SBOM",
                sbom_id=sbom.id,
                cadence="DAILY",
                hour_utc=2,
                mode="CUSTOM",
                enabled=True,
                created_on=datetime.now(UTC).isoformat(),
            )
            db.add(schedule)
            db.commit()
            jobs[tid] = (schedule.id, sbom.id)
    schedule_a, sbom_a = jobs[1]
    schedule_b, sbom_b = jobs[tenant_b]
    assert schedule_tenant_id(schedule_a, sbom_id=sbom_a) == 1
    assert schedule_tenant_id(schedule_b, sbom_id=sbom_b) == tenant_b
    assert schedule_tenant_id(schedule_a, sbom_id=sbom_b) is None
    result = analyze_sbom_async.run(schedule_id=schedule_a, sbom_id=sbom_b)
    assert result == {"status": "SKIPPED", "reason": "schedule_scope_invalid"}
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        assert db.get(AnalysisSchedule, schedule_a).last_run_status is None
    assert get_bound_context() is None


@pytest.mark.parametrize("operation", ["update", "delete", "restore"])
def test_foreign_orm_mutations_are_rejected(tenant_projects, operation):
    tenant_b, identifiers = tenant_projects
    identifier = identifiers[tenant_b, operation != "restore"]
    with SessionLocal() as db:
        with tenant_scope(minimal_background_context(tenant_b)):
            held = db.scalar(select(Projects).where(Projects.id == identifier).execution_options(include_deleted=True))
        with tenant_scope(minimal_background_context(1)):
            if operation == "delete":
                db.delete(held)
            elif operation == "restore":
                held.is_active = True
            else:
                held.project_name = "forbidden"
            with pytest.raises(RuntimeError, match="Cross-tenant"):
                db.flush()
            db.rollback()
    with tenant_scope(minimal_background_context(tenant_b)), SessionLocal() as db:
        row = db.scalar(select(Projects).where(Projects.id == identifier).execution_options(include_deleted=True))
        assert row is not None
        assert row.project_name != "forbidden"
        assert row.is_active is (operation != "restore")


def test_core_insert_stamps_owner_and_blocks_multirow_foreign_owner(tenant_projects):
    tenant_b, _ = tenant_projects
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        identifier = db.scalar(insert(Projects.__table__).values(project_name="core-own").returning(Projects.id))
        db.commit()
        assert db.get(Projects, identifier).tenant_id == 1
        with pytest.raises(RuntimeError, match="Cross-tenant"):
            db.execute(
                insert(Projects.__table__).values(
                    [
                        {"tenant_id": 1, "project_name": "own-multi"},
                        {"tenant_id": tenant_b, "project_name": "foreign-multi"},
                    ]
                )
            )
        db.rollback()


def test_report_dispatch_processes_only_selected_tenant(tenant_projects, monkeypatch):
    from types import SimpleNamespace

    from app.workers import report_notifications

    tenant_b, _ = tenant_projects
    seen = []
    monkeypatch.setattr(
        report_notifications, "get_settings", lambda: SimpleNamespace(report_notifications_enabled=True)
    )

    def dispatch():
        seen.append(get_bound_context().tenant_id)
        return {"pending": 1}

    monkeypatch.setattr(report_notifications, "_dispatch_for_tenant", dispatch)
    assert report_notifications.dispatch_pending() == {"pending": 2}
    assert seen == [1, tenant_b]
    assert get_bound_context() is None


def test_advisor_worker_rejects_invalid_tenant_before_business_work(tenant_projects, monkeypatch):
    from app.workers import component_advisor_tasks

    def forbidden(*args, **kwargs):
        pytest.fail("invalid tenant reached business evaluation")

    monkeypatch.setattr(component_advisor_tasks, "evaluate_recommendation", forbidden)
    assert component_advisor_tasks.evaluate_recommendation_task(123, 987654) == "NOT_FOUND"
    assert get_bound_context() is None


def test_upsert_cannot_mutate_foreign_primary_key(tenant_projects):
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    tenant_b, identifiers = tenant_projects
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        statement = (
            pg_insert(Projects.__table__)
            .values(id=identifiers[tenant_b, True], tenant_id=1, project_name="hijacked")
            .on_conflict_do_update(index_elements=[Projects.id], set_={"project_name": "hijacked"})
        )
        with pytest.raises(RuntimeError, match="upsert"):
            db.execute(statement)
        db.rollback()
    with tenant_scope(minimal_background_context(tenant_b)), SessionLocal() as db:
        assert db.get(Projects, identifiers[tenant_b, True]).project_name != "hijacked"


def test_insert_returning_subquery_cannot_read_foreign_data(tenant_projects):
    tenant_b, identifiers = tenant_projects
    table = Projects.__table__
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        foreign_name = select(table.c.project_name).where(table.c.id == identifiers[tenant_b, True]).scalar_subquery()
        statement = insert(table).values(project_name="returning-own").returning(foreign_name)
        assert db.scalar(statement) is None
        db.commit()


@pytest.mark.parametrize("query", ["SELECT * FROM projects", r'SELECT * FROM U&"pro\006Aects"'])
def test_raw_sql_cannot_bypass_statement_scope(tenant_projects, query):
    from sqlalchemy import text

    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        with pytest.raises(RuntimeError, match="Raw SQL"):
            db.execute(text(query))


def test_shared_cte_preserves_identity_and_tenant_scope(tenant_projects):
    tenant_b, identifiers = tenant_projects
    table = Projects.__table__
    shared = select(table.c.id).cte("shared_projects")
    statement = select(shared.c.id).where(shared.c.id.in_(select(shared.c.id)))
    for tid in (1, tenant_b):
        with tenant_scope(minimal_background_context(tid)), SessionLocal() as db:
            assert set(db.scalars(statement)) == {identifiers[tid, True], identifiers[tid, False]}


def test_recursive_cte_preserves_identity_and_tenant_scope(tenant_projects):
    _, identifiers = tenant_projects
    table = Projects.__table__
    nodes = select(table.c.id).cte("recursive_projects", recursive=True)
    related = table.alias()
    nodes = nodes.union(select(related.c.id).select_from(nodes.join(related, related.c.id == nodes.c.id)))
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        assert set(db.scalars(select(nodes.c.id))) == {identifiers[1, True], identifiers[1, False]}
