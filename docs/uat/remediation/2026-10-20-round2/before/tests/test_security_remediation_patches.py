"""Security regressions using isolated routers, actual guards, and disposable SQLite."""

from dataclasses import replace
from unittest.mock import MagicMock

import pytest
from app.core.context import CurrentContext, bind_context, reset_context, tenant_scope
from app.core.security import enforce_request_access, get_current_tenant_context
from app.db import Base, TenantSession, get_db
from app.models import Projects, VulnerabilityRemediation, VulnerabilityRemediationAudit
from app.routers import projects, remediation
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool


def actor(*permissions, tenant_id=1, platform=False):
    return CurrentContext(
        1,
        "authenticated-user",
        "actor@example.test",
        "Actor",
        tenant_id,
        str(tenant_id) if tenant_id else None,
        frozenset(),
        frozenset(permissions),
        platform,
    )


@pytest.fixture
def isolated_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with TenantSession(engine, expire_on_commit=False) as db:
        for tenant_id in (1, 2):
            token = bind_context(actor(tenant_id=tenant_id))
            try:
                db.add(
                    Projects(
                        id=tenant_id,
                        tenant_id=tenant_id,
                        project_name="Own" if tenant_id == 1 else "Foreign",
                        created_on="2026-10-13",
                        is_active=tenant_id == 1,
                    )
                )
                db.commit()
            finally:
                reset_context(token)
        with tenant_scope(actor()):
            yield db
    engine.dispose()


def router_client(router, db, context, *, bind=True):
    app = FastAPI()
    app.include_router(router, dependencies=[Depends(enforce_request_access)])

    async def current_context():
        token = bind_context(context) if bind else None
        try:
            yield context
        finally:
            if token is not None:
                reset_context(token)

    app.dependency_overrides[get_current_tenant_context] = current_context
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def payload(status="Open"):
    return dict(
        vuln_id="CVE-2026-1234",
        component_name="lib",
        component_version="1",
        status=status,
        resolution_date="2026-10-13" if status == "Closed" else None,
    )


@pytest.mark.parametrize(
    "role,permissions",
    [
        ("Viewer", ("remediation:read",)),
        ("Developer", ("remediation:write",)),
        ("Security Analyst", ("remediation:write", "remediation:close")),
        ("Tenant Administrator", ("remediation:write", "remediation:close")),
    ],
)
def test_close_requires_separate_permission(isolated_db, role, permissions):
    with router_client(remediation.router, isolated_db, actor(*permissions)) as client:
        result = client.post("/api/remediation?project_id=1", json=payload("Closed"))
    allowed = "remediation:close" in permissions
    assert result.status_code == (200 if allowed else 403)
    assert len(isolated_db.scalars(select(VulnerabilityRemediation)).all()) == (1 if allowed else 0)


def test_remediation_actor_cannot_be_spoofed(isolated_db):
    with router_client(remediation.router, isolated_db, actor("remediation:write")) as client:
        result = client.post("/api/remediation?project_id=1&user_id=spoofed-admin", json=payload())
    assert result.status_code == 200
    assert isolated_db.scalar(select(VulnerabilityRemediationAudit.changed_by)) == "actor@example.test"


def test_restore_foreign_project_with_tenant_guard(isolated_db):
    with router_client(projects.router, isolated_db, actor("project:update")) as client:
        result = client.post("/api/projects/2/restore")
    assert result.status_code == 404
    with tenant_scope(actor(tenant_id=2)):
        assert isolated_db.scalar(select(Projects).where(Projects.id == 2).execution_options(include_deleted=True)).is_active is False


def test_restore_own_project_and_audit_actor(isolated_db, monkeypatch):
    own = isolated_db.get(Projects, 1)
    own.is_active = False
    isolated_db.commit()
    audit = MagicMock()
    monkeypatch.setattr(projects.audit_log, "record", audit)
    with router_client(projects.router, isolated_db, actor("project:update")) as client:
        result = client.post("/api/projects/1/restore?user_id=spoofed-admin")
    assert result.status_code == 200
    assert own.is_active is True
    assert audit.call_args.kwargs["user_id"] == "actor@example.test"


@pytest.mark.parametrize("operation", ["create_record", "update_record", "disable_record", "import_records"])
@pytest.mark.parametrize(
    "context",
    [
        None,
        actor("lifecycle:vendor-record:write", "lifecycle:vendor-record:delete"),
        actor("platform:admin", platform=False),
    ],
)
def test_global_vendor_service_denies_before_db(operation, context):
    from app.services.lifecycle.provider_config_service import LifecycleVendorRecordService

    db = MagicMock()
    args = {"create_record": ({},), "update_record": (1, {}), "disable_record": (1,), "import_records": ([],)}
    with pytest.raises(HTTPException) as exc:
        getattr(LifecycleVendorRecordService(), operation)(db, *args[operation], context=context)
    assert exc.value.status_code == 403
    assert db.mock_calls == []


@pytest.mark.parametrize("platform", [False, True])
def test_kev_sync_platform_authority(isolated_db, monkeypatch, platform):
    from app.routers import kev

    sync = MagicMock(
        return_value={
            "upserted": 0,
            "matched_after_filter": 0,
            "total_in_feed": 0,
            "filtered_since": None,
            "duration_seconds": 0,
        }
    )
    monkeypatch.setattr(kev, "sync_kev", sync)
    context = actor("tenant:settings:update", "platform:admin", tenant_id=None if platform else 1, platform=platform)
    with router_client(kev.router, isolated_db, context) as client:
        response = client.post("/api/v1/kev/sync", json={})
    assert response.status_code == (200 if platform else 403)
    assert sync.call_count == (1 if platform else 0)


def test_platform_vendor_crud_and_import(isolated_db):
    from app.services.lifecycle.provider_config_service import LifecycleVendorRecordService

    service = LifecycleVendorRecordService()
    context = actor("platform:admin", tenant_id=None, platform=True)
    row = service.create_record(
        isolated_db, {"vendor_name": "Acme", "product_name": "Runtime", "lifecycle_status": "EOL"}, context=context
    )
    assert row.updated_by_user_id == context.user_id
    service.update_record(isolated_db, row.id, {"product_name": "Runtime 2"}, context=context)
    assert row.product_name == "Runtime 2"
    assert (
        service.import_records(
            isolated_db, [{"vendor_name": "Acme", "product_name": "Other", "lifecycle_status": "EOL"}], context=context
        )["created"]
        == 1
    )
    assert service.disable_record(isolated_db, row.id, context=context)
    assert row.enabled is False


EXPORT_OPERATIONS = [
    ("GET", "/api/sboms/1/download"),
    ("GET", "/api/sboms/1/export"),
    ("GET", "/api/sboms/1/reports/vulnerabilities.xlsx"),
    ("GET", "/api/analysis-runs/1/export/csv"),
    ("GET", "/api/analysis-runs/1/export/sarif"),
    ("GET", "/api/sboms/1/vex/report"),
    ("GET", "/api/sboms/1/reports/vex-pack"),
    ("GET", "/api/sboms/1/lifecycle/report"),
    ("GET", "/api/sboms/1/reports/lifecycle-pack"),
    ("POST", "/api/projects/1/reports/fda-510k-sbom/export"),
    ("POST", "/api/v1/compare/cache/export"),
    ("POST", "/api/pdf-report"),
    ("GET", "/api/report-deliveries/1/artifacts/1"),
]


@pytest.mark.parametrize("method,path", EXPORT_OPERATIONS)
def test_exports_require_explicit_export_permission(method, path):
    from app.core.security import permission_for_request
    from starlette.requests import Request

    request = Request({"type": "http", "method": method, "path": path, "headers": []})
    assert permission_for_request(request) == "sbom:export"


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE"])
def test_unmapped_operations_fail_closed(method):
    from app.core.security import permission_for_request
    from starlette.requests import Request

    request = Request({"type": "http", "method": method, "path": "/api/new-sensitive-operation", "headers": []})
    with pytest.raises(HTTPException) as exc:
        permission_for_request(request)
    assert exc.value.status_code == 403


def test_registered_routes_have_explicit_policies():
    from app.core.route_policy import validate_route_policies
    from app.main import app

    validate_route_policies(app)


def test_registration_rejects_new_unmapped_route():
    from app.core.route_policy import validate_route_policies

    app = FastAPI()

    @app.get("/api/new-protected", dependencies=[Depends(enforce_request_access)])
    def handler():
        return {}

    with pytest.raises(RuntimeError, match="missing policy"):
        validate_route_policies(app)


def test_registration_rejects_catalogued_but_unguarded_route():
    from app.core.route_policy import validate_route_policies

    app = FastAPI()

    @app.get("/api/projects")
    def handler():
        return {}

    with pytest.raises(RuntimeError, match="missing permission guard"):
        validate_route_policies(app)


@pytest.mark.parametrize("permission", ["platform:admin", "platform:ai:update"])
def test_tenant_context_cannot_grant_platform_authority(permission):
    assert not actor(permission, platform=False).has_permission(permission)
    assert not actor(permission, platform=True).has_permission(permission)
    assert actor(permission, tenant_id=None, platform=True).has_permission(permission)


@pytest.mark.parametrize("environment", ["production", "staging"])
def test_production_cannot_disable_auth(monkeypatch, environment):
    from app.auth import validate_auth_setup
    from app.settings import reset_settings

    monkeypatch.setenv("APP_ENVIRONMENT", environment)
    monkeypatch.setenv("AUTH_ENABLED", "false")
    reset_settings()
    with pytest.raises(RuntimeError, match="AUTH_ENABLED"):
        validate_auth_setup()


def test_enabled_provider_cannot_use_development_identity(monkeypatch):
    from app.core.security import get_current_claims
    from app.settings import reset_settings

    monkeypatch.setenv("NATIVE_AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_ENABLED", "false")
    reset_settings()
    with pytest.raises(RuntimeError, match="AUTH_ENABLED"):
        get_current_claims(None)


def test_forwarding_headers_do_not_change_rate_limit_identity():
    from app.rate_limit import build_rate_limit_bucket_key
    from starlette.requests import Request

    def request(ip):
        return Request({"type": "http", "client": ("192.0.2.1", 123), "headers": [(b"x-forwarded-for", ip.encode())]})

    assert build_rate_limit_bucket_key(request("198.51.100.1")) == build_rate_limit_bucket_key(request("198.51.100.2"))


@pytest.mark.parametrize("method,path", EXPORT_OPERATIONS)
@pytest.mark.parametrize("can_export", [False, True])
def test_export_guard_precedes_business_database_access(method, path, can_export):
    app = FastAPI()
    db = MagicMock()
    permissions = ("sbom:read", "analysis:read", "vex:read", "lifecycle:read") + (
        ("sbom:export",) if can_export else ()
    )
    app.dependency_overrides[get_current_tenant_context] = lambda: actor(*permissions)
    app.dependency_overrides[get_db] = lambda: db

    def handler():
        db.execute("business operation sentinel")
        return {"ok": True}

    from app.core.route_policies import ROUTE_POLICIES
    from starlette.routing import compile_path

    template = next(
        key.split(" ", 1)[1]
        for key in ROUTE_POLICIES
        if key.split(" ", 1)[0] == method and compile_path(key.split(" ", 1)[1])[0].fullmatch(path)
    )
    app.add_api_route(template, handler, methods=[method], dependencies=[Depends(enforce_request_access)])
    with TestClient(app) as client:
        result = client.request(method, path)
    assert result.status_code == (200 if can_export else 403)
    assert db.execute.call_count == (1 if can_export else 0)


@pytest.mark.parametrize("authorization", [None, "Bearer invalid-token"])
def test_protected_missing_invalid_authentication_is_401(monkeypatch, authorization):
    from app.settings import reset_settings

    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
    reset_settings()
    app = FastAPI()
    db = MagicMock()
    app.dependency_overrides[get_db] = lambda: db

    @app.get("/api/projects", dependencies=[Depends(enforce_request_access)])
    def handler():
        db.execute("business operation sentinel")
        return {}

    with TestClient(app) as client:
        result = client.get("/api/projects", headers={"Authorization": authorization} if authorization else {})
    assert result.status_code == 401
    assert db.mock_calls == []


def test_legacy_principal_ignores_forged_identity_headers():
    from app.auth import get_current_principal, require_roles

    app = FastAPI()
    app.dependency_overrides[get_current_tenant_context] = lambda: replace(actor(), roles=frozenset({"VIEWER"}))

    @app.get("/principal")
    def principal(value=Depends(get_current_principal)):
        return {"user": value.user_id, "roles": sorted(value.roles)}

    @app.post("/admin", dependencies=[Depends(require_roles("platform_admin"))])
    def admin():
        return {}

    with TestClient(app) as client:
        headers = {"X-SBOM-User": "forged-admin", "X-SBOM-Roles": "platform_admin"}
        assert client.get("/principal", headers=headers).json() == {"user": "actor@example.test", "roles": ["viewer"]}
        assert client.post("/admin", headers=headers).status_code == 403


@pytest.mark.parametrize("operation", ["edit", "restore"])
def test_version_actor_is_authenticated(monkeypatch, operation):
    from types import SimpleNamespace

    from app.routers import sbom_versions
    from app.schemas import SbomEditPayload
    from fastapi import BackgroundTasks

    service = MagicMock(return_value=SimpleNamespace(id=1))
    context = actor("sbom:update")
    token = bind_context(context)
    try:
        if operation == "edit":
            monkeypatch.setattr(sbom_versions, "edit_sbom", service)
            sbom_versions.edit_sbom_endpoint(
                1, SbomEditPayload(), BackgroundTasks(), user_id="forged", context=context, db=MagicMock()
            )
            assert service.call_args.kwargs["user_id"] == context.actor_label()
        else:
            monkeypatch.setattr(sbom_versions, "restore_version", service)
            sbom_versions.restore_sbom_version(1, 2, user_id="forged", context=context, db=MagicMock())
            assert service.call_args.args[3] == context.actor_label()
    finally:
        reset_context(token)


def test_schedule_actor_is_authenticated():
    from app.models import AnalysisSchedule
    from app.routers.schedules import _apply_payload
    from app.schemas import ScheduleUpsert

    row = AnalysisSchedule(scope="PROJECT")
    token = bind_context(actor())
    try:
        _apply_payload(row, ScheduleUpsert(cadence="DAILY", modified_by="forged"), partial=False)
        assert row.modified_by == "actor@example.test"
    finally:
        reset_context(token)


def test_old_ai_jobs_without_actor_do_not_execute(monkeypatch):
    from types import SimpleNamespace

    import app.db
    from app.workers import ai_fix_tasks

    db = MagicMock()
    monkeypatch.setattr(app.db, "SessionLocal", lambda: db)
    monkeypatch.setattr(ai_fix_tasks, "evaluate_access", lambda **kw: SimpleNamespace(allowed=True))
    pipeline = MagicMock()
    monkeypatch.setattr(ai_fix_tasks, "AiFixBatchPipeline", pipeline)
    monkeypatch.setattr(ai_fix_tasks, "build_budget_guard", lambda **kw: object())
    monkeypatch.setattr(ai_fix_tasks, "get_progress_store", MagicMock())

    async def fake_pipeline(*args, **kwargs):
        return SimpleNamespace(
            progress=SimpleNamespace(
                status="completed",
                generated=1,
                from_cache=0,
                failed=0,
                cost_so_far_usd=0,
                model_dump=lambda **kw: {"status": "completed"},
            )
        )

    monkeypatch.setattr(ai_fix_tasks, "_run_pipeline_with_http_client", fake_pipeline)
    response = ai_fix_tasks.generate_run_fixes.run(1, tenant_id=1)
    assert response["status"] == "failed"
    pipeline.assert_not_called()


@pytest.fixture
def job_actor_db(isolated_db):
    from datetime import UTC, datetime

    from app.models import (
        AuthorizationPermission,
        AuthorizationRole,
        AuthorizationRolePermission,
        IAMUser,
        Tenant,
        TenantUser,
        TenantUserRoleAssignment,
    )

    db = isolated_db
    now = datetime.now(UTC)
    token = bind_context(actor(tenant_id=1))
    try:
        user = IAMUser(
            id=1,
            external_iam_user_id="job-actor",
            email="actor@example.test",
            display_name="Actor",
            status="ACTIVE",
            email_verified=True,
            email_verified_at=now,
            verification_required=False,
            created_at=now,
            updated_at=now,
        )
        tenant = Tenant(
            id=1, name="Own", slug="own", external_iam_tenant_id="own", status="ACTIVE", created_at=now, updated_at=now
        )
        member = TenantUser(
            id=1, user_id=1, tenant_id=1, role="SECURITY_ANALYST", status="ACTIVE", created_at=now, updated_at=now
        )
        role = AuthorizationRole(
            id=1,
            code="SECURITY_ANALYST",
            name="Security Analyst",
            scope="TENANT",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        permission = AuthorizationPermission(
            id=1,
            code="analysis:run",
            name="Run analysis",
            scope="TENANT",
            resource="analysis",
            action="run",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        db.add_all([user, tenant, member, role, permission])
        db.flush()
        db.add(AuthorizationRolePermission(role_id=1, permission_id=1, created_at=now, updated_at=now))
        assignment = TenantUserRoleAssignment(
            tenant_id=1,
            tenant_user_id=1,
            role_id=1,
            status="ACTIVE",
            is_primary=True,
            assignment_source="SYSTEM",
            assigned_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(assignment)
        db.commit()
        yield db, user, tenant, member, permission, assignment
    finally:
        reset_context(token)


@pytest.mark.parametrize(
    "revocation",
    [
        "none",
        "disabled_user",
        "removed_member",
        "disabled_tenant",
        "disabled_permission",
        "revoked_role",
        "foreign_tenant",
    ],
)
def test_background_actor_live_authority(job_actor_db, revocation):
    from app.services.job_authorization import authorize_job_actor

    db, user, tenant, member, permission, assignment = job_actor_db
    if revocation == "disabled_user":
        user.status = "DISABLED"
    elif revocation == "removed_member":
        member.status = "DISABLED"
    elif revocation == "disabled_tenant":
        tenant.status = "DISABLED"
    elif revocation == "disabled_permission":
        permission.status = "DISABLED"
    elif revocation == "revoked_role":
        from datetime import UTC, datetime

        assignment.status = "REVOKED"
        assignment.revoked_at = datetime.now(UTC)
        assignment.is_primary = False
    db.commit()
    if revocation == "none":
        context = authorize_job_actor(db, actor_user_id=1, tenant_id=1, permission="analysis:run")
        assert context.has_permission("analysis:run")
    else:
        with pytest.raises(HTTPException) as exc:
            authorize_job_actor(
                db, actor_user_id=1, tenant_id=2 if revocation == "foreign_tenant" else 1, permission="analysis:run"
            )
        assert exc.value.status_code == 403


def test_live_membership_revocation_is_immediate(job_actor_db):
    from app.services.job_authorization import authorize_job_actor

    db, user, tenant, member, permission, assignment = job_actor_db
    assert authorize_job_actor(db, actor_user_id=1, tenant_id=1, permission="analysis:run")
    member.status = "DISABLED"
    db.commit()
    with pytest.raises(HTTPException):
        authorize_job_actor(db, actor_user_id=1, tenant_id=1, permission="analysis:run")


def test_authentication_is_enabled_by_default(monkeypatch):
    from app.settings import Settings

    monkeypatch.delenv("AUTH_ENABLED", raising=False)
    assert Settings(_env_file=None).auth_enabled is True


@pytest.mark.parametrize("field", ["AUTHORIZATION_CATALOG_MODE", "TENANT_ROLE_ASSIGNMENT_MODE"])
def test_production_requires_database_authorization(monkeypatch, field):
    from app.auth import validate_auth_setup
    from app.settings import reset_settings

    monkeypatch.setenv("APP_ENVIRONMENT", "production")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv(field, "COMPARE")
    reset_settings()
    with pytest.raises(RuntimeError, match="DATABASE"):
        validate_auth_setup()


def test_report_generation_requires_export_authority_before_scope_queries():
    from types import SimpleNamespace

    from app.services.report_access import authorize_preferences

    db = MagicMock()
    context = actor("sbom:read", "analysis:read", "project:read", "product:read")
    preferences = SimpleNamespace(scope="PROJECT", project_id=None, product_id=None, sbom_id=None)
    with pytest.raises(HTTPException) as exc:
        authorize_preferences(db, preferences, context)
    assert exc.value.status_code == 403
    assert db.mock_calls == []


def test_remediation_service_requires_write_before_database_access():
    from app.services.remediation_service import create_or_update_remediation

    db = MagicMock()
    token = bind_context(actor("remediation:read"))
    try:
        with pytest.raises(HTTPException) as exc:
            create_or_update_remediation(db, 1, payload())
        assert exc.value.status_code == 403
        assert db.mock_calls == []
    finally:
        reset_context(token)


def test_report_generation_with_export_permission():
    from types import SimpleNamespace

    from app.services.report_access import authorize_preferences

    context = actor("sbom:read", "sbom:export", "analysis:read", "project:read", "product:read")
    authorize_preferences(
        MagicMock(), SimpleNamespace(scope="PROJECT", project_id=None, product_id=None, sbom_id=None), context
    )


@pytest.mark.parametrize("status", ["DISABLED", "LOCKED", "SUSPENDED", "PENDING", "FORCE_PASSWORD_CHANGE"])
def test_non_active_user_cannot_start_job(job_actor_db, status):
    from app.services.job_authorization import authorize_job_actor

    db, user, *_ = job_actor_db
    user.status = status
    db.commit()
    with pytest.raises(HTTPException):
        authorize_job_actor(db, actor_user_id=1, tenant_id=1, permission="analysis:run")


@pytest.mark.parametrize("revocation", ["removed_member", "disabled_user"])
def test_http_membership_revocation_rechecks_authority(job_actor_db, monkeypatch, revocation):
    from types import SimpleNamespace

    from app.core.security import get_current_user
    from app.services import authenticated_principal_service
    from app.settings import reset_settings

    db, user, tenant, member, *_ = job_actor_db
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("DEV_DEFAULT_TENANT", "false")
    reset_settings()
    monkeypatch.setattr(
        authenticated_principal_service,
        "resolve_principal",
        lambda *a, **kw: SimpleNamespace(user=user, provider="HCL_CS"),
    )
    app = FastAPI()
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: {"sub": "job-actor", "role": ["PLATFORM_ADMIN"]}
    business = MagicMock()

    @app.post("/api/sboms/{sbom_id}/analyze", dependencies=[Depends(enforce_request_access)])
    def handler(sbom_id: int):
        business()
        return {"ok": True}

    with TestClient(app) as client:
        assert client.post("/api/sboms/1/analyze").status_code == 200
        if revocation == "removed_member":
            member.status = "DISABLED"
        else:
            user.status = "DISABLED"
        db.commit()
        assert client.post("/api/sboms/1/analyze").status_code == 403
    assert business.call_count == 1


@pytest.mark.parametrize("operation", ["json", "multipart"])
def test_sbom_upload_actor_is_authenticated(monkeypatch, operation):
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from app.routers import sbom_upload, sboms_crud
    from app.schemas import SBOMSourceCreate
    from fastapi import BackgroundTasks, Response

    assigned = MagicMock(side_effect=HTTPException(418, "stop after assignment boundary"))
    if operation == "json":
        monkeypatch.setattr(sboms_crud, "resolve_product_assignment", assigned)
        with pytest.raises(HTTPException):
            sboms_crud.create_sbom(
                SBOMSourceCreate(sbom_name="test", created_by="forged"),
                BackgroundTasks(),
                Response(),
                context=actor(),
                db=MagicMock(),
            )
    else:
        monkeypatch.setattr(sbom_upload, "resolve_product_assignment", assigned)
        with pytest.raises(HTTPException):
            asyncio.run(
                sbom_upload.upload_sbom(
                    BackgroundTasks(),
                    SimpleNamespace(form=AsyncMock(return_value={})),
                    Response(),
                    file=MagicMock(),
                    sbom_name="test",
                    project_id=None,
                    product_id=None,
                    sbom_type=None,
                    sbom_version=None,
                    product_version=None,
                    productver=None,
                    created_by="forged",
                    logical_sbom_id=None,
                    create_new_logical_sbom=False,
                    parent_sbom_id=None,
                    set_as_current=False,
                    strict_ntia=False,
                    context=actor(),
                    db=MagicMock(),
                )
            )
    assert assigned.call_args.kwargs["actor"] == "actor@example.test"


def test_vex_upload_actor_is_authenticated(monkeypatch):
    from app.routers import vex

    monkeypatch.setattr(vex, "_require_sbom", lambda *a: None)
    imported = MagicMock(return_value={})
    monkeypatch.setattr(vex, "import_vex_document", imported)
    vex.upload_vex_document(1, {"document": {}, "uploaded_by": "forged"}, context=actor(), db=MagicMock())
    assert imported.call_args.kwargs["uploaded_by"] == "actor@example.test"


def test_project_update_actor_is_authenticated(isolated_db):
    from app.schemas import ProjectUpdate

    token = bind_context(actor())
    try:
        projects.update_project(
            1, ProjectUpdate(project_name="Own renamed", modified_by="forged"), context=actor(), db=isolated_db
        )
        assert isolated_db.get(Projects, 1).modified_by == "actor@example.test"
    finally:
        reset_context(token)


@pytest.mark.parametrize("role", ["VIEWER", "DEVELOPER", "SECURITY_ANALYST", "TENANT_ADMIN", "PLATFORM_ADMIN"])
def test_builtin_roles_export_policy(role):
    from app.core.permissions import ROLE_PERMISSIONS

    permissions = ROLE_PERMISSIONS[role]
    context = replace(
        actor(*permissions, tenant_id=None if role == "PLATFORM_ADMIN" else 1, platform=role == "PLATFORM_ADMIN"),
        roles=frozenset({role}),
    )
    assert context.has_permission("sbom:export") == (role in {"SECURITY_ANALYST", "TENANT_ADMIN"})


def test_restore_requires_update_authority(isolated_db):
    with router_client(projects.router, isolated_db, actor("project:create")) as client:
        assert client.post("/api/projects/1/restore").status_code == 403


def test_audit_ip_ignores_forwarding_header():
    from app.services.audit_service import _client_ip
    from starlette.requests import Request

    request = Request(
        {"type": "http", "client": ("192.0.2.1", 123), "headers": [(b"x-forwarded-for", b"198.51.100.9")]}
    )
    assert _client_ip(request) == "192.0.2.1"


def test_unmapped_route_cannot_borrow_known_url_policy():
    app = FastAPI()
    app.dependency_overrides[get_current_tenant_context] = lambda: actor("project:read")
    app.dependency_overrides[get_db] = lambda: MagicMock()

    @app.get("/api/{operation}", dependencies=[Depends(enforce_request_access)])
    def handler(operation: str):
        return {"unexpected": True}

    with TestClient(app) as client:
        assert client.get("/api/projects").status_code == 403


def test_registration_rejects_lookalike_permission_dependency():
    from app.core.route_policy import validate_route_policies

    app = FastAPI()
    permission = "project:read"

    def fake_guard():
        return permission

    @app.get("/api/projects", dependencies=[Depends(fake_guard)])
    def handler():
        return {}

    with pytest.raises(RuntimeError, match="missing permission guard"):
        validate_route_policies(app)


@pytest.mark.parametrize(
    "method,template,path,permission",
    [
        ("GET", "/api/projects/{project_id}", "/api/projects/1", "project:read"),
        ("POST", "/api/projects", "/api/projects", "project:create"),
        ("PUT", "/api/lifecycle/component/{component_id}", "/api/lifecycle/component/1", "lifecycle:override"),
        ("PATCH", "/api/projects/{project_id}", "/api/projects/1", "project:update"),
        ("DELETE", "/api/projects/{project_id}", "/api/projects/1", "project:delete"),
    ],
)
@pytest.mark.parametrize("role", ["VIEWER", "DEVELOPER", "SECURITY_ANALYST", "TENANT_ADMIN", "PLATFORM_ADMIN"])
def test_http_role_method_matrix(method, template, path, permission, role):
    from app.core.permissions import ROLE_PERMISSIONS

    context = replace(
        actor(
            *ROLE_PERMISSIONS[role],
            tenant_id=None if role == "PLATFORM_ADMIN" else 1,
            platform=role == "PLATFORM_ADMIN",
        ),
        roles=frozenset({role}),
    )
    db = MagicMock()
    app = FastAPI()
    app.dependency_overrides[get_current_tenant_context] = lambda: context
    app.dependency_overrides[get_db] = lambda: db

    def handler():
        db.execute("business operation sentinel")
        return {"ok": True}

    app.add_api_route(template, handler, methods=[method], dependencies=[Depends(enforce_request_access)])
    with TestClient(app) as client:
        response = client.request(method, path)
    allowed = context.has_permission(permission)
    assert response.status_code == (200 if allowed else 403)
    assert db.execute.call_count == (1 if allowed else 0)


@pytest.mark.parametrize("owns_run", [False, True])
def test_ai_worker_ownership_precedes_execution_and_progress_writes(monkeypatch, owns_run):
    from types import SimpleNamespace

    import app.db
    from app.workers import ai_fix_tasks

    db = MagicMock()
    db.scalar.return_value = 1 if owns_run else None
    monkeypatch.setattr(app.db, "SessionLocal", lambda: db)
    monkeypatch.setattr(ai_fix_tasks, "authorize_job_actor", lambda *a, **kw: actor("analysis:run"))
    monkeypatch.setattr(ai_fix_tasks, "evaluate_access", lambda **kw: SimpleNamespace(allowed=True))
    pipeline = MagicMock()
    monkeypatch.setattr(ai_fix_tasks, "AiFixBatchPipeline", pipeline)
    monkeypatch.setattr(ai_fix_tasks, "build_budget_guard", lambda **kw: object())
    store = MagicMock()
    monkeypatch.setattr(ai_fix_tasks, "get_progress_store", lambda: store)

    async def completed(*a, **kw):
        return SimpleNamespace(
            progress=SimpleNamespace(
                status="completed",
                generated=1,
                from_cache=0,
                failed=0,
                cost_so_far_usd=0,
                model_dump=lambda **kw: {"status": "completed"},
            )
        )

    monkeypatch.setattr(ai_fix_tasks, "_run_pipeline_with_http_client", completed)
    result = ai_fix_tasks.generate_run_fixes.run(1, tenant_id=1, actor_user_id=1)
    assert result["status"] == ("completed" if owns_run else "failed")
    assert pipeline.call_count == (1 if owns_run else 0)
    if not owns_run:
        store.write.assert_not_called()
