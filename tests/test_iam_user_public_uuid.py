"""Real PostgreSQL IAM public-identity and authorized HTTP boundary acceptance."""
from concurrent.futures import ThreadPoolExecutor
from uuid import NAMESPACE_DNS, RFC_4122, UUID, uuid1, uuid4, uuid5

import pytest
from app.db import SessionLocal, engine
from app.models import IAMUser, TenantUser
from sqlalchemy import event, select, text
from sqlalchemy.exc import IntegrityError

from tests.phase6_helpers import seed_membership, seed_user
from tests.public_id_fixture import membership_uuid, tenant_uuid
from tests.tenant_fixture_scope import verified_fixture_tenant


def assert_uuid(value):
    result = UUID(str(value))
    assert result.version == 4 and result.variant == RFC_4122
    return result


def test_native_uuid_persists_and_retains_integer_keys(client):
    with SessionLocal() as db:
        user = seed_user(db)
        member = seed_membership(db, user)
        original, membership = user.id, member.id
        identity = user.public_id
        db.commit()
    with SessionLocal() as db:
        user = db.get(IAMUser, original)
        assert type(user.id) is int
        assert user.public_id == identity
        assert_uuid(identity)
        assert db.get(TenantUser, membership).user_id == original


@pytest.mark.parametrize("explicit_null", [False, True])
def test_database_allocator_omitted_and_explicit_null(client, explicit_null):
    with engine.begin() as c:
        columns, values = (",public_id", ",NULL") if explicit_null else ("", "")
        result = c.exec_driver_sql(
            "INSERT INTO iam_users(status,email_verified,verification_required,created_at,updated_at"
            + columns
            + ") VALUES('ACTIVE',false,true,now(),now()"
            + values
            + ") RETURNING id,public_id"
        ).one()
        assert_uuid(result.public_id)
    with engine.connect() as c:
        assert (
            c.execute(text("SELECT public_id FROM iam_users WHERE id=:id"), {"id": result.id}).scalar_one()
            == result.public_id
        )


@pytest.mark.parametrize(
    "bad",
    [
        str(uuid1()),
        str(uuid5(NAMESPACE_DNS, "synthetic.example")),
        "00000000-0000-0000-0000-000000000000",
        "00000000-0000-4000-7000-000000000001",
        "invalid",
    ],
)
def test_database_invalid_uuid_is_rejected_with_real_sqlstate(client, bad):
    with engine.connect() as c:
        with pytest.raises(Exception) as exc:
            c.execute(
                text(
                    "INSERT INTO iam_users(public_id,status,email_verified,verification_required,created_at,updated_at) VALUES(CAST(:uuid AS uuid),'ACTIVE',false,true,now(),now())"
                ),
                {"uuid": bad},
            )
        assert exc.value.orig.sqlstate == ("22P02" if bad == "invalid" else "23514")
        c.rollback()


def test_unique_constraint_and_immutability(client):
    with SessionLocal() as db:
        user = seed_user(db)
        uid, identity = user.id, user.public_id
        db.commit()
    for query, values, state in [
        ("UPDATE iam_users SET public_id=:uuid WHERE id=:id", {"uuid": uuid4(), "id": uid}, "23514"),
        ("UPDATE iam_users SET public_id=NULL WHERE id=:id", {"id": uid}, "23502"),
        (
            "INSERT INTO iam_users(public_id,status,email_verified,verification_required,created_at,updated_at) VALUES(:uuid,'ACTIVE',false,true,now(),now())",
            {"uuid": identity},
            "23505",
        ),
    ]:
        with engine.connect() as c:
            with pytest.raises(IntegrityError) as exc:
                c.execute(text(query), values)
            assert exc.value.orig.sqlstate == state
            c.rollback()
    with engine.begin() as c:
        c.execute(
            text("UPDATE iam_users SET public_id=public_id,department=:department WHERE id=:id"),
            {"department": "Synthetic", "id": uid},
        )
    with SessionLocal() as db:
        assert db.get(IAMUser, uid).public_id == identity


def test_concurrent_allocation_and_rollback(client):
    def insert(_):
        with engine.begin() as c:
            return c.exec_driver_sql(
                "INSERT INTO iam_users(status,email_verified,verification_required,created_at,updated_at) VALUES('ACTIVE',false,true,now(),now()) RETURNING public_id"
            ).scalar_one()

    with ThreadPoolExecutor(max_workers=2) as pool:
        ids = list(pool.map(insert, range(8)))
    assert len(set(ids)) == 8
    for value in ids:
        assert_uuid(value)
    with engine.connect() as c:
        identity = c.exec_driver_sql(
            "INSERT INTO iam_users(status,email_verified,verification_required,created_at,updated_at) VALUES('ACTIVE',false,true,now(),now()) RETURNING public_id"
        ).scalar_one()
        c.rollback()
    with engine.connect() as c:
        assert (
            c.execute(text("SELECT count(*) FROM iam_users WHERE public_id=:uuid"), {"uuid": identity}).scalar_one()
            == 0
        )


def test_auth_context_has_public_user_but_provider_identity_unchanged(client):
    response = client.get("/api/auth/me")
    assert response.status_code == 200, response.text
    body = response.json()
    assert_uuid(body["user_id"])
    assert body["auth_context"]["user"]["id"] == body["user_id"]
    assert body["external_user_id"] == "dev-user"
    with SessionLocal() as db:
        user = db.scalar(select(IAMUser).where(IAMUser.public_id == UUID(body["user_id"])))
        assert isinstance(user.id, int)


def test_member_search_add_roles_membership_detail_and_remove(client):
    with SessionLocal() as db:
        user = seed_user(db, display_name="Synthetic UUID candidate")
        identity = str(user.public_id)
        db.commit()
    tenant = tenant_uuid(1)
    response = client.get(f"/api/tenants/{tenant}/user-candidates?q=Synthetic")
    assert response.status_code == 200, response.text
    assert identity in {r["id"] for r in response.json()["items"]}
    response = client.post(f"/api/tenants/{tenant}/users", json={"user_id": identity, "roles": ["VIEWER"]})
    assert response.status_code == 201, response.text
    member = response.json()
    assert_uuid(member["membership_id"])
    assert member["user_id"] == identity
    response = client.get(f"/api/tenants/{tenant}/users/{identity}/roles")
    assert response.status_code == 200, response.text
    state = response.json()
    assert state["user_id"] == identity
    response = client.put(
        f"/api/tenants/{tenant}/users/{identity}/roles",
        json={
            "role_codes": ["DEVELOPER"],
            "primary_role_code": "DEVELOPER",
            "expected_version": state["role_assignment_version"],
        },
    )
    assert response.status_code == 200, response.text
    response = client.get(f"/api/tenants/{tenant}/users/{membership_uuid(member['membership_id'])}")
    assert response.status_code == 200 and response.json()["user_id"] == identity
    assert client.delete(f"/api/tenants/{tenant}/users/{membership_uuid(member['membership_id'])}").status_code == 204


@pytest.mark.parametrize(
    "identifier",
    [
        "1",
        "not-a-uuid",
        12345678123442348234123456781234,
        "12345678123442348234123456781234",
        str(uuid1()),
        str(uuid5(NAMESPACE_DNS, "synthetic.example")),
    ],
)
def test_bad_user_paths_and_body_refuse_422(client, identifier):
    tenant = tenant_uuid(1)
    assert client.get(f"/api/tenants/{tenant}/users/{identifier}/roles").status_code == 422
    response = client.post(f"/api/tenants/{tenant}/users", json={"user_id": identifier, "roles": ["VIEWER"]})
    assert response.status_code == 422, response.text


def test_nonexistent_and_nonmember_are_concealed(client):
    with SessionLocal() as db:
        user = seed_user(db)
        identity = str(user.public_id)
        db.commit()
    for value in (str(uuid4()), identity):
        assert client.get(f"/api/tenants/{tenant_uuid(1)}/users/{value}/roles").status_code == 404


def test_platform_policy_is_not_widened_to_discover_users(client):
    assert client.get("/api/platform/users").status_code == 403
    assert client.get(f"/api/platform/users/{uuid4()}").status_code == 403


def test_user_and_membership_serialization_is_batched(client):
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        for _ in range(12):
            seed_membership(db, seed_user(db))
        db.commit()
    queries = []

    def record(_c, _cur, sql, _p, _ctx, _many):
        if sql.startswith("SELECT iam_users.id, iam_users.public_id"):
            queries.append(sql)

    event.listen(engine, "before_cursor_execute", record)
    try:
        response = client.get(f"/api/tenants/{tenant_uuid(1)}/users")
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert response.status_code == 200, response.text
    for member in response.json():
        assert_uuid(member["user_id"])
        assert_uuid(member["membership_id"])
    assert len(queries) == 1


def test_openapi_user_and_membership_contract_is_uuid(client):
    doc = client.get("/openapi.json").json()
    for name in ("AuthContextUser", "PlatformUserSummary", "UserSearchResult", "TenantUserCandidate"):
        assert doc["components"]["schemas"][name]["properties"]["id"]["format"] == "uuid"
    paths = doc["paths"]
    fields = paths["/api/tenants/{tenant_id}/users/{user_id}/roles"]["get"]["parameters"]
    assert next(x for x in fields if x["name"] == "user_id")["schema"]["format"] == "uuid"
    fields = paths["/api/tenants/{tenant_id}/users/{membership_id}"]["get"]["parameters"]
    assert next(x for x in fields if x["name"] == "membership_id")["schema"]["format"] == "uuid"


def test_numeric_uuid_shaped_json_integer_refuses_before_lookup(client):
    value = 12345678123442348234123456781234
    assert UUID(str(value)).version == 4  # Demonstrate why UUID(str(value)) alone is insufficient.
    response = client.post(f"/api/tenants/{tenant_uuid(1)}/users", json={"user_id": value, "roles": ["VIEWER"]})
    assert response.status_code == 422, response.text


def test_platform_user_audit_event_id_is_not_a_user_reference(client):
    """Only serializer semantics: real endpoint privacy remains covered separately."""
    from app.core.context import CurrentContext
    from app.public_api import install_public_boundary
    from fastapi import APIRouter, FastAPI, Request
    from fastapi.testclient import TestClient

    with SessionLocal() as db:
        user = seed_user(db)
        uid, public = user.id, str(user.public_id)
        db.commit()

    projection = FastAPI()
    router = APIRouter()

    @projection.middleware("http")
    async def authorized_projection(request: Request, call_next):
        request.state.current_context = CurrentContext(
            user_id=uid,
            external_user_id="synthetic-audit-reader",
            email=None,
            display_name=None,
            tenant_id=None,
            external_tenant_id=None,
            roles=frozenset(),
            permissions=frozenset({"platform:user:read"}),
            is_platform_admin=True,
        )
        return await call_next(request)

    @router.get("/api/platform/users/{user_id}/audit")
    def audit(user_id: int):
        assert user_id == uid
        return {"items": [{"id": 900001, "action": "SYNTHETIC_AUDIT", "actor_user_id": uid}]}

    projection.include_router(router)
    install_public_boundary(projection)
    with TestClient(projection) as wire:
        response = wire.get(f"/api/platform/users/{public}/audit")
    assert response.status_code == 200, response.text
    record = response.json()["items"][0]
    assert record["id"] == 900001
    assert record["actor_user_id"] == public


def test_validation_error_retains_public_user_input_not_internal_key(client):
    with SessionLocal() as db:
        user = seed_user(db)
        public = str(user.public_id)
        db.commit()
    response = client.post(f"/api/tenants/{tenant_uuid(1)}/users", json={"user_id": public, "roles": []})
    assert response.status_code == 422, response.text
    error = next(item for item in response.json()["detail"] if item["loc"] == ["body"])
    assert error["input"]["user_id"] == public


def test_registered_native_validation_redaction_is_preserved(client):
    from app import error_handlers
    from app.public_api import install_public_boundary
    from app.routers.native_auth import Activation
    from fastapi import APIRouter, FastAPI
    from fastapi.testclient import TestClient

    protected = FastAPI()
    routes = APIRouter()

    @routes.post("/api/auth/native/activate")
    def activate(payload: Activation):
        raise AssertionError("Invalid sensitive payload reached the endpoint")

    protected.include_router(routes)
    error_handlers.install(protected)
    install_public_boundary(protected)
    marker = "synthetic-sensitive-validation-value"
    with TestClient(protected) as wire:
        response = wire.post("/api/auth/native/activate", json={"token": marker, "password": {"secret": marker}})
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid authentication input"}
    assert marker not in response.text
