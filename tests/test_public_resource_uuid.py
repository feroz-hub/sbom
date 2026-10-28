"""Real PostgreSQL identities and authorized HTTP selectors for revision 102."""

import json
from datetime import UTC, datetime
from uuid import UUID, uuid1, uuid4

import pytest
from app.db import SessionLocal, engine
from app.models import AnalysisRun, PlatformUserRole, SBOMSource, TenantUser
from sqlalchemy import event, text
from sqlalchemy.exc import IntegrityError

from tests.phase6_helpers import seed_membership, seed_platform_grant, seed_user
from tests.public_id_fixture import public_row, tenant_uuid
from tests.tenant_fixture_scope import verified_fixture_tenant

MODELS = (TenantUser, PlatformUserRole, AnalysisRun)


def uuid(value):
    result = UUID(str(value))
    assert result.version == 4 and result.variant == "specified in RFC 4122"
    return result


def seed(db, model):
    if model is TenantUser:
        return seed_membership(db, seed_user(db))
    if model is PlatformUserRole:
        return seed_platform_grant(db, seed_user(db))
    source = SBOMSource(sbom_name="Synthetic Run UUID", sbom_data="{}", tenant_id=1)
    db.add(source)
    db.flush()
    now = datetime.now(UTC).isoformat()
    run = AnalysisRun(tenant_id=1, sbom_id=source.id, source="OSV", run_status="OK", started_on=now, completed_on=now)
    db.add(run)
    db.flush()
    return run


@pytest.mark.parametrize("model", MODELS)
def test_uuid_persists_without_changing_internal_keys(client, model):
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        row = seed(db, model)
        internal, public = row.id, row.public_id
        assert type(internal) is int
        uuid(public)
        db.commit()
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        row = db.get(model, internal)
        assert row.public_id == public
        row.updated_at = datetime.now(UTC) if model is not AnalysisRun else None
        if model is AnalysisRun:
            row.duration_ms = 5
        db.commit()
        assert row.public_id == public


@pytest.mark.parametrize("model", MODELS)
@pytest.mark.parametrize(
    "bad,state", [(str(uuid1()), "23514"), ("00000000-0000-4000-7000-000000000001", "23514"), ("invalid", "22P02")]
)
def test_invalid_uuid_version_variant_or_syntax_refuses(client, model, bad, state):
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        row = seed(db, model)
        uid = row.id
        db.commit()
    with engine.connect() as c:
        with pytest.raises(Exception) as exc:
            c.execute(
                text(f"UPDATE {model.__tablename__} SET public_id=CAST(:uuid AS uuid) WHERE id=:id"),
                {"uuid": bad, "id": uid},
            )
        assert exc.value.orig.sqlstate == state
        c.rollback()


@pytest.mark.parametrize("model", MODELS)
def test_unique_not_null_immutable_and_same_value_update(client, model):
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        first, second = seed(db, model), seed(db, model)
        uid, public = first.id, second.public_id
        db.commit()
    for identity, expected in [(uuid4(), "23514"), (public, "23505"), (None, "23502")]:
        with engine.connect() as c:
            with pytest.raises(IntegrityError) as exc:
                c.execute(
                    text(f"UPDATE {model.__tablename__} SET public_id=:uuid WHERE id=:id"),
                    {"uuid": identity, "id": uid},
                )
            assert exc.value.orig.sqlstate == expected
            c.rollback()
    with engine.begin() as c:
        c.execute(text(f"UPDATE {model.__tablename__} SET public_id=public_id WHERE id=:id"), {"id": uid})


@pytest.mark.parametrize("model", MODELS)
def test_database_omitted_and_explicit_null_allocator_and_rollback(client, model):
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        row = seed(db, model)
        uid = row.id
        db.commit()
    # Clone the exact synthetic row, excluding PK/public ID. Avoid unrelated
    # membership/user uniqueness by using a new synthetic parent where needed.
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        base = seed(db, model)
        values = {
            col.name: getattr(base, col.name) for col in model.__table__.columns if col.name not in {"id", "public_id"}
        }
        db.rollback()
    # Reuse committed parent keys, removing the owned row inside the transaction.
    with engine.connect() as c:
        original = c.execute(text(f"SELECT * FROM {model.__tablename__} WHERE id=:id"), {"id": uid}).mappings().one()
        cols = [key for key in original if key not in {"id", "public_id"}]
        c.execute(text(f"DELETE FROM {model.__tablename__} WHERE id=:id"), {"id": uid})
        identities = []
        for explicit in (False, True):
            names = cols + (["public_id"] if explicit else [])
            params = {key: original[key] for key in cols}
            if explicit:
                params["public_id"] = None
            inserted = c.execute(model.__table__.insert().values(**params).returning(model.public_id)).scalar_one()
            uuid(inserted)
            identities.append(inserted)
            c.execute(text(f"DELETE FROM {model.__tablename__} WHERE public_id=:uuid"), {"uuid": inserted})
        assert len(set(identities)) == 2
        c.rollback()
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        assert db.get(model, uid) is not None


def test_analysis_create_read_list_and_integer_rejection(client, sample_sbom_dict, mock_external_sources):
    response = client.post(
        "/api/sboms", json={"sbom_name": "UUID Run Boundary", "sbom_data": json.dumps(sample_sbom_dict)}
    )
    assert response.status_code == 201, response.text
    sbom = response.json()["id"]
    response = client.post(f"/api/sboms/{sbom}/analyze", json={"sources": ["OSV"]})
    assert response.status_code == 201, response.text
    identity = response.json()["id"]
    uuid(identity)
    result = client.get(f"/api/runs/{identity}")
    assert result.status_code == 200, result.text
    assert result.json()["id"] == identity
    assert client.get(f"/api/sboms/{sbom}/analysis-runs").json()[0]["id"] == identity
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        row = public_row(db, AnalysisRun, identity)
        internal = row.id
    assert client.get(f"/api/runs/{internal}").status_code == 422
    assert client.get(f"/api/runs/{uuid4()}").status_code == 404
    assert client.get(f"/api/runs/{identity}/findings").status_code == 200
    compare = client.get("/api/analysis-runs/compare", params={"run_a": identity, "run_b": identity})
    assert compare.status_code == 200, compare.text
    assert compare.json()["run_a"]["id"] == identity
    assert client.get("/api/analysis-runs/compare", params={"run_a": internal, "run_b": internal}).status_code == 422


@pytest.mark.parametrize(
    "selector",
    [
        "1",
        "12345678123442348234123456781234",
        "invalid",
        "00000000-0000-4000-7000-000000000001",
        "111111111-111-4111-8111-111111111111",
    ],
)
def test_public_membership_and_run_invalid_selectors_refuse(client, selector):
    tenant = tenant_uuid(1)
    assert client.get(f"/api/tenants/{tenant}/users/{selector}").status_code == 422
    assert client.get(f"/api/runs/{selector}").status_code == 422


def test_membership_wire_identity_is_distinct_from_user_and_other_tenants(client):
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        user = seed_user(db)
        member = seed_membership(db, user)
        identity, user_id = str(member.public_id), str(user.public_id)
        db.commit()
    result = client.get(f"/api/tenants/{tenant_uuid(1)}/users/{identity}")
    assert result.status_code == 200, result.text
    assert result.json()["membership_id"] == identity
    assert result.json()["user_id"] == user_id
    assert identity != user_id
    assert client.get(f"/api/tenants/{tenant_uuid(1)}/users/{user_id}").status_code == 404


def test_new_public_reference_lookups_are_batched(client):
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        for _ in range(15):
            seed_membership(db, seed_user(db))
        db.commit()
    queries = []

    def record(c, cur, sql, p, ctx, many):
        if sql.startswith("SELECT tenant_users.id, tenant_users.public_id"):
            queries.append(sql)

    event.listen(engine, "before_cursor_execute", record)
    try:
        response = client.get(f"/api/tenants/{tenant_uuid(1)}/users")
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert response.status_code == 200, response.text
    assert len(queries) == 1
    for row in response.json():
        uuid(row["membership_id"])


def test_openapi_selected_resource_contracts(client):
    doc = client.get("/openapi.json").json()
    for path, key in [
        ("/api/runs/{run_id}", "run_id"),
        ("/api/platform/administrators/{grant_id}", "grant_id"),
        ("/api/tenants/{tenant_id}/users/{membership_id}", "membership_id"),
    ]:
        op = next(iter(doc["paths"][path].values()))
        assert next(p for p in op["parameters"] if p["name"] == key)["schema"]["format"] == "uuid"
    assert doc["components"]["schemas"]["AnalysisRunOut"]["properties"]["id"]["format"] == "uuid"


@pytest.mark.parametrize("model", MODELS)
def test_concurrent_creation_has_unique_stable_public_ids(client, model):
    from concurrent.futures import ThreadPoolExecutor

    def create(_):
        with SessionLocal() as db, verified_fixture_tenant(db, 1):
            row = seed(db, model)
            key, public = row.id, row.public_id
            db.commit()
            return key, public

    with ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(pool.map(create, range(6)))
    assert len({key for key, _ in rows}) == 6
    assert len({public for _, public in rows}) == 6
    for _, public in rows:
        uuid(public)


def test_report_export_projects_runs_and_retains_unrelated_event_ids(client):
    from app.services.report_composer import public_report_snapshot

    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        run = seed(db, AnalysisRun)
        report = {
            "sboms": [
                {
                    "id": run.sbom_id,
                    "A": {"run_id": run.id},
                    "comparison": {"run_a": {"id": run.id}, "run_b": {"id": run.id}},
                }
            ],
            "event_id": 71,
        }
        result = public_report_snapshot(db, report, 1)
        assert result["sboms"][0]["A"]["run_id"] == str(run.public_id)
        assert result["sboms"][0]["comparison"]["run_a"]["id"] == str(run.public_id)
        assert result["event_id"] == 71 and report["sboms"][0]["A"]["run_id"] == run.id


def test_stream_translation_uses_authorized_cache_without_worker_id_changes():
    from app.resource_stream import run_payload

    identity = str(uuid4())
    original = {"run_id": 17, "batch_id": "task-123", "generated": 4, "items": [{"finding_id": 9}]}
    result = run_payload(original, {("analysis_run", 17): identity})
    assert result == {**original, "run_id": identity}
    assert original["run_id"] == 17
    with pytest.raises(RuntimeError, match="Unresolvable"):
        run_payload(original, {})


def test_stream_fragmented_utf8_keeps_events_counters_and_run_uuid():
    import asyncio

    from app.resource_stream import translate_run_stream

    public = str(uuid4())
    frame = (
        "event: progress\ndata: " + json.dumps({"run_id": 17, "label": "café", "count": 2}, ensure_ascii=False) + "\n\n"
    ).encode()

    async def chunks():
        for byte in frame:
            yield bytes([byte])

    async def collect():
        return b"".join([chunk async for chunk in translate_run_stream(chunks(), {("analysis_run", 17): public})])

    output = asyncio.run(collect()).decode()
    assert output.startswith("event: progress\n")
    assert json.loads(output.split("data: ")[1]) == {"run_id": public, "label": "café", "count": 2}


def test_untyped_openapi_membership_run_and_namespaced_assignee_contracts(client):
    schemas = client.app.openapi()["components"]["schemas"]
    assert schemas["PublicMembershipReference"]["properties"]["membership_id"]["format"] == "uuid"
    assert schemas["PublicRunReference"]["properties"]["id"]["format"] == "uuid"
    assert "membership:" in schemas["PublicVexAssignee"]["properties"]["id"]["pattern"]
    assert schemas["PlatformGrantSummary"]["properties"]["grant_id"]["format"] == "uuid"


def test_platform_request_audit_uses_global_stream_with_correct_internal_actor(client):
    from app.models import AuthorizationAuditLog
    from sqlalchemy import select

    from tests.phase6_helpers import seed_dev_platform_admin

    with SessionLocal() as db:
        admin, _ = seed_dev_platform_admin(db)
        target = seed_user(db)
        actor, public = admin.id, str(target.public_id)
        db.commit()
    response = client.post("/api/platform/administrators", json={"user_id": public})
    assert response.status_code == 201, response.text
    uuid(response.json()["grant_id"])
    with SessionLocal() as db:
        rows = list(db.scalars(select(AuthorizationAuditLog).where(AuthorizationAuditLog.action == "api.post")))
        assert rows and any(row.actor_user_id == actor and row.tenant_id is None for row in rows)
