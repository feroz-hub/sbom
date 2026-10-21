"""UUID response translation is bounded and retains its tenant/native boundaries."""
from contextlib import contextmanager

import pytest
from app.core.context import CurrentContext
from app.db import SessionLocal, engine
from app.models import Projects
from app.public_api import install_public_boundary
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import event

from tests.tenant_fixture_scope import declare_fixture_tenant, scoped_context_override, verified_fixture_tenant


@contextmanager
def serialization_client(payload, owner=1):
    context = CurrentContext(user_id=1, external_user_id="serializer-unit", email=None, display_name=None,
                             tenant_id=owner, external_tenant_id=None, roles=frozenset(), permissions=frozenset())
    local = FastAPI()
    router = APIRouter()
    dependency = scoped_context_override(lambda: context)

    @router.get('/api/serialization-unit', dependencies=[Depends(dependency)])
    def rows():
        return payload

    local.include_router(router)
    install_public_boundary(local)
    with TestClient(local) as client:
        yield client


@pytest.fixture
def projects(client):
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        declare_fixture_tenant(db, 2)
        rows = [Projects(project_name=f"batch-identity-{i}") for i in range(12)]
        db.add_all(rows)
        db.commit()
        return [(row.id, str(row.public_id)) for row in rows]


def test_distinct_references_use_one_scoped_lookup_not_one_per_row(projects):
    statements = []
    def record(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().upper().startswith('SELECT') and 'projects.public_id' in statement:
            statements.append(statement)
    payload = {'projects': [{'id': internal, 'name': str(i)} for i, (internal, _) in enumerate(projects)]}
    event.listen(engine, 'before_cursor_execute', record)
    try:
        with serialization_client(payload) as client:
            response = client.get('/api/serialization-unit')
    finally:
        event.remove(engine, 'before_cursor_execute', record)
    assert response.status_code == 200
    assert [row['id'] for row in response.json()['projects']] == [public for _, public in projects]
    assert len(statements) == 1, f"Expected one scoped batch query; observed {len(statements)}"
    assert all('tenant_id' in sql for sql in statements)


def test_repeated_ids_native_documents_and_integer_nonresources_stay_distinct(projects):
    internal, public = projects[0]
    payload = {'projects': [{'id': internal}, {'id': internal}], 'row_version': internal,
               'metadata_json': {'project_id': internal}, 'raw_document': {'products': [{'id': internal}]},
               'versions': [{'id': internal}], 'run_id': internal}
    with serialization_client(payload) as client:
        response = client.get('/api/serialization-unit')
    assert response.status_code == 200
    body = response.json()
    assert body['projects'] == [{'id': public}, {'id': public}]
    for key in ('row_version', 'metadata_json', 'raw_document', 'versions', 'run_id'):
        assert body[key] == payload[key]


def test_foreign_reference_cannot_be_resolved_under_another_owner(projects):
    internal, public = projects[0]
    with serialization_client({'projects': [{'id': internal}]}, owner=2) as client:
        response = client.get('/api/serialization-unit')
    assert response.status_code == 500
    assert response.json() == {'detail': 'Unresolvable public resource reference'}
    assert public not in response.text


def test_missing_reference_fails_closed(projects):
    with serialization_client({'projects': [{'id': max(i for i, _ in projects) + 1000}]}) as client:
        response = client.get('/api/serialization-unit')
    assert response.status_code == 500
    assert response.json() == {'detail': 'Unresolvable public resource reference'}


def test_more_than_one_lookup_chunk_preserves_every_uuid(client):
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        rows = [Projects(project_name=f"chunked-identity-{i}") for i in range(501)]
        db.add_all(rows)
        db.commit()
        references = [(row.id, str(row.public_id)) for row in rows]
    statements = []
    def record(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().upper().startswith("SELECT") and "projects.public_id" in statement:
            statements.append(statement)
    event.listen(engine, "before_cursor_execute", record)
    try:
        with serialization_client({"projects": [{"id": internal} for internal, _ in references]}) as api:
            response = api.get("/api/serialization-unit")
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert response.status_code == 200
    assert [row["id"] for row in response.json()["projects"]] == [public for _, public in references]
    assert len(statements) == 2
