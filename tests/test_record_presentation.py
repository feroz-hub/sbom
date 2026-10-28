"""No database connections: exercise the actual HTTP projection with scoped rows."""

from types import SimpleNamespace
from uuid import uuid4

import pytest
from app.core.context import CurrentContext
from app.db import get_db
from app.public_api import install_public_boundary, install_public_openapi
from app.record_presentation import ENTITIES, add_display, augment_openapi
from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient


class Rows(list):
    def all(self):
        return self

    def first(self):
        return self[0] if self else None


class Database:
    def __init__(self):
        self.calls = []
        self.public = {}

    def execute(self, statement):
        self.calls.append(statement)
        name = statement.get_final_froms()[0].name
        params = statement.compile().params
        if name not in {"iam_users", "tenants", "platform_user_roles"}:
            assert 7 in params.values(), "all business queries must retain tenant scoping"
        ids = next((v for v in params.values() if isinstance(v, list)), None)
        if ids is None:
            ids = [i for (table, i), public in self.public.items() if table == name and public in params.values()]
        return Rows(SimpleNamespace(id=i, public_id=self.public.setdefault((name, i), uuid4())) for i in ids)


@pytest.fixture
def wire():
    db = Database()
    app = FastAPI()
    router = APIRouter()

    @app.middleware("http")
    async def context(request: Request, call_next):
        request.state.current_context = CurrentContext(
            user_id=9,
            external_user_id="synthetic",
            email=None,
            display_name=None,
            tenant_id=7,
            external_tenant_id=None,
            roles=frozenset(),
            permissions=frozenset(),
            is_platform_admin=False,
        )
        request.state.public_identity_session = db
        return await call_next(request)

    app.dependency_overrides[get_db] = lambda: db

    @router.get("/api/projects")
    def projects():
        return [{"id": i, "project_name": f"Project {i}"} for i in range(1, 602)]

    @router.get("/api/products/{product_id}")
    def product(product_id: int):
        return {
            "id": product_id,
            "latest_sbom_id": 567,
            "current_sbom_id": 566,
            "project_id": 45,
            "metadata_json": {"id": "native-document-id"},
        }

    @router.get("/api/runs")
    def runs():
        return [{"id": 891, "sbom_id": 567, "sbom_display_id": None, "findings": [{"id": 44, "severity": "LOW"}]}]

    @router.get("/api/v1/runs/{run_id}/ai-fixes")
    def progress(run_id: int):
        return {"run_id": run_id, "batch_id": "synthetic", "status": "complete"}

    @router.get("/api/tenants/{tenant_id}/user-candidates")
    def candidates(tenant_id: int):
        return [{"id": 23, "display_name": "Authorized candidate"}]

    @router.get("/api/projects/{project_id}")
    def project(project_id: int):
        return {"id": project_id}

    @router.patch("/api/products/{product_id}")
    def change(product_id: int, body: dict):
        return body

    @router.get("/api/runs/{run_id}")
    def rejected(run_id: int):
        raise HTTPException(403, {"run_id": run_id, "message": "Insufficient permission"})

    app.include_router(router)
    install_public_boundary(app)
    install_public_openapi(app)
    with TestClient(app) as client:
        yield client, db


@pytest.mark.parametrize("entity", sorted(ENTITIES))
def test_only_actual_positive_persisted_integer_is_labelled(entity):
    result = {}
    add_display(result, "id", entity, 123)
    assert result == {"display_id": 123}


@pytest.mark.parametrize("bad", [None, 0, -1, True, 1.5, "123", str(uuid4()), 2**53])
def test_missing_or_invalid_keys_never_invent_label(bad):
    result = {}
    add_display(result, "id", "projects", bad)
    assert result == {}


@pytest.mark.parametrize("entity", ["tenants", "iam_users", "tenant_users", "platform_user_roles", None])
def test_sensitive_sequences_stay_private(entity):
    result = {}
    add_display(result, "id", entity, 23)
    assert not result


def test_list_projection_keeps_uuid_and_bounded_tenant_queries(wire):
    client, db = wire
    response = client.get("/api/projects")
    assert response.status_code == 200
    assert len(db.calls) == 2  # 500 + 101, not one query per row
    assert response.json()[122] == {
        "id": str(db.public[("projects", 123)]),
        "display_id": 123,
        "project_name": "Project 123",
    }


def test_related_sboms_are_distinct_and_use_existing_projection_batches(wire):
    client, db = wire
    public = uuid4()
    db.public[("products", 45)] = public
    response = client.get(f"/api/products/{public}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(public) and data["display_id"] == 45
    assert data["latest_sbom_display_id"] == 567 and data["current_sbom_display_id"] == 566
    assert data["latest_sbom_id"] == str(db.public[("sbom_source", 567)])
    assert data["metadata_json"] == {"id": "native-document-id"}
    assert len(db.calls) == 3  # selector, batched SBOMs, batched project


def test_runs_keep_findings_ids_separate(wire):
    client, _ = wire
    data = client.get("/api/runs").json()[0]
    assert data["display_id"] == 891 and data["sbom_display_id"] == 567
    assert data["findings"] == [{"id": 44, "severity": "LOW"}]


def test_operational_ai_progress_contract_is_unchanged(wire):
    client, db = wire
    public = uuid4()
    db.public[("analysis_run", 891)] = public
    response = client.get(f"/api/v1/runs/{public}/ai-fixes")
    assert response.status_code == 200
    assert response.json() == {"run_id": str(public), "batch_id": "synthetic", "status": "complete"}


def test_iam_candidate_does_not_disclose_global_sequence(wire):
    client, db = wire
    public = uuid4()
    db.public[("tenants", 7)] = public
    response = client.get(f"/api/tenants/{public}/user-candidates")
    assert response.status_code == 200
    assert response.json() == [{"id": str(db.public[("iam_users", 23)]), "display_name": "Authorized candidate"}]


@pytest.mark.parametrize("selector", ["123", "not-a-uuid", "00000000-0000-1000-8000-000000000001"])
def test_integer_and_invalid_selectors_remain_422_without_query(wire, selector):
    client, db = wire
    assert client.get("/api/projects/" + selector).status_code == 422
    assert not db.calls


def test_foreign_or_missing_resource_remains_concealed(wire):
    client, db = wire
    assert client.get("/api/projects/" + str(uuid4())).status_code == 404
    assert len(db.calls) == 1


def test_errors_never_gain_display_labels(wire):
    client, db = wire
    public = uuid4()
    db.public[("analysis_run", 891)] = public
    response = client.get(f"/api/runs/{public}")
    assert response.status_code == 403
    assert response.json()["detail"]["run_id"] == str(public)
    assert "display_id" not in response.text and "891" not in response.text


@pytest.mark.parametrize("field", ["display_id", "project_display_id", "current_sbom_display_id"])
def test_output_only_fields_refuse_in_requests(wire, field):
    client, db = wire
    public = uuid4()
    db.public[("products", 45)] = public
    response = client.patch(f"/api/products/{public}", json={field: 123})
    assert response.status_code == 422 and "output-only" in response.text


def test_openapi_output_fields_are_readonly_and_selectors_stay_uuid():
    doc = {
        "components": {
            "schemas": {
                "ProjectOut": {"title": "ProjectOut", "properties": {"id": {"type": "string", "format": "uuid"}}}
            }
        },
        "paths": {
            "/api/projects": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ProjectOut"}}}
                        }
                    }
                }
            }
        },
    }
    from app.public_api import field_entity, schema_entity

    props = augment_openapi(doc, schema_entity, field_entity)["components"]["schemas"]["ProjectOut"]["properties"]
    assert props["display_id"]["readOnly"] is True
    assert props["display_id"]["anyOf"][0]["type"] == "integer"
    assert props["id"] == {"type": "string", "format": "uuid"}


def test_report_snapshot_reuses_scoped_batches_and_preserves_machine_uuids():
    from app.services.report_composer import public_report_snapshot

    db = Database()
    original = {
        "tenant_id": 7,
        "sboms": [{"id": 567, "A": {"run_id": 891}}],
        "scheduled_outcomes": {"567": {"run_id": 891, "status": "complete"}},
        "event_id": 44,
    }
    result = public_report_snapshot(db, original, 7)
    assert result["sboms"][0]["id"] == str(db.public[("sbom_source", 567)])
    assert result["sboms"][0]["display_id"] == 567
    assert result["sboms"][0]["A"]["run_display_id"] == 891
    assert result["scheduled_outcomes"][str(db.public[("sbom_source", 567)])]["sbom_display_id"] == 567
    assert "tenant_display_id" not in result and result["event_id"] == 44
    assert original["sboms"][0]["A"]["run_id"] == 891
    assert len(db.calls) == 3  # the original tenant/SBOM/run batches; no per-row lookup


def test_report_preview_labels_are_distinct_from_export_resource_references():
    from itertools import islice

    from app.services.report_rendering import report_sections

    tenant, sbom, run = (str(uuid4()) for _ in range(3))
    report = {
        "tenant_id": tenant,
        "schema_version": 1,
        "cycle_start": "start",
        "cycle_end": "end",
        "generated_at": "now",
        "timezone": "UTC",
        "scope": "SBOM",
        "runs_considered": 1,
        "severity_floor": "ALL",
        "summary": {},
        "comparison_summary": {},
        "total_sboms": 1,
        "included_sboms": 1,
        "truncated_sboms": 0,
        "scheduled_outcomes": {
            sbom: {"status": "complete", "run_id": run, "run_display_id": 891, "sbom_display_id": 567}
        },
        "sboms": [
            {
                "name": "Gateway",
                "version": "1",
                "A": {
                    "run_id": run,
                    "run_display_id": 891,
                    "run_status": "OK",
                    "latest_attempt_status": "OK",
                    "total_findings": 0,
                },
            }
        ],
    }
    human = str(list(islice(report_sections(report, display=True), 5)))
    assert "Run #891" in human and "SBOM #567" in human
    assert run not in human and sbom not in human and tenant not in human
    export = str(list(islice(report_sections(report), 5)))
    assert run in export and sbom in export and tenant in export
