"""Deterministic repair uses real vendored schemas and the full validator."""

import copy
import json
import uuid

import pytest
from app.services.sbom.repair.engine import RepairEngine
from app.services.sbom.repair.policy import RepairPolicy
from app.validation import run as validate


def document():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"type": "library", "bom-ref": "a", "name": "alpha", "version": "1.0"},
            {"type": "library", "bom-ref": "b", "name": "beta", "version": "2.0", "purl": "pkg:npm/beta@2.0"},
        ],
        "dependencies": [{"ref": "a", "dependsOn": ["b"]}],
    }


def repair(doc, **kwargs):
    original = json.dumps(doc).encode()
    before = copy.deepcopy(doc)
    result = RepairEngine(**kwargs).run(original)
    assert doc == before
    return result


def test_valid_is_unchanged_and_not_required():
    doc = document()
    result = repair(doc)
    assert result.candidate == json.dumps(doc).encode()
    assert result.report["status"] == "NOT_REQUIRED"


def test_unreferenced_duplicate_gets_stable_unique_id():
    doc = document()
    doc["dependencies"] = []
    doc["components"][1]["bom-ref"] = "a"
    first = repair(doc)
    second = repair(doc)
    assert first.report["status"] == "REPAIRED"
    assert first.candidate == second.candidate
    candidate = json.loads(first.candidate)
    assert len({c["bom-ref"] for c in candidate["components"]}) == 2
    assert not validate(first.candidate).has_errors()
    assert RepairEngine().run(first.candidate).candidate == first.candidate


def test_identical_duplicate_with_dependencies_retains_targets():
    doc = document()
    doc["components"].append(copy.deepcopy(doc["components"][1]))
    result = repair(doc)
    assert result.report["status"] == "REPAIRED"
    candidate = json.loads(result.candidate)
    assert candidate["dependencies"] == doc["dependencies"]
    assert len(candidate["components"]) == 2
    assert not validate(result.candidate).has_errors()


def test_distinct_duplicate_with_references_requires_review():
    doc = document()
    doc["components"][1]["bom-ref"] = "a"
    doc["dependencies"] = [{"ref": "a", "dependsOn": []}]
    result = repair(doc)
    assert result.report["repairs_applied"] == 0
    assert result.report["analysis"]["suggested"] == 1
    assert result.report["validation_status"] == "FAILED"


@pytest.mark.parametrize("identifier", ["pkg:npm/beta@2.0", "beta@2.0", " b "])
def test_exact_unambiguous_dangling_dependency(identifier):
    doc = document()
    doc["dependencies"][0]["dependsOn"] = [identifier]
    result = repair(doc)
    assert result.report["status"] == "REPAIRED"
    assert json.loads(result.candidate)["dependencies"][0]["dependsOn"] == ["b"]


def test_dangling_source_node_without_edges():
    doc = document()
    doc["dependencies"] = [{"ref": "pkg:npm/beta@2.0", "dependsOn": []}]
    assert repair(doc).report["status"] == "REPAIRED"


def test_ambiguous_purl_not_automatically_fixed():
    doc = document()
    doc["components"].append(
        {"type": "library", "bom-ref": "c", "name": "beta", "version": "2.0", "purl": "pkg:npm/beta@2.0"}
    )
    doc["dependencies"][0]["dependsOn"] = ["pkg:npm/beta@2.0"]
    result = repair(doc)
    assert result.report["repairs_applied"] == 0
    assert result.report["analysis"]["suggested"] == 1


@pytest.mark.parametrize("duplicate_node", [False, True])
def test_dependency_deduplication_retains_order_and_semantics(duplicate_node):
    doc = document()
    if duplicate_node:
        doc["dependencies"].append(copy.deepcopy(doc["dependencies"][0]))
    else:
        doc["dependencies"][0]["dependsOn"] = ["b", "b"]
    result = repair(doc)
    assert result.report["status"] == "REPAIRED"
    assert json.loads(result.candidate)["dependencies"] == document()["dependencies"]


def test_safe_enum_case_normalization_uses_exact_spec():
    doc = document()
    doc["components"][0]["type"] = " Library "
    result = repair(doc)
    assert result.report["status"] == "REPAIRED"
    assert json.loads(result.candidate)["components"][0]["type"] == "library"


def test_partial_repair_discovers_later_errors_without_weakening_validation():
    doc = document()
    doc["components"][0]["type"] = "LIBRARY"
    doc["components"][1]["purl"] = "made-up-purl"
    result = repair(doc)
    assert result.report["status"] == "PARTIALLY_REPAIRED"
    assert result.report["validation_status"] == "FAILED"
    assert result.report["repairs_applied"] == 1
    assert json.loads(result.candidate)["components"][1]["purl"] == "made-up-purl"


def test_repair_that_creates_self_edge_is_rolled_back():
    doc = document()
    doc["dependencies"] = [{"ref": "b", "dependsOn": ["pkg:npm/beta@2.0"]}]
    result = repair(doc)
    assert result.report["status"] == "REPAIR_FAILED"
    assert result.candidate == json.dumps(doc).encode()
    assert result.report["rollback"]


def test_no_missing_facts_are_fabricated():
    doc = document()
    doc["components"][0].pop("version")
    result = repair(doc, policy=RepairPolicy(strict_ntia=True))
    assert result.report["validation_status"] == "FAILED"
    assert all(i["classification"] == "MANUAL_ONLY" for i in result.report["analysis"]["issues"])
    assert "version" not in json.loads(result.candidate)["components"][0]


def test_disabled_keeps_original_errors_and_content():
    doc = document()
    doc["components"][0]["type"] = "LIBRARY"
    result = repair(doc, policy=RepairPolicy(enabled=False))
    assert result.report["errors_before"] == result.report["errors_after"] > 0
    assert result.candidate == json.dumps(doc).encode()


def test_security_walk_runs_even_when_schema_fails():
    doc = document()
    doc["components"][0]["type"] = "LIBRARY"
    doc["__proto__"] = {"attack": "data"}
    result = repair(doc)
    assert result.report["repairs_applied"] == 0
    assert all(i["classification"] == "MANUAL_ONLY" for i in result.report["analysis"]["issues"])


def test_signed_document_is_never_modified():
    doc = document()
    doc["components"][0]["type"] = "LIBRARY"
    doc["signature"] = {"algorithm": "RS256", "value": "abc"}
    assert repair(doc).report["repairs_applied"] == 0


def test_maximum_passes_bound_large_repair_set():
    doc = document()
    doc["dependencies"] = []
    doc["components"] = [
        {"type": "LIBRARY", "bom-ref": str(i), "name": f"component-{i}", "version": "1"} for i in range(105)
    ]
    result = repair(doc, policy=RepairPolicy(max_passes=1))
    assert result.report["passes"] == 1
    assert result.report["repairs_applied"] <= 100
    assert result.report["status"] == "PARTIALLY_REPAIRED"


def upload_invalid(client, doc=None):
    doc = doc or document()
    doc["components"][0]["type"] = "LIBRARY"
    response = client.post(
        "/api/sboms", json={"sbom_name": f"auto-repair-{uuid.uuid4()}", "sbom_data": json.dumps(doc)}
    )
    assert response.status_code == 422, response.text
    return response.json()["detail"]["session_id"]


def run_job(client, session):
    response = client.post(f"/api/sbom-validation-sessions/{session}/repair")
    assert response.status_code == 200, response.text
    return response.json()


def test_api_approval_imports_only_candidate_and_keeps_original(client):
    session = upload_invalid(client)
    base = f"/api/sbom-validation-sessions/{session}"
    original = client.get(base + "/download-original").content
    analysis = client.post(base + "/repair/analyze")
    assert analysis.status_code == 200, analysis.text
    assert analysis.json()["auto_fixable"] == 1
    job = run_job(client, session)
    assert job["status"] == "REPAIRED"
    assert run_job(client, session)["repair_job_id"] == job["repair_job_id"]
    assert client.get(base + "/download-original").content == original
    assert client.get(base + "/download-repair-draft").content == original
    candidate = client.get(base + f"/repair/{job['repair_job_id']}/download").content.decode()
    assert candidate != original.decode()
    assert client.get(base + f"/repair/{job['repair_job_id']}/changes").json()["changes"]
    assert client.get(base + f"/repair/{job['repair_job_id']}/report").status_code == 200
    approved = client.post(base + f"/repair/{job['repair_job_id']}/approve")
    assert approved.status_code == 200, approved.text
    approved_again = client.post(base + f"/repair/{job['repair_job_id']}/approve")
    assert approved_again.json()["imported_sbom_id"] == approved.json()["imported_sbom_id"]
    from app.db import SessionLocal
    from app.models import SBOMRepairJob, SBOMSource, SBOMValidationSessionEvent

    with SessionLocal() as db:
        assert db.get(SBOMSource, approved.json()["imported_sbom_id"]).sbom_data == candidate
        assert db.get(SBOMRepairJob, job["repair_job_id"]).approval_status == "APPROVED"
        events = [e.event_type for e in db.query(SBOMValidationSessionEvent).filter_by(session_id=session)]
        assert "SBOM_REPAIR_APPROVED" in events
    assert client.get(base + "/download-original").content == original


def test_rejection_retains_source_and_cannot_be_approved(client):
    session = upload_invalid(client)
    base = f"/api/sbom-validation-sessions/{session}"
    original = client.get(base + "/download-repair-draft").content
    job = run_job(client, session)
    assert client.post(base + f"/repair/{job['repair_job_id']}/reject").json()["status"] == "REJECTED"
    assert client.post(base + f"/repair/{job['repair_job_id']}/approve").status_code == 409
    assert client.get(base + "/download-repair-draft").content == original
    assert client.get(base).json()["imported_sbom_id"] is None


def test_stale_draft_cannot_be_approved(client):
    session = upload_invalid(client)
    job = run_job(client, session)
    base = f"/api/sbom-validation-sessions/{session}"
    edited = document()
    edited["components"][0]["name"] = "changed"
    assert client.patch(base, json={"current_content": json.dumps(edited)}).status_code == 200
    assert client.post(base + f"/repair/{job['repair_job_id']}/approve").status_code == 409


def test_partial_candidate_cannot_be_approved(client):
    doc = document()
    doc["components"][1]["purl"] = "not-a-purl"
    session = upload_invalid(client, doc)
    job = run_job(client, session)
    assert job["status"] == "PARTIALLY_REPAIRED"
    assert (
        client.post(f"/api/sbom-validation-sessions/{session}/repair/{job['repair_job_id']}/approve").status_code == 409
    )


def test_unauthenticated_requests_rejected(client, monkeypatch):
    session = upload_invalid(client)
    monkeypatch.setenv("AUTH_ENABLED", "true")
    from app.settings import reset_settings

    reset_settings()
    assert client.post(f"/api/sbom-validation-sessions/{session}/repair").status_code == 401


def test_tenant_isolation_all_repair_surfaces(client, monkeypatch):
    session = upload_invalid(client)
    job = run_job(client, session)
    # Use the real service with a foreign authenticated context: all lookups
    # include tenant predicates, independently of middleware RLS filtering.
    from app.core.context import CurrentContext
    from app.db import SessionLocal
    from app.services.sbom.repair.service import AutoRepairService
    from fastapi import HTTPException

    context = CurrentContext(
        user_id=99999,
        external_user_id="foreign",
        email=None,
        display_name=None,
        tenant_id=99999,
        external_tenant_id="foreign",
        roles=frozenset(),
        permissions=frozenset(),
    )
    with SessionLocal() as db:
        service = AutoRepairService(db, context)
        for call in (
            lambda: service.analyze(session),
            lambda: service.run(session),
            lambda: service.get(session, job["repair_job_id"]),
            lambda: service.approve(session, job["repair_job_id"]),
            lambda: service.reject(session, job["repair_job_id"]),
        ):
            with pytest.raises(HTTPException) as error:
                call()
            assert error.value.status_code == 404


def test_http_tenant_isolation_and_permission_denials(client):
    from app.core.context import CurrentContext
    from app.core.permissions import ROLE_PERMISSIONS
    from app.core.security import get_current_tenant_context

    session = upload_invalid(client)
    job = run_job(client, session)
    base = f"/api/sbom-validation-sessions/{session}/repair"
    foreign = CurrentContext(
        user_id=900,
        external_user_id="foreign",
        email=None,
        display_name="foreign",
        tenant_id=99999,
        external_tenant_id="foreign",
        roles=frozenset({"TENANT_ADMIN"}),
        permissions=frozenset(ROLE_PERMISSIONS["TENANT_ADMIN"]),
    )
    client.app.dependency_overrides[get_current_tenant_context] = lambda: foreign
    try:
        for method, suffix in [
            ("POST", "/analyze"),
            ("POST", ""),
            ("GET", ""),
            ("GET", f"/{job['repair_job_id']}"),
            ("GET", f"/{job['repair_job_id']}/changes"),
            ("GET", f"/{job['repair_job_id']}/download"),
            ("GET", f"/{job['repair_job_id']}/report"),
            ("POST", f"/{job['repair_job_id']}/approve"),
            ("POST", f"/{job['repair_job_id']}/reject"),
        ]:
            assert client.request(method, base + suffix).status_code == 404, suffix
        viewer = CurrentContext(
            user_id=900,
            external_user_id="viewer",
            email=None,
            display_name="viewer",
            tenant_id=1,
            external_tenant_id="default",
            roles=frozenset({"VIEWER"}),
            permissions=frozenset({"sbom:repair:read"}),
        )
        client.app.dependency_overrides[get_current_tenant_context] = lambda: viewer
        for suffix in ["", f"/{job['repair_job_id']}/approve", f"/{job['repair_job_id']}/reject"]:
            assert client.post(base + suffix).status_code == 403
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_candidate_hash_checked_even_if_database_content_is_tampered(client):
    from app.db import SessionLocal
    from app.models import SBOMRepairJob
    from sqlalchemy import update

    session = upload_invalid(client)
    job = run_job(client, session)
    with SessionLocal() as db:
        db.execute(update(SBOMRepairJob).where(SBOMRepairJob.id == job["repair_job_id"]).values(candidate_content="{}"))
        db.commit()
    response = client.post(f"/api/sbom-validation-sessions/{session}/repair/{job['repair_job_id']}/approve")
    assert response.status_code == 409
    assert "hash" in response.json()["detail"]


def test_candidate_is_immutable_through_orm(client):
    from app.db import SessionLocal
    from app.models import SBOMRepairJob

    session = upload_invalid(client)
    job = run_job(client, session)
    with SessionLocal() as db:
        row = db.get(SBOMRepairJob, job["repair_job_id"])
        row.candidate_content = "{}"
        with pytest.raises(RuntimeError, match="immutable"):
            db.commit()
        db.rollback()


def test_upload_strict_ntia_policy_is_preserved(client):
    doc = document()
    doc["components"][0]["type"] = "LIBRARY"
    response = client.post(
        "/api/sboms/upload?strict_ntia=true",
        data={"sbom_name": f"strict-{uuid.uuid4()}"},
        files={"file": ("input.cdx.json", json.dumps(doc).encode(), "application/json")},
    )
    assert response.status_code == 422, response.text
    session = response.json()["detail"]["session_id"]
    job = run_job(client, session)
    assert job["status"] == "PARTIALLY_REPAIRED"
    from app.db import SessionLocal
    from app.models import SBOMRepairJob

    with SessionLocal() as db:
        assert db.get(SBOMRepairJob, job["repair_job_id"]).validation_options_json["strict_ntia"] is True


def test_existing_accepted_artifact_is_preserved_on_approval(client):
    response = client.post(
        "/api/sboms/upload",
        data={"sbom_name": f"accepted-{uuid.uuid4()}"},
        files={"file": ("input.cdx.json", json.dumps(document()).encode(), "application/json")},
    )
    assert response.status_code == 202, response.text
    session = response.json()["validation_session_id"]
    source_id = response.json()["sbom_id"]
    edited = document()
    edited["components"][0]["type"] = "LIBRARY"
    base = f"/api/sbom-validation-sessions/{session}"
    assert client.patch(base, json={"current_content": json.dumps(edited)}).status_code == 200
    job = run_job(client, session)
    approval = client.post(base + f"/repair/{job['repair_job_id']}/approve")
    assert approval.status_code == 200, approval.text
    assert approval.json()["imported_sbom_id"] != source_id
    from app.db import SessionLocal
    from app.models import SBOMSource

    with SessionLocal() as db:
        assert json.loads(db.get(SBOMSource, source_id).sbom_data) == document()
    assert (
        client.get(base + "/download-repair-draft").content
        == client.get(base + f"/repair/{job['repair_job_id']}/download").content
    )


def test_disabled_repair_returns_original_validation_and_no_job(client, monkeypatch):
    session = upload_invalid(client)
    monkeypatch.setenv("SBOM_AUTO_REPAIR_ENABLED", "false")
    from app.settings import reset_settings

    reset_settings()
    base = f"/api/sbom-validation-sessions/{session}/repair"
    response = client.post(base + "/analyze")
    assert response.status_code == 200
    assert response.json()["enabled"] is False
    assert response.json()["total_errors"] > 0
    assert response.json()["auto_fixable"] == 0
    assert client.post(base).status_code == 409


def test_duplicate_json_keys_never_lose_facts_through_serialization():
    raw = (
        json.dumps(document())
        .replace('"bom-ref": "a"', '"bom-ref": "first", "bom-ref": "a"')
        .replace('"type": "library"', '"type": "LIBRARY"', 1)
        .encode()
    )
    result = RepairEngine().run(raw)
    assert result.candidate == raw
    assert result.report["repairs_applied"] == 0


def test_byte_budget_leaves_large_document_manual_only():
    raw = json.dumps(document()).replace('"type": "library"', '"type": "LIBRARY"', 1).encode()
    result = RepairEngine(RepairPolicy(max_bytes=1)).run(raw)
    assert result.candidate == raw
    assert result.report["analysis"]["manual_only"] > 0


def test_repair_cannot_remove_unknown_reference_target():
    doc = document()
    doc["dependencies"] = []
    doc["components"][1]["bom-ref"] = "a"
    doc["properties"] = [{"name": "external-link", "value": "a"}]
    assert repair(doc).report["repairs_applied"] == 0


def test_cpe_exact_match_reuses_existing_identity():
    doc = document()
    cpe = "cpe:2.3:a:vendor:beta:2.0:*:*:*:*:*:*:*"
    doc["components"][1]["cpe"] = cpe
    doc["dependencies"][0]["dependsOn"] = [cpe]
    assert repair(doc).report["status"] == "REPAIRED"


def test_purl_surrounding_whitespace_does_not_invent_facts():
    doc = document()
    doc["components"][1]["purl"] = " pkg:npm/beta@2.0 "
    result = repair(doc)
    assert result.report["status"] == "REPAIRED"
    assert json.loads(result.candidate)["components"][1]["purl"] == "pkg:npm/beta@2.0"


def test_permanent_delete_handles_new_repair_job_foreign_keys(client):
    session = upload_invalid(client)
    job = run_job(client, session)
    approved = client.post(f"/api/sbom-validation-sessions/{session}/repair/{job['repair_job_id']}/approve").json()
    from app.db import SessionLocal
    from app.models import SBOMRepairJob
    from app.services.sbom_delete_service import SBOMDeleteService

    with SessionLocal() as db:
        service = SBOMDeleteService(db, tenant_id=1)
        impact = service.get_delete_impact(approved["imported_sbom_id"])
        assert impact["can_delete"]
        assert impact["dependent_counts"]["repair_jobs"] == 1
        service.permanently_delete_sbom(approved["imported_sbom_id"], "test", True)
        assert db.get(SBOMRepairJob, job["repair_job_id"]) is None


def test_original_hash_is_verified_against_upload_metadata(client):
    from app.db import SessionLocal
    from app.models import SBOMValidationSession

    session = upload_invalid(client)
    job = run_job(client, session)
    with SessionLocal() as db:
        row = db.get(SBOMValidationSession, session)
        row.raw_content_blob = b"altered-original"
        db.commit()
    base = f"/api/sbom-validation-sessions/{session}/repair"
    assert client.post(base).status_code == 409
    assert client.post(base + f"/{job['repair_job_id']}/approve").status_code == 409


def test_successful_upload_workspace_retains_validation_policy(client):
    doc = document()
    doc["metadata"] = {
        "timestamp": "2026-10-05T00:00:00Z",
        "tools": [{"vendor": "Example", "name": "Generator", "version": "1"}],
    }
    doc["components"][0]["purl"] = "pkg:npm/alpha@1.0"
    for component in doc["components"]:
        component["supplier"] = {"name": "Example Supplier"}
    assert not validate(json.dumps(doc).encode(), strict_ntia=True).has_errors()
    response = client.post(
        "/api/sboms/upload?strict_ntia=true",
        data={"sbom_name": f"policy-{uuid.uuid4()}"},
        files={"file": ("input.cdx.json", json.dumps(doc).encode(), "application/json")},
    )
    assert response.status_code == 202, response.text
    session = response.json()["validation_session_id"]
    # A later draft edit must not downgrade the accepted upload's policy.
    doc["components"][0]["type"] = "LIBRARY"
    doc["components"][0].pop("supplier")
    assert (
        client.patch(f"/api/sbom-validation-sessions/{session}", json={"current_content": json.dumps(doc)}).status_code
        == 200
    )
    job = run_job(client, session)
    assert job["status"] == "PARTIALLY_REPAIRED"
    assert job["validation_status"] == "FAILED"
    assert (
        client.post(f"/api/sbom-validation-sessions/{session}/repair/{job['repair_job_id']}/approve").status_code == 409
    )
