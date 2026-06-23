from __future__ import annotations

from app.db import SessionLocal
from app.models import SBOMComponent, SBOMSource, VexOverrideAudit, VexStatement
from app.services.lifecycle.deps_dev_provider import DepsDevProvider
from app.services.lifecycle.normalizer import build_vulnerability_lookup_key, normalize_component, parse_cpe
from app.services.lifecycle.types import DEPRECATED
from sqlalchemy import select


def _db_session():
    return SessionLocal()


def test_vex_import_list_and_dashboard(client):
    db = _db_session()
    try:
        sbom = SBOMSource(sbom_name="vex-sbom", sbom_data="{}", status="validated")
        db.add(sbom)
        db.flush()
        component = SBOMComponent(
            sbom_id=sbom.id,
            bom_ref="pkg:npm/lodash@4.17.20",
            name="lodash",
            version="4.17.20",
            purl="pkg:npm/lodash@4.17.20",
        )
        db.add(component)
        db.commit()

        payload = {
            "document": {
                "bomFormat": "CycloneDX",
                "vulnerabilities": [
                    {
                        "id": "CVE-2020-8203",
                        "analysis": {
                            "state": "not_affected",
                            "justification": "vulnerable_code_not_in_execute_path",
                            "detail": "The vulnerable function is not shipped in this product profile.",
                        },
                        "affects": [{"ref": "pkg:npm/lodash@4.17.20"}],
                    }
                ],
            }
        }
        response = client.post(f"/api/sboms/{sbom.id}/vex", json=payload)
        assert response.status_code == 200
        assert response.json()["statements_imported"] == 1

        listed = client.get(f"/api/sboms/{sbom.id}/vex")
        assert listed.status_code == 200
        statements = listed.json()["statements"]
        assert statements[0]["status"] == "not_affected"
        assert statements[0]["component_id"] == component.id

        dashboard = client.get("/dashboard/vex")
        assert dashboard.status_code == 200
        assert dashboard.json()["not_affected_count"] >= 1
        assert dashboard.json()["vulnerabilities_reduced_by_vex"] >= 1
    finally:
        db.rollback()
        db.close()


def test_vex_not_affected_requires_justification(client):
    db = _db_session()
    try:
        sbom = SBOMSource(sbom_name="bad-vex-sbom", sbom_data="{}", status="validated")
        db.add(sbom)
        db.commit()

        response = client.post(
            f"/api/sboms/{sbom.id}/vex",
            json={
                "document": {
                    "bomFormat": "CycloneDX",
                    "vulnerabilities": [{"id": "CVE-2024-0001", "analysis": {"state": "not_affected"}}],
                }
            },
        )
        assert response.status_code == 422
    finally:
        db.rollback()
        db.close()


def test_manual_vex_override_is_audited(client):
    db = _db_session()
    try:
        sbom = SBOMSource(sbom_name="override-vex-sbom", sbom_data="{}", status="validated")
        db.add(sbom)
        db.flush()
        component = SBOMComponent(sbom_id=sbom.id, name="openssl", version="1.1.1")
        db.add(component)
        db.commit()

        response = client.patch(
            f"/api/components/{component.id}/vulnerabilities/CVE-2023-1234/vex-override",
            json={
                "status": "affected",
                "reason": "Confirmed by product security review.",
                "impact_statement": "The vulnerable code path is reachable.",
                "updated_by": "security@example.test",
            },
        )
        assert response.status_code == 200
        assert response.json()["status"] == "affected"

        statement = db.execute(select(VexStatement).where(VexStatement.component_id == component.id)).scalars().first()
        audit = (
            db.execute(select(VexOverrideAudit).where(VexOverrideAudit.component_id == component.id)).scalars().first()
        )
        assert statement is not None
        assert audit is not None
        assert audit.reason == "Confirmed by product security review."
    finally:
        db.rollback()
        db.close()


def test_cpe_and_vulnerability_lookup_key_include_identity():
    component = SBOMComponent(
        sbom_id=1,
        name="ignored",
        version="0",
        cpe="cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
    )
    parsed = parse_cpe(component.cpe)
    normalized = normalize_component(component)
    assert parsed["product"] == "openssl"
    assert normalized.identity_method == "cpe"
    assert build_vulnerability_lookup_key(normalized, "CVE-2023-1234").endswith(":vuln:CVE-2023-1234")


def test_deps_dev_deprecation_signal_marks_deprecated():
    def fake_get(url: str):
        if "/versions/" in url:
            return {"versionKey": {"version": "1.0.0"}, "isDeprecated": True}
        return {"versions": [{"versionKey": {"version": "1.0.0"}}, {"versionKey": {"version": "2.0.0"}}]}

    component = normalize_component(
        SBOMComponent(
            sbom_id=1,
            name="left-pad",
            version="1.0.0",
            purl="pkg:npm/left-pad@1.0.0",
        )
    )
    result = DepsDevProvider(http_get=fake_get).lookup(component)
    assert result.lifecycle_status == DEPRECATED
    assert result.recommended_version == "2.0.0"
