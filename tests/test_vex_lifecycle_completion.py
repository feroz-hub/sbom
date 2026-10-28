"""B5/B6/M1/M2/M3: version-aware posture and retained VEX evidence."""
import json

import pytest
from app.models import AnalysisRun, SBOMComponent, VexInvestigation, VexStatement
from app.services.dashboard_scope import DashboardScope
from app.services.vex.reconciliation import MANUAL_SOURCE_NAME
from sqlalchemy import event, select

from tests.public_id_fixture import public_membership_key
from tests.test_vex_version_lifecycle import NOW, queue, tiles, two_versions

pytest_plugins = ["tests.test_vex_version_lifecycle"]


def comparison(client, sbom):
    response = client.get("/api/vex/investigations/comparison", params={"sbom_id": str(sbom.public_id)})
    assert response.status_code == 200, response.text
    return response.json()


def test_pending_upload_preserves_last_known_posture(client, app_line):
    a = app_line.version("A1.0.0")
    c = app_line.component(a, "library", "1.0")
    app_line.run(a, [(c, f"CVE-2026-{1000 + i}") for i in range(81)])
    app_line.reconcile(a)
    b = app_line.version("A1.1.0", parent=a)
    data = queue(client)
    assert data["total"] == tiles(client)["total_contexts"] == 81
    assert data["posture"][0]["current_sbom"]["id"] == str(b.public_id)
    assert data["posture"][0]["posture_sbom"]["id"] == str(a.public_id)
    assert data["posture"][0]["analysis_status"] == "ANALYSIS_PENDING"
    assert "last known security posture from A1.0.0" in data["posture"][0]["warning"]
    assert client.get("/api/vex/investigations/comparison", params={"sbom_id": str(b.public_id)}).status_code == 409


@pytest.mark.parametrize("inactive", ["lifecycle", "soft_delete"])
def test_ineligible_child_does_not_hide_active_parent(client, app_line, db, inactive):
    a, b = two_versions(app_line)
    if inactive == "lifecycle":
        b.lifecycle_status = "INACTIVE"
    else:
        b.is_active = False
    db.commit()
    assert queue(client)["total"] == tiles(client)["total_contexts"] == 3
    assert list(db.scalars(DashboardScope(1).eligible_sbom_ids())) == [a.id]


def test_designated_current_not_overridden_by_upload_or_analysis(client, app_line, db):
    a, b = two_versions(app_line)
    app_line.product.current_sbom_id = a.id
    db.commit()
    data = queue(client)
    assert data["total"] == tiles(client)["total_contexts"] == 3
    assert data["posture"][0]["designation_required"]
    assert data["posture"][0]["current_sbom"]["id"] == str(a.public_id)
    app_line.product.current_sbom_id = b.id
    db.commit()
    assert queue(client)["total"] == 2


def test_invalid_designation_falls_back_active_lineage(client, app_line, db):
    a, b = two_versions(app_line)
    app_line.product.current_sbom_id = b.id
    b.lifecycle_status = "INACTIVE"
    db.commit()
    assert queue(client)["total"] == 3
    a.lifecycle_status = "INACTIVE"
    db.commit()
    assert queue(client)["total"] == 0


def test_deleted_application_has_no_posture(client, app_line, db):
    two_versions(app_line)
    app_line.product.deleted_at = NOW
    db.commit()
    assert queue(client)["total"] == tiles(client)["total_contexts"] == 0


def test_full_81_to_15_workflow_with_history_and_prior_decision(client, app_line, db):
    a = app_line.version("A1.0.0")
    c = app_line.component(a, "library", "1.0")
    app_line.run(a, [(c, f"CVE-2026-{1000 + i}") for i in range(81)])
    app_line.reconcile(a)
    old = db.scalar(select(VexInvestigation).where(VexInvestigation.canonical_vulnerability_id == "CVE-2026-1000"))
    old.assigned_to = "historical-owner"
    old.reviewed_by, old.reviewed_at = "Security Analyst", NOW
    statement = VexStatement(
        tenant_id=1,
        sbom_id=a.id,
        component_id=c.id,
        vulnerability_id="CVE-2026-1000",
        status="not_affected",
        normalized_status="NOT_AFFECTED",
        justification="code_not_reachable",
        source_name=MANUAL_SOURCE_NAME,
        created_at=NOW,
    )
    db.add(statement)
    db.commit()
    app_line.reconcile(a)
    b = app_line.version("A1.1.0", parent=a)
    assert queue(client)["total"] == 81
    cb = app_line.component(b, "library", "1.0")
    app_line.run(
        b, [(cb, f"CVE-2026-{1000 + i}") for i in range(12)] + [(cb, f"CVE-2026-{2000 + i}") for i in range(3)]
    )
    app_line.reconcile(b)
    assert queue(client)["total"] == 15
    diff = comparison(client, b)
    assert (
        diff["previous_findings"],
        diff["current_findings"],
        diff["still_detected"],
        diff["new"],
        diff["no_longer_observed"],
    ) == (81, 15, 12, 3, 69)
    historical = queue(client, version_scope="historical", sbom_id=str(a.public_id), limit=5)
    summary = client.get(
        "/api/vex/investigations/summary", params={"version_scope": "historical", "sbom_id": str(a.public_id)}
    ).json()
    assert historical["total"] == summary["total"] == 81
    assert all(row["historical"] for row in historical["items"])
    prior_detail = client.get(f"/api/vex/investigations/{old.id}").json()
    assert not prior_detail["capabilities"]["can_update"]
    assert prior_detail["internal_decision"]["assigned_to"] == "historical-owner"
    new = db.scalar(
        select(VexInvestigation).where(
            VexInvestigation.sbom_id == b.id, VexInvestigation.canonical_vulnerability_id == "CVE-2026-1000"
        )
    )
    detail = client.get(f"/api/vex/investigations/{new.id}").json()
    assert new.assigned_to is None and new.effective_status == "UNDER_INVESTIGATION"
    assert detail["previous_decisions"][0]["statement_id"] == statement.id
    assert len(detail["previous_decisions"]) == 1
    assert detail["previous_decisions"][0]["investigation_id"] == old.id
    assert detail["previous_decisions"][0]["applicability"] == "REVIEW_REQUIRED"
    assert (
        client.put(
            f"/api/vex/investigations/{old.id}/decision",
            json={"status": "AFFECTED", "reason": "historical bypass", "row_version": old.row_version},
        ).status_code
        == 403
    )


@pytest.mark.parametrize("status,is_current", [("ERROR", True), ("FINDINGS", False)])
def test_failed_or_obsolete_new_analysis_keeps_predecessor(client, app_line, status, is_current):
    a = app_line.version("1.0")
    ca = app_line.component(a, "a", "1")
    app_line.run(a, [(ca, "CVE-2026-1001")])
    app_line.reconcile(a)
    b = app_line.version("2.0", parent=a)
    app_line.run(b, [], status=status, is_current=is_current)
    app_line.reconcile(b)
    assert queue(client)["total"] == 1
    assert queue(client)["posture"][0]["last_known_posture"]


def test_successful_zero_findings_is_real_current_posture(client, app_line):
    a = app_line.version("1")
    c = app_line.component(a, "a", "1")
    app_line.run(a, [(c, "CVE-2026-1001")])
    app_line.reconcile(a)
    b = app_line.version("2", parent=a)
    app_line.run(b, [], status="OK")
    app_line.reconcile(b)
    data = queue(client)
    assert data["total"] == 0 and not data["posture"][0]["last_known_posture"]
    assert data["posture"][0]["analysis_run_id"]


def test_partial_comparison_does_not_call_missing_findings_resolved(client, app_line, db):
    a, b = two_versions(app_line)
    run = app_line.run(b, [], status="PARTIAL")
    run.query_error_count = 1
    run.raw_report = json.dumps({"analysis_metadata": {"source_summary": [{"source": "NVD", "status": "error"}]}})
    db.commit()
    app_line.reconcile(b)
    diff = comparison(client, b)
    assert diff["no_longer_observed"] == 0 and diff["unresolved_comparison"] == 3
    assert queue(client)["posture"][0]["coverage_incomplete"]


def test_alias_matching_and_same_cve_different_components(client, app_line):
    a = app_line.version("1")
    ca = app_line.component(a, "a", "1")
    da = app_line.component(a, "d", "1")
    app_line.run(a, [(ca, "GHSA-abcd-1234-5678", "HIGH", '["CVE-2026-1001"]'), (da, "CVE-2026-1001")])
    app_line.reconcile(a)
    b = app_line.version("2", parent=a)
    cb = app_line.component(b, "a", "1")
    dbb = app_line.component(b, "d", "2")
    app_line.run(b, [(cb, "CVE-2026-1001"), (dbb, "CVE-2026-1001")])
    app_line.reconcile(b)
    diff = comparison(client, b)
    assert (diff["still_detected"], diff["new"], diff["no_longer_observed"]) == (1, 1, 1)
    absent = next(i for i in diff["items"] if i["category"] == "NO_LONGER_OBSERVED")
    assert "version changed" in absent["reason"]


def test_multiple_active_branches_and_unrelated_lineages(client, app_line):
    a = app_line.version("1")
    c = app_line.component(a, "a", "1")
    app_line.run(a, [(c, "CVE-2026-1001")])
    app_line.reconcile(a)
    app_line.version("2", parent=a)
    app_line.version("3", parent=a)
    other = app_line.version("separate")
    co = app_line.component(other, "other", "1")
    app_line.run(other, [(co, "CVE-2026-2001")])
    app_line.reconcile(other)
    # shared ancestor is counted once, independent lineage remains present
    assert queue(client)["total"] == 2


def test_page_queries_do_not_grow_with_row_count(client, app_line, db):
    a = app_line.version("1")
    c = app_line.component(a, "a", "1")
    app_line.run(a, [(c, f"CVE-2026-{1000 + i}") for i in range(60)])
    app_line.reconcile(a)

    from app.services.vex.authorization import membership_key

    from tests.test_vex_scoped_authorization import make_member

    developer = make_member(db, "DEVELOPER")
    for row in db.scalars(select(VexInvestigation).where(VexInvestigation.sbom_id == a.id)):
        row.assigned_to = membership_key(developer)
    db.commit()

    def queries(limit):
        seen = []

        def before(conn, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith(("SELECT", "WITH")):
                seen.append(statement)

        event.listen(db.bind, "before_cursor_execute", before)
        try:
            queue(client, limit=limit)
        finally:
            event.remove(db.bind, "before_cursor_execute", before)
        return len(seen)

    small, large = queries(1), queries(50)
    print(f"Page SELECT/WITH queries: 1-row={small}, 50-row={large}")
    assert large <= small + 2, (small, large)


def test_historical_assignments_do_not_authorize_mutation(client, app_line, db):
    from app.core.security import get_current_tenant_context
    from app.services.vex.authorization import membership_key

    from tests.test_vex_scoped_authorization import as_actor, make_member

    a, b = two_versions(app_line)
    old = db.scalar(select(VexInvestigation).where(VexInvestigation.sbom_id == a.id))
    current = db.scalar(select(VexInvestigation).where(VexInvestigation.sbom_id == b.id))
    developer = make_member(db, "DEVELOPER")
    old.assigned_to = membership_key(developer)
    db.commit()
    try:
        for role in ["DEVELOPER", "VIEWER", "SECURITY_ANALYST", "TENANT_ADMIN"]:
            member = developer if role == "DEVELOPER" else make_member(db, role)
            as_actor(client, member)
            detail = client.get(f"/api/vex/investigations/{old.id}").json()
            assert not detail["capabilities"]["can_update"]
            assert (
                client.put(
                    f"/api/vex/investigations/{old.id}/decision",
                    json={"status": "AFFECTED", "reason": "history", "row_version": old.row_version},
                ).status_code
                == 403
            )
            assert (
                client.put(
                    f"/api/vex/investigations/{old.id}/assignment",
                    json={"assigned_to": None, "reason": "history", "row_version": old.row_version},
                ).status_code
                == 403
            )
            if role in {"VIEWER", "DEVELOPER"}:
                assert (
                    client.put(
                        f"/api/vex/investigations/{current.id}/decision",
                        json={"status": "AFFECTED", "reason": "unassigned", "row_version": current.row_version},
                    ).status_code
                    == 403
                )
        as_actor(client, developer)
        assert (
            client.patch(
                f"/api/components/{db.get(SBOMComponent, old.component_id).public_id}/vulnerabilities/{old.canonical_vulnerability_id}/vex-override",
                json={"status": "affected", "reason": "bypass"},
            ).status_code
            == 403
        )
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_history_comparison_and_versions_cross_tenant_not_found(client, app_line, db):
    from app.core.security import get_current_tenant_context
    from app.models import Tenant

    from tests.test_vex_scoped_authorization import as_actor, make_member

    a, b = two_versions(app_line)
    row = db.scalar(select(VexInvestigation).where(VexInvestigation.sbom_id == a.id))
    from datetime import UTC, datetime

    tenant = Tenant(
        name="Other tenant", slug="other-tenant", created_at=datetime.now(UTC), updated_at=datetime.now(UTC)
    )
    db.add(tenant)
    db.commit()
    member = make_member(db, "SECURITY_ANALYST", tenant_id=tenant.id)
    as_actor(client, member)
    try:
        for url in [
            f"/api/vex/investigations/{row.id}",
            f"/api/vex/investigations?version_scope=all&sbom_id={a.public_id}",
            f"/api/vex/investigations/summary?version_scope=all&sbom_id={a.public_id}",
            f"/api/vex/investigations/comparison?sbom_id={b.public_id}",
        ]:
            response = client.get(url)
            assert response.status_code == 404, response.text
            assert a.sbom_name not in response.text and "CVE-2026-1001" not in response.text
        versions = client.get("/api/vex/investigations/versions", params={"product_id": str(app_line.product.public_id)})
        assert versions.status_code == 404, versions.text
        assert a.sbom_name not in versions.text and "CVE-2026-1001" not in versions.text
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


def test_same_version_rerun_preserves_decision_assignment_and_history(client, app_line, db):
    a = app_line.version("1")
    c = app_line.component(a, "a", "1")
    app_line.run(a, [(c, "CVE-2026-1001"), (c, "CVE-2026-1002")])
    app_line.reconcile(a)
    row = db.scalar(select(VexInvestigation).where(VexInvestigation.canonical_vulnerability_id == "CVE-2026-1001"))
    row.assigned_to = "retained-owner"
    db.add(
        VexStatement(
            tenant_id=1,
            sbom_id=a.id,
            component_id=c.id,
            vulnerability_id="CVE-2026-1001",
            status="affected",
            normalized_status="AFFECTED",
            source_name=MANUAL_SOURCE_NAME,
            created_at=NOW,
        )
    )
    db.commit()
    app_line.run(a, [(c, "CVE-2026-1001")])
    app_line.reconcile(a)
    assert queue(client)["total"] == 1
    db.refresh(row)
    assert row.assigned_to == "retained-owner" and row.effective_status == "AFFECTED"
    assert queue(client, version_scope="historical")["total"] == 1
    assert queue(client, version_scope="all")["total"] == 2


def test_imported_vex_only_is_version_scoped_and_metrics_agree(client, app_line, db):
    a, b = two_versions(app_line)
    c = app_line.component(b, "extra", "1")
    db.add(
        VexStatement(
            tenant_id=1,
            sbom_id=b.id,
            component_id=c.id,
            vulnerability_id="CVE-2026-9999",
            status="affected",
            normalized_status="AFFECTED",
            source_name="Imported",
            created_at=NOW,
        )
    )
    db.commit()
    app_line.reconcile(b)
    result = queue(client)
    assert result["total"] == 3
    summary = client.get("/api/vex/investigations/summary").json()
    assert summary["total"] == 3 and summary["vex_only_count"] == 1
    assert comparison(client, b)["current_findings"] == 2
    assert queue(client, version_scope="historical", sbom_id=str(a.public_id))["total"] == 3


def test_run_bound_severity_ignores_failed_newer_findings(client, app_line):
    a = app_line.version("1")
    c = app_line.component(a, "a", "1")
    app_line.run(a, [(c, "CVE-2026-1001", "LOW")])
    app_line.reconcile(a)
    app_line.run(a, [(c, "CVE-2026-1001", "CRITICAL")], status="ERROR")
    app_line.reconcile(a)
    assert queue(client)["items"][0]["severity"] == "LOW"
    assert queue(client, severity="CRITICAL")["total"] == 0
    assert queue(client)["posture"][0]["analysis_status"] == "ANALYSIS_FAILED"


def test_active_grandchild_supersedes_through_inactive_middle(client, app_line, db):
    a = app_line.version("1")
    ca = app_line.component(a, "a", "1")
    app_line.run(a, [(ca, "CVE-2026-1001")])
    app_line.reconcile(a)
    middle = app_line.version("2", parent=a)
    middle.lifecycle_status = "INACTIVE"
    db.commit()
    tip = app_line.version("3", parent=middle)
    ct = app_line.component(tip, "a", "3")
    app_line.run(tip, [(ct, "CVE-2026-1002")])
    app_line.reconcile(tip)
    assert queue(client)["total"] == 1
    assert queue(client)["items"][0]["sbom_id"] == str(tip.public_id)


def test_direct_historical_url_and_inactive_history_remain_read_only(client, app_line, db):
    a, b = two_versions(app_line)
    b.lifecycle_status = "INACTIVE"
    db.commit()
    data = queue(client, version_scope="all", sbom_id=str(b.public_id))
    assert data["total"] == 2 and all(row["historical"] for row in data["items"])
    detail = client.get(f"/api/vex/investigations/{data['items'][0]['id']}").json()
    assert detail["historical"] and not detail["capabilities"]["can_update"]


def test_real_assignment_and_decision_audit_survive_promotion(client, app_line, db):
    from app.core.security import get_current_tenant_context
    from app.services.vex.authorization import membership_key

    from tests.test_vex_scoped_authorization import as_actor, make_member

    a = app_line.version("1")
    ca = app_line.component(a, "a", "1")
    app_line.run(a, [(ca, "CVE-2026-1001")])
    app_line.reconcile(a)
    row = db.scalar(select(VexInvestigation).where(VexInvestigation.sbom_id == a.id))
    analyst = make_member(db, "SECURITY_ANALYST")
    developer = make_member(db, "DEVELOPER")
    as_actor(client, analyst)
    try:
        assigned = client.put(
            f"/api/vex/investigations/{row.id}/assignment",
            json={"assigned_to": public_membership_key(membership_key(developer)), "reason": "triage", "row_version": row.row_version},
        )
        assert assigned.status_code == 200, assigned.text
        decided = client.put(
            f"/api/vex/investigations/{row.id}/decision",
            json={
                "status": "NOT_AFFECTED",
                "justification": "code_not_reachable",
                "reason": "reviewed evidence",
                "row_version": assigned.json()["row_version"],
            },
        )
        assert decided.status_code == 200, decided.text
        b = app_line.version("2", parent=a)
        cb = app_line.component(b, "a", "1")
        app_line.run(b, [(cb, "CVE-2026-1001")])
        app_line.reconcile(b)
        old = client.get(f"/api/vex/investigations/{row.id}").json()
        assert {"assignment", "decision"} <= {event["kind"] for event in old["history"]}
        assert old["internal_decision"]["assigned_to"] == public_membership_key(developer)
        new = db.scalar(select(VexInvestigation).where(VexInvestigation.sbom_id == b.id))
        assert new.assigned_to is None and new.effective_status == "UNDER_INVESTIGATION"
        assert client.get(f"/api/vex/investigations/{new.id}").json()["previous_decisions"]
    finally:
        client.app.dependency_overrides.pop(get_current_tenant_context, None)


@pytest.mark.parametrize("identifier", ["CVE-2026-1001", "GHSA-abcd-1234-5678"])
def test_retired_same_sbom_context_cannot_be_mutated_by_legacy_override(client, app_line, db, identifier):
    a = app_line.version("1")
    component = app_line.component(a, "library", "1")
    app_line.run(a, [(component, "GHSA-abcd-1234-5678", "HIGH", '["CVE-2026-1001"]')])
    app_line.reconcile(a)
    app_line.run(a, [], status="OK")
    app_line.reconcile(a)
    response = client.patch(
        f"/api/components/{component.public_id}/vulnerabilities/{identifier}/vex-override",
        json={"status": "affected", "reason": "old context bypass"},
    )
    assert response.status_code == 403
    assert db.scalar(select(VexInvestigation).where(VexInvestigation.sbom_id == a.id)).is_current is False


def test_unlinked_designated_upload_preserves_application_evidence_without_inventing_lineage(client, app_line, db):
    a = app_line.version("1")
    component = app_line.component(a, "library", "1")
    app_line.run(a, [(component, "CVE-2026-1001")])
    app_line.reconcile(a)
    b = app_line.version("2")
    app_line.product.current_sbom_id = b.id
    db.commit()
    result = queue(client)
    assert result["total"] == tiles(client)["total_contexts"] == 1
    assert result["posture"][0]["current_sbom"]["id"] == str(b.public_id)
    assert result["posture"][0]["posture_sbom"]["id"] == str(a.public_id)
    assert "another declared lineage" in result["posture"][0]["warning"]
    assert b.parent_id is None
    assert client.get("/api/vex/investigations/comparison", params={"sbom_id": str(b.public_id)}).status_code == 409


def test_same_failed_source_coverage_cannot_prove_absence(client, app_line, db):
    a, b = two_versions(app_line)
    for run in db.scalars(select(AnalysisRun).where(AnalysisRun.sbom_id.in_([a.id, b.id]))):
        run.raw_report = json.dumps({"analysis_metadata": {"source_summary": [{"source": "NVD", "status": "error"}]}})
        run.query_error_count = 0  # even if an older producer omitted its counter
    db.commit()
    result = comparison(client, b)
    assert result["no_longer_observed"] == 0
    assert result["unresolved_comparison"] == 2
    assert result["still_detected"] == 1
