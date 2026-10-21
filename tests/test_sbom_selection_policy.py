"""AUTO/MANUAL_PIN policy (lifecycle phases 1–3, VEX-DASH-004/005)."""
import importlib.util
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from app.models import AuditLog
from app.services.sbom_selection import promote_successful_analysis
from sqlalchemy import create_engine, select, text

from tests.test_vex_version_lifecycle import queue

pytest_plugins = ["tests.test_vex_version_lifecycle"]


def test_auto_promotes_only_successful_descendant_and_keeps_pending_posture(client, app_line, db):
    a = app_line.version("1.0.0")
    ca = app_line.component(a, "library", "1")
    first = app_line.run(a, [(ca, f"CVE-2026-{1000+i}") for i in range(81)])
    assert promote_successful_analysis(db, first)
    app_line.reconcile(a)
    b = app_line.version("1.1.0", parent=a)
    assert app_line.product.current_sbom_id == a.id
    assert queue(client)["total"] == 81
    failed = app_line.run(b, [], status="ERROR")
    assert not promote_successful_analysis(db, failed)
    cb = app_line.component(b, "library", "1")
    successful = app_line.run(b, [(cb, f"CVE-2026-{1000+i}") for i in range(15)])
    assert promote_successful_analysis(db, successful)
    app_line.reconcile(b)
    assert app_line.product.current_sbom_id == b.id
    assert queue(client)["total"] == 15
    assert queue(client, version_scope="historical", sbom_id=str(a.public_id))["total"] == 81
    audits = db.scalars(select(AuditLog).where(AuditLog.action == "product.current_sbom.changed")).all()
    assert audits[-1].new_value["analysis_run_id"] == successful.id
    assert not promote_successful_analysis(db, first)  # late completion cannot revert a newer descendant


def test_manual_selection_pins_until_explicit_mode_change(client, app_line, db):
    a = app_line.version("1")
    run = app_line.run(a, [], status="OK")
    promote_successful_analysis(db, run)
    db.commit()
    response = client.patch(f"/api/products/{app_line.product.public_id}", json={"current_sbom_id": str(a.public_id)})
    assert response.status_code == 200, response.text
    assert response.json()["current_sbom_mode"] == "MANUAL_PIN"
    b = app_line.version("2", parent=a)
    newer = app_line.run(b, [], status="OK")
    assert not promote_successful_analysis(db, newer)
    assert app_line.product.current_sbom_id == a.id
    db.commit()
    response = client.patch(f"/api/products/{app_line.product.public_id}", json={"current_sbom_mode": "AUTO"})
    assert response.status_code == 200, response.text
    assert promote_successful_analysis(db, newer)


@pytest.mark.parametrize("status,current", [("ERROR", True), ("PENDING", True), ("RUNNING", True), ("CANCELLED", True), ("FINDINGS", False)])
def test_ineligible_runs_never_promote(app_line, status, current, db):
    a = app_line.version("1")
    run = app_line.run(a, [], status=status, is_current=current)
    assert not promote_successful_analysis(db, run)
    assert app_line.product.current_sbom_id is None


def test_partial_promotes_with_warning_and_independent_lineage_cannot_override(client, app_line, db):
    a = app_line.version("1")
    run = app_line.run(a, [], status="PARTIAL")
    assert promote_successful_analysis(db, run)
    app_line.reconcile(a)
    assert queue(client)["posture"][0]["coverage_incomplete"]
    other = app_line.version("other")
    run = app_line.run(other, [], status="OK")
    assert not promote_successful_analysis(db, run)
    assert app_line.product.current_sbom_id == a.id


def test_invalid_pin_is_explicit_and_does_not_mutate_selection(client, app_line, db):
    a = app_line.version("1")
    ca = app_line.component(a, "lib", "1")
    app_line.run(a, [(ca, "CVE-2026-1000")])
    app_line.reconcile(a)
    b = app_line.version("2", parent=a)
    app_line.product.current_sbom_id = b.id
    app_line.product.current_sbom_mode = "MANUAL_PIN"
    b.lifecycle_status = "INACTIVE"
    db.commit()
    data = queue(client)
    assert data["total"] == 1
    assert data["posture"][0]["invalid_selection"]
    assert data["posture"][0]["fallback_reason"] == "INVALID_SELECTION"
    assert app_line.product.current_sbom_id == b.id


def test_selection_migration_preserves_legacy_pins_and_rolls_back():
    spec = importlib.util.spec_from_file_location("selection_migration", str(Path(__file__).resolve().parents[1] / "alembic/versions/077_sbom_selection_mode.py"))
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE products (id INTEGER PRIMARY KEY, current_sbom_id INTEGER)"))
        connection.execute(text("INSERT INTO products VALUES (1, 99), (2, NULL)"))
        migration.op = Operations(MigrationContext.configure(connection))
        migration.upgrade()
        assert connection.execute(text("SELECT current_sbom_mode FROM products ORDER BY id")).scalars().all() == ["MANUAL_PIN", "AUTO"]
        migration.downgrade()
        assert connection.execute(text("SELECT current_sbom_id FROM products ORDER BY id")).scalars().all() == [99, None]


def test_run_snapshot_preserves_prior_assignment_and_decision(client, app_line, db):
    from app.models import VexInvestigation
    from app.services.vex.run_history import capture_run_snapshot
    a = app_line.version("1")
    component = app_line.component(a, "lib", "1")
    run = app_line.run(a, [(component, "CVE-2026-1000")])
    app_line.reconcile(a)
    context = db.scalar(select(VexInvestigation).where(VexInvestigation.sbom_id == a.id))
    context.assigned_to = "original-assignee"
    context.effective_status = "NOT_AFFECTED"
    db.flush()
    capture_run_snapshot(db, run)
    db.commit()
    context.assigned_to = "later-assignee"
    context.effective_status = "AFFECTED"
    capture_run_snapshot(db, run)
    db.commit()
    response = client.get("/api/vex/investigations/run-snapshot", params={"sbom_id": str(a.public_id), "analysis_run_id": run.id})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["total"] == 1 and data["read_only"]
    assert data["items"][0]["assigned_to"] == "original-assignee"
    assert data["items"][0]["effective_status"] == "NOT_AFFECTED"
    other = app_line.version("unrelated")
    assert client.get("/api/vex/investigations/run-snapshot", params={"sbom_id": str(other.public_id), "analysis_run_id": run.id}).status_code == 404


def test_zero_context_snapshot_distinguishes_legacy_missing_snapshot(client, app_line, db):
    from app.services.vex.run_history import capture_run_snapshot
    a = app_line.version("1")
    run = app_line.run(a, [], status="OK")
    capture_run_snapshot(db, run)
    db.commit()
    data = client.get("/api/vex/investigations/run-snapshot", params={"sbom_id": str(a.public_id), "analysis_run_id": run.id}).json()
    assert data["snapshot_available"] and data["total"] == 0


def test_multiple_active_branches_require_explicit_selection(app_line, db):
    a = app_line.version("1")
    first = app_line.run(a, [], status="OK")
    assert promote_successful_analysis(db, first)
    db.commit()
    b = app_line.version("2a", parent=a)
    app_line.version("2b", parent=a)
    run = app_line.run(b, [], status="OK")
    assert not promote_successful_analysis(db, run)
    assert app_line.product.current_sbom_id == a.id


def test_no_eligible_version_reports_invalid_selection(client, app_line, db):
    a = app_line.version("1", lifecycle_status="INACTIVE")
    app_line.product.current_sbom_id = a.id
    app_line.product.current_sbom_mode = "MANUAL_PIN"
    db.commit()
    data = queue(client)
    assert data["total"] == 0
    assert data["posture"][0]["analysis_status"] == "NO_POSTURE"
    assert data["posture"][0]["current_sbom"] is None


def test_snapshot_cannot_be_rewritten(app_line, db):
    from app.models import VexInvestigationSnapshot
    from app.services.vex.run_history import capture_run_snapshot
    a = app_line.version("1")
    c = app_line.component(a, "lib", "1")
    run = app_line.run(a, [(c, "CVE-2026-1000")])
    app_line.reconcile(a)
    capture_run_snapshot(db, run)
    db.commit()
    snapshot = db.scalar(select(VexInvestigationSnapshot))
    snapshot.payload_json = {"assigned_to": "rewritten"}
    with pytest.raises(RuntimeError, match="immutable"):
        db.flush()
    db.rollback()


def test_obsolete_analyzer_contexts_are_not_current_security_posture(client, app_line, db):
    a = app_line.version("1")
    c = app_line.component(a, "lib", "1")
    run = app_line.run(a, [(c, "CVE-2026-1000")])
    app_line.reconcile(a)
    run.is_current = False
    db.commit()
    assert queue(client)["total"] == 0
    assert client.get('/dashboard/vex').json()['total_contexts'] == 0
    assert queue(client, version_scope="all", sbom_id=str(a.public_id))["total"] == 1
    historical = queue(client, version_scope="historical", sbom_id=str(a.public_id))
    assert historical["total"] == 1 and historical["items"][0]["historical"]
    assert not client.get(f'/api/vex/investigations/{historical["items"][0]["id"]}').json()["capabilities"]["can_update"]


def test_independent_lineages_are_not_silently_collapsed(client, app_line, db):
    a = app_line.version("independent-a")
    app_line.version("independent-b")
    c = app_line.component(a, "lib", "1")
    run = app_line.run(a, [(c, "CVE-2026-1000")])
    assert not promote_successful_analysis(db, run)
    app_line.reconcile(a)
    assert app_line.product.current_sbom_id is None
    data = queue(client)
    assert data["total"] == 1 and len(data["posture"]) == 2


def test_concurrent_promotion_writes_one_designation_audit(app_line, db):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from app.db import SessionLocal
    from app.models import AnalysisRun

    from tests.tenant_fixture_scope import verified_fixture_tenant
    a = app_line.version("1")
    run = app_line.run(a, [], status="OK")
    run_id = run.id
    # Trusted owner read from this fixture's persisted run, before threading.
    tenant_id = run.tenant_id
    barrier = Barrier(2)

    def promote():
        with SessionLocal() as session:
            with verified_fixture_tenant(session, tenant_id):
                candidate = session.get(AnalysisRun, run_id)
                barrier.wait(timeout=30)
                result = promote_successful_analysis(session, candidate)
                session.commit()
                return result

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(promote) for _ in range(2)]
        assert sorted(f.result(timeout=60) for f in futures) == [False, True]
    audits = db.scalars(select(AuditLog).where(AuditLog.action == "product.current_sbom.changed")).all()
    assert len(audits) == 1


def test_imported_prior_assertion_is_evidence_for_only_its_vulnerability(client, app_line, db):
    from app.models import VexInvestigation, VexStatement

    from tests.test_vex_version_lifecycle import NOW, two_versions
    a, b = two_versions(app_line)
    old = db.scalar(select(VexInvestigation).where(
        VexInvestigation.sbom_id == a.id, VexInvestigation.canonical_vulnerability_id == "CVE-2026-1001"))
    statement = VexStatement(tenant_id=1, sbom_id=a.id, component_id=old.component_id,
        vulnerability_id="CVE-2026-1001", status="not_affected", normalized_status="NOT_AFFECTED",
        justification="code_not_reachable", source_name="Vendor OpenVEX", source_format="openvex", created_at=NOW)
    db.add(statement)
    db.commit()
    app_line.reconcile(a)
    current = db.scalar(select(VexInvestigation).where(
        VexInvestigation.sbom_id == b.id, VexInvestigation.canonical_vulnerability_id == "CVE-2026-1001"))
    data = client.get(f"/api/vex/investigations/{current.id}").json()
    assert len(data["previous_decisions"]) == 1
    assert data["previous_decisions"][0]["source_name"] == "Vendor OpenVEX"
    assert data["previous_decisions"][0]["investigation_id"] == old.id
    assert current.effective_status == "UNDER_INVESTIGATION"
    assert data["internal_decision"]["effective_status"] is None  # Internal default is not an authored decision.


def test_acceptance_auto_81_to_15_with_http_decisions_assignment_and_inactive_fallback(client, app_line, db):
    from app.models import VexInvestigation, VexOverrideAudit, VexStatement
    from app.services.vex.authorization import membership_key

    from tests.test_vex_scoped_authorization import make_member
    a = app_line.version("1.0.0")
    ca = app_line.component(a, "library", "1")
    first = app_line.run(a, [(ca, f"CVE-2026-{1000+i}") for i in range(81)])
    assert promote_successful_analysis(db, first)
    app_line.reconcile(a)
    assert queue(client)["total"] == 81
    assert not db.scalars(select(VexStatement)).all()
    rows = queue(client, limit=100)["items"]
    for row, status in zip(rows[:3], ["NOT_AFFECTED", "AFFECTED", "UNDER_INVESTIGATION"], strict=True):
        response = client.put(f'/api/vex/investigations/{row["id"]}/decision', json={
            "status": status, "reason": "Synthetic lifecycle review", "row_version": row["row_version"],
            "justification": "code_not_reachable" if status == "NOT_AFFECTED" else None,
        })
        assert response.status_code == 200, response.text
    developer = make_member(db, "DEVELOPER")
    assigned = rows[3]
    response = client.put(f'/api/vex/investigations/{assigned["id"]}/assignment', json={
        "assigned_to": membership_key(developer), "reason": "Synthetic developer delegation",
        "row_version": assigned["row_version"],
    })
    assert response.status_code == 200, response.text
    assert db.scalars(select(VexOverrideAudit)).all()
    b = app_line.version("1.1.0", parent=a)
    assert app_line.product.current_sbom_id == a.id and queue(client)["total"] == 81
    failed = app_line.run(b, [], status="ERROR")
    assert not promote_successful_analysis(db, failed)
    db.commit()
    assert queue(client)["total"] == 81
    cb = app_line.component(b, "library", "1")
    successful = app_line.run(b, [(cb, f"CVE-2026-{1000+i}") for i in range(12)] +
                              [(cb, f"CVE-2026-{2000+i}") for i in range(3)])
    assert promote_successful_analysis(db, successful)
    app_line.reconcile(b)
    assert queue(client)["total"] == 15
    diff = client.get('/api/vex/investigations/comparison', params={"sbom_id": str(b.public_id)}).json()
    assert (diff["previous_findings"], diff["current_findings"], diff["still_detected"], diff["new"], diff["no_longer_observed"]) == (81, 15, 12, 3, 69)
    assert queue(client, version_scope="historical", sbom_id=str(a.public_id))["total"] == 81
    db.expire_all()
    current = db.scalars(select(VexInvestigation).where(VexInvestigation.sbom_id == b.id)).all()
    assert all(row.assigned_to is None and row.effective_status == "UNDER_INVESTIGATION" for row in current)
    historical = client.get(f'/api/vex/investigations/{assigned["id"]}').json()
    assert not historical["capabilities"]["can_update"]
    assert historical["internal_decision"]["assigned_to"] == membership_key(developer)
    b.lifecycle_status = "INACTIVE"
    db.commit()
    assert queue(client)["total"] == 81
    assert queue(client)["posture"][0]["invalid_selection"]
