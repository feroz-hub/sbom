"""Operator reconciliation keeps tenant guards and atomic dry-run/apply behavior."""
from datetime import UTC, datetime

import pytest
from app.core.context import get_bound_context, minimal_background_context, tenant_scope
from app.db import SessionLocal
from app.models import AnalysisRun, AuthorizationAuditLog, SBOMSource, Tenant
from scripts import reconcile_analysis_run_finding_counts as command
from sqlalchemy import select

from tests.tenant_fixture_scope import declare_fixture_tenant, verified_fixture_tenant


@pytest.fixture
def runs(client):
    identifiers = {}
    with SessionLocal() as db:
        declare_fixture_tenant(db, 2)
        db.commit()
        for owner in (1, 2):
            with verified_fixture_tenant(db, owner):
                sbom = SBOMSource(sbom_name=f"operator-scope-{owner}", status="validated")
                db.add(sbom)
                db.flush()
                run = AnalysisRun(sbom_id=sbom.id, run_status="FINDINGS", started_on="2026-10-20",
                                  completed_on="2026-10-20", total_findings=5, high_count=5)
                db.add(run)
                db.commit()
                identifiers[owner] = run.id
    return identifiers


def invoke(monkeypatch, *args):
    monkeypatch.setattr("sys.argv", ["reconcile_analysis_run_finding_counts.py", *map(str, args)])
    return command.main()


def stored(owner, run_id):
    assert owner in (1, 2)
    with tenant_scope(minimal_background_context(owner)), SessionLocal() as db:
        row = db.get(AnalysisRun, run_id)
        return row.total_findings, row.high_count


def test_dry_run_never_updates_either_owner(runs, monkeypatch, capsys):
    assert invoke(monkeypatch, "--run-id", runs[1], "--dry-run") == 0
    assert "canonical findings: 0" in capsys.readouterr().out
    assert stored(1, runs[1]) == stored(2, runs[2]) == (5, 5)
    assert get_bound_context() is None


def test_explicit_scope_cannot_reconcile_foreign_run(runs, monkeypatch, capsys):
    assert invoke(monkeypatch, "--tenant-id", 1, "--run-id", runs[2], "--apply") == 1
    assert "not found" in capsys.readouterr().out
    assert stored(1, runs[1]) == stored(2, runs[2]) == (5, 5)
    assert get_bound_context() is None


def test_apply_all_is_scoped_audited_and_idempotent(runs, monkeypatch, capsys):
    assert invoke(monkeypatch, "--tenant-id", 1, "--all", "--apply") == 0
    assert "Reconciled runs updated: 1" in capsys.readouterr().out
    assert stored(1, runs[1]) == (0, 0)
    assert stored(2, runs[2]) == (5, 5)
    assert invoke(monkeypatch, "--tenant-id", 1, "--all", "--apply") == 0
    assert "Reconciled runs updated: 0" in capsys.readouterr().out
    with SessionLocal() as db:
        events = db.scalars(select(AuthorizationAuditLog).where(
            AuthorizationAuditLog.action.in_(["maintenance.started", "maintenance.finished"]))).all()
        events = [event for event in events if (event.new_value or {}).get("operation") == "reconcile_analysis_run_finding_counts"]
        assert [event.action for event in events].count("maintenance.started") == 2
        assert [event.action for event in events].count("maintenance.finished") == 2
        assert all(event.tenant_id == 1 and event.outcome == "SUCCESS" for event in events)
    assert get_bound_context() is None


def test_inactive_owner_is_rejected(runs, monkeypatch):
    with SessionLocal() as db:
        db.get(Tenant, 2).status = "DISABLED"
        db.get(Tenant, 2).updated_at = datetime.now(UTC)
        db.commit()
    with pytest.raises(RuntimeError, match="Inactive maintenance tenant"):
        invoke(monkeypatch, "--tenant-id", 2, "--all", "--apply")
    assert stored(2, runs[2]) == (5, 5)
    assert get_bound_context() is None


def test_request_context_cannot_invoke_operator_discovery(runs, monkeypatch):
    with tenant_scope(minimal_background_context(1)):
        with pytest.raises(RuntimeError, match="request contexts"):
            invoke(monkeypatch, "--all", "--apply")
    assert stored(1, runs[1]) == stored(2, runs[2]) == (5, 5)


def test_mutation_failure_rolls_back_and_clears_scope(runs, monkeypatch):
    def fail(row, metrics):
        row.total_findings = metrics.total_findings
        raise RuntimeError("controlled reconciliation failure")
    monkeypatch.setattr(command, "apply_metrics_to_run", fail)
    with pytest.raises(RuntimeError, match="controlled reconciliation failure"):
        invoke(monkeypatch, "--tenant-id", 1, "--all", "--apply")
    assert stored(1, runs[1]) == stored(2, runs[2]) == (5, 5)
    assert get_bound_context() is None
    with SessionLocal() as db:
        event = db.scalar(select(AuthorizationAuditLog).where(
            AuthorizationAuditLog.action == "maintenance.finished", AuthorizationAuditLog.outcome == "FAILED"))
        assert event.tenant_id == 1 and event.outcome == "FAILED"
