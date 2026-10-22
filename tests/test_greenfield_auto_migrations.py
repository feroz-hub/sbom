"""Inert graph selection, future revisions and unchanged upgrade safety gates."""

from pathlib import Path
from unittest.mock import Mock

import pytest
from scripts import greenfield_auto_migrations as auto
from scripts import greenfield_migration_graph as graph
from scripts import greenfield_migrations as common


def migration_source(revision, parent, extra=""):
    return f"revision = {revision!r}\ndown_revision = {parent!r}\nbranch_labels = None\ndepends_on = None\n" + extra


FUTURE = """
startup = {"version": 1, "tables": ("tenant_users",), "advisory_key": 7160085103,
           "description": "Synthetic future column; verify exact ownership and original row preservation."}
def startup_preflight(connection):
    return True
def startup_validate(connection, before):
    return True
def upgrade():
    from alembic import op
    op.get_bind().exec_driver_sql("ALTER TABLE public.tenant_users ADD COLUMN startup_probe text")
"""


@pytest.fixture
def repository(tmp_path):
    versions = tmp_path / "alembic/versions"
    versions.mkdir(parents=True)
    root = Path(__file__).resolve().parents[1]
    (versions / "079.py").write_text(migration_source("079_lifecycle_provider_verification", None))
    for name in (
        "100_greenfield_uuid_final.py",
        "101_iam_user_public_uuid.py",
        "102_public_membership_grant_analysis_uuid.py",
    ):
        (versions / name).write_bytes((root / "alembic/versions" / name).read_bytes())
    return tmp_path


def add_future(root, number=103, parent="102_public_membership_grant_analysis_uuid", extra=FUTURE):
    p = root / "alembic/versions" / f"{number}_synthetic.py"
    p.write_text(migration_source(f"{number}_synthetic", parent, extra))
    return p


def test_actual_graph_head_is_discovered_without_historical_imports(monkeypatch):
    import importlib.util

    monkeypatch.setattr(
        importlib.util, "spec_from_file_location", Mock(side_effect=AssertionError("no module imports"))
    )
    observed = graph.discover(Path(__file__).resolve().parents[1])
    assert len(observed.revisions) == 82
    assert observed.head == "102_public_membership_grant_analysis_uuid"


def test_future_head_and_multi_step_path_require_no_launcher_edit(repository):
    add_future(repository)
    add_future(repository, 104, "103_synthetic")
    discovered = graph.discover(repository)
    assert discovered.head == "104_synthetic"
    assert [r.revision for r in discovered.pending("101_iam_user_public_uuid")] == [
        "102_public_membership_grant_analysis_uuid",
        "103_synthetic",
        "104_synthetic",
    ]
    assert discovered.pending("104_synthetic") == ()


def test_discovery_never_executes_top_level_code(repository):
    sentinel = repository / "must-not-exist"
    add_future(repository, extra=f"raise AssertionError({str(sentinel)!r})\n")
    assert graph.discover(repository).head == "103_synthetic"
    assert not sentinel.exists()


@pytest.mark.parametrize(
    "defect", ["duplicate", "branch", "ancestor", "cycle", "frozen", "duplicate_key", "computed", "symlink"]
)
def test_bad_graph_or_frozen_history_refuses(repository, defect):
    versions = repository / "alembic/versions"
    if defect == "duplicate":
        (versions / "duplicate.py").write_bytes((versions / "101_iam_user_public_uuid.py").read_bytes())
    elif defect == "branch":
        add_future(repository)
        add_future(repository, 104)
    elif defect == "ancestor":
        add_future(repository, parent="098_missing")
    elif defect == "cycle":
        add_future(repository, parent="104_synthetic")
        add_future(repository, 104, "103_synthetic")
    elif defect == "frozen":
        p = versions / "101_iam_user_public_uuid.py"
        p.write_text(p.read_text() + "\n# changed\n")
    elif defect == "duplicate_key":
        add_future(repository, extra="revision='103_duplicate'\n")
    elif defect == "computed":
        add_future(repository, extra="startup=dict(version=1)\n")
    elif defect == "symlink":
        p = add_future(repository)
        raw = p.read_bytes()
        p.unlink()
        target = repository / "external.py"
        target.write_bytes(raw)
        p.symlink_to(target)
    with pytest.raises(graph.DiscoveryError):
        graph.discover(repository)


@pytest.mark.parametrize("marker", ["079_lifecycle_provider_verification", "104_missing", "garbage"])
def test_unknown_or_pre_greenfield_database_refuses(repository, marker):
    with pytest.raises(graph.DiscoveryError):
        graph.discover(repository).pending(marker)


@pytest.mark.parametrize("change", ["modify", "add", "delete", "dependency"])
def test_whole_runtime_snapshot_revalidated_after_review(repository, monkeypatch, change):
    app = repository / "app"
    app.mkdir()
    source = app / "synthetic.py"
    source.write_text("value=1\n")
    lock = graph.SourceLock.capture(repository)
    lock.verify()
    if change == "modify":
        source.write_text("value=2\n")
    elif change == "add":
        (app / "new.py").write_text("value=1\n")
    elif change == "delete":
        source.unlink()
    else:
        monkeypatch.setattr(graph.importlib.metadata, "version", lambda name: "unreviewed")
    with pytest.raises(graph.DiscoveryError, match="changed after review"):
        lock.verify()


@pytest.mark.parametrize(
    "extra",
    [
        "",
        FUTURE.replace("def startup_validate", "def other_hook"),
        FUTURE + '\nprint("side effect")',
        FUTURE.replace("from alembic import op", "from alembic import op") + "\nimport app.settings\n",
        FUTURE.replace('("tenant_users",)', '("tenant_users;DROP TABLE x",)'),
        FUTURE.replace("7160085103", "False"),
        FUTURE.replace('"version": 1', '"version": 2'),
    ],
)
def test_future_revision_needs_inert_explicit_startup_contract(repository, extra):
    add_future(repository, extra=extra)
    discovered = graph.discover(repository)
    with pytest.raises(graph.DiscoveryError):
        auto.MigrationUnit(discovered.revisions[-1], graph.SourceLock.capture(repository))


def test_future_unit_exact_target_confirmation_and_source_binding(repository):
    add_future(repository)
    unit = auto.MigrationUnit(graph.discover(repository).revisions[-1], graph.SourceLock.capture(repository))
    assert unit.PREVIOUS == "102_public_membership_grant_analysis_uuid"
    assert unit.CURRENT == "103_synthetic"
    assert unit.CONFIRMATION == "UPGRADE sbom_greenfield_uuid 102 TO 103"
    assert unit.TABLES == ("tenant_users",)
    assert callable(unit.module().startup_validate)
    add_future(repository, extra=FUTURE + "\n# substitution\n")
    with pytest.raises(graph.DiscoveryError):
        unit.module()


@pytest.fixture
def automatic_flow(repository, monkeypatch):
    add_future(repository)
    monkeypatch.setattr(common.stack, "ROOT", repository)
    state = repository / "state"
    state.mkdir()
    monkeypatch.setattr(common.stack, "STATE", state)
    resources = Mock()
    monkeypatch.setattr(common.stack, "verify_resources", resources)
    observe = Mock(
        side_effect=["101_iam_user_public_uuid", "102_public_membership_grant_analysis_uuid", "103_synthetic"]
    )
    monkeypatch.setattr(auto, "observe_revision", observe)
    units = {r.revision: Mock(CURRENT=r.revision) for r in graph.discover(repository).revisions[2:]}
    monkeypatch.setattr(auto, "select_unit", lambda revision, lock: units[revision.revision])
    run = Mock()
    monkeypatch.setattr(common, "_ensure_unit", run)
    return units, observe, run, resources, state


def test_automatic_path_invokes_distinct_confirmed_units_in_order(automatic_flow):
    units, observe, run, resources, state = automatic_flow
    prompt = Mock()
    auto.ensure_current(confirm=prompt)
    assert [c.args[0].CURRENT for c in run.call_args_list] == [
        "102_public_membership_grant_analysis_uuid",
        "103_synthetic",
    ]
    assert all(c.kwargs["confirm"] is prompt for c in run.call_args_list)
    assert observe.call_count == 3


def test_cancelled_or_failed_unit_does_not_continue(automatic_flow):
    units, observe, run, resources, state = automatic_flow
    run.side_effect = common.SchemaUpgradeError("Migration not approved")
    with pytest.raises(common.SchemaUpgradeError):
        auto.ensure_current(confirm=lambda: "")
    assert run.call_count == 1 and observe.call_count == 1


def test_source_drift_between_units_prevents_next_unit(automatic_flow, repository):
    units, observe, run, resources, state = automatic_flow
    run.side_effect = lambda *a, **k: add_future(repository, extra=FUTURE + "\n# edited during first unit\n")
    with pytest.raises(common.SchemaUpgradeError, match="changed after review"):
        auto.ensure_current(confirm=Mock())
    assert run.call_count == 1


def test_existing_attempt_claim_blocks_before_resources_and_credentials(automatic_flow):
    units, observe, run, resources, state = automatic_flow
    (state / "pending-schema-upgrade.json").write_text("consumed")
    with pytest.raises(common.SchemaUpgradeError, match="manual reconciliation"):
        auto.ensure_current()
    resources.assert_not_called()
    observe.assert_not_called()
    run.assert_not_called()


def test_current_schema_validates_without_upgrade_or_prompt(automatic_flow):
    units, observe, run, resources, state = automatic_flow
    observe.side_effect = None
    observe.return_value = "103_synthetic"
    auto.ensure_current()
    run.assert_called_once_with(units["103_synthetic"], confirm=None)


def test_manifestless_future_revision_rejected_before_docker_or_credentials(repository, monkeypatch):
    add_future(repository, extra="def upgrade():\n    pass\n")
    monkeypatch.setattr(common.stack, "ROOT", repository)
    monkeypatch.setattr(common.stack, "STATE", repository / "state")
    resources = Mock()
    monkeypatch.setattr(common.stack, "verify_resources", resources)
    with pytest.raises(common.SchemaUpgradeError, match="startup v1 contract"):
        auto.ensure_current()
    resources.assert_not_called()


def test_initial_driver_error_never_leaks_sensitive_exception_arguments(automatic_flow):
    units, observe, run, resources, state = automatic_flow
    observe.side_effect = RuntimeError("synthetic credential-bearing diagnostic must remain private")
    with pytest.raises(common.SchemaUpgradeError) as caught:
        auto.ensure_current()
    assert "credential-bearing" not in str(caught.value)
    assert "RuntimeError" in str(caught.value)
    run.assert_not_called()


def test_fresh_installer_reuses_future_units_in_its_owned_transaction(repository, monkeypatch):
    add_future(repository)
    monkeypatch.setattr(common.stack, "ROOT", repository)
    module = Mock()
    module.startup_preflight.return_value = True
    unit = Mock(TABLES=("tenant_users",), ADVISORY_KEY=7160085103)
    unit.module.return_value = module
    unit.snapshot.return_value = {"synthetic_original_rows": True}
    monkeypatch.setattr(auto, "select_unit", Mock(return_value=unit))
    connection = Mock()
    connection.exec_driver_sql.return_value.scalars.return_value.all.return_value = [
        "102_public_membership_grant_analysis_uuid"
    ]
    auto.apply_fresh_tail(connection)
    module.startup_preflight.assert_called_once_with(connection)
    unit.apply_revision.assert_called_once_with(connection)
    unit.validate_after.assert_called_once_with(connection, {"synthetic_original_rows": True})
    connection.commit.assert_not_called()
    connection.close.assert_not_called()
    assert any("LOCK TABLE ONLY public.tenant_users" in c.args[0] for c in connection.exec_driver_sql.call_args_list)


def test_fresh_installer_refuses_incorrect_base_marker(repository, monkeypatch):
    add_future(repository)
    monkeypatch.setattr(common.stack, "ROOT", repository)
    connection = Mock()
    connection.exec_driver_sql.return_value.scalars.return_value.all.return_value = ["101_iam_user_public_uuid"]
    with pytest.raises(common.SchemaUpgradeError, match="requires verified 102"):
        auto.apply_fresh_tail(connection)


def test_independent_fresh_readback_invokes_validation_without_replay(repository, monkeypatch):
    add_future(repository)
    monkeypatch.setattr(common.stack, "ROOT", repository)
    module = Mock()
    module.startup_validate.return_value = True
    unit = Mock()
    unit.module.return_value = module
    monkeypatch.setattr(auto, "select_unit", Mock(return_value=unit))
    connection = Mock()
    auto.validate_current_tail(connection)
    module.startup_validate.assert_called_once_with(connection, None)
    unit.apply_revision.assert_not_called()
    module.startup_validate.return_value = False
    with pytest.raises(common.SchemaUpgradeError, match="committed schema acceptance failed"):
        auto.validate_current_tail(connection)
