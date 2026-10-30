"""No live database, Docker, credential or service access in this module."""

import copy
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import greenfield_migrations as migration

IDENTITY = ("sbom_greenfield_uuid", "greenfield_setup", "160015", "synthetic-cluster", "greenfield_setup")


@pytest.fixture
def flow(monkeypatch, tmp_path):
    monkeypatch.setattr(migration.stack, "current_revision", lambda: migration.CURRENT)
    monkeypatch.setattr(migration.stack, "STATE", tmp_path)
    monkeypatch.setattr(migration.stack, "verify_resources", Mock())
    monkeypatch.setattr(migration, "verify_sources", Mock())
    events = []
    transaction = Mock()
    transaction.commit.side_effect = lambda: events.append("commit")
    transaction.rollback.side_effect = lambda: events.append("rollback")

    class Connection:
        def __enter__(self):
            events.append("open")
            return self

        def __exit__(self, *args):
            events.append("close")

        def exec_driver_sql(self, sql):
            events.append(sql)

        def begin(self):
            return transaction

        def rollback(self):
            events.append("reader rollback")

    engine = Mock()
    engine.connect.side_effect = Connection
    monkeypatch.setattr(migration, "engine", Mock(return_value=engine))
    marker = Mock(return_value=(IDENTITY, migration.PREVIOUS))
    monkeypatch.setattr(migration, "inspect_current", marker)
    monkeypatch.setattr(migration, "identity", Mock(return_value=IDENTITY))
    monkeypatch.setattr(migration, "exclusive", Mock())
    before = {"data": {"iam_users": [2, "synthetic digest"]}}
    monkeypatch.setattr(migration, "before_upgrade", Mock(return_value=before))
    monkeypatch.setattr(migration, "snapshot", Mock(return_value=before))
    monkeypatch.setattr(migration, "validate_after", Mock())
    folder = tmp_path / "synthetic-backup"
    folder.mkdir()
    backup = Mock(return_value=folder)
    monkeypatch.setattr(migration, "backup_and_rehearse", backup)
    from app import iam_schema

    body = Mock(side_effect=lambda c: events.append("migration101"))
    monkeypatch.setattr(iam_schema, "apply_user_uuid_revision", body)
    return SimpleNamespace(
        events=events,
        transaction=transaction,
        engine=engine,
        backup=backup,
        before=before,
        folder=folder,
        tmp=tmp_path,
        marker=marker,
        body=body,
    )


def test_current_schema_starts_without_prompt_or_migration(flow):
    flow.marker.return_value = (IDENTITY, migration.CURRENT)
    prompt = Mock(side_effect=AssertionError("unnecessary prompt"))
    migration._ensure_unit(migration, confirm=prompt)
    prompt.assert_not_called()
    flow.backup.assert_not_called()
    flow.body.assert_not_called()
    flow.engine.dispose.assert_called_once()


@pytest.mark.parametrize("answer", ["", "yes", "101", "UPGRADE other_database 100 TO 101"])
def test_unapproved_upgrade_does_not_backup_or_write(flow, answer):
    with pytest.raises(migration.SchemaUpgradeError, match="not approved"):
        migration._ensure_unit(migration, confirm=lambda: answer)
    flow.backup.assert_not_called()
    flow.body.assert_not_called()
    assert flow.events == []


def test_noninteractive_start_cannot_approve_itself(flow, monkeypatch):
    monkeypatch.setattr(migration.sys.stdin, "isatty", lambda: False)
    with pytest.raises(migration.SchemaUpgradeError, match="interactive migration approval"):
        migration._ensure_unit(
            migration,
        )
    flow.body.assert_not_called()
    flow.backup.assert_not_called()


def test_confirmed_upgrade_backup_precedes_single_write_and_separate_readback(flow):
    migration._ensure_unit(migration, confirm=lambda: migration.CONFIRMATION)
    flow.backup.assert_called_once_with(flow.engine, flow.before, IDENTITY)
    flow.body.assert_called_once()
    assert flow.events.count("migration101") == flow.events.count("commit") == 1
    assert flow.events.count("open") == flow.events.count("close") == 2
    assert flow.events.index("close") < flow.events.index("reader rollback")
    assert flow.events.index("SET TRANSACTION READ WRITE") < flow.events.index("migration101")
    assert flow.events.index("SET LOCAL ROLE greenfield_owner") < flow.events.index("migration101")
    assert not (flow.tmp / "pending-schema-upgrade.json").exists()
    assert (flow.folder / "upgrade-accepted.json").exists()
    journal = [json.loads(line)["event"] for line in (flow.folder / "upgrade-events.jsonl").read_text().splitlines()]
    assert journal == [
        "single_write_attempt_claimed",
        "precommit_checks_passed",
        "commit_acknowledged",
        "write_connection_closed",
        "independent_readback_rolled_back_and_closed",
    ]


def test_backup_failure_cannot_reach_ddl(flow):
    flow.backup.side_effect = migration.SchemaUpgradeError("backup verification failed")
    with pytest.raises(migration.SchemaUpgradeError, match="backup verification failed"):
        migration._ensure_unit(migration, confirm=lambda: migration.CONFIRMATION)
    flow.body.assert_not_called()
    assert not flow.events


def test_source_is_rechecked_after_backup_before_any_write(flow):
    migration.verify_sources.side_effect = [None, migration.SchemaUpgradeError("source changed")]
    with pytest.raises(migration.SchemaUpgradeError, match="source changed"):
        migration._ensure_unit(migration, confirm=lambda: migration.CONFIRMATION)
    flow.body.assert_not_called()


def test_database_changed_after_backup_refuses(flow):
    flow.marker.side_effect = [(IDENTITY, migration.PREVIOUS), (IDENTITY, migration.CURRENT)]
    with pytest.raises(migration.SchemaUpgradeError, match="changed after review"):
        migration._ensure_unit(migration, confirm=lambda: migration.CONFIRMATION)
    flow.body.assert_not_called()


def test_locked_catalog_drift_rolls_back_and_physically_closes(flow):
    migration.snapshot.return_value = {"unexpected": "catalog drift"}
    with pytest.raises(migration.SchemaUpgradeError, match="before locked migration"):
        migration._ensure_unit(migration, confirm=lambda: migration.CONFIRMATION)
    flow.body.assert_not_called()
    flow.transaction.rollback.assert_called_once()
    flow.transaction.commit.assert_not_called()
    assert flow.events.count("close") == 1
    assert (flow.tmp / "pending-schema-upgrade.json").exists()


def test_precommit_failure_retains_manual_reconciliation_claim(flow):
    flow.body.side_effect = RuntimeError("synthetic unprintable driver credential")
    with pytest.raises(migration.SchemaUpgradeError, match="precommit migration") as caught:
        migration._ensure_unit(migration, confirm=lambda: migration.CONFIRMATION)
    assert "credential" not in str(caught.value)
    flow.transaction.rollback.assert_called_once()
    assert flow.events.count("close") == 1
    assert (flow.tmp / "pending-schema-upgrade.json").exists()


def test_unknown_commit_never_retries_rolls_back_or_reads_back(flow):
    flow.transaction.commit.side_effect = RuntimeError("lost acknowledgement")
    with pytest.raises(migration.SchemaUpgradeError, match="UNKNOWN COMMIT"):
        migration._ensure_unit(migration, confirm=lambda: migration.CONFIRMATION)
    flow.transaction.rollback.assert_not_called()
    assert flow.engine.connect.call_count == 1
    assert (flow.tmp / "pending-schema-upgrade.json").exists()


def test_committed_but_failed_acceptance_stops_services_and_future_attempts(flow):
    migration.validate_after.side_effect = [None, migration.SchemaUpgradeError("readback drift")]
    with pytest.raises(migration.SchemaUpgradeError, match="committed but acceptance is incomplete"):
        migration._ensure_unit(migration, confirm=lambda: migration.CONFIRMATION)
    flow.transaction.commit.assert_called_once()
    flow.transaction.rollback.assert_not_called()
    assert flow.events.count("close") == 2
    flow.marker.reset_mock()
    with pytest.raises(migration.SchemaUpgradeError, match="manual reconciliation"):
        migration._ensure_unit(migration, confirm=lambda: migration.CONFIRMATION)
    flow.marker.assert_not_called()


def test_existing_pending_claim_cannot_be_bypassed_even_on_schema101(flow):
    (flow.tmp / "pending-schema-upgrade.json").write_text("synthetic pending attempt")
    flow.marker.return_value = (IDENTITY, migration.CURRENT)
    with pytest.raises(migration.SchemaUpgradeError, match="manual reconciliation"):
        migration._ensure_unit(migration, confirm=lambda: migration.CONFIRMATION)
    flow.marker.assert_not_called()
    flow.body.assert_not_called()


def test_source_pins_refuse_tampering(monkeypatch, tmp_path):
    p = tmp_path / "synthetic.py"
    p.write_text("reviewed")
    monkeypatch.setattr(migration.stack, "ROOT", tmp_path)
    monkeypatch.setattr(migration, "PINS", {p.name: hashlib.sha256(p.read_bytes()).hexdigest()})
    migration.verify_sources()
    p.write_text("changed")
    with pytest.raises(migration.SchemaUpgradeError, match="source changed"):
        migration.verify_sources()


def test_private_backup_artifact_is_exclusive_private_and_rejects_symlinks(tmp_path):
    p = tmp_path / "backup.key"
    migration._private(p, b"synthetic")
    assert p.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        migration._private(p, b"replacement")
    link = tmp_path / "symlink"
    link.symlink_to(p)
    with pytest.raises(FileExistsError):
        migration._private(link, b"replacement")
    assert p.read_bytes() == b"synthetic"


@pytest.mark.parametrize("database", ["sbom_greenfield_uuid", "uuid_w2_f_fresh", "sbom_other", "postgres", "../bad"])
def test_backup_database_override_is_fixed_and_refuses_other_targets(monkeypatch, database):
    monkeypatch.setattr(migration.stack, "url", lambda *args: "postgresql+psycopg://synthetic@127.0.0.1:56044/postgres")
    with pytest.raises(migration.SchemaUpgradeError, match="Invalid task-owned"):
        migration.engine(database)


@pytest.mark.parametrize(
    "host,port,user",
    [("remote", 56044, "greenfield_setup"), ("127.0.0.1", 56043, "greenfield_setup"), ("127.0.0.1", 56044, "other")],
)
def test_wrong_connection_target_refused(monkeypatch, host, port, user):
    monkeypatch.setattr(migration.stack, "url", lambda *args: f"postgresql+psycopg://{user}@{host}:{port}/postgres")
    with pytest.raises(migration.SchemaUpgradeError, match="Unexpected Greenfield migration endpoint"):
        migration.engine()


@pytest.mark.parametrize("name", ["PGSERVICE", "PGHOSTADDR", "PGOPTIONS", "PGPASSWORD", "PGDATABASE"])
def test_ambient_postgres_configuration_cannot_override_target(monkeypatch, name):
    monkeypatch.setenv(name, "synthetic override")
    read = Mock(side_effect=AssertionError("credentials must not be read"))
    monkeypatch.setattr(migration.stack, "url", read)
    with pytest.raises(migration.SchemaUpgradeError, match=r"Ambient PG\*"):
        migration.engine()
    read.assert_not_called()


def test_exact_catalog_model_rejects_any_existing_data_or_schema_change(monkeypatch):
    # Exercise the exact-delta check independently of the orchestration mocks.
    before = {
        "catalog": {
            k: [] for k in ("relations", "columns", "constraints", "triggers", "functions", "schema", "sequences")
        },
        "data": {"iam_users": [2, "digest"]},
    }
    changed = copy.deepcopy(before)
    changed["data"]["iam_users"] = [2, "changed digest"]
    monkeypatch.setattr(migration, "snapshot", lambda c: changed)
    with pytest.raises(migration.SchemaUpgradeError, match="data changed"):
        migration.validate_after(Mock(), before)
    changed["data"] = before["data"]
    changed["catalog"]["relations"] = [["unreviewed", "r"]]
    with pytest.raises(migration.SchemaUpgradeError, match="catalog difference"):
        migration.validate_after(Mock(), before)


def test_restore_parity_accepts_only_pg16_literal_array_cast_representation():
    original = (
        "CHECK (((status)::text = ANY ((ARRAY['ACTIVE'::character varying, 'PENDING'::character varying])::text[])))"
    )
    restored = "CHECK (((status)::text = ANY (ARRAY[('ACTIVE'::character varying)::text, ('PENDING'::character varying)::text])))"
    before = {
        "catalog": {"constraints": [["iam_users", "status", original, True]], "roles": []},
        "data": {"iam_users": [2, "same"]},
    }
    after = copy.deepcopy(before)
    after["catalog"]["constraints"][0][2] = restored
    assert migration.restored_snapshot_matches(before, after)
    after["catalog"]["constraints"][0][2] = restored.replace("PENDING", "DIFFERENT")
    assert not migration.restored_snapshot_matches(before, after)
    after["catalog"]["constraints"][0][2] = restored
    after["catalog"]["constraints"][0][3] = False
    assert not migration.restored_snapshot_matches(before, after)
    after["catalog"]["constraints"][0][3] = True
    after["catalog"]["roles"] = [["unapproved"]]
    assert not migration.restored_snapshot_matches(before, after)


def test_restore_parity_rejects_nonliteral_expression_cast_changes():
    before = {"catalog": {"constraints": [["table", "check", "CHECK ((ARRAY[func()])::text[])", True]]}, "data": {}}
    after = copy.deepcopy(before)
    after["catalog"]["constraints"][0][2] = "CHECK (ARRAY[(func())::text])"
    assert not migration.restored_snapshot_matches(before, after)


def test_public_launcher_delegates_to_automatic_graph_discovery(monkeypatch):
    from scripts import greenfield_auto_migrations as automatic

    execute = Mock()
    monkeypatch.setattr(automatic, "ensure_current", execute)
    migration.ensure_current()
    execute.assert_called_once_with(confirm=None)
