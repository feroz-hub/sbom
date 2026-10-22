"""101->102 startup contract; no live resources, secrets or database access."""

import copy
from unittest.mock import MagicMock, Mock

import pytest
from scripts import greenfield_migrations as common
from scripts import greenfield_resource_migrations as unit

from tests.test_greenfield_startup_migrations import IDENTITY
from tests.test_greenfield_startup_migrations import flow as flow


@pytest.fixture
def resource_flow(flow, monkeypatch):
    monkeypatch.setattr(common.stack, "REVISION", unit.CURRENT)
    flow.marker.return_value = (IDENTITY, unit.PREVIOUS)
    flow.before["data"].update({table: [2, "synthetic unchanged"] for table in unit.TABLES})
    monkeypatch.setattr(unit, "verify_sources", common.verify_sources)
    monkeypatch.setattr(unit, "engine", Mock(return_value=flow.engine))
    monkeypatch.setattr(unit, "inspect_current", flow.marker)
    monkeypatch.setattr(unit, "before_upgrade", Mock(return_value=flow.before))
    monkeypatch.setattr(unit, "snapshot", Mock(return_value=flow.before))
    monkeypatch.setattr(unit, "validate_after", Mock())
    monkeypatch.setattr(unit, "backup_and_rehearse", flow.backup)
    flow.body = Mock(side_effect=lambda c: flow.events.append("migration102"))
    monkeypatch.setattr(unit, "apply_revision", flow.body)
    return flow


@pytest.mark.parametrize("answer", ["", "yes", "102", common.CONFIRMATION])
def test_only_exact_separate_101_102_confirmation_authorizes(resource_flow, answer):
    with pytest.raises(common.SchemaUpgradeError, match="not approved"):
        common.ensure_current(confirm=lambda: answer)
    resource_flow.backup.assert_not_called()
    resource_flow.body.assert_not_called()
    assert not resource_flow.events


def test_noninteractive_start_refuses(resource_flow, monkeypatch):
    monkeypatch.setattr(common.sys.stdin, "isatty", lambda: False)
    with pytest.raises(common.SchemaUpgradeError, match="interactive migration approval"):
        common.ensure_current()
    resource_flow.backup.assert_not_called()
    resource_flow.body.assert_not_called()


def test_backup_single_transaction_three_locks_and_closed_independent_readback(resource_flow):
    common.ensure_current(confirm=lambda: unit.CONFIRMATION)
    f = resource_flow
    f.backup.assert_called_once_with(f.engine, f.before, IDENTITY)
    f.body.assert_called_once()
    assert f.events.count("migration102") == f.events.count("commit") == 1
    assert f.events.count("open") == f.events.count("close") == 2
    assert f.events.index("close") < f.events.index("reader rollback")
    for table in unit.TABLES:
        assert f.events.index(f"LOCK TABLE ONLY public.{table} IN ACCESS EXCLUSIVE MODE NOWAIT") < f.events.index(
            "migration102"
        )
    assert "SELECT pg_advisory_xact_lock(7160085102)" in f.events
    assert "SELECT pg_advisory_xact_lock(7160085101)" not in f.events
    assert not (f.tmp / "pending-schema-upgrade.json").exists()
    assert (f.folder / "upgrade-accepted.json").exists()


def test_already102_never_migrates_or_prompts(resource_flow):
    resource_flow.marker.return_value = (IDENTITY, unit.CURRENT)
    prompt = Mock(side_effect=AssertionError("no prompt for accepted current schema"))
    common.ensure_current(confirm=prompt)
    prompt.assert_not_called()
    resource_flow.backup.assert_not_called()
    resource_flow.body.assert_not_called()


@pytest.mark.parametrize("failure", ["backup", "source", "locked", "body", "rollback", "readback", "commit"])
def test_failures_stop_without_retry_or_automatic_repair(resource_flow, failure):
    f = resource_flow
    if failure == "backup":
        f.backup.side_effect = common.SchemaUpgradeError("synthetic backup failure")
    elif failure == "source":
        unit.verify_sources.side_effect = [None, common.SchemaUpgradeError("source changed")]
    elif failure == "locked":
        unit.snapshot.return_value = {"drift": True}
    elif failure in {"body", "rollback"}:
        f.body.side_effect = RuntimeError("sensitive synthetic driver arguments")
        if failure == "rollback":
            f.transaction.rollback.side_effect = RuntimeError("synthetic rollback failure")
    elif failure == "readback":
        unit.validate_after.side_effect = [None, common.SchemaUpgradeError("readback drift")]
    elif failure == "commit":
        f.transaction.commit.side_effect = RuntimeError("lost acknowledgement")
    with pytest.raises(common.SchemaUpgradeError) as caught:
        common.ensure_current(confirm=lambda: unit.CONFIRMATION)
    assert "sensitive" not in str(caught.value)
    assert f.body.call_count <= 1 and f.transaction.commit.call_count <= 1
    if failure in {"backup", "source"}:
        f.body.assert_not_called()
    if failure in {"locked", "body", "rollback"}:
        f.transaction.rollback.assert_called_once()
        f.transaction.commit.assert_not_called()
    if failure == "commit":
        assert "UNKNOWN COMMIT" in str(caught.value)
        f.transaction.rollback.assert_not_called()
        assert f.engine.connect.call_count == 1
    if failure == "readback":
        assert "committed but acceptance is incomplete" in str(caught.value)
        f.transaction.rollback.assert_not_called()
    assert f.events.count("open") == f.events.count("close")
    if failure not in {"backup", "source"}:
        assert (f.tmp / "pending-schema-upgrade.json").exists()
        with pytest.raises(common.SchemaUpgradeError, match="manual reconciliation"):
            common.ensure_current(confirm=lambda: unit.CONFIRMATION)


def test_existing_attempt_claim_blocks_even_current102(resource_flow):
    (resource_flow.tmp / "pending-schema-upgrade.json").write_text("synthetic attempt")
    resource_flow.marker.return_value = (IDENTITY, unit.CURRENT)
    with pytest.raises(common.SchemaUpgradeError, match="manual reconciliation"):
        common.ensure_current(confirm=lambda: unit.CONFIRMATION)
    resource_flow.marker.assert_not_called()


def test_backup_requires_revision101_full_snapshot_and_new_pre102_rehearsal(monkeypatch):
    backup = Mock(return_value="synthetic private folder")
    monkeypatch.setattr(common, "backup_and_rehearse", backup)
    assert unit.backup_and_rehearse("engine", "snapshot", IDENTITY) == "synthetic private folder"
    backup.assert_called_once_with("engine", "snapshot", IDENTITY, predecessor=unit.PREVIOUS, snapshotter=unit.snapshot)


def test_preflight_preserves_existing_iam_uuid_in_data_snapshot(monkeypatch):
    snapshot = Mock(return_value="complete existing rows")
    monkeypatch.setattr(common, "snapshot", snapshot)
    assert unit.snapshot("connection") == "complete existing rows"
    snapshot.assert_called_once_with("connection", omit_public_id_tables=())


def test_reviewed_sources_match_real_files_without_credentials():
    unit.verify_sources()


@pytest.fixture
def catalog(monkeypatch):
    keys = (
        "relations",
        "columns",
        "constraints",
        "triggers",
        "functions",
        "schema",
        "sequences",
        "database",
        "database_settings",
        "roles",
        "default_acls",
    )
    before = {
        "catalog": {key: [] for key in keys},
        "data": {name: [2, "unchanged data and IAM UUIDs"] for name in (*unit.TABLES, "iam_users")},
    }
    after = copy.deepcopy(before)
    for name in unit.TABLES:
        after["catalog"]["relations"].append([f"uq_{name}_public_id", "i", "p", False, "greenfield_owner", None])
        after["catalog"]["columns"].extend(
            [
                [name, "public_id", "uuid", True, "gen_random_uuid()"],
                [f"uq_{name}_public_id", "public_id", "uuid", False, None],
            ]
        )
        after["catalog"]["constraints"].extend(
            [
                [name, f"uq_{name}_public_id", "UNIQUE (public_id)", True],
                [name, f"ck_{name}_public_id_v4", unit.UUID_CHECK, True],
            ]
        )
        after["catalog"]["triggers"].extend(
            [
                [name, f"trg_{name}_public_id_allocate", "O", "synthetic trigger"],
                [name, f"trg_{name}_public_id_immutable", "O", "synthetic trigger"],
            ]
        )
    after["catalog"]["functions"].append(
        ["resource_public_identity_guard_v1", "greenfield_owner", "{}", "synthetic definition"]
    )
    monkeypatch.setattr(common, "snapshot", Mock(return_value=after))
    monkeypatch.setattr(unit, "_validate_user", Mock())
    monkeypatch.setattr(unit, "_validate_identities", Mock())
    c = Mock()
    c.exec_driver_sql.return_value.scalars.return_value.all.return_value = [unit.CURRENT]
    return before, after, c


def test_exact_three_table_schema_delta_and_seven_existing_uuids_preserved(catalog):
    before, after, c = catalog
    unit.validate_after(c, before)
    common.snapshot.assert_called_once_with(c, omit_public_id_tables=unit.TABLES)
    unit._validate_user.assert_called_once()
    unit._validate_identities.assert_called_once()


@pytest.mark.parametrize(
    "category",
    [
        "relations",
        "columns",
        "constraints",
        "triggers",
        "functions",
        "schema",
        "sequences",
        "database",
        "database_settings",
        "roles",
        "default_acls",
    ],
)
def test_unrelated_catalog_drift_is_not_hidden_by_new_columns(catalog, category):
    before, after, c = catalog
    after["catalog"][category].append(["unexpected", "unapproved"])
    with pytest.raises(common.SchemaUpgradeError, match="catalog difference"):
        unit.validate_after(c, before)


@pytest.mark.parametrize("table", ["iam_users", *unit.TABLES])
def test_existing_values_cannot_change(catalog, table):
    before, after, c = catalog
    after["data"][table][1] = "changed credentials, roles, history or existing UUIDs"
    with pytest.raises(common.SchemaUpgradeError, match="values changed"):
        unit.validate_after(c, before)


def test_marker_requires_exactly102_on_readback(catalog):
    before, after, c = catalog
    c.exec_driver_sql.return_value.scalars.return_value.all.return_value = [unit.PREVIOUS]
    with pytest.raises(common.SchemaUpgradeError, match="revision verification failed"):
        unit.validate_after(c, before)


@pytest.fixture
def identity_schema():
    from app.resource_public_identity import GUARD_SQL

    name = "tenant_users"
    function = "resource_public_identity_guard_v1"
    catalog = {
        "columns": [[name, "public_id", "uuid", True, "gen_random_uuid()"]],
        "relations": [
            [name, "r", "p", False, "greenfield_owner", None],
            [f"uq_{name}_public_id", "i", "p", False, "greenfield_owner", None],
        ],
        "constraints": [
            [name, f"uq_{name}_public_id", "UNIQUE (public_id)", True],
            [name, f"ck_{name}_public_id_v4", unit.UUID_CHECK, True],
        ],
        "triggers": [
            [
                name,
                f"trg_{name}_public_id_allocate",
                "O",
                f"CREATE TRIGGER trg_{name}_public_id_allocate BEFORE INSERT ON public.{name} FOR EACH ROW EXECUTE FUNCTION {function}()",
            ],
            [
                name,
                f"trg_{name}_public_id_immutable",
                "O",
                f"CREATE TRIGGER trg_{name}_public_id_immutable AFTER UPDATE ON public.{name} FOR EACH ROW WHEN ((old.public_id IS DISTINCT FROM new.public_id)) EXECUTE FUNCTION {function}()",
            ],
        ],
    }
    guard = ["greenfield_owner", False, "v", ["search_path=pg_catalog"], GUARD_SQL.split("$guard$")[1], False, True]
    c = Mock()
    c.exec_driver_sql.side_effect = lambda sql: Mock(
        one=Mock(return_value=(2, 2, 0) if sql.startswith("SELECT count") else tuple(guard))
    )
    return catalog, guard, c, function, GUARD_SQL


def test_exact_identity_definition_and_owner_only_execute_acl_pass(identity_schema):
    catalog, guard, c, function, sql = identity_schema
    unit._validate_identities(c, catalog, ("tenant_users",), function, sql)
    assert c.exec_driver_sql.call_count == 2


@pytest.mark.parametrize(
    "defect",
    [
        "missing_column",
        "wrong_type",
        "nullable",
        "wrong_default",
        "wrong_owner",
        "missing_index",
        "missing_constraint",
        "unvalidated",
        "wrong_check",
        "disabled_trigger",
        "wrong_trigger",
        "extra_trigger",
        "security_definer",
        "function_source",
        "public_execute",
        "additional_grantee",
        "wrong_function_owner",
        "wrong_search_path",
    ],
)
def test_identity_metadata_security_drift_refuses(identity_schema, defect):
    catalog, guard, c, function, sql = identity_schema
    if defect == "missing_column":
        catalog["columns"].clear()
    elif defect == "wrong_type":
        catalog["columns"][0][2] = "text"
    elif defect == "nullable":
        catalog["columns"][0][3] = False
    elif defect == "wrong_default":
        catalog["columns"][0][4] = "unreviewed()"
    elif defect == "wrong_owner":
        catalog["relations"][0][4] = "other"
    elif defect == "missing_index":
        catalog["relations"].pop()
    elif defect == "missing_constraint":
        catalog["constraints"].pop()
    elif defect == "unvalidated":
        catalog["constraints"][1][3] = False
    elif defect == "wrong_check":
        catalog["constraints"][1][2] = "CHECK (true)"
    elif defect == "disabled_trigger":
        catalog["triggers"][0][2] = "D"
    elif defect == "wrong_trigger":
        catalog["triggers"][1][3] = "unreviewed definition"
    elif defect == "extra_trigger":
        catalog["triggers"].append(["tenant_users", "extra_public_id", "O", "unreviewed"])
    elif defect == "security_definer":
        guard[1] = True
    elif defect == "function_source":
        guard[4] = "unreviewed"
    elif defect == "public_execute":
        guard[5] = True
    elif defect == "additional_grantee":
        guard[6] = False
    elif defect == "wrong_function_owner":
        guard[0] = "greenfield_setup"
    elif defect == "wrong_search_path":
        guard[3] = ["search_path=public"]
    with pytest.raises(common.SchemaUpgradeError):
        unit._validate_identities(c, catalog, ("tenant_users",), function, sql)


@pytest.mark.parametrize("counts", [(2, 1, 0), (2, 2, 1)])
def test_uuid_duplicate_or_invalid_row_refuses(identity_schema, counts):
    catalog, guard, c, function, sql = identity_schema
    c.exec_driver_sql.side_effect = lambda query: Mock(one=Mock(return_value=counts))
    with pytest.raises(common.SchemaUpgradeError, match="allocation/uniqueness/version/variant"):
        unit._validate_identities(c, catalog, ("tenant_users",), function, sql)


@pytest.mark.parametrize("markers", [[], [common.PREVIOUS], ["103_unreviewed"], [unit.PREVIOUS, unit.CURRENT]])
def test_database_marker_cannot_skip_or_chain_units(monkeypatch, markers):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.exec_driver_sql.return_value.scalar_one.return_value = "on"
    connection.exec_driver_sql.return_value.scalars.return_value.all.return_value = markers
    engine = Mock(connect=Mock(return_value=connection))
    monkeypatch.setattr(common, "identity", Mock(return_value=IDENTITY))
    with pytest.raises(common.SchemaUpgradeError, match="no skipping, stamping or chained upgrade"):
        unit.inspect_current(engine)
    connection.__exit__.assert_called_once()


def test_preflight_cannot_accept_a_readwrite_connection(monkeypatch):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.exec_driver_sql.return_value.scalar_one.return_value = "off"
    monkeypatch.setattr(common, "identity", Mock(return_value=IDENTITY))
    with pytest.raises(common.SchemaUpgradeError, match="READ ONLY"):
        unit.inspect_current(Mock(connect=Mock(return_value=connection)))
