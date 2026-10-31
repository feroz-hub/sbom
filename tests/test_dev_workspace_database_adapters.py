"""Synthetic adapter boundaries only: no driver/engine/socket or application fixtures."""

from __future__ import annotations

import ast
import importlib
import io
import os
import socket
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from scripts import dev_instance_plan as instances
from scripts import dev_workspace_compose as compose
from scripts import dev_workspace_database_adapters as adapters
from scripts import dev_workspace_database_prepare as db
from scripts import dev_workspace_engine as engine
from scripts import dev_workspace_provider as provider

PRIVATE = "synthetic_private_credential_never_disclose_123456789"


@pytest.fixture(autouse=True)
def no_live(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Live operation forbidden")

    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    # libpq connects in C and would bypass Python socket tripwires.
    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=denied))
    for key in tuple(os.environ):
        if key.startswith("PG") or key in {"SSLKEYLOGFILE", "OPENSSL_CONF", "OPENSSL_MODULES"}:
            monkeypatch.delenv(key)


@pytest.fixture
def prepared():
    descriptor = instances.plan_instance(
        repository_id="a" * 64, worktree_id="b" * 64, commit="c" * 40, generation=1, mode="isolated", auth_mode="native"
    ).descriptor
    names = ("postgres", "redis", "mailpit")
    policy = provider.ContainerPolicy(
        "docker",
        "d" * 64,
        "e" * 64,
        {n: "approved/" + n + "@sha256:" + str(i + 1) * 64 for i, n in enumerate(names)},
        {n: "1000:1000" for n in names},
    )
    proposal = provider.plan_provider(descriptor, policy)
    paths, files = [], []
    for reference in (v for values in compose.secret_layout(proposal).values() for v in values.values()):
        path = Path("C:/synthetic-private" if os.name == "nt" else "/synthetic-private") / reference
        paths.append(compose.SecretFile(reference, str(path), sys.platform))
        files.append(engine.SecretFile(reference, path, (1, 2, 55, 4, 5)))
    policy2 = compose.ComposePolicy(
        policy.policy_id,
        "f" * 64,
        sys.platform,
        {n: "linux/amd64" for n in names},
        dict(compose._PROFILES),
        {n: compose.ResourceLimits("1.5", 128 * 1048576, 192, 1048576, 1048576) for n in names},
        {n: compose.DataOwnership(1000, 1000, 0o700) for n in ("postgres", "redis")},
        {n: "preowned-empty-volume" for n in ("postgres", "redis")},
        compose.HealthPolicy(3, 2, 5, 0, 10),
        tuple(paths),
    )
    review = compose.ComposeContractReview(
        policy.policy_id,
        proposal.fingerprint,
        compose.policy_fingerprint(policy2),
        policy2.private_binding(),
        {n: "VERIFIED" for n in compose._CHECKS},
    )
    manifest = compose.plan_compose(proposal, policy2, review=review)
    records = engine.ResourceRecords(
        policy.engine_identity,
        proposal.fingerprint,
        tuple(engine.ContainerRecord(n, str(i + 1) * 64, "2026-10-31T00:00:00Z") for i, n in enumerate(names)),
        "4" * 64,
        ((proposal.volumes[0], "5" * 64, "a" * 64), (proposal.volumes[1], "6" * 64, "b" * 64)),
        tuple(files),
    )
    return SimpleNamespace(proposal=proposal, manifest=manifest, records=records)


def plan(prepared, action="initdb"):
    prior = (
        None
        if action == "initdb"
        else db.PreparationReceipt(
            "initdb",
            db.plan_preparation(
                prepared.proposal,
                prepared.manifest,
                prepared.records,
                "initdb",
                confirm_database=prepared.proposal.descriptor.resources["database"],
                source_fingerprint="a" * 64,
            ).target.fingerprint(),
            adapters.cluster_fingerprint("123456789"),
        )
    )
    return db.plan_preparation(
        prepared.proposal,
        prepared.manifest,
        prepared.records,
        action,
        confirm_database=prepared.proposal.descriptor.resources["database"],
        source_fingerprint="a" * 64,
        prior=prior,
    )


class FakeClient(engine.DockerComposeClient):
    def __init__(self, planned):
        self.capability = SimpleNamespace(platform="linux/amd64")
        self.planned, self.calls, self.objects, self.count = planned, [], {}, 8
        self.output, self.exit_code, self.interrupt = b"SBOMPG1 1000 1000 700 EMPTY 0\n", 0, False
        self.drift, self.server = False, "created"

    def _current(self, request):
        self.calls.append(("current",))

    def _engine(self):
        self.calls.append(("engine",))

    def _resources(self, request, **kwargs):
        self.calls.append(("resources", kwargs))
        if self.drift:
            raise engine.EngineError("ENGINE_RESOURCE_DRIFT")
        return self.planned.records

    def _call(self, *args, timeout):
        self.calls.append((args, timeout))
        if args[:2] == ("container", "create"):
            cid = str(self.count) * 64
            self.count -= 1
            image_index = args.index(self.planned.target.image)
            labels = dict(item.split("=", 1) for i, item in enumerate(args) if i > 0 and args[i - 1] == "--label")
            mounts = []
            for i, item in enumerate(args):
                if i and args[i - 1] == "--mount":
                    parts = dict(part.split("=", 1) for part in item.split(",") if "=" in part)
                    mounts.append(
                        {
                            "Type": parts["type"],
                            "Name": parts["source"],
                            "Source": parts["source"],
                            "Destination": parts["target"],
                            "RW": "readonly" not in item.split(","),
                        }
                    )
            self.objects[cid] = {
                "Id": cid,
                "Image": "sha256:" + "f" * 64,
                "Config": {
                    "Image": self.planned.target.image,
                    "User": self.planned.target.user,
                    "Entrypoint": [args[args.index("--entrypoint") + 1]],
                    "Cmd": list(args[image_index + 1 :]),
                    "Labels": labels,
                    "Env": [],
                },
                "HostConfig": {
                    "NetworkMode": "none",
                    "ReadonlyRootfs": True,
                    "Privileged": False,
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges:true"],
                    "AutoRemove": False,
                    "RestartPolicy": {"Name": "no"},
                    "PidsLimit": 192,
                    "Memory": 805306368,
                    "NanoCpus": 1500000000,
                },
                "Mounts": mounts,
                "State": {"Status": "created", "ExitCode": 0},
            }
            return cid.encode() + b"\n"
        if args[:3] == ("container", "start", "--attach"):
            self.objects[args[-1]]["State"] = {
                "Status": "running" if self.interrupt else "exited",
                "ExitCode": self.exit_code,
            }
            if self.interrupt:
                raise KeyboardInterrupt
            return self.output
        if args[:2] == ("container", "stop"):
            self.objects[args[-1]]["State"]["Status"] = "exited"
            return b""
        self.server = "running"
        return b""

    def _inspect(self, kind, identifier):
        if kind == "image":
            return {
                "Id": "sha256:" + "f" * 64,
                "RepoDigests": [self.planned.target.image],
                "Os": "linux",
                "Architecture": "amd64",
                "Config": {"Env": []},
            }
        if identifier == self.planned.target.postgres_id:
            return {"State": {"Status": self.server}}
        return self.objects[identifier]


def provider_adapter(planned):
    client = FakeClient(planned)
    request = SimpleNamespace(recorded=planned.records, provider=planned.provider_plan, compose=planned.compose_plan)
    consent = db.Consent(planned.action, str(uuid4()), planned.fingerprint, planned.target.database)
    authority = SimpleNamespace(
        verify_adapter=Mock(
            return_value=adapters._CHECKS
            | {
                "helper-tools",
                "read-only-volume-observer",
                "preparation-server",
                "initdb-image-tools",
                "fresh-empty-volume",
                "bootstrap-superuser",
            }
        )
    )
    journal = SimpleNamespace(intent=Mock(), receipt=Mock())
    result = adapters.DockerPreparationAdapter(
        client,
        request,
        consent=consent,
        authority=authority,
        journal=journal,
        utility_contract=adapters.UtilityContract(planned.target.image, "linux/amd64"),
    )
    return result, client, authority, journal


def test_observation_uses_concrete_boundary_and_retains_recorded_helper(prepared):
    planned = plan(prepared)
    adapter, client, authority, journal = provider_adapter(planned)
    state = adapter.observe(planned)
    assert state.data_state == "EMPTY" and state.cluster_id is None and state.mode == 0o700
    assert journal.receipt.call_args.args == (planned, "observe-helper", "8" * 64)
    assert len([c for c in client.calls if c[0] == "resources"]) >= 3
    create = next(c[0] for c in client.calls if type(c[0]) is tuple and c[0][:2] == ("container", "create"))
    assert "readonly,volume-nocopy" in repr(create) and PRIVATE not in repr(create)
    assert authority.verify_adapter.call_args.args[3] == planned.records
    assert not any("remove" in repr(c) or "chown" in repr(c) for c in client.calls)


@pytest.mark.parametrize(
    "output",
    [
        b"PG_VERSION absent",
        b"SBOMPG1 0 1000 700 EMPTY 0\n",
        b"SBOMPG1 1000 1000 777 EMPTY 0\n",
        b"SBOMPG1 1000 1000 700 EMPTY 4\n",
        PRIVATE.encode(),
        b"SBOMPG1 1000 1000 700 INITIALIZED 18446744073709551616\n",
    ],
)
def test_observer_rejects_partial_unknown_or_bad_owner_without_output(prepared, output):
    planned = plan(prepared)
    adapter, client, _, _ = provider_adapter(planned)
    client.output = output
    with pytest.raises(adapters.AdapterError) as error:
        adapter.observe(planned)
    assert PRIVATE not in str(error.value) and "synthetic-private" not in str(error.value)


def test_observation_initialized_identity_matches_database_system_identity(prepared):
    planned = plan(prepared)
    adapter, client, _, _ = provider_adapter(planned)
    client.output = b"SBOMPG1 1000 1000 700 INITIALIZED 123456789\n"
    assert adapter.observe(planned).cluster_id == adapters.cluster_fingerprint(123456789)


@pytest.mark.parametrize("reason", ["contract", "authority", "drift", "consent"])
def test_helper_creation_has_no_default_authority(prepared, reason):
    planned = plan(prepared)
    adapter, client, authority, _ = provider_adapter(planned)
    if reason == "contract":
        adapter.contract = None
    elif reason == "authority":
        authority.verify_adapter.return_value = frozenset()
    elif reason == "drift":
        client.drift = True
    else:
        adapter.consent = replace(adapter.consent, plan_fingerprint="0" * 64)
    with pytest.raises(adapters.AdapterError):
        adapter.observe(planned)
    assert not client.objects


def test_durable_receipt_failure_retains_known_cid_before_any_start(prepared):
    planned = plan(prepared)
    adapter, client, _, journal = provider_adapter(planned)
    journal.receipt.side_effect = RuntimeError(PRIVATE)
    with pytest.raises(adapters.AdapterError) as error:
        adapter.observe(planned)
    assert error.value.helper_id == "8" * 64 and adapter.unconfirmed_helper_ids == {"8" * 64}
    assert client.objects["8" * 64]["State"]["Status"] == "created"
    assert PRIVATE not in str(error.value)


@pytest.mark.parametrize("failure", ["observe-helper", "initdb-helper"])
def test_executor_reports_actual_adapter_receipt_failure_cid_and_claim_boundary(prepared, failure):
    planned = plan(prepared)
    adapter, client, _, helper_journal = provider_adapter(planned)

    def receipt(plan, kind, object_id):
        if kind == failure:
            raise RuntimeError(PRIVATE)

    helper_journal.receipt.side_effect = receipt
    journal = SimpleNamespace(claim=Mock(return_value=True), intent=Mock(), receipt=Mock(), outcome=Mock())
    authority = SimpleNamespace(
        source_fingerprint=lambda plan: "a" * 64, verify=Mock(return_value=db._CHECKS | db._ACTION_CHECKS["initdb"])
    )
    executor = db.PreparationExecutor(provider_adapter=adapter, authority=authority, journal=journal)
    result = executor.execute(planned, adapter.consent)
    expected_id = "8" * 64 if failure == "observe-helper" else "6" * 64
    assert result.helper_id == expected_id and result.unconfirmed_helper_ids == (expected_id,)
    assert result.code == "DB_PREPARATION_UNCONFIRMED" and not result.cleanup_verified
    assert not result.completed and result.receipt is None
    assert client.objects[expected_id]["State"]["Status"] == "created"
    assert PRIVATE not in str(result.to_dict()) + repr(result)
    if failure == "observe-helper":
        journal.claim.assert_not_called()
        journal.intent.assert_not_called()
        journal.receipt.assert_not_called()
        journal.outcome.assert_not_called()
    else:
        journal.claim.assert_called_once()
        journal.outcome.assert_called_once_with(planned, result)


def test_initdb_exact_command_verified_before_start(prepared, monkeypatch):
    planned = plan(prepared)
    adapter, client, _, _ = provider_adapter(planned)
    monkeypatch.setattr(engine, "_file", lambda *a, **k: (1, 2, 55, 4, 5))
    cid = adapter.create_helper(planned, db.initdb_command(planned))
    assert adapter.run_helper(planned, cid, timeout=120) == 0
    with pytest.raises(adapters.AdapterError):
        adapter.create_helper(planned, db.initdb_command(planned) + ("--unsafe",))


@pytest.mark.parametrize(
    "field,value",
    [
        ("User", "0:0"),
        ("Image", "another@sha256:" + "a" * 64),
        ("Entrypoint", ["chown"]),
        ("Cmd", ["malicious"]),
        ("Labels", {}),
        ("Env", ["X=secret"]),
    ],
)
def test_helper_config_drift_blocks_start(prepared, field, value):
    planned = plan(prepared)
    adapter, client, _, _ = provider_adapter(planned)
    # Create observer, then mutate the independently inspected engine payload.
    command = (
        "container",
        "create",
        "--pull",
        "never",
        "--network",
        "none",
        "--user",
        planned.target.user,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--restart",
        "no",
        "--pids-limit",
        "192",
        "--memory",
        "805306368",
        "--cpus",
        "1.5",
        "--entrypoint",
        "/bin/sh",
        "--mount",
        "type=volume,source=" + planned.target.volume_id + ",target=/var/lib/postgresql/data,readonly,volume-nocopy",
        planned.target.image,
        "-c",
        adapters._OBSERVE,
    )
    cid = adapter._create(planned, "observe", command)
    client.objects[cid]["Config"][field] = value
    with pytest.raises(adapters.AdapterError):
        adapter._run(planned, cid, 10)
    assert client.objects[cid]["State"]["Status"] == "created"


def test_interrupted_helper_stops_only_reverified_original_cid(prepared):
    planned = plan(prepared)
    adapter, client, _, _ = provider_adapter(planned)
    client.interrupt = True
    with pytest.raises(adapters.AdapterError) as error:
        adapter.observe(planned)
    assert error.value.helper_id == "8" * 64
    assert ("container", "stop", "--time", "2", "8" * 64) in [c[0] for c in client.calls]
    assert not adapter.unconfirmed_helper_ids


def test_repeated_interrupt_during_helper_cleanup_retains_known_uncertainty(prepared, monkeypatch):
    planned = plan(prepared)
    adapter, client, _, _ = provider_adapter(planned)
    client.interrupt = True
    original = client._inspect

    def inspect(kind, identifier):
        if identifier in client.objects and client.objects[identifier]["State"]["Status"] == "running":
            raise KeyboardInterrupt
        return original(kind, identifier)

    monkeypatch.setattr(client, "_inspect", inspect)
    with pytest.raises(adapters.AdapterError) as error:
        adapter.observe(planned)
    assert error.value.helper_id == "8" * 64 and adapter.unconfirmed_helper_ids == {"8" * 64}
    assert not any(type(c[0]) is tuple and c[0][:2] == ("container", "stop") for c in client.calls)


def test_separate_preparation_start_gate_does_not_invoke_normal_start(prepared):
    planned = plan(prepared, "database")
    adapter, client, authority, _ = provider_adapter(planned)
    client._authorize = Mock(side_effect=AssertionError("normal start must retain DB-prepared gate"))
    adapter.start_server(planned, ("container", "start", planned.target.postgres_id), timeout=30)
    assert client.server == "running"
    assert authority.verify_adapter.call_args.args[2] == "start-server"
    client._authorize.assert_not_called()
    before = list(client.calls)
    with pytest.raises(adapters.AdapterError):
        adapter.start_server(planned, ("container", "start", planned.target.postgres_id), timeout=30)
    assert not any(
        call[0] == ("container", "start", planned.target.postgres_id) for call in client.calls[len(before) :]
    )


def test_preparation_start_refuses_unrelated_container_restart_drift(prepared, monkeypatch):
    planned = plan(prepared, "database")
    adapter, client, _, _ = provider_adapter(planned)
    original = client._resources

    def resources(request, **kwargs):
        if kwargs.get("refresh"):
            return replace(
                planned.records,
                containers=tuple(
                    replace(item, started_at="2026-11-01T00:00:00Z") if item.component == "redis" else item
                    for item in planned.records.containers
                ),
            )
        return original(request, **kwargs)

    monkeypatch.setattr(client, "_resources", resources)
    with pytest.raises(adapters.AdapterError) as error:
        adapter.start_server(planned, ("container", "start", planned.target.postgres_id), timeout=30)
    assert error.value.code == "DB_PREPARATION_UNCONFIRMED" and adapter.records == planned.records


class SQL:
    @staticmethod
    def SQL(value):
        return SimpleNamespace(format=lambda *parts: (value, parts))

    @staticmethod
    def Identifier(value):
        return ("identifier", value)


class FakeConnection:
    def __init__(self, planned):
        self.plan, self.calls, self.name = planned, [], "postgres"
        self.readonly, self.closed = False, False
        self.pgconn = SimpleNamespace(ssl_in_use=True, backend_pid=1234, change_password=Mock())
        self.roles, self.structure, self.revisions = [], [], []
        self.functions, self.types = [], []
        self.namespaces = [("public", 201, None)]
        self.unsafe = (False, False, False, False, False, False, True, True)
        self.identity_override = None

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        self.current = sql

    def fetchmany(self, limit):
        target = self.plan.target
        if self.current == adapters._IDENTITY:
            return [
                self.identity_override
                or (
                    self.name,
                    target.bootstrap_role,
                    target.bootstrap_role,
                    "on" if self.readonly else "off",
                    "3s",
                    "250ms",
                    "5s",
                )
            ]
        if self.current == adapters._ROLES:
            return self.roles
        if self.current == adapters._DATABASE:
            return [(101, target.owner_role)]
        if self.current == adapters._STRUCTURE:
            return self.structure
        if self.current == adapters._FUNCTIONS:
            return self.functions
        if self.current == adapters._TYPES:
            return self.types
        if self.current == adapters._NAMESPACES:
            return self.namespaces
        if self.current == adapters._UNSAFE:
            return [self.unsafe]
        if self.current == "SELECT system_identifier::text FROM pg_control_system()":
            return [("123456789",)]
        if self.current == "SHOW password_encryption":
            return [("scram-sha-256",)]
        if "version_num" in str(self.current):
            return self.revisions
        return [(202,)]

    def close(self):
        self.closed = True


def database_adapter(prepared, monkeypatch):
    planned = plan(prepared, "database")
    refs = compose.secret_layout(prepared.proposal)["postgres"]

    def item(name):
        return next(s for s in prepared.records.secrets if s.reference == refs[name])

    files = adapters.ConnectionFiles(item("bootstrap"), item("runtime"), item("ca"))
    monkeypatch.setattr(engine, "_file", lambda *args, **kwargs: files.ca.identity)
    monkeypatch.setattr(adapters, "_read_private_bytes", lambda *args, **kwargs: PRIVATE.encode())
    connection = FakeConnection(planned)

    def connect(**kwargs):
        connection.name, connection.readonly = kwargs["dbname"], "read_only=on" in kwargs["options"]
        return connection

    driver = SimpleNamespace(connect=Mock(side_effect=connect), sql=SQL, pq=SimpleNamespace(version=lambda: 170000))
    authority = SimpleNamespace(
        verify_database=Mock(return_value=adapters._CHECKS | {"database-session", "credential-audit"})
    )
    peer = Mock(return_value="f" * 64)
    adapter = adapters.PsycopgDatabaseAdapter(files, authority=authority, peer_verifier=peer, driver=driver)
    return planned, adapter, connection, driver, authority, peer


def test_connection_exact_target_tls_bounds_no_dotenv(prepared, monkeypatch):
    planned, adapter, connection, driver, _, _ = database_adapter(prepared, monkeypatch)
    session = adapter.open(planned, planned.target.database, readonly=True)
    args = driver.connect.call_args.kwargs
    assert args["host"] == args["hostaddr"] == "127.0.0.1" and args["port"] == planned.target.port
    assert args["sslmode"] == "verify-full" and args["gssencmode"] == "disable" and args["channel_binding"] == "require"
    assert args["connect_timeout"] == 3 and args["tcp_user_timeout"] == 3000 and args["autocommit"] is True
    state = session.inspect()
    assert state.cluster_id == adapters.cluster_fingerprint("123456789") and state.read_only and state.bounded
    assert PRIVATE not in repr(connection.calls) and "alembic" not in sys.modules
    with pytest.raises(adapters.AdapterError):
        session.begin()


@pytest.mark.parametrize(
    "name",
    [
        "PGSERVICE",
        "PGSERVICEFILE",
        "PGOPTIONS",
        "PGPASSWORD",
        "PGPASSFILE",
        "SSLKEYLOGFILE",
        "OPENSSL_CONF",
        "OPENSSL_MODULES",
    ],
)
def test_ambient_transport_configuration_blocks_before_connect(prepared, monkeypatch, name):
    planned, adapter, _, driver, _, _ = database_adapter(prepared, monkeypatch)
    monkeypatch.setenv(name, "private-untrusted-input")
    with pytest.raises(adapters.AdapterError):
        adapter.open(planned, "postgres")
    driver.connect.assert_not_called()


@pytest.mark.parametrize("problem", ["authority", "file", "tls", "peer", "identity", "target"])
def test_connection_fail_closed_and_closed_on_postconnect_failure(prepared, monkeypatch, problem):
    planned, adapter, connection, driver, authority, peer = database_adapter(prepared, monkeypatch)
    name = "postgres"
    if problem == "authority":
        authority.verify_database.return_value = frozenset()
    elif problem == "file":
        monkeypatch.setattr(engine, "_file", lambda *a, **k: (5, 4, 3, 2, 1))
    elif problem == "tls":
        connection.pgconn.ssl_in_use = False
    elif problem == "peer":
        peer.return_value = None
    elif problem == "identity":
        connection.identity_override = (
            "wrong",
            planned.target.bootstrap_role,
            planned.target.bootstrap_role,
            "off",
            "3s",
            "250ms",
            "5s",
        )
    else:
        name = "protected_database"
    with pytest.raises(adapters.AdapterError) as error:
        adapter.open(planned, name)
    assert PRIVATE not in str(error.value)
    assert connection.closed if driver.connect.called else not connection.closed


@pytest.mark.parametrize("unsafe_index", range(6))
def test_readonly_role_and_schema_observation_rejects_extra_privileges(prepared, monkeypatch, unsafe_index):
    planned, adapter, connection, _, _, _ = database_adapter(prepared, monkeypatch)
    connection.roles = [(planned.target.runtime_role, 202, True, False, False, False, False, False, False, [])]
    flags = list(connection.unsafe)
    flags[unsafe_index] = True
    connection.unsafe = tuple(flags)
    state = adapter.open(planned, planned.target.database).inspect()
    assert not state.runtime_grants_safe


def test_fixed_statements_identifier_composition_and_native_password_transport(prepared, monkeypatch):
    planned, adapter, connection, _, _, _ = database_adapter(prepared, monkeypatch)
    session = adapter.open(planned, planned.target.database)
    session.begin()
    session.apply("prepare-schema", db.statements(planned, "prepare-schema"))
    session.install_runtime_credential(planned.target.runtime_role, adapter.files.runtime.reference)
    connection.pgconn.change_password.assert_called_once_with(planned.target.runtime_role.encode(), PRIVATE.encode())
    assert all("PASSWORD" not in repr(sql) and PRIVATE not in repr(sql) for sql, _ in connection.calls)
    assert any(
        type(sql) is tuple and ("identifier", planned.target.runtime_role) in sql[1] for sql, _ in connection.calls
    )
    session.commit()
    session.close()
    assert connection.closed and not session.active


@pytest.mark.parametrize(
    "problem", ["old-libpq", "no-api", "encryption", "audit", "reference", "role", "no-transaction"]
)
def test_no_plaintext_password_fallback(prepared, monkeypatch, problem):
    planned, adapter, connection, driver, authority, _ = database_adapter(prepared, monkeypatch)
    session = adapter.open(planned, planned.target.database)
    if problem != "no-transaction":
        session.begin()
    role, reference = planned.target.runtime_role, adapter.files.runtime.reference
    change = connection.pgconn.change_password
    if problem == "old-libpq":
        driver.pq.version = lambda: 160000
    elif problem == "no-api":
        connection.pgconn.change_password = None
    elif problem == "encryption":
        original = session._rows
        session._rows = lambda sql, params=None: (
            [("md5",)] if sql == "SHOW password_encryption" else original(sql, params)
        )
    elif problem == "audit":
        authority.verify_database.return_value -= {"credential-audit"}
    elif problem == "reference":
        reference += "-other"
    elif problem == "role":
        role = planned.target.bootstrap_role
    with pytest.raises(adapters.AdapterError):
        session.install_runtime_credential(role, reference)
    change.assert_not_called()
    assert all("PASSWORD" not in repr(sql) and "log_statement" not in repr(sql) for sql, _ in connection.calls)


def test_pid_and_certificate_drift_rechecked_before_every_statement(prepared, monkeypatch):
    planned, adapter, connection, _, _, _ = database_adapter(prepared, monkeypatch)
    session = adapter.open(planned, planned.target.database)
    session.begin()
    connection.pgconn.backend_pid += 1
    with pytest.raises(adapters.AdapterError):
        session.apply("prepare-schema", db.statements(planned, "prepare-schema"))


@pytest.mark.parametrize("category", ["structure", "functions", "types", "namespaces"])
def test_catalog_structure_and_unknown_schema_drift_changes_fingerprint(prepared, monkeypatch, category):
    planned, adapter, connection, _, _, _ = database_adapter(prepared, monkeypatch)
    session = adapter.open(planned, planned.target.database, readonly=True)
    before = session.inspect()
    setattr(
        connection,
        category,
        [["private-definition", 999]]
        if category != "structure"
        else [[[999, "table_1", "r", 201, False, False, None]]],
    )
    after = session.inspect()
    assert after.schema_fingerprint != before.schema_fingerprint and not after.schema_empty
    assert "private-definition" not in repr(after) and PRIVATE not in repr(after)


def test_peer_drift_blocks_before_write(prepared, monkeypatch):
    planned, adapter, connection, _, _, peer = database_adapter(prepared, monkeypatch)
    session = adapter.open(planned, planned.target.database)
    session.begin()
    before = tuple(connection.calls)
    peer.return_value = "0" * 64
    with pytest.raises(adapters.AdapterError):
        session.apply("prepare-schema", db.statements(planned, "prepare-schema"))
    assert tuple(connection.calls) == before


def test_connected_cluster_must_match_independent_prior_receipt(prepared, monkeypatch):
    planned, adapter, connection, _, _, _ = database_adapter(prepared, monkeypatch)
    original = connection.fetchmany

    def fetchmany(limit):
        if connection.current == "SELECT system_identifier::text FROM pg_control_system()":
            return [("987654321",)]
        return original(limit)

    monkeypatch.setattr(connection, "fetchmany", fetchmany)
    with pytest.raises(adapters.AdapterError) as error:
        adapter.open(planned, planned.target.database)
    assert error.value.code == "DB_TARGET_UNVERIFIED" and connection.closed
    assert not any(sql == "BEGIN" for sql, _ in connection.calls)


def test_arbitrary_statements_rejected_without_execution(prepared, monkeypatch):
    planned, adapter, connection, _, _, _ = database_adapter(prepared, monkeypatch)
    session = adapter.open(planned, planned.target.database)
    session.begin()
    before = tuple(connection.calls)
    with pytest.raises(adapters.AdapterError):
        session.apply("prepare-schema", (db.Statement("DROP DATABASE {}", ("protected",)),))
    assert tuple(connection.calls) == before


@pytest.mark.parametrize(
    "operation", ["migration-owner", "runtime-grants", "create-owner", "create-runtime", "create-database"]
)
def test_direct_target_connection_cannot_perform_other_stage_operations(prepared, monkeypatch, operation):
    planned, adapter, connection, _, _, _ = database_adapter(prepared, monkeypatch)
    session = adapter.open(planned, planned.target.database)
    session.begin()
    before = tuple(connection.calls)
    with pytest.raises(adapters.AdapterError):
        session.apply(operation, db.statements(planned, operation))
    assert tuple(connection.calls) == before


def test_migration_callback_requires_reviewed_plan_and_same_owned_transaction(prepared, monkeypatch):
    planned, adapter, _, _, _, _ = database_adapter(prepared, monkeypatch)
    initial = db.PreparationReceipt(
        "database",
        planned.target.fingerprint(),
        adapters.cluster_fingerprint("123456789"),
        (("owner", 201), ("runtime", 202), ("database", 101)),
    )
    selected = db.MigrationSelection(
        (), ("revision_1",), (("alembic/env.py", "a" * 64),), "reviewed-fresh-baseline", "f" * 64
    )
    migration_plan = db.plan_preparation(
        prepared.proposal,
        prepared.manifest,
        prepared.records,
        "migrate",
        confirm_database=planned.target.database,
        source_fingerprint="a" * 64,
        prior=initial,
        migration=selected,
    )
    session = adapter.open(migration_plan, migration_plan.target.database)
    session.begin()
    callback, verifier = Mock(), Mock(return_value=migration_plan.fingerprint)
    migrations = adapters.ReviewedMigrationAdapter(callback, verifier=verifier)
    migrations.apply(migration_plan, session)
    callback.assert_called_once_with(migration_plan, session)
    assert verifier.call_count == 2 and session.active
    callback.reset_mock()
    verifier.return_value = "0" * 64
    with pytest.raises(adapters.AdapterError):
        migrations.apply(migration_plan, session)
    callback.assert_not_called()

    verifier.return_value = migration_plan.fingerprint
    callback.side_effect = RuntimeError(PRIVATE)
    with pytest.raises(adapters.AdapterError) as error:
        migrations.apply(migration_plan, session)
    assert PRIVATE not in str(error.value)
    callback.side_effect = None
    verifier.side_effect = [migration_plan.fingerprint, "0" * 64]
    with pytest.raises(adapters.AdapterError) as error:
        migrations.apply(migration_plan, session)
    assert error.value.code == "DB_MIGRATION_REVIEW_REQUIRED"


def test_database_action_cannot_invoke_migration_callback(prepared, monkeypatch):
    # A database action must never enter the migration callback, even with a marker.
    planned, adapter, _, _, _, _ = database_adapter(prepared, monkeypatch)
    session = adapter.open(planned, planned.target.database)
    session.begin()
    callback = Mock(side_effect=RuntimeError(PRIVATE))
    migration = adapters.ReviewedMigrationAdapter(callback, verifier=Mock(return_value=planned.fingerprint))
    with pytest.raises(adapters.AdapterError) as error:
        migration.apply(planned, session)
    callback.assert_not_called()
    assert PRIVATE not in str(error.value)


def test_import_and_source_have_no_implicit_execution_or_legacy_bootstrap(monkeypatch):
    importlib.reload(adapters)
    tree = ast.parse(Path(adapters.__file__).read_text(encoding="utf-8"), feature_version=(3, 11))
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any(name and (name.startswith("app") or "bootstrap" in name) for name in imported)
    assert "doctor" not in Path(adapters.__file__).read_text(encoding="utf-8")


@pytest.mark.parametrize("identifier", [0, -1, True, "01", "0", "1;secret", 2**64, None])
def test_cluster_identity_strict_numeric(identifier):
    with pytest.raises(adapters.AdapterError):
        adapters.cluster_fingerprint(identifier)


@pytest.mark.parametrize("problem", [None, "fid", "hardlink", "redirect", "changed-after-read", "oversized"])
def test_opened_private_descriptor_identity_revalidated(prepared, monkeypatch, problem):
    item = prepared.records.secrets[0]
    value = SimpleNamespace(
        st_dev=1,
        st_ino=2,
        st_size=55,
        st_mtime_ns=4,
        st_ctime_ns=5,
        st_mode=stat.S_IFREG | 0o600,
        st_nlink=1,
        st_file_attributes=0,
    )
    if problem == "fid":
        value.st_ino += 1
    elif problem == "hardlink":
        value.st_nlink = 2
    elif problem == "redirect":
        value.st_file_attributes = 1024
    reads = []

    def fstat(fd):
        reads.append(fd)
        if problem == "changed-after-read" and len(reads) > 1:
            return SimpleNamespace(**(vars(value) | {"st_mtime_ns": 999}))
        return value

    stream = io.BytesIO(b"x" * 16385 if problem == "oversized" else PRIVATE.encode())
    stream.fileno = lambda: 123
    monkeypatch.setattr(os, "open", lambda *a, **k: 123)
    monkeypatch.setattr(os, "fdopen", lambda *a, **k: stream)
    monkeypatch.setattr(os, "fstat", fstat)
    monkeypatch.setattr(engine, "_file", lambda *a, **k: item.identity)
    if problem:
        with pytest.raises(adapters.AdapterError):
            adapters._read_private_bytes(item)
    else:
        assert adapters._read_private_bytes(item) == PRIVATE.encode() and len(reads) == 2
    assert stream.closed


def test_private_descriptor_closed_when_stream_construction_fails(prepared, monkeypatch):
    item = prepared.records.secrets[0]
    monkeypatch.setattr(engine, "_file", lambda *a, **k: item.identity)
    monkeypatch.setattr(os, "open", lambda *a, **k: 123)
    monkeypatch.setattr(os, "fdopen", Mock(side_effect=RuntimeError(PRIVATE)))
    close = Mock()
    monkeypatch.setattr(os, "close", close)
    with pytest.raises(adapters.AdapterError) as error:
        adapters._read_private_bytes(item)
    close.assert_called_once_with(123)
    assert PRIVATE not in str(error.value)


@pytest.mark.parametrize("oid", [None, True, 0, -1, 2**32, "201"])
def test_oid_observations_never_accept_unknown_or_coerced_identity(oid):
    with pytest.raises(adapters.AdapterError):
        adapters.PsycopgSession._oid([(oid,)])
