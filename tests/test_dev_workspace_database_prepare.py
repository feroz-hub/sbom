"""Pure planning and synthetic adapters; no app conftest, driver or resources."""

from __future__ import annotations

import builtins
import json
import os
import socket
import subprocess
import sys
import types
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev_instance_plan as instances
from scripts import dev_workspace_compose as compose
from scripts import dev_workspace_database_prepare as database
from scripts import dev_workspace_engine as engine
from scripts import dev_workspace_provider as provider

SECRET = "synthetic-bootstrap-private-value-never-disclose"
SOURCE = "a" * 64
CLUSTER = "c" * 64


class FakeProvider:
    def __init__(self):
        self.initialized, self.state, self.uid, self.gid, self.mode = False, "created", 1000, 1000, 0o700
        self.target_override, self.cluster, self.calls = None, CLUSTER, []
        self.helper_exit = 0

    def observe(self, plan):
        return database.ProviderState(
            self.target_override or plan.target.fingerprint(),
            "INITIALIZED" if self.initialized else "EMPTY",
            self.state,
            self.uid,
            self.gid,
            self.mode,
            self.cluster if self.initialized else None,
        )

    def create_helper(self, plan, command):
        self.calls.append(("create-helper", command))
        assert command[:2] == ("container", "create") and command[command.index("--network") + 1] == "none"
        assert (
            SECRET not in repr(command) and "--user" in command and command[command.index("--user") + 1] == "1000:1000"
        )
        return "9" * 64

    def run_helper(self, plan, helper_id, *, timeout):
        assert helper_id == "9" * 64 and timeout == 120
        self.calls.append(("run-helper", helper_id))
        if self.helper_exit == 0:
            self.initialized = True
        return self.helper_exit

    def start_server(self, plan, command, *, timeout):
        assert command == ("container", "start", plan.target.postgres_id) and timeout == 30
        self.calls.append(("start-server", command))
        self.state = "running"


class FakeAuthority:
    def __init__(self):
        self.source, self.denied_stage, self.calls = SOURCE, None, []

    def source_fingerprint(self, plan):
        return self.source

    def verify(self, plan, consent, stage, provider_state, database_state):
        self.calls.append(stage)
        return frozenset() if stage == self.denied_stage else database._CHECKS | database._ACTION_CHECKS[plan.action]


class FakeJournal:
    def __init__(self):
        self.claims, self.intents, self.receipts, self.outcomes = set(), [], [], []
        self.on_intent = None
        self.denied = False

    def claim(self, plan, consent):
        if self.denied or consent.operation_id in self.claims:
            return False
        self.claims.add(consent.operation_id)
        return True

    def intent(self, plan, stage):
        self.intents.append(stage)
        if self.on_intent:
            self.on_intent(stage)

    def receipt(self, plan, kind, object_id):
        self.receipts.append((kind, object_id))

    def outcome(self, plan, outcome):
        self.outcomes.append(outcome)


class FakeDatabase:
    def __init__(self):
        self.roles, self.exists, self.oid, self.owner = {}, False, None, None
        self.empty, self.public_create, self.safe, self.revisions = True, True, False, ()
        self.schema, self.sessions, self.events = None, [], []
        self.wrong_database, self.bad_cluster, self.fail_stage, self.fail_close, self.fail_rollback = (
            None,
            False,
            None,
            False,
            False,
        )

    def open(self, plan, name, *, readonly=False):
        result = FakeSession(self, plan, self.wrong_database or name, readonly)
        self.sessions.append(result)
        self.events.append(("open", name, readonly))
        return result


class FakeSession:
    def __init__(self, store, plan, name, readonly):
        self.store, self.plan, self.name, self.readonly = store, plan, name, readonly
        self.active, self.closed, self.snapshot = False, False, None
        self.effective = plan.target.bootstrap_role

    def inspect(self):
        return database.DatabaseState(
            "0" * 64 if self.store.bad_cluster else CLUSTER,
            self.name,
            self.plan.target.bootstrap_role,
            "f" * 64,
            True,
            tuple(self.store.roles.values()),
            self.store.exists,
            self.store.oid,
            self.store.owner,
            self.store.empty,
            self.store.public_create,
            self.store.safe,
            self.store.revisions,
            self.effective,
            self.readonly,
            self.store.schema,
        )

    def begin(self):
        assert not self.readonly and not self.active
        self.snapshot = (
            dict(self.store.roles),
            self.store.empty,
            self.store.public_create,
            self.store.safe,
            self.store.revisions,
            self.store.schema,
        )
        self.active = True
        self.store.events.append(("begin", self.name))

    def apply(self, operation, sql):
        assert not self.readonly and all(type(value) is database.Statement for value in sql)
        assert SECRET not in repr(sql) and not any("PASSWORD" in value.template for value in sql)
        self.store.events.append((operation, self.name))
        if self.store.fail_stage == operation:
            raise RuntimeError(SECRET)
        target = self.plan.target
        if operation in {"create-owner", "create-runtime"}:
            assert self.active
            name, oid = (target.owner_role, 11) if operation == "create-owner" else (target.runtime_role, 12)
            assert name not in self.store.roles
            self.store.roles[name] = database.RoleState(name, oid, False)
            return oid
        if operation == "create-database":
            assert not self.active and self.name == "postgres" and not self.store.exists
            self.store.exists, self.store.oid, self.store.owner = True, 13, target.owner_role
            return 13
        if operation == "prepare-schema":
            assert self.active and self.name == target.database
            self.store.public_create, self.store.safe = False, True
        elif operation == "runtime-login":
            self.store.roles[target.runtime_role] = replace(self.store.roles[target.runtime_role], login=True)
        elif operation == "migration-owner":
            self.effective = target.owner_role
        elif operation == "runtime-grants":
            self.store.safe = True
        return None

    def install_runtime_credential(self, role, reference):
        assert (
            self.active and role == self.plan.target.runtime_role and reference.endswith("-postgres-runtime-password")
        )
        self.store.events.append(("credential-reference", reference))

    def commit(self):
        assert self.active and not self.readonly
        self.store.events.append(("commit", self.name))
        if self.store.fail_stage == "commit":
            raise RuntimeError(SECRET)
        self.active = False
        self.effective = self.plan.target.bootstrap_role

    def rollback(self):
        self.store.events.append(("rollback", self.name))
        if self.store.fail_rollback:
            raise RuntimeError(SECRET)
        if self.active:
            (
                roles,
                self.store.empty,
                self.store.public_create,
                self.store.safe,
                self.store.revisions,
                self.store.schema,
            ) = self.snapshot
            self.store.roles = roles
        self.active = False

    def close(self):
        self.store.events.append(("close", self.name, self.readonly))
        if self.store.fail_close:
            raise RuntimeError(SECRET)
        self.closed = True


class FakeMigrations:
    def __init__(self, store):
        self.store, self.calls = store, []

    def apply(self, plan, session):
        assert session.active and session.effective == plan.target.owner_role
        self.calls.append(plan.migration)
        self.store.empty, self.store.revisions, self.store.schema = (
            False,
            plan.migration.heads,
            plan.migration.schema_fingerprint,
        )


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
        {name: "approved/" + name + "@sha256:" + str(index + 1) * 64 for index, name in enumerate(names)},
        {name: "1000:1000" for name in names},
    )
    proposal = provider.plan_provider(descriptor, policy)
    references, files = [], []
    for reference in (item for values in compose.secret_layout(proposal).values() for item in values.values()):
        path = Path("C:/synthetic-private" if os.name == "nt" else "/synthetic-private") / reference
        references.append(compose.SecretFile(reference, str(path), sys.platform))
        files.append(engine.SecretFile(reference, path, (1, 1, 1, 1, 1)))
    contract_policy = compose.ComposePolicy(
        policy.policy_id,
        "f" * 64,
        sys.platform,
        {name: "linux/amd64" for name in names},
        dict(compose._PROFILES),
        {name: compose.ResourceLimits("1.5", 128 * 1048576, 192, 1048576, 1048576) for name in names},
        {name: compose.DataOwnership(1000, 1000, 0o700) for name in ("postgres", "redis")},
        {name: "preowned-empty-volume" for name in ("postgres", "redis")},
        compose.HealthPolicy(3, 2, 5, 0, 10),
        tuple(references),
    )
    review = compose.ComposeContractReview(
        "d" * 64,
        proposal.fingerprint,
        compose.policy_fingerprint(contract_policy),
        contract_policy.private_binding(),
        {name: "VERIFIED" for name in compose._CHECKS},
    )
    contract = compose.plan_compose(proposal, contract_policy, review=review)
    records = engine.ResourceRecords(
        policy.engine_identity,
        proposal.fingerprint,
        tuple(
            engine.ContainerRecord(name, str(index + 1) * 64, "2026-10-31T00:00:00Z")
            for index, name in enumerate(names)
        ),
        "4" * 64,
        ((proposal.volumes[0], "5" * 64, "a" * 64), (proposal.volumes[1], "6" * 64, "b" * 64)),
        tuple(files),
    )
    state = FakeDatabase()
    return SimpleNamespace(
        provider=FakeProvider(),
        authority=FakeAuthority(),
        journal=FakeJournal(),
        database=state,
        migrations=FakeMigrations(state),
        proposal=proposal,
        compose=contract,
        records=records,
    )


def plan(fixture, action="initdb", *, prior=None, migration=None, confirmation=None):
    return database.plan_preparation(
        fixture.proposal,
        fixture.compose,
        fixture.records,
        action,
        confirm_database=confirmation or fixture.proposal.descriptor.resources["database"],
        source_fingerprint=SOURCE,
        prior=prior,
        migration=migration,
    )


def consent(planned):
    return database.Consent(planned.action, str(uuid.uuid4()), planned.fingerprint, planned.target.database)


def executor(fixture):
    return database.PreparationExecutor(
        provider_adapter=fixture.provider,
        authority=fixture.authority,
        journal=fixture.journal,
        database_adapter=fixture.database,
        migration_adapter=fixture.migrations,
    )


def initialized(fixture):
    planned = plan(fixture)
    outcome = executor(fixture).execute(planned, consent(planned))
    assert outcome.code == "DB_PREPARATION_COMPLETED"
    return outcome.receipt


def configured(fixture):
    planned = plan(fixture, "database", prior=initialized(fixture))
    outcome = executor(fixture).execute(planned, consent(planned))
    assert outcome.code == "DB_PREPARATION_COMPLETED"
    return outcome.receipt


def test_initdb_is_explicit_nonroot_exact_volume_and_does_not_start_server_or_migrate(prepared):
    planned = plan(prepared)
    outcome = executor(prepared).execute(planned, consent(planned))
    assert outcome.code == "DB_PREPARATION_COMPLETED" and outcome.helper_id == "9" * 64
    assert outcome.receipt.action == "initdb" and outcome.receipt.cluster_id == CLUSTER
    assert [kind for kind, _ in prepared.provider.calls] == ["create-helper", "run-helper"]
    command = prepared.provider.calls[0][1]
    assert "--entrypoint" in command and "initdb" in command and "--pwfile=/run/secrets/bootstrap-password" in command
    assert any("source=" + planned.target.volume_id in item for item in command)
    assert not prepared.database.sessions and not prepared.migrations.calls
    assert outcome.to_dict()["application_ready"] is False and SECRET not in repr(outcome)


def test_database_action_separates_bootstrap_owner_runtime_credentials_and_independent_reader(prepared):
    receipt = configured(prepared)
    assert receipt.action == "database" and dict(receipt.object_oids) == {"owner": 11, "runtime": 12, "database": 13}
    assert not prepared.database.roles[prepared.proposal.database_runtime_role].inherit
    assert prepared.database.roles[prepared.proposal.database_runtime_role].login is True
    assert not prepared.database.roles[next(name for name in prepared.database.roles if name.endswith("_owner"))].login
    assert [session.readonly for session in prepared.database.sessions] == [False, False, True]
    assert all(session.closed for session in prepared.database.sessions)
    assert not prepared.migrations.calls and prepared.provider.calls[-1][0] == "start-server"
    assert prepared.database.events.index(
        ("close", receipt_database(prepared), False)
    ) < prepared.database.events.index(("open", receipt_database(prepared), True))


def receipt_database(fixture):
    return fixture.proposal.descriptor.resources["database"]


def test_migrations_require_separate_hashed_review_and_reapply_safe_runtime_grants(prepared):
    prior = configured(prepared)
    selected = database.MigrationSelection(
        (),
        ("103_tenant_admin_governance",),
        (("alembic/env.py", "a" * 64), ("scripts/schema/postgresql_047_baseline.sql", "b" * 64)),
        "reviewed-fresh-baseline",
        "d" * 64,
    )
    planned = plan(prepared, "migrate", prior=prior, migration=selected)
    outcome = executor(prepared).execute(planned, consent(planned))
    assert outcome.code == "DB_PREPARATION_COMPLETED" and outcome.receipt.revisions == selected.heads
    assert prepared.migrations.calls == [selected] and prepared.database.safe
    assert prepared.database.sessions[-1].readonly and prepared.database.sessions[-1].closed


@pytest.mark.parametrize("wrong", ["postgres", "sbom_analyser_dev", SECRET])
def test_wrong_database_confirmation_fails_before_any_adapter_or_driver(prepared, wrong):
    with pytest.raises(database.PreparationError) as caught:
        plan(prepared, confirmation=wrong)
    assert (
        caught.value.code == "DB_EXACT_CONFIRMATION_REQUIRED"
        and not prepared.provider.calls
        and not prepared.database.sessions
    )
    assert SECRET not in repr(caught.value)


@pytest.mark.parametrize("wrong", ["owner", "root", "volume", "cluster", "running", "populated"])
def test_initdb_refuses_unknown_nonroot_or_nonempty_target_without_mutating(prepared, wrong):
    planned = plan(prepared)
    if wrong == "owner":
        prepared.provider.uid = 1001
    elif wrong == "root":
        prepared.provider.uid = 0
    elif wrong == "volume":
        prepared.provider.target_override = "0" * 64
    elif wrong == "cluster":
        prepared.provider.initialized = True
    elif wrong == "running":
        prepared.provider.state = "running"
    else:
        prepared.provider.mode = 0o755
    outcome = executor(prepared).execute(planned, consent(planned))
    assert outcome.code in {"DB_PROVIDER_DRIFT", "DB_VOLUME_NOT_FRESH"} and not prepared.provider.calls
    assert not prepared.journal.outcomes and not prepared.database.sessions


def test_replayed_or_foreign_pending_journal_is_never_overwritten(prepared):
    prepared.journal.denied = True
    planned = plan(prepared)
    outcome = executor(prepared).execute(planned, consent(planned))
    assert outcome.code == "DB_REPLAY_OR_PENDING_ATTEMPT" and not prepared.provider.calls
    assert not prepared.journal.outcomes and not prepared.journal.intents


@pytest.mark.parametrize("stage", ["create-initdb-helper", "run-initdb-helper"])
def test_policy_or_source_drift_between_claim_and_helper_mutation_fails_closed(prepared, stage):
    planned = plan(prepared)
    prepared.authority.denied_stage = stage
    outcome = executor(prepared).execute(planned, consent(planned))
    assert outcome.code in {"DB_POLICY_REQUIRED", "DB_PREPARATION_UNCONFIRMED"}
    assert not any(name == "run-helper" for name, _ in prepared.provider.calls)
    assert outcome.helper_id == ("9" * 64 if stage == "run-initdb-helper" else None)


def test_source_drift_after_journal_intent_is_checked_before_mutation(prepared):
    planned = plan(prepared)
    prepared.journal.on_intent = lambda stage: setattr(prepared.authority, "source", "b" * 64)
    outcome = executor(prepared).execute(planned, consent(planned))
    assert outcome.code == "DB_SOURCE_CHANGED" and not prepared.provider.calls


def test_cancelled_helper_retains_its_exact_receipt_and_never_claims_verified_cleanup(prepared):
    planned = plan(prepared)
    prepared.provider.run_helper = Mock(side_effect=KeyboardInterrupt())
    outcome = executor(prepared).execute(planned, consent(planned))
    assert outcome.code == "DB_PREPARATION_UNCONFIRMED" and outcome.helper_id == "9" * 64
    assert outcome.cleanup_verified is False and outcome.receipt is None
    assert prepared.journal.receipts == [("initdb-helper", "9" * 64)]
    assert len(prepared.provider.calls) == 1 and prepared.provider.calls[0][0] == "create-helper"


class ReportedHelperError(database.PreparationError):
    def __init__(self, helper_id):
        super().__init__("DB_HELPER_UNCONFIRMED")
        self.helper_id = helper_id


def test_helper_creation_receipt_failure_preserves_known_id_without_false_completion(prepared):
    planned = plan(prepared)
    prepared.provider.create_helper = Mock(side_effect=ReportedHelperError("8" * 64))
    prepared.provider.unconfirmed_helper_ids = {"8" * 64}
    result = executor(prepared).execute(planned, consent(planned))
    assert result.code == "DB_PREPARATION_UNCONFIRMED" and result.helper_id == "8" * 64
    assert result.unconfirmed_helper_ids == ("8" * 64,) and result.cleanup_verified is False
    assert not result.completed and result.receipt is None
    assert prepared.journal.outcomes == [result] and prepared.journal.claims
    assert not prepared.journal.receipts


def test_observer_failure_before_claim_reports_owned_helper_without_outer_journal_events(prepared):
    planned = plan(prepared)
    prepared.provider.observe = Mock(side_effect=ReportedHelperError("8" * 64))
    prepared.provider.unconfirmed_helper_ids = {"8" * 64}
    prepared.journal.claim = Mock(wraps=prepared.journal.claim)
    result = executor(prepared).execute(planned, consent(planned))
    assert result.helper_id == "8" * 64 and result.unconfirmed_helper_ids == ("8" * 64,)
    assert result.cleanup_verified is False and result.code == "DB_PREPARATION_UNCONFIRMED"
    assert not result.completed and result.receipt is None and not prepared.provider.calls
    prepared.journal.claim.assert_not_called()
    assert not prepared.journal.intents and not prepared.journal.receipts and not prepared.journal.outcomes


def test_multiple_reported_helpers_are_deduplicated_sorted_and_private_metadata_is_omitted(prepared):
    planned = plan(prepared)
    prepared.provider.observe = Mock(side_effect=ReportedHelperError(SECRET))
    prepared.provider.unconfirmed_helper_ids = ("8" * 64, SECRET, "7" * 64, "8" * 64, None, True)
    result = executor(prepared).execute(planned, consent(planned))
    assert result.helper_id is None and result.unconfirmed_helper_ids == ("7" * 64, "8" * 64)
    assert result.cleanup_verified is False and result.receipt is None
    public = json.dumps(result.to_dict()) + repr(result)
    assert SECRET not in public and "None" not in json.dumps(result.to_dict()["unconfirmed_helper_ids"])
    assert not prepared.provider.calls and not prepared.journal.outcomes


@pytest.mark.parametrize("metadata", [SECRET, {SECRET: "8" * 64}, iter(("8" * 64,)), None])
def test_invalid_helper_collection_never_becomes_a_public_identifier_or_success(prepared, metadata):
    planned = plan(prepared)
    prepared.provider.observe = Mock(side_effect=ReportedHelperError(None))
    prepared.provider.unconfirmed_helper_ids = metadata
    result = executor(prepared).execute(planned, consent(planned))
    assert result.unconfirmed_helper_ids == () and result.helper_id is None and not result.cleanup_verified
    assert result.receipt is None and result.code == "DB_PREPARATION_UNCONFIRMED"
    assert SECRET not in repr(result) + json.dumps(result.to_dict())
    assert not prepared.journal.outcomes


def test_only_preparation_adapter_exceptions_supply_helper_identity(prepared):
    planned = plan(prepared)
    error = RuntimeError(SECRET)
    error.helper_id = "8" * 64
    prepared.provider.observe = Mock(side_effect=error)
    result = executor(prepared).execute(planned, consent(planned))
    assert result.helper_id is None and result.unconfirmed_helper_ids == ()
    assert SECRET not in repr(result) + json.dumps(result.to_dict())


def test_unknown_helper_status_blocks_completion_even_when_requested_initdb_returns_zero(prepared):
    planned = plan(prepared)
    prepared.provider.unconfirmed_helper_ids = {"8" * 64}
    result = executor(prepared).execute(planned, consent(planned))
    assert result.code == "DB_PREPARATION_UNCONFIRMED" and result.receipt is None
    assert not result.cleanup_verified and result.helper_id == "9" * 64
    assert result.unconfirmed_helper_ids == ("8" * 64,)
    assert prepared.journal.outcomes == [result]


def test_invalid_direct_helper_return_is_redacted_and_preserves_uncertainty(prepared):
    planned = plan(prepared)
    prepared.provider.create_helper = Mock(return_value=SECRET)
    result = executor(prepared).execute(planned, consent(planned))
    assert result.helper_id is None and result.unconfirmed_helper_ids == () and not result.cleanup_verified
    assert result.code == "DB_PREPARATION_UNCONFIRMED" and result.receipt is None
    assert SECRET not in repr(result) + json.dumps(result.to_dict())


def test_repeated_cancellation_in_helper_metadata_retains_cleanup_uncertainty(prepared):
    class InterruptedMetadata(database.PreparationError):
        @property
        def helper_id(self):
            raise KeyboardInterrupt

    planned = plan(prepared)
    prepared.provider.observe = Mock(side_effect=InterruptedMetadata("DB_HELPER_UNCONFIRMED"))
    result = executor(prepared).execute(planned, consent(planned))
    assert not result.cleanup_verified and result.unconfirmed_helper_ids == ()
    assert result.code == "DB_PREPARATION_UNCONFIRMED" and not prepared.journal.outcomes


@pytest.mark.parametrize("ids", [["8" * 64], (SECRET,), ("8" * 64, "8" * 64), (False,)])
def test_public_outcome_requires_strict_validated_helper_tuple(ids):
    with pytest.raises(database.PreparationError) as error:
        database.PreparationOutcome("DB_PREPARATION_UNCONFIRMED", cleanup_verified=False, unconfirmed_helper_ids=ids)
    assert SECRET not in str(error.value)


def test_public_outcome_never_claims_completion_or_cleanup_for_unconfirmed_helpers():
    for code, cleanup in (("DB_PREPARATION_COMPLETED", False), ("DB_PREPARATION_UNCONFIRMED", True)):
        with pytest.raises(database.PreparationError):
            database.PreparationOutcome(code, cleanup_verified=cleanup, unconfirmed_helper_ids=("8" * 64,))


@pytest.mark.parametrize("conflict", ["database", "role", "superuser", "membership", "wrong-session", "wrong-cluster"])
def test_database_preparation_refuses_existing_privilege_target_or_session_conflicts(prepared, conflict):
    prior = initialized(prepared)
    planned = plan(prepared, "database", prior=prior)
    if conflict == "database":
        prepared.database.exists = True
    elif conflict in {"role", "superuser", "membership"}:
        prepared.database.roles[planned.target.runtime_role] = database.RoleState(
            planned.target.runtime_role,
            99,
            True,
            superuser=conflict == "superuser",
            memberships=(123,) if conflict == "membership" else (),
        )
    elif conflict == "wrong-session":
        prepared.database.wrong_database = planned.target.database
    else:
        prepared.database.bad_cluster = True
    outcome = executor(prepared).execute(planned, consent(planned))
    assert outcome.code == "DB_PREPARATION_UNCONFIRMED"  # Explicit server-start may already be acknowledged.
    assert not any(event[0] == "create-owner" for event in prepared.database.events)
    assert all(session.closed for session in prepared.database.sessions)


@pytest.mark.parametrize("failure", ["create-runtime", "create-database", "prepare-schema", "commit"])
def test_partial_database_failures_roll_back_owned_transactions_and_preserve_receipts(prepared, failure):
    planned = plan(prepared, "database", prior=initialized(prepared))
    prepared.database.fail_stage = failure
    result = executor(prepared).execute(planned, consent(planned))
    assert result.code == "DB_PREPARATION_UNCONFIRMED" and result.postgres_id == planned.target.postgres_id
    assert all(session.closed for session in prepared.database.sessions)
    assert any(event[0] == "rollback" for event in prepared.database.events)
    assert SECRET not in repr(result) + json.dumps(result.to_dict())


@pytest.mark.parametrize("failure", ["close", "rollback"])
def test_privileged_session_cleanup_uncertainty_cannot_report_success(prepared, failure):
    planned = plan(prepared, "database", prior=initialized(prepared))
    if failure == "close":
        prepared.database.fail_close = True
    else:
        prepared.database.fail_stage, prepared.database.fail_rollback = "prepare-schema", True
    result = executor(prepared).execute(planned, consent(planned))
    assert result.code == "DB_PREPARATION_UNCONFIRMED" and result.cleanup_verified is False
    assert result.receipt is None and SECRET not in repr(result)


@pytest.mark.parametrize("drift", ["role-oid", "database-oid", "schema-acl", "policy"])
def test_state_and_policy_are_revalidated_at_the_actual_commit_boundary(prepared, drift):
    planned = plan(prepared, "database", prior=initialized(prepared))

    def change(stage):
        if drift == "role-oid" and stage == "commit-roles":
            prepared.database.roles[planned.target.runtime_role] = replace(
                prepared.database.roles[planned.target.runtime_role], oid=999
            )
        elif drift == "database-oid" and stage == "commit-schema":
            prepared.database.oid = 999
        elif drift == "schema-acl" and stage == "commit-schema":
            prepared.database.public_create = True

    prepared.journal.on_intent = change
    if drift == "policy":
        prepared.authority.denied_stage = "commit-schema"
    result = executor(prepared).execute(planned, consent(planned))
    assert result.code == "DB_PREPARATION_UNCONFIRMED" and result.receipt is None
    commits = [event for event in prepared.database.events if event[0] == "commit"]
    assert len(commits) == (0 if drift == "role-oid" else 1)
    assert all(session.closed for session in prepared.database.sessions)


@pytest.mark.parametrize("bad_reader", ["writer-reuse", "not-readonly"])
def test_durable_readback_requires_a_new_readonly_connection(prepared, bad_reader):
    planned = plan(prepared, "database", prior=initialized(prepared))
    original = prepared.database.open

    def open_session(current, name, *, readonly=False):
        if readonly and bad_reader == "writer-reuse":
            return prepared.database.sessions[-1]
        return original(current, name, readonly=False if bad_reader == "not-readonly" else readonly)

    prepared.database.open = open_session
    result = executor(prepared).execute(planned, consent(planned))
    assert result.code == "DB_PREPARATION_UNCONFIRMED" and result.receipt is None


def test_migration_source_drift_before_commit_rolls_back_schema_and_preserves_prior_receipt(prepared):
    prior = configured(prepared)
    selected = database.MigrationSelection(
        (), ("103_tenant_admin_governance",), (("alembic/env.py", "a" * 64),), "reviewed-fresh-baseline", "d" * 64
    )
    planned = plan(prepared, "migrate", prior=prior, migration=selected)
    prepared.journal.on_intent = lambda stage: (
        setattr(prepared.authority, "source", "b" * 64) if stage == "commit-migration" else None
    )
    result = executor(prepared).execute(planned, consent(planned))
    assert result.code == "DB_PREPARATION_UNCONFIRMED" and prepared.database.revisions == ()
    assert result.receipt is None and prior.action == "database"
    assert all(session.closed for session in prepared.database.sessions)


def test_cluster_receipts_cannot_be_reused_for_another_target(prepared):
    prior = initialized(prepared)
    with pytest.raises(database.PreparationError, match="^DB_CLUSTER_RECEIPT_REQUIRED$"):
        plan(prepared, "database", prior=replace(prior, target_fingerprint="0" * 64))
    assert not prepared.database.sessions


def test_sql_identifiers_are_driver_composed_and_never_password_or_role_interpolated(prepared):
    planned = plan(prepared)
    driver = SimpleNamespace(
        SQL=Mock(side_effect=lambda template: SimpleNamespace(format=lambda *identifiers: (template, identifiers))),
        Identifier=Mock(side_effect=lambda value: ("Identifier", value)),
    )
    result = database.statements(planned, "create-runtime")[0].compose(driver)
    assert planned.target.runtime_role not in result[0] and result[1] == (("Identifier", planned.target.runtime_role),)
    assert "NOINHERIT" in result[0] and "NOBYPASSRLS" in result[0] and "PASSWORD" not in result[0]


def test_public_outcome_and_options_reject_private_or_mutable_claims():
    for constructor in (
        lambda: database.PreparationOutcome(SECRET),
        lambda: database.PreparationOutcome("DB_PREPARATION_COMPLETED", [SECRET]),
        lambda: database.Consent("database", SECRET, SOURCE, "postgres"),
    ):
        with pytest.raises(database.PreparationError) as caught:
            constructor()
        assert SECRET not in repr(caught.value)


def test_fresh_module_and_planning_are_side_effect_free_with_external_tripwires(prepared, monkeypatch):
    source = Path(database.__file__).read_text(encoding="utf-8")
    fixture = types.ModuleType("sbo101_database_preparation_fixture")
    fixture.__package__ = "scripts"
    monkeypatch.setitem(sys.modules, fixture.__name__, fixture)
    forbidden = Mock(side_effect=AssertionError("Pure preparation planning attempted external access"))
    original_import = builtins.__import__

    def guarded_import(name, *arguments, **keywords):
        assert name.split(".", 1)[0] not in {"app", "psycopg", "sqlalchemy", "alembic", "dotenv"}
        return original_import(name, *arguments, **keywords)

    with monkeypatch.context() as guarded:
        guarded.setattr(builtins, "open", forbidden)
        guarded.setattr(os, "open", forbidden)
        guarded.setattr(os, "mkdir", forbidden)
        for name in ("read_text", "read_bytes", "write_text", "write_bytes", "mkdir", "stat", "home"):
            guarded.setattr(Path, name, forbidden)
        guarded.setattr(subprocess, "Popen", forbidden)
        guarded.setattr(subprocess, "run", forbidden)
        guarded.setattr(socket, "socket", forbidden)
        guarded.setattr(socket, "create_connection", forbidden)
        guarded.setattr(builtins, "__import__", guarded_import)
        exec(compile(source, "<pure-preparation-fixture>", "exec"), fixture.__dict__)
        proposed = fixture.plan_preparation(
            prepared.proposal,
            prepared.compose,
            prepared.records,
            "initdb",
            confirm_database=receipt_database(prepared),
            source_fingerprint=SOURCE,
        )
        assert proposed.to_dict()["live_authorized"] is False
    forbidden.assert_not_called()
