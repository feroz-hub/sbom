"""Fresh synthetic private files; no provider/DB/process operations or recovery."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest
from scripts import dev_instance_storage as storage
from scripts import dev_private
from scripts import dev_workspace_database_prepare as database
from scripts import dev_workspace_engine as engine
from scripts import dev_workspace_operation_journal as journals

from tests.test_dev_workspace_database_prepare import consent, executor, plan
from tests.test_dev_workspace_database_prepare import prepared as prepared
from tests.test_dev_workspace_engine import Authority as EngineAuthority
from tests.test_dev_workspace_engine import prepared as _engine_prepared
from tests.test_dev_workspace_engine import request as engine_action

SECRET = "synthetic-private-data-must-never-appear-in-journal"
OPERATION = "ccbe8f60-6957-4bc8-99d2-ceb56fa67223"


@pytest.fixture
def private_home(tmp_path, prepared):
    home = tmp_path.resolve() / "private-home"
    if os.name == "nt":
        storage._windows_create(home)
    else:
        home.mkdir(mode=0o700)
    root = home / ".sbom-dev" / "instances" / prepared.proposal.descriptor.instance_id / "operations"
    storage.initialize_private_directory(root, anchor=home)
    return home


def journal(home, prepared):
    return journals.OperationJournal(home=home, instance_id=prepared.proposal.descriptor.instance_id)


def approval(request, supplied=None):
    binding = journals._binding(request, supplied)
    return journals.ReservationConsent(
        binding["instance_id"], binding["operation_id"], binding["category"], binding["request_binding"]
    )


def engine_request(prepared):
    capability = engine.EngineCapability(
        "AVAILABLE",
        "ENGINE_CAPABILITY_OBSERVED",
        Path("C:/synthetic/docker.exe" if os.name == "nt" else "/synthetic/docker"),
        Path("C:/synthetic/config" if os.name == "nt" else "/synthetic/config"),
        "npipe:////./pipe/docker_engine" if os.name == "nt" else "unix:///synthetic/docker.sock",
        (1, 1, 1, 1, 1, "a" * 64),
        (1, 1),
        prepared.proposal.policy.engine_identity,
        "linux/amd64",
        "29.0.0",
    )
    selected = engine.ActionConsent(
        "create",
        OPERATION,
        prepared.proposal.fingerprint,
        capability.engine_identity,
        prepared.proposal.policy.policy_id,
        engine.action_targets(prepared.proposal, prepared.compose, secrets=prepared.records.secrets),
    )
    proofs = tuple((name, (1, 1, 1, 1, 1, "a" * 64)) for name in engine._CONTROLLER_NAMES)
    return engine.EngineActionPlan(
        prepared.proposal,
        capability,
        selected,
        prepared.compose,
        secrets=prepared.records.secrets,
        controller_proofs=proofs,
        fingerprint="b" * 64,
    )


def engine_complete(book, request, prepared):
    prefix = "sbom-dev-" + request.provider.descriptor.instance_id.replace("-", "")
    book.verify_reservation(request)
    book.record_intent(request)
    book.verify_reservation(request)
    book.record_receipt(request, "network", prefix + "-network", prepared.records.network_id)
    for index, name in enumerate(("postgres", "redis", "mailpit")):
        book.verify_reservation(request)
        book.record_intent(request)
        book.record_receipt(request, "container", prefix + "-" + name, str(index + 1) * 64)
    for logical, actual, _ in prepared.records.volume_births:
        book.record_receipt(request, "volume", logical, actual)
    result = engine.EngineOutcome(
        "ENGINE_ACTION_COMPLETED",
        ("1" * 64, "2" * 64, "3" * 64),
        prepared.records,
        created_network_id=prepared.records.network_id,
    )
    book.record_outcome(request, result)


def test_readonly_missing_storage_does_not_create_root_or_lock(tmp_path, prepared, monkeypatch):
    book = journal(tmp_path.resolve(), prepared)
    forbidden = Mock(side_effect=AssertionError("Read summary attempted a write"))
    monkeypatch.setattr(dev_private, "create_private_file", forbidden)
    monkeypatch.setattr(os, "mkdir", forbidden)
    report = book.read_summary()
    assert report.status == "SKIPPED" and report.code == "JOURNAL_STORAGE_MISSING"
    assert not book.root.exists()
    forbidden.assert_not_called()


def test_storage_requires_exact_category_binding_before_creating_any_file(private_home, prepared):
    book, request = journal(private_home, prepared), engine_request(prepared)
    before = tuple(book.root.iterdir())
    wrong = journals.ReservationConsent(book.instance_id, OPERATION, "migrations", request.fingerprint)
    with pytest.raises(journals.JournalError, match="^JOURNAL_STORAGE_APPROVAL_REQUIRED$"):
        book.reserve(request, wrong)
    assert tuple(book.root.iterdir()) == before


def test_engine_sequence_has_private_native_records_and_no_public_private_hashes(private_home, prepared):
    book, request = journal(private_home, prepared), engine_request(prepared)
    assert book.reserve(request, approval(request)) is True
    engine_complete(book, request, prepared)
    summary = book.read_summary()
    assert summary.status == "OBSERVED" and summary.operations[0].state == "COMPLETED"
    assert summary.operations[0].stages == journals._STAGES["create"]
    assert len(summary.operations[0].receipts) == 6
    public = json.dumps(summary.to_dict())
    assert (
        request.fingerprint not in public
        and "claim_tag" not in public
        and "request_binding" not in public
        and str(private_home) not in public
    )
    assert summary.to_dict()["live_authorized"] is summary.to_dict()["runtime_verified"] is False
    for path in book.root.iterdir():
        journals.dev_instance_registry._private(path)  # Actual current-user/private ACL verification on Windows.
        assert SECRET.encode() not in path.read_bytes()


def test_real_engine_executor_protocol_uses_concrete_journal_with_only_fake_provider(private_home, prepared, tmp_path):
    candidate = _engine_prepared.__wrapped__(tmp_path)
    candidate.fake.configure(candidate.plan, candidate.compose, candidate.files, existing=False)
    request = engine_action(candidate, "create")
    book = journal(private_home, prepared)
    assert book.reserve(request, approval(request))
    outcome = engine.DockerEngineClient(
        candidate.capability, authority=EngineAuthority(), runner=candidate.fake
    ).execute(request, creation_journal=book)
    assert outcome.code == "ENGINE_ACTION_COMPLETED"
    assert book.read_summary().operations[0].state == "COMPLETED"


def test_concrete_database_journal_supports_exact_preparation_protocol_and_next_phase(private_home, prepared):
    prior = None
    for action in ("initdb", "database", "migrate"):
        selected = (
            database.MigrationSelection(
                (),
                ("103_tenant_admin_governance",),
                (("alembic/env.py", "a" * 64),),
                "reviewed-fresh-baseline",
                "d" * 64,
            )
            if action == "migrate"
            else None
        )
        planned = plan(prepared, action, prior=prior, migration=selected)
        chosen = consent(planned)
        book = journal(private_home, prepared).arm(approval(planned, chosen))
        prepared.journal = book
        result = executor(prepared).execute(planned, chosen)
        assert result.code == "DB_PREPARATION_COMPLETED"
        prior = result.receipt
    view = book.read_summary()
    assert view.status == "OBSERVED" and len(view.operations) == 3
    assert all(item.state == "COMPLETED" for item in view.operations)
    assert not any("credential" in item[1] for row in view.operations for item in row.receipts)


def test_new_object_cannot_adopt_existing_claim_even_with_identical_caller_data(private_home, prepared):
    request = engine_request(prepared)
    original = journal(private_home, prepared)
    assert original.reserve(request, approval(request))
    other = journal(private_home, prepared)
    before = tuple(original.root.iterdir())
    assert other.reserve(request, approval(request)) is False
    with pytest.raises(journals.JournalError):
        other.record_intent(request)
    assert tuple(original.root.iterdir()) == before


def test_denied_database_claim_never_overwrites_prior_pending_outcome(private_home, prepared):
    planned = plan(prepared)
    chosen = consent(planned)
    first = journal(private_home, prepared).arm(approval(planned, chosen))
    assert first.claim(planned, chosen)
    second = journal(private_home, prepared).arm(approval(planned, chosen))
    before = tuple(first.root.iterdir())
    prepared.journal = second
    result = executor(prepared).execute(planned, chosen)
    assert result.code == "DB_REPLAY_OR_PENDING_ATTEMPT" and tuple(first.root.iterdir()) == before
    assert first.read_summary().operations[0].state == "PENDING"


def test_unconfirmed_helper_identity_survives_new_readonly_journal_object(private_home, prepared):
    planned = plan(prepared)
    chosen = consent(planned)
    book = journal(private_home, prepared).arm(approval(planned, chosen))
    assert book.claim(planned, chosen)
    result = database.PreparationOutcome(
        "DB_HELPER_UNCONFIRMED", cleanup_verified=False, unconfirmed_helper_ids=("a" * 64, "b" * 64)
    )
    book.outcome(planned, result)
    public = journal(private_home, prepared).read_summary().to_dict()
    view = public["operations"][0]
    assert view["state"] == "UNCONFIRMED" and view["cleanup_verified"] is False
    assert view["unconfirmed_helper_ids"] == ["a" * 64, "b" * 64]
    assert view["resource_ownership_verified"] is False
    assert SECRET not in json.dumps(public) and str(private_home) not in json.dumps(public)


def test_preclaim_failure_cannot_create_or_adopt_a_journal_outcome(private_home, prepared):
    planned = plan(prepared)
    book = journal(private_home, prepared)
    before = tuple(book.root.iterdir())
    result = database.PreparationOutcome(
        "DB_HELPER_UNCONFIRMED", cleanup_verified=False, unconfirmed_helper_ids=("a" * 64,)
    )
    with pytest.raises(journals.JournalError):
        book.outcome(planned, result)
    assert tuple(book.root.iterdir()) == before
    assert result.to_dict()["unconfirmed_helper_ids"] == ["a" * 64]


@pytest.mark.parametrize("fault", ["partial-stage", "raced-destination", "after-rename"])
def test_interrupted_publication_preserves_unknown_and_staging_for_readonly_recovery(
    private_home, prepared, monkeypatch, fault
):
    book, request = journal(private_home, prepared), engine_request(prepared)
    assert book.reserve(request, approval(request))
    original_move, original_create = journals._move_private, dev_private.create_private_file
    if fault == "partial-stage":

        def create(path, payload):
            original_create(path, b"partial synthetic write")
            raise OSError(SECRET)

        monkeypatch.setattr(dev_private, "create_private_file", create)
    else:

        def move(source, destination):
            if fault == "raced-destination":
                original_create(destination, SECRET.encode())
            original_move(source, destination)
            if fault == "after-rename":
                raise OSError(SECRET)

        monkeypatch.setattr(journals, "_move_private", move)
    with pytest.raises(journals.JournalError) as caught:
        book.record_intent(request)
    assert str(caught.value) == "JOURNAL_PUBLICATION_UNCONFIRMED"
    report = book.read_summary()
    assert report.status == "BLOCKED" and SECRET not in json.dumps(report.to_dict())
    if fault != "after-rename":
        assert any(path.name.startswith(".pending-journal-") for path in book.root.iterdir())
    if fault == "raced-destination":
        destination = book.root / (OPERATION + ".000002.json")
        assert destination.read_bytes() == SECRET.encode()
    before = tuple(book.root.iterdir())
    with pytest.raises(journals.JournalError):
        book.record_intent(request)
    assert tuple(book.root.iterdir()) == before


def test_real_os_lock_prevents_a_concurrent_reservation(private_home, prepared):
    book, request = journal(private_home, prepared), engine_request(prepared)
    competitor = journal(private_home, prepared)
    with book._store._lock():
        with pytest.raises(journals.JournalError):
            competitor.reserve(request, approval(request))
    assert not list(book.root.glob("*.json"))


@pytest.mark.parametrize("replacement", ["root", "lock", "record"])
def test_detectable_identity_replacement_blocks_without_repair(private_home, prepared, monkeypatch, replacement):
    book, request = journal(private_home, prepared), engine_request(prepared)
    assert book.reserve(request, approval(request))
    original = journals.dev_instance_registry._identity
    selected = book._pins[0 if replacement == "root" else 2] if replacement != "record" else book._last[2]

    def changed(info):
        result = original(info)
        return (result[0], result[1] + 1000) if result == selected else result

    monkeypatch.setattr(journals.dev_instance_registry, "_identity", changed)
    before = tuple(book.root.iterdir())
    with pytest.raises(journals.JournalError):
        book.record_intent(request)
    assert tuple(book.root.iterdir()) == before


def test_duplicate_receipt_and_schema_drift_cannot_be_replayed(private_home, prepared):
    book, request = journal(private_home, prepared), engine_request(prepared)
    assert book.reserve(request, approval(request))
    book.record_intent(request)
    book.record_receipt(request, "network", request.provider.network, "4" * 64)
    with pytest.raises(journals.JournalError):
        book.record_receipt(request, "network", request.provider.network, "4" * 64)
    assert book.read_summary().operations[0].state == "PENDING"


def test_unknown_artifacts_are_preserved_without_printing_names_or_contents(private_home, prepared):
    book = journal(private_home, prepared)
    path = book.root / (SECRET + ".unknown")
    dev_private.create_private_file(path, SECRET.encode())
    report = book.read_summary()
    assert report.status == "BLOCKED" and report.code == "JOURNAL_UNKNOWN_ARTIFACT"
    assert path.read_bytes() == SECRET.encode() and SECRET not in repr(report) + json.dumps(report.to_dict())


def test_immutable_public_dtos_reject_arbitrary_private_claims():
    for create in (
        lambda: journals.JournalSummary("OBSERVED", SECRET),
        lambda: journals.JournalSummary("OBSERVED", "JOURNAL_OBSERVED", []),
        lambda: journals.ReservationConsent(OPERATION, OPERATION, SECRET, "a" * 64),
    ):
        with pytest.raises(journals.JournalError) as caught:
            create()
        assert SECRET not in repr(caught.value)


def test_engine_verification_cursor_refuses_a_restarted_execution_before_any_second_intent(private_home, prepared):
    book, request = journal(private_home, prepared), engine_request(prepared)
    assert book.reserve(request, approval(request))
    book.verify_reservation(request)
    book.record_intent(request)
    before = tuple(book.root.iterdir())
    book.verify_reservation(request)  # Normal second checkpoint immediately before first network create.
    with pytest.raises(journals.JournalError):
        book.verify_reservation(request)  # A restarted executor cannot reuse that checkpoint.
    assert tuple(book.root.iterdir()) == before


def test_unknown_private_file_never_makes_a_mutable_operation_claim(private_home, prepared):
    book = journal(private_home, prepared)
    fake = book.root / (OPERATION + ".000001.json")
    dev_private.create_private_file(fake, b'{"claim_tag":"' + SECRET.encode() + b'"}')
    request = engine_request(prepared)
    with pytest.raises(journals.JournalError):
        book.reserve(request, approval(request))
    assert fake.read_bytes().endswith(SECRET.encode() + b'"}')
    assert book.read_summary().status == "BLOCKED"

