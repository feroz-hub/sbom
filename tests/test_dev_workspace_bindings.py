"""New private synthetic state only; no generation, Git, engine or database."""

from __future__ import annotations

import builtins
import json
import os
import socket
import subprocess
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev_instance_plan as instances
from scripts import dev_workspace_bindings as bindings

from tests.test_dev_workspace_bundle import approve, fake_material
from tests.test_dev_workspace_bundle import fixture as _bundle_fixture
from tests.test_dev_workspace_bundle import synthetic_crypto as synthetic_crypto
from tests.test_dev_workspace_certificates import approve as approve_tls
from tests.test_dev_workspace_certificates import fake_crypto as fake_crypto
from tests.test_dev_workspace_certificates import fixture as _tls_fixture
from tests.test_dev_workspace_certificates import material as tls_material
from tests.test_dev_workspace_database_prepare import consent as database_consent
from tests.test_dev_workspace_database_prepare import executor as database_executor
from tests.test_dev_workspace_database_prepare import plan as database_plan
from tests.test_dev_workspace_database_prepare import prepared as _database_fixture
from tests.test_dev_workspace_operation_journal import engine_request

PRIVATE = "synthetic-private-marker-must-not-escape"
bundle_fixture, tls_fixture, database_fixture = _bundle_fixture, _tls_fixture, _database_fixture


def private_directory(path):
    if os.name == "nt":
        bindings.storage._windows_create(path)
    else:
        path.mkdir(mode=0o700)


@pytest.fixture(autouse=True)
def no_live(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Binding test attempted a live operation"))
    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.split(".")[0] in {"app", "psycopg", "sqlalchemy", "celery", "redis", "docker", "alembic"}:
            return forbidden(name)
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(bindings.bundle, "generate_material", forbidden)
    monkeypatch.setattr(bindings._tls_module(), "generate_material", forbidden)
    yield forbidden
    forbidden.assert_not_called()


@pytest.fixture
def state(tmp_path):
    home = tmp_path.resolve() / "h"
    private_directory(home)
    descriptor = instances.plan_instance(
        repository_id="a" * 64, worktree_id="b" * 64, commit="c" * 40, mode="isolated", auth_mode="native", generation=1
    ).descriptor
    binding = bindings.PreparedBinding(descriptor)
    store = bindings.BindingStore(home=home, instance_id=descriptor.instance_id)
    return SimpleNamespace(home=home, descriptor=descriptor, binding=binding, store=store)


def publish(state, binding=None, *, revision=0, completed=None, authorize=None):
    return state.store.publish(
        binding or state.binding,
        expected_revision=revision,
        completed=completed,
        authorize=authorize or (lambda _binding, _revision: True),
    )


def advanced(state):
    return replace(state.binding, descriptor=replace(state.descriptor, commit="d" * 40))


def test_constructor_missing_read_are_readonly_and_private_legacy_files_unread(state, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Read-only binding lookup attempted mutation"))
    monkeypatch.setattr(bindings.dev_private, "create_private_file", forbidden)
    monkeypatch.setattr(bindings.storage, "initialize_private_directory", forbidden)
    monkeypatch.setattr(bindings.registry.InstanceRegistry, "_lock", forbidden)
    monkeypatch.setattr(os, "mkdir", forbidden)
    monkeypatch.setattr(bindings, "uuid4", forbidden)
    store = bindings.BindingStore(home=state.home, instance_id=state.descriptor.instance_id)
    snapshot = store.read()
    assert snapshot.code == "BINDING_MISSING" and snapshot.binding is None
    assert not store.root.exists()
    forbidden.assert_not_called()


def test_declined_guard_creates_nothing_and_never_consumes_source_or_entropy(state, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Declined binding publication progressed"))
    monkeypatch.setattr(bindings, "uuid4", forbidden)
    monkeypatch.setattr(state.store, "_completed", forbidden)
    with pytest.raises(bindings.BindingError, match="^BINDING_CONSENT_REQUIRED$"):
        publish(state, authorize=lambda *_args: False)
    assert not state.store.root.exists()
    forbidden.assert_not_called()


def test_append_cas_reopen_and_source_head_change_reuse_without_rotation(state):
    original = publish(state)
    assert original.revision == 1 and original.binding == state.binding
    reopened = bindings.BindingStore(home=state.home, instance_id=state.descriptor.instance_id)
    assert reopened.read() == original
    result = reopened.publish(advanced(state), expected_revision=1, authorize=lambda *_args: True)
    assert result.revision == 2 and result.binding.descriptor.commit == "d" * 40
    assert {path.name for path in state.store.root.iterdir()} == {"000001.json", "000002.json", ".registry.lock"}
    summary = result.to_dict()
    assert not summary["ready"] and not summary["ownership_verified"] and not summary["live_operations_authorized"]
    assert str(state.home) not in repr(result) + json.dumps(summary)
    with pytest.raises(FrozenInstanceError):
        result.binding.descriptor = state.descriptor


def test_replay_and_cas_conflict_preserve_every_existing_record(state):
    publish(state)
    before = (state.store.root / "000001.json").read_bytes()
    with pytest.raises(bindings.BindingError, match="^BINDING_REPLAY_BLOCKED$"):
        publish(state, revision=1)
    with pytest.raises(bindings.BindingError, match="^BINDING_REVISION_CHANGED$"):
        publish(state, advanced(state))
    assert (state.store.root / "000001.json").read_bytes() == before
    assert state.store.read().revision == 1


@pytest.mark.parametrize(
    "name,code",
    [
        ("unknown-user-data", "BINDING_UNKNOWN_ARTIFACT"),
        (".pending-binding-interrupted.json", "BINDING_INTERRUPTED_WRITE"),
    ],
)
def test_unknown_or_partial_state_is_preserved_and_blocks_publish(state, name, code):
    publish(state)
    unknown = state.store.root / name
    bindings.dev_private.create_private_file(unknown, PRIVATE.encode())
    assert state.store.read().code == code
    with pytest.raises(bindings.BindingError, match="^" + code + "$"):
        publish(state, advanced(state), revision=1)
    assert unknown.read_bytes() == PRIVATE.encode() and not (state.store.root / "000002.json").exists()
    assert PRIVATE not in repr(state.store.read()) + json.dumps(state.store.read().to_dict())


def test_atomic_no_replace_collision_preserves_destination_and_pending_stage(state, monkeypatch):
    original = bindings._move_private

    def collide(source, destination):
        bindings.dev_private.create_private_file(destination, PRIVATE.encode())
        return original(source, destination)

    monkeypatch.setattr(bindings, "_move_private", collide)
    with pytest.raises(bindings.BindingError, match="^BINDING_PUBLICATION_UNCONFIRMED$"):
        publish(state)
    assert (state.store.root / "000001.json").read_bytes() == PRIVATE.encode()
    assert len(tuple(state.store.root.glob(".pending-binding-*"))) == 1
    assert state.store.read().code == "BINDING_INTERRUPTED_WRITE"


def test_post_publication_parent_drift_reports_uncertainty_and_preserves_record(state, monkeypatch):
    original = bindings._move_private

    def moved(source, destination):
        original(source, destination)
        monkeypatch.setattr(state.store, "_parent_pins", lambda: ((1, 2), (3, 4), (5, 6)))

    monkeypatch.setattr(bindings, "_move_private", moved)
    with pytest.raises(bindings.BindingError, match="^BINDING_PUBLICATION_UNCONFIRMED$"):
        publish(state)
    assert (state.store.root / "000001.json").exists()
    assert not tuple(state.store.root.glob(".pending-binding-*"))


def test_competing_writer_lock_is_nonblocking_and_preserves_empty_private_root(state):
    bindings.storage.initialize_private_directory(state.store.root, anchor=state.home)
    other = bindings.BindingStore(home=state.home, instance_id=state.descriptor.instance_id)
    with state.store._store._lock():
        with pytest.raises(bindings.BindingError, match="^BINDING_PUBLICATION_UNCONFIRMED$"):
            other.publish(state.binding, expected_revision=0, authorize=lambda *_args: True)
    assert {path.name for path in state.store.root.iterdir()} == {".registry.lock"}


def test_writer_conflict_is_rechecked_after_guard_and_does_not_overwrite(state):
    other = bindings.BindingStore(home=state.home, instance_id=state.descriptor.instance_id)
    count = [0]

    def authority(_binding, _revision):
        count[0] += 1
        if count[0] == 2:
            other.publish(state.binding, expected_revision=0, authorize=lambda *_args: True)
        return True

    with pytest.raises(bindings.BindingError, match="^BINDING_REVISION_CHANGED$"):
        publish(state, authorize=authority)
    assert state.store.read().revision == 1
    assert not (state.store.root / "000002.json").exists()


def test_final_guard_revocation_retains_private_stage_without_publication(state):
    calls = [0]

    def authority(_binding, _revision):
        calls[0] += 1
        return calls[0] < 4

    with pytest.raises(bindings.BindingError, match="^BINDING_CONSENT_REQUIRED$"):
        publish(state, authorize=authority)
    assert not (state.store.root / "000001.json").exists()
    assert len(tuple(state.store.root.glob(".pending-binding-*"))) == 1
    assert state.store.read().code == "BINDING_INTERRUPTED_WRITE"


def test_root_identity_and_permanent_lock_cannot_be_replaced_on_reopen(state):
    publish(state)
    original = state.store.root / "000001.json"
    raw = original.read_bytes()
    retired = state.store.root.with_name("retained-bindings")
    state.store.root.rename(retired)
    private_directory(state.store.root)
    bindings.dev_private.create_private_file(state.store.root / "000001.json", raw)
    bindings.dev_private.create_private_file(state.store.root / ".registry.lock", b"\0")
    reopened = bindings.BindingStore(home=state.home, instance_id=state.descriptor.instance_id)
    assert reopened.read().code == "BINDING_HISTORY_UNVERIFIED"
    assert (retired / "000001.json").read_bytes() == raw
    assert state.store.read().code == "BINDING_CONTEXT_CHANGED"


def test_lock_replacement_is_detected_from_protected_history(state):
    publish(state)
    lock = state.store.root / ".registry.lock"
    lock.rename(state.store.root / "retained-lock")
    bindings.dev_private.create_private_file(lock, b"\0")
    # Preserve the old artifact outside the inspected root; no lock repair/removal.
    (state.store.root / "retained-lock").rename(state.home / "retained-lock")
    fresh = bindings.BindingStore(home=state.home, instance_id=state.descriptor.instance_id)
    assert fresh.read().code == "BINDING_HISTORY_UNVERIFIED"
    assert state.store.read().code == "BINDING_CONTEXT_CHANGED"


def test_history_file_and_stage_drift_before_publication_are_refused(state):
    publish(state)
    calls = [0]

    def authority(_binding, _revision):
        calls[0] += 1
        if calls[0] == 4:
            (state.store.root / "000001.json").write_bytes(PRIVATE.encode())
        return True

    with pytest.raises(bindings.BindingError, match="^BINDING_REVISION_CHANGED$"):
        publish(state, advanced(state), revision=1, authorize=authority)
    assert not (state.store.root / "000002.json").exists()
    assert (state.store.root / "000001.json").read_bytes() == PRIVATE.encode()
    assert state.store.read().code == "BINDING_INTERRUPTED_WRITE"


def test_hardlinked_record_is_never_adopted_or_changed(state):
    publish(state)
    source = state.store.root / "000001.json"
    os.link(source, state.home / "retained-link")
    before = source.read_bytes()
    assert state.store.read().code == "BINDING_ACCESS_UNVERIFIED"
    with pytest.raises(bindings.BindingError):
        publish(state, advanced(state), revision=1)
    assert source.read_bytes() == before and source.stat().st_nlink == 2


@pytest.mark.parametrize("depth", [1, 2, 3])
def test_redirected_parent_is_preserved_and_refused(state, monkeypatch, depth):
    # A reparse attribute models the native boundary without requiring symlink privilege.
    publish(state)
    target = state.home.joinpath(*(".sbom-dev", "instances", state.descriptor.instance_id)[:depth])
    original = Path.lstat

    def redirected(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == target:
            values = {name: getattr(result, name) for name in dir(result) if name.startswith("st_")}
            values["st_file_attributes"] = 1024
            return SimpleNamespace(**values)
        return result

    monkeypatch.setattr(Path, "lstat", redirected)
    assert state.store.read().code == "BINDING_ACCESS_UNVERIFIED"
    assert (state.store.root / "000001.json").exists()


@pytest.mark.parametrize(
    "change", ["unknown-field", "duplicate-key", "revision-gap", "digest", "root-type", "secret-field"]
)
def test_strict_history_schema_refuses_unknown_or_malformed_private_input(state, change):
    publish(state)
    path = state.store.root / "000001.json"
    value = json.loads(path.read_bytes())
    if change == "duplicate-key":
        raw = b'{"version":1,' + path.read_bytes()[1:]
    else:
        if change == "unknown-field":
            value["unknown"] = PRIVATE
        elif change == "revision-gap":
            value["revision"] = 2
        elif change == "digest":
            value["digest"] = "0" * 64
        elif change == "root-type":
            value["root_identity"] = {"private": PRIVATE}
        else:
            value["binding"]["DATABASE_URL"] = PRIVATE
        raw = json.dumps(value).encode()
    path.write_bytes(raw)
    snapshot = state.store.read()
    assert snapshot.code in {"BINDING_HISTORY_UNVERIFIED", "BINDING_INPUT_INVALID"}
    assert PRIVATE not in repr(snapshot) + json.dumps(snapshot.to_dict())


def test_foreign_instance_and_identity_changes_cannot_publish(state):
    other = instances.plan_instance(
        repository_id="a" * 64, worktree_id="e" * 64, commit="c" * 40, mode="isolated", auth_mode="native", generation=1
    ).descriptor
    with pytest.raises(bindings.BindingError, match="^BINDING_INPUT_INVALID$"):
        publish(state, bindings.PreparedBinding(other))
    publish(state)
    changed = replace(state.binding, descriptor=replace(state.descriptor, auth_mode="hcl"))
    with pytest.raises(bindings.BindingError, match="^BINDING_CONTEXT_CHANGED$"):
        publish(state, changed, revision=1)


def test_policy_metadata_is_private_pinned_and_requires_known_source(state):
    bindings.storage.initialize_private_directory(state.home / "policy", anchor=state.home)
    path = state.home / "policy" / "selected.json"
    bindings.dev_private.create_private_file(path, PRIVATE.encode())
    reference = bindings.PolicyFileReference.inspect(path)
    binding = replace(state.binding, policy_file=reference)
    with pytest.raises(bindings.BindingError, match="^BINDING_COMPLETED_SOURCE_REQUIRED$"):
        publish(state, binding)
    result = publish(state, binding, completed=bindings.CompletedSources(policy_reference=reference))
    public = repr(result) + repr(binding) + repr(reference) + json.dumps(result.to_dict())
    assert str(path) not in public and PRIVATE not in public and str(reference.identity) not in public
    path.write_bytes(b"changed-private-policy")
    assert state.store.read().code == "BINDING_ARTIFACT_CHANGED"


@pytest.fixture
def prepared_bundle(bundle_fixture, synthetic_crypto):
    fixture = bundle_fixture
    outcome = bindings.bundle.prepare_bundle(fixture.plan, authorize=approve, generator=fake_material)
    assert outcome.exit_code == 0
    descriptor = replace(
        fixture.provider.descriptor, config_generation=fixture.plan.generation, configuration_present=True
    )
    binding = bindings.PreparedBinding(descriptor, bundle_generation=outcome.generation, bundle_receipt=outcome.receipt)
    store = bindings.BindingStore(home=fixture.anchor, instance_id=descriptor.instance_id)
    return SimpleNamespace(
        fixture=fixture,
        binding=binding,
        store=store,
        outcome=outcome,
        sources=bindings.CompletedSources(bundle_plan=fixture.plan, bundle_outcome=outcome),
    )


def test_known_bundle_requires_same_success_outcome_then_reopens_without_generation(prepared_bundle, monkeypatch):
    value = prepared_bundle
    with pytest.raises(bindings.BindingError, match="^BINDING_COMPLETED_SOURCE_REQUIRED$"):
        value.store.publish(value.binding, expected_revision=0, authorize=lambda *_args: True)
    value.store.publish(value.binding, expected_revision=0, authorize=lambda *_args: True, completed=value.sources)
    forbidden = Mock(side_effect=AssertionError("Read binding adopted/generated/revalidated current source"))
    monkeypatch.setattr(bindings.bundle, "_reuse", forbidden)
    monkeypatch.setattr(bindings.bundle, "_revalidate", forbidden)
    monkeypatch.setattr(bindings.bundle, "prepare_bundle", forbidden)
    loaded = bindings.BindingStore(home=value.fixture.anchor, instance_id=value.binding.descriptor.instance_id).read()
    assert loaded.binding == value.binding and loaded.revision == 1
    updated = replace(value.binding, descriptor=replace(value.binding.descriptor, commit="d" * 40))
    value.store.publish(updated, expected_revision=1, authorize=lambda *_args: True)
    assert value.store.read().binding.bundle_receipt == value.outcome.receipt
    assert value.outcome.receipt.private_binding not in json.dumps(loaded.to_dict())
    forbidden.assert_not_called()


@pytest.mark.parametrize("failure", ["failed", "reused", "wrong-path", "wrong-receipt"])
def test_incomplete_or_unrelated_bundle_outcomes_cannot_seed_history(prepared_bundle, failure):
    value = prepared_bundle
    outcome = value.outcome
    if failure == "failed":
        outcome = replace(outcome, exit_code=1, code="BUNDLE_PREPARATION_UNCONFIRMED")
    elif failure == "reused":
        outcome = replace(outcome, reused=True, code="BUNDLE_EXISTING_VERIFIED")
    elif failure == "wrong-path":
        outcome = replace(outcome, directory=value.fixture.root)
    else:
        outcome = replace(outcome, receipt=replace(outcome.receipt, private_binding="f" * 64))
    sources = bindings.CompletedSources(bundle_plan=value.fixture.plan, bundle_outcome=outcome)
    with pytest.raises(bindings.BindingError, match="^BINDING_COMPLETED_SOURCE_REQUIRED$"):
        value.store.publish(value.binding, expected_revision=0, authorize=lambda *_args: True, completed=sources)
    assert not value.store.root.exists()


@pytest.mark.parametrize("change", ["content", "directory", "unknown"])
def test_recorded_bundle_artifacts_must_keep_identity_and_exact_inventory(prepared_bundle, change):
    value = prepared_bundle
    value.store.publish(value.binding, expected_revision=0, authorize=lambda *_args: True, completed=value.sources)
    directory = value.outcome.directory
    if change == "content":
        (directory / "keys/auth-transaction-key").write_bytes(PRIVATE.encode())
    elif change == "directory":
        (directory / "keys").rename(directory / "retained-keys")
        private_directory(directory / "keys")
    else:
        bindings.dev_private.create_private_file(directory / "unknown", PRIVATE.encode())
    snapshot = value.store.read()
    assert snapshot.code in {"BINDING_ARTIFACT_CHANGED", "BINDING_HISTORY_UNVERIFIED"}
    assert PRIVATE not in json.dumps(snapshot.to_dict())


def test_certificate_only_receipt_roundtrips_without_preview_or_source_adoption(tls_fixture, fake_crypto, monkeypatch):
    tls = bindings._tls_module()
    outcome = tls.prepare_certificates(tls_fixture.plan, authorize=approve_tls, generator=tls_material)
    assert outcome.exit_code == 0
    binding = bindings.PreparedBinding(
        tls_fixture.descriptor, certificate_generation=outcome.receipt.generation, certificate_receipt=outcome.receipt
    )
    store = bindings.BindingStore(home=tls_fixture.anchor, instance_id=binding.descriptor.instance_id)
    sources = bindings.CompletedSources(certificate_plan=tls_fixture.plan, certificate_outcome=outcome)
    result = store.publish(binding, expected_revision=0, authorize=lambda *_args: True, completed=sources)
    forbidden = Mock(side_effect=AssertionError("Receipt read invoked preview, generation or current source"))
    monkeypatch.setattr(tls, "_reuse", forbidden)
    monkeypatch.setattr(tls, "_revalidate", forbidden)
    monkeypatch.setattr(tls, "PreviewTls", forbidden)
    assert bindings.BindingStore(home=tls_fixture.anchor, instance_id=binding.descriptor.instance_id).read() == result
    assert outcome.receipt.material_binding not in json.dumps(result.to_dict())
    forbidden.assert_not_called()


@pytest.fixture
def provider_state(bundle_fixture, synthetic_crypto, database_fixture):
    value = database_fixture
    private = bindings.bundle
    planned = private.plan_bundle(
        value.proposal,
        bundle_fixture.source,
        anchor=bundle_fixture.plan.anchor,
        generation=bundle_fixture.plan.generation,
        profiles=private.compose._PROFILES,
    )
    material = private.prepare_bundle(planned, authorize=approve, generator=fake_material)
    assert material.exit_code == 0
    references = tuple(
        replace(item, source=str(material.directory / "provider" / item.reference))
        for item in value.compose.policy.secret_files
    )
    policy = replace(value.compose.policy, bundle_generation=planned.generation, secret_files=references)
    review = replace(
        value.compose.review,
        policy_fingerprint=private.compose.policy_fingerprint(policy),
        private_binding=policy.private_binding(),
    )
    value.compose = private.compose.plan_compose(value.proposal, policy, review=review)
    value.records = replace(
        value.records,
        secrets=tuple(bindings.engine.SecretFile.inspect(item.reference, Path(item.source)) for item in references),
    )
    descriptor = replace(value.proposal.descriptor, configuration_present=True, config_generation=planned.generation)
    base = bindings.PreparedBinding(descriptor, bundle_generation=planned.generation, bundle_receipt=material.receipt)
    state = SimpleNamespace(
        home=bundle_fixture.anchor,
        descriptor=descriptor,
        binding=base,
        store=bindings.BindingStore(home=bundle_fixture.anchor, instance_id=descriptor.instance_id),
    )
    request = engine_request(value)
    outcome = bindings.engine.EngineOutcome(
        "ENGINE_ACTION_COMPLETED",
        tuple(item.object_id for item in value.records.containers),
        value.records,
        created_network_id=value.records.network_id,
    )
    binding = replace(state.binding, resources=value.records)
    sources = bindings.CompletedSources(
        bundle_plan=planned, bundle_outcome=material, engine_plan=request, engine_outcome=outcome
    )
    return SimpleNamespace(
        state=state, fixture=value, request=request, outcome=outcome, binding=binding, sources=sources
    )


def test_engine_and_database_completed_results_roundtrip_without_live_adapters(provider_state, monkeypatch):
    value, state = provider_state, provider_state.state
    publish(state, value.binding, completed=value.sources)
    init = database_plan(value.fixture)
    initialized = database_executor(value.fixture).execute(init, database_consent(init))
    assert initialized.code == "DB_PREPARATION_COMPLETED"
    binding = replace(value.binding, database_target=init.target, database_receipts=(initialized.receipt,))
    source = bindings.CompletedSources(database_plan=init, database_outcome=initialized)
    result = publish(state, binding, revision=1, completed=source)
    assert result.revision == 2
    roles = database_plan(value.fixture, "database", prior=initialized.receipt)
    configured = database_executor(value.fixture).execute(roles, database_consent(roles))
    assert configured.code == "DB_PREPARATION_COMPLETED"
    binding = replace(binding, database_receipts=(*binding.database_receipts, configured.receipt))
    result = publish(
        state,
        binding,
        revision=2,
        completed=bindings.CompletedSources(database_plan=roles, database_outcome=configured),
    )
    forbidden = Mock(side_effect=AssertionError("Binding reopen contacted a resource"))
    monkeypatch.setattr(bindings.engine, "discover_engine", forbidden)
    monkeypatch.setattr(bindings.database.PreparationExecutor, "execute", forbidden)
    assert bindings.BindingStore(home=state.home, instance_id=state.descriptor.instance_id).read() == result
    assert result.binding.resources == value.fixture.records
    assert {receipt.action for receipt in result.binding.database_receipts} == {"initdb", "database"}
    assert init.target.fingerprint() not in json.dumps(result.to_dict())
    forbidden.assert_not_called()


@pytest.mark.parametrize("failure", ["no-source", "partial", "wrong-engine", "start-adoption", "missing-created-id"])
def test_provider_records_need_initial_successful_create_and_exact_engine(provider_state, failure):
    value, state = provider_state, provider_state.state
    sources = value.sources
    if failure == "no-source":
        sources = bindings.CompletedSources()
    elif failure == "partial":
        sources = replace(sources, engine_outcome=replace(value.outcome, code="ENGINE_ACTION_UNCONFIRMED"))
    elif failure == "wrong-engine":
        sources = replace(
            sources,
            engine_plan=replace(value.request, capability=replace(value.request.capability, engine_identity="f" * 64)),
        )
    elif failure == "start-adoption":
        sources = replace(
            sources, engine_plan=replace(value.request, consent=replace(value.request.consent, action="start"))
        )
    else:
        sources = replace(sources, engine_outcome=replace(value.outcome, completed_ids=()))
    with pytest.raises(bindings.BindingError, match="^BINDING_COMPLETED_SOURCE_REQUIRED$"):
        publish(state, value.binding, completed=sources)
    assert not state.store.root.exists()


@pytest.mark.parametrize(
    "failure", ["missing-source", "failed", "cleanup", "uncertain-helper", "wrong-target", "wrong-postgres"]
)
def test_database_receipts_do_not_promote_failed_or_uncertain_results(provider_state, failure):
    value, state = provider_state, provider_state.state
    publish(state, value.binding, completed=value.sources)
    planned = database_plan(value.fixture)
    outcome = database_executor(value.fixture).execute(planned, database_consent(planned))
    assert outcome.code == "DB_PREPARATION_COMPLETED"
    binding = replace(value.binding, database_target=planned.target, database_receipts=(outcome.receipt,))
    sources = bindings.CompletedSources(database_plan=planned, database_outcome=outcome)
    if failure == "missing-source":
        sources = bindings.CompletedSources()
    elif failure == "failed":
        sources = replace(sources, database_outcome=replace(outcome, code="DB_PREPARATION_UNCONFIRMED"))
    elif failure == "cleanup":
        sources = replace(sources, database_outcome=replace(outcome, cleanup_verified=False))
    elif failure == "uncertain-helper":
        sources = replace(
            sources,
            database_outcome=replace(
                outcome, code="DB_HELPER_UNCONFIRMED", cleanup_verified=False, unconfirmed_helper_ids=("f" * 64,)
            ),
        )
    elif failure == "wrong-target":
        sources = replace(
            sources, database_plan=replace(planned, target=replace(planned.target, volume_birth="f" * 64))
        )
    else:
        sources = replace(sources, database_outcome=replace(outcome, postgres_id="f" * 64))
    with pytest.raises(bindings.BindingError, match="^BINDING_COMPLETED_SOURCE_REQUIRED$"):
        publish(state, binding, revision=1, completed=sources)
    assert state.store.read().revision == 1 and not (state.store.root / "000002.json").exists()


def test_resources_from_other_instance_and_unknown_secret_paths_fail_closed(provider_state):
    value, state = provider_state, provider_state.state
    foreign = instances.plan_instance(
        repository_id="a" * 64, worktree_id="f" * 64, commit="c" * 40, mode="isolated", auth_mode="native", generation=1
    ).descriptor
    with pytest.raises(bindings.BindingError, match="^BINDING_CONTEXT_CHANGED$"):
        replace(value.binding, descriptor=foreign)
    publish(state, value.binding, completed=value.sources)
    altered = replace(value.binding, resources=replace(value.fixture.records, network_id="f" * 64))
    with pytest.raises(bindings.BindingError, match="^BINDING_CONTEXT_CHANGED$"):
        publish(state, altered, revision=1)


def test_history_and_payload_bounds_preserve_existing_state(state, monkeypatch):
    publish(state)
    monkeypatch.setattr(state.store, "MAX_FILES", 1)
    assert state.store.read().code == "BINDING_LIMIT_REQUIRED"
    monkeypatch.setattr(state.store, "MAX_FILES", 130)
    monkeypatch.setattr(state.store, "MAX_BYTES", 16)
    assert state.store.read().code == "BINDING_HISTORY_UNVERIFIED"
    assert (state.store.root / "000001.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode compatibility; native ACL policy is separately exercised")
def test_owned_non_writable_0755_home_is_supported_without_changing_it(state):
    state.home.chmod(0o755)
    publish(state)
    assert state.store.read().revision == 1
    assert state.home.stat().st_mode & 0o777 == 0o755


def test_home_is_anchor_and_every_state_descendant_requires_private_access(state, monkeypatch):
    original, calls = bindings.storage._verify, []

    def verify(path, *, private):
        calls.append((path, private))
        return original(path, private=private)

    monkeypatch.setattr(bindings.storage, "_verify", verify)
    publish(state)
    assert (state.home, False) in calls and (state.home, True) not in calls
    assert all(
        (state.home / relative, True) in calls
        for relative in (".sbom-dev", ".sbom-dev/instances", ".sbom-dev/instances/" + state.descriptor.instance_id)
    )


def test_database_predecessor_must_match_the_protected_completed_receipt(provider_state):
    value, state = provider_state, provider_state.state
    publish(state, value.binding, completed=value.sources)
    init = database_plan(value.fixture)
    initialized = database_executor(value.fixture).execute(init, database_consent(init))
    known = replace(value.binding, database_target=init.target, database_receipts=(initialized.receipt,))
    publish(
        state, known, revision=1, completed=bindings.CompletedSources(database_plan=init, database_outcome=initialized)
    )
    roles = database_plan(value.fixture, "database", prior=initialized.receipt)
    configured = database_executor(value.fixture).execute(roles, database_consent(roles))
    assert configured.code == "DB_PREPARATION_COMPLETED"
    next_binding = replace(known, database_receipts=(*known.database_receipts, configured.receipt))
    foreign_prior = replace(initialized.receipt, cluster_id="f" * 64)
    with pytest.raises(bindings.BindingError, match="^BINDING_COMPLETED_SOURCE_REQUIRED$"):
        publish(
            state,
            next_binding,
            revision=2,
            completed=bindings.CompletedSources(
                database_plan=replace(roles, prior=foreign_prior), database_outcome=configured
            ),
        )
    assert state.store.read().revision == 2
    with pytest.raises(bindings.BindingError, match="^BINDING_CONTEXT_CHANGED$"):
        replace(known, database_receipts=(configured.receipt,))
    migrated = bindings.database.PreparationReceipt(
        "migrate",
        init.target.fingerprint(),
        initialized.receipt.cluster_id,
        (("owner", 99), ("runtime", 12), ("database", 13)),
        ("103_tenant_admin_governance",),
    )
    with pytest.raises(bindings.BindingError, match="^BINDING_CONTEXT_CHANGED$"):
        replace(next_binding, database_receipts=(*next_binding.database_receipts, migrated))


@pytest.mark.parametrize(
    "factory",
    [
        lambda: bindings.CompletedSources(bundle_outcome=object()),
        lambda: bindings.PreparedBinding({"secret": PRIVATE}),
        lambda: bindings.BindingStore(home=Path("relative"), instance_id="bad"),
        lambda: bindings.PolicyFileReference(Path("relative"), (1, 2, 3, 4, 5)),
    ],
)
def test_invalid_or_mutable_input_is_rejected_without_private_exception_text(factory):
    with pytest.raises(bindings.BindingError) as raised:
        factory()
    assert PRIVATE not in str(raised.value)
