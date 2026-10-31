"""Disposable metadata only; no application, database or managed process."""

from __future__ import annotations

import json
import os
import sys
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev_instance_plan as plans
from scripts import dev_instance_registry as registry


def descriptor(worktree="b" * 64, *, claimed=()):
    return plans.plan_instance(
        repository_id="a" * 64,
        worktree_id=worktree,
        commit="c" * 40,
        generation=1,
        mode="mock",
        auth_mode="native",
        provider="mock",
        claimed_ports=claimed,
    ).descriptor


@pytest.fixture
def store(tmp_path):
    from scripts import dev_instance_storage as storage

    anchor = tmp_path.resolve() / "private-anchor"
    if sys.platform == "win32":
        storage._windows_create(anchor)  # New synthetic directory only; never repair parent ACLs.
    else:
        anchor.mkdir(mode=0o700)
    root = anchor / "registry"
    storage.initialize_private_directory(root, anchor=anchor)
    return registry.InstanceRegistry(root, anchor=anchor, repository_id="a" * 64)


def test_absent_registry_read_has_no_write_lock_or_directory(tmp_path, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Read-only registry attempted mutation"))
    monkeypatch.setattr(os, "mkdir", forbidden)
    monkeypatch.setattr(registry.dev_private, "create_private_file", forbidden)
    store = registry.InstanceRegistry(tmp_path / "missing", anchor=tmp_path)
    assert store.read().codes == ("REGISTRY_MISSING",)
    assert not (tmp_path / "missing").exists()
    forbidden.assert_not_called()


def test_public_descriptor_roundtrip_and_permanent_lock(store):
    entry = registry.RegistryEntry(descriptor())
    assert store.publish(entry, expected_revision=0) == entry
    lock = store.root / ".registry.lock"
    before = lock.stat().st_ino
    assert store.read() == registry.RegistrySnapshot((entry,))
    updated = replace(entry, revision=2, state="STOPPED")
    assert store.publish(updated, expected_revision=1) == updated
    assert lock.stat().st_ino == before
    assert store.read().entries == (updated,)


def test_stale_revision_cannot_replace_known_record(store):
    entry = registry.RegistryEntry(descriptor())
    store.publish(entry, expected_revision=0)
    before = (store.root / (entry.descriptor.instance_id + ".json")).read_bytes()
    with pytest.raises(registry.RegistryError, match="REGISTRY_REVISION_CHANGED"):
        store.publish(replace(entry, revision=2), expected_revision=0)
    assert (store.root / (entry.descriptor.instance_id + ".json")).read_bytes() == before


def test_competing_writer_retains_lock_and_records(store):
    with store._lock():
        with pytest.raises(registry.RegistryError, match="REGISTRY_BUSY"):
            store.publish(registry.RegistryEntry(descriptor()), expected_revision=0)
    assert (store.root / ".registry.lock").exists()
    assert not store.read().entries


def test_two_worktrees_have_independent_records_and_reserved_ports(store):
    first = registry.RegistryEntry(descriptor())
    second = registry.RegistryEntry(descriptor("d" * 64, claimed=tuple(first.descriptor.ports.values())))
    store.publish(first, expected_revision=0)
    store.publish(second, expected_revision=0)
    assert len(store.read().entries) == 2
    assert not set(first.descriptor.ports.values()) & set(second.descriptor.ports.values())


def test_other_repository_cannot_publish(store):
    other = plans.plan_instance(
        repository_id="f" * 64,
        worktree_id="b" * 64,
        commit="c" * 40,
        generation=1,
        mode="mock",
        auth_mode="native",
        provider="mock",
    ).descriptor
    with pytest.raises(registry.RegistryError):
        store.publish(registry.RegistryEntry(other), expected_revision=0)
    assert not store.read().entries


@pytest.mark.parametrize(
    "field,value",
    [
        ("password", "fixture-private-value"),
        ("DATABASE_URL", "fixture-private-value"),
        ("environment", {"SECRET": "fixture"}),
        ("operator_authorization", "fixture"),
    ],
)
def test_unknown_manifest_fields_are_never_accepted_or_echoed(field, value):
    raw = registry.RegistryEntry(descriptor()).to_dict()
    raw[field] = value
    with pytest.raises(registry.RegistryError, match="^REGISTRY_SCHEMA_INVALID$") as caught:
        registry.RegistryEntry.from_dict(raw)
    assert "fixture-private-value" not in str(caught.value)


@pytest.mark.parametrize(
    "field,value", [("revision", True), ("revision", -1), ("state", "DELETE"), ("last_code", "private:fixture")]
)
def test_invalid_metadata_refused(field, value):
    raw = registry.RegistryEntry(descriptor()).to_dict()
    raw[field] = value
    with pytest.raises(registry.RegistryError):
        registry.RegistryEntry.from_dict(raw)


def test_unknown_artifact_preserved_and_blocks_writer(store):
    path = store.root / "unknown.json"
    path.write_text("fixture-unknown", encoding="utf-8")
    assert store.read().codes == ("REGISTRY_UNKNOWN_ARTIFACT",)
    with pytest.raises(registry.RegistryError, match="REGISTRY_UNKNOWN_ARTIFACT"):
        store.publish(registry.RegistryEntry(descriptor()), expected_revision=0)
    assert path.read_text() == "fixture-unknown"


def test_failed_publication_retains_staging_for_explicit_recovery(store, monkeypatch):
    entry = registry.RegistryEntry(descriptor())
    store.publish(entry, expected_revision=0)
    destination = store.root / (entry.descriptor.instance_id + ".json")
    before = destination.read_bytes()
    monkeypatch.setattr(os, "replace", Mock(side_effect=PermissionError("fixture-private-error")))
    with pytest.raises(registry.RegistryError, match="^REGISTRY_PUBLICATION_UNCONFIRMED$"):
        store.publish(replace(entry, revision=2), expected_revision=1)
    staged = tuple(store.root.glob(".pending-*"))
    assert len(staged) == 1 and staged[0].exists()
    assert destination.read_bytes() == before
    assert store.read().codes == ("REGISTRY_UNKNOWN_ARTIFACT",)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode semantics; native DACL tested separately")
def test_public_registry_directory_refused_without_repair(store):
    store.root.chmod(0o755)
    assert store.read().codes == ("REGISTRY_ACCESS_UNVERIFIED",)
    assert store.root.stat().st_mode & 0o777 == 0o755


def test_corrupt_owned_record_preserved(store):
    entry = registry.RegistryEntry(descriptor())
    store.publish(entry, expected_revision=0)
    path = store.root / (entry.descriptor.instance_id + ".json")
    path.write_bytes(b"{invalid-fixture-json")
    assert store.read().codes == ("REGISTRY_RECORD_UNVERIFIED",)
    assert path.read_bytes() == b"{invalid-fixture-json"


def test_new_publication_is_create_only_and_restores_one_owned_link(store, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("New publication attempted replacement"))
    monkeypatch.setattr(os, "replace", forbidden)
    entry = registry.RegistryEntry(descriptor())
    assert store.publish(entry, expected_revision=0) == entry
    destination = store.root / (entry.descriptor.instance_id + ".json")
    assert destination.stat().st_nlink == 1
    assert not tuple(store.root.glob(".pending-*"))
    assert store.read().entries == (entry,)
    forbidden.assert_not_called()


def test_destination_appearing_at_create_publication_is_never_overwritten(store, monkeypatch):
    entry = registry.RegistryEntry(descriptor())
    destination = store.root / (entry.descriptor.instance_id + ".json")
    original_link = os.link

    def race(source, target, *, follow_symlinks):
        assert target == destination and follow_symlinks is False
        registry.dev_private.create_private_file(destination, b"unknown-fixture-do-not-overwrite")
        return original_link(source, target, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "link", race)
    monkeypatch.setattr(os, "replace", Mock(side_effect=AssertionError("Create-only fallback replaced a file")))
    with pytest.raises(registry.RegistryError, match="^REGISTRY_REVISION_CHANGED$"):
        store.publish(entry, expected_revision=0)
    assert destination.read_bytes() == b"unknown-fixture-do-not-overwrite"
    staged = tuple(store.root.glob(".pending-*"))
    assert len(staged) == 1 and staged[0].stat().st_nlink == 1
    assert json.loads(staged[0].read_bytes()) == entry.to_dict()


def test_unsupported_create_only_publication_retains_stage_without_replace_fallback(store, monkeypatch):
    entry = registry.RegistryEntry(descriptor())
    monkeypatch.setattr(os, "link", Mock(side_effect=NotImplementedError("fixture-private-error")))
    forbidden = Mock(side_effect=AssertionError("Unsupported hardlinks triggered replacement"))
    monkeypatch.setattr(os, "replace", forbidden)
    with pytest.raises(registry.RegistryError, match="^REGISTRY_PUBLICATION_UNCONFIRMED$"):
        store.publish(entry, expected_revision=0)
    assert not (store.root / (entry.descriptor.instance_id + ".json")).exists()
    assert len(tuple(store.root.glob(".pending-*"))) == 1
    forbidden.assert_not_called()


def test_failure_after_link_never_removes_published_destination_or_stage(store, monkeypatch):
    entry = registry.RegistryEntry(descriptor())
    destination = store.root / (entry.descriptor.instance_id + ".json")
    monkeypatch.setattr(os, "unlink", Mock(side_effect=PermissionError("fixture-private-error")))
    with pytest.raises(registry.RegistryError, match="^REGISTRY_PUBLICATION_UNCONFIRMED$"):
        store.publish(entry, expected_revision=0)
    staged = tuple(store.root.glob(".pending-*"))
    assert len(staged) == 1 and destination.exists()
    assert staged[0].stat().st_ino == destination.stat().st_ino
    assert staged[0].stat().st_nlink == destination.stat().st_nlink == 2
    assert destination.read_bytes() == staged[0].read_bytes()


def test_stage_substitution_after_link_is_preserved_without_cleanup(store, monkeypatch):
    entry = registry.RegistryEntry(descriptor())
    destination = store.root / (entry.descriptor.instance_id + ".json")
    original_link, original_replace = os.link, os.replace

    def substitute(source, target, *, follow_symlinks):
        original_link(source, target, follow_symlinks=follow_symlinks)
        replacement = store.root / "fixture-stage-replacement"
        registry.dev_private.create_private_file(replacement, b"unknown-replacement-stage")
        original_replace(replacement, source)

    monkeypatch.setattr(os, "link", substitute)
    cleanup = Mock(side_effect=AssertionError("Unverified stage was removed"))
    monkeypatch.setattr(os, "unlink", cleanup)
    with pytest.raises(registry.RegistryError, match="^REGISTRY_PUBLICATION_UNCONFIRMED$"):
        store.publish(entry, expected_revision=0)
    staged = tuple(store.root.glob(".pending-*"))
    assert len(staged) == 1 and staged[0].read_bytes() == b"unknown-replacement-stage"
    assert json.loads(destination.read_bytes()) == entry.to_dict()
    cleanup.assert_not_called()


@pytest.mark.parametrize("changed", ["root", "lock"])
@pytest.mark.parametrize("update", [False, True])
def test_detected_root_or_lock_identity_change_refuses_before_publication(store, monkeypatch, changed, update):
    entry = registry.RegistryEntry(descriptor())
    destination = store.root / (entry.descriptor.instance_id + ".json")
    if update:
        store.publish(entry, expected_revision=0)
    before = destination.read_bytes() if update else None
    original_create, original_private = registry.dev_private.create_private_file, registry._private
    staged = False

    def create(path, content):
        nonlocal staged
        original_create(path, content)
        if path.name.startswith(".pending-"):
            staged = True

    def private(path, **kwargs):
        info = original_private(path, **kwargs)
        target = store.root if changed == "root" else store.root / ".registry.lock"
        if staged and path == target:
            return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino + 1, st_size=info.st_size)
        return info

    monkeypatch.setattr(registry.dev_private, "create_private_file", create)
    monkeypatch.setattr(registry, "_private", private)
    publication = Mock(side_effect=AssertionError("Changed root/lock reached publication"))
    monkeypatch.setattr(os, "replace", publication)
    monkeypatch.setattr(os, "link", publication)
    with pytest.raises(registry.RegistryError, match="^REGISTRY_LOCK_UNVERIFIED$"):
        store.publish(replace(entry, revision=2) if update else entry, expected_revision=1 if update else 0)
    assert (destination.read_bytes() if destination.exists() else None) == before
    assert len(tuple(store.root.glob(".pending-*"))) == 1
    publication.assert_not_called()


@pytest.mark.skipif(sys.platform == "win32", reason="Windows open-file sharing can prevent this synthetic rename")
@pytest.mark.parametrize("changed", ["root", "lock"])
def test_actual_replacement_of_pinned_directory_or_lock_is_not_adopted(store, monkeypatch, changed):
    from scripts.dev_instance_storage import initialize_private_directory

    entry = registry.RegistryEntry(descriptor())
    original_create = registry.dev_private.create_private_file
    archived = store.anchor / "archived-registry"

    def create(path, content):
        original_create(path, content)
        if path.name.startswith(".pending-"):
            if changed == "root":
                store.root.rename(archived)
                initialize_private_directory(store.root, anchor=store.anchor)
            else:
                lock = store.root / ".registry.lock"
                lock.rename(store.root / "retained-original-lock")
                original_create(lock, b"\0")

    monkeypatch.setattr(registry.dev_private, "create_private_file", create)
    with pytest.raises(registry.RegistryError, match="^REGISTRY_LOCK_UNVERIFIED$"):
        store.publish(entry, expected_revision=0)
    assert not (store.root / (entry.descriptor.instance_id + ".json")).exists()
    retained_root = archived if changed == "root" else store.root
    assert len(tuple(retained_root.glob(".pending-*"))) == 1
    if changed == "root":
        assert not tuple(store.root.iterdir())
    else:
        assert (store.root / "retained-original-lock").exists()


def test_identical_content_record_replacement_after_snapshot_is_not_overwritten(store, monkeypatch):
    entry = registry.RegistryEntry(descriptor())
    store.publish(entry, expected_revision=0)
    destination = store.root / (entry.descriptor.instance_id + ".json")
    before = destination.read_bytes()
    original_create, original_replace = registry.dev_private.create_private_file, os.replace
    replaced_identity = None

    def create(path, content):
        nonlocal replaced_identity
        original_create(path, content)
        if path.name.startswith(".pending-"):
            replacement = store.root / "fixture-record-replacement"
            original_create(replacement, before)
            original_replace(replacement, destination)
            replaced_identity = destination.stat().st_ino

    monkeypatch.setattr(registry.dev_private, "create_private_file", create)
    mutation = Mock(side_effect=AssertionError("Unknown replacement inode was overwritten"))
    monkeypatch.setattr(os, "replace", mutation)
    with pytest.raises(registry.RegistryError, match="^REGISTRY_REVISION_CHANGED$"):
        store.publish(replace(entry, revision=2), expected_revision=1)
    assert destination.read_bytes() == before and destination.stat().st_ino == replaced_identity
    assert len(tuple(store.root.glob(".pending-*"))) == 1
    mutation.assert_not_called()


def test_registry_capacity_rejects_new_record_but_allows_existing_update(store, monkeypatch):
    monkeypatch.setattr(store, "MAX_RECORDS", 2)
    first = registry.RegistryEntry(descriptor())
    second = registry.RegistryEntry(descriptor("d" * 64, claimed=first.descriptor.ports.values()))
    store.publish(first, expected_revision=0)
    store.publish(second, expected_revision=0)
    third = registry.RegistryEntry(
        descriptor("e" * 64, claimed=(*first.descriptor.ports.values(), *second.descriptor.ports.values()))
    )
    with pytest.raises(registry.RegistryError, match="^REGISTRY_LIMIT_REQUIRED$"):
        store.publish(third, expected_revision=0)
    assert not tuple(store.root.glob(".pending-*"))
    updated = replace(first, revision=2, state="STOPPED")
    store.publish(updated, expected_revision=1)
    assert len(store.read().entries) == 2 and updated in store.read().entries


def test_directory_enumeration_stops_at_bound_before_reading_records(store, monkeypatch):
    class EndlessEntries:
        count, closed = 0, False

        def __enter__(self):
            return self

        def __exit__(self, *values):
            self.closed = True

        def __iter__(self):
            return self

        def __next__(self):
            self.count += 1
            return SimpleNamespace(name="fixture-" + str(self.count))

    iterator = EndlessEntries()
    monkeypatch.setattr(store, "MAX_RECORDS", 2)
    with monkeypatch.context() as guarded:
        guarded.setattr(os, "scandir", lambda path: iterator)
        snapshot = store.read()
    assert snapshot.codes == ("REGISTRY_LIMIT_REQUIRED",)
    assert iterator.count == 4 and iterator.closed is True


def test_record_count_limit_applies_even_without_a_lock_file(store, monkeypatch):
    monkeypatch.setattr(store, "MAX_RECORDS", 1)
    first = registry.RegistryEntry(descriptor())
    second = registry.RegistryEntry(descriptor("d" * 64, claimed=first.descriptor.ports.values()))
    for entry in (first, second):
        registry.dev_private.create_private_file(
            store.root / (entry.descriptor.instance_id + ".json"), json.dumps(entry.to_dict()).encode()
        )
    assert store.read().codes == ("REGISTRY_LIMIT_REQUIRED",)
    assert not (store.root / ".registry.lock").exists()


def test_registry_dtos_copy_mutable_inputs_and_do_not_imply_authority():
    operations = ["REGISTRY_PREPARED"]
    entry = registry.RegistryEntry(descriptor(), operations=operations, plan_fingerprint="f" * 64)
    entries, codes = [entry], ["REGISTRY_MISSING"]
    snapshot = registry.RegistrySnapshot(entries=entries)
    failed = registry.RegistrySnapshot(codes=codes)
    operations.append("STOP_REQUESTED")
    entries.clear()
    codes.clear()
    assert entry.operations == ("REGISTRY_PREPARED",) and snapshot.entries == (entry,)
    assert failed.codes == ("REGISTRY_MISSING",)
    output = entry.to_dict()
    output["operations"].append("START_REQUESTED")
    assert entry.operations == ("REGISTRY_PREPARED",)
    assert entry.descriptor.ownership_verified is False and entry.descriptor.live_operations_authorized is False
    with pytest.raises(FrozenInstanceError):
        entry.state = "READY"


@pytest.mark.parametrize(
    "changes",
    [
        {"descriptor": {"password": "FIXTURE_PRIVATE_TOKEN"}},
        {"revision": True},
        {"state": "DELETE"},
        {"last_code": "FIXTURE_PRIVATE_TOKEN"},
        {"last_code": "A" * 64},
        {"plan_fingerprint": "FIXTURE_PRIVATE_TOKEN"},
        {"operations": ["FIXTURE_PRIVATE_TOKEN"]},
        {"operations": ["REGISTRY_PREPARED"] * 129},
        {"operations": {"REGISTRY_PREPARED": "FIXTURE_PRIVATE_TOKEN"}},
    ],
)
def test_registry_entry_constructors_refuse_unreviewed_text_and_invalid_metadata(changes):
    values = {"descriptor": descriptor(), **changes}
    with pytest.raises(registry.RegistryError) as caught:
        registry.RegistryEntry(**values)
    assert "FIXTURE_PRIVATE_TOKEN" not in str(caught.value) + repr(caught.value)


@pytest.mark.parametrize(
    "changes",
    [
        {"entries": [{"password": "FIXTURE_PRIVATE_TOKEN"}]},
        {"codes": ["FIXTURE_PRIVATE_TOKEN"]},
        {"entries": [None]},
        {"codes": [True]},
        {"entries": [None] * 129},
    ],
)
def test_registry_snapshot_constructors_reject_unverified_entries_and_unknown_codes(changes):
    with pytest.raises(registry.RegistryError) as caught:
        registry.RegistrySnapshot(**changes)
    assert "FIXTURE_PRIVATE_TOKEN" not in str(caught.value)


def test_uppercase_token_shaped_last_code_is_rejected_by_json_parser_without_echo():
    raw = registry.RegistryEntry(descriptor()).to_dict()
    raw["last_code"] = "FIXTURE_PRIVATE_TOKEN_0123456789"
    with pytest.raises(registry.RegistryError, match="^REGISTRY_SCHEMA_INVALID$") as caught:
        registry.RegistryEntry.from_dict(raw)
    assert "FIXTURE_PRIVATE_TOKEN" not in str(caught.value)
    assert str(registry.RegistryError("FIXTURE_PRIVATE_TOKEN")) == "REGISTRY_SCHEMA_INVALID"


def test_duplicate_json_fields_remain_unverified_and_preserved(store):
    entry = registry.RegistryEntry(descriptor())
    destination = store.root / (entry.descriptor.instance_id + ".json")
    payload = json.dumps(entry.to_dict()).replace('"version": 1', '"version": 1, "version": 1', 1).encode()
    registry.dev_private.create_private_file(destination, payload)
    assert store.read().codes == ("REGISTRY_SCHEMA_INVALID",)
    assert destination.read_bytes() == payload


def test_existing_hardlinked_record_is_not_adopted_or_unlinked(store):
    entry = registry.RegistryEntry(descriptor())
    store.publish(entry, expected_revision=0)
    destination = store.root / (entry.descriptor.instance_id + ".json")
    retained = store.anchor / "fixture-retained-hardlink"
    os.link(destination, retained)
    before = destination.read_bytes()
    assert store.read().codes == ("REGISTRY_OBJECT_UNVERIFIED",)
    with pytest.raises(registry.RegistryError, match="^REGISTRY_OBJECT_UNVERIFIED$"):
        store.publish(replace(entry, revision=2), expected_revision=1)
    assert retained.read_bytes() == destination.read_bytes() == before
    assert retained.stat().st_nlink == destination.stat().st_nlink == 2


@pytest.mark.parametrize("update", [False, True])
def test_failure_only_at_writer_context_exit_is_uncertain_and_keeps_publication(store, monkeypatch, update):
    entry = registry.RegistryEntry(descriptor())
    if update:
        store.publish(entry, expected_revision=0)
        entry = replace(entry, revision=2, state="STOPPED")
    original_lock = store._lock

    @contextmanager
    def late_failure():
        with original_lock() as verify:
            yield verify
            raise registry.RegistryError("REGISTRY_LOCK_UNVERIFIED")

    monkeypatch.setattr(store, "_lock", late_failure)
    with pytest.raises(registry.RegistryError, match="^REGISTRY_PUBLICATION_UNCONFIRMED$"):
        store.publish(entry, expected_revision=1 if update else 0)
    destination = store.root / (entry.descriptor.instance_id + ".json")
    assert destination.stat().st_nlink == 1
    assert json.loads(destination.read_bytes()) == entry.to_dict()
    assert not tuple(store.root.glob(".pending-*"))
    assert store.read().entries == (entry,)
