"""Synthetic source comparison and private log metadata; no application stack."""

from __future__ import annotations

import builtins
import json
import os
import socket
import subprocess
import sys
import types
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev_instance_plan as plans
from scripts import dev_instance_registry as registry
from scripts import dev_instance_storage as storage
from scripts import dev_private, dev_workspace
from scripts import dev_workspace_observe as observe

INSTANCE = "f8cf338c-4696-5862-b36d-989ad012ac79"
SECRET = "fixture-private-password-never-print"
EMAIL = "private-customer@example.test"


def descriptor(worktree="b" * 64, mode="mock"):
    return plans.plan_instance(
        repository_id="a" * 64, worktree_id=worktree, commit="c" * 40, generation=1, mode=mode, auth_mode="native"
    ).descriptor


def compared():
    identity = dev_workspace.FilesystemIdentity(Path("/fixture/repository"), 1, 1)
    left = dev_workspace.WorktreeSnapshot(
        "b" * 64, Path("/fixture/base"), identity, "c" * 40, "refs/heads/baseline", False, False, False, False, False
    )
    right = replace(left, worktree_id="d" * 64, head="e" * 40, branch="refs/heads/candidate", dirty=True)
    repository = dev_workspace.RepositorySnapshot(
        "a" * 64, Path("/fixture"), identity, "c" * 40, (left, right), identity
    )
    entries = registry.RegistrySnapshot(
        (registry.RegistryEntry(descriptor(), state="READY"), registry.RegistryEntry(descriptor("d" * 64, "isolated")))
    )
    return repository, entries


def test_comparison_distinguishes_source_and_proposals_from_runtime_api_visual_acceptance():
    repository, entries = compared()
    result = observe.compare_workspaces(repository, "b" * 64, "d" * 64, entries)
    assert result.status == "OBSERVED"
    assert set(result.differences) == {
        "COMMIT",
        "BRANCH",
        "DIRTY",
        "MODE",
        "PROPOSED_URLS",
        "PROPOSED_RESOURCES",
        "CANDIDATE_HEAD_DRIFT",
    }
    output = result.to_dict()
    assert output["baseline"]["reported_registry_state"] == "READY"
    assert output["candidate"]["registered_head_drift"] is True
    assert output["candidate"]["proposed_urls"]["api"].startswith("http://127.0.0.1:")
    assert all(
        output[key] is False for key in ("runtime_verified", "api_verified", "visual_verified", "acceptance_verified")
    )
    assert output["baseline"]["runtime_verified"] is False
    assert "/fixture" not in json.dumps(output)


def test_known_absent_registry_still_allows_source_comparison_with_explicit_missing_metadata():
    repository, _ = compared()
    result = observe.compare_workspaces(
        repository, "b" * 64, "d" * 64, registry.RegistrySnapshot(codes=("REGISTRY_MISSING",))
    )
    assert result.status == "OBSERVED" and result.codes == ("COMPARISON_REGISTRY_ENTRY_MISSING",)
    assert result.baseline.to_dict()["mode"] is None


@pytest.mark.parametrize("changed", ["repository", "target", "same", "registry", "branch", "unknown-flags"])
def test_unknown_or_unlisted_comparison_inputs_remain_blocked_without_arbitrary_values(changed):
    repository, entries = compared()
    baseline, candidate = "b" * 64, "d" * 64
    if changed == "repository":
        repository = replace(repository, status="BLOCKED")
    elif changed == "target":
        candidate = SECRET
    elif changed == "same":
        candidate = baseline
    elif changed == "registry":
        entries = registry.RegistrySnapshot(codes=("REGISTRY_UNKNOWN_ARTIFACT",))
    else:
        selected = repository.worktrees[1]
        selected = (
            replace(selected, branch=SECRET + "@" + EMAIL) if changed == "branch" else replace(selected, bare=None)
        )
        repository = replace(repository, worktrees=(repository.worktrees[0], selected))
    result = observe.compare_workspaces(repository, baseline, candidate, entries)
    assert result.status == "BLOCKED"
    assert SECRET not in repr(result) + json.dumps(result.to_dict())


@pytest.mark.parametrize("mode", ["isolated", "mock", "shared-backend"])
def test_diagnostics_have_no_self_claimed_ready_or_service_acceptance(mode):
    output = observe.diagnose_instance(descriptor(mode=mode)).to_dict()
    assert {row["category"] for row in output["results"]} == {
        "dependencies",
        "configuration",
        "providers",
        "database",
        "authentication",
        "tls",
        "workers",
        "process_ownership",
        "health",
    }
    assert all(row["status"] in {"BLOCKED", "SKIPPED"} for row in output["results"])
    assert output["runtime_verified"] is output["acceptance_verified"] is False
    assert output["host"] == {}
    assert output["results"][0] == {
        "category": "dependencies",
        "status": "BLOCKED",
        "code": "INSTANCE_DEPENDENCY_READ_ADAPTER_REQUIRED",
    }


def test_unregistered_diagnostics_require_metadata_without_fabricating_a_descriptor(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Unregistered diagnostics fabricated metadata or probed a service"))
    with monkeypatch.context() as guarded:
        guarded.setattr(plans, "InstanceDescriptor", forbidden)
        guarded.setattr(plans, "plan_instance", forbidden)
        guarded.setattr(observe, "diagnose_instance", forbidden)
        guarded.setattr(os, "cpu_count", forbidden)
        guarded.setattr(observe.shutil, "disk_usage", forbidden)
        output = observe.diagnose_unregistered().to_dict()
    assert len(output["results"]) == 9
    assert all(row["status"] == "BLOCKED" and row["code"] == "INSTANCE_METADATA_REQUIRED" for row in output["results"])
    assert output["host"] == {}
    assert all(
        output[key] is False for key in ("runtime_verified", "api_verified", "visual_verified", "acceptance_verified")
    )
    forbidden.assert_not_called()


@pytest.mark.parametrize("include_host", [None, 1, "true", SECRET])
def test_unregistered_diagnostic_options_are_strict_and_redacted(include_host):
    with pytest.raises(observe.ObservationError) as caught:
        observe.diagnose_unregistered(include_host=include_host)
    assert str(caught.value) == "INSTANCE_OBSERVATION_INVALID"
    assert SECRET not in repr(caught.value)


@pytest.fixture
def private_logs(tmp_path):
    home = tmp_path.resolve() / "private-home"
    if sys.platform == "win32":
        storage._windows_create(home)  # New synthetic home only; no permission repair.
    else:
        home.mkdir(mode=0o700)
    directory = home / ".sbom-dev" / "instances" / INSTANCE / ".dev-logs"
    storage.initialize_private_directory(directory, anchor=home)
    return home, directory


def write_log(private_logs, content, filename="api.log"):
    path = private_logs[1] / filename
    dev_private.create_private_file(path, content if isinstance(content, bytes) else content.encode("utf-8"))
    return path


@pytest.mark.parametrize("present", [False, True])
def test_setup_log_uses_only_its_fixed_path_and_missing_file_is_not_created(private_logs, monkeypatch, present):
    path = private_logs[1] / "setup.log"
    if present:
        write_log(
            private_logs, "2026-10-31T10:20:30Z ERROR exception_class=OSError winerror=5 " + SECRET + "\n", "setup.log"
        )
    before = tuple(private_logs[1].iterdir())
    forbidden = Mock(side_effect=AssertionError("Setup log observation attempted a write"))
    with monkeypatch.context() as guarded:
        guarded.setattr(dev_private, "create_private_file", forbidden)
        guarded.setattr(os, "mkdir", forbidden)
        result = observe.observe_logs(INSTANCE, "setup", home=private_logs[0])
    assert result.status == ("OBSERVED" if present else "SKIPPED")
    assert result.local_path == (path if present else None)
    assert path.exists() is present and tuple(private_logs[1].iterdir()) == before
    assert SECRET not in repr(result) + json.dumps(result.to_dict())
    if present:
        assert result.records[0].exception_class == "OSError"
    else:
        assert result.code == "INSTANCE_LOG_MISSING" and result.records == ()
    forbidden.assert_not_called()


@pytest.mark.parametrize("registered", [False, True])
def test_optional_host_capacity_is_read_only_and_separate_from_component_health(private_logs, monkeypatch, registered):
    home, _ = private_logs
    proposed = descriptor()
    monkeypatch.setattr(os, "cpu_count", lambda: 8)
    monkeypatch.setattr(observe.shutil, "disk_usage", lambda root: SimpleNamespace(total=100000, free=50000))
    before = tuple(home.iterdir())
    forbidden = Mock(side_effect=AssertionError("Host capacity attempted a mutating or service operation"))
    with monkeypatch.context() as guarded:
        guarded.setattr(os, "open", forbidden)
        guarded.setattr(os, "mkdir", forbidden)
        guarded.setattr(dev_private, "create_private_file", forbidden)
        guarded.setattr(subprocess, "Popen", forbidden)
        guarded.setattr(subprocess, "run", forbidden)
        guarded.setattr(socket, "socket", forbidden)
        guarded.setattr(socket, "create_connection", forbidden)
        result = (
            observe.diagnose_instance(proposed, include_host=True, home=home)
            if registered
            else observe.diagnose_unregistered(include_host=True, home=home)
        )
    assert dict(result.host) == {"cpu_count": 8, "disk_total": 100000, "disk_free": 50000}
    assert result.results[-1] == ("host", "OBSERVED", "HOST_CAPACITY_OBSERVED")
    assert tuple(home.iterdir()) == before
    assert result.to_dict()["acceptance_verified"] is False
    assert "memory" not in json.dumps(result.to_dict()).lower()
    assert "fit" not in json.dumps(result.to_dict()).lower()
    forbidden.assert_not_called()


@pytest.mark.parametrize("registered", [False, True])
def test_host_capacity_failures_reveal_no_private_path_or_exception(private_logs, monkeypatch, registered):
    home, _ = private_logs
    monkeypatch.setattr(observe.shutil, "disk_usage", Mock(side_effect=OSError(SECRET + "@" + EMAIL)))
    result = (
        observe.diagnose_instance(descriptor(), include_host=True, home=home)
        if registered
        else observe.diagnose_unregistered(include_host=True, home=home)
    )
    assert result.results[-1] == ("host", "BLOCKED", "HOST_CAPACITY_UNVERIFIED")
    assert dict(result.host) == {}
    serialized = repr(result) + json.dumps(result.to_dict())
    assert SECRET not in serialized and EMAIL not in serialized and str(home) not in serialized


def test_log_projection_exposes_only_allowlisted_metadata_not_message_content(private_logs):
    path = write_log(
        private_logs,
        f"2026-10-31T10:20:30Z ERROR exception_class=PermissionError winerror=5 status=UNKNOWN user={EMAIL} DATABASE_URL=postgresql://user:{SECRET}@localhost/private\n"
        + json.dumps(
            {
                "timestamp": "2026-10-31 10:20:31",
                "level": "INFO",
                "exception_class": "TimeoutError",
                "winerror": 1460,
                "status": "STOPPED",
                "message": SECRET,
                "customer": EMAIL,
                "private_key": SECRET,
            }
        )
        + "\n",
    )
    result = observe.observe_logs(INSTANCE, "api", home=private_logs[0])
    assert result.status == "OBSERVED" and result.local_path == path, result.code
    assert [record.to_dict() for record in result.records] == [
        {
            "timestamp": "2026-10-31T10:20:30Z",
            "level": "ERROR",
            "exception_class": "PermissionError",
            "winerror": 5,
            "reported_status": "UNKNOWN",
        },
        {
            "timestamp": "2026-10-31T10:20:31",
            "level": "INFO",
            "exception_class": "TimeoutError",
            "winerror": 1460,
            "reported_status": "STOPPED",
        },
    ]
    output = json.dumps(result.to_dict()) + repr(result)
    assert SECRET not in output and EMAIL not in output and "postgresql://" not in output
    assert str(path) not in json.dumps(result.to_dict())
    assert result.to_dict()["runtime_verified"] is False
    assert "Open the verified local log" in result.to_dict()["content_guidance"]


def test_real_private_log_read_has_mutation_network_process_and_application_tripwires(private_logs, monkeypatch):
    path = write_log(private_logs, "2026-10-31T10:20:30Z ERROR exception_class=OSError winerror=5 " + SECRET + "\n")
    original_open, original_import = os.open, builtins.__import__
    forbidden = Mock(side_effect=AssertionError("Read-only log projection attempted an unrelated operation"))

    def read_only_open(target, flags, *arguments, **keywords):
        assert target == path
        assert not flags & (os.O_CREAT | os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_TRUNC)
        return original_open(target, flags, *arguments, **keywords)

    def guarded_import(name, *arguments, **keywords):
        assert name.split(".", 1)[0] not in {"app", "dotenv", "psycopg", "sqlalchemy", "celery"}
        return original_import(name, *arguments, **keywords)

    with monkeypatch.context() as guarded:
        guarded.setattr(os, "open", read_only_open)
        for name in ("mkdir", "replace", "unlink", "rmdir"):
            guarded.setattr(os, name, forbidden)
        guarded.setattr(dev_private, "create_private_file", forbidden)
        guarded.setattr(storage, "initialize_private_directory", forbidden)
        guarded.setattr(storage, "_windows_create", forbidden)
        guarded.setattr(subprocess, "run", forbidden)
        guarded.setattr(subprocess, "Popen", forbidden)
        guarded.setattr(socket, "socket", forbidden)
        guarded.setattr(socket, "create_connection", forbidden)
        guarded.setattr(builtins, "__import__", guarded_import)
        result = observe.observe_logs(INSTANCE, "api", home=private_logs[0])
    assert result.status == "OBSERVED" and result.records[0].winerror == 5
    assert SECRET not in json.dumps(result.to_dict())
    forbidden.assert_not_called()


def test_unrecognized_message_fields_exception_names_numbers_and_ready_are_not_projected(private_logs):
    write_log(
        private_logs,
        json.dumps(
            {
                "timestamp": SECRET,
                "level": SECRET,
                "exception_class": "CustomerAliceError",
                "winerror": 987654321,
                "status": "READY",
                "message": EMAIL,
                "connection_string": SECRET,
            }
        )
        + "\n"
        + SECRET,
    )
    result = observe.observe_logs(INSTANCE, "api", home=private_logs[0])
    assert result.status == "OBSERVED" and result.records == ()
    assert SECRET not in json.dumps(result.to_dict())


@pytest.mark.parametrize("extra", [0, 10])
def test_bounded_tail_preserves_exact_line_boundaries_and_discards_partial_first_lines(
    private_logs, monkeypatch, extra
):
    last = b"2026-10-31T10:20:30Z ERROR exception_class=OSError winerror=87 status=UNKNOWN\n"
    write_log(private_logs, (SECRET.encode() * 5000) + b"\n" + last)
    original_read, reads = os.read, []

    def read(fd, count):
        value = original_read(fd, count)
        reads.append(len(value))
        return value

    monkeypatch.setattr(os, "read", read)
    limit = len(last) + extra
    result = observe.observe_logs(INSTANCE, "api", home=private_logs[0], max_bytes=limit, max_lines=1)
    assert result.status == "OBSERVED" and len(result.records) == 1
    assert sum(reads) <= limit + 1
    assert result.records[0].winerror == 87


def test_missing_log_is_skipped_without_directory_or_lock_creation(tmp_path, monkeypatch):
    home = tmp_path.resolve() / "private-empty-home"
    if sys.platform == "win32":
        storage._windows_create(home)
    else:
        home.mkdir(mode=0o700)
    forbidden = Mock(side_effect=AssertionError("Log observation attempted mutation"))
    monkeypatch.setattr(os, "mkdir", forbidden)
    monkeypatch.setattr(dev_private, "create_private_file", forbidden)
    assert observe.observe_logs(INSTANCE, "api", home=home).status == "SKIPPED"
    assert not (home / ".sbom-dev").exists()
    forbidden.assert_not_called()


@pytest.mark.parametrize("component", ["postgres", "redis", "mailpit"])
def test_provider_log_requests_never_run_engine_or_read_local_files(component, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Provider logs attempted a command or file read"))
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    result = observe.observe_logs(INSTANCE, component)
    assert result.status == "BLOCKED" and result.code == "INSTANCE_PROVIDER_LOG_ADAPTER_REQUIRED"
    forbidden.assert_not_called()


def test_file_identity_drift_and_missing_after_open_are_blocked_not_reported_as_absent(private_logs, monkeypatch):
    path = write_log(private_logs, "INFO status=RUNNING " + SECRET)
    original_file = observe._file
    count = 0

    def changed(target):
        nonlocal count
        info = original_file(target)
        count += 1
        if count == 2:
            return SimpleNamespace(
                st_dev=info.st_dev,
                st_ino=info.st_ino + 1,
                st_size=info.st_size,
                st_mtime_ns=info.st_mtime_ns,
                st_ctime_ns=info.st_ctime_ns,
            )
        return info

    with monkeypatch.context() as guarded:
        guarded.setattr(observe, "_file", changed)
        result = observe.observe_logs(INSTANCE, "api", home=private_logs[0])
    assert result.status == "BLOCKED" and result.code == "INSTANCE_LOG_CHANGED" and not result.records
    with monkeypatch.context() as guarded:
        guarded.setattr(os, "read", Mock(side_effect=FileNotFoundError(SECRET)))
        result = observe.observe_logs(INSTANCE, "api", home=private_logs[0])
    assert result.status == "BLOCKED" and result.code == "INSTANCE_LOG_CHANGED"
    assert path.read_text() == "INFO status=RUNNING " + SECRET


@pytest.mark.parametrize("changed_handle", [False, True])
def test_native_cross_api_ctime_difference_is_allowed_but_handle_drift_is_blocked(
    private_logs, monkeypatch, changed_handle
):
    path = write_log(private_logs, "INFO status=STOPPED\n")
    before = observe._file(path)
    original_fstat, calls = os.fstat, 0

    def fstat(fd):
        nonlocal calls
        info = original_fstat(fd)
        calls += 1
        return SimpleNamespace(
            st_dev=info.st_dev,
            st_ino=info.st_ino,
            st_size=info.st_size,
            st_mode=info.st_mode,
            st_nlink=info.st_nlink,
            st_mtime_ns=info.st_mtime_ns,
            st_ctime_ns=before.st_ctime_ns + 1000000 + int(changed_handle and calls > 1),
        )

    with monkeypatch.context() as guarded:
        guarded.setattr(os, "fstat", fstat)
        result = observe.observe_logs(INSTANCE, "api", home=private_logs[0])
    if changed_handle:
        assert result.status == "BLOCKED" and result.code == "INSTANCE_LOG_CHANGED" and not result.records
    else:
        assert result.status == "OBSERVED" and result.records[0].reported_status == "STOPPED"


def test_unknown_parent_or_acl_is_protected_and_no_content_is_relayed(private_logs, monkeypatch):
    path = write_log(private_logs, "ERROR " + SECRET)
    original_verify = storage._verify

    def unverified(target, **kwargs):
        if target == private_logs[1]:
            raise PermissionError(SECRET)
        return original_verify(target, **kwargs)

    monkeypatch.setattr(storage, "_verify", unverified)
    result = observe.observe_logs(INSTANCE, "api", home=private_logs[0])
    assert result.status == "BLOCKED" and result.records == () and result.local_path is None
    assert SECRET not in repr(result) + json.dumps(result.to_dict())
    assert path.read_text() == "ERROR " + SECRET


def test_hardlinked_log_is_preserved_and_never_read(private_logs, monkeypatch):
    path = write_log(private_logs, "ERROR " + SECRET)
    retained = private_logs[0] / "retained-fixture"
    os.link(path, retained)
    forbidden = Mock(side_effect=AssertionError("Unverified hardlink was opened"))
    monkeypatch.setattr(os, "open", forbidden)
    result = observe.observe_logs(INSTANCE, "api", home=private_logs[0])
    assert result.status == "BLOCKED" and result.code == "INSTANCE_LOG_PATH_UNVERIFIED"
    assert path.stat().st_nlink == retained.stat().st_nlink == 2
    forbidden.assert_not_called()


@pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX permission mode semantics; native ACL verified by successful fixture reads"
)
def test_public_log_permissions_are_refused_without_repair(private_logs):
    path = write_log(private_logs, SECRET)
    path.chmod(0o644)
    result = observe.observe_logs(INSTANCE, "api", home=private_logs[0])
    assert result.status == "BLOCKED" and path.stat().st_mode & 0o777 == 0o644


@pytest.mark.skipif(sys.platform == "win32", reason="No Windows symlink privilege is requested by synthetic tests")
def test_redirected_log_is_not_followed_and_target_is_preserved(private_logs, monkeypatch):
    target = private_logs[0] / "private-target"
    dev_private.create_private_file(target, SECRET.encode())
    link = private_logs[1] / "api.log"
    link.symlink_to(target)
    forbidden = Mock(side_effect=AssertionError("Redirected logfile was opened"))
    monkeypatch.setattr(os, "open", forbidden)
    result = observe.observe_logs(INSTANCE, "api", home=private_logs[0])
    assert result.status == "BLOCKED" and result.code == "INSTANCE_LOG_PATH_UNVERIFIED"
    assert link.is_symlink() and target.read_text() == SECRET
    forbidden.assert_not_called()


@pytest.mark.parametrize("component", ["../.env", "api.log", SECRET])
def test_arbitrary_log_paths_and_components_are_rejected_without_echo(component):
    with pytest.raises(observe.ObservationError, match="^INSTANCE_LOG_COMPONENT_INVALID$") as caught:
        observe.observe_logs(INSTANCE, component)
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize("options", [{"max_bytes": True}, {"max_bytes": 65537}, {"max_lines": 0}, {"max_lines": 201}])
def test_log_limits_are_strict_and_cannot_enable_large_reads(options):
    with pytest.raises(observe.ObservationError, match="^INSTANCE_LOG_LIMIT_INVALID$"):
        observe.observe_logs(INSTANCE, "api", **options)


def test_immutable_dtos_cannot_store_arbitrary_log_messages_or_exception_names():
    record = observe.LogRecord(level="ERROR", exception_class="OSError", winerror=5)
    records = [record]
    report = observe.LogReport(INSTANCE, "api", "OBSERVED", "INSTANCE_LOG_METADATA_OBSERVED", records)
    records.clear()
    assert report.records == (record,)
    with pytest.raises(FrozenInstanceError):
        record.level = "INFO"
    for changes in (
        {"exception_class": SECRET},
        {"winerror": 987654321},
        {"reported_status": "READY"},
        {"level": [SECRET]},
    ):
        with pytest.raises(observe.ObservationError):
            observe.LogRecord(**changes)


def test_pure_comparison_diagnosis_and_provider_logs_do_not_read_files_or_use_process_network_app_apis(monkeypatch):
    source = Path(observe.__file__).read_text(encoding="utf-8")
    compiled = compile(source, "<pure-observation-fixture>", "exec")
    fixture = types.ModuleType("sbo101_observe_fixture")
    fixture.__package__ = "scripts"
    monkeypatch.setitem(sys.modules, fixture.__name__, fixture)
    repository, entries = compared()
    proposed = descriptor()

    def forbidden(*arguments, **keywords):
        raise AssertionError("Pure observation attempted an external operation")

    original_import = builtins.__import__

    def guarded_import(name, *arguments, **keywords):
        assert name.split(".", 1)[0] not in {"app", "dotenv", "sqlalchemy", "psycopg", "celery"}
        return original_import(name, *arguments, **keywords)

    with monkeypatch.context() as guarded:
        guarded.setattr(builtins, "open", forbidden)
        guarded.setattr(os, "open", forbidden)
        guarded.setattr(os, "mkdir", forbidden)
        for method in ("read_text", "read_bytes", "write_text", "write_bytes", "mkdir", "stat", "home"):
            guarded.setattr(Path, method, forbidden)
        guarded.setattr(subprocess, "run", forbidden)
        guarded.setattr(subprocess, "Popen", forbidden)
        guarded.setattr(socket, "socket", forbidden)
        guarded.setattr(socket, "create_connection", forbidden)
        guarded.setattr(builtins, "__import__", guarded_import)
        exec(compiled, fixture.__dict__)
        assert fixture.compare_workspaces(repository, "b" * 64, "d" * 64, entries).status == "OBSERVED"
        assert fixture.diagnose_instance(proposed).to_dict()["acceptance_verified"] is False
        unregistered = fixture.diagnose_unregistered().to_dict()
        assert all(row["code"] == "INSTANCE_METADATA_REQUIRED" for row in unregistered["results"])
        assert unregistered["runtime_verified"] is unregistered["acceptance_verified"] is False
        assert fixture.observe_logs(INSTANCE, "postgres").status == "BLOCKED"
