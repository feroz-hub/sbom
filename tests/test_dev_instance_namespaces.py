"""Pure resource names only; --noconftest, no settings/application/DB startup."""

from __future__ import annotations

import builtins
import os
import socket
import subprocess
import sys
import traceback
import types
from dataclasses import FrozenInstanceError
from pathlib import Path
from uuid import UUID

import pytest
from app import dev_instance as namespaces
from scripts import dev_instance_plan as plans

RESOURCE = "SBOM_DEV_RESOURCE_ID"
FIRST = "f8cf338c-4696-5862-b36d-989ad012ac79"
SECOND = "bb1c44d6-283e-548d-936e-0b42c29651cf"
SECRET = "fixture-private-namespace-input-never-print"
FIELDS = (
    "queue_default",
    "queue_reports",
    "beat_namespace",
    "session_namespace",
    "rate_limit_namespace",
    "mail_worker_heartbeat",
    "native_rate_limit_bucket",
    "native_account_rate_limit_bucket",
)


def snapshot(value):
    return {name: getattr(value, name) for name in FIELDS}


def test_absent_resource_id_preserves_every_existing_production_name():
    value = namespaces.get_instance_namespace({})
    assert value.resource_id is None
    assert snapshot(value) == {
        "queue_default": "celery",
        "queue_reports": "reports",
        "beat_namespace": "sbom:dev:beat",
        "session_namespace": "sbom:bff:",
        "rate_limit_namespace": "",
        "mail_worker_heartbeat": "sbom:iam:mail-worker",
        "native_rate_limit_bucket": "native",
        "native_account_rate_limit_bucket": "native-account",
    }


def test_ambient_lookup_is_read_only_and_does_not_consume_runtime_launch_generation(monkeypatch):
    environment = {RESOURCE: FIRST, "SBOM_DEV_INSTANCE": SECOND, "PRIVATE_FIXTURE": SECRET}
    monkeypatch.setattr(os, "environ", environment)
    before = dict(environment)
    value = namespaces.get_instance_namespace()
    assert value.resource_id == FIRST and environment == before
    assert namespaces.get_instance_namespace({"SBOM_DEV_INSTANCE": FIRST}).resource_id is None
    assert snapshot(namespaces.get_instance_namespace({"SBOM_DEV_INSTANCE": SECRET})) == snapshot(
        namespaces.InstanceNamespace()
    )


def test_explicit_map_never_reads_other_environment_values_or_an_ambient_selection(monkeypatch):
    requested = []

    class SelectedValueOnly(dict):
        def __getitem__(self, name):
            requested.append(name)
            assert name == RESOURCE
            return super().__getitem__(name)

    supplied = SelectedValueOnly({RESOURCE: FIRST, "DATABASE_URL": SECRET, "NATIVE_JWT_PRIVATE_KEY": SECRET})
    monkeypatch.setattr(os, "environ", {RESOURCE: SECOND})
    assert namespaces.get_instance_namespace(supplied).resource_id == FIRST
    assert requested == [RESOURCE]
    assert namespaces.get_instance_namespace({}).resource_id is None


def test_two_instances_have_distinct_resource_names_and_match_public_planner_proposals():
    first = plans.plan_instance(
        repository_id="a" * 64, worktree_id="b" * 64, commit="c" * 40, generation=1, mode="isolated", auth_mode="native"
    )
    second = plans.plan_instance(
        repository_id="a" * 64, worktree_id="d" * 64, commit="c" * 40, generation=1, mode="isolated", auth_mode="native"
    )
    left = namespaces.get_instance_namespace({RESOURCE: first.descriptor.instance_id})
    right = namespaces.get_instance_namespace({RESOURCE: second.descriptor.instance_id})
    for field in ("queue_default", "queue_reports", "beat_namespace", "session_namespace", "rate_limit_namespace"):
        assert getattr(left, field) == first.descriptor.resources[field]
        assert getattr(right, field) == second.descriptor.resources[field]
    assert all(getattr(left, name) != getattr(right, name) for name in FIELDS)
    assert left.mail_worker_heartbeat == left.rate_limit_namespace + "mail-worker"
    assert left.native_rate_limit_bucket == left.rate_limit_namespace + "native"
    assert left.native_account_rate_limit_bucket == left.rate_limit_namespace + "native-account"


def test_namespace_is_an_immutable_snapshot_and_explicit_resource_drift_requires_a_new_snapshot():
    environment = {RESOURCE: FIRST, "SBOM_DEV_INSTANCE": "launch-one"}
    previous = namespaces.get_instance_namespace(environment)
    before = snapshot(previous)
    environment["SBOM_DEV_INSTANCE"] = "launch-two"
    assert namespaces.get_instance_namespace(environment) == previous
    environment[RESOURCE] = SECOND
    current = namespaces.get_instance_namespace(environment)
    assert snapshot(previous) == before and current != previous
    environment[RESOURCE] = SECRET
    with pytest.raises(namespaces.InstanceNamespaceError):
        namespaces.get_instance_namespace(environment)
    assert snapshot(previous) == before
    with pytest.raises(FrozenInstanceError):
        previous.resource_id = SECOND


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        FIRST.upper(),
        FIRST.replace("-", ""),
        "{" + FIRST + "}",
        "urn:uuid:" + FIRST,
        FIRST + "\n",
        " " + FIRST,
        "https://user:" + SECRET + "@localhost/",
        SECRET,
        "-----BEGIN PRIVATE KEY-----",
        True,
        1,
        UUID(FIRST),
        [],
        {},
    ],
)
def test_invalid_explicit_resource_id_refuses_without_fallback_or_private_output(value):
    with pytest.raises(namespaces.InstanceNamespaceError, match="^DEV_INSTANCE_RESOURCE_ID_INVALID$") as caught:
        namespaces.get_instance_namespace({RESOURCE: value})
    assert SECRET not in str(caught.value) + repr(caught.value)
    with pytest.raises(namespaces.InstanceNamespaceError, match="^DEV_INSTANCE_RESOURCE_ID_INVALID$"):
        namespaces.InstanceNamespace(value)


def test_explicit_null_is_invalid_but_constructor_none_represents_absence():
    assert namespaces.InstanceNamespace(None).resource_id is None
    with pytest.raises(namespaces.InstanceNamespaceError, match="^DEV_INSTANCE_RESOURCE_ID_INVALID$"):
        namespaces.get_instance_namespace({RESOURCE: None})


@pytest.mark.parametrize("alias", ["sbom_dev_resource_id", "Sbom_Dev_Resource_Id"])
@pytest.mark.parametrize("canonical_present", [False, True])
def test_case_variant_resource_selection_never_silently_uses_default_names(alias, canonical_present):
    environment = {alias: FIRST}
    if canonical_present:
        environment[RESOURCE] = FIRST
    with pytest.raises(namespaces.InstanceNamespaceError, match="^DEV_INSTANCE_RESOURCE_ID_INVALID$"):
        namespaces.get_instance_namespace(environment)


def test_string_subclasses_cannot_retain_private_representations():
    class PrivateString(str):
        def __repr__(self):
            return SECRET

    with pytest.raises(namespaces.InstanceNamespaceError) as caught:
        namespaces.InstanceNamespace(PrivateString(FIRST))
    assert SECRET not in str(caught.value) + repr(caught.value)
    with pytest.raises(namespaces.InstanceNamespaceError):
        namespaces.get_instance_namespace({PrivateString(RESOURCE): FIRST})


@pytest.mark.parametrize("environment", [False, [], SECRET])
def test_nonmapping_environment_is_a_fixed_safe_configuration_error(environment):
    with pytest.raises(namespaces.InstanceNamespaceError, match="^DEV_INSTANCE_ENVIRONMENT_UNVERIFIED$"):
        namespaces.get_instance_namespace(environment)


def test_mapping_failure_is_redacted_in_the_printable_exception_chain():
    class UnverifiableMapping(dict):
        def __iter__(self):
            raise RuntimeError(SECRET)

    with pytest.raises(namespaces.InstanceNamespaceError) as caught:
        namespaces.get_instance_namespace(UnverifiableMapping())
    assert caught.value.code == "DEV_INSTANCE_ENVIRONMENT_UNVERIFIED"
    assert SECRET not in "".join(traceback.format_exception(caught.type, caught.value, caught.tb))
    assert str(namespaces.InstanceNamespaceError(SECRET)) == "DEV_INSTANCE_RESOURCE_ID_INVALID"


def test_fresh_helper_module_and_explicit_snapshots_have_no_io_or_application_imports(monkeypatch):
    source = Path(namespaces.__file__).read_text(encoding="utf-8")
    compiled = compile(source, "<pure-instance-namespace-fixture>", "exec")
    fixture = types.ModuleType("sbo101_namespace_fixture")
    monkeypatch.setitem(sys.modules, fixture.__name__, fixture)

    def forbidden(*arguments, **keywords):
        raise AssertionError("Namespace helper attempted an external side effect")

    class NoEnvironment(dict):
        __iter__ = __getitem__ = __contains__ = get = items = copy = forbidden

    original_import = builtins.__import__

    def guarded_import(name, *arguments, **keywords):
        assert name.split(".", 1)[0] not in {"app", "sqlalchemy", "psycopg", "celery"}
        return original_import(name, *arguments, **keywords)

    with monkeypatch.context() as guarded:
        guarded.setattr(os, "environ", NoEnvironment())
        guarded.setattr(os, "getenv", forbidden)
        guarded.setattr(os, "open", forbidden)
        guarded.setattr(builtins, "open", forbidden)
        for method in ("open", "read_bytes", "read_text", "write_bytes", "write_text", "mkdir", "exists", "stat"):
            guarded.setattr(Path, method, forbidden)
        guarded.setattr(socket, "socket", forbidden)
        guarded.setattr(socket, "create_connection", forbidden)
        guarded.setattr(subprocess, "Popen", forbidden)
        guarded.setattr(subprocess, "run", forbidden)
        guarded.setattr(builtins, "__import__", guarded_import)
        exec(compiled, fixture.__dict__)
        assert fixture.get_instance_namespace({}).queue_default == "celery"
        assert (
            fixture.get_instance_namespace({RESOURCE: FIRST}).queue_reports
            == namespaces.InstanceNamespace(FIRST).queue_reports
        )
