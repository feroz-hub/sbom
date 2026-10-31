"""Only typed diagnostic metadata crosses adapters; no service or app I/O."""

import json

import pytest
from scripts import dev
from scripts import dev_workspace_readiness as readiness
from scripts import dev_workspace_runtime as runtime

from tests.test_dev_workspace_runtime import instance as instance
from tests.test_dev_workspace_runtime import start


def test_readiness_diagnosis_survives_verified_startup_cleanup(instance):
    def failed(_spec, _timeout):
        raise readiness.ReadinessError("LISTENER_PROBE_CLEANUP_UNCONFIRMED", winerror=5, probe_pid=123)

    result = start(instance, probes={"Frontend": failed})
    assert result.code == "LISTENER_PROBE_CLEANUP_UNCONFIRMED"
    assert result.winerror == 5 and result.probe_pid == 123
    assert result.component == "Frontend" and not result.ready
    assert not result.records_retained and ("verified-stop", 100) in instance.events


def test_arbitrary_error_cannot_supply_diagnostic_or_helper_identity(instance):
    class Untrusted(ValueError):
        code = "LISTENER_PROBE_CLEANUP_UNCONFIRMED"
        winerror = 5
        probe_pid = 123

    def failed(_spec, _timeout):
        raise Untrusted("private connection string must never appear")

    result = start(instance, probes={"Frontend": failed})
    assert result.code == "INSTANCE_READINESS_PROBE_FAILED"
    assert result.winerror is result.probe_pid is None
    assert "connection string" not in json.dumps(result.to_dict())


@pytest.mark.parametrize("code", [None, True, -1, 2**32, "credential"])
def test_windows_inspection_error_has_only_safe_numeric_metadata(code):
    error = dev._windows_error(99, "OpenProcess", code)
    assert error.winerror is None and error.operation == "OpenProcess"
    assert error.process_status == "UNKNOWN" and "credential" not in str(error)


def test_windows_double_inspection_failure_preserves_primary_code(monkeypatch):
    def failed(*_args):
        raise dev._windows_error(99, "WaitForSingleObject", 6)

    monkeypatch.setattr(dev, "_windows_exited", failed)
    with pytest.raises(dev.OwnershipError) as caught:
        dev._windows_query_failed(None, None, 99, "GetProcessTimes", 5)
    assert caught.value.winerror == 5 and caught.value.secondary_winerror == 6


def test_invalid_runtime_metadata_is_redacted_at_public_serialization():
    public = runtime.RuntimeOutcome("INSTANCE_START_FAILED", 1, winerror=True, probe_pid="credential").to_dict()
    assert public["winerror"] is public["probe_pid"] is None
