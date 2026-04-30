"""Unit tests for app.validation.errors — code table, ErrorReport contract."""

from __future__ import annotations

import pytest
from app.validation import errors as E
from app.validation.errors import ErrorReport, Severity


def test_every_constant_is_in_code_table() -> None:
    """Every public ``E*``/``W*``/``I*`` constant must have a status mapping."""
    constants = [name for name in dir(E) if name[0] in {"E", "W", "I"} and "_" in name and name[1:4].isdigit()]
    assert constants, "no error-code constants found"
    for name in constants:
        code = getattr(E, name)
        assert code in E._CODE_TABLE, f"{name}={code!r} missing from _CODE_TABLE"


def test_status_priority_ordering() -> None:
    """413 must beat 415, 415 must beat 422, 422 must beat 400."""
    assert E._STATUS_PRIORITY[413] > E._STATUS_PRIORITY[415]
    assert E._STATUS_PRIORITY[415] > E._STATUS_PRIORITY[422]
    assert E._STATUS_PRIORITY[422] > E._STATUS_PRIORITY[400]


def test_report_truncates_after_100_entries() -> None:
    report = ErrorReport()
    for i in range(120):
        report.add(
            E.E025_SCHEMA_VIOLATION,
            stage="schema",
            path=f"x[{i}]",
            message=f"m{i}",
            remediation="r",
        )
    assert len(report.entries) == E.MAX_ENTRIES
    assert report.truncated is True


def test_report_http_status_picks_highest_priority() -> None:
    report = ErrorReport()
    report.add(E.E025_SCHEMA_VIOLATION, stage="schema", path="", message="m", remediation="r")  # 422
    report.add(E.E001_SIZE_EXCEEDED, stage="ingress", path="", message="m", remediation="r")  # 413
    report.add(E.E020_JSON_PARSE_FAILED, stage="schema", path="", message="m", remediation="r")  # 400
    assert report.http_status == 413


def test_report_http_status_202_when_no_errors() -> None:
    report = ErrorReport()
    report.add(
        E.W074_DEPENDENCY_CYCLE_DETECTED,
        stage="integrity",
        path="",
        message="m",
        remediation="r",
    )
    assert report.has_errors() is False
    assert report.http_status == 202


def test_report_partitions_severity() -> None:
    report = ErrorReport()
    report.add(E.E025_SCHEMA_VIOLATION, stage="schema", path="", message="m", remediation="r")
    report.add(E.W074_DEPENDENCY_CYCLE_DETECTED, stage="integrity", path="", message="m", remediation="r")
    report.add(E.I075_ORPHAN_COMPONENT, stage="integrity", path="", message="m", remediation="r")
    assert len(report.errors) == 1
    assert len(report.warnings) == 1
    assert len(report.info) == 1
    assert all(isinstance(e.severity, Severity) for e in report.entries)


def test_report_explicit_severity_overrides_default() -> None:
    """NTIA strict mode promotes warnings to errors via the ``severity`` param."""
    report = ErrorReport()
    report.add(
        E.W100_NTIA_SUPPLIER_MISSING,
        stage="ntia",
        path="",
        message="m",
        remediation="r",
        severity=Severity.ERROR,
    )
    assert report.has_errors() is True
    assert report.http_status == 422


def test_status_for_unknown_raises() -> None:
    with pytest.raises(KeyError):
        E.status_for("SBOM_VAL_E999_UNKNOWN")


def test_to_dict_shape() -> None:
    report = ErrorReport()
    report.add(E.E001_SIZE_EXCEEDED, stage="ingress", path="", message="m", remediation="r")
    payload = report.to_dict()
    assert set(payload.keys()) == {"entries", "truncated"}
    assert payload["truncated"] is False
    entry = payload["entries"][0]
    assert set(entry.keys()) == {"code", "severity", "stage", "path", "message", "remediation", "spec_reference"}
