from __future__ import annotations

import asyncio
import logging
from dataclasses import replace
from typing import Any

import pytest
import requests

from app.analysis import get_analysis_settings_multi, nvd_query_by_components_async


LOG4J_CPE = "cpe:2.3:a:apache:log4j:3.0.0:*:*:*:*:*:*:*"
LOG4J_CRITERIA = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"


def _settings(*, detail_logging: bool = True):
    return replace(get_analysis_settings_multi(), nvd_rejection_detail_logging=detail_logging)


def _component(*, version: str | None = "3.0.0", cpe: str = LOG4J_CPE) -> dict[str, Any]:
    return {
        "name": "log4j-core",
        "version": version,
        "cpe": cpe,
        "ecosystem": "Maven",
    }


def _raw_cve(
    cve_id: str,
    *,
    criteria: str = LOG4J_CRITERIA,
    version_end_excluding: str | None = "2.17.0",
    status: str = "Analyzed",
) -> dict[str, Any]:
    match: dict[str, Any] = {
        "vulnerable": True,
        "criteria": criteria,
    }
    if version_end_excluding is not None:
        match["versionEndExcluding"] = version_end_excluding
    return {
        "id": cve_id,
        "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
        "references": [],
        "metrics": {},
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [match]}]}],
    }


def _run(
    components: list[dict[str, Any]],
    raw_records: list[Any],
    *,
    caplog: pytest.LogCaptureFixture,
    detail_logging: bool = True,
):
    def fake_lookup(cpe: str, api_key: str | None, settings: Any) -> list[Any]:
        return list(raw_records)

    with caplog.at_level(logging.DEBUG):
        return asyncio.run(
            nvd_query_by_components_async(
                components,
                _settings(detail_logging=detail_logging),
                nvd_api_key="test-key",
                lookup_service=fake_lookup,
            )
        )


def _summary_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == "sbom.nvd" and r.getMessage() == "nvd.findings_rejection_summary"]


def _debug_rejections(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.name == "sbom.nvd"
        and r.getMessage() == "nvd.finding_rejected"
        and r.levelno == logging.DEBUG
    ]


def test_rejection_summary_counts_stable_reason_codes(caplog: pytest.LogCaptureFixture) -> None:
    cpe_mismatch = _raw_cve(
        "CVE-2099-0002",
        criteria="cpe:2.3:a:other:package:*:*:*:*:*:*:*:*",
    )
    accepted = _raw_cve("CVE-2099-0003", version_end_excluding="9.0.0")
    duplicate = _raw_cve("CVE-2099-0003", version_end_excluding="9.0.0")

    findings, errors, warnings = _run(
        [_component()],
        [
            _raw_cve("CVE-2099-0001"),
            cpe_mismatch,
            accepted,
            duplicate,
        ],
        caplog=caplog,
    )

    assert errors == []
    assert len(findings) == 1
    summary = _summary_records(caplog)[0]
    assert summary.total_rejected == 3
    assert summary.by_reason == {
        "cpe_mismatch": 1,
        "duplicate_finding": 1,
        "version_not_affected": 1,
    }
    assert summary.total_rejected == sum(summary.by_reason.values())
    assert summary.accepted_findings + summary.total_rejected == summary.candidate_findings
    assert warnings[0]["rejection_summary"]["by_reason"] == summary.by_reason


def test_missing_version_increments_missing_component_version(caplog: pytest.LogCaptureFixture) -> None:
    _run([_component(version=None)], [_raw_cve("CVE-2099-0004")], caplog=caplog)

    summary = _summary_records(caplog)[0]
    assert summary.by_reason == {"missing_component_version": 1}
    assert summary.accepted_findings == 0
    assert summary.candidate_findings == 1


def test_individual_rejection_logs_are_debug_only(caplog: pytest.LogCaptureFixture) -> None:
    _run([_component()], [_raw_cve("CVE-2099-0005")], caplog=caplog)

    debug_records = _debug_rejections(caplog)
    assert len(debug_records) == 1
    assert debug_records[0].reason == "version_not_affected"
    assert not [
        r
        for r in caplog.records
        if r.getMessage() == "nvd.finding_rejected" and r.levelno == logging.INFO
    ]


def test_detail_logging_flag_suppresses_individual_debug_logs(caplog: pytest.LogCaptureFixture) -> None:
    _run(
        [_component()],
        [_raw_cve("CVE-2099-0006")],
        caplog=caplog,
        detail_logging=False,
    )

    assert _debug_rejections(caplog) == []
    assert len(_summary_records(caplog)) == 1


def test_zero_rejection_run_still_emits_one_summary(caplog: pytest.LogCaptureFixture) -> None:
    _run(
        [_component()],
        [_raw_cve("CVE-2099-0007", version_end_excluding="9.0.0")],
        caplog=caplog,
    )

    summaries = _summary_records(caplog)
    assert len(summaries) == 1
    assert summaries[0].total_rejected == 0
    assert summaries[0].by_reason == {}
    assert summaries[0].accepted_findings == 1


def test_no_secret_or_authorization_header_in_rejection_logs(caplog: pytest.LogCaptureFixture) -> None:
    raw = _raw_cve("CVE-2099-0008")
    raw["configurations"] = None
    raw["detail"] = "Authorization: Bearer should-not-leak apiKey=also-secret"

    _run([_component()], [raw], caplog=caplog)

    rendered = "\n".join(record.getMessage() + " " + str(record.__dict__) for record in caplog.records)
    assert "should-not-leak" not in rendered
    assert "also-secret" not in rendered


def test_rejected_metric_labels_stay_low_cardinality(caplog: pytest.LogCaptureFixture) -> None:
    _run([_component()], [_raw_cve("CVE-2099-0009")], caplog=caplog)

    rejected_metrics = [
        r
        for r in caplog.records
        if r.name == "sbom.nvd.metrics" and getattr(r, "metric", None) == "nvd.findings_rejected_total"
    ]
    assert len(rejected_metrics) == 1
    assert set(rejected_metrics[0].labels) == {"reason"}
    assert rejected_metrics[0].labels == {"reason": "version_not_affected"}


def test_multiple_rejections_do_not_produce_repetitive_info_metric_lines(caplog: pytest.LogCaptureFixture) -> None:
    _run(
        [_component()],
        [_raw_cve(f"CVE-2099-{idx:04d}") for idx in range(10, 15)],
        caplog=caplog,
    )

    info_rejected_metrics = [
        r
        for r in caplog.records
        if r.levelno == logging.INFO and r.getMessage() == "nvd.findings_rejected_total"
    ]
    assert info_rejected_metrics == []
    assert len(_summary_records(caplog)) == 1


def test_malformed_nvd_record_logs_warning_with_safe_fields(caplog: pytest.LogCaptureFixture) -> None:
    malformed = _raw_cve("CVE-2099-0015")
    malformed["configurations"] = [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True}]}]}]

    _run([_component()], [malformed], caplog=caplog)

    warnings = [
        r
        for r in caplog.records
        if r.name == "sbom.nvd" and r.getMessage() == "nvd.finding_rejected" and r.levelno == logging.WARNING
    ]
    assert len(warnings) == 1
    assert warnings[0].reason == "invalid_nvd_record"
    assert not hasattr(warnings[0], "raw")


def test_provider_failure_logs_error_separately_from_rejections(caplog: pytest.LogCaptureFixture) -> None:
    def failing_lookup(cpe: str, api_key: str | None, settings: Any) -> list[Any]:
        raise requests.exceptions.SSLError("certificate failed Authorization: Bearer should-not-leak")

    with caplog.at_level(logging.DEBUG):
        findings, errors, warnings = asyncio.run(
            nvd_query_by_components_async(
                [_component()],
                _settings(),
                nvd_api_key="test-key",
                lookup_service=failing_lookup,
            )
        )

    assert findings == []
    assert errors[0]["provider_failed"] is True
    assert warnings[0]["rejection_summary"]["total_rejected"] == 0
    error_records = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(error_records) == 1
    assert "NVD provider failed" in error_records[0].getMessage()
    rendered = "\n".join(record.getMessage() + " " + str(record.__dict__) for record in caplog.records)
    assert "should-not-leak" not in rendered
