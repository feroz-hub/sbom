"""Phase 3.2 — JSON → CveRecord mappers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.nvd_mirror.domain.mappers import (
    MalformedCveError,
    map_batch,
    map_cve,
)


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "nvd"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# --- map_batch on recorded fixtures ---------------------------------------


def test_log4j_window_full_mapping() -> None:
    batch = map_batch(_load("cve_log4j_window.json"))
    assert batch.start_index == 0
    assert batch.results_per_page == 2000
    assert batch.total_results == 2
    assert len(batch.records) == 2

    log4j = next(r for r in batch.records if r.cve_id == "CVE-2021-44228")
    assert log4j.vuln_status == "Modified"
    assert log4j.last_modified == datetime(2024, 4, 16, 1, 23, 45, tzinfo=timezone.utc)
    assert log4j.published == datetime(2021, 12, 10, 10, 15, 9, 143000, tzinfo=timezone.utc)
    assert log4j.description_en is not None
    assert "Apache Log4j2" in log4j.description_en

    # CVSS — v3.1 score wins for severity_text but v2 is recorded too.
    assert log4j.score_v31 == 10.0
    assert log4j.score_v2 == 9.3
    assert log4j.score_v40 is None
    assert log4j.severity_text == "CRITICAL"
    assert log4j.vector_string == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

    # Weaknesses → aliases (CWE-* only).
    assert "CWE-502" in log4j.aliases
    assert "CWE-20" in log4j.aliases

    # CPE flattening.
    assert len(log4j.cpe_criteria) == 1
    crit = log4j.cpe_criteria[0]
    assert crit.criteria_stem == "apache:log4j"
    assert crit.vulnerable is True
    assert crit.version_start_including == "2.0.0"
    assert crit.version_end_excluding == "2.17.0"

    # References.
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in log4j.references


def test_log4j_window_includes_rejected_record() -> None:
    batch = map_batch(_load("cve_log4j_window.json"))
    rejected = next(r for r in batch.records if r.cve_id == "CVE-2099-REJECT")
    assert rejected.vuln_status == "Rejected"
    assert rejected.score_v31 is None
    assert rejected.cpe_criteria == ()


def test_empty_window_mapping() -> None:
    batch = map_batch(_load("cve_empty_window.json"))
    assert batch.records == ()
    assert batch.total_results == 0
    assert batch.results_per_page == 2000


def test_v40_only_mapping() -> None:
    batch = map_batch(_load("cve_minimal_v40_only.json"))
    assert len(batch.records) == 1
    rec = batch.records[0]
    assert rec.score_v40 == 9.8
    assert rec.score_v31 is None
    assert rec.severity_text == "CRITICAL"
    assert rec.vector_string is not None and rec.vector_string.startswith("CVSS:4.0")
    assert rec.cpe_criteria[0].criteria_stem == "example:widget"
    # No bounds — exact-criteria CPE.
    assert rec.cpe_criteria[0].version_start_including is None


# --- map_cve edge cases ---------------------------------------------------


def test_map_cve_missing_id_raises() -> None:
    with pytest.raises(MalformedCveError, match="missing 'id'"):
        map_cve(
            {
                "lastModified": "2024-04-16T01:23:45.000",
                "published": "2024-01-01T00:00:00.000",
            }
        )


def test_map_cve_missing_dates_raises() -> None:
    with pytest.raises(MalformedCveError, match="missing required datetime"):
        map_cve({"id": "CVE-X", "published": "2024-01-01T00:00:00.000"})


def test_map_cve_unparseable_date_raises() -> None:
    with pytest.raises(MalformedCveError, match="could not parse datetime"):
        map_cve(
            {
                "id": "CVE-X",
                "lastModified": "yesterday",
                "published": "2024-01-01T00:00:00.000",
            }
        )


def test_map_cve_handles_timezone_suffix() -> None:
    rec = map_cve(
        {
            "id": "CVE-X",
            "lastModified": "2024-04-16T01:23:45.000+00:00",
            "published": "2024-01-01T00:00:00",
        }
    )
    assert rec.last_modified.tzinfo is not None
    assert rec.published.tzinfo is not None


def test_map_cve_picks_english_description() -> None:
    rec = map_cve(
        {
            "id": "CVE-X",
            "lastModified": "2024-04-16T01:23:45.000",
            "published": "2024-01-01T00:00:00.000",
            "descriptions": [
                {"lang": "fr", "value": "français"},
                {"lang": "en-US", "value": "english"},
            ],
        }
    )
    assert rec.description_en == "english"


def test_map_cve_falls_back_to_first_description_when_no_english() -> None:
    rec = map_cve(
        {
            "id": "CVE-X",
            "lastModified": "2024-04-16T01:23:45.000",
            "published": "2024-01-01T00:00:00.000",
            "descriptions": [
                {"lang": "ja", "value": "日本語"},
                {"lang": "fr", "value": "français"},
            ],
        }
    )
    assert rec.description_en == "日本語"


def test_map_cve_cpe_stem_lowercased() -> None:
    rec = map_cve(
        {
            "id": "CVE-X",
            "lastModified": "2024-04-16T01:23:45.000",
            "published": "2024-01-01T00:00:00.000",
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:Apache:Log4J:2.14.0:*:*:*:*:*:*:*",
                                }
                            ]
                        }
                    ]
                }
            ],
        }
    )
    assert rec.cpe_criteria[0].criteria_stem == "apache:log4j"


def test_map_batch_skips_individually_malformed_entries() -> None:
    batch = map_batch(
        {
            "vulnerabilities": [
                {"cve": {"id": "CVE-good", "lastModified": "2024-04-16T00:00:00.000",
                         "published": "2024-01-01T00:00:00.000", "vulnStatus": "Analyzed"}},
                {"cve": {"id": "CVE-bad-no-dates"}},
                {"not_a_cve": {}},
                {"cve": "not-a-dict"},
            ],
            "totalResults": 4,
            "resultsPerPage": 4,
            "startIndex": 0,
        }
    )
    # Only one good record survives.
    assert [r.cve_id for r in batch.records] == ["CVE-good"]
    assert batch.total_results == 4  # paging metadata preserved


def test_map_cve_walks_nested_children() -> None:
    rec = map_cve(
        {
            "id": "CVE-X",
            "lastModified": "2024-04-16T01:23:45.000",
            "published": "2024-01-01T00:00:00.000",
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "AND",
                            "children": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:o:vendor:os:1.0:*:*:*:*:*:*:*",
                                        }
                                    ]
                                },
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:vendor:app:2.0:*:*:*:*:*:*:*",
                                        }
                                    ]
                                },
                            ],
                        }
                    ]
                }
            ],
        }
    )
    stems = {c.criteria_stem for c in rec.cpe_criteria}
    assert stems == {"vendor:os", "vendor:app"}
